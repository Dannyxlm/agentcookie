package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/state"
)

func TestStatusReportsCookiePolicy(t *testing.T) {
	dir := t.TempDir()
	writeCLIFile(t, filepath.Join(dir, "blocklist.yaml"), `
version: 1
policy: allowlist
domains:
  - pattern: "example.com"
`)

	oldDir := common.ConfigDir
	oldJSON := common.JSON
	common.ConfigDir = dir
	common.JSON = false
	t.Cleanup(func() {
		common.ConfigDir = oldDir
		common.JSON = oldJSON
	})

	out := captureStdout(t, func() {
		if err := statusCmd.RunE(commandWithOutput(&bytes.Buffer{}), nil); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	if !strings.Contains(out, "cookie policy: allowlist") {
		t.Fatalf("status output should report allowlist policy, got %q", out)
	}
}

func TestStatusReportsResolvedSourceSinks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	writeCLIFile(t, filepath.Join(dir, "source.yaml"), `
sinks:
  - url: http://first.test:9999/sync
    peer: first
  - url: http://second.test:9999/sync
    peer: second
cdp_source:
  enabled: true
  endpoint: http://127.0.0.1:9222
`)

	oldDir := common.ConfigDir
	oldJSON := common.JSON
	common.ConfigDir = dir
	common.JSON = false
	t.Cleanup(func() {
		common.ConfigDir = oldDir
		common.JSON = oldJSON
	})

	out := captureStdout(t, func() {
		if err := statusCmd.RunE(commandWithOutput(&bytes.Buffer{}), nil); err != nil {
			t.Fatalf("status: %v", err)
		}
	})
	want := "source -> http://first.test:9999/sync, http://second.test:9999/sync"
	if !strings.Contains(out, want) {
		t.Fatalf("status should report resolved source sinks %q, got %q", want, out)
	}
	if !strings.Contains(out, "cdp source: http://127.0.0.1:9222") {
		t.Fatalf("status should identify the active CDP source, got %q", out)
	}
	if strings.Contains(out, "chrome db:") {
		t.Fatalf("status must not present a SQLite source for a CDP source, got %q", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return buf.String()
}

func TestSinkSkipStatusLines(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	if lines := sinkSkipStatusLines(state.SinkPushState{URL: "http://a.test/sync", TotalPushes: 2}, now); len(lines) != 0 {
		t.Fatalf("healthy sink should add no lines, got %q", lines)
	}

	asleep := state.SinkPushState{Asleep: true, LastAsleepAt: now.Add(-90 * time.Second)}
	lines := sinkSkipStatusLines(asleep, now)
	if len(lines) != 1 || !strings.Contains(lines[0], "asleep") || !strings.Contains(lines[0], "1m30s ago") {
		t.Fatalf("asleep sink should explain the skip, got %q", lines)
	}

	backoff := state.SinkPushState{ConsecutiveFailures: 3, BackoffUntil: now.Add(2 * time.Minute)}
	lines = sinkSkipStatusLines(backoff, now)
	if len(lines) != 1 || !strings.Contains(lines[0], "3 consecutive failure(s)") || !strings.Contains(lines[0], "next retry in 2m0s") {
		t.Fatalf("backing-off sink should show the next retry, got %q", lines)
	}

	expired := state.SinkPushState{ConsecutiveFailures: 3, BackoffUntil: now.Add(-time.Second)}
	if lines := sinkSkipStatusLines(expired, now); len(lines) != 0 {
		t.Fatalf("an elapsed backoff window should add no lines, got %q", lines)
	}
}
