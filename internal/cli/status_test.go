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

// The teammates block shows the listener and one compact line per
// teammate with the same diagnosis doctor gives, and is absent without
// teammates.yaml.
func TestStatusTeammatesBlock(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	oldDir, oldJSON, oldTags := common.ConfigDir, common.JSON, statusNodeTags
	common.ConfigDir, common.JSON = dir, false
	statusNodeTags = func(string) ([]string, error) { return []string{"tag:instinct"}, nil }
	t.Cleanup(func() { common.ConfigDir, common.JSON, statusNodeTags = oldDir, oldJSON, oldTags })

	run := func() string {
		return captureStdout(t, func() {
			if err := statusCmd.RunE(commandWithOutput(&bytes.Buffer{}), nil); err != nil {
				t.Fatalf("status: %v", err)
			}
		})
	}
	if out := run(); strings.Contains(out, "teammates") {
		t.Fatalf("no teammates.yaml must print no teammates block, got %q", out)
	}

	writeTeammatesFile(t, dir, "teammates:\n  - name: grokbot\n  - name: instinct\n")
	writeCLIFile(t, state.SourcePath(home), `{"role":"source","pull_listener":"up","pull_listener_addr":"100.64.0.1:9998"}`)
	store, err := state.OpenTeammateStore(state.TeammatesPath(home))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sent := now.Add(-40 * time.Minute)
	if err := store.Update(func(st *state.TeammatesState) error {
		st.LaptopDNSName = "laptop.tail-abc.ts.net."
		st.Teammates = map[string]*state.TeammateRecord{
			"grokbot": {Phase: state.PhasePaired, BoundNodeID: "nGROK", BoundNodeName: "grok-bot", PairedAt: now.Add(-time.Hour), LastPulledAt: now.Add(-5 * time.Minute)},
			"instinct": {Phase: state.PhasePairing, BoundNodeID: "nINST", BoundNodeName: "instinct-box",
				NotifyPurpose: state.NotifyPurposePairing, NotifyStatus: state.NotifySent, NotifySentAt: sent,
				CodeExpiresAt: sent.Add(pairCodeTTL), RelaySeenAt: sent.Add(time.Minute)},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out := run()
	for _, want := range []string{
		"teammates: 2 listed, pull listener up on 100.64.0.1:9998",
		"grokbot: paired on grok-bot, last pull 5m ago",
		"instinct: pairing on instinct-box",
		"tag:instinct -> laptop.tail-abc.ts.net:9998",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status missing %q:\n%s", want, out)
		}
	}
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
