package tincan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/tincan/tincantest"
)

func newTestClient(t *testing.T) (*Client, *tincantest.Fake) {
	t.Helper()
	f := tincantest.New(t)
	return &Client{Path: f.Path, Config: "/cfg/agentcookie.json", Timeout: 10 * time.Second}, f
}

func TestRosterParsesAdminNodeFields(t *testing.T) {
	c, f := newTestClient(t)
	f.Set("agents", `{"agents":[
	  {"name":"grokbot","online":true,"wake":"webhook","kind":"vm-webhook","last_poll":"2026-10-11T10:00:00Z","last_active":"2026-10-11T10:05:00Z","node_id":"nGROK1CNTRL","node_name":"grok-bot","node_user":"tagged-devices"},
	  {"name":"instinct","online":false,"wake":"email","kind":"e2b-email"}
	],"relay_version":"0.16.0"}`, "", 0)

	r, err := c.Roster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	g, ok := r.Find("grokbot")
	if !ok || g.NodeID != "nGROK1CNTRL" || g.NodeName != "grok-bot" || g.NodeUser != "tagged-devices" || g.Kind != "vm-webhook" {
		t.Fatalf("grokbot = %+v", g)
	}
	if want := time.Date(2026, 10, 11, 10, 5, 0, 0, time.UTC); !g.LastSeen().Equal(want) {
		t.Fatalf("LastSeen = %v, want the later last_active %v", g.LastSeen(), want)
	}
	if i, _ := r.Find("instinct"); i.NodeID != "" {
		t.Fatalf("instinct has no node yet: %+v", i)
	}
	if !r.NodeFieldsVisible() {
		t.Fatal("node fields are visible when any agent carries a node")
	}
	calls := f.Calls()
	if len(calls) != 1 || calls[0].Config != "/cfg/agentcookie.json" || !slices.Equal(calls[0].Args, []string{"agents", "--json"}) {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestRosterFromOlderRelayHasNoNodeFields(t *testing.T) {
	c, f := newTestClient(t)
	f.Set("agents", `{"agents":[{"name":"grokbot","online":true,"wake":"webhook"}]}`, "", 0)
	r, err := c.Roster(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.NodeFieldsVisible() {
		t.Fatal("an older relay shows no node fields")
	}
}

func TestRosterErrorCarriesStderr(t *testing.T) {
	c, f := newTestClient(t)
	f.Set("agents", "", "tincan: relay: unreachable\n", 1)
	_, err := c.Roster(context.Background())
	if err == nil || !strings.Contains(err.Error(), "relay: unreachable") {
		t.Fatalf("err = %v", err)
	}
}

func TestNotifyOutcomes(t *testing.T) {
	cases := []struct {
		name    string
		stdout  string
		stderr  string
		code    int
		want    Outcome
		wantID  string
		wantErr bool
	}{
		{"sent", `{"outcome":"sent","request":{"id":"r-1","to":"grokbot","body":"x"}}`, "", 0, OutcomeSent, "r-1", false},
		{"held", `{"outcome":"sent","request":{"id":"r-2","to":"grokbot","body":"x","status":"held"}}`, "", 0, OutcomeHeld, "r-2", false},
		{"rate limited", "", "tincan: relay: too many requests (HTTP 429)\n", 1, OutcomeRateLimited, "", true},
		{"relay down", "", "tincan: dial tcp: connection refused\n", 1, OutcomeError, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, f := newTestClient(t)
			f.Set("ask", tc.stdout, tc.stderr, tc.code)
			res := c.Notify(context.Background(), "grokbot", "line one\nline two")
			if res.Outcome != tc.want || res.RequestID != tc.wantID || (res.Err != nil) != tc.wantErr {
				t.Fatalf("res = %+v", res)
			}
			call := f.CallsTo("ask")[0]
			if !slices.Equal(call.Args, []string{"ask", "grokbot", "--notify", "--json", "--", "line one\nline two"}) {
				t.Fatalf("args = %q", call.Args)
			}
		})
	}
}

func TestCancelAndRequestStatus(t *testing.T) {
	c, f := newTestClient(t)
	if err := c.Cancel(context.Background(), "r-9"); err != nil {
		t.Fatal(err)
	}
	if got := f.CallsTo("cancel")[0].Args; !slices.Equal(got, []string{"cancel", "r-9"}) {
		t.Fatalf("cancel args = %q", got)
	}
	// get --json exits 2 for a request with no final state, still printing JSON.
	f.Set("get", `{"outcome":"pending","result":{"request":{"id":"r-9","to":"x","body":""},"status":"held"}}`, "", 2)
	st, err := c.RequestStatus(context.Background(), "r-9")
	if err != nil || st != "held" {
		t.Fatalf("status = %q, %v", st, err)
	}
	f.Set("get", `{"outcome":"failed","result":{"request":{"id":"r-9","to":"x","body":""},"status":"expired"}}`, "", 1)
	if st, _ := c.RequestStatus(context.Background(), "r-9"); st != "expired" {
		t.Fatalf("status = %q", st)
	}
}

func TestDrainInboxConsumes(t *testing.T) {
	c, f := newTestClient(t)
	f.Set("inbox", `{"requests":[{"id":"q1","to":"agentcookie","body":"hi"}],"replies":[]}`, "", 0)
	n, err := c.DrainInbox(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n = %d, err = %v", n, err)
	}
	if got := f.CallsTo("inbox")[0].Args; !slices.Equal(got, []string{"inbox", "--json"}) {
		t.Fatalf("args = %q", got)
	}
}

func TestResolve(t *testing.T) {
	prev := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("not on PATH") }
	t.Cleanup(func() { lookPath = prev })

	home := t.TempDir()
	if _, err := Resolve("", home); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if _, err := Resolve("relative/tincan", home); err == nil {
		t.Fatal("a relative tincan_path must be refused")
	}

	local := filepath.Join(home, ".local", "bin", "tincan")
	writeExe(t, local)
	if got, err := Resolve("", home); err != nil || got != local {
		t.Fatalf("got %q, %v; want %q", got, err, local)
	}
	bin := filepath.Join(home, "bin", "tincan")
	writeExe(t, bin)
	if got, _ := Resolve("", home); got != bin {
		t.Fatalf("~/bin wins over ~/.local/bin: got %q", got)
	}
	configured := filepath.Join(t.TempDir(), "tincan")
	writeExe(t, configured)
	if got, _ := Resolve(configured, home); got != configured {
		t.Fatalf("configured path wins: got %q", got)
	}

	lookPath = func(string) (string, error) { return "/opt/tincan/bin/tincan", nil }
	if got, _ := Resolve("", home); got != "/opt/tincan/bin/tincan" {
		t.Fatalf("PATH wins over the home probes: got %q", got)
	}
}

func writeExe(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}
