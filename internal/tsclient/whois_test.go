package tsclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseWhoIsSampleJSON(t *testing.T) {
	// Shape of `tailscale whois --json <ip>` (apitype.WhoIsResponse),
	// trimmed to the fields agentcookie reads.
	raw := []byte(`{
	  "Node": {
	    "ID": 1234567,
	    "StableID": "nGROKBOT1CNTRL",
	    "Name": "grok-bot.tail-xxxx.ts.net.",
	    "Addresses": ["100.124.19.34/32"],
	    "Tags": ["tag:agent"]
	  },
	  "UserProfile": {"ID": 42, "LoginName": "tagged-devices", "DisplayName": "Tagged Devices"}
	}`)
	got, err := ParseWhoIs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.StableID != "nGROKBOT1CNTRL" || got.NodeName != "grok-bot.tail-xxxx.ts.net." || got.LoginName != "tagged-devices" {
		t.Fatalf("parsed = %+v", got)
	}
}

func TestParseWhoIsRequiresStableID(t *testing.T) {
	if _, err := ParseWhoIs([]byte(`{"Node":{"Name":"x"}}`)); err == nil {
		t.Fatal("a WhoIs answer without a StableID must be an error (callers fail closed)")
	}
	if _, err := ParseWhoIs([]byte(`not json`)); err == nil {
		t.Fatal("garbage must be an error")
	}
}

func TestWhoIsRejectsNonIP(t *testing.T) {
	if _, err := WhoIs(context.Background(), "grok-bot"); err == nil {
		t.Fatal("WhoIs must take an IP literal")
	}
}

// A tailscale CLI that leaves a child holding its stdout open must not
// hang /pull and /pair authorization past the lookup timeout.
func TestWhoIsReturnsWhenChildHoldsStdout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "tailscale")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 15 &\nsleep 15\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevFind, prevTimeout := whoisFindCLI, whoisTimeout
	whoisFindCLI = func() (string, error) { return script, nil }
	whoisTimeout = 100 * time.Millisecond
	t.Cleanup(func() { whoisFindCLI, whoisTimeout = prevFind, prevTimeout })

	start := time.Now()
	if _, err := WhoIs(context.Background(), "100.64.0.5"); err == nil {
		t.Fatal("a timed-out whois must be an error")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("WhoIs returned after %s; a child holding stdout must not block past WaitDelay", d)
	}
}
