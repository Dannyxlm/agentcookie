package tsclient

import (
	"context"
	"testing"
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
