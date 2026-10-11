package notify

import (
	"strings"
	"testing"
)

func TestDialogTextNamesTheMachine(t *testing.T) {
	got := DialogText(ApprovalRequest{Agent: "grokbot", NodeID: "nABCDEFGHIJKLMNCNTRL", NodeName: "grok-bot", NodeUser: "tagged-devices"})
	for _, want := range []string{`"grokbot"`, "Machine: grok-bot", "Login: tagged-devices", "Tailscale node: nABCDEFGHIJK..."} {
		if !strings.Contains(got, want) {
			t.Errorf("dialog text lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "replaces") {
		t.Errorf("a first sighting replaces nothing:\n%s", got)
	}
	got = DialogText(ApprovalRequest{Agent: "grokbot", NodeID: "nNEW", NodeName: "grok-bot-2", Replaces: "grok-bot"})
	if !strings.Contains(got, "replaces its previous machine, grok-bot") {
		t.Errorf("a node change must name the machine it replaces:\n%s", got)
	}
}

func TestDialogScriptQuotesAndDefaultsToNotNow(t *testing.T) {
	s := dialogScript(ApprovalRequest{Agent: "x", NodeName: `evil" & do shell script "rm`, NodeID: "n1"}, 60)
	if strings.Contains(s, `evil" &`) {
		t.Fatalf("node name not escaped: %s", s)
	}
	if !strings.Contains(s, `evil\" & do shell script \"rm`) {
		t.Fatalf("escaped name missing: %s", s)
	}
	if !strings.Contains(s, `default button "Not now" cancel button "Not now"`) {
		t.Fatalf("Return or Escape must not approve: %s", s)
	}
}

func TestParseDialogResult(t *testing.T) {
	cases := map[string]bool{
		"button returned:Approve, gave up:false": true,
		"button returned:Approve":                true,
		"button returned:Not now, gave up:false": false,
		"button returned:, gave up:true":         false,
		"":                                       false,
	}
	for out, want := range cases {
		if got := parseDialogResult(out); got != want {
			t.Errorf("parseDialogResult(%q) = %v, want %v", out, got, want)
		}
	}
}
