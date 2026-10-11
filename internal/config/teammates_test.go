package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTeammates(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, TeammatesFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTeammatesMissingFileIsAbsent(t *testing.T) {
	tm, err := LoadTeammates(t.TempDir())
	if err != nil {
		t.Fatalf("missing teammates.yaml should not be an error: %v", err)
	}
	if tm != nil {
		t.Fatalf("missing teammates.yaml should yield nil, got %+v", tm)
	}
}

func TestLoadTeammatesParsesNamesCadenceAndTincan(t *testing.T) {
	dir := t.TempDir()
	writeTeammates(t, dir, `
tincan_path: ~/bin/tincan
tincan_config: ~/.config/tincan-agentcookie/client.json
teammates:
  - name: grokbot
    cadence: turn+timer
  - name: instinct
    cadence: turn
  - name: dot
`)
	tm, err := LoadTeammates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := tm.Names(); strings.Join(got, ",") != "grokbot,instinct,dot" {
		t.Fatalf("names = %v", got)
	}
	if tm.Teammates[0].Cadence != CadenceTurnTimer || tm.Teammates[1].Cadence != CadenceTurn || tm.Teammates[2].Cadence != "" {
		t.Fatalf("cadences = %+v", tm.Teammates)
	}
	home, _ := os.UserHomeDir()
	if tm.TincanPath != filepath.Join(home, "bin", "tincan") {
		t.Errorf("tincan_path not tilde-expanded: %q", tm.TincanPath)
	}
	if !tm.Has("instinct") || tm.Has("nobody") {
		t.Error("Has() wrong")
	}
}

func TestLoadTeammatesRejectsVirtualKinds(t *testing.T) {
	for _, name := range []string{"chatgpt", "sesame", "claude-web"} {
		dir := t.TempDir()
		writeTeammates(t, dir, "teammates:\n  - name: "+name+"\n")
		_, err := LoadTeammates(dir)
		if err == nil {
			t.Fatalf("%s should be rejected", name)
		}
		if !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "no Tailscale node") {
			t.Errorf("error should name %s and say why, got: %v", name, err)
		}
	}
}

func TestLoadTeammatesRejectsDuplicatesUnknownKeysAndBadCadence(t *testing.T) {
	cases := map[string]string{
		"duplicate":   "teammates:\n  - name: grokbot\n  - name: grokbot\n",
		"unknown key": "teammates:\n  - name: grokbot\n    sink_url: http://x\n",
		"top unknown": "teammates: []\nfoo: bar\n",
		"cadence":     "teammates:\n  - name: grokbot\n    cadence: hourly\n",
		"empty name":  "teammates:\n  - cadence: turn\n",
		"bad name":    "teammates:\n  - name: ../evil\n",
	}
	for label, body := range cases {
		dir := t.TempDir()
		writeTeammates(t, dir, body)
		if _, err := LoadTeammates(dir); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestIsVirtualTincanKind(t *testing.T) {
	for _, k := range []string{"chatgpt", "sesame", "dot-web", "grok-web"} {
		if !IsVirtualTincanKind(k) {
			t.Errorf("%s should be virtual", k)
		}
	}
	for _, k := range []string{"grokbot", "e2b", "hermes", "dot", ""} {
		if IsVirtualTincanKind(k) {
			t.Errorf("%s should not be virtual", k)
		}
	}
}

func TestExampleTeammatesFileLoads(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", TeammatesFile))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeTeammates(t, dir, string(data))
	tm, err := LoadTeammates(dir)
	if err != nil {
		t.Fatalf("examples/teammates.yaml does not load: %v", err)
	}
	if len(tm.Teammates) == 0 {
		t.Fatal("example lists no teammates")
	}
}
