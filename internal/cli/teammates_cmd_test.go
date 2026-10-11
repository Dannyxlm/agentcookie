package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tincan/tincantest"
)

func TestTeammatesRemoveEditsListAndDeletesKey(t *testing.T) {
	dir := t.TempDir()
	writeTeammatesFile(t, dir, "# my agents\nteammates:\n  # the VM\n  - name: grokbot\n    cadence: turn+timer\n  - name: instinct\n")
	if err := keystore.Save(dir, &keystore.PeerKey{Peer: "grokbot", Key: bytes.Repeat([]byte{2}, 32), PairedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runTeammatesRemove(&out, dir, "grokbot"); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadTeammates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Has("grokbot") || !cfg.Has("instinct") {
		t.Fatalf("names = %v", cfg.Names())
	}
	data, _ := os.ReadFile(config.TeammatesPath(dir))
	if !strings.Contains(string(data), "# my agents") {
		t.Fatalf("owner comments lost:\n%s", data)
	}
	if _, err := keystore.Load(dir, "grokbot"); err == nil {
		t.Fatal("key not deleted")
	}
	if !strings.Contains(out.String(), "stay valid") {
		t.Fatalf("output must say delivered cookies stay valid:\n%s", out.String())
	}
	if err := runTeammatesRemove(&out, dir, "grokbot"); err == nil {
		t.Fatal("removing a name that is not listed must fail")
	}
}

func TestTeammatesApproveWaitsForDaemonAnswer(t *testing.T) {
	home := t.TempDir()
	prev := teammateApproveWait
	teammateApproveWait = 5 * time.Second
	t.Cleanup(func() { teammateApproveWait = prev })

	// A stand-in daemon answers the queued approval.
	go func() {
		intent := filepath.Join(teammateApprovalsDir(home), "grokbot.json")
		for range 200 {
			if _, err := os.Stat(intent); err == nil {
				_ = os.Remove(intent)
				_ = writeJSONFile(filepath.Join(teammateApprovalsDir(home), "grokbot.result.json"),
					approvalResult{NodeID: "nOLD", Message: "the roster shows a different machine (now waiting: grok-bot-2, node nNEW)"})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	var out bytes.Buffer
	err := runTeammatesApprove(context.Background(), &out, home, "grokbot", "nOLD")
	if err == nil || !strings.Contains(err.Error(), "nNEW") {
		t.Fatalf("err = %v", err)
	}
}

func TestTeammatesApproveQueuesWithoutDaemon(t *testing.T) {
	home := t.TempDir()
	prev := teammateApproveWait
	teammateApproveWait = 50 * time.Millisecond
	t.Cleanup(func() { teammateApproveWait = prev })
	var out bytes.Buffer
	if err := runTeammatesApprove(context.Background(), &out, home, "grokbot", "nGROK"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Queued") {
		t.Fatalf("out = %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(teammateApprovalsDir(home), "grokbot.json")); err != nil {
		t.Fatal("approval not left for the daemon")
	}
	if err := runTeammatesApprove(context.Background(), &out, home, "../x", "n"); err == nil {
		t.Fatal("a path-like name must be refused")
	}
}

func TestTeammateStatusesAndList(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	writeTeammatesFile(t, dir, "teammates:\n  - name: grokbot\n  - name: instinct\n    cadence: turn\n")
	store, err := state.OpenTeammateStore(state.TeammatesPath(home))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.Update(func(st *state.TeammatesState) error {
		g := st.Teammate("grokbot")
		g.Phase, g.Kind, g.BoundNodeID, g.BoundNodeName, g.LastPulledAt = state.PhasePaired, "vm-webhook", "nGROK", "grok-bot", now.Add(-2*time.Hour)
		i := st.Teammate("instinct")
		i.Phase, i.PendingNodeID, i.PendingNodeName, i.PendingNodeUser = state.PhaseAwaitingApproval, "nINST", "instinct-sbx", "owner@example.com"
		d := st.Teammate("dot")
		d.Phase, d.RemovedAt = state.PhaseRemoved, now
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := TeammateStatuses(dir, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Name != "grokbot" || rows[1].Name != "instinct" || rows[2].Name != "dot" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].Cadence != config.CadenceTurnTimer || rows[0].StateLabel != "paired" || rows[0].NodeName != "grok-bot" {
		t.Fatalf("grokbot = %+v", rows[0])
	}
	if rows[2].Listed || rows[2].State != state.PhaseRemoved {
		t.Fatalf("dot = %+v", rows[2])
	}
	var out bytes.Buffer
	printTeammateStatuses(&out, rows, now)
	for _, want := range []string{"2h ago", "agentcookie teammates approve instinct --node nINST", "stay valid"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, out.String())
		}
	}

	// A list that does not load shows every teammate suspended.
	writeTeammatesFile(t, dir, "teammates:\n  - name: chatgpt\n")
	rows, err = TeammateStatuses(dir, home)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.State != "suspended" {
			t.Fatalf("row = %+v", r)
		}
	}
}

func TestTeammatesSetupRecordsPathAndChecksAdminView(t *testing.T) {
	dir, home := t.TempDir(), t.TempDir()
	fake := tincantest.New(t)
	t.Setenv("PATH", fake.Dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	tincanConf := filepath.Join(home, "agentcookie.json")
	writeCLIFile(t, tincanConf, "{}")
	writeTeammatesFile(t, dir, "tincan_config: "+tincanConf+"\nteammates:\n  - name: grokbot\n")
	fake.Set("agents", `{"agents":[{"name":"grokbot","node_id":"nGROK"}]}`, "", 0)
	prev := laptopDNSNameFunc
	laptopDNSNameFunc = func(context.Context) (string, error) { return "mac-laptop.tail.ts.net", nil }
	t.Cleanup(func() { laptopDNSNameFunc = prev })

	var out bytes.Buffer
	if err := runTeammatesSetup(context.Background(), &out, dir, home); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadTeammates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TincanPath != fake.Path {
		t.Fatalf("tincan_path = %q, want %q", cfg.TincanPath, fake.Path)
	}
	for _, want := range []string{"tincan: " + fake.Path, "roster: OK", `"dst": ["mac-laptop.tail.ts.net:9998"]`, "Teammates: grokbot", `"unless"`, "already joined"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("setup output lacks %q:\n%s", want, out.String())
		}
	}
	if c := fake.CallsTo("agents"); len(c) != 1 || c[0].Config != tincanConf {
		t.Fatalf("roster read as %+v", c)
	}

	// Without admin node fields, setup says how to fix it.
	fake.Set("agents", `{"agents":[{"name":"grokbot"}]}`, "", 0)
	out.Reset()
	if err := runTeammatesSetup(context.Background(), &out, dir, home); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "--admin list") {
		t.Fatalf("setup output:\n%s", out.String())
	}

	// Not joined yet: the invite and join steps use agentcookie's own config.
	_ = os.Remove(tincanConf)
	out.Reset()
	if err := runTeammatesSetup(context.Background(), &out, dir, home); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tincan invite agentcookie", "TINCAN_CONFIG=" + tincanConf + " " + fake.Path + " join"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("setup output lacks %q:\n%s", want, out.String())
		}
	}
}
