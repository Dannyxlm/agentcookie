package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/state"
)

var tmDoctorNow = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

const tmLaptop = "laptop.tail-abc.ts.net."

// newTeammateDoctorDeps writes teammates.yaml (when body is not empty)
// and a teammates-state.json shaped by mutate, with a working tincan path,
// visible node fields, and an up pull listener unless the test changes them.
func newTeammateDoctorDeps(t *testing.T, body string, mutate func(*state.TeammatesState)) doctorDeps {
	t.Helper()
	dir, home := t.TempDir(), t.TempDir()
	if body != "" {
		writeTeammatesFile(t, dir, body)
	}
	tincanBin := filepath.Join(home, "bin", "tincan")
	writeFile(t, tincanBin, "#!/bin/sh\n")
	store, err := state.OpenTeammateStore(state.TeammatesPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(st *state.TeammatesState) error {
		st.Tincan = state.TincanStatus{Path: tincanBin, LastRosterAt: tmDoctorNow.Add(-5 * time.Minute), NodeFieldsVisible: true}
		st.LaptopDNSName = tmLaptop
		if mutate != nil {
			mutate(st)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return doctorDeps{
		ConfigDir: dir,
		Home:      home,
		Now:       func() time.Time { return tmDoctorNow },
		LoadSourceState: func() (*state.SourceState, error) {
			return &state.SourceState{PullListener: "up", PullListenerAddr: "100.64.0.1:9998"}, nil
		},
		NodeTags: func(string) ([]string, error) { return nil, nil },
	}
}

func findCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, checks)
	return Check{}
}

func wantCheck(t *testing.T, c Check, sev Severity, subs ...string) {
	t.Helper()
	if c.Severity != sev {
		t.Fatalf("%s: severity %q, want %q (detail %q, fix %q)", c.Name, c.Severity, sev, c.Detail, c.Remediation)
	}
	all := c.Detail + "\n" + c.Remediation
	for _, s := range subs {
		if !strings.Contains(all, s) {
			t.Fatalf("%s: %q missing %q", c.Name, all, s)
		}
	}
}

const twoTeammates = "teammates:\n  - name: grokbot\n  - name: instinct\n"

func TestDoctorTeammatesAbsentWithoutFile(t *testing.T) {
	d := newTeammateDoctorDeps(t, "", nil)
	if got := checkTeammates(d); got != nil {
		t.Fatalf("no teammates.yaml must add no checks, got %+v", got)
	}
}

func TestDoctorTeammatesListener(t *testing.T) {
	d := newTeammateDoctorDeps(t, twoTeammates, nil)
	wantCheck(t, findCheck(t, checkTeammates(d), "Teammate pull listener"), SeverityOK, "100.64.0.1:9998")

	d.LoadSourceState = func() (*state.SourceState, error) { return &state.SourceState{PullListener: "down"}, nil }
	wantCheck(t, findCheck(t, checkTeammates(d), "Teammate pull listener"), SeverityFail, "down")

	d.LoadSourceState = func() (*state.SourceState, error) { return nil, nil }
	wantCheck(t, findCheck(t, checkTeammates(d), "Teammate pull listener"), SeverityFail, "source --watch")
}

func TestDoctorTeammatesConfigParseError(t *testing.T) {
	d := newTeammateDoctorDeps(t, "teammates:\n  - name: [\n", func(st *state.TeammatesState) {
		st.Teammate("grokbot").Phase = state.PhasePaired
	})
	checks := checkTeammates(d)
	wantCheck(t, findCheck(t, checks, "Teammates config"), SeverityFail, "does not load", "yaml")
	wantCheck(t, findCheck(t, checks, "Teammate grokbot"), SeverityWarn, "suspended")

	ok := newTeammateDoctorDeps(t, twoTeammates, nil)
	wantCheck(t, findCheck(t, checkTeammates(ok), "Teammates config"), SeverityOK, "2 listed")
}

// Doctor names a build that cannot pin a release for the pairing notice,
// since the daemon then sends no notice at all.
func TestDoctorTeammatesReleasePin(t *testing.T) {
	prevVersion, prevAMD64, prevARM64 := Version, releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256
	t.Cleanup(func() { Version, releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256 = prevVersion, prevAMD64, prevARM64 })
	d := newTeammateDoctorDeps(t, twoTeammates, nil)

	Version, releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256 = "1.3.0-rc.1", strings.Repeat("a", 64), strings.Repeat("b", 64)
	wantCheck(t, findCheck(t, checkTeammates(d), "Teammate release pin"), SeverityOK, "v1.3.0-rc.1", "amd64", "arm64")

	releaseLinuxARM64SHA256 = ""
	wantCheck(t, findCheck(t, checkTeammates(d), "Teammate release pin"), SeverityWarn, "v1.3.0-rc.1", "amd64 only")

	Version, releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256 = "0.0.1-dev", "", ""
	wantCheck(t, findCheck(t, checkTeammates(d), "Teammate release pin"), SeverityFail,
		"this agentcookie build has no release pin; install a release build", "no pairing notice")
}

func TestDoctorTeammatesTincan(t *testing.T) {
	ok := newTeammateDoctorDeps(t, twoTeammates, nil)
	wantCheck(t, findCheck(t, checkTeammates(ok), "Tincan"), SeverityOK)

	missing := newTeammateDoctorDeps(t, twoTeammates, func(st *state.TeammatesState) {
		st.Tincan.Path = "/nonexistent/tincan"
	})
	wantCheck(t, findCheck(t, checkTeammates(missing), "Tincan"), SeverityWarn, "/nonexistent/tincan", "agentcookie teammates setup")

	unset := newTeammateDoctorDeps(t, twoTeammates, func(st *state.TeammatesState) { st.Tincan.Path = "" })
	wantCheck(t, findCheck(t, checkTeammates(unset), "Tincan"), SeverityWarn, "agentcookie teammates setup")

	hidden := newTeammateDoctorDeps(t, twoTeammates, func(st *state.TeammatesState) {
		st.Tincan.NodeFieldsVisible = false
	})
	wantCheck(t, findCheck(t, checkTeammates(hidden), "Tincan"), SeverityWarn, "--admin", "agentcookie teammates setup")
}

// Covers R11: each lifecycle state renders its line.
func TestDoctorTeammateStateLines(t *testing.T) {
	cases := []struct {
		name string
		rec  state.TeammateRecord
		sev  Severity
		subs []string
	}{
		{"waiting", state.TeammateRecord{Phase: state.PhaseWaitingForNode}, SeverityInfo, []string{"waiting for its machine"}},
		{"awaiting", state.TeammateRecord{Phase: state.PhaseAwaitingApproval, PendingNodeID: "nNEW", PendingNodeName: "grok-bot-2", PendingNodeUser: "tagged-devices"},
			SeverityWarn, []string{"waiting for approval", "grok-bot-2", "agentcookie teammates approve grokbot --node nNEW"}},
		{"pairing", state.TeammateRecord{Phase: state.PhasePairing, BoundNodeID: "nGROK", BoundNodeName: "grok-bot",
			NotifyPurpose: state.NotifyPurposePairing, NotifyStatus: state.NotifySent, NotifySentAt: tmDoctorNow.Add(-10 * time.Minute),
			CodeExpiresAt: tmDoctorNow.Add(20 * time.Minute)}, SeverityInfo, []string{"pairing", "grok-bot", "code valid"}},
		{"held", state.TeammateRecord{Phase: state.PhaseHeld, BoundNodeID: "nGROK", BoundNodeName: "grok-bot",
			NotifyID: "r-1", NotifyPurpose: state.NotifyPurposePairing, NotifyStatus: state.NotifyHeld, NotifySentAt: tmDoctorNow.Add(-time.Hour)},
			SeverityWarn, []string{"held by the Tincan approval gate", "unless", "approval.json"}},
		{"paired", state.TeammateRecord{Phase: state.PhasePaired, BoundNodeID: "nGROK", BoundNodeName: "grok-bot",
			PairedAt: tmDoctorNow.Add(-48 * time.Hour), LastPulledAt: tmDoctorNow.Add(-5 * time.Minute)}, SeverityOK, []string{"paired", "last pull 5m ago"}},
		{"stale", state.TeammateRecord{Phase: state.PhasePaired, BoundNodeID: "nGROK", BoundNodeName: "grok-bot",
			PairedAt: tmDoctorNow.Add(-48 * time.Hour), LastPulledAt: tmDoctorNow.Add(-7 * time.Hour), LastPullError: "not on its approved machine"},
			SeverityWarn, []string{"last pull 7h ago", "no pull for over 6h", "not on its approved machine", "pull-once"}},
		{"paired never pulled", state.TeammateRecord{Phase: state.PhasePaired, BoundNodeID: "nGROK", BoundNodeName: "grok-bot",
			PairedAt: tmDoctorNow.Add(-8 * time.Hour)}, SeverityWarn, []string{"never pulled", "no pull for over 6h"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newTeammateDoctorDeps(t, twoTeammates, func(st *state.TeammatesState) {
				r := tc.rec
				st.Teammates = map[string]*state.TeammateRecord{"grokbot": &r}
			})
			wantCheck(t, findCheck(t, checkTeammates(d), "Teammate grokbot"), tc.sev, tc.subs...)
		})
	}

	removed := newTeammateDoctorDeps(t, "teammates:\n  - name: instinct\n", func(st *state.TeammatesState) {
		st.Teammates = map[string]*state.TeammateRecord{"grokbot": {Phase: state.PhaseRemoved, RemovedAt: tmDoctorNow.Add(-time.Hour)}}
	})
	wantCheck(t, findCheck(t, checkTeammates(removed), "Teammate grokbot"), SeverityInfo, "removed", "stay valid")
}

// pickedUpNotice is a pairing teammate whose notice went out 40 minutes
// ago, whose code expired 10 minutes ago, and which polled the relay
// after the notice (it picked the notice up).
func pickedUpNotice() state.TeammateRecord {
	sent := tmDoctorNow.Add(-40 * time.Minute)
	return state.TeammateRecord{
		Phase: state.PhasePairing, BoundNodeID: "nGROK", BoundNodeName: "grok-bot.tail-abc.ts.net.",
		NotifyID: "r-1", NotifyPurpose: state.NotifyPurposePairing, NotifyStatus: state.NotifySent,
		NotifySentAt: sent, CodeExpiresAt: sent.Add(pairCodeTTL), RelaySeenAt: sent.Add(2 * time.Minute),
	}
}

func teammateCheckFor(t *testing.T, rec state.TeammateRecord, tags []string) Check {
	t.Helper()
	d := newTeammateDoctorDeps(t, twoTeammates, func(st *state.TeammatesState) {
		st.Teammates = map[string]*state.TeammateRecord{"grokbot": &rec}
	})
	var asked string
	d.NodeTags = func(id string) ([]string, error) { asked = id; return tags, nil }
	c := findCheck(t, checkTeammates(d), "Teammate grokbot")
	if asked != "" && asked != "nGROK" {
		t.Fatalf("tags looked up for node %q, want the bound node nGROK", asked)
	}
	return c
}

// The ACL is blamed only when the teammate polled the relay after its
// pairing notice, the code expired, and no /pair attempt arrived. The
// rule names its tag (or its node name) and the laptop's port 9998.
func TestDoctorTeammateACLDiagnosis(t *testing.T) {
	c := teammateCheckFor(t, pickedUpNotice(), []string{"tag:grokbot"})
	wantCheck(t, c, SeverityWarn, "tailnet ACL", "tag:grokbot -> laptop.tail-abc.ts.net:9998")

	c = teammateCheckFor(t, pickedUpNotice(), nil)
	wantCheck(t, c, SeverityWarn, "tailnet ACL", "grok-bot.tail-abc.ts.net -> laptop.tail-abc.ts.net:9998")

	// The lifecycle already re-minted: the live code is new, but the
	// missed one is remembered and no attempt came after it.
	reminted := pickedUpNotice()
	reminted.PairCodeMissedAt = reminted.CodeExpiresAt
	reminted.NotifySentAt, reminted.CodeExpiresAt = tmDoctorNow.Add(-5*time.Minute), tmDoctorNow.Add(25*time.Minute)
	wantCheck(t, teammateCheckFor(t, reminted, []string{"tag:grokbot"}), SeverityWarn, "tag:grokbot -> laptop.tail-abc.ts.net:9998")

	// An attempt after the notice means the laptop was reachable.
	tried := pickedUpNotice()
	tried.LastPairAttemptAt = tried.NotifySentAt.Add(3 * time.Minute)
	c = teammateCheckFor(t, tried, []string{"tag:grokbot"})
	if strings.Contains(c.Detail+c.Remediation, "ACL") || strings.Contains(c.Detail+c.Remediation, "not picked up") {
		t.Fatalf("attempted pairing must not blame the ACL or pickup: %+v", c)
	}

	// Never polled after the notice: it has not picked up its notice.
	unread := pickedUpNotice()
	unread.RelaySeenAt = unread.NotifySentAt.Add(-time.Hour)
	c = teammateCheckFor(t, unread, []string{"tag:grokbot"})
	wantCheck(t, c, SeverityWarn, "has not picked up its pairing notice")
	if strings.Contains(c.Detail+c.Remediation, "ACL") {
		t.Fatalf("unread notice must not blame the ACL: %+v", c)
	}

	// A held notice is never an ACL problem.
	held := pickedUpNotice()
	held.Phase, held.NotifyStatus = state.PhaseHeld, state.NotifyHeld
	if c := teammateCheckFor(t, held, []string{"tag:grokbot"}); strings.Contains(c.Detail+c.Remediation, "ACL") {
		t.Fatalf("held notice must not blame the ACL: %+v", c)
	}
}
