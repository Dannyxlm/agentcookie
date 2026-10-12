package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/notify"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tincan/tincantest"
)

// lcHarness is a lifecycle over a real hub, state store and fake tincan.
type lcHarness struct {
	t         *testing.T
	dir, home string
	hub       *teammateHub
	lc        *teammateLifecycle
	fake      *tincantest.Fake
	log       *bytes.Buffer
	now       time.Time

	mu      sync.Mutex
	dialogs []notify.ApprovalRequest
	answer  bool
}

// lcAMD64SHA and lcARM64SHA are the Linux digests the harness embeds as
// if this were a release build.
var (
	lcAMD64SHA = "ab12" + strings.Repeat("0", 60)
	lcARM64SHA = "cd34" + strings.Repeat("0", 60)
)

const lcTincanConfig = "/cfg/tincan/agentcookie.json"

func newLCHarness(t *testing.T, names ...string) *lcHarness {
	t.Helper()
	h := &lcHarness{t: t, dir: t.TempDir(), home: t.TempDir(), fake: tincantest.New(t), now: stepT0, answer: true}
	h.writeList(names...)
	hub, logBuf := newTestHub(t, h.dir)
	hub.now = func() time.Time { return h.now }
	if err := hub.Reload(); err != nil {
		t.Fatal(err)
	}
	h.hub, h.log = hub, logBuf
	h.lc = newTeammateLifecycle(hub, h.home)
	h.lc.cookiesChangedAt = func() time.Time { return time.Time{} }

	prevDialog, prevNotice, prevDNS, prevVersion := approvalDialogFunc, ownerNoticeFunc, laptopDNSNameFunc, Version
	prevAMD64, prevARM64 := releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256
	approvalDialogFunc = func(_ context.Context, req notify.ApprovalRequest) (bool, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.dialogs = append(h.dialogs, req)
		return h.answer, nil
	}
	ownerNoticeFunc = func(context.Context, string, string) error { return nil }
	laptopDNSNameFunc = func(context.Context) (string, error) { return "mac-laptop.tail2b6977.ts.net", nil }
	releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256 = lcAMD64SHA, lcARM64SHA
	Version = "1.4.0"
	t.Cleanup(func() {
		approvalDialogFunc, ownerNoticeFunc, laptopDNSNameFunc, Version = prevDialog, prevNotice, prevDNS, prevVersion
		releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256 = prevAMD64, prevARM64
	})
	h.setRoster()
	h.fake.Set("inbox", `{"requests":[],"replies":[]}`, "", 0)
	h.fake.Set("ask", `{"outcome":"sent","request":{"id":"r-1","to":"grokbot","body":""}}`, "", 0)
	return h
}

func (h *lcHarness) writeList(names ...string) {
	h.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "tincan_path: %s\ntincan_config: %s\nteammates:\n", h.fake.Path, lcTincanConfig)
	for _, n := range names {
		fmt.Fprintf(&b, "  - name: %s\n", n)
	}
	if len(names) == 0 {
		b.WriteString("  []\n")
	}
	writeTeammatesFile(h.t, h.dir, b.String())
}

// setRoster makes `tincan agents --json` list the given agents as JSON
// objects (already encoded).
func (h *lcHarness) setRoster(agents ...string) {
	h.fake.Set("agents", `{"agents":[`+strings.Join(agents, ",")+`]}`, "", 0)
}

func grokEntry(node, nodeName string, lastPoll time.Time) string {
	poll := ""
	if !lastPoll.IsZero() {
		poll = fmt.Sprintf(`,"last_poll":%q`, lastPoll.Format(time.RFC3339))
	}
	return fmt.Sprintf(`{"name":"grokbot","online":true,"wake":"webhook","kind":"vm-webhook","node_id":%q,"node_name":%q,"node_user":"tagged-devices"%s}`, node, nodeName, poll)
}

func (h *lcHarness) dialogCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.dialogs)
}

// answerDialog delivers the stub dialog's answer into the lifecycle.
func (h *lcHarness) answerDialog() {
	h.t.Helper()
	select {
	case in := <-h.lc.inputs:
		h.lc.handleInput(context.Background(), in)
	case <-time.After(5 * time.Second):
		h.t.Fatal("no dialog answer arrived")
	}
}

func (h *lcHarness) rec(name string) state.TeammateRecord {
	r, _ := h.hub.store.Record(name)
	return r
}

func (h *lcHarness) asks() []tincantest.Call { return h.fake.CallsTo("ask") }

// Covers R2 and R6 through the daemon: waiting with no notify, one dialog
// on the first sighting, approval binds the shown node and sends one
// pairing notify carrying the install line, join command and standing line.
func TestLifecycleFirstSightingApprovalAndPairingNotice(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	ctx := context.Background()

	h.lc.syncAll(ctx)
	if got := h.rec("grokbot").Phase; got != state.PhaseWaitingForNode {
		t.Fatalf("phase = %q", got)
	}
	if len(h.asks()) != 0 || h.dialogCount() != 0 {
		t.Fatal("a teammate absent from the roster gets no notify and no dialog")
	}

	h.setRoster(grokEntry("nGROK1CNTRL", "grok-bot", time.Time{}))
	h.lc.syncAll(ctx)
	h.answerDialog()
	if h.dialogCount() != 1 {
		t.Fatalf("dialogs = %d, want 1", h.dialogCount())
	}
	d := h.dialogs[0]
	if d.Agent != "grokbot" || d.NodeID != "nGROK1CNTRL" || d.NodeName != "grok-bot" || d.NodeUser != "tagged-devices" {
		t.Fatalf("dialog = %+v", d)
	}

	rec := h.rec("grokbot")
	if rec.BoundNodeID != "nGROK1CNTRL" || rec.Phase != state.PhasePairing || rec.NotifyID != "r-1" || rec.NotifyStatus != state.NotifySent {
		t.Fatalf("rec = %+v", rec)
	}
	pending := h.hub.PendingPairings()
	if len(pending) != 1 || pending[0].Name != "grokbot" || pending[0].NodeID != "nGROK1CNTRL" {
		t.Fatalf("pending = %+v", pending)
	}

	asks := h.asks()
	if len(asks) != 1 {
		t.Fatalf("asks = %d, want exactly one pairing notify", len(asks))
	}
	call := asks[0]
	if call.Config != lcTincanConfig || call.Args[1] != "grokbot" || call.Args[2] != "--notify" {
		t.Fatalf("ask call = %+v", call)
	}
	text := call.Args[len(call.Args)-1]
	for _, want := range []string{
		"https://raw.githubusercontent.com/mvanhorn/agentcookie/v1.4.0/scripts/teammate-install.sh",
		"| bash -s -- v1.4.0 amd64=ab12" + strings.Repeat("0", 60) + " arm64=cd34" + strings.Repeat("0", 60),
		"join --from mac-laptop.tail2b6977.ts.net --code ",
		"--as grokbot --cadence turn+timer",
		teammateStandingLine(),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("pairing notice lacks %q:\n%s", want, text)
		}
	}
	if !strings.Contains(teammateStandingLine(), "`agentcookie`") || !strings.Contains(teammateStandingLine(), "sink --pull-once") || !strings.Contains(teammateStandingLine(), "exited 3") {
		t.Fatalf("standing line = %q", teammateStandingLine())
	}
	snap := h.hub.store.Snapshot()
	if snap.LaptopDNSName != "mac-laptop.tail2b6977.ts.net" {
		t.Fatalf("laptop name not kept: %+v", snap)
	}
	if !snap.Tincan.NodeFieldsVisible || snap.Tincan.Path != h.fake.Path {
		t.Fatalf("tincan status = %+v", snap.Tincan)
	}

	// The next poll neither prompts nor notifies again.
	h.lc.syncAll(ctx)
	if h.dialogCount() != 1 || len(h.asks()) != 1 {
		t.Fatalf("dialogs = %d asks = %d after a quiet poll", h.dialogCount(), len(h.asks()))
	}
	// Every poll drains the agentcookie inbox.
	if n := len(h.fake.CallsTo("inbox")); n < 2 {
		t.Fatalf("inbox drained %d times", n)
	}
}

// Not now: no repeat dialog on later polls.
func TestLifecycleNotNowDoesNotRepeat(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.answer = false
	h.setRoster(grokEntry("nGROK", "grok-bot", time.Time{}))
	ctx := context.Background()
	h.lc.syncAll(ctx)
	h.answerDialog()
	h.lc.syncAll(ctx)
	h.lc.syncAll(ctx)
	if h.dialogCount() != 1 || len(h.asks()) != 0 {
		t.Fatalf("dialogs = %d asks = %d", h.dialogCount(), len(h.asks()))
	}
	if rec := h.rec("grokbot"); rec.Phase != state.PhaseAwaitingApproval || rec.BoundNodeID != "" {
		t.Fatalf("rec = %+v", rec)
	}
}

// approved drives grokbot to pairing on nGROK.
func (h *lcHarness) approved() {
	h.t.Helper()
	h.setRoster(grokEntry("nGROK", "grok-bot", time.Time{}))
	h.lc.syncAll(context.Background())
	h.answerDialog()
	if h.rec("grokbot").BoundNodeID != "nGROK" {
		h.t.Fatalf("not approved: %+v", h.rec("grokbot"))
	}
}

// pairedNow simulates a completed /pair from the bound node.
func (h *lcHarness) pairedNow() {
	h.t.Helper()
	if err := h.hub.store.Update(func(st *state.TeammatesState) error {
		st.Teammate("grokbot").PairedAt = h.now
		return nil
	}); err != nil {
		h.t.Fatal(err)
	}
	h.hub.CancelPairing("grokbot")
	h.lc.handleHubEvent(context.Background(), TeammateEvent{Kind: TeammatePaired, Name: "grokbot", NodeID: "nGROK"})
}

// A pairing notice the teammate already answered cannot be withdrawn: the
// relay answers 409. That is not an error, so nothing is logged and the
// record carries no open notice. Any other cancel failure is still logged.
func TestLifecyclePairedNoticeAlreadyAnswered(t *testing.T) {
	cases := []struct {
		name    string
		stderr  string
		wantLog bool
	}{
		{"answered", "tincan: relay: request is not in a state that allows this (HTTP 409)\n", false},
		{"relay down", "tincan: dial tcp: connection refused\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newLCHarness(t, "grokbot")
			h.approved()
			h.fake.Set("cancel", "", tc.stderr, 1)
			h.pairedNow()
			if rec := h.rec("grokbot"); rec.Phase != state.PhasePaired || rec.NotifyID != "" {
				t.Fatalf("rec = %+v", rec)
			}
			if c := h.fake.CallsTo("cancel"); len(c) != 1 || c[0].Args[1] != "r-1" {
				t.Fatalf("cancel calls = %+v", c)
			}
			if got := strings.Contains(h.log.String(), "could not withdraw notice"); got != tc.wantLog {
				t.Fatalf("withdraw error logged = %v, want %v; log:\n%s", got, tc.wantLog, h.log.String())
			}
		})
	}
}

// Paired closes the pairing notify; a key-lost event re-pairs with no
// dialog, and a second inside 6 hours does not.
func TestLifecyclePairedThenKeyLost(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.pairedNow()
	if rec := h.rec("grokbot"); rec.Phase != state.PhasePaired || rec.NotifyID != "" {
		t.Fatalf("rec = %+v", rec)
	}
	if c := h.fake.CallsTo("cancel"); len(c) != 1 || c[0].Args[1] != "r-1" {
		t.Fatalf("cancel calls = %+v", c)
	}

	h.fake.Set("ask", `{"outcome":"sent","request":{"id":"r-2","to":"grokbot","body":""}}`, "", 0)
	h.now = h.now.Add(time.Hour)
	h.lc.handleHubEvent(context.Background(), TeammateEvent{Kind: TeammateKeyLost, Name: "grokbot", NodeID: "nGROK"})
	if len(h.asks()) != 2 || h.dialogCount() != 1 {
		t.Fatalf("asks = %d dialogs = %d", len(h.asks()), h.dialogCount())
	}
	if len(h.hub.PendingPairings()) != 1 {
		t.Fatal("re-pair must mint a fresh code")
	}
	h.pairedNow()
	h.now = h.now.Add(time.Hour)
	h.lc.handleHubEvent(context.Background(), TeammateEvent{Kind: TeammateKeyLost, Name: "grokbot", NodeID: "nGROK"})
	if len(h.asks()) != 2 {
		t.Fatalf("a second key loss inside 6h must not re-pair; asks = %d", len(h.asks()))
	}
}

// Covers R7: a node change on a paired teammate shows one dialog naming
// the machine it replaces, and the old node's pulls stop at once.
func TestLifecycleNodeChangeStopsOldBinding(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.pairedNow()
	h.answer = false
	h.setRoster(grokEntry("nNEW", "grok-bot-2", time.Time{}))
	h.lc.syncAll(context.Background())
	h.answerDialog()
	if h.dialogCount() != 2 || h.dialogs[1].NodeID != "nNEW" || h.dialogs[1].Replaces != "grok-bot" {
		t.Fatalf("dialogs = %+v", h.dialogs)
	}
	rec := h.rec("grokbot")
	if rec.BoundNodeID != "" || rec.Phase != state.PhaseAwaitingApproval {
		t.Fatalf("rec = %+v", rec)
	}
	// /pull authorization reads BoundNodeID: the old machine is refused.
	if d := h.hub.authorizeTeammatePull(httptestRequest(), "grokbot", "secret"); d.status == 0 {
		t.Fatal("a pull from the old binding must stop")
	}
}

// Held: status shows held, nothing is resent, and the hold is checked.
func TestLifecycleHeldNotResent(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.fake.Set("ask", `{"outcome":"sent","request":{"id":"r-h","to":"grokbot","body":"","status":"held"}}`, "", 0)
	h.approved()
	h.lc.syncAll(context.Background()) // stub dialog already answered; this is a later poll
	rec := h.rec("grokbot")
	if rec.Phase != state.PhaseHeld || rec.NotifyStatus != state.NotifyHeld {
		t.Fatalf("rec = %+v", rec)
	}
	h.fake.Set("get", `{"outcome":"pending","result":{"request":{"id":"r-h","to":"grokbot","body":""},"status":"held"}}`, "", 2)
	h.now = h.now.Add(time.Hour)
	h.setRoster(grokEntry("nGROK", "grok-bot", h.now))
	h.lc.syncAll(context.Background())
	if len(h.asks()) != 1 {
		t.Fatalf("a held notify must not be resent; asks = %d", len(h.asks()))
	}
	if len(h.fake.CallsTo("get")) == 0 {
		t.Fatal("the held notify's status is never checked")
	}
}

// Relay down: the daemon keeps going, records the error, logs it once,
// and recovers on a later poll.
func TestLifecycleRelayDownRetriesQuietly(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.fake.Set("agents", "", "tincan: dial tcp: connection refused\n", 1)
	h.lc.syncAll(context.Background())
	h.lc.syncAll(context.Background())
	if n := strings.Count(h.log.String(), "cannot read the Tincan roster"); n != 1 {
		t.Fatalf("roster failure logged %d times:\n%s", n, h.log.String())
	}
	if snap := h.hub.store.Snapshot(); !strings.Contains(snap.Tincan.LastError, "connection refused") {
		t.Fatalf("tincan status = %+v", snap.Tincan)
	}
	h.setRoster(grokEntry("nGROK", "grok-bot", time.Time{}))
	h.lc.syncAll(context.Background())
	h.answerDialog()
	if h.rec("grokbot").Phase != state.PhasePairing {
		t.Fatalf("did not recover: %+v", h.rec("grokbot"))
	}
}

// A 429 leaves the teammate pairing with a backoff, then a later poll
// past the backoff sends again.
func TestLifecycleRateLimitedBacksOff(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.fake.Set("ask", "", "tincan: relay: slow down (HTTP 429)\n", 1)
	h.approved()
	rec := h.rec("grokbot")
	if rec.NotifyStatus != state.NotifyRateLimited || len(h.hub.PendingPairings()) != 0 {
		t.Fatalf("rec = %+v pending = %+v", rec, h.hub.PendingPairings())
	}
	h.lc.syncAll(context.Background())
	if len(h.asks()) != 1 {
		t.Fatalf("resent inside the backoff: asks = %d", len(h.asks()))
	}
	h.fake.Set("ask", `{"outcome":"sent","request":{"id":"r-9","to":"grokbot","body":""}}`, "", 0)
	h.now = h.now.Add(notifyBackoffMin)
	h.lc.syncAll(context.Background())
	if len(h.asks()) != 2 || h.rec("grokbot").NotifyID != "r-9" {
		t.Fatalf("asks = %d rec = %+v", len(h.asks()), h.rec("grokbot"))
	}
}

// An expired code is re-minted only after the roster shows a poll after
// the notify, cancelling the prior notify first.
func TestLifecycleExpiredCodeRemint(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.now = h.now.Add(pairCodeTTL + time.Minute) // code expired
	h.setRoster(grokEntry("nGROK", "grok-bot", stepT0.Add(-time.Minute)))
	h.lc.syncAll(context.Background())
	if len(h.asks()) != 1 {
		t.Fatal("no poll since the notify: no re-mint")
	}
	h.fake.Set("ask", `{"outcome":"sent","request":{"id":"r-2","to":"grokbot","body":""}}`, "", 0)
	h.setRoster(grokEntry("nGROK", "grok-bot", h.now))
	h.lc.syncAll(context.Background())
	if len(h.asks()) != 2 {
		t.Fatalf("asks = %d", len(h.asks()))
	}
	if c := h.fake.CallsTo("cancel"); len(c) != 1 || c[0].Args[1] != "r-1" {
		t.Fatalf("prior notify not cancelled first: %+v", c)
	}
	if rec := h.rec("grokbot"); rec.Phase != state.PhasePairing || rec.NotifyID != "r-2" || h.dialogCount() != 1 {
		t.Fatalf("rec = %+v dialogs = %d", rec, h.dialogCount())
	}
}

// Staleness: one reminder when the last pull is over 6 hours old and
// cookies changed since; none again inside 6 hours.
func TestLifecycleStaleReminder(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.pairedNow()
	h.lc.cookiesChangedAt = func() time.Time { return stepT0.Add(time.Hour) }
	h.fake.Set("ask", `{"outcome":"sent","request":{"id":"r-s","to":"grokbot","body":""}}`, "", 0)
	h.now = stepT0.Add(7 * time.Hour)
	h.lc.syncAll(context.Background())
	asks := h.asks()
	if len(asks) != 2 || !strings.Contains(asks[1].Args[len(asks[1].Args)-1], "sink --pull-once") {
		t.Fatalf("asks = %+v", asks)
	}
	h.now = stepT0.Add(9 * time.Hour)
	h.lc.syncAll(context.Background())
	if len(h.asks()) != 2 {
		t.Fatalf("second reminder inside 6h: asks = %d", len(h.asks()))
	}
}

// Covers R8: removal deletes keys/<name>.json, cancels the open notify,
// and drops any pending code.
func TestLifecycleRemovalDeletesKeyAndCancels(t *testing.T) {
	h := newLCHarness(t, "grokbot", "instinct")
	h.approved()
	if err := keystore.Save(h.dir, &keystore.PeerKey{Peer: "grokbot", Key: bytes.Repeat([]byte{1}, 32), PairedAt: stepT0}); err != nil {
		t.Fatal(err)
	}
	h.writeList("instinct")
	if err := h.hub.Reload(); err != nil {
		t.Fatal(err)
	}
	h.lc.syncAll(context.Background())
	if _, err := keystore.Load(h.dir, "grokbot"); err == nil {
		t.Fatal("removed teammate's key still on disk")
	}
	if c := h.fake.CallsTo("cancel"); len(c) != 1 || c[0].Args[1] != "r-1" {
		t.Fatalf("open notify not cancelled: %+v", c)
	}
	if len(h.hub.PendingPairings()) != 0 {
		t.Fatal("pending code survived removal")
	}
	if rec := h.rec("grokbot"); rec.Phase != state.PhaseRemoved || rec.BoundNodeID != "" {
		t.Fatalf("rec = %+v", rec)
	}
	if !strings.Contains(h.log.String(), "stay valid") {
		t.Fatalf("removal log must say delivered cookies stay valid:\n%s", h.log.String())
	}
}

// A CLI approval binds the node it names; one for a node that is no
// longer waiting binds nothing and says what is waiting now.
func TestLifecycleCLIApprovalIntent(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.answer = false
	h.setRoster(grokEntry("nGROK", "grok-bot", time.Time{}))
	h.lc.syncAll(context.Background())
	h.answerDialog()

	if err := queueTeammateApproval(h.home, "grokbot", "nOLD", h.now); err != nil {
		t.Fatal(err)
	}
	h.lc.processApprovals(context.Background())
	res := readApprovalResult(t, h.home, "grokbot")
	if res.OK || !strings.Contains(res.Message, "nGROK") || h.rec("grokbot").BoundNodeID != "" {
		t.Fatalf("stale approval: res = %+v rec = %+v", res, h.rec("grokbot"))
	}

	if err := queueTeammateApproval(h.home, "grokbot", "nGROK", h.now); err != nil {
		t.Fatal(err)
	}
	h.lc.processApprovals(context.Background())
	res = readApprovalResult(t, h.home, "grokbot")
	if !res.OK || h.rec("grokbot").BoundNodeID != "nGROK" || len(h.asks()) != 1 {
		t.Fatalf("res = %+v rec = %+v", res, h.rec("grokbot"))
	}
}

func readApprovalResult(t *testing.T, home, name string) approvalResult {
	t.Helper()
	p := filepath.Join(teammateApprovalsDir(home), name+".result.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(p)
	var res approvalResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// Run reads the roster on start and again on a teammates.yaml reload.
func TestLifecycleRunPollsOnStartAndReload(t *testing.T) {
	h := newLCHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.lc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	time.Sleep(100 * time.Millisecond)
	if n := len(h.fake.CallsTo("agents")); n != 0 {
		t.Fatalf("an empty list must not touch Tincan; agents calls = %d", n)
	}
	h.writeList("grokbot")
	if err := h.hub.Reload(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(h.fake.CallsTo("agents")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("reload did not trigger a roster read")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func httptestRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/pull", nil)
	r.RemoteAddr = "100.64.0.9:41000"
	return r
}

// laptopName asks Tailscale only while no name is stored, so a sync
// cycle that already refreshed the name does not run `tailscale status`
// again for each pairing notice.
func TestLifecycleLaptopNameUsesStoredName(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	ctx := context.Background()
	var calls int
	laptopDNSNameFunc = func(context.Context) (string, error) {
		calls++
		return "mac-laptop.tail2b6977.ts.net", nil
	}
	if name, err := h.lc.laptopName(ctx); err != nil || name != "mac-laptop.tail2b6977.ts.net" {
		t.Fatalf("laptopName = %q, %v", name, err)
	}
	if calls != 1 {
		t.Fatalf("Tailscale calls with no stored name = %d, want 1", calls)
	}
	if name, err := h.lc.laptopName(ctx); err != nil || name != "mac-laptop.tail2b6977.ts.net" {
		t.Fatalf("laptopName = %q, %v", name, err)
	}
	if calls != 1 {
		t.Fatalf("Tailscale calls with a stored name = %d, want 1", calls)
	}
}

// A release build with only the linux_amd64 digest embedded pins amd64
// only; the install line then carries no arm64 digest, so the installer
// refuses an arm64 host.
func TestLifecyclePinsAMD64OnlyWhenOnlyAMD64Embedded(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	releaseLinuxARM64SHA256 = ""
	h.approved()
	asks := h.asks()
	if len(asks) != 1 {
		t.Fatalf("asks = %d", len(asks))
	}
	text := asks[0].Args[len(asks[0].Args)-1]
	if !strings.Contains(text, "| bash -s -- v1.4.0 amd64="+lcAMD64SHA+"\n") || strings.Contains(text, "arm64=") {
		t.Fatalf("install line should pin amd64 only:\n%s", text)
	}
}

// A build with no embedded release pin (a dev build, or a version that is
// not a release tag) sends no pairing notice: the teammate stays in
// pairing with the reason recorded for status, doctor and teammates list,
// and the reason is logged once however often the send is retried.
func TestLifecycleNoReleasePinSendsNoNotice(t *testing.T) {
	for name, setup := range map[string]func(){
		"no digests":     func() { releaseLinuxAMD64SHA256, releaseLinuxARM64SHA256 = "", "" },
		"not a release":  func() { Version = "1.4.0-3-gabc1234" },
		"dev default":    func() { Version = "0.0.1-dev" },
		"dirty describe": func() { Version = "1.4.0-dirty" },
	} {
		t.Run(name, func(t *testing.T) {
			h := newLCHarness(t, "grokbot")
			setup()
			h.approved()
			for range 3 {
				h.now = h.now.Add(notifyBackoffMax + time.Minute)
				h.lc.syncAll(context.Background())
			}
			if n := len(h.asks()); n != 0 {
				t.Fatalf("asks = %d, want no pairing notice without a release pin", n)
			}
			rec := h.rec("grokbot")
			if rec.Phase != state.PhasePairing || !strings.Contains(rec.NotifyError, "this agentcookie build has no release pin; install a release build") {
				t.Fatalf("rec = %+v, want pairing with the no-pin reason", rec)
			}
			if len(h.hub.PendingPairings()) != 0 {
				t.Fatal("no pairing code may be live without a notice")
			}
			if got := strings.Count(h.log.String(), "no release pin"); got != 1 {
				t.Fatalf("no-pin reason logged %d times, want once:\n%s", got, h.log.String())
			}
		})
	}
}

func (h *lcHarness) saveKey(peer string) {
	h.t.Helper()
	if err := keystore.Save(h.dir, &keystore.PeerKey{Peer: peer, Key: bytes.Repeat([]byte{1}, 32), PairedAt: stepT0}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *lcHarness) hasKey(peer string) bool {
	_, err := keystore.Load(h.dir, peer)
	return err == nil
}

// A dropped paired event self-heals on the next sync.
func TestLifecycleDroppedPairedEventSelfHeals(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.now = h.now.Add(time.Minute)
	if err := h.hub.store.Update(func(st *state.TeammatesState) error {
		st.Teammate("grokbot").PairedAt = h.now
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	h.hub.CancelPairing("grokbot")
	h.lc.syncAll(context.Background())
	if rec := h.rec("grokbot"); rec.Phase != state.PhasePaired || rec.NotifyID != "" {
		t.Fatalf("rec = %+v, want paired after a dropped paired event", rec)
	}
}

// A new machine for a teammate drops the old machine's key with the old
// binding; keys of non-teammate peers are never touched.
func TestLifecycleNodeChangeDeletesOldKey(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.pairedNow()
	h.saveKey("grokbot")
	h.saveKey("muse-box")
	h.answer = false
	h.setRoster(grokEntry("nNEW", "grok-bot-2", time.Time{}))
	h.lc.syncAll(context.Background())
	h.answerDialog()
	if h.hasKey("grokbot") {
		t.Fatal("the old machine's key survived the node change")
	}
	if !h.hasKey("muse-box") {
		t.Fatal("a non-teammate peer's key was deleted")
	}
	// A quiet poll on the same new node deletes nothing else.
	h.saveKey("grokbot")
	h.lc.syncAll(context.Background())
	if !h.hasKey("grokbot") {
		t.Fatal("a key written after the node change was deleted without a further change")
	}
}

// A /pair that completes after the teammate's removal was processed
// leaves a stale key; the next sync deletes it. Non-teammate keys stay.
func TestLifecycleSyncDeletesStaleKeyOfRemovedTeammate(t *testing.T) {
	h := newLCHarness(t, "grokbot", "instinct")
	h.approved()
	h.writeList("instinct")
	if err := h.hub.Reload(); err != nil {
		t.Fatal(err)
	}
	h.lc.syncAll(context.Background())
	if rec := h.rec("grokbot"); rec.Phase != state.PhaseRemoved {
		t.Fatalf("phase = %q", rec.Phase)
	}
	h.saveKey("grokbot") // the mid-handshake /pair lands now
	h.saveKey("muse-box")
	h.lc.syncAll(context.Background())
	if h.hasKey("grokbot") {
		t.Fatal("a removed teammate's stale key survived a sync")
	}
	if !h.hasKey("muse-box") {
		t.Fatal("a non-teammate peer's key was deleted")
	}
}

// syncBuffer is a bytes.Buffer safe for a dialog goroutine to write while
// the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// No approval dialog (no GUI session, osascript failure): the owner gets
// a plain notice and a log line, both naming the approve command.
func TestLifecycleDialogErrorPostsApproveCommand(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	logBuf := &syncBuffer{}
	h.lc.log = logBuf
	approvalDialogFunc = func(context.Context, notify.ApprovalRequest) (bool, error) {
		return false, errors.New("no GUI session")
	}
	type notice struct{ title, body string }
	notices := make(chan notice, 1)
	ownerNoticeFunc = func(_ context.Context, title, body string) error {
		notices <- notice{title, body}
		return nil
	}
	h.setRoster(grokEntry("nGROK", "grok-bot", time.Time{}))
	h.lc.syncAll(context.Background())

	want := notify.ApproveCommand("grokbot", "nGROK")
	select {
	case n := <-notices:
		if !strings.Contains(n.body, want) || !strings.Contains(n.title, "grokbot") {
			t.Fatalf("notice = %+v, want it to name %q", n, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no fallback notice after the dialog failed")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logBuf.String(), "no approval dialog (no GUI session)") {
		if time.Now().After(deadline) {
			t.Fatalf("fallback log missing:\n%s", logBuf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logBuf.String(), "approve from a terminal: "+want) {
		t.Fatalf("fallback log does not name the approve command:\n%s", logBuf.String())
	}
	if rec := h.rec("grokbot"); rec.BoundNodeID != "" || rec.Phase != state.PhaseAwaitingApproval {
		t.Fatalf("a failed dialog must bind nothing: %+v", rec)
	}
}

// A transition whose state save fails stops: none of its actions run (the
// old machine's key stays, no dialog is shown), and teammate pulls and
// pairing are suspended rather than continuing on the stale binding.
func TestLifecycleFailedSaveStopsTransitionAndSuspends(t *testing.T) {
	h := newLCHarness(t, "grokbot")
	h.approved()
	h.pairedNow()
	if err := keystore.Save(h.dir, &keystore.PeerKey{Peer: "grokbot", Key: []byte("old-machine-key")}); err != nil {
		t.Fatal(err)
	}

	// Move the store onto a directory whose saves fail.
	stateDir := t.TempDir()
	statePath := filepath.Join(stateDir, "teammates-state.json")
	data, err := json.Marshal(h.hub.store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenTeammateStore(statePath)
	if err != nil {
		t.Fatal(err)
	}
	h.hub.store = store
	if err := os.Chmod(stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stateDir, 0o700) })

	dialogsBefore := h.dialogCount()
	h.setRoster(grokEntry("nNEW", "grok-bot-2", time.Time{}))
	h.lc.syncAll(context.Background())

	if _, err := keystore.Load(h.dir, "grokbot"); err != nil {
		t.Fatalf("a transition that was not saved deleted the key: %v", err)
	}
	if h.dialogCount() != dialogsBefore {
		t.Fatal("a transition that was not saved showed a dialog")
	}
	if h.hub.Suspended() == nil {
		t.Fatal("a failed required state save must suspend teammate access")
	}
	if d := h.hub.authorizeTeammatePull(httptestRequest(), "grokbot", "secret"); d.status == 0 {
		t.Fatal("pulls must be refused while teammate state cannot be saved")
	}
	if _, _, err := h.hub.MintPairing("grokbot", "nGROK"); err == nil {
		t.Fatal("pairing must be refused while teammate state cannot be saved")
	}
	// A teammates.yaml reload does not lift the suspension.
	_ = h.hub.Reload()
	if h.hub.Suspended() == nil {
		t.Fatal("a reload lifted the state-save suspension")
	}
}
