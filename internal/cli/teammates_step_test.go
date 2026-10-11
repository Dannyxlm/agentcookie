package cli

import (
	"errors"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tincan"
)

var stepT0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func nodeAgent(id, name string) tincan.Agent {
	return tincan.Agent{Name: "grokbot", Kind: "vm-webhook", NodeID: id, NodeName: name, NodeUser: "tagged-devices"}
}

func rosterEv(a tincan.Agent) tmEvent { return tmEvent{Kind: evRoster, OnRoster: true, Agent: a} }

func mustStep(t *testing.T, s tmState, ev tmEvent, now time.Time) (tmState, []tmAction) {
	t.Helper()
	next, acts, err := stepTeammate(s, ev, now)
	if err != nil {
		t.Fatalf("step %v: %v", ev.Kind, err)
	}
	return next, acts
}

func kinds(acts []tmAction) []tmActionKind {
	out := make([]tmActionKind, len(acts))
	for i, a := range acts {
		out[i] = a.Kind
	}
	return out
}

func wantActs(t *testing.T, acts []tmAction, want ...tmActionKind) {
	t.Helper()
	got := kinds(acts)
	if len(got) != len(want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("actions = %v, want %v", got, want)
		}
	}
}

// pairedState is a teammate bound to nGROK and paired, with an open
// pairing notify r-1.
func pairedState() tmState {
	return tmState{Rec: state.TeammateRecord{
		Phase: state.PhasePaired, BoundNodeID: "nGROK", BoundNodeName: "grok-bot",
		ApprovedAt: stepT0, PairedAt: stepT0, LastPulledAt: stepT0,
	}}
}

// pairingState is a teammate bound to nGROK whose pairing notice r-1 was
// sent at stepT0 and whose code is live.
func pairingState() tmState {
	return tmState{
		Rec: state.TeammateRecord{
			Phase: state.PhasePairing, BoundNodeID: "nGROK", BoundNodeName: "grok-bot", ApprovedAt: stepT0,
			NotifyID: "r-1", NotifyPurpose: state.NotifyPurposePairing, NotifyStatus: state.NotifySent, NotifySentAt: stepT0,
			CodeExpiresAt: stepT0.Add(pairCodeTTL),
		},
		Mem: tmMem{CodeLive: true},
	}
}

// Covers R2: absent from the roster stays waiting with no notify; the
// first sighting moves to awaiting approval with exactly one dialog.
func TestStepWaitingThenFirstSighting(t *testing.T) {
	s, acts := mustStep(t, tmState{}, tmEvent{Kind: evRoster}, stepT0)
	if s.Rec.Phase != state.PhaseWaitingForNode {
		t.Fatalf("phase = %q", s.Rec.Phase)
	}
	wantActs(t, acts)

	// On the roster but without node fields (older relay, or not admin).
	s, acts = mustStep(t, s, rosterEv(tincan.Agent{Name: "grokbot", Kind: "vm-webhook"}), stepT0)
	if s.Rec.Phase != state.PhaseWaitingForNode {
		t.Fatalf("no node fields must stay waiting, phase = %q", s.Rec.Phase)
	}
	wantActs(t, acts)

	s, acts = mustStep(t, s, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0)
	if s.Rec.Phase != state.PhaseAwaitingApproval || s.Rec.PendingNodeID != "nGROK" || s.Rec.PendingNodeName != "grok-bot" || s.Rec.PendingNodeUser != "tagged-devices" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	if s.Rec.BoundNodeID != "" {
		t.Fatal("a sighting must never bind a node")
	}
	wantActs(t, acts, actDialog)
	if acts[0].NodeID != "nGROK" || acts[0].NodeName != "grok-bot" || acts[0].Replaces != "" {
		t.Fatalf("dialog = %+v", acts[0])
	}
	if s.Rec.Kind != "vm-webhook" {
		t.Fatalf("kind not recorded: %q", s.Rec.Kind)
	}

	// Later polls of the same node show no second dialog.
	s, acts = mustStep(t, s, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0.Add(10*time.Minute))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhaseAwaitingApproval {
		t.Fatalf("phase = %q", s.Rec.Phase)
	}
}

// Not now leaves the teammate waiting with no repeat dialog until the
// daemon restarts (fresh tmMem) or the node changes.
func TestStepNotNow(t *testing.T) {
	s, _ := mustStep(t, tmState{}, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0)
	s, acts := mustStep(t, s, tmEvent{Kind: evNotNow, NodeID: "nGROK"}, stepT0)
	wantActs(t, acts)
	if s.Rec.Phase != state.PhaseAwaitingApproval || s.Rec.BoundNodeID != "" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	for i := 1; i <= 3; i++ {
		s, acts = mustStep(t, s, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0.Add(time.Duration(i)*10*time.Minute))
		wantActs(t, acts)
	}

	restarted := tmState{Rec: s.Rec}
	_, acts = mustStep(t, restarted, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0.Add(time.Hour))
	wantActs(t, acts, actDialog)

	_, acts = mustStep(t, s, rosterEv(nodeAgent("nOTHER", "grok-bot-2")), stepT0.Add(time.Hour))
	wantActs(t, acts, actDialog)
	if acts[0].NodeID != "nOTHER" {
		t.Fatalf("dialog = %+v", acts[0])
	}
}

// Covers R6: approval binds the shown node and sends one pairing notify.
func TestStepApproveBindsShownNode(t *testing.T) {
	s, _ := mustStep(t, tmState{}, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0)
	s, acts := mustStep(t, s, tmEvent{Kind: evApprove, NodeID: "nGROK"}, stepT0.Add(time.Minute))
	if s.Rec.BoundNodeID != "nGROK" || s.Rec.BoundNodeName != "grok-bot" || !s.Rec.ApprovedAt.Equal(stepT0.Add(time.Minute)) {
		t.Fatalf("rec = %+v", s.Rec)
	}
	if s.Rec.Phase != state.PhasePairing || s.Rec.PendingNodeID != "" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	wantActs(t, acts, actPairingNotify)
	if acts[0].NodeID != "nGROK" {
		t.Fatalf("notify for %+v", acts[0])
	}

	// Approving again is refused: nothing is waiting.
	if _, _, err := stepTeammate(s, tmEvent{Kind: evApprove, NodeID: "nGROK"}, stepT0); !errors.Is(err, errNotAwaiting) {
		t.Fatalf("err = %v", err)
	}
}

// Covers R9: the roster's node changes between the dialog and Approve, so
// nothing is bound and a new dialog shows the new node.
func TestStepApproveRefusedWhenRosterChanged(t *testing.T) {
	s, acts := mustStep(t, tmState{}, rosterEv(nodeAgent("nOLD", "grok-bot")), stepT0)
	wantActs(t, acts, actDialog)
	// The roster moves to a new node before the owner answers.
	s, _ = mustStep(t, s, rosterEv(nodeAgent("nNEW", "grok-bot-2")), stepT0.Add(time.Minute))

	next, acts, err := stepTeammate(s, tmEvent{Kind: evApprove, NodeID: "nOLD"}, stepT0.Add(2*time.Minute))
	if !errors.Is(err, errApprovalStale) {
		t.Fatalf("err = %v, want errApprovalStale", err)
	}
	if next.Rec.BoundNodeID != "" || next.Rec.Phase != state.PhaseAwaitingApproval || next.Rec.PendingNodeID != "nNEW" {
		t.Fatalf("rec = %+v", next.Rec)
	}
	wantActs(t, acts, actDialog)
	if acts[0].NodeID != "nNEW" {
		t.Fatalf("dialog must show the new node: %+v", acts[0])
	}
}

// Pairing -> Paired: the pairing notify is closed.
func TestStepPairedClosesNotify(t *testing.T) {
	s, acts := mustStep(t, pairingState(), tmEvent{Kind: evPaired, NodeID: "nGROK"}, stepT0.Add(time.Minute))
	if s.Rec.Phase != state.PhasePaired || s.Rec.NotifyID != "" || s.Mem.CodeLive {
		t.Fatalf("state = %+v", s)
	}
	wantActs(t, acts, actCancelNotify)
	if acts[0].RequestID != "r-1" {
		t.Fatalf("cancel = %+v", acts[0])
	}
}

// Pairing -> Pairing: an expired code is re-minted only after the roster
// shows a poll by the teammate after the notify, and never goes back to
// approval. The prior notify is cancelled first (one open notify).
func TestStepExpiredCodeRemintedOnlyAfterPoll(t *testing.T) {
	s := pairingState()
	s.Mem.CodeLive = false // expired
	a := nodeAgent("nGROK", "grok-bot")
	a.LastPoll = stepT0.Add(-time.Hour) // polled before the notify
	s, acts := mustStep(t, s, rosterEv(a), stepT0.Add(40*time.Minute))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhasePairing {
		t.Fatalf("phase = %q", s.Rec.Phase)
	}

	a.LastPoll = stepT0.Add(45 * time.Minute) // polled after the notify
	s, acts = mustStep(t, s, rosterEv(a), stepT0.Add(50*time.Minute))
	wantActs(t, acts, actCancelNotify, actPairingNotify)
	if acts[0].RequestID != "r-1" || acts[1].NodeID != "nGROK" {
		t.Fatalf("acts = %+v", acts)
	}
	if s.Rec.Phase != state.PhasePairing || s.Rec.BoundNodeID != "nGROK" || s.Rec.NotifyID != "" {
		t.Fatalf("rec = %+v", s.Rec)
	}

	// The new notify is sent; the same old poll does not re-mint again.
	s, _ = mustStep(t, s, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposePairing,
		Result: tincan.SendResult{Outcome: tincan.OutcomeSent, RequestID: "r-2"}, CodeExpires: stepT0.Add(80 * time.Minute)}, stepT0.Add(50*time.Minute))
	if s.Rec.NotifyID != "r-2" || !s.Mem.CodeLive || !s.Rec.NotifySentAt.Equal(stepT0.Add(50*time.Minute)) {
		t.Fatalf("state = %+v", s)
	}
	s.Mem.CodeLive = false
	_, acts = mustStep(t, s, rosterEv(a), stepT0.Add(90*time.Minute))
	wantActs(t, acts)

	// A live code is never re-minted, whatever the roster shows.
	live := pairingState()
	a.LastPoll = stepT0.Add(5 * time.Minute)
	_, acts = mustStep(t, live, rosterEv(a), stepT0.Add(10*time.Minute))
	wantActs(t, acts)
}

// Covers R7: a key-lost signal from the bound node re-pairs with no
// dialog, and a second one within 6 hours does not.
func TestStepKeyLostRepairsAtMostEverySixHours(t *testing.T) {
	s, acts := mustStep(t, pairedState(), tmEvent{Kind: evKeyLost, NodeID: "nGROK"}, stepT0.Add(time.Hour))
	wantActs(t, acts, actPairingNotify)
	if s.Rec.Phase != state.PhasePairing || !s.Rec.LastRepairAt.Equal(stepT0.Add(time.Hour)) || s.Rec.BoundNodeID != "nGROK" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	// It pairs again, then loses its key again inside 6 hours.
	s, _ = mustStep(t, s, tmEvent{Kind: evPaired, NodeID: "nGROK"}, stepT0.Add(2*time.Hour))
	s, acts = mustStep(t, s, tmEvent{Kind: evKeyLost, NodeID: "nGROK"}, stepT0.Add(3*time.Hour))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhasePaired {
		t.Fatalf("phase = %q", s.Rec.Phase)
	}
	// After 6 hours it may re-pair again.
	_, acts = mustStep(t, s, tmEvent{Kind: evKeyLost, NodeID: "nGROK"}, stepT0.Add(7*time.Hour+time.Minute))
	wantActs(t, acts, actPairingNotify)

	// A key-lost signal from another node is ignored.
	_, acts = mustStep(t, pairedState(), tmEvent{Kind: evKeyLost, NodeID: "nOTHER"}, stepT0.Add(time.Hour))
	wantActs(t, acts)
}

// Covers R7: a roster node change on a paired teammate moves it back to
// awaiting approval with one dialog, and the old binding is dropped so its
// pulls stop.
func TestStepNodeChangeOnPaired(t *testing.T) {
	s := pairedState()
	s.Rec.NotifyID = "r-1"
	s, acts := mustStep(t, s, rosterEv(nodeAgent("nNEW", "grok-bot-2")), stepT0.Add(time.Hour))
	if s.Rec.Phase != state.PhaseAwaitingApproval || s.Rec.BoundNodeID != "" || !s.Rec.PairedAt.IsZero() {
		t.Fatalf("rec = %+v", s.Rec)
	}
	if s.Rec.PendingNodeID != "nNEW" || s.Rec.ReplacesNodeID != "nGROK" || s.Rec.ReplacesNodeName != "grok-bot" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	wantActs(t, acts, actCancelPairing, actCancelNotify, actDialog)
	if acts[2].NodeID != "nNEW" || acts[2].Replaces != "grok-bot" {
		t.Fatalf("dialog = %+v", acts[2])
	}
	_, acts = mustStep(t, s, rosterEv(nodeAgent("nNEW", "grok-bot-2")), stepT0.Add(2*time.Hour))
	wantActs(t, acts)

	// Approving the new node binds it and pairs.
	s, acts = mustStep(t, s, tmEvent{Kind: evApprove, NodeID: "nNEW"}, stepT0.Add(2*time.Hour))
	wantActs(t, acts, actPairingNotify)
	if s.Rec.BoundNodeID != "nNEW" || s.Rec.ReplacesNodeID != "" {
		t.Fatalf("rec = %+v", s.Rec)
	}
}

// Pairing -> AwaitingApproval on a node change.
func TestStepNodeChangeWhilePairing(t *testing.T) {
	s, acts := mustStep(t, pairingState(), rosterEv(nodeAgent("nNEW", "grok-bot-2")), stepT0.Add(time.Minute))
	if s.Rec.Phase != state.PhaseAwaitingApproval || s.Rec.BoundNodeID != "" || s.Mem.CodeLive {
		t.Fatalf("state = %+v", s)
	}
	wantActs(t, acts, actCancelPairing, actCancelNotify, actDialog)
}

// Node fields vanishing (relay downgraded) never unbinds a teammate.
func TestStepNodeFieldsVanishKeepsBinding(t *testing.T) {
	s, acts := mustStep(t, pairedState(), rosterEv(tincan.Agent{Name: "grokbot"}), stepT0.Add(time.Minute))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhasePaired || s.Rec.BoundNodeID != "nGROK" {
		t.Fatalf("rec = %+v", s.Rec)
	}
}

// Pairing -> Held: no resend while held; status shows held.
func TestStepHeldNoResend(t *testing.T) {
	s := pairingState()
	s.Rec.NotifyID = ""
	s, acts := mustStep(t, s, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposePairing,
		Result: tincan.SendResult{Outcome: tincan.OutcomeHeld, RequestID: "r-h"}, CodeExpires: stepT0.Add(pairCodeTTL)}, stepT0)
	wantActs(t, acts)
	if s.Rec.Phase != state.PhaseHeld || s.Rec.NotifyStatus != state.NotifyHeld || s.Rec.NotifyID != "r-h" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	// Code expires and the teammate polls: still no resend, only a hold check.
	s.Mem.CodeLive = false
	a := nodeAgent("nGROK", "grok-bot")
	a.LastPoll = stepT0.Add(time.Hour)
	s, acts = mustStep(t, s, rosterEv(a), stepT0.Add(time.Hour))
	wantActs(t, acts, actCheckHold)
	if acts[0].RequestID != "r-h" {
		t.Fatalf("check = %+v", acts[0])
	}
	s, acts = mustStep(t, s, tmEvent{Kind: evHoldStatus, Status: "held"}, stepT0.Add(time.Hour))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhaseHeld {
		t.Fatalf("phase = %q", s.Rec.Phase)
	}
}

// Held -> Pairing when the owner releases the hold: no new notify, the
// release counts as the delivery time for the expired-code rule.
func TestStepHoldReleased(t *testing.T) {
	s := pairingState()
	s.Rec.Phase, s.Rec.NotifyStatus, s.Rec.NotifyID = state.PhaseHeld, state.NotifyHeld, "r-h"
	s, acts := mustStep(t, s, tmEvent{Kind: evHoldStatus, Status: "queued"}, stepT0.Add(time.Hour))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhasePairing || s.Rec.NotifyStatus != state.NotifySent || !s.Rec.NotifySentAt.Equal(stepT0.Add(time.Hour)) {
		t.Fatalf("rec = %+v", s.Rec)
	}
}

// Held -> Pairing when the hold expires: the code is re-minted once; a
// second expired hold leaves it held with no further resend.
func TestStepHoldExpiredRemintsOnce(t *testing.T) {
	s := pairingState()
	s.Rec.Phase, s.Rec.NotifyStatus, s.Rec.NotifyID = state.PhaseHeld, state.NotifyHeld, "r-h"
	s.Mem.CodeLive = false
	s, acts := mustStep(t, s, tmEvent{Kind: evHoldStatus, Status: "expired"}, stepT0.Add(2*time.Hour))
	wantActs(t, acts, actPairingNotify)
	if s.Rec.Phase != state.PhasePairing || !s.Mem.HoldReminted {
		t.Fatalf("state = %+v", s)
	}
	s, _ = mustStep(t, s, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposePairing,
		Result: tincan.SendResult{Outcome: tincan.OutcomeHeld, RequestID: "r-h2"}}, stepT0.Add(2*time.Hour))
	s.Mem.CodeLive = false
	s, acts = mustStep(t, s, tmEvent{Kind: evHoldStatus, Status: "expired"}, stepT0.Add(4*time.Hour))
	wantActs(t, acts)
	if s.Rec.Phase != state.PhaseHeld || s.Rec.NotifyID != "" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	a := nodeAgent("nGROK", "grok-bot")
	a.LastPoll = stepT0.Add(5 * time.Hour)
	_, acts = mustStep(t, s, rosterEv(a), stepT0.Add(5*time.Hour))
	wantActs(t, acts)
}

// A 429 backs off; a relay error retries later; neither sends again
// before the backoff passes.
func TestStepNotifyBackoff(t *testing.T) {
	for _, outcome := range []tincan.Outcome{tincan.OutcomeRateLimited, tincan.OutcomeError} {
		t.Run(string(outcome), func(t *testing.T) {
			s := pairingState()
			s.Rec.NotifyID, s.Rec.NotifySentAt = "", time.Time{}
			s.Mem.CodeLive = false
			s, acts := mustStep(t, s, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposePairing,
				Result: tincan.SendResult{Outcome: outcome, Err: errors.New("boom")}}, stepT0)
			wantActs(t, acts)
			if s.Rec.NotifyStatus != string(outcome) || s.Rec.NotifyError != "boom" || !s.Mem.BackoffUntil.After(stepT0) {
				t.Fatalf("state = %+v", s)
			}
			a := nodeAgent("nGROK", "grok-bot")
			_, acts = mustStep(t, s, rosterEv(a), stepT0.Add(30*time.Second))
			wantActs(t, acts)
			s, acts = mustStep(t, s, rosterEv(a), s.Mem.BackoffUntil)
			wantActs(t, acts, actPairingNotify)
			// A second failure backs off longer.
			first := notifyBackoffMin
			s, _ = mustStep(t, s, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposePairing,
				Result: tincan.SendResult{Outcome: outcome, Err: errors.New("boom")}}, stepT0.Add(time.Hour))
			if got := s.Mem.BackoffUntil.Sub(stepT0.Add(time.Hour)); got <= first {
				t.Fatalf("second backoff %v not longer than %v", got, first)
			}
		})
	}
}

// Covers KTD6: the staleness notify fires once when the last pull is over
// 6 hours old and cookies changed since, and not again inside 6 hours.
func TestStepStaleNotify(t *testing.T) {
	s := pairedState()
	a := nodeAgent("nGROK", "grok-bot")
	ev := rosterEv(a)

	// Over 6h, but cookies have not changed since the last pull.
	ev.CookiesChangedAt = stepT0.Add(-time.Minute)
	_, acts := mustStep(t, s, ev, stepT0.Add(7*time.Hour))
	wantActs(t, acts)

	// Cookies changed, but the last pull is recent.
	ev.CookiesChangedAt = stepT0.Add(time.Hour)
	_, acts = mustStep(t, s, ev, stepT0.Add(2*time.Hour))
	wantActs(t, acts)

	s.Rec.NotifyID = "r-1" // an open notify is cancelled first
	s, acts = mustStep(t, s, ev, stepT0.Add(7*time.Hour))
	wantActs(t, acts, actCancelNotify, actStaleNotify)
	s, _ = mustStep(t, s, tmEvent{Kind: evNotifyResult, Purpose: state.NotifyPurposeStale,
		Result: tincan.SendResult{Outcome: tincan.OutcomeSent, RequestID: "r-s"}}, stepT0.Add(7*time.Hour))
	if !s.Rec.StaleNotifiedAt.Equal(stepT0.Add(7*time.Hour)) || s.Rec.NotifyID != "r-s" || s.Rec.Phase != state.PhasePaired {
		t.Fatalf("rec = %+v", s.Rec)
	}
	_, acts = mustStep(t, s, ev, stepT0.Add(12*time.Hour))
	wantActs(t, acts)
	_, acts = mustStep(t, s, ev, stepT0.Add(13*time.Hour))
	wantActs(t, acts, actCancelNotify, actStaleNotify)
}

// Paired -> [*]: removal deletes the key, drops any pending code, cancels
// the open notify, and forgets the binding.
func TestStepRemoved(t *testing.T) {
	s := pairedState()
	s.Rec.NotifyID = "r-1"
	s, acts := mustStep(t, s, tmEvent{Kind: evRemoved}, stepT0.Add(time.Hour))
	wantActs(t, acts, actCancelNotify, actCancelPairing, actDeleteKey)
	if s.Rec.Phase != state.PhaseRemoved || s.Rec.BoundNodeID != "" || s.Rec.NotifyID != "" {
		t.Fatalf("rec = %+v", s.Rec)
	}
	_, acts = mustStep(t, s, tmEvent{Kind: evRemoved}, stepT0.Add(2*time.Hour))
	wantActs(t, acts)

	// Listed again: it needs a fresh approval.
	s, acts = mustStep(t, s, rosterEv(nodeAgent("nGROK", "grok-bot")), stepT0.Add(3*time.Hour))
	wantActs(t, acts, actDialog)
	if s.Rec.Phase != state.PhaseAwaitingApproval {
		t.Fatalf("phase = %q", s.Rec.Phase)
	}
}
