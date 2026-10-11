package cli

import (
	"errors"
	"time"

	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tincan"
)

// Teammate lifecycle timing (KTD4a, KTD6).
const (
	// repairInterval caps automatic re-pairs after a lost key.
	repairInterval = 6 * time.Hour
	// staleAfter is how long a paired teammate may go without a pull
	// (while cookies changed) before it gets a staleness notice.
	staleAfter = 6 * time.Hour
	// staleNotifyInterval caps staleness notices per teammate.
	staleNotifyInterval = 6 * time.Hour
	// notifyBackoffMin and notifyBackoffMax bound the retry delay after a
	// 429 or a failed send.
	notifyBackoffMin = time.Minute
	notifyBackoffMax = 30 * time.Minute
)

// tmEventKind is one observation the lifecycle reacts to.
type tmEventKind int

const (
	// evRoster: the roster was read; Agent/OnRoster say what it shows
	// for this name. CookiesChangedAt rides along for the staleness check.
	evRoster tmEventKind = iota + 1
	// evApprove: the owner approved NodeID (dialog or CLI).
	evApprove
	// evNotNow: the owner answered Not now for NodeID.
	evNotNow
	// evPaired: a /pair from the bound node completed.
	evPaired
	// evKeyLost: a keyless or failed-HMAC /pull came from NodeID.
	evKeyLost
	// evNotifyResult: a notify this lifecycle asked for was attempted.
	evNotifyResult
	// evHoldStatus: the relay's status of the held notify.
	evHoldStatus
	// evRemoved: the name is no longer listed.
	evRemoved
)

type tmEvent struct {
	Kind tmEventKind

	// evRoster
	OnRoster         bool
	Agent            tincan.Agent
	CookiesChangedAt time.Time

	// evApprove, evNotNow, evKeyLost
	NodeID string

	// evNotifyResult
	Purpose     string
	Result      tincan.SendResult
	CodeExpires time.Time

	// evHoldStatus
	Status string
}

// tmMem is per-teammate state that lives only as long as the daemon.
type tmMem struct {
	// DialogNode is the node an approval dialog was shown for in this
	// daemon run. Not now leaves it set, so the dialog does not repeat
	// until the daemon restarts or the node changes.
	DialogNode string
	// CodeLive: a minted pairing code for this teammate is still pending
	// in the hub. The driver sets it before every step.
	CodeLive bool
	// HoldReminted: the one re-mint after a hold was used.
	HoldReminted bool
	// Failures and BackoffUntil pace notify retries after 429 or errors.
	Failures     int
	BackoffUntil time.Time
}

// tmState is everything the transition function reads and writes.
type tmState struct {
	Rec state.TeammateRecord
	Mem tmMem
}

type tmActionKind int

const (
	// actDialog: show the approval dialog for the pending node.
	actDialog tmActionKind = iota + 1
	// actPairingNotify: mint a code for the bound node and send the
	// pairing notice; the driver answers with evNotifyResult.
	actPairingNotify
	// actStaleNotify: send the staleness notice; answered with
	// evNotifyResult.
	actStaleNotify
	// actCancelNotify: withdraw RequestID.
	actCancelNotify
	// actCancelPairing: drop the teammate's pending code.
	actCancelPairing
	// actDeleteKey: delete keys/<name>.json.
	actDeleteKey
	// actCheckHold: read RequestID's status; answered with evHoldStatus.
	actCheckHold
)

type tmAction struct {
	Kind      tmActionKind
	NodeID    string
	NodeName  string
	NodeUser  string
	Replaces  string
	RequestID string
}

// errApprovalStale refuses an approval for a node that is no longer the
// one awaiting approval.
var errApprovalStale = errors.New("the roster shows a different machine for this teammate now; nothing was approved")

// errNotAwaiting refuses an approval when no machine is waiting.
var errNotAwaiting = errors.New("no machine is waiting for approval for this teammate")

// stepTeammate is the teammate lifecycle as a pure function: given one
// teammate's state, one observed event and the time, it returns the next
// state, the side effects to run in order, and (for evApprove) why the
// approval was refused. The teammate lifecycle:
//
//	WaitingForNode -> AwaitingApproval -> Pairing <-> Held
//	Pairing -> Paired -> Pairing (lost key, at most every 6h)
//	Pairing/Held/Paired -> AwaitingApproval (roster shows a new node)
//	any -> Removed (name no longer listed)
func stepTeammate(s tmState, ev tmEvent, now time.Time) (tmState, []tmAction, error) {
	r, m := &s.Rec, &s.Mem
	var acts []tmAction

	if ev.Kind == evRemoved {
		if r.Phase == state.PhaseRemoved {
			return s, nil, nil
		}
		acts = append(acts, cancelOpenNotify(r)...)
		acts = append(acts, tmAction{Kind: actCancelPairing}, tmAction{Kind: actDeleteKey})
		r.Phase = state.PhaseRemoved
		unbind(r)
		clearPending(r)
		r.ReplacesNodeID, r.ReplacesNodeName = "", ""
		r.CodeExpiresAt, r.PairCodeMissedAt = time.Time{}, time.Time{}
		s.Mem = tmMem{}
		return s, acts, nil
	}
	if r.Phase == state.PhaseRemoved {
		// Listed again: start over; the binding was dropped on removal.
		r.Phase = ""
	}
	if r.Phase == "" && r.BoundNodeID != "" {
		// A binding from before the lifecycle tracked phases.
		r.Phase = state.PhasePairing
		if !r.PairedAt.IsZero() {
			r.Phase = state.PhasePaired
		}
	}

	switch ev.Kind {
	case evRoster:
		acts = stepRoster(r, m, ev, now)
	case evApprove:
		return stepApprove(s, ev, now)
	case evNotNow:
		// The dialog stays marked as shown for this node, so it does not
		// repeat until the daemon restarts or the node changes.
	case evPaired:
		if r.BoundNodeID == "" || ev.NodeID != r.BoundNodeID {
			break
		}
		r.Phase = state.PhasePaired
		r.PairCodeMissedAt = time.Time{}
		if r.NotifyPurpose == state.NotifyPurposePairing {
			acts = append(acts, cancelOpenNotify(r)...)
		}
		r.CodeExpiresAt = time.Time{}
		m.CodeLive, m.HoldReminted = false, false
	case evKeyLost:
		if r.Phase != state.PhasePaired || ev.NodeID == "" || ev.NodeID != r.BoundNodeID {
			break
		}
		if !r.LastRepairAt.IsZero() && now.Sub(r.LastRepairAt) < repairInterval {
			break
		}
		r.LastRepairAt = now
		r.Phase = state.PhasePairing
		acts = append(acts, pairingNotify(r)...)
	case evNotifyResult:
		stepNotifyResult(r, m, ev, now)
	case evHoldStatus:
		acts = stepHoldStatus(r, m, ev, now)
	}
	return s, acts, nil
}

func stepRoster(r *state.TeammateRecord, m *tmMem, ev tmEvent, now time.Time) []tmAction {
	var acts []tmAction
	nodeID := ""
	if ev.OnRoster {
		if ev.Agent.Kind != "" {
			r.Kind = ev.Agent.Kind
		}
		if seen := ev.Agent.LastSeen(); seen.After(r.RelaySeenAt) {
			r.RelaySeenAt = seen
		}
		nodeID = ev.Agent.NodeID
	}
	if nodeID == "" {
		// No machine on the roster (not yet, an older relay, or no admin
		// view). An existing binding is kept: only the owner unbinds.
		if r.BoundNodeID == "" {
			if r.Phase != state.PhaseAwaitingApproval {
				r.Phase = state.PhaseWaitingForNode
			}
			return nil
		}
		return maintain(r, m, ev, now)
	}
	if r.BoundNodeID != "" && nodeID != r.BoundNodeID {
		// A different machine now carries this name (rebuild). The old
		// binding stops at once; the new one needs the owner's approval.
		acts = append(acts, tmAction{Kind: actCancelPairing})
		acts = append(acts, cancelOpenNotify(r)...)
		r.ReplacesNodeID, r.ReplacesNodeName = r.BoundNodeID, r.BoundNodeName
		unbind(r)
		r.CodeExpiresAt = time.Time{}
		m.CodeLive, m.HoldReminted = false, false
	}
	if r.BoundNodeID == "" {
		r.Phase = state.PhaseAwaitingApproval
		r.PendingNodeID = nodeID
		r.PendingNodeName = ev.Agent.NodeName
		r.PendingNodeUser = ev.Agent.NodeUser
		if m.DialogNode != nodeID {
			m.DialogNode = nodeID
			acts = append(acts, dialogFor(r))
		}
		return acts
	}
	return maintain(r, m, ev, now)
}

// maintain runs the per-poll duties of a bound teammate: re-mint an
// expired code after the teammate polled, retry a failed send, check a
// held notify, and send a staleness notice.
func maintain(r *state.TeammateRecord, m *tmMem, ev tmEvent, now time.Time) []tmAction {
	switch r.Phase {
	case state.PhasePairing:
		if m.CodeLive || now.Before(m.BackoffUntil) {
			return nil
		}
		failed := r.NotifyStatus == state.NotifyRateLimited || r.NotifyStatus == state.NotifyError
		if r.NotifySentAt.IsZero() || failed || r.RelaySeenAt.After(r.NotifySentAt) {
			return pairingNotify(r)
		}
	case state.PhaseHeld:
		if r.NotifyID != "" {
			return []tmAction{{Kind: actCheckHold, RequestID: r.NotifyID}}
		}
		if !m.HoldReminted {
			// A hold that ended in an earlier daemon run gets its one
			// re-mint in this one.
			m.HoldReminted = true
			r.Phase = state.PhasePairing
			return pairingNotify(r)
		}
	case state.PhasePaired:
		if now.Before(m.BackoffUntil) {
			return nil
		}
		last := r.LastPulledAt
		if last.IsZero() {
			last = r.PairedAt
		}
		if last.IsZero() || now.Sub(last) <= staleAfter || !ev.CookiesChangedAt.After(last) {
			return nil
		}
		if !r.StaleNotifiedAt.IsZero() && now.Sub(r.StaleNotifiedAt) < staleNotifyInterval {
			return nil
		}
		acts := cancelOpenNotify(r)
		return append(acts, tmAction{Kind: actStaleNotify})
	}
	return nil
}

func stepApprove(s tmState, ev tmEvent, now time.Time) (tmState, []tmAction, error) {
	r, m := &s.Rec, &s.Mem
	if r.Phase != state.PhaseAwaitingApproval || r.PendingNodeID == "" {
		return s, nil, errNotAwaiting
	}
	if ev.NodeID != r.PendingNodeID {
		// The roster moved on since the owner saw the dialog: bind
		// nothing and show the machine that is there now.
		m.DialogNode = r.PendingNodeID
		return s, []tmAction{dialogFor(r)}, errApprovalStale
	}
	acts := cancelOpenNotify(r)
	r.BoundNodeID, r.BoundNodeName = r.PendingNodeID, r.PendingNodeName
	r.ApprovedAt = now
	r.PairedAt = time.Time{}
	clearPending(r)
	r.ReplacesNodeID, r.ReplacesNodeName = "", ""
	r.Phase = state.PhasePairing
	r.NotifyStatus, r.NotifyError, r.NotifySentAt = "", "", time.Time{}
	r.PairCodeMissedAt = time.Time{}
	s.Mem = tmMem{}
	acts = append(acts, pairingNotify(r)...)
	return s, acts, nil
}

func stepNotifyResult(r *state.TeammateRecord, m *tmMem, ev tmEvent, now time.Time) {
	res := ev.Result
	if ev.Purpose == state.NotifyPurposePairing && pairNoticeUnanswered(*r, now) {
		// This notice replaces one the teammate picked up and never
		// answered; keep that evidence for doctor's ACL diagnosis.
		r.PairCodeMissedAt = r.CodeExpiresAt
	}
	r.NotifyPurpose = ev.Purpose
	r.NotifyStatus = string(res.Outcome)
	switch res.Outcome {
	case tincan.OutcomeSent, tincan.OutcomeHeld:
		r.NotifyID = res.RequestID
		r.NotifySentAt = now
		r.NotifyError = ""
		m.Failures, m.BackoffUntil = 0, time.Time{}
		if ev.Purpose == state.NotifyPurposeStale {
			r.StaleNotifiedAt = now
			return
		}
		r.CodeExpiresAt = ev.CodeExpires
		m.CodeLive = true
		if res.Outcome == tincan.OutcomeHeld {
			r.Phase = state.PhaseHeld
		} else if r.Phase == state.PhaseHeld {
			r.Phase = state.PhasePairing
		}
	default:
		r.NotifyID = ""
		r.NotifySentAt = time.Time{}
		r.NotifyError = ""
		if res.Err != nil {
			r.NotifyError = res.Err.Error()
		}
		m.Failures++
		m.BackoffUntil = now.Add(notifyBackoff(m.Failures))
		if ev.Purpose == state.NotifyPurposePairing {
			r.CodeExpiresAt = time.Time{}
			m.CodeLive = false
		}
	}
}

func stepHoldStatus(r *state.TeammateRecord, m *tmMem, ev tmEvent, now time.Time) []tmAction {
	if r.Phase != state.PhaseHeld {
		return nil
	}
	switch ev.Status {
	case "", "held":
		return nil
	case "queued", "delivered", "claimed", "needs_input", "answered":
		// The owner released it: it reaches the teammate now. An expired
		// code is re-minted by the usual poll rule.
		r.Phase = state.PhasePairing
		r.NotifyStatus = state.NotifySent
		r.NotifySentAt = now
		return nil
	default:
		// The hold expired or was declined: re-mint once.
		r.NotifyID = ""
		r.NotifyStatus = state.NotifyHeld + "-" + ev.Status
		if m.HoldReminted {
			return nil
		}
		m.HoldReminted = true
		r.Phase = state.PhasePairing
		return pairingNotify(r)
	}
}

// pairNoticeUnanswered reports whether r's pairing notice reached the
// teammate (the roster shows it polled the relay after the notice was
// sent) and its code expired with no /pair attempt after the notice. A
// teammate that read its notice but never reached the laptop's /pair is
// most likely blocked by the tailnet ACL.
func pairNoticeUnanswered(r state.TeammateRecord, now time.Time) bool {
	return r.NotifyPurpose == state.NotifyPurposePairing && r.NotifyStatus == state.NotifySent &&
		!r.NotifySentAt.IsZero() && !r.CodeExpiresAt.IsZero() && !now.Before(r.CodeExpiresAt) &&
		r.RelaySeenAt.After(r.NotifySentAt) && !r.LastPairAttemptAt.After(r.NotifySentAt)
}

// pairingNotify cancels the open notify, then asks for a fresh code and
// pairing notice for the bound node.
func pairingNotify(r *state.TeammateRecord) []tmAction {
	acts := cancelOpenNotify(r)
	return append(acts, tmAction{Kind: actPairingNotify, NodeID: r.BoundNodeID, NodeName: r.BoundNodeName})
}

// cancelOpenNotify withdraws the open notify so at most one is open.
func cancelOpenNotify(r *state.TeammateRecord) []tmAction {
	if r.NotifyID == "" {
		return nil
	}
	id := r.NotifyID
	r.NotifyID = ""
	return []tmAction{{Kind: actCancelNotify, RequestID: id}}
}

func dialogFor(r *state.TeammateRecord) tmAction {
	return tmAction{Kind: actDialog, NodeID: r.PendingNodeID, NodeName: r.PendingNodeName, NodeUser: r.PendingNodeUser, Replaces: r.ReplacesNodeName}
}

func unbind(r *state.TeammateRecord) {
	r.BoundNodeID, r.BoundNodeName = "", ""
	r.ApprovedAt, r.PairedAt = time.Time{}, time.Time{}
}

func clearPending(r *state.TeammateRecord) {
	r.PendingNodeID, r.PendingNodeName, r.PendingNodeUser = "", "", ""
}

func notifyBackoff(failures int) time.Duration {
	d := notifyBackoffMin
	for i := 1; i < failures && d < notifyBackoffMax; i++ {
		d *= 2
	}
	return min(d, notifyBackoffMax)
}
