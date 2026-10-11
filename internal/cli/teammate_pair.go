package cli

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/pairing"
	"github.com/mvanhorn/agentcookie/internal/state"
)

// pairCodeTTL is how long a minted teammate pairing code stays valid.
const pairCodeTTL = 30 * time.Minute

// PendingPairing is one teammate pairing waiting for its /pair.
type PendingPairing struct {
	Name    string
	NodeID  string
	Expires time.Time
}

type pendingPair struct {
	PendingPairing
	code pairing.Code
}

// pendingPairings holds the in-memory minted codes, at most one per
// teammate. Several teammates can be pending at once.
type pendingPairings struct {
	mu     sync.Mutex
	byName map[string]*pendingPair
}

func newPendingPairings() *pendingPairings {
	return &pendingPairings{byName: make(map[string]*pendingPair)}
}

// open reports whether any unexpired pairing is pending, pruning expired
// entries as it goes.
func (p *pendingPairings) open(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, e := range p.byName {
		if !now.Before(e.Expires) {
			delete(p.byName, name)
		}
	}
	return len(p.byName) > 0
}

// match finds the pending entry whose code equals c (constant-time per
// entry). An expired match is removed and reported as expired.
func (p *pendingPairings) match(c pairing.Code, now time.Time) (pendingPair, bool, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, e := range p.byName {
		if e.code.Equal(c) {
			if !now.Before(e.Expires) {
				delete(p.byName, name)
				return pendingPair{}, false, true
			}
			return *e, true, false
		}
	}
	return pendingPair{}, false, false
}

// consume removes name's entry if it still carries code, making the code
// single-use even under concurrent /pair requests.
func (p *pendingPairings) consume(name string, code pairing.Code) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byName[name]
	if !ok || !e.code.Equal(code) {
		return false
	}
	delete(p.byName, name)
	return true
}

// MintPairing mints a fresh single-use pairing code for a listed teammate
// whose approved node is nodeID, replacing any code already pending for it,
// and opens /pair until it is used or expires (30 minutes). It is the entry
// point the teammate lifecycle calls after approval or on key loss.
func (h *teammateHub) MintPairing(name, nodeID string) (pairing.Code, time.Time, error) {
	if err := h.Suspended(); err != nil {
		return "", time.Time{}, fmt.Errorf("teammates suspended: %w", err)
	}
	if !h.IsListed(name) {
		return "", time.Time{}, fmt.Errorf("%s is not a listed teammate", name)
	}
	if nodeID == "" {
		return "", time.Time{}, errors.New("pairing needs the approved node StableID")
	}
	if rec, _ := h.store.Record(name); rec.BoundNodeID != nodeID {
		return "", time.Time{}, fmt.Errorf("%s is bound to node %q, not %q", name, rec.BoundNodeID, nodeID)
	}
	code, err := pairing.NewCode()
	if err != nil {
		return "", time.Time{}, err
	}
	now := h.now()
	expires := now.Add(pairCodeTTL)
	h.pairings.mu.Lock()
	h.pairings.byName[name] = &pendingPair{PendingPairing: PendingPairing{Name: name, NodeID: nodeID, Expires: expires}, code: code}
	h.pairings.mu.Unlock()
	err = h.store.Update(func(st *state.TeammatesState) error {
		st.Teammate(name).PairCodeMintedAt = now.UTC()
		return nil
	})
	if err != nil {
		fmt.Fprintf(h.log, "agentcookie source: teammates: %v\n", err)
	}
	return code, expires, nil
}

// CancelPairing drops name's pending code, if any.
func (h *teammateHub) CancelPairing(name string) {
	h.pairings.mu.Lock()
	defer h.pairings.mu.Unlock()
	delete(h.pairings.byName, name)
}

// PendingPairings lists unexpired pending pairings, sorted by name.
func (h *teammateHub) PendingPairings() []PendingPairing {
	now := h.now()
	h.pairings.open(now)
	h.pairings.mu.Lock()
	defer h.pairings.mu.Unlock()
	out := make([]PendingPairing, 0, len(h.pairings.byName))
	for _, e := range h.pairings.byName {
		out = append(out, e.PendingPairing)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// pairHandler serves POST /pair on the daemon's 9998 server (KTD7). It is
// a 404 unless a pairing is pending. A code is accepted only from the
// node it was minted for (WhoIs StableID), and the key is filed as
// keys/<teammate>.json.
func (h *teammateHub) pairHandler(localHostname string) http.Handler {
	inner := pairing.NewHandler(pairing.HandlerConfig{
		LocalHostname: localHostname,
		Authorize: func(r *http.Request, req *pairing.SinkRequest) (pairing.Code, string, error) {
			if err := h.Suspended(); err != nil {
				return "", "", &pairing.PairError{Status: http.StatusServiceUnavailable, Msg: "teammate pairing is suspended until teammates.yaml loads"}
			}
			p, ok, expired := h.pairings.match(pairing.Code(req.Code), h.now())
			if expired {
				return "", "", &pairing.PairError{Status: http.StatusUnauthorized, Msg: "pairing code expired"}
			}
			if !ok {
				return "", "", &pairing.PairError{Status: http.StatusUnauthorized, Msg: "invalid pairing code"}
			}
			if !h.IsListed(p.Name) {
				h.CancelPairing(p.Name)
				return "", "", &pairing.PairError{Status: http.StatusForbidden, Msg: "not a listed teammate"}
			}
			if rec, _ := h.store.Record(p.Name); rec.BoundNodeID != p.NodeID {
				h.CancelPairing(p.Name)
				return "", "", &pairing.PairError{Status: http.StatusForbidden, Msg: "teammate's approved machine changed"}
			}
			node, err := h.whois.lookup(r.Context(), remoteIP(r))
			if err != nil {
				return "", "", &pairing.PairError{Status: http.StatusForbidden, Msg: "cannot verify Tailscale node"}
			}
			if node.StableID != p.NodeID {
				fmt.Fprintf(h.log, "agentcookie source: security: /pair with %s's code came from node %s (%s), not its approved node %s; refused\n",
					p.Name, node.StableID, node.NodeName, p.NodeID)
				return "", "", &pairing.PairError{Status: http.StatusForbidden, Msg: "request is not from this teammate's approved machine"}
			}
			return p.code, p.Name, nil
		},
		Complete: func(name string, code pairing.Code, res *pairing.HandshakeResult) error {
			if !h.pairings.consume(name, code) {
				return &pairing.PairError{Status: http.StatusConflict, Msg: "pairing code already used"}
			}
			rec, _ := h.store.Record(name)
			err := keystore.Save(h.configDir, &keystore.PeerKey{
				Peer:        name,
				AnnouncedAs: res.RemotePeer,
				Key:         res.Key,
				PairedAt:    res.PairedAt.UTC(),
				Fingerprint: res.Fingerprint,
				ProtocolVer: pairing.ProtocolVersion,
			})
			if err != nil {
				return fmt.Errorf("store key for %s: %w", name, err)
			}
			now := h.now()
			if err := h.store.Update(func(st *state.TeammatesState) error {
				st.Teammate(name).PairedAt = now.UTC()
				return nil
			}); err != nil {
				fmt.Fprintf(h.log, "agentcookie source: teammates: %v\n", err)
			}
			fmt.Fprintf(h.log, "agentcookie source: teammate %s paired from node %s (fingerprint %s)\n", name, rec.BoundNodeID, res.Fingerprint)
			h.emit(TeammateEvent{Kind: TeammatePaired, Name: name, NodeID: rec.BoundNodeID, At: now})
			return nil
		},
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.pairings.open(h.now()) {
			http.NotFound(w, r)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
