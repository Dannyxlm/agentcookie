package cli

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mvanhorn/agentcookie/internal/pairing"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/transport"
	"github.com/mvanhorn/agentcookie/internal/tsclient"
)

// whoIsFunc resolves a remote tailnet IP to its Tailscale node. Production
// shells to `tailscale whois`; tests replace it with SetWhoIsForTesting.
var whoIsFunc = tsclient.WhoIs

// SetWhoIsForTesting replaces the WhoIs resolver and returns a restore
// func. Test-only seam.
func SetWhoIsForTesting(f func(ctx context.Context, ip string) (*tsclient.WhoIsResult, error)) func() {
	prev := whoIsFunc
	whoIsFunc = f
	return func() { whoIsFunc = prev }
}

// whoisCacheTTL bounds how long a remote IP's node identity is trusted
// without asking Tailscale again.
const whoisCacheTTL = 5 * time.Minute

// whoisErrorTTL bounds how long a failed lookup for a remote IP is
// remembered. A failure still fails closed; this only stops a burst of
// requests from one IP shelling out to `tailscale whois` each time.
const whoisErrorTTL = 15 * time.Second

type whoisEntry struct {
	res *tsclient.WhoIsResult
	err error
	at  time.Time
}

// whoisCache memoizes WhoIs answers per remote IP: a success for
// whoisCacheTTL, an error for whoisErrorTTL.
type whoisCache struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]whoisEntry
}

func newWhoisCache(now func() time.Time) *whoisCache {
	return &whoisCache{now: now, entries: make(map[string]whoisEntry)}
}

// clear forgets every cached answer, failures included.
func (c *whoisCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]whoisEntry)
}

func (c *whoisCache) lookup(ctx context.Context, ip string) (*tsclient.WhoIsResult, error) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[ip]; ok {
		if e.err != nil && now.Sub(e.at) < whoisErrorTTL {
			c.mu.Unlock()
			return nil, e.err
		}
		if e.err == nil && now.Sub(e.at) < whoisCacheTTL {
			c.mu.Unlock()
			return e.res, nil
		}
	}
	c.mu.Unlock()
	res, err := whoIsFunc(ctx, ip)
	if err == nil && (res == nil || res.StableID == "") {
		err = fmt.Errorf("whois %s: no node StableID", ip)
	}
	if err != nil {
		// A canceled or timed-out request says nothing about the IP, so
		// only a failure under a live context is remembered.
		if ctx.Err() == nil {
			c.mu.Lock()
			c.entries[ip] = whoisEntry{err: err, at: now}
			c.mu.Unlock()
		}
		return nil, err
	}
	c.mu.Lock()
	c.entries[ip] = whoisEntry{res: res, at: now}
	c.mu.Unlock()
	return res, nil
}

// TeammateEventKind names a teammate event the lifecycle consumes.
type TeammateEventKind string

const (
	// TeammateKeyLost: a keyless or failed-HMAC /pull came from a paired
	// teammate's bound node, so that machine lost its key (KTD4a). The
	// lifecycle answers with a silent re-pair, rate-limited per teammate.
	TeammateKeyLost TeammateEventKind = "key_lost"
	// TeammatePaired: a /pair from the bound node completed and
	// keys/<name>.json was written.
	TeammatePaired TeammateEventKind = "paired"
)

// TeammateEvent is one event on teammateHub.Events().
type TeammateEvent struct {
	Kind       TeammateEventKind
	Name       string
	NodeID     string
	RemoteAddr string
	At         time.Time
}

// teammateEventBuffer is the Events() channel capacity. Sends never block a
// request handler; an event that does not fit is dropped and logged.
const teammateEventBuffer = 32

// Events returns the channel the teammate lifecycle reads key-lost and
// paired events from.
func (h *teammateHub) Events() <-chan TeammateEvent { return h.events }

func (h *teammateHub) emit(ev TeammateEvent) {
	select {
	case h.events <- ev:
	default:
		fmt.Fprintf(h.log, "agentcookie source: teammate event queue full; dropped %s for %s\n", ev.Kind, ev.Name)
	}
}

// pullDecision is the outcome of authorizing one GET /pull. status 0 means
// allowed: the envelope is sealed with secret and served runs afterwards.
type pullDecision struct {
	secret string
	status int
	msg    string
	served func()
}

type pullAuth interface {
	authorizePull(r *http.Request) pullDecision
}

type pullAuthFunc func(r *http.Request) pullDecision

func (f pullAuthFunc) authorizePull(r *http.Request) pullDecision { return f(r) }

func denyPull(status int, msg string) pullDecision { return pullDecision{status: status, msg: msg} }

// legacySecretsAuth is the pre-teammate rule: any listed secret may pull.
func legacySecretsAuth(secrets func() []string) pullAuth {
	return pullAuthFunc(func(r *http.Request) pullDecision {
		var list []string
		if secrets != nil {
			list = secrets()
		}
		matched, err := transport.VerifyRequestAny(r, list, time.Now(), 0)
		if err != nil {
			return denyPull(http.StatusUnauthorized, "unauthorized")
		}
		return pullDecision{secret: matched}
	})
}

// pullAuthorizer authorizes GET /pull per KTD8. A matched key resolves to a
// peer name. A teammate name must be listed, not suspended, and calling
// from its bound Tailscale node. Any other paired peer keeps today's
// behavior. The legacy shared secret is refused once teammates exist.
// With no teammates.yaml it reduces exactly to legacySecretsAuth.
type pullAuthorizer struct {
	configDir string
	legacy    string
	hub       *teammateHub
}

func newPullAuthorizer(configDir, legacy string, hub *teammateHub) *pullAuthorizer {
	return &pullAuthorizer{configDir: configDir, legacy: legacy, hub: hub}
}

func (a *pullAuthorizer) authorizePull(r *http.Request) pullDecision {
	peers := pullAuthPeers(a.configDir, a.legacy)
	secrets := make([]string, len(peers))
	for i, p := range peers {
		secrets[i] = p.secret
	}
	matched, err := transport.VerifyRequestAny(r, secrets, time.Now(), 0)
	if err != nil {
		a.hub.checkKeyLost(r)
		return denyPull(http.StatusUnauthorized, "unauthorized")
	}
	var peer peerSecret
	for _, p := range peers {
		if p.secret == matched {
			peer = p
			break
		}
	}
	if peer.legacy {
		if a.hub.Active() {
			fmt.Fprintf(a.hub.log, "agentcookie source: refused /pull with the legacy shared secret from %s: teammates are configured\n", r.RemoteAddr)
			return denyPull(http.StatusForbidden, "legacy shared secret is not accepted while teammates are configured")
		}
		return pullDecision{secret: matched}
	}
	if a.hub.Unclassifiable() {
		fmt.Fprintf(a.hub.log, "agentcookie source: refused /pull with %s's key from %s: teammate state is unavailable, so it cannot be told apart from a teammate\n", peer.name, r.RemoteAddr)
		return denyPull(http.StatusForbidden, "teammate state is unavailable; pulls are refused until it loads")
	}
	if !a.hub.IsTeammateName(peer.name) {
		return pullDecision{secret: matched}
	}
	return a.hub.authorizeTeammatePull(r, peer.name, matched)
}

// authorizeTeammatePull applies the teammate rules for name, whose key
// already verified.
func (h *teammateHub) authorizeTeammatePull(r *http.Request, name, secret string) pullDecision {
	if err := h.Suspended(); err != nil {
		h.recordPull(name, "teammate pulls suspended: "+err.Error())
		return denyPull(http.StatusForbidden, "teammate pulls are suspended until teammates.yaml loads")
	}
	if !h.IsListed(name) {
		h.recordPull(name, "refused: not a listed teammate")
		return denyPull(http.StatusForbidden, "not a listed teammate")
	}
	rec, _ := h.store.Record(name)
	if rec.BoundNodeID == "" {
		h.recordPull(name, "refused: machine not approved yet")
		return denyPull(http.StatusForbidden, "teammate machine not approved")
	}
	node, err := h.whois.lookup(r.Context(), pairing.ClientIP(r))
	if err != nil {
		h.recordPull(name, "refused: cannot verify Tailscale node: "+err.Error())
		return denyPull(http.StatusForbidden, "cannot verify Tailscale node")
	}
	if node.StableID != rec.BoundNodeID {
		fmt.Fprintf(h.log, "agentcookie source: security: /pull with %s's key came from node %s (%s), not its bound node %s; refused\n",
			name, node.StableID, node.NodeName, rec.BoundNodeID)
		h.recordPull(name, fmt.Sprintf("refused: request from node %s, bound to %s", node.StableID, rec.BoundNodeID))
		return denyPull(http.StatusForbidden, "request is not from this teammate's approved machine")
	}
	return pullDecision{secret: secret, served: func() { h.recordPull(name, "") }}
}

// recordPull stores a pull outcome: errMsg "" records a served pull.
func (h *teammateHub) recordPull(name, errMsg string) {
	if h.store == nil {
		return
	}
	now := h.now().UTC()
	err := h.store.Update(func(st *state.TeammatesState) error {
		r := st.Teammate(name)
		if errMsg == "" {
			r.LastPulledAt = now
			r.LastPullError = ""
			r.LastPullErrorAt = time.Time{}
		} else {
			r.LastPullError = errMsg
			r.LastPullErrorAt = now
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(h.log, "agentcookie source: teammates: %v\n", err)
	}
}

// checkKeyLost raises TeammateKeyLost when an unauthenticated /pull comes
// from the bound node of a listed, paired teammate. Two agents may share
// one machine, so the teammate is the one the X-Agentcookie-Teammate
// header names (it must be bound and paired to the caller's node); with no
// header it is the only paired teammate bound to that node, and with
// several nothing is raised. It never asks Tailscale unless a paired
// teammate exists.
func (h *teammateHub) checkKeyLost(r *http.Request) {
	if !h.Active() || h.Suspended() != nil || h.store == nil {
		return
	}
	snap := h.store.Snapshot()
	bound := map[string][]string{} // node -> paired teammates bound to it
	for name, rec := range snap.Teammates {
		if rec.BoundNodeID != "" && !rec.PairedAt.IsZero() && h.IsListed(name) {
			bound[rec.BoundNodeID] = append(bound[rec.BoundNodeID], name)
		}
	}
	if len(bound) == 0 {
		return
	}
	node, err := h.whois.lookup(r.Context(), pairing.ClientIP(r))
	if err != nil {
		return
	}
	names := bound[node.StableID]
	if len(names) == 0 {
		return
	}
	name := ""
	if claimed := strings.TrimSpace(r.Header.Get(teammateHeader)); claimed != "" {
		if !slices.Contains(names, claimed) {
			fmt.Fprintf(h.log, "agentcookie source: keyless /pull from node %s names %q, which is not a paired teammate bound to that node; no re-pair\n", node.StableID, claimed)
			return
		}
		name = claimed
	} else if len(names) == 1 {
		name = names[0]
	} else {
		sort.Strings(names)
		fmt.Fprintf(h.log, "agentcookie source: keyless /pull from node %s, which several teammates share (%s), names no teammate; no re-pair (update agentcookie on that machine so its pulls send %s)\n",
			node.StableID, strings.Join(names, ", "), teammateHeader)
		return
	}
	h.emit(TeammateEvent{Kind: TeammateKeyLost, Name: name, NodeID: node.StableID, RemoteAddr: r.RemoteAddr, At: h.now()})
}
