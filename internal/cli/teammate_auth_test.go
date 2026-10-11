package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/transport"
	"github.com/mvanhorn/agentcookie/internal/tsclient"
)

const (
	grokIP      = "100.64.0.5"
	strangerIP  = "100.64.0.9"
	grokNode    = "nGROKBOT"
	otherNode   = "nSTRANGER"
	grokKey     = "grokbot-paired-key-32-bytes-long"
	legacyKey   = "legacy-shared-secret-32-bytes-xx"
	musePeer    = "muse-box"
	museKey     = "muse-box-paired-key-32-bytes-lng"
	testEnvJSON = `{"protocol_version":2,"source_hostname":"mac","sequence":7}`
)

// fakeWhoIs answers WhoIs from a table and counts calls. An IP mapped to
// an error answers with it.
type fakeWhoIs struct {
	mu    sync.Mutex
	nodes map[string]string
	errs  map[string]error
	calls atomic.Int32
}

func installFakeWhoIs(t *testing.T) *fakeWhoIs {
	t.Helper()
	f := &fakeWhoIs{nodes: map[string]string{grokIP: grokNode, strangerIP: otherNode}, errs: map[string]error{}}
	restore := SetWhoIsForTesting(func(_ context.Context, ip string) (*tsclient.WhoIsResult, error) {
		f.calls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if err, ok := f.errs[ip]; ok {
			return nil, err
		}
		id, ok := f.nodes[ip]
		if !ok {
			return nil, errors.New("no such node")
		}
		return &tsclient.WhoIsResult{StableID: id, NodeName: ip + ".ts.net."}, nil
	})
	t.Cleanup(restore)
	return f
}

type authFixture struct {
	dir   string
	hub   *teammateHub
	whois *fakeWhoIs
	cache *pullCache
	h     http.Handler
}

// newAuthFixture lists teammates (empty body = no teammates.yaml), pairs
// grokbot and muse-box keys, and binds grokbot to grokNode.
func newAuthFixture(t *testing.T, teammatesYAML string) *authFixture {
	t.Helper()
	dir := t.TempDir()
	withConfigDir(t, dir)
	if teammatesYAML != "" {
		writeTeammatesFile(t, dir, teammatesYAML)
	}
	for peer, key := range map[string]string{"grokbot": grokKey, musePeer: museKey} {
		if err := keystore.Save(dir, &keystore.PeerKey{Peer: peer, Key: []byte(key)}); err != nil {
			t.Fatal(err)
		}
	}
	hub, _ := newTestHub(t, dir)
	if err := hub.Reload(); err != nil {
		t.Fatal(err)
	}
	if teammatesYAML != "" {
		bindTeammate(t, hub, "grokbot", grokNode, true)
	}
	cache := newPullCache()
	cache.Store([]byte(testEnvJSON))
	return &authFixture{
		dir:   dir,
		hub:   hub,
		whois: installFakeWhoIs(t),
		cache: cache,
		h:     newPullHandlerWithAuth(cache, newPullAuthorizer(dir, legacyKey, hub)),
	}
}

func bindTeammate(t *testing.T, hub *teammateHub, name, node string, paired bool) {
	t.Helper()
	err := hub.store.Update(func(st *state.TeammatesState) error {
		r := st.Teammate(name)
		r.BoundNodeID = node
		r.ApprovedAt = time.Now()
		if paired {
			r.PairedAt = time.Now()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *authFixture) pull(t *testing.T, key, ip string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/pull", nil)
	req.RemoteAddr = ip + ":41000"
	if key != "" {
		if err := transport.SignRequest(req, key, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

// Covers R9: a listed teammate's key from its bound node gets the envelope
// and updates last_pulled_at.
func TestTeammatePullFromBoundNodeServesEnvelope(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	rec := f.pull(t, grokKey, grokIP)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	got, err := transport.OpenWithSecret(rec.Body.Bytes(), grokKey)
	if err != nil || string(got) != testEnvJSON {
		t.Fatalf("envelope = %q, err=%v", got, err)
	}
	r, _ := f.hub.store.Record("grokbot")
	if r.LastPulledAt.IsZero() || r.LastPullError != "" {
		t.Fatalf("pull not recorded: %+v", r)
	}
}

// Covers R9: the same key from a different node is refused, with a
// security event logged and the error recorded.
func TestTeammatePullFromOtherNodeRefused(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	var logBuf strings.Builder
	f.hub.log = &logBuf
	rec := f.pull(t, grokKey, strangerIP)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(logBuf.String(), "security") || !strings.Contains(logBuf.String(), otherNode) {
		t.Fatalf("security event not logged: %q", logBuf.String())
	}
	r, _ := f.hub.store.Record("grokbot")
	if r.LastPullError == "" || !r.LastPulledAt.IsZero() {
		t.Fatalf("refusal not recorded: %+v", r)
	}
}

func TestTeammatePullBeforeApprovalRefused(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n  - name: dot\n")
	if err := keystore.Save(f.dir, &keystore.PeerKey{Peer: "dot", Key: []byte("dot-key-32-bytes-long-xxxxxxxxxx")}); err != nil {
		t.Fatal(err)
	}
	f.whois.nodes["100.64.0.7"] = "nDOT"
	if rec := f.pull(t, "dot-key-32-bytes-long-xxxxxxxxxx", "100.64.0.7"); rec.Code != http.StatusForbidden {
		t.Fatalf("unbound teammate status = %d, want 403", rec.Code)
	}
}

// Covers R8: a teammate removed from the file is refused on its next pull,
// and its key does not fall back to the non-teammate path.
func TestRemovedTeammateRefusedNoFallback(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n  - name: dot\n")
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusOK {
		t.Fatalf("baseline status = %d", rec.Code)
	}
	writeTeammatesFile(t, f.dir, "teammates:\n  - name: dot\n")
	if err := f.hub.Reload(); err != nil {
		t.Fatal(err)
	}
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusForbidden {
		t.Fatalf("removed teammate status = %d, want 403", rec.Code)
	}
}

// Covers R8 / KTD5: a broken edit suspends every teammate pull.
func TestSuspendedTeammatesRefused(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	writeTeammatesFile(t, f.dir, "teammates:\n  - name: [\n")
	_ = f.hub.Reload()
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusForbidden {
		t.Fatalf("suspended status = %d, want 403", rec.Code)
	}
}

func TestLegacySharedSecretRefusedOnceTeammatesExist(t *testing.T) {
	f := newAuthFixture(t, "")
	if rec := f.pull(t, legacyKey, strangerIP); rec.Code != http.StatusOK {
		t.Fatalf("without teammates the legacy secret still pulls, got %d", rec.Code)
	}
	f = newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	if rec := f.pull(t, legacyKey, strangerIP); rec.Code != http.StatusForbidden {
		t.Fatalf("legacy secret with teammates status = %d, want 403", rec.Code)
	}
}

func TestTeammatePullWhoIsErrorFailsClosed(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	f.whois.errs[grokIP] = errors.New("tailscaled not running")
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusForbidden {
		t.Fatalf("WhoIs error status = %d, want 403", rec.Code)
	}
}

func TestTeammateWhoIsCachedPerIPForFiveMinutes(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	now := time.Now()
	f.hub.now = func() time.Time { return now }
	for range 3 {
		if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	}
	if n := f.whois.calls.Load(); n != 1 {
		t.Fatalf("WhoIs calls = %d, want 1 (cached)", n)
	}
	now = now.Add(5*time.Minute + time.Second)
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if n := f.whois.calls.Load(); n != 2 {
		t.Fatalf("WhoIs calls after expiry = %d, want 2", n)
	}
}

// Covers R7 / KTD4a: a keyless /pull from a paired teammate's bound node
// returns 401 and raises key-lost once; from any other node it raises
// nothing.
func TestKeylessPullFromBoundNodeRaisesKeyLost(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	if rec := f.pull(t, "", grokIP); rec.Code != http.StatusUnauthorized {
		t.Fatalf("keyless status = %d, want 401", rec.Code)
	}
	select {
	case ev := <-f.hub.Events():
		if ev.Kind != TeammateKeyLost || ev.Name != "grokbot" || ev.NodeID != grokNode {
			t.Fatalf("event = %+v", ev)
		}
	default:
		t.Fatal("no key-lost event raised")
	}
	if rec := f.pull(t, "wrong-key-32-bytes-long-xxxxxxxx", grokIP); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-HMAC status = %d, want 401", rec.Code)
	}
	if ev := <-f.hub.Events(); ev.Kind != TeammateKeyLost {
		t.Fatalf("failed HMAC should raise key-lost, got %+v", ev)
	}

	if rec := f.pull(t, "", strangerIP); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stranger status = %d, want 401", rec.Code)
	}
	select {
	case ev := <-f.hub.Events():
		t.Fatalf("keyless pull from another node raised %+v", ev)
	default:
	}
}

func TestKeylessPullFromUnpairedTeammateRaisesNothing(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	bindTeammate(t, f.hub, "grokbot", grokNode, false)
	_ = f.hub.store.Update(func(st *state.TeammatesState) error {
		st.Teammate("grokbot").PairedAt = time.Time{}
		return nil
	})
	f.pull(t, "", grokIP)
	select {
	case ev := <-f.hub.Events():
		t.Fatalf("unpaired teammate raised %+v", ev)
	default:
	}
}

// Covers R1: a non-teammate peer from an existing pull-mode config keeps
// today's behavior (no WhoIs at all), with or without teammates.
func TestNonTeammatePeerStillPulls(t *testing.T) {
	for _, yaml := range []string{"", "teammates:\n  - name: grokbot\n"} {
		f := newAuthFixture(t, yaml)
		if rec := f.pull(t, museKey, strangerIP); rec.Code != http.StatusOK {
			t.Fatalf("non-teammate peer status = %d, want 200 (teammates=%q)", rec.Code, yaml)
		}
		if n := f.whois.calls.Load(); n != 0 {
			t.Fatalf("non-teammate pull called WhoIs %d times", n)
		}
	}
}

// Without teammates.yaml nothing changes: failed auth stays a plain 401
// and Tailscale is never asked.
func TestNoTeammatesNoWhoIsOnFailedAuth(t *testing.T) {
	f := newAuthFixture(t, "")
	if rec := f.pull(t, "", grokIP); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if n := f.whois.calls.Load(); n != 0 {
		t.Fatalf("WhoIs called %d times without teammates.yaml", n)
	}
}

func TestConcurrentTeammatePullsAllSucceed(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n")
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 50 {
		wg.Go(func() {
			req := httptest.NewRequest(http.MethodGet, "/pull", nil)
			req.RemoteAddr = grokIP + ":41000"
			if err := transport.SignRequest(req, grokKey, time.Now()); err != nil {
				bad.Add(1)
				return
			}
			rec := httptest.NewRecorder()
			f.h.ServeHTTP(rec, req)
			got, err := transport.OpenWithSecret(rec.Body.Bytes(), grokKey)
			if rec.Code != http.StatusOK || err != nil || string(got) != testEnvJSON {
				bad.Add(1)
			}
		})
	}
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d of 50 concurrent pulls failed", n)
	}
}

func TestWhoisCacheRemembersErrorsFifteenSeconds(t *testing.T) {
	var calls int
	var fail bool
	restore := SetWhoIsForTesting(func(_ context.Context, ip string) (*tsclient.WhoIsResult, error) {
		calls++
		if fail {
			return nil, errors.New("tailscaled not running")
		}
		return &tsclient.WhoIsResult{StableID: grokNode}, nil
	})
	t.Cleanup(restore)
	now := time.Now()
	c := newWhoisCache(func() time.Time { return now })
	ctx := context.Background()

	fail = true
	for i := range 2 {
		if res, err := c.lookup(ctx, grokIP); err == nil || res != nil {
			t.Fatalf("lookup %d after error = %v, %v; want an error", i, res, err)
		}
		now = now.Add(5 * time.Second)
	}
	if calls != 1 {
		t.Fatalf("WhoIs calls within 15s of an error = %d, want 1", calls)
	}
	now = now.Add(6 * time.Second)
	if _, err := c.lookup(ctx, grokIP); err == nil {
		t.Fatal("lookup after error expiry succeeded; want an error")
	}
	if calls != 2 {
		t.Fatalf("WhoIs calls after error expiry = %d, want 2", calls)
	}

	fail = false
	now = now.Add(16 * time.Second)
	if res, err := c.lookup(ctx, grokIP); err != nil || res.StableID != grokNode {
		t.Fatalf("lookup = %v, %v", res, err)
	}
	now = now.Add(4 * time.Minute)
	if _, err := c.lookup(ctx, grokIP); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("WhoIs calls with a cached success = %d, want 3", calls)
	}
	now = now.Add(time.Minute + time.Second)
	if _, err := c.lookup(ctx, grokIP); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("WhoIs calls after success expiry = %d, want 4", calls)
	}
}

func TestWhoisCacheDoesNotRememberCanceledLookup(t *testing.T) {
	var calls int
	restore := SetWhoIsForTesting(func(ctx context.Context, ip string) (*tsclient.WhoIsResult, error) {
		calls++
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return &tsclient.WhoIsResult{StableID: grokNode}, nil
	})
	t.Cleanup(restore)
	c := newWhoisCache(time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.lookup(ctx, grokIP); err == nil {
		t.Fatal("canceled lookup succeeded")
	}
	if res, err := c.lookup(context.Background(), grokIP); err != nil || res.StableID != grokNode {
		t.Fatalf("lookup after canceled one = %v, %v", res, err)
	}
	if calls != 2 {
		t.Fatalf("WhoIs calls = %d, want 2", calls)
	}
}

// newNilStoreAuthFixture is a daemon whose teammates-state.json could not
// be opened (nil store) with teammates.yaml set to body (empty body = no
// teammates.yaml) and keys for grokbot and muse-box.
func newNilStoreAuthFixture(t *testing.T, body string) *authFixture {
	t.Helper()
	dir := t.TempDir()
	withConfigDir(t, dir)
	if body != "" {
		writeTeammatesFile(t, dir, body)
	}
	for peer, key := range map[string]string{"grokbot": grokKey, musePeer: museKey} {
		if err := keystore.Save(dir, &keystore.PeerKey{Peer: peer, Key: []byte(key)}); err != nil {
			t.Fatal(err)
		}
	}
	hub := newTeammateHub(dir, nil, nil)
	hub.log = &strings.Builder{}
	_ = hub.Reload()
	cache := newPullCache()
	cache.Store([]byte(testEnvJSON))
	return &authFixture{
		dir:   dir,
		hub:   hub,
		whois: installFakeWhoIs(t),
		cache: cache,
		h:     newPullHandlerWithAuth(cache, newPullAuthorizer(dir, legacyKey, hub)),
	}
}

// Fail closed: with teammates.yaml present but the state store
// unavailable, a listed name's key is refused and never falls through to
// the non-teammate rule; neither does any other keystore peer, since a
// removed teammate cannot be told apart without the store.
func TestTeammatePullRefusedWhenStateStoreUnavailable(t *testing.T) {
	f := newNilStoreAuthFixture(t, "teammates:\n  - name: grokbot\n")
	if !f.hub.IsTeammateName("grokbot") {
		t.Fatal("a listed name must stay classified while the state store is unavailable")
	}
	if rec := f.pull(t, grokKey, strangerIP); rec.Code != http.StatusForbidden {
		t.Fatalf("listed teammate from an unbound node with no state store: status = %d, want 403", rec.Code)
	}
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusForbidden {
		t.Fatalf("listed teammate with no state store: status = %d, want 403", rec.Code)
	}
	if rec := f.pull(t, museKey, strangerIP); rec.Code != http.StatusForbidden {
		t.Fatalf("keystore peer while classification is impossible: status = %d, want 403", rec.Code)
	}
}

// Fail closed: with no teammates.yaml but an unopenable state store, a
// leftover teammate key (the owner deleted the list and restarted before
// key cleanup ran) cannot be told apart from an ordinary peer key, so every
// keyed /pull is refused from any node. The push side is held to match.
func TestPullRefusedWithoutTeammatesFileWhenStateStoreUnavailable(t *testing.T) {
	f := newNilStoreAuthFixture(t, "")
	if f.hub.Active() {
		t.Fatal("hub should be inactive without teammates.yaml")
	}
	for _, ip := range []string{grokIP, strangerIP} {
		if rec := f.pull(t, grokKey, ip); rec.Code != http.StatusForbidden {
			t.Fatalf("leftover teammate key from %s with no state store: status = %d, want 403", ip, rec.Code)
		}
		if rec := f.pull(t, museKey, ip); rec.Code != http.StatusForbidden {
			t.Fatalf("keystore peer from %s with no state store: status = %d, want 403", ip, rec.Code)
		}
	}
	if err := f.hub.PushHeld(musePeer); !errors.Is(err, errTeammateHistoryUnknown) {
		t.Fatalf("PushHeld with no state store = %v, want errTeammateHistoryUnknown", err)
	}
}

// A missing state file opens as an empty store, so a config that never
// used teammates keeps serving its legacy peer keys.
func TestLegacyPeerKeyServedWithFreshStateStore(t *testing.T) {
	f := newAuthFixture(t, "")
	if f.hub.Unclassifiable() {
		t.Fatal("a fresh state store must not make peers unclassifiable")
	}
	if rec := f.pull(t, museKey, strangerIP); rec.Code != http.StatusOK {
		t.Fatalf("legacy peer key with a fresh state store: status = %d, want 200", rec.Code)
	}
	if err := f.hub.PushHeld(musePeer); err != nil {
		t.Fatalf("PushHeld with a fresh state store = %v, want nil", err)
	}
}

// Fail closed: a teammates.yaml that never loaded (parse error at start,
// no state store) still refuses the key of a name it lists.
func TestTeammatePullRefusedWhenSuspendedWithoutStore(t *testing.T) {
	f := newNilStoreAuthFixture(t, "teammates:\n  - name: grokbot\n  - name: [\n")
	if f.hub.Suspended() == nil {
		t.Fatal("hub should be suspended")
	}
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusForbidden {
		t.Fatalf("suspended, listed name's key: status = %d, want 403", rec.Code)
	}
}

// Fail closed: a teammates.yaml that is broken from the daemon's start
// (no good list ever loaded) leaves every keystore peer unclassifiable, so
// a key for a name the broken file lists is refused even with a state
// store.
func TestTeammatePullRefusedWhenNeverLoaded(t *testing.T) {
	dir := t.TempDir()
	withConfigDir(t, dir)
	writeTeammatesFile(t, dir, "teammates:\n  - name: grokbot\n  - name: [\n")
	if err := keystore.Save(dir, &keystore.PeerKey{Peer: "grokbot", Key: []byte(grokKey)}); err != nil {
		t.Fatal(err)
	}
	hub, _ := newTestHub(t, dir)
	_ = hub.Reload()
	installFakeWhoIs(t)
	cache := newPullCache()
	cache.Store([]byte(testEnvJSON))
	f := &authFixture{dir: dir, hub: hub, cache: cache, h: newPullHandlerWithAuth(cache, newPullAuthorizer(dir, legacyKey, hub))}
	if rec := f.pull(t, grokKey, grokIP); rec.Code != http.StatusForbidden {
		t.Fatalf("never-loaded teammates.yaml: status = %d, want 403", rec.Code)
	}
}

// keylessPullAs sends an unsigned /pull from ip, naming as in the
// X-Agentcookie-Teammate header when it is not empty.
func (f *authFixture) keylessPullAs(t *testing.T, ip, as string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/pull", nil)
	req.RemoteAddr = ip + ":41000"
	if as != "" {
		req.Header.Set("X-Agentcookie-Teammate", as)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec.Code
}

func drainEvents(hub *teammateHub) []TeammateEvent {
	var out []TeammateEvent
	for {
		select {
		case ev := <-hub.Events():
			out = append(out, ev)
		default:
			return out
		}
	}
}

// Two agents on one machine: the keyless /pull names the agent whose key
// was lost, and only that teammate is re-paired.
func TestKeylessPullOnSharedNodeUsesTeammateHeader(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n  - name: dot\n  - name: other\n")
	bindTeammate(t, f.hub, "dot", grokNode, true)
	bindTeammate(t, f.hub, "other", otherNode, true)

	if code := f.keylessPullAs(t, grokIP, "dot"); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	evs := drainEvents(f.hub)
	if len(evs) != 1 || evs[0].Kind != TeammateKeyLost || evs[0].Name != "dot" || evs[0].NodeID != grokNode {
		t.Fatalf("events = %+v, want one key-lost for dot", evs)
	}

	// A header naming a teammate bound to a different node raises nothing.
	f.keylessPullAs(t, grokIP, "other")
	if evs := drainEvents(f.hub); len(evs) != 0 {
		t.Fatalf("header naming another node's teammate raised %+v", evs)
	}
	// So does a header naming nobody listed.
	f.keylessPullAs(t, grokIP, "stranger")
	if evs := drainEvents(f.hub); len(evs) != 0 {
		t.Fatalf("header naming an unlisted agent raised %+v", evs)
	}
}

// Two paired teammates bound to one node and no header: the key-lost
// owner is ambiguous, so nothing is raised and the ambiguity is logged.
func TestKeylessPullOnSharedNodeWithoutHeaderIsAmbiguous(t *testing.T) {
	f := newAuthFixture(t, "teammates:\n  - name: grokbot\n  - name: dot\n")
	var logBuf strings.Builder
	f.hub.log = &logBuf
	bindTeammate(t, f.hub, "dot", grokNode, true)
	if code := f.keylessPullAs(t, grokIP, ""); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if evs := drainEvents(f.hub); len(evs) != 0 {
		t.Fatalf("ambiguous keyless pull raised %+v", evs)
	}
	if !strings.Contains(logBuf.String(), "dot") || !strings.Contains(logBuf.String(), "grokbot") {
		t.Fatalf("ambiguity not logged: %q", logBuf.String())
	}

	// With only one of them paired, the unpaired one does not count.
	_ = f.hub.store.Update(func(st *state.TeammatesState) error {
		st.Teammate("dot").PairedAt = time.Time{}
		return nil
	})
	f.keylessPullAs(t, grokIP, "")
	if evs := drainEvents(f.hub); len(evs) != 1 || evs[0].Name != "grokbot" {
		t.Fatalf("events = %+v, want one key-lost for grokbot", evs)
	}
}
