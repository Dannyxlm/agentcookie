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
