package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/chrome"
	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/protocol"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/transport"
)

func TestNormalizePullURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"mac.tailnet", "http://mac.tailnet:9998/pull"},
		{"mac.tailnet:9998", "http://mac.tailnet:9998/pull"},
		{"http://mac.tailnet:9998", "http://mac.tailnet:9998/pull"},
		{"http://mac.tailnet:9998/", "http://mac.tailnet:9998/pull"},
		{"http://mac.tailnet:9998/pull", "http://mac.tailnet:9998/pull"},
		{"https://mac.tailnet.ts.net:9998/pull", "https://mac.tailnet.ts.net:9998/pull"},
		{"  100.64.0.1:9998  ", "http://100.64.0.1:9998/pull"},
	}
	for _, tc := range cases {
		got, err := normalizePullURL(tc.in)
		if err != nil {
			t.Errorf("normalizePullURL(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizePullURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizePullURLRejectsEmpty(t *testing.T) {
	if _, err := normalizePullURL("  "); err == nil {
		t.Fatal("expected error for empty --pull-from")
	}
}

func TestSinkPollAppliesEnvelopeAndSkipsReplay(t *testing.T) {
	fx := newSinkHandlerFixture(t, false)
	writeCLIFile(t, filepath.Join(fx.configDir, "blocklist.yaml"), `
version: 1
policy: blocklist
domains: []
`)
	restore := SetResolveSinkURLForTesting(func(_ context.Context, rawURL string) (string, error) {
		return rawURL, nil
	})
	defer restore()

	payload, err := json.Marshal(protocol.SyncEnvelope{
		ProtocolVersion: protocol.Version,
		SourceHostname:  "source-test",
		Sequence:        7,
		Cookies: []chrome.Cookie{
			{HostKey: ".allowed.com", Name: "sid", Value: "abc", Path: "/"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := transport.SealWithSecret(payload, fx.secret)
	if err != nil {
		t.Fatal(err)
	}

	hits := 0
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/pull" {
			http.NotFound(w, r)
			return
		}
		if err := transport.VerifyRequest(r, fx.secret, time.Now(), 0); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(sealed)
	}))
	defer src.Close()

	pullURL, err := normalizePullURL(src.URL)
	if err != nil {
		t.Fatal(err)
	}

	apply := func(b []byte) envelopeApplyResult { return fx.applySealed(b) }
	if err := pollSourceOnce(context.Background(), pullURL, fx.secret, apply); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if hits != 1 {
		t.Fatalf("source hits = %d, want 1", hits)
	}
	if fx.sinkState.TotalWrites != 1 {
		t.Fatalf("TotalWrites = %d, want 1 after first poll", fx.sinkState.TotalWrites)
	}
	if got := fx.sidecarHosts(); len(got) != 1 || got[0] != ".allowed.com" {
		t.Fatalf("sidecar hosts = %v, want [.allowed.com]", got)
	}

	if err := pollSourceOnce(context.Background(), pullURL, fx.secret, apply); err != nil {
		t.Fatalf("second poll (replay) should skip, got: %v", err)
	}
	if fx.sinkState.TotalWrites != 1 {
		t.Fatalf("TotalWrites = %d, want 1 after sequence skip", fx.sinkState.TotalWrites)
	}
	if fx.seqTracker.Last("source-test") != 7 {
		t.Errorf("sequence last = %d, want 7", fx.seqTracker.Last("source-test"))
	}
}

func TestSinkPollRejectsUnauthenticatedSource(t *testing.T) {
	fx := newSinkHandlerFixture(t, false)
	restore := SetResolveSinkURLForTesting(func(_ context.Context, rawURL string) (string, error) {
		return rawURL, nil
	})
	defer restore()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer src.Close()

	err := pollSourceOnce(context.Background(), src.URL+"/pull", fx.secret, fx.applySealed)
	if err == nil {
		t.Fatal("expected error for 401 pull response")
	}
}

func TestSinkPollNoContentIsSkip(t *testing.T) {
	fx := newSinkHandlerFixture(t, false)
	restore := SetResolveSinkURLForTesting(func(_ context.Context, rawURL string) (string, error) {
		return rawURL, nil
	})
	defer restore()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := transport.VerifyRequest(r, fx.secret, time.Now(), 0); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer src.Close()

	if err := pollSourceOnce(context.Background(), src.URL+"/pull", fx.secret, fx.applySealed); err != nil {
		t.Fatalf("204 should be a no-op, got: %v", err)
	}
	if fx.sinkState.TotalWrites != 0 {
		t.Errorf("TotalWrites = %d, want 0", fx.sinkState.TotalWrites)
	}
}

// teammateSink is a teammate machine (pull-mode sink.yaml written as join
// writes it) plus the laptop it pulls from.
type teammateSink struct {
	home, dir string
	key       string
	laptop    *httptest.Server
	hits      atomic.Int32
	keyless   atomic.Int32
	asHeader  atomic.Value // last X-Agentcookie-Teammate seen
	envSeq    atomic.Int64
	status    atomic.Int32 // non-zero: answer every /pull with this status
	gate      chan struct{}
	entered   chan struct{}
}

const teammateTestKey = "teammate-paired-key-32-bytes-xyz"

func newTeammateSink(t *testing.T, cadence, proxy string) *teammateSink {
	t.Helper()
	ts := &teammateSink{home: t.TempDir(), dir: t.TempDir(), key: teammateTestKey}
	t.Setenv("HOME", ts.home)
	withConfigDir(t, ts.dir)
	restore := SetResolveSinkURLForTesting(func(_ context.Context, rawURL string) (string, error) {
		return rawURL, nil
	})
	t.Cleanup(restore)
	prevBudget, prevMin, prevMax := pullOnceBudget, pullOnceRetryMin, pullOnceRetryMax
	pullOnceBudget, pullOnceRetryMin, pullOnceRetryMax = 500*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { pullOnceBudget, pullOnceRetryMin, pullOnceRetryMax = prevBudget, prevMin, prevMax })
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}

	ts.envSeq.Store(7)
	ts.laptop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := ts.hits.Add(1); n == 1 && ts.entered != nil {
			ts.entered <- struct{}{}
			<-ts.gate
		}
		if r.Header.Get(transport.HeaderMAC) == "" {
			ts.keyless.Add(1)
		}
		ts.asHeader.Store(r.Header.Get("X-Agentcookie-Teammate"))
		if s := ts.status.Load(); s != 0 {
			http.Error(w, "refused", int(s))
			return
		}
		if err := transport.VerifyRequest(r, ts.key, time.Now(), 0); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		payload, _ := json.Marshal(protocol.SyncEnvelope{
			ProtocolVersion: protocol.Version,
			SourceHostname:  "laptop",
			Sequence:        ts.envSeq.Load(),
		})
		sealed, err := transport.SealWithSecret(payload, ts.key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(sealed)
	}))
	t.Cleanup(ts.laptop.Close)

	from := strings.TrimPrefix(ts.laptop.URL, "http://")
	yml := "pull:\n  from: " + from + "\n  cadence: " + cadence + "\n  as: grokbot\n"
	if proxy != "" {
		yml += "  proxy: " + proxy + "\n"
	}
	yml += "peer:\n  hostname: 127.0.0.1\nskip_chrome_sqlite: true\nlive_cdp:\n  endpoint: http://127.0.0.1:1\n"
	writeCLIFile(t, filepath.Join(ts.dir, "sink.yaml"), yml)
	writeCLIFile(t, filepath.Join(ts.dir, "blocklist.yaml"), teammateBlocklistYAML)
	if err := keystore.Save(ts.dir, &keystore.PeerKey{Peer: "127.0.0.1", Key: []byte(ts.key)}); err != nil {
		t.Fatal(err)
	}
	return ts
}

func (ts *teammateSink) pullOnce(t *testing.T) (int, string) {
	t.Helper()
	var out bytes.Buffer
	err := runSinkPullOnce(context.Background(), &out)
	return exitCodeOf(err), out.String()
}

func (ts *teammateSink) totalWrites(t *testing.T) int {
	t.Helper()
	st, err := state.LoadSink(state.SinkPath(ts.home))
	if err != nil {
		t.Fatal(err)
	}
	if st == nil {
		return 0
	}
	return st.TotalWrites
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	if ec, ok := errors.AsType[*exitCodeError](err); ok {
		return ec.code
	}
	return 1
}

// Covers R4: a newer envelope is applied; the same sequence again is a
// no-op success, across separate invocations.
func TestPullOnceAppliesNewerAndSkipsSeenSequence(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	code, out := ts.pullOnce(t)
	if code != 0 || !strings.Contains(out, "applied") {
		t.Fatalf("first run: code=%d out=%q", code, out)
	}
	if got := ts.totalWrites(t); got != 1 {
		t.Fatalf("TotalWrites = %d, want 1", got)
	}
	code, out = ts.pullOnce(t)
	if code != 0 || !strings.Contains(out, "nothing new") {
		t.Fatalf("second run: code=%d out=%q", code, out)
	}
	if got := ts.totalWrites(t); got != 1 {
		t.Fatalf("TotalWrites = %d after a seen sequence, want 1", got)
	}
	ts.envSeq.Store(8)
	if code, out = ts.pullOnce(t); code != 0 || !strings.Contains(out, "applied") {
		t.Fatalf("newer sequence: code=%d out=%q", code, out)
	}
	if got := ts.totalWrites(t); got != 2 {
		t.Fatalf("TotalWrites = %d, want 2", got)
	}
}

// Covers R10: the laptop unreachable exits 3 within the budget and leaves
// what was applied before untouched.
func TestPullOnceUnreachableExits3WithinBudget(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	if code, _ := ts.pullOnce(t); code != 0 {
		t.Fatalf("seed pull code = %d", code)
	}
	seqBefore, _ := os.ReadFile(protocol.DefaultSequencePath(ts.home))
	ts.laptop.Close()

	start := time.Now()
	code, out := ts.pullOnce(t)
	elapsed := time.Since(start)
	if code != pullExitUnreachable || !strings.Contains(out, "unreachable") {
		t.Fatalf("code=%d out=%q, want 3", code, out)
	}
	if elapsed > pullOnceBudget+time.Second {
		t.Fatalf("took %s, budget %s", elapsed, pullOnceBudget)
	}
	if got := ts.totalWrites(t); got != 1 {
		t.Fatalf("TotalWrites = %d, want 1 (untouched)", got)
	}
	seqAfter, _ := os.ReadFile(protocol.DefaultSequencePath(ts.home))
	if !bytes.Equal(seqBefore, seqAfter) {
		t.Fatalf("sequence state changed: %q -> %q", seqBefore, seqAfter)
	}
}

// KTD4a: with no local key, one keyless /pull goes to the pinned laptop
// and the run exits 4.
func TestPullOnceWithoutKeySendsOneKeylessPullAndExits4(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	if err := keystore.Delete(ts.dir, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	code, out := ts.pullOnce(t)
	if code != pullExitRepair || !strings.Contains(out, "re-pair") {
		t.Fatalf("code=%d out=%q, want 4", code, out)
	}
	if ts.hits.Load() != 1 || ts.keyless.Load() != 1 {
		t.Fatalf("hits=%d keyless=%d, want exactly one keyless /pull", ts.hits.Load(), ts.keyless.Load())
	}
	// The keyless /pull names this agent so a laptop with two teammates on
	// one machine knows whose key was lost.
	if got, _ := ts.asHeader.Load().(string); got != "grokbot" {
		t.Fatalf("X-Agentcookie-Teammate = %q, want grokbot (pull.as from sink.yaml)", got)
	}
}

func TestPullOnce401WithKeyExits4(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	ts.status.Store(http.StatusUnauthorized)
	if code, out := ts.pullOnce(t); code != pullExitRepair {
		t.Fatalf("code=%d out=%q, want 4", code, out)
	}
	if ts.keyless.Load() != 0 {
		t.Fatal("a run with a key must sign its /pull")
	}
}

// Two concurrent invocations: one pulls, the other exits 0 at once.
func TestPullOnceConcurrentSecondExitsImmediately(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	ts.gate, ts.entered = make(chan struct{}), make(chan struct{}, 1)
	pullOnceBudget = 10 * time.Second
	release := sync.OnceFunc(func() { close(ts.gate) })
	t.Cleanup(release)

	first := make(chan int, 1)
	go func() {
		var out bytes.Buffer
		first <- exitCodeOf(runSinkPullOnce(context.Background(), &out))
	}()
	<-ts.entered // the first run holds pull.lock and is inside its request

	start := time.Now()
	code, out := ts.pullOnce(t)
	if code != 0 || !strings.Contains(out, "another pull is running") {
		t.Fatalf("second run: code=%d out=%q", code, out)
	}
	if time.Since(start) > time.Second {
		t.Fatal("second run waited instead of exiting at once")
	}
	if ts.hits.Load() != 1 {
		t.Fatalf("laptop hits = %d, want 1", ts.hits.Load())
	}
	release()
	if c := <-first; c != 0 {
		t.Fatalf("first run code = %d", c)
	}
}

// newForwardProxy is a plain HTTP forward proxy that counts requests.
func newForwardProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		out := r.Clone(r.Context())
		out.RequestURI = ""
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		maps.Copy(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(proxy.Close)
	return proxy, &proxied
}

// The proxy saved in sink.yaml carries the pull with no proxy in the
// environment.
func TestPullOnceUsesSinkYAMLProxy(t *testing.T) {
	proxy, proxied := newForwardProxy(t)
	ts := newTeammateSink(t, "turn", proxy.URL)
	code, out := ts.pullOnce(t)
	if code != 0 || !strings.Contains(out, "applied") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if proxied.Load() == 0 {
		t.Fatal("pull did not go through the sink.yaml proxy")
	}
}

const pullLoopHelperEnv = "AGENTCOOKIE_TEST_PULL_LOOP_HELPER_DIR"

// TestPullLoopHelperProcess is the detached loop when re-executed by the
// turn+timer test; it is a no-op in a normal test run.
func TestPullLoopHelperProcess(t *testing.T) {
	dir := os.Getenv(pullLoopHelperEnv)
	if dir == "" {
		return
	}
	common.ConfigDir = dir
	_ = runTeammatePullLoop(context.Background())
	os.Exit(0)
}

func loopRunning(t *testing.T) bool {
	t.Helper()
	f, ok, err := tryLock(pullLoopPidPath())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		f.Close()
	}
	return !ok
}

func waitLoop(t *testing.T, running bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for loopRunning(t) != running {
		if time.Now().After(deadline) {
			t.Fatalf("loop running = %v, want %v", !running, running)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func loopPid(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, _ := os.ReadFile(pullLoopPidPath())
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatal("loop never wrote its pid")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// For turn+timer the first run starts one loop, the next run starts no
// second one, and a killed loop is restarted by the following run.
func TestPullOnceTurnTimerKeepsOneLoop(t *testing.T) {
	ts := newTeammateSink(t, "turn+timer", "")
	var spawns atomic.Int32
	prev := pullLoopCommand
	pullLoopCommand = func() (*exec.Cmd, error) {
		spawns.Add(1)
		cmd := exec.Command(os.Args[0], "-test.run=^TestPullLoopHelperProcess$")
		cmd.Env = append(os.Environ(), pullLoopHelperEnv+"="+ts.dir)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		return cmd, nil
	}
	t.Cleanup(func() { pullLoopCommand = prev })
	t.Cleanup(func() {
		data, _ := os.ReadFile(pullLoopPidPath())
		if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	if code, out := ts.pullOnce(t); code != 0 || !strings.Contains(out, "started background pull loop") {
		t.Fatalf("first run: code=%d out=%q", code, out)
	}
	waitLoop(t, true)
	pid := loopPid(t)

	if code, _ := ts.pullOnce(t); code != 0 {
		t.Fatalf("second run code = %d", code)
	}
	if n := spawns.Load(); n != 1 {
		t.Fatalf("spawns = %d after a second run, want 1", n)
	}

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitLoop(t, false)
	if code, _ := ts.pullOnce(t); code != 0 {
		t.Fatalf("third run code = %d", code)
	}
	if n := spawns.Load(); n != 2 {
		t.Fatalf("spawns = %d after the loop was killed, want 2", n)
	}
	waitLoop(t, true)
}

// cadence turn never starts a loop.
func TestPullOnceTurnCadenceStartsNoLoop(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	prev := pullLoopCommand
	pullLoopCommand = func() (*exec.Cmd, error) { t.Fatal("cadence turn started a loop"); return nil, nil }
	t.Cleanup(func() { pullLoopCommand = prev })
	if code, _ := ts.pullOnce(t); code != 0 {
		t.Fatalf("code = %d", code)
	}
}

// The apply step runs inside the pull-once budget: a stalled Chrome
// connection cannot hold the agent's turn past it.
func TestPullOnceApplyStaysInsideBudget(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	prev := pullApplier
	pullApplier = func(_ *sinkRuntime, ctx context.Context, _ string) func([]byte) envelopeApplyResult {
		return func([]byte) envelopeApplyResult {
			select {
			case <-ctx.Done():
				return envelopeApplyResult{Status: http.StatusGatewayTimeout, Reply: ctx.Err().Error()}
			case <-time.After(5 * time.Second):
				return envelopeApplyResult{Status: http.StatusOK}
			}
		}
	}
	t.Cleanup(func() { pullApplier = prev })

	start := time.Now()
	code, out := ts.pullOnce(t)
	if elapsed := time.Since(start); elapsed > pullOnceBudget+time.Second {
		t.Fatalf("apply outlasted the %s budget: took %s (code=%d out=%q)", pullOnceBudget, elapsed, code, out)
	}
	if code == 0 {
		t.Fatalf("a stalled apply must not report success: out=%q", out)
	}
}

// --pull-once --dry-run never starts a background loop that would write
// cookies later.
func TestPullOnceDryRunStartsNoLoop(t *testing.T) {
	ts := newTeammateSink(t, "turn+timer", "")
	prevDry := sinkDryRun
	sinkDryRun = true
	t.Cleanup(func() { sinkDryRun = prevDry })
	prev := pullLoopCommand
	pullLoopCommand = func() (*exec.Cmd, error) { t.Fatal("a dry run started a writing background loop"); return nil, nil }
	t.Cleanup(func() { pullLoopCommand = prev })
	if code, out := ts.pullOnce(t); code != 0 {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

// Plain `sink` in pull mode names the configured teammate on its pulls,
// so a laptop with two teammates on one node can re-pair the right one.
func TestSinkPullLoopSendsConfiguredTeammate(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	cfg, err := config.LoadSink(ts.dir)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := newSinkRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pullURL, err := normalizePullURL(cfg.Pull.From)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runSinkPullLoop(ctx, nil, rt, ts.key, pullURL, time.Hour) }()
	deadline := time.Now().Add(5 * time.Second)
	for ts.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if got, _ := ts.asHeader.Load().(string); got != "grokbot" {
		t.Fatalf("X-Agentcookie-Teammate = %q, want grokbot (pull.as)", got)
	}
}

// The background loop exits once sink.yaml no longer asks for a timer.
func TestTeammatePullLoopExitsWhenCadenceIsTurn(t *testing.T) {
	ts := newTeammateSink(t, "turn", "")
	prev := teammatePullInterval
	teammatePullInterval = func() time.Duration { return 10 * time.Millisecond }
	t.Cleanup(func() { teammatePullInterval = prev })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runTeammatePullLoop(ctx); err != nil {
		t.Fatalf("loop did not exit on its own for cadence turn: %v", err)
	}
	if ts.hits.Load() != 0 {
		t.Fatalf("loop pulled %d times for cadence turn, want 0", ts.hits.Load())
	}
}
