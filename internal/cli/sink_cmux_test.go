package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/mvanhorn/agentcookie/internal/chrome"
	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/protocol"
	"github.com/mvanhorn/agentcookie/internal/sinkpush"
	"github.com/mvanhorn/agentcookie/internal/transport"
)

func cmuxCfg(enabled bool, path string, filter ...string) *config.SinkConfig {
	return &config.SinkConfig{Cmux: config.CmuxRef{Enabled: enabled, CmuxPath: path, DomainFilter: filter}}
}

// Each pull resolves the cmux surface from the config it just loaded: a
// later enable takes effect, a narrowed filter replaces the adapter, an
// unchanged config reuses it (and its hidden tab), and a disable drops it.
func TestCmuxSurfaceFollowsLoadedConfig(t *testing.T) {
	c := &cmuxSurfaceCache{}
	if got := c.adapters(cmuxCfg(false, "/nonexistent/cmux")); len(got) != 0 {
		t.Fatalf("disabled cmux yielded %d adapters", len(got))
	}
	first := c.adapters(cmuxCfg(true, "/nonexistent/cmux", "%github.com"))
	if len(first) != 1 || !slices.Equal(first[0].CookieHostPatterns(), []string{"%github.com"}) {
		t.Fatalf("enable after start: got %+v", first)
	}
	if again := c.adapters(cmuxCfg(true, "/nonexistent/cmux", "%github.com")); len(again) != 1 || again[0] != first[0] {
		t.Fatal("unchanged settings must reuse the adapter so its hidden tab is reused")
	}
	narrowed := c.adapters(cmuxCfg(true, "/nonexistent/cmux", "%example.com"))
	if len(narrowed) != 1 || !slices.Equal(narrowed[0].CookieHostPatterns(), []string{"%example.com"}) {
		t.Fatalf("narrowed filter not applied: %+v", narrowed)
	}
	moved := c.adapters(cmuxCfg(true, "/other/cmux", "%example.com"))
	if len(moved) != 1 || moved[0].CLIBinary() != "/other/cmux" {
		t.Fatalf("cmux_path change not applied: %+v", moved)
	}
	if got := c.adapters(cmuxCfg(false, "/other/cmux", "%example.com")); len(got) != 0 {
		t.Fatalf("disable after enable still yields %d adapters", len(got))
	}
}

// The apply step uses the cmux settings of the config it is handed, so a
// reloaded sink.yaml changes delivery on the next pull.
func TestApplySealedEnvelope_CmuxFollowsConfigReload(t *testing.T) {
	f := newSinkHandlerFixture(t, false)
	t.Cleanup(sinkpush.SetRegistryForTesting([]sinkpush.Adapter{&recordingAdapter{installed: true}}))
	cookies := []chrome.Cookie{{HostKey: ".example.com", Name: "sess", Value: "v", Path: "/"}}

	names := func() []string {
		f.stateMu.Lock()
		defer f.stateMu.Unlock()
		var out []string
		for _, r := range f.sinkState.LastAdapterResults {
			out = append(out, r.Name)
		}
		return out
	}

	f.cfg.Cmux = config.CmuxRef{Enabled: true, CmuxPath: "/nonexistent/cmux"}
	if rec := f.postSync(1, cookies); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !slices.Contains(names(), "cmux") {
		t.Fatalf("cmux enabled but not run: %v", names())
	}
	f.cfg.Cmux.Enabled = false
	if rec := f.postSync(2, cookies); rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if slices.Contains(names(), "cmux") {
		t.Fatalf("cmux disabled in the reloaded config but still run: %v", names())
	}
}

type ctxKey struct{}

// ctxSeeingAdapter records whether PushContext saw the caller's context.
type ctxSeeingAdapter struct{ saw any }

func (a *ctxSeeingAdapter) Name() string                 { return "ctx-seeing" }
func (a *ctxSeeingAdapter) CLIBinary() string            { return "/nonexistent/ctx-seeing" }
func (a *ctxSeeingAdapter) IsInstalled() bool            { return true }
func (a *ctxSeeingAdapter) CookieHostPatterns() []string { return nil }
func (a *ctxSeeingAdapter) Push([]chrome.Cookie) error   { return nil }
func (a *ctxSeeingAdapter) PushContext(ctx context.Context, _ []chrome.Cookie) error {
	a.saw = ctx.Value(ctxKey{})
	return nil
}

// Adapter delivery runs under the apply step's context, which pull-once
// bounds with its budget.
func TestApplySealedEnvelope_AdaptersGetCallerContext(t *testing.T) {
	f := newSinkHandlerFixture(t, false)
	a := &ctxSeeingAdapter{}
	t.Cleanup(sinkpush.SetRegistryForTesting([]sinkpush.Adapter{a}))
	payload, err := json.Marshal(protocol.SyncEnvelope{
		ProtocolVersion: protocol.Version,
		SourceHostname:  "source-test",
		Sequence:        1,
		Cookies:         []chrome.Cookie{{HostKey: ".example.com", Name: "sess", Value: "v", Path: "/"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := transport.SealWithSecret(payload, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), ctxKey{}, "budget")
	if res := applySealedEnvelope(ctx, f.cfg, f.secret, f.key, f.seqTracker, f.stateWriter, f.sinkState, f.stateMu, sealed); res.Status != http.StatusOK {
		t.Fatalf("apply status %d: %s", res.Status, res.Reply)
	}
	if a.saw != "budget" {
		t.Fatalf("adapter saw context value %v, want the apply step's context", a.saw)
	}
}
