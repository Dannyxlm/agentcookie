package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/keystore"
)

type joinFixture struct {
	laptop *pairFixture
	home   string
	dir    string
	from   string
}

// newJoinFixture is a laptop daemon (the real 9998 mux, grokbot listed and
// approved on grokNode) plus an empty teammate machine.
func newJoinFixture(t *testing.T) *joinFixture {
	t.Helper()
	laptop := newPairFixture(t, grokNode)
	home, dir := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TINCAN_CONFIG", filepath.Join(home, "no-tincan.json"))
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"} {
		t.Setenv(k, "")
	}
	withConfigDir(t, dir)
	restore := SetResolveSinkURLForTesting(func(_ context.Context, rawURL string) (string, error) {
		return rawURL, nil
	})
	t.Cleanup(restore)
	return &joinFixture{laptop: laptop, home: home, dir: dir, from: strings.TrimPrefix(laptop.srv.URL, "http://")}
}

func (f *joinFixture) mint(t *testing.T) string {
	t.Helper()
	code, _, err := f.laptop.hub.MintPairing("grokbot", grokNode)
	if err != nil {
		t.Fatal(err)
	}
	return string(code)
}

func (f *joinFixture) join(opts joinOptions) (string, error) {
	var out bytes.Buffer
	err := joinTeammate(context.Background(), &out, opts)
	return out.String(), err
}

func (f *joinFixture) read(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Covers R6: join writes a pull-mode config, pairs through the laptop's
// /pair, pulls once, and a rerun changes nothing and does not pair again.
func TestJoinPairsWritesConfigAndPulls(t *testing.T) {
	f := newJoinFixture(t)
	out, err := f.join(joinOptions{From: f.from, Code: f.mint(t), As: "grokbot"})
	if err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if !strings.Contains(out, "paired with "+f.from+" as grokbot") || !strings.Contains(out, "applied") {
		t.Fatalf("output = %q", out)
	}
	cfg, err := config.LoadSink(f.dir)
	if err != nil {
		t.Fatalf("written sink.yaml does not load: %v", err)
	}
	if cfg.Pull.From != f.from || cfg.Pull.Cadence != config.CadenceTurn || cfg.Listen.Addr != "" || cfg.Peer.Hostname != "127.0.0.1" || !cfg.SkipChromeSQLite {
		t.Fatalf("sink config = %+v", cfg)
	}
	if got := f.read(t, "blocklist.yaml"); got != teammateBlocklistYAML {
		t.Fatalf("blocklist.yaml = %q", got)
	}
	bl, err := config.LoadBlocklist(f.dir)
	if err != nil || bl.PolicyModeForSink() != config.CookiePolicyBlocklist || len(bl.Domains) != 0 {
		t.Fatalf("default blocklist = %+v, %v; want blocklist policy with no patterns", bl, err)
	}
	if _, err := keystore.Load(f.dir, "127.0.0.1"); err != nil {
		t.Fatalf("key not stored under the laptop name: %v", err)
	}
	if rec, _ := f.laptop.hub.store.Record("grokbot"); rec.LastPulledAt.IsZero() {
		t.Fatal("laptop did not record a pull from grokbot")
	}

	before := f.read(t, "sink.yaml")
	// Same command again: the code is spent, so a second pairing would fail.
	out, err = f.join(joinOptions{From: f.from, Code: "AAAA-BBBB-CCCC", As: "grokbot"})
	if err != nil {
		t.Fatalf("rerun: %v\n%s", err, out)
	}
	if !strings.Contains(out, "already paired") || strings.Contains(out, "wrote ") {
		t.Fatalf("rerun output = %q", out)
	}
	if after := f.read(t, "sink.yaml"); after != before {
		t.Fatalf("rerun rewrote sink.yaml:\n%s\n->\n%s", before, after)
	}
}

func TestJoinRefusesDifferentLaptopWithoutReplace(t *testing.T) {
	f := newJoinFixture(t)
	if out, err := f.join(joinOptions{From: f.from, Code: f.mint(t), As: "grokbot"}); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	before := f.read(t, "sink.yaml")
	_, err := f.join(joinOptions{From: "other-laptop.tail1234.ts.net", Code: "AAAA-BBBB-CCCC", As: "grokbot"})
	if err == nil || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("err = %v, want refusal naming --replace", err)
	}
	if f.read(t, "sink.yaml") != before {
		t.Fatal("a refused join changed sink.yaml")
	}
	// With --replace the pin moves (pairing then fails: nothing listens there).
	_, _ = f.join(joinOptions{From: "localhost:1", Code: "AAAA-BBBB-CCCC", As: "grokbot", Replace: true})
	if cfg, err := config.LoadSink(f.dir); err != nil || cfg.Pull.From != "localhost:1" {
		t.Fatalf("--replace did not re-pin: %+v %v", cfg, err)
	}
}

func TestJoinKeepsExistingBlocklist(t *testing.T) {
	f := newJoinFixture(t)
	mine := "version: 1\npolicy: allowlist\ndomains:\n  - pattern: \"%.example.com\"\n"
	writeCLIFile(t, filepath.Join(f.dir, "blocklist.yaml"), mine)
	if out, err := f.join(joinOptions{From: f.from, Code: f.mint(t), As: "grokbot"}); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if got := f.read(t, "blocklist.yaml"); got != mine {
		t.Fatalf("existing blocklist overwritten: %q", got)
	}
}

// join takes the proxy saved in the agent's Tincan client.json, records
// it in sink.yaml, and pairs and pulls through it.
func TestJoinUsesTincanClientJSONProxy(t *testing.T) {
	f := newJoinFixture(t)
	proxy, proxied := newForwardProxy(t)
	tincan := filepath.Join(f.home, "tincan", "grokbot.json")
	writeCLIFile(t, tincan, `{"relay":"http://tincan-relay:8787","proxy":"`+proxy.URL+`","agent":"grokbot"}`)
	t.Setenv("TINCAN_CONFIG", tincan)

	if out, err := f.join(joinOptions{From: f.from, Code: f.mint(t), As: "grokbot"}); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	cfg, err := config.LoadSink(f.dir)
	if err != nil || cfg.Pull.Proxy != proxy.URL {
		t.Fatalf("pull.proxy = %+v, %v; want %s", cfg, err, proxy.URL)
	}
	if proxied.Load() < 2 {
		t.Fatalf("proxied requests = %d, want the /pair and the /pull", proxied.Load())
	}
}
