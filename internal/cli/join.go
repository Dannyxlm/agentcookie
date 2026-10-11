package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/mvanhorn/agentcookie/internal/cli/httpserver"
	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/keystore"
	"github.com/mvanhorn/agentcookie/internal/pairing"
)

var joinOpts joinOptions

var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "Set this machine up as a teammate that pulls cookies from the owner's laptop",
	Long: `Run on a teammate agent's machine, with the values from the laptop's
pairing notice:

  agentcookie join --from <laptop-magicdns> --code <code> --as <agent-name>

It writes a pull-mode sink.yaml pinned to that laptop (no listener), a
default blocklist.yaml when none exists, pairs through the laptop's /pair
on port 9998, and pulls once. Rerunning it is safe: an already-paired
machine just pulls again.

The proxy is --proxy, else the "proxy" saved in this agent's Tincan
client.json (TINCAN_CONFIG, or the default Tincan config path), else the
one already in sink.yaml. A different --from than the pinned laptop is
refused unless --replace is given.

Each turn, run 'agentcookie sink --pull-once'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return joinTeammate(cmd.Context(), cmd.OutOrStdout(), joinOpts)
	},
}

func init() {
	joinCmd.Flags().StringVar(&joinOpts.From, "from", "", "the laptop's Tailscale MagicDNS name (required)")
	joinCmd.Flags().StringVar(&joinOpts.Code, "code", "", "pairing code from the laptop's notice (required)")
	joinCmd.Flags().StringVar(&joinOpts.As, "as", "", "this agent's Tincan name (required)")
	joinCmd.Flags().StringVar(&joinOpts.Proxy, "proxy", "", "proxy for reaching the laptop (default: the proxy saved in the Tincan client.json)")
	joinCmd.Flags().StringVar(&joinOpts.Cadence, "cadence", "", "turn or turn+timer (default: keep the current value, else turn)")
	joinCmd.Flags().BoolVar(&joinOpts.Replace, "replace", false, "switch this machine to a different laptop than the pinned one")
}

type joinOptions struct {
	From, Code, As, Proxy, Cadence string
	Replace                        bool
}

// teammateBlocklistYAML is the blocklist join writes when none exists. On
// Linux a missing file means "ship nothing", which would make a teammate
// silently receive no cookies; the laptop's own blocklist already decides
// what leaves it.
const teammateBlocklistYAML = `# blocklist.yaml written by agentcookie join.
# The laptop's own blocklist decides which cookies leave it. This file
# accepts everything the laptop sends; add patterns to keep a site off
# this machine.
version: 1
policy: blocklist
domains: []
`

func joinTeammate(ctx context.Context, w io.Writer, opts joinOptions) error {
	from := strings.TrimSpace(opts.From)
	switch {
	case from == "":
		return fmt.Errorf("--from is required (the laptop's MagicDNS name)")
	case strings.TrimSpace(opts.Code) == "":
		return fmt.Errorf("--code is required")
	case strings.TrimSpace(opts.As) == "":
		return fmt.Errorf("--as is required (this agent's Tincan name)")
	}
	pullURL, err := normalizePullURL(from)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	u, _ := url.Parse(pullURL)
	peer := u.Hostname()
	u.Path = "/pair"
	pairURL := u.String()

	dir := common.ConfigDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	sinkPath := filepath.Join(dir, "sink.yaml")
	raw := map[string]any{}
	if data, err := os.ReadFile(sinkPath); err == nil {
		if err := yaml.Unmarshal(data, &raw); err != nil && !opts.Replace {
			return fmt.Errorf("%s does not parse (%v); rerun with --replace to overwrite it", sinkPath, err)
		}
		if raw == nil {
			raw = map[string]any{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	prevPull, _ := raw["pull"].(map[string]any)
	prevFrom, _ := prevPull["from"].(string)
	if !opts.Replace {
		if prevFrom != "" && prevFrom != from {
			return fmt.Errorf("this machine is pinned to laptop %q; refusing %q (rerun with --replace to switch laptops)", prevFrom, from)
		}
		if prevFrom == "" && len(raw) > 0 {
			return fmt.Errorf("%s already configures a sink that is not a teammate; rerun with --replace to overwrite it", sinkPath)
		}
	}

	cadence := opts.Cadence
	if cadence == "" {
		cadence, _ = prevPull["cadence"].(string)
	}
	if cadence == "" {
		cadence = string(config.CadenceTurn)
	}
	if cadence != string(config.CadenceTurn) && cadence != string(config.CadenceTurnTimer) {
		return fmt.Errorf("--cadence must be %q or %q", config.CadenceTurn, config.CadenceTurnTimer)
	}
	proxy := opts.Proxy
	if proxy == "" {
		proxy = tincanSavedProxy()
	}
	if proxy == "" {
		proxy, _ = prevPull["proxy"].(string)
	}
	if _, err := pullHTTPClient(httpserver.PairClient, proxy); err != nil {
		return err
	}

	if opts.Replace && prevFrom != from {
		raw = map[string]any{}
	}
	wantPull := map[string]any{"from": from, "cadence": cadence}
	if proxy != "" {
		wantPull["proxy"] = proxy
	}
	wantPeer := map[string]any{"hostname": peer}
	_, hasSkip := raw["skip_chrome_sqlite"]
	if !reflect.DeepEqual(raw["pull"], wantPull) || !reflect.DeepEqual(raw["peer"], wantPeer) || !hasSkip {
		raw["pull"] = wantPull
		raw["peer"] = wantPeer
		if !hasSkip {
			raw["skip_chrome_sqlite"] = true
		}
		out, err := yaml.Marshal(raw)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(sinkPath, append([]byte("# Written by agentcookie join: this machine pulls cookies from the laptop below.\n"), out...), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(w, "agentcookie join: wrote %s (pull from %s, cadence %s)\n", sinkPath, from, cadence)
	}
	if _, err := config.LoadSink(dir); err != nil {
		return err
	}
	if err := writeYAMLIfMissing(filepath.Join(dir, "blocklist.yaml"), teammateBlocklistYAML, false); err != nil {
		return err
	}

	pair := func() error {
		client, err := pullHTTPClient(httpserver.PairClient, proxy)
		if err != nil {
			return err
		}
		res, err := pairing.RunSinkWithClient(ctx, client, pairURL, pairing.Code(opts.Code), opts.As)
		if err != nil {
			return fmt.Errorf("pair with %s: %w", from, err)
		}
		if err := keystore.Save(dir, &keystore.PeerKey{
			Peer:        peer,
			Key:         res.Key,
			PairedAt:    res.PairedAt,
			Fingerprint: res.Fingerprint,
			ProtocolVer: pairing.ProtocolVersion,
		}); err != nil {
			return fmt.Errorf("save key: %w", err)
		}
		fmt.Fprintf(w, "agentcookie join: paired with %s as %s (fingerprint %s)\n", from, opts.As, res.Fingerprint)
		return nil
	}

	pairedNow := false
	if pk, err := keystore.Load(dir, peer); err != nil || pk == nil || len(pk.Key) == 0 {
		if err := pair(); err != nil {
			return err
		}
		pairedNow = true
	} else {
		fmt.Fprintf(w, "agentcookie join: already paired with %s\n", from)
	}
	err = runSinkPullOnce(ctx, w)
	if ec, ok := errors.AsType[*exitCodeError](err); ok && ec.code == pullExitRepair && !pairedNow {
		// The laptop no longer accepts the stored key: use the new code.
		if err := pair(); err != nil {
			return err
		}
		err = runSinkPullOnce(ctx, w)
	}
	return err
}

// tincanSavedProxy returns the "proxy" saved in this agent's Tincan
// client.json: TINCAN_CONFIG (leading ~/ expanded) or Tincan's default
// path. Empty when there is none.
func tincanSavedProxy() string {
	path := os.Getenv("TINCAN_CONFIG")
	if path != "" {
		path = config.ExpandTilde(path)
	} else {
		dir, err := os.UserConfigDir()
		if err != nil {
			return ""
		}
		path = filepath.Join(dir, "tincan", "client.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var c struct {
		Proxy string `json:"proxy"`
	}
	if json.Unmarshal(data, &c) != nil {
		return ""
	}
	return strings.TrimSpace(c.Proxy)
}

// writeFileAtomic writes data to path via a temp file and rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
