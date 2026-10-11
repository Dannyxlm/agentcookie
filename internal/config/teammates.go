package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TeammatesFile is the owner's teammate list, next to source.yaml. The
// daemon only reads it; daemon-written binding state lives in
// ~/.agentcookie/teammates-state.json (internal/state).
const TeammatesFile = "teammates.yaml"

// Cadence says when a teammate pulls. Empty means "default by Tincan kind",
// resolved by the teammate lifecycle once the roster shows the agent's kind.
type Cadence string

const (
	// CadenceTurn pulls at the start of each of the agent's turns.
	CadenceTurn Cadence = "turn"
	// CadenceTurnTimer also runs a 5 to 15 minute background pull loop.
	CadenceTurnTimer Cadence = "turn+timer"
)

// Teammate is one listed Tincan agent.
type Teammate struct {
	Name    string  `yaml:"name"`
	Cadence Cadence `yaml:"cadence,omitempty"`
}

// TeammatesConfig is the parsed teammates.yaml.
type TeammatesConfig struct {
	Teammates []Teammate `yaml:"teammates"`
	// TincanPath overrides the tincan CLI location.
	TincanPath string `yaml:"tincan_path,omitempty"`
	// TincanConfig is the TINCAN_CONFIG for the laptop's dedicated
	// `agentcookie` Tincan agent.
	TincanConfig string `yaml:"tincan_config,omitempty"`
}

// TeammatesPath returns the teammates.yaml path under dir.
func TeammatesPath(dir string) string { return filepath.Join(dir, TeammatesFile) }

// LoadTeammates reads teammates.yaml from dir. A missing file returns
// (nil, nil): teammate mode is off and nothing changes for that config.
// Decoding is strict, duplicate names are an error, and names of virtual
// Tincan kinds are rejected because they can never have a Tailscale node.
func LoadTeammates(dir string) (*TeammatesConfig, error) {
	path := TeammatesPath(dir)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	var cfg TeammatesConfig
	if err := loadYAML(path, &cfg); err != nil {
		// An empty file decodes to io.EOF; treat it as an empty list.
		if !isEmptyYAML(path) {
			return nil, err
		}
	}
	seen := make(map[string]bool, len(cfg.Teammates))
	for i, tm := range cfg.Teammates {
		name := tm.Name
		if name == "" {
			return nil, fmt.Errorf("%s: teammates[%d].name is required", path, i)
		}
		if !validTeammateName(name) {
			return nil, fmt.Errorf("%s: teammate %q: names are Tincan agent names (lowercase letters, digits, '-' and '_')", path, name)
		}
		if IsVirtualTincanKind(name) {
			return nil, fmt.Errorf("%s: teammate %q is a virtual Tincan agent (ChatGPT, Sesame, or a web agent); it has no Tailscale node, so it can never pull cookies", path, name)
		}
		if seen[name] {
			return nil, fmt.Errorf("%s: teammate %q is listed more than once", path, name)
		}
		seen[name] = true
		switch tm.Cadence {
		case "", CadenceTurn, CadenceTurnTimer:
		default:
			return nil, fmt.Errorf("%s: teammate %q: cadence %q is not one of %q or %q", path, name, tm.Cadence, CadenceTurn, CadenceTurnTimer)
		}
	}
	cfg.TincanPath = ExpandTilde(cfg.TincanPath)
	cfg.TincanConfig = ExpandTilde(cfg.TincanConfig)
	return &cfg, nil
}

// Names returns the listed names in file order.
func (c *TeammatesConfig) Names() []string {
	if c == nil {
		return nil
	}
	out := make([]string, 0, len(c.Teammates))
	for _, tm := range c.Teammates {
		out = append(out, tm.Name)
	}
	return out
}

// Has reports whether name is listed.
func (c *TeammatesConfig) Has(name string) bool {
	if c == nil {
		return false
	}
	for _, tm := range c.Teammates {
		if tm.Name == name {
			return true
		}
	}
	return false
}

// IsVirtualTincanKind reports whether a Tincan agent kind (or a name that
// equals one) is virtual: ChatGPT, Sesame, and the *-web agents reach the
// relay through its gateway and never have a Tailscale node.
func IsVirtualTincanKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case "chatgpt", "sesame":
		return true
	}
	return strings.HasSuffix(k, "-web")
}

// validTeammateName keeps names usable as key filenames (keys/<name>.json)
// without the keystore having to rewrite them.
func validTeammateName(name string) bool {
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '-' || r == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

func isEmptyYAML(path string) bool {
	data, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(data)) == ""
}
