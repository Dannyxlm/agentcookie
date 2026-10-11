// Package tincan runs the Agent Tincan CLI for the laptop's dedicated
// `agentcookie` Tincan agent: it reads the admin roster, sends notifies,
// cancels them, checks whether one is held, and drains the agent's inbox.
//
// It always runs `tincan` at an absolute path (the launchd PATH does not
// include ~/bin) and always sets TINCAN_CONFIG, so it never borrows another
// agent's identity on the same machine. Cookies never pass through here.
package tincan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultTimeout bounds one tincan invocation.
const DefaultTimeout = 30 * time.Second

// ErrNotFound means no tincan binary was found.
var ErrNotFound = errors.New("tincan CLI not found")

// DefaultConfigPath is the TINCAN_CONFIG of the laptop's `agentcookie`
// agent when teammates.yaml does not name one.
func DefaultConfigPath(home string) string {
	return filepath.Join(home, ".config", "tincan", "agentcookie.json")
}

// lookPath is exec.LookPath; tests replace it to keep the host PATH out.
var lookPath = exec.LookPath

// Resolve returns the absolute tincan path. A configured path must be an
// absolute executable file. Otherwise PATH is probed, then ~/bin and
// ~/.local/bin.
func Resolve(configured, home string) (string, error) {
	if configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("tincan_path %q is not an absolute path", configured)
		}
		if err := checkExecutable(configured); err != nil {
			return "", fmt.Errorf("tincan_path %s: %w", configured, err)
		}
		return configured, nil
	}
	if p, err := lookPath("tincan"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs, nil
		}
	}
	tried := []string{"PATH"}
	if home != "" {
		for _, p := range []string{filepath.Join(home, "bin", "tincan"), filepath.Join(home, ".local", "bin", "tincan")} {
			if checkExecutable(p) == nil {
				return p, nil
			}
			tried = append(tried, p)
		}
	}
	return "", fmt.Errorf("%w (looked in %s); set tincan_path in teammates.yaml", ErrNotFound, strings.Join(tried, ", "))
}

func checkExecutable(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.IsDir() || fi.Mode().Perm()&0o111 == 0 {
		return errors.New("not an executable file")
	}
	return nil
}

// Client runs one tincan binary as one Tincan agent.
type Client struct {
	// Path is the absolute tincan binary.
	Path string
	// Config is the TINCAN_CONFIG for the `agentcookie` agent.
	Config  string
	Timeout time.Duration
}

// Agent is one roster entry from `tincan agents --json`. NodeID, NodeName
// and NodeUser are filled only for an admin caller by a relay that has
// them; an older relay, or a non-admin caller, leaves them empty.
type Agent struct {
	Name       string    `json:"name"`
	Online     bool      `json:"online"`
	LastPoll   time.Time `json:"last_poll"`
	LastActive time.Time `json:"last_active"`
	Wake       string    `json:"wake"`
	Kind       string    `json:"kind"`
	NodeID     string    `json:"node_id"`
	NodeName   string    `json:"node_name"`
	NodeUser   string    `json:"node_user"`
}

// LastSeen is the agent's latest relay call the roster shows: the later of
// its last long-poll and its last call of any kind.
func (a Agent) LastSeen() time.Time {
	if a.LastActive.After(a.LastPoll) {
		return a.LastActive
	}
	return a.LastPoll
}

// Roster is the relay's agent list.
type Roster struct {
	Agents       []Agent `json:"agents"`
	RelayVersion string  `json:"relay_version"`
}

// Find returns the entry for name.
func (r *Roster) Find(name string) (Agent, bool) {
	if r == nil {
		return Agent{}, false
	}
	for _, a := range r.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return Agent{}, false
}

// NodeFieldsVisible reports whether any entry carries a node: the relay
// supports node fields and this machine reads the roster as an admin.
func (r *Roster) NodeFieldsVisible() bool {
	if r == nil {
		return false
	}
	for _, a := range r.Agents {
		if a.NodeID != "" {
			return true
		}
	}
	return false
}

// Outcome is what happened to one notify.
type Outcome string

const (
	// OutcomeSent: the relay queued the notify.
	OutcomeSent Outcome = "sent"
	// OutcomeHeld: the owner's Tincan approval gate holds it.
	OutcomeHeld Outcome = "held"
	// OutcomeRateLimited: the relay answered 429.
	OutcomeRateLimited Outcome = "rate-limited"
	// OutcomeError: anything else (relay down, bad config, ...).
	OutcomeError Outcome = "error"
)

// SendResult is one notify's outcome. RequestID is set for sent and held.
type SendResult struct {
	Outcome   Outcome
	RequestID string
	Err       error
}

// runError carries a failed invocation's stderr.
type runError struct {
	args   []string
	err    error
	stderr string
}

func (e *runError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" {
		return fmt.Sprintf("tincan %s: %v", strings.Join(e.args, " "), e.err)
	}
	return fmt.Sprintf("tincan %s: %v: %s", strings.Join(e.args, " "), e.err, msg)
}

func (e *runError) Unwrap() error { return e.err }

// waitDelay bounds how long run waits for tincan's output pipes after
// the process exits or is killed.
const waitDelay = 2 * time.Second

// run executes tincan with args. It returns stdout even on a non-zero exit
// so callers that print JSON before a status exit can still read it.
func (c *Client) run(ctx context.Context, args ...string) ([]byte, error) {
	if c.Path == "" {
		return nil, ErrNotFound
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, c.Path, args...)
	// A child that outlives a killed tincan and holds its stdout open must
	// not hang the lifecycle: stop waiting for the pipes 2s after the kill.
	cmd.WaitDelay = waitDelay
	cmd.Env = append(withoutEnv(os.Environ(), "TINCAN_CONFIG"), "TINCAN_CONFIG="+c.Config)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &runError{args: args, err: err, stderr: stderr.String()}
	}
	return stdout.Bytes(), nil
}

func withoutEnv(env []string, key string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// Roster reads the relay roster with `tincan agents --json`.
func (c *Client) Roster(ctx context.Context) (*Roster, error) {
	out, err := c.run(ctx, "agents", "--json")
	if err != nil {
		return nil, err
	}
	var r Roster
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("tincan agents --json: decode: %w", err)
	}
	return &r, nil
}

type sentJSON struct {
	Outcome string `json:"outcome"`
	Request struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	} `json:"request"`
}

// Notify sends text to the agent `to` as a notify with
// `tincan ask <to> --notify --json -- <text>`.
func (c *Client) Notify(ctx context.Context, to, text string) SendResult {
	out, err := c.run(ctx, "ask", to, "--notify", "--json", "--", text)
	if err != nil {
		var re *runError
		if errors.As(err, &re) && strings.Contains(re.stderr, "HTTP 429") {
			return SendResult{Outcome: OutcomeRateLimited, Err: err}
		}
		return SendResult{Outcome: OutcomeError, Err: err}
	}
	var s sentJSON
	if err := json.Unmarshal(out, &s); err != nil {
		return SendResult{Outcome: OutcomeError, Err: fmt.Errorf("tincan ask --json: decode: %w", err)}
	}
	if s.Request.ID == "" {
		return SendResult{Outcome: OutcomeError, Err: errors.New("tincan ask --json: no request id")}
	}
	if s.Request.Status == "held" {
		return SendResult{Outcome: OutcomeHeld, RequestID: s.Request.ID}
	}
	return SendResult{Outcome: OutcomeSent, RequestID: s.Request.ID}
}

// Cancel withdraws a request the agent sent, with `tincan cancel <id>`.
func (c *Client) Cancel(ctx context.Context, id string) error {
	_, err := c.run(ctx, "cancel", id)
	return err
}

type getJSON struct {
	Result struct {
		Status string `json:"status"`
	} `json:"result"`
}

// RequestStatus returns the relay's status for a request the agent sent
// ("held", "queued", "delivered", "claimed", "expired", ...), with
// `tincan get <id> --json`. That command exits 1 or 2 for a request that
// is not answered yet, so the JSON is read whatever the exit code.
func (c *Client) RequestStatus(ctx context.Context, id string) (string, error) {
	out, err := c.run(ctx, "get", id, "--json")
	var g getJSON
	if len(bytes.TrimSpace(out)) > 0 {
		if jerr := json.Unmarshal(out, &g); jerr == nil && g.Result.Status != "" {
			return g.Result.Status, nil
		}
	}
	if err != nil {
		return "", err
	}
	return "", errors.New("tincan get --json: no status")
}

type inboxJSON struct {
	Requests []json.RawMessage `json:"requests"`
	Replies  []json.RawMessage `json:"replies"`
}

// DrainInbox empties the agent's inbox with `tincan inbox --json` so relay
// notes and stray requests do not pile up. Nothing is answered. It returns
// how many items were taken.
func (c *Client) DrainInbox(ctx context.Context) (int, error) {
	out, err := c.run(ctx, "inbox", "--json")
	if err != nil {
		return 0, err
	}
	var in inboxJSON
	if err := json.Unmarshal(out, &in); err != nil {
		return 0, fmt.Errorf("tincan inbox --json: decode: %w", err)
	}
	return len(in.Requests) + len(in.Replies), nil
}
