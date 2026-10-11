package tsclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// WhoIsResult is the Tailscale identity of a remote tailnet address.
// StableID is the node's stable identifier, the same value Tincan's roster
// reports as node_id.
type WhoIsResult struct {
	StableID  string
	NodeName  string
	LoginName string
}

type whoIsJSON struct {
	Node *struct {
		StableID string `json:"StableID"`
		Name     string `json:"Name"`
	} `json:"Node"`
	UserProfile *struct {
		LoginName string `json:"LoginName"`
	} `json:"UserProfile"`
}

// ParseWhoIs decodes `tailscale whois --json` output. An answer without a
// node StableID is an error so callers never authorize on an empty ID.
func ParseWhoIs(raw []byte) (*WhoIsResult, error) {
	var w whoIsJSON
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("tsclient: parse whois JSON: %w", err)
	}
	if w.Node == nil || w.Node.StableID == "" {
		return nil, errors.New("tsclient: whois answer has no node StableID")
	}
	res := &WhoIsResult{StableID: w.Node.StableID, NodeName: w.Node.Name}
	if w.UserProfile != nil {
		res.LoginName = w.UserProfile.LoginName
	}
	return res, nil
}

// WhoIs asks the local Tailscale daemon which node owns ip, via
// `tailscale whois --json <ip>`. Callers that authorize on the answer must
// treat any error as a refusal.
func WhoIs(ctx context.Context, ip string) (*WhoIsResult, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("tsclient: whois needs an IP address, got %q", ip)
	}
	cli, err := FindCLI()
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(runCtx, cli, "whois", "--json", ip).Output()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			return nil, fmt.Errorf("tsclient: %s whois %s: %w (%s)", cli, ip, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("tsclient: %s whois %s: %w", cli, ip, err)
	}
	return ParseWhoIs(out)
}
