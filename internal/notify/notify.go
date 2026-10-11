// Package notify asks the laptop owner to approve a teammate's machine and
// posts plain notifications. On macOS the approval is an osascript
// `display dialog` (a bare launchd binary cannot post an actionable
// notification). Elsewhere, or without a GUI session, AskApproval returns
// ErrNoGUI and callers fall back to a plain notice that names the
// `agentcookie teammates approve` command.
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrNoGUI means no dialog could be shown.
var ErrNoGUI = errors.New("notify: no GUI session for an approval dialog")

// Button labels of the approval dialog.
const (
	ButtonApprove = "Approve"
	ButtonNotNow  = "Not now"
)

// ApprovalRequest names the machine a teammate appeared on.
type ApprovalRequest struct {
	Agent    string // Tincan agent name
	NodeID   string // Tailscale node StableID the approval binds
	NodeName string // machine name
	NodeUser string // owning Tailscale login
	// Replaces is the machine this one replaces, empty on a first sighting.
	Replaces string
}

// ShortID shortens a StableID for display.
func ShortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12] + "..."
}

// ApproveCommand is the terminal equivalent of the dialog's Approve.
func ApproveCommand(agent, nodeID string) string {
	return fmt.Sprintf("agentcookie teammates approve %s --node %s", agent, nodeID)
}

// DialogText is the approval dialog's message.
func DialogText(req ApprovalRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Let teammate %q pull your browser cookies from this Mac?\n\n", req.Agent)
	fmt.Fprintf(&b, "Machine: %s\n", orUnknown(req.NodeName))
	fmt.Fprintf(&b, "Login: %s\n", orUnknown(req.NodeUser))
	fmt.Fprintf(&b, "Tailscale node: %s\n", ShortID(req.NodeID))
	if req.Replaces != "" {
		fmt.Fprintf(&b, "\nThis replaces its previous machine, %s, which stops syncing.\n", req.Replaces)
	}
	b.WriteString("\nApprove only if you recognize this machine. Not now asks again when agentcookie restarts.")
	return b.String()
}

func orUnknown(s string) string {
	if s == "" {
		return "(unknown)"
	}
	return s
}

// dialogScript is the AppleScript for req. "Not now" is the default and
// cancel button, so Return or Escape never approves.
func dialogScript(req ApprovalRequest, giveUpSeconds int) string {
	return fmt.Sprintf(`display dialog %s with title %s buttons {%s, %s} default button %s cancel button %s with icon caution giving up after %d`,
		appleString(DialogText(req)), appleString("agentcookie: approve a teammate's machine"),
		appleString(ButtonNotNow), appleString(ButtonApprove), appleString(ButtonNotNow), appleString(ButtonNotNow), giveUpSeconds)
}

// parseDialogResult reads osascript's dialog output: Approve only when
// the Approve button was pressed and the dialog did not give up.
func parseDialogResult(out string) bool {
	out = strings.TrimSpace(out)
	return strings.Contains(out, "button returned:"+ButtonApprove) && !strings.Contains(out, "gave up:true")
}

// appleString quotes s as an AppleScript string literal.
func appleString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// AskApproval shows the approval dialog and blocks until the owner answers,
// it gives up, or ctx ends. It reports true only for Approve. ErrNoGUI (or
// another error) means no answer could be had.
func AskApproval(ctx context.Context, req ApprovalRequest) (bool, error) {
	return askApproval(ctx, req)
}

// Show posts a plain notification. It is best effort.
func Show(ctx context.Context, title, body string) error {
	return show(ctx, title, body)
}
