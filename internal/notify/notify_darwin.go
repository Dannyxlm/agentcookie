//go:build darwin

package notify

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// dialogGiveUp closes an unanswered dialog after 12 hours (counted as Not
// now), so a forgotten dialog never lingers for days.
const dialogGiveUp = 12 * 60 * 60

// runOsascript runs one AppleScript. Test seam.
var runOsascript = func(ctx context.Context, script string) ([]byte, error) {
	return exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).CombinedOutput()
}

func askApproval(ctx context.Context, req ApprovalRequest) (bool, error) {
	out, err := runOsascript(ctx, dialogScript(req, dialogGiveUp))
	if err != nil {
		text := string(out)
		// The cancel button ("Not now") makes osascript exit 1 with
		// "User canceled." (-128). That is an answer, not a failure.
		if strings.Contains(text, "-128") {
			return false, nil
		}
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// -1713 "No user interaction allowed": no GUI session.
		if strings.Contains(text, "-1713") {
			return false, ErrNoGUI
		}
		return false, fmt.Errorf("%w: osascript: %v: %s", ErrNoGUI, err, strings.TrimSpace(text))
	}
	return parseDialogResult(string(out)), nil
}

func show(ctx context.Context, title, body string) error {
	out, err := runOsascript(ctx, notificationScript(title, body))
	if err != nil {
		return errors.Join(err, fmt.Errorf("osascript: %s", strings.TrimSpace(string(out))))
	}
	return nil
}

// notificationScript posts a plain notification.
func notificationScript(title, body string) string {
	return fmt.Sprintf("display notification %s with title %s", appleString(body), appleString(title))
}
