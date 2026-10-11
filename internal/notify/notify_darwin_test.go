//go:build darwin

package notify

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func stubOsascript(t *testing.T, out string, err error) *[]string {
	t.Helper()
	var scripts []string
	prev := runOsascript
	runOsascript = func(_ context.Context, script string) ([]byte, error) {
		scripts = append(scripts, script)
		return []byte(out), err
	}
	t.Cleanup(func() { runOsascript = prev })
	return &scripts
}

func TestAskApprovalApprove(t *testing.T) {
	scripts := stubOsascript(t, "button returned:Approve, gave up:false\n", nil)
	ok, err := AskApproval(context.Background(), ApprovalRequest{Agent: "grokbot", NodeID: "nX", NodeName: "grok-bot"})
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if len(*scripts) != 1 || !strings.HasPrefix((*scripts)[0], "display dialog ") {
		t.Fatalf("scripts = %q", *scripts)
	}
}

func TestAskApprovalNotNowIsAnAnswer(t *testing.T) {
	stubOsascript(t, "execution error: User canceled. (-128)\n", errors.New("exit status 1"))
	ok, err := AskApproval(context.Background(), ApprovalRequest{Agent: "grokbot", NodeID: "nX"})
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestAskApprovalWithoutGUI(t *testing.T) {
	stubOsascript(t, "execution error: No user interaction allowed. (-1713)\n", errors.New("exit status 1"))
	_, err := AskApproval(context.Background(), ApprovalRequest{Agent: "grokbot", NodeID: "nX"})
	if !errors.Is(err, ErrNoGUI) {
		t.Fatalf("err = %v, want ErrNoGUI", err)
	}
}
