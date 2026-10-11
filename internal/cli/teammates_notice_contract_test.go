package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/config"
)

// The pairing notice is run verbatim on a teammate, so its commands must
// match the real join flags and the install script's arguments.
func TestPairingNoticeMatchesJoinAndInstaller(t *testing.T) {
	text := pairingNoticeText(pairingNotice{
		Name: "grokbot", Laptop: "macbook-pro-44", Code: "ABCD-EFGH",
		Expires: time.Unix(0, 0), Tag: "v9.9.9", SHA256: strings.Repeat("a", 64),
		Cadence: config.CadenceTurnTimer,
	})

	var joinLine, installLine string
	for line := range strings.SplitSeq(text, "\n") {
		if strings.Contains(line, " join --from ") {
			joinLine = line
		}
		if strings.Contains(line, "teammate-install.sh") {
			installLine = line
		}
	}
	if joinLine == "" || installLine == "" {
		t.Fatalf("notice is missing the join or install line:\n%s", text)
	}

	fields := strings.Fields(joinLine)
	for i, f := range fields {
		if !strings.HasPrefix(f, "--") {
			continue
		}
		if joinCmd.Flags().Lookup(strings.TrimPrefix(f, "--")) == nil {
			t.Errorf("join line uses %s, which agentcookie join does not define", f)
		}
		if i+1 >= len(fields) || strings.HasPrefix(fields[i+1], "--") {
			t.Errorf("join line flag %s has no value", f)
		}
	}

	// The installer takes the tag and SHA256 as positional arguments and is
	// a bash script; run it in its argument-validation-only mode by giving
	// it an unpinned tag through the same invocation shape.
	if !strings.Contains(installLine, "| bash -s -- v9.9.9 "+strings.Repeat("a", 64)) {
		t.Errorf("install line does not pass <tag> <sha256> positionally to bash: %s", installLine)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "teammate-install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Skipf("installer not found: %v", err)
	}
	cmd := exec.Command("bash", "-s", "--", "latest", strings.Repeat("a", 64))
	src, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = strings.NewReader(string(src))
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Errorf("installer run as `bash -s -- <tag> <sha>` with an unpinned tag: err=%v, want exit 2 (argument check reached)", err)
	}
}
