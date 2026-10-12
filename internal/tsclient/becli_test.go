package tsclient

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fakeAppCLI writes a stand-in for the Tailscale.app binary that, like
// the real one, acts as a CLI only when TAILSCALE_BE_CLI=1 is set (under
// launchd it otherwise tries to start the GUI and fails).
func fakeAppCLI(t *testing.T, stdout string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	p := filepath.Join(t.TempDir(), "Tailscale")
	script := "#!/bin/sh\nif [ \"$TAILSCALE_BE_CLI\" != 1 ]; then echo 'The Tailscale GUI failed to start' >&2; exit 1; fi\ncat <<'JSON'\n" + stdout + "\nJSON\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGetRunsTheCLIInCLIMode(t *testing.T) {
	t.Setenv("TAILSCALE_BE_CLI", "")
	cli := fakeAppCLI(t, `{"Self":{"DNSName":"laptop.tail-abc.ts.net."}}`)
	st, err := Get(context.Background(), cli)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if st.Self == nil || st.Self.DNSName != "laptop.tail-abc.ts.net." {
		t.Fatalf("status = %+v", st.Self)
	}
}

func TestWhoIsRunsTheCLIInCLIMode(t *testing.T) {
	t.Setenv("TAILSCALE_BE_CLI", "")
	cli := fakeAppCLI(t, `{"Node":{"StableID":"nGROK","ComputedName":"grok-bot-2"},"UserProfile":{"LoginName":"owner@example.com"}}`)
	old := whoisFindCLI
	whoisFindCLI = func() (string, error) { return cli, nil }
	t.Cleanup(func() { whoisFindCLI = old })
	res, err := WhoIs(context.Background(), "100.64.0.9")
	if err != nil {
		t.Fatalf("WhoIs: %v", err)
	}
	if res == nil {
		t.Fatal("nil whois result")
	}
}
