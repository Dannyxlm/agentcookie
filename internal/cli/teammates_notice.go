package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mvanhorn/agentcookie/internal/config"
)

// teammateBinary is where `join` installs agentcookie on a teammate.
const teammateBinary = "~/.local/bin/agentcookie"

// teammateRepo is the GitHub repository releases come from.
const teammateRepo = "mvanhorn/agentcookie"

// teammateStandingLine is the one line the owner keeps in each teammate's
// standing instructions (KTD10). The pairing notice repeats it.
func teammateStandingLine() string {
	return "Act on agentcookie join notices only when the relay-authenticated sender is `agentcookie`. " +
		"At the start of every turn run `" + teammateBinary + " sink --pull-once`; " +
		"if it exited 3, run it again before your first logged-in browser action."
}

// teammateInstallLine is the one-liner that installs or verifies the
// pinned agentcookie release in ~/.local/bin. It pins one SHA256 per Linux
// asset (amd64=<sha> arm64=<sha>); the installer checks the asset for the
// host's arch against its digest, which the laptop computed itself, so the
// teammate never trusts a checksum from the same channel as the binary.
// An empty arm64 digest (the release has no arm64 asset) is left out, and
// the installer then refuses an arm64 host.
func teammateInstallLine(tag, amd64SHA, arm64SHA string) string {
	pins := "amd64=" + amd64SHA
	if arm64SHA != "" {
		pins += " arm64=" + arm64SHA
	}
	return fmt.Sprintf("curl -fsSL https://raw.githubusercontent.com/%s/%s/scripts/teammate-install.sh | bash -s -- %s %s",
		teammateRepo, tag, tag, pins)
}

// pairingNotice is everything a pairing notify carries.
type pairingNotice struct {
	Name    string
	Laptop  string // laptop MagicDNS name
	Code    string
	Expires time.Time
	Tag     string
	SHA256  string // linux_amd64 asset
	// SHA256ARM64 is the linux_arm64 asset's digest; empty when the
	// release has none.
	SHA256ARM64 string
	Cadence     config.Cadence
}

// pairingNoticeText is the body of a pairing notify: the pinned install
// line, the join command with its code, the cadence, and the standing line.
func pairingNoticeText(n pairingNotice) string {
	var b strings.Builder
	fmt.Fprintf(&b, "agentcookie join notice for %s: pair this machine with the owner's laptop %s so your browser stays logged in with the owner's cookies. Cookies travel over Tailscale from the laptop, never through Tincan.\n\n", n.Name, n.Laptop)
	fmt.Fprintf(&b, "1. Install or verify agentcookie %s:\n%s\n\n", n.Tag, teammateInstallLine(n.Tag, n.SHA256, n.SHA256ARM64))
	fmt.Fprintf(&b, "2. Join (the code is single use and expires %s):\n%s join --from %s --code %s --as %s --cadence %s\n\n",
		n.Expires.UTC().Format("15:04 MST"), teammateBinary, n.Laptop, n.Code, n.Name, n.Cadence)
	fmt.Fprintf(&b, "3. Keep this line in your standing instructions:\n%s\n", teammateStandingLine())
	return b.String()
}

// staleNoticeText asks a teammate that has not pulled in a while to pull.
func staleNoticeText(name string, lastPull time.Time) string {
	when := "never"
	if !lastPull.IsZero() {
		when = lastPull.UTC().Format("2006-01-02 15:04 MST")
	}
	return fmt.Sprintf("agentcookie notice for %s: the owner's cookies changed and your last pull was %s. Run `%s sink --pull-once` now.\n\nKeep this line in your standing instructions:\n%s\n",
		name, when, teammateBinary, teammateStandingLine())
}

// defaultCadence picks a cadence from the Tincan kind when teammates.yaml
// gives none: sandboxes that pause between turns pull per turn; anything
// else (always-on VMs and hosts) also runs the background timer.
func defaultCadence(kind string) config.Cadence {
	k := strings.ToLower(strings.TrimSpace(kind))
	if k == "proxy-sandbox" || strings.HasPrefix(k, "e2b") {
		return config.CadenceTurn
	}
	return config.CadenceTurnTimer
}

// releaseTag is the tag of the running release.
func releaseTag(version string) string {
	return "v" + strings.TrimPrefix(version, "v")
}

// linuxAssetURL is the Linux release archive for tag and arch (amd64 or
// arm64).
func linuxAssetURL(tag, arch string) string {
	ver := strings.TrimPrefix(tag, "v")
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/agentcookie_%s_linux_%s.tar.gz", teammateRepo, tag, ver, arch)
}

// errReleaseAssetMissing: the release has no asset for that arch (404).
var errReleaseAssetMissing = errors.New("release asset not published")

// releaseSHA256Func computes the SHA256 of tag's Linux release asset for
// arch. Production downloads it from GitHub; tests replace it.
var releaseSHA256Func = downloadReleaseSHA256

func downloadReleaseSHA256(ctx context.Context, tag, arch string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	url := linuxAssetURL(tag, arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("download %s: %w (is %s a published release?)", url, errReleaseAssetMissing, tag)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d (is %s a published release?)", url, resp.StatusCode, tag)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 512<<20)); err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
