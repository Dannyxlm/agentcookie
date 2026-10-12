package livecdp

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"

	"github.com/mvanhorn/agentcookie/internal/chrome"
)

// githubSessionCookies returns fake cookies shaped exactly like GitHub's
// login set as the sink receives them (Chrome SQLite encoding), all with the
// given last_access_utc.
func githubSessionCookies(lastAccess int64) []chrome.Cookie {
	exp := (time.Now().Add(14*24*time.Hour).Unix() + 11644473600) * 1e6
	mk := func(host, name string, expires int64, sameSite int) chrome.Cookie {
		has := 0
		if expires != 0 {
			has = 1
		}
		return chrome.Cookie{
			HostKey: host, Name: name, Value: "fake-" + name, Path: "/",
			ExpiresUTC: expires, IsSecure: 1, IsHTTPOnly: 1, HasExpires: has, IsPersistent: has,
			Priority: 1, SameSite: sameSite, SourceScheme: 2, SourcePort: 443,
			LastAccessUTC: lastAccess,
		}
	}
	return []chrome.Cookie{
		mk("github.com", "user_session", exp, 1),
		mk("github.com", "__Host-user_session_same_site", exp, 2),
		mk(".github.com", "logged_in", exp, 1),
		mk("github.com", "_gh_sess", 0, 1),
		mk(".github.com", "_device_id", exp, 1),
	}
}

// bulkCookies returns n cookies, one per distinct registrable domain (so
// Chrome's per-domain cap never interferes), all with the given last access.
func bulkCookies(n int, lastAccess int64) []chrome.Cookie {
	out := make([]chrome.Cookie, 0, n)
	for i := range n {
		out = append(out, chrome.Cookie{
			HostKey: fmt.Sprintf(".bulk%d.com", i), Name: "c", Value: "v", Path: "/",
			IsSecure: 1, SameSite: -1, LastAccessUTC: lastAccess,
		})
	}
	return out
}

// TestBuildCookieParams_CapsAtChromeGlobalLimit: Chrome's cookie store holds
// at most ~3300 cookies and silently evicts the least-recently-accessed ones
// past that, while Storage.setCookies still reports success. A batch larger
// than the limit must be trimmed to MaxInjectCookies so what we push is
// exactly what Chrome keeps.
func TestBuildCookieParams_CapsAtChromeGlobalLimit(t *testing.T) {
	got := BuildCookieParams(bulkCookies(4868, 1))
	if len(got) != MaxInjectCookies {
		t.Fatalf("want %d params (Chrome global cap), got %d", MaxInjectCookies, len(got))
	}
}

// TestBuildCookieParams_KeepsMostRecentlyUsed is the regression for the
// GitHub-redirects-to-/login bug: the user's live session cookies came early
// in a 4868-cookie batch, were set first, and so were the first ones Chrome
// evicted. The params must be ordered least-recently-used first, so the
// cookies the user actually uses are set last, and the trim must drop the
// stale tail, never the session.
func TestBuildCookieParams_KeepsMostRecentlyUsed(t *testing.T) {
	in := append(githubSessionCookies(1_000), bulkCookies(4863, 500)...)
	got := BuildCookieParams(in)
	if len(got) != MaxInjectCookies {
		t.Fatalf("want %d params, got %d", MaxInjectCookies, len(got))
	}
	tail := got[len(got)-5:]
	for i, want := range []string{"user_session", "__Host-user_session_same_site", "logged_in", "_gh_sess", "_device_id"} {
		if tail[i].Name != want {
			t.Errorf("tail[%d]: want %q set last, got %q (%s)", i, want, tail[i].Name, tail[i].URL)
		}
	}
}

// TestBuildCookieParams_StableWithoutLastAccess: sources without a
// last-access time (the CDP source leaves it 0) keep their input order, so
// small batches are unchanged by the ordering pass.
func TestBuildCookieParams_StableWithoutLastAccess(t *testing.T) {
	in := []chrome.Cookie{
		{HostKey: "b.example", Name: "one", Value: "1", IsSecure: 1},
		{HostKey: "a.example", Name: "two", Value: "2", IsSecure: 1},
		{HostKey: "c.example", Name: "three", Value: "3", IsSecure: 1},
	}
	got := BuildCookieParams(in)
	for i, want := range []string{"one", "two", "three"} {
		if got[i].Name != want {
			t.Errorf("param %d: want %q, got %q", i, want, got[i].Name)
		}
	}
}

// TestAttachAndInject_LargeBatchKeepsSession reproduces the field failure
// against a real Chrome: a 4868-cookie batch whose GitHub session cookies
// come first. Before the fix Chrome evicted them during the same
// Storage.setCookies call that reported success. Gated because it launches
// Chrome: AGENTCOOKIE_LIVE_CDP_TEST=1 go test ./internal/livecdp/
func TestAttachAndInject_LargeBatchKeepsSession(t *testing.T) {
	if os.Getenv("AGENTCOOKIE_LIVE_CDP_TEST") == "" {
		t.Skip("set AGENTCOOKIE_LIVE_CDP_TEST=1 to run the live-Chrome large-batch test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	oc, err := LaunchOwnedChrome(ctx, "", t.TempDir(), freePort(t), true)
	if err != nil {
		t.Fatalf("LaunchOwnedChrome: %v", err)
	}
	defer oc.Close()

	in := append(githubSessionCookies(1_000), bulkCookies(4863, 500)...)
	n, err := AttachAndInject(ctx, oc.Endpoint, in)
	if err != nil || n != 1 {
		t.Fatalf("AttachAndInject: contexts=%d err=%v", n, err)
	}

	allocCtx, allocCancel := chromedp.NewRemoteAllocator(ctx, oc.Endpoint+"/json/version")
	defer allocCancel()
	bctx, bcancel := chromedp.NewContext(allocCtx)
	defer bcancel()
	if err := chromedp.Run(bctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	stored, err := storage.GetCookies().Do(cdp.WithExecutor(bctx, chromedp.FromContext(bctx).Browser))
	if err != nil {
		t.Fatalf("Storage.getCookies: %v", err)
	}
	have := map[string]bool{}
	for _, c := range stored {
		if strings.HasSuffix(c.Domain, "github.com") {
			have[c.Name] = true
		}
	}
	for _, c := range githubSessionCookies(0) {
		if !have[c.Name] {
			t.Errorf("GitHub cookie %q evicted from the cookie store (store holds %d cookies)", c.Name, len(stored))
		}
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Expired cookies never take a live cookie's slot under the cap: Chrome
// cannot keep an expired cookie, so counting it would push out a usable
// session for nothing.
func TestBuildCookieParams_ExpiredCookiesDoNotTakeSlots(t *testing.T) {
	past := (time.Now().Add(-time.Hour).Unix() + 11644473600) * 1e6
	expired := bulkCookies(MaxInjectCookies, 3_000_000)
	for i := range expired {
		expired[i].ExpiresUTC = past
		expired[i].HasExpires = 1
	}
	batch := append(githubSessionCookies(1_000_000), expired...)
	params := BuildCookieParams(batch)
	if len(params) != len(githubSessionCookies(0)) {
		t.Fatalf("got %d params, want only the %d unexpired session cookies", len(params), len(githubSessionCookies(0)))
	}
	for _, p := range params {
		if p.Name == "c" {
			t.Fatalf("unexpected cookie %q kept", p.Name)
		}
	}
}

func TestHasAccessTimes(t *testing.T) {
	if HasAccessTimes(bulkCookies(3, 0)) {
		t.Fatal("cookies without last access times reported as having them")
	}
	if !HasAccessTimes(githubSessionCookies(5)) {
		t.Fatal("cookies with last access times reported as lacking them")
	}
}
