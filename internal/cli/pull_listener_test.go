package cli

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/state"
	"github.com/mvanhorn/agentcookie/internal/tsclient"
)

type listenerStatus struct {
	up   bool
	addr string
}

// Covers R10 / KTD9: Tailscale unavailable at start and available later
// brings the listener up without a restart, an IP change rebinds, and the
// address going away takes it down.
func TestPullListenerWaitsForTailscaleAndRebinds(t *testing.T) {
	var mu sync.Mutex
	ip, ipErr := "", error(tsclient.ErrNoTailnetInterface)
	setIP := func(v string, err error) {
		mu.Lock()
		defer mu.Unlock()
		ip, ipErr = v, err
	}
	restore := setPullListenerSeamsForTesting(func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		return ip, ipErr
	}, "0", 5*time.Millisecond, 20*time.Millisecond)
	t.Cleanup(restore)

	prevListen := sourcePullListen
	sourcePullListen = ""
	t.Cleanup(func() { sourcePullListen = prevListen })

	statuses := make(chan listenerStatus, 64)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := startWatchPullListener(ctx, &config.SourceConfig{}, func(up bool, addr string) {
		statuses <- listenerStatus{up, addr}
	}); err != nil {
		t.Fatalf("no Tailscale at start must not fail the daemon: %v", err)
	}
	if s := nextStatus(t, statuses); s.up {
		t.Fatalf("first status = %+v, want down", s)
	}

	setIP("127.0.0.1", nil)
	first := waitStatus(t, statuses, true)
	if !strings.HasPrefix(first.addr, "127.0.0.1:") {
		t.Fatalf("listener addr = %q", first.addr)
	}
	healthz(t, first.addr, true)

	setIP("localhost", nil)
	second := waitStatus(t, statuses, true)
	if second.addr == first.addr {
		t.Fatalf("IP change did not rebind (still %s)", second.addr)
	}
	healthz(t, second.addr, true)
	healthz(t, first.addr, false)

	setIP("", tsclient.ErrNoTailnetInterface)
	waitStatus(t, statuses, false)
	healthz(t, second.addr, false)
}

func nextStatus(t *testing.T, ch <-chan listenerStatus) listenerStatus {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no listener status")
		return listenerStatus{}
	}
}

func waitStatus(t *testing.T, ch <-chan listenerStatus, up bool) listenerStatus {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case s := <-ch:
			if s.up == up {
				return s
			}
		case <-deadline:
			t.Fatalf("listener never reported up=%v", up)
		}
	}
}

func healthz(t *testing.T, addr string, want bool) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/healthz", addr))
	if resp != nil {
		resp.Body.Close()
	}
	if got := err == nil && resp.StatusCode == http.StatusOK; got != want {
		t.Fatalf("healthz on %s reachable=%v, want %v (err=%v)", addr, got, want, err)
	}
}

func TestPullListenerStateRecordedInSourceState(t *testing.T) {
	path := t.TempDir() + "/source-state.json"
	w := state.NewWriter(path)
	st := &state.SourceState{Role: "source"}
	recordPullListenerState(st, w, true, "100.64.0.1:9998")
	got, err := state.LoadSource(path)
	if err != nil || got.PullListener != "up" || got.PullListenerAddr != "100.64.0.1:9998" {
		t.Fatalf("state = %+v err=%v", got, err)
	}
	recordPullListenerState(st, w, false, "")
	got, _ = state.LoadSource(path)
	if got.PullListener != "down" {
		t.Fatalf("pull_listener = %q, want down", got.PullListener)
	}
}
