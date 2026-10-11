package sinkpush

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mvanhorn/agentcookie/internal/chrome"
)

// blockingCtxAdapter blocks in PushContext until its context ends.
type blockingCtxAdapter struct{ stubAdapterBase }

func (a *blockingCtxAdapter) Push([]chrome.Cookie) error {
	select {} // a context-blind push would hang forever
}

func (a *blockingCtxAdapter) PushContext(ctx context.Context, _ []chrome.Cookie) error {
	<-ctx.Done()
	return ctx.Err()
}

// countingAdapter counts pushes.
type countingAdapter struct {
	stubAdapterBase
	pushes atomic.Int32
}

func (a *countingAdapter) Push([]chrome.Cookie) error { a.pushes.Add(1); return nil }

type stubAdapterBase struct{ name string }

func (s stubAdapterBase) Name() string                 { return s.name }
func (s stubAdapterBase) CLIBinary() string            { return "/nonexistent/" + s.name }
func (s stubAdapterBase) IsInstalled() bool            { return true }
func (s stubAdapterBase) CookieHostPatterns() []string { return nil }

var ctxTestCookies = []chrome.Cookie{{HostKey: ".example.com", Name: "x", Value: "1"}}

// RunAll hands its context to adapters that take one, so a caller's
// budget stops a stalled adapter.
func TestRunAll_ContextBoundsAdapterPush(t *testing.T) {
	t.Cleanup(SetRegistryForTesting([]Adapter{&blockingCtxAdapter{stubAdapterBase{"blocker"}}}))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan []Result, 1)
	go func() { done <- RunAll(ctx, ctxTestCookies) }()
	select {
	case rs := <-done:
		if len(rs) != 1 || !errors.Is(rs[0].Err, context.DeadlineExceeded) {
			t.Fatalf("results = %+v, want one DeadlineExceeded failure", rs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunAll ignored its context and hung on a stalled adapter")
	}
}

// Once the context is done, the remaining adapters are not started and
// are reported as failed, not as pushed.
func TestRunAll_DoneContextStartsNoAdapter(t *testing.T) {
	a := &countingAdapter{stubAdapterBase: stubAdapterBase{"counter"}}
	t.Cleanup(SetRegistryForTesting([]Adapter{a}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rs := RunAll(ctx, ctxTestCookies)
	if a.pushes.Load() != 0 {
		t.Fatalf("adapter pushed %d times after the context ended", a.pushes.Load())
	}
	if len(rs) != 1 || !errors.Is(rs[0].Err, context.Canceled) {
		t.Fatalf("results = %+v, want one Canceled failure", rs)
	}
}

// Adapters passed per call run after the registered ones.
func TestRunAll_RunsPerCallAdapters(t *testing.T) {
	t.Cleanup(SetRegistryForTesting(nil))
	a := &countingAdapter{stubAdapterBase: stubAdapterBase{"extra"}}
	rs := RunAll(context.Background(), ctxTestCookies, a)
	if a.pushes.Load() != 1 || len(rs) != 1 || rs[0].Name != "extra" {
		t.Fatalf("pushes=%d results=%+v, want the per-call adapter run once", a.pushes.Load(), rs)
	}
	if AnyInstalled() {
		t.Fatal("registry should be empty")
	}
	if !AnyInstalled(a) {
		t.Fatal("AnyInstalled must count per-call adapters")
	}
}

// hangingScript writes a stub executable whose shell forks a long sleep,
// so the sleep keeps the output pipes open after the shell is killed.
func hangingScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	p := filepath.Join(t.TempDir(), "stub")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func expectBoundedErr(t *testing.T, what string, push func(ctx context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- push(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("%s: a killed command must not report success", what)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: a hung child command outlived its context", what)
	}
}

// The cmux adapter stops a hung cmux command when its context ends,
// including a grandchild that holds the output pipes, and reports it.
func TestCmuxPushContext_KillsHungCommand(t *testing.T) {
	a := NewCmux(hangingScript(t, "sleep 30"), nil)
	expectBoundedErr(t, "cmux", func(ctx context.Context) error { return a.PushContext(ctx, ctxTestCookies) })
}

// A hung set mid-batch is not swallowed by the per-cookie fallback.
func TestCmuxPushContext_DoneContextIsNotAPerCookieReject(t *testing.T) {
	f := &fakeCmux{}
	a := newTestCmux(f, nil)
	ctx, cancel := context.WithCancel(context.Background())
	a.run = func(c context.Context, args ...string) (string, error) {
		if len(args) > 1 && args[1] == "browser.cookies.set" {
			cancel()
			return "", errors.New("signal: killed")
		}
		return f.run(args...)
	}
	if err := a.PushContext(ctx, ctxTestCookies); err == nil {
		t.Fatal("a set killed by the context must fail the push")
	}
}

// The instacart adapter's `auth paste` is bounded the same way.
func TestInstacartPushContext_KillsHungCommand(t *testing.T) {
	a := &InstacartAdapter{binary: hangingScript(t, "cat >/dev/null; sleep 30")}
	cookies := []chrome.Cookie{{HostKey: ".instacart.com", Name: "s", Value: "v"}}
	expectBoundedErr(t, "instacart", func(ctx context.Context) error { return a.PushContext(ctx, cookies) })
}
