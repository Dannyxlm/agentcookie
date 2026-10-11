package sinkpush

import (
	"context"

	"github.com/mvanhorn/agentcookie/internal/chrome"
)

// registry is the package-level slice of registered adapters. A slice
// (not a map) so iteration order is stable -- adapters run in the
// order they were registered, which makes sink log output predictable
// across runs.
var registry []Adapter

// Register adds an adapter to the package registry. Built-in adapter
// implementations call Register from their package init function; tests
// may also call it to install stub adapters. Registration is
// append-only; there is no Deregister, by design.
func Register(a Adapter) {
	registry = append(registry, a)
}

// All returns a copy of the current registry. Callers iterate the
// returned slice; mutating it does not affect the package registry.
func All() []Adapter {
	out := make([]Adapter, len(registry))
	copy(out, registry)
	return out
}

// resetForTesting clears the registry. Test-only helper; not exported.
func resetForTesting() {
	registry = nil
}

// AnyInstalled reports whether at least one registered adapter, or one of
// the per-call extra adapters, has its target CLI installed. The sink uses
// it to skip the extra-profile Chrome Safe Storage read when no adapter
// could consume those cookies.
func AnyInstalled(extra ...Adapter) bool {
	for _, a := range append(All(), extra...) {
		if a.IsInstalled() {
			return true
		}
	}
	return false
}

// SetRegistryForTesting replaces the package registry with adapters and
// returns a restore func. Test-only seam for callers outside this
// package: the built-in adapters probe the real PATH, so tests that
// depend on which adapters are installed swap the whole registry.
func SetRegistryForTesting(adapters []Adapter) func() {
	prev := registry
	registry = append([]Adapter(nil), adapters...)
	return func() { registry = prev }
}

// RunAll invokes every registered adapter, then each per-call extra
// adapter (config-driven ones such as cmux, which the caller resolves
// from its current config), against the given cookie slice. ctx bounds
// delivery: adapters that implement ContextPusher get it and stop their
// child commands when it ends, and once it is done no further adapter
// starts (each is reported with ctx.Err()). For each adapter:
//
//  1. If IsInstalled returns false, the adapter is skipped (Result with
//     Skipped=true, no error).
//  2. Otherwise, cookies are filtered by the adapter's host patterns.
//     If the filtered slice is empty, the adapter is skipped with
//     SkippedReason="no matching cookies".
//  3. Otherwise, Push is invoked. The Push error (if any) lands in
//     Result.Err. Success returns Pushed=len(filtered).
//
// One adapter's failure does NOT stop subsequent adapters from running.
// The Result slice has one entry per registered adapter, in registration
// order, so callers can log a full report.
func RunAll(ctx context.Context, cookies []chrome.Cookie, extra ...Adapter) []Result {
	adapters := append(All(), extra...)
	results := make([]Result, 0, len(adapters))
	for _, a := range adapters {
		results = append(results, runOne(ctx, a, cookies))
	}
	return results
}

func runOne(ctx context.Context, a Adapter, cookies []chrome.Cookie) Result {
	r := Result{Name: a.Name()}
	if err := ctx.Err(); err != nil {
		r.Err = err
		return r
	}

	if !a.IsInstalled() {
		r.Skipped = true
		r.SkippedReason = "CLI not installed"
		return r
	}

	filtered := filterByHostPatterns(cookies, a.CookieHostPatterns())
	if len(filtered) == 0 {
		r.Skipped = true
		r.SkippedReason = "no matching cookies"
		return r
	}

	valid := make([]chrome.Cookie, 0, len(filtered))
	for _, c := range filtered {
		if err := Validate(c); err != nil {
			r.Invalid++
			continue
		}
		valid = append(valid, c)
	}
	if len(valid) == 0 {
		r.Skipped = true
		r.SkippedReason = "all cookies failed validation"
		return r
	}

	var err error
	if cp, ok := a.(ContextPusher); ok {
		err = cp.PushContext(ctx, valid)
	} else {
		err = a.Push(valid)
	}
	if err != nil {
		r.Err = err
		return r
	}
	r.Pushed = len(valid)
	return r
}
