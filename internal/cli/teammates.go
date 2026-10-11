package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/mvanhorn/agentcookie/internal/config"
	"github.com/mvanhorn/agentcookie/internal/state"
)

// activeTeammates is the running daemon's teammate hub. nil (no source
// --watch, or tests that do not install one) means teammate mode is off and
// every caller keeps its pre-teammate behavior.
var activeTeammates *teammateHub

// teammatesReloadDebounce coalesces the burst of fsnotify events an editor
// produces for one save. Overridable in tests.
var teammatesReloadDebounce = 200 * time.Millisecond

// errTeammatesStateUnavailable suspends teammate mode when the daemon-owned
// state file cannot be opened.
var errTeammatesStateUnavailable = errors.New("teammates state unavailable")

// teammateHub is the daemon's teammate-mode core. It owns the owner's list
// (teammates.yaml, hot-reloaded), the daemon-owned state store, the
// per-remote-IP WhoIs cache, the pending pairings served on /pair, and the
// event channel the teammate lifecycle consumes.
//
// Without teammates.yaml the hub reports inactive and every consumer
// (push fan-out, /pull authorization, /pair) behaves exactly as before.
type teammateHub struct {
	configDir string
	store     *state.TeammateStore
	log       io.Writer
	now       func() time.Time

	mu      sync.RWMutex
	present bool                    // teammates.yaml exists
	cfg     *config.TeammatesConfig // last file that loaded; nil before any
	loadErr error                   // non-nil: teammate pull and pair suspended
	// legacyPeers are the peer names of source.yaml push sinks; a listed
	// name among them is migrated to teammate mode.
	legacyPeers []string
	onReload    []func()

	whois    *whoisCache
	pairings *pendingPairings
	events   chan TeammateEvent
}

// newTeammateHub builds a hub. store may be nil when the state file could
// not be opened; teammate mode then stays suspended (fail closed).
func newTeammateHub(configDir string, store *state.TeammateStore, legacyPeers []string) *teammateHub {
	h := &teammateHub{
		configDir:   configDir,
		store:       store,
		log:         os.Stderr,
		now:         time.Now,
		legacyPeers: append([]string(nil), legacyPeers...),
		events:      make(chan TeammateEvent, teammateEventBuffer),
	}
	h.whois = newWhoisCache(func() time.Time { return h.now() })
	h.pairings = newPendingPairings()
	return h
}

// OnReload registers fn to run after every reload attempt (good or bad), on
// the reloading goroutine. The lifecycle (U4) subscribes here so a file edit
// reaches /pull authorization and the lifecycle within one event.
func (h *teammateHub) OnReload(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onReload = append(h.onReload, fn)
}

// Reload re-reads teammates.yaml and applies it. A parse failure keeps the
// previous good list only for push suppression and suspends every teammate
// /pull and /pair until a good file loads. Returns the load error, if any.
func (h *teammateHub) Reload() error {
	cfg, err := config.LoadTeammates(h.configDir)
	_, statErr := os.Stat(config.TeammatesPath(h.configDir))
	present := statErr == nil || err != nil
	if err == nil && present && h.store == nil {
		err = errTeammatesStateUnavailable
	}

	h.mu.Lock()
	h.present = present
	h.loadErr = err
	if err == nil {
		h.cfg = cfg
	}
	subs := append([]func(){}, h.onReload...)
	h.mu.Unlock()

	if h.store != nil {
		h.applyToState(cfg, err)
	}
	if err != nil {
		fmt.Fprintf(h.log, "agentcookie source: teammates suspended: %v\n", err)
	}
	for _, fn := range subs {
		fn()
	}
	return err
}

// applyToState records listings, removals, the config error, and legacy
// push migrations in teammates-state.json.
func (h *teammateHub) applyToState(cfg *config.TeammatesConfig, loadErr error) {
	now := h.now().UTC()
	var migrated []string
	err := h.store.Update(func(st *state.TeammatesState) error {
		if loadErr != nil {
			if st.ConfigError != loadErr.Error() {
				st.ConfigError = loadErr.Error()
				st.ConfigErrorAt = now
			}
			return nil
		}
		st.ConfigError = ""
		st.ConfigErrorAt = time.Time{}
		for _, name := range cfg.Names() {
			rec := st.Teammate(name)
			if rec.ListedAt.IsZero() || !rec.RemovedAt.IsZero() {
				rec.ListedAt = now
				rec.RemovedAt = time.Time{}
			}
		}
		for name, rec := range st.Teammates {
			if !cfg.Has(name) && rec.RemovedAt.IsZero() {
				rec.RemovedAt = now
			}
		}
		for _, peer := range h.legacyPeers {
			if peer != "" && cfg.Has(peer) && st.AddMigratedLegacy(peer, now) {
				migrated = append(migrated, peer)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(h.log, "agentcookie source: teammates: %v\n", err)
		return
	}
	for _, peer := range migrated {
		fmt.Fprintf(h.log, "agentcookie source: %s is now a teammate and pulls its cookies; push to it is off. Its key is kept. You can delete its sink entry from source.yaml (agentcookie never edits that file).\n", peer)
	}
}

// Active reports whether teammate mode is on: teammates.yaml lists at least
// one name, or exists but does not load (fail closed).
func (h *teammateHub) Active() bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.present {
		return false
	}
	return h.loadErr != nil || (h.cfg != nil && len(h.cfg.Teammates) > 0)
}

// Suspended returns the error that has teammate mode suspended, or nil.
func (h *teammateHub) Suspended() error {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.loadErr
}

// IsListed reports whether name is a listed teammate in a file that loaded.
// Always false while suspended.
func (h *teammateHub) IsListed(name string) bool {
	if h == nil {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.loadErr == nil && h.present && h.cfg.Has(name)
}

// IsTeammateName reports whether name belongs to teammate mode now or ever
// did: listed (in the last good file), recorded in the state file
// (including removed teammates), or a migrated legacy peer. Such a name is
// never authorized under the non-teammate peer rules.
func (h *teammateHub) IsTeammateName(name string) bool {
	if h == nil || name == "" {
		return false
	}
	h.mu.RLock()
	listed := h.present && h.cfg.Has(name)
	h.mu.RUnlock()
	if listed {
		return true
	}
	if h.store == nil {
		return false
	}
	if _, ok := h.store.Record(name); ok {
		return true
	}
	return h.store.IsMigrated(name)
}

// SuppressPush reports whether the legacy push to peer must be skipped: the
// peer was migrated to teammate mode (persisted, survives removal), or it is
// listed right now.
func (h *teammateHub) SuppressPush(peer string) bool {
	if h == nil || peer == "" {
		return false
	}
	h.mu.RLock()
	listed := h.present && h.cfg.Has(peer)
	h.mu.RUnlock()
	if listed {
		return true
	}
	return h.store != nil && h.store.IsMigrated(peer)
}

// Watch hot-reloads teammates.yaml on fsnotify events until ctx ends. It
// watches the config directory so editor rename-saves and a file created
// after startup are both seen.
func (h *teammateHub) Watch(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("teammates watcher: %w", err)
	}
	defer fsw.Close()
	if err := fsw.Add(h.configDir); err != nil {
		return fmt.Errorf("watch %s: %w", h.configDir, err)
	}
	var timer *time.Timer
	var fire <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case ev, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if filepath.Base(ev.Name) != config.TeammatesFile {
				continue
			}
			if timer == nil {
				timer = time.NewTimer(teammatesReloadDebounce)
			} else {
				timer.Reset(teammatesReloadDebounce)
			}
			fire = timer.C
		case <-fire:
			fire = nil
			_ = h.Reload()
		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(h.log, "agentcookie source: teammates watcher: %v\n", err)
		}
	}
}

// legacyPeerNames returns the peer names of cfg's push sinks.
func legacyPeerNames(cfg *config.SourceConfig) []string {
	if cfg == nil {
		return nil
	}
	var out []string
	for _, s := range cfg.ResolvedSinks() {
		if s.Peer != "" {
			out = append(out, s.Peer)
		}
	}
	return out
}

// startTeammates opens the state file and loads teammates.yaml; with watch
// it also hot-reloads edits for the life of ctx. It always returns a hub;
// without teammates.yaml the hub is inactive.
func startTeammates(ctx context.Context, configDir, home string, cfg *config.SourceConfig, watch bool) *teammateHub {
	store, err := state.OpenTeammateStore(state.TeammatesPath(home))
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentcookie source: %v; teammate pulls and pairing stay suspended\n", err)
		store = nil
	}
	hub := newTeammateHub(configDir, store, legacyPeerNames(cfg))
	_ = hub.Reload()
	if !watch {
		return hub
	}
	go func() {
		if err := hub.Watch(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "agentcookie source: %v; teammates.yaml edits need a daemon restart\n", err)
		}
	}()
	return hub
}
