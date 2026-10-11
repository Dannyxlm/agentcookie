package state

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTeammatesPath(t *testing.T) {
	if got, want := TeammatesPath("/h"), filepath.Join("/h", ".agentcookie", "teammates-state.json"); got != want {
		t.Fatalf("TeammatesPath = %q, want %q", got, want)
	}
}

func TestTeammateStoreMissingFileStartsEmpty(t *testing.T) {
	s, err := OpenTeammateStore(filepath.Join(t.TempDir(), "teammates-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	snap := s.Snapshot()
	if len(snap.Teammates) != 0 || len(snap.MigratedLegacy) != 0 {
		t.Fatalf("fresh store not empty: %+v", snap)
	}
}

func TestTeammateStoreUpdatePersistsAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "teammates-state.json")
	s, err := OpenTeammateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	err = s.Update(func(st *TeammatesState) error {
		r := st.Teammate("grokbot")
		r.BoundNodeID = "nGROK"
		r.LastPulledAt = at
		r.LastPullError = ""
		st.AddMigratedLegacy("instinct", at)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v, want 0600", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"last_pulled_at"`) || !strings.Contains(string(raw), `"migrated_legacy"`) {
		t.Fatalf("state file missing fields: %s", raw)
	}

	reopened, err := OpenTeammateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := reopened.Record("grokbot")
	if !ok || rec.BoundNodeID != "nGROK" || !rec.LastPulledAt.Equal(at) {
		t.Fatalf("record not persisted: %+v ok=%v", rec, ok)
	}
	if !reopened.IsMigrated("instinct") || reopened.IsMigrated("grokbot") {
		t.Fatal("migrated_legacy not persisted")
	}
}

func TestTeammateStoreAddMigratedLegacyIsIdempotent(t *testing.T) {
	var st TeammatesState
	if !st.AddMigratedLegacy("instinct", time.Now()) {
		t.Fatal("first add should report true")
	}
	if st.AddMigratedLegacy("instinct", time.Now()) {
		t.Fatal("second add should report false")
	}
	if len(st.MigratedLegacy) != 1 {
		t.Fatalf("migrated = %+v", st.MigratedLegacy)
	}
}

func TestTeammateStoreSnapshotIsACopy(t *testing.T) {
	s, _ := OpenTeammateStore(filepath.Join(t.TempDir(), "s.json"))
	_ = s.Update(func(st *TeammatesState) error { st.Teammate("dot"); return nil })
	snap := s.Snapshot()
	snap.Teammates["dot"].BoundNodeID = "mutated"
	if rec, _ := s.Record("dot"); rec.BoundNodeID != "" {
		t.Fatal("Snapshot shares memory with the store")
	}
}

func TestTeammateStoreCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTeammateStore(path); err == nil {
		t.Fatal("corrupt state should be an error, not silently empty")
	}
}

func TestTeammateStoreConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	s, _ := OpenTeammateStore(path)
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_ = s.Update(func(st *TeammatesState) error {
				st.Teammate("grokbot").LastPulledAt = time.Now()
				return nil
			})
		})
	}
	wg.Wait()
	if _, err := OpenTeammateStore(path); err != nil {
		t.Fatalf("state unreadable after concurrent updates: %v", err)
	}
}

func TestTeammateStoreNoOpUpdateSkipsWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "teammates-state.json")
	s, err := OpenTeammateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// A no-op Update on a store with no file yet still writes it.
	if err := s.Update(func(*TeammatesState) error { return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("first Update did not write the file: %v", err)
	}

	if err := s.Update(func(st *TeammatesState) error {
		st.LaptopDNSName = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("no-op Update rewrote the state file")
	}

	if err := s.Update(func(st *TeammatesState) error {
		st.LaptopDNSName = "laptop.tail.ts.net"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	changed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(after, changed) {
		t.Fatal("changing Update did not rewrite the state file")
	}

	// A reopened store treats the loaded file as current.
	s2, err := OpenTeammateStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Update(func(*TeammatesState) error { return nil }); err != nil {
		t.Fatal(err)
	}
	reopened, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(changed, reopened) {
		t.Fatal("no-op Update after reopen rewrote the state file")
	}
	if got := s2.Snapshot().LaptopDNSName; got != "laptop.tail.ts.net" {
		t.Fatalf("LaptopDNSName = %q", got)
	}
}
