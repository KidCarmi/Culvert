package pac

// exceptions_durability_test.go — durability / persistence regression coverage
// for the node-local governance store. This is infrastructure: it must survive
// restarts, never brick startup on a bad file, never lose data across a reload,
// and never corrupt its on-disk file under concurrency. Each test pins one of
// those guarantees so a future refactor cannot silently regress it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestDurability_LoadReadErrorNonFatal covers the read-error arm of Load (a path
// that exists but can't be read as a file — here a directory). It must return a
// (non-fatal) error and leave a usable, empty store — never panic or brick.
func TestDurability_LoadReadErrorNonFatal(t *testing.T) {
	dir := t.TempDir() // a directory, not a file → ReadFile errors (not IsNotExist)
	var s ExceptionStore
	if err := s.Load(dir); err == nil {
		t.Error("Load of a directory path should return a read error")
	}
	if len(s.All()) != 0 {
		t.Error("store must be empty after a read error")
	}
	// No quarantine for a read error (only a parse error quarantines).
	if _, err := os.Stat(dir + ".corrupt"); err == nil {
		t.Error("a read error must not quarantine")
	}
}

// TestDurability_PersistMarshalErrorPropagates forces the otherwise-unreachable
// marshal-error path in persistLocked (a map[string]ExceptionRecord always
// marshals) via the exceptionsMarshal seam, proving Put surfaces the error
// rather than silently succeeding.
func TestDurability_PersistMarshalErrorPropagates(t *testing.T) {
	orig := exceptionsMarshal
	t.Cleanup(func() { exceptionsMarshal = orig })
	exceptionsMarshal = func(any) ([]byte, error) { return nil, errors.New("forced marshal failure") }

	path := filepath.Join(t.TempDir(), "pac_exceptions.json")
	var s ExceptionStore
	if err := s.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := s.Put(ExceptionRecord{ProfileID: "a", Owner: "o", Reason: "r"}); err == nil {
		t.Error("Put must propagate a marshal error")
	}
}

// TestDurability_PutWritesValidAtomic0600 proves every Put lands a valid,
// re-parseable JSON file with 0600 perms (governance metadata is 0600-class).
func TestDurability_PutWritesValidAtomic0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pac_exceptions.json")
	var s ExceptionStore
	if err := s.Load(path); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := s.Put(ExceptionRecord{ProfileID: "hq", Owner: "o", Reason: "r"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]ExceptionRecord
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("on-disk file is not valid JSON: %v", err)
	}
	if round["hq"].Owner != "o" {
		t.Errorf("on-disk record wrong: %+v", round["hq"])
	}
}

// TestDurability_SurvivesRestart proves a fresh store (simulating a process
// restart) loads exactly what a prior store persisted, and computed status is
// identical across the "restart".
func TestDurability_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pac_exceptions.json")
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

	var pre ExceptionStore
	if err := pre.Load(path); err != nil {
		t.Fatal(err)
	}
	rec := ExceptionRecord{
		ProfileID: "vendor", Owner: "neteng", Reason: "saas",
		ExpiresAt: now.AddDate(0, 0, 30).Format(time.RFC3339),
	}
	if err := pre.Put(rec); err != nil {
		t.Fatal(err)
	}
	wantStatus := rec.Status(now, true)

	// "Restart": brand-new store instance over the same file.
	var post ExceptionStore
	if err := post.Load(path); err != nil {
		t.Fatalf("reload after restart: %v", err)
	}
	got, ok := post.Get("vendor")
	if !ok {
		t.Fatal("record did not survive restart")
	}
	// Put mints the 2F-A token (revision 1) for a record stored without one;
	// the persisted record must reload byte-identical to what Put stored.
	stored, _ := pre.Get("vendor")
	if stored.Revision != 1 {
		t.Fatalf("Put must mint revision 1 for a token-less record, got %d", stored.Revision)
	}
	if got != stored {
		t.Errorf("record changed across restart:\n pre=%+v\npost=%+v", stored, got)
	}
	if s := got.Status(now, true); s != wantStatus {
		t.Errorf("status changed across restart: pre=%q post=%q", wantStatus, s)
	}
}

// TestDurability_BadFileMatrix pins the load behavior for every malformed file
// class: startup must NEVER be bricked by governance metadata.
func TestDurability_BadFileMatrix(t *testing.T) {
	cases := []struct {
		name       string
		content    string
		wantErr    bool
		wantQuar   bool // a .corrupt sibling is written
		wantLoaded int  // records after load
	}{
		{"corrupt json", "{not json", true, true, 0},
		{"empty file", "", true, true, 0},
		{"json null", "null", false, false, 0},
		{"empty object", "{}", false, false, 0},
		{"valid one record", `{"hq":{"profileId":"hq","owner":"o","reason":"r"}}`, false, false, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "pac_exceptions.json")
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			var s ExceptionStore
			err := s.Load(path)
			if c.wantErr && err == nil {
				t.Errorf("want a (non-fatal) error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("want no error, got %v", err)
			}
			if got := len(s.All()); got != c.wantLoaded {
				t.Errorf("loaded %d records, want %d", got, c.wantLoaded)
			}
			// The store must always be usable after load (never nil-map panic).
			if err := s.Put(ExceptionRecord{ProfileID: "x", Owner: "o", Reason: "r"}); err != nil {
				t.Errorf("store unusable after load: %v", err)
			}
			if _, err := os.Stat(path + ".corrupt"); c.wantQuar && err != nil {
				t.Errorf("expected quarantine file %s.corrupt", path)
			}
		})
	}
}

// TestDurability_ConcurrentWritesKeepFileValid runs many concurrent Puts/Deletes
// against a file-backed store and then proves the final on-disk file is still
// valid, re-loadable JSON (atomic write never leaves a torn file). Run under
// -race this also proves the locking is sound.
func TestDurability_ConcurrentWritesKeepFileValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pac_exceptions.json")
	var s ExceptionStore
	if err := s.Load(path); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			id := fmt.Sprintf("g%d", g)
			for i := 0; i < 100; i++ {
				_ = s.Put(ExceptionRecord{ProfileID: id, Owner: "o", Reason: "r"})
				if i%4 == 0 {
					_ = s.Delete(id)
				}
			}
		}(g)
	}
	wg.Wait()

	// Final file must be intact and reloadable into a fresh store.
	var reload ExceptionStore
	if err := reload.Load(path); err != nil {
		t.Fatalf("final file is corrupt after concurrent writes: %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err == nil {
		t.Error("a torn/corrupt file was quarantined — atomic write did not hold under concurrency")
	}
}

// TestDurability_SnapshotRestoreIsolation proves Snapshot/Restore deep-copy so
// test isolation (the -shuffle hermeticity contract) actually holds.
func TestDurability_SnapshotRestoreIsolation(t *testing.T) {
	var s ExceptionStore
	_ = s.Put(ExceptionRecord{ProfileID: "a", Owner: "o1", Reason: "r"})
	snap := s.Snapshot()

	// Mutate after snapshot.
	_ = s.Put(ExceptionRecord{ProfileID: "b", Owner: "o2", Reason: "r"})
	_ = s.Delete("a")

	// Restore must bring back exactly the snapshot state.
	s.Restore(snap)
	if _, ok := s.Get("a"); !ok {
		t.Error("Restore lost the snapshotted record")
	}
	if _, ok := s.Get("b"); ok {
		t.Error("Restore leaked a post-snapshot record")
	}
	// Mutating the snapshot map must not affect the store (deep copy).
	snap.ByID["a"] = ExceptionRecord{ProfileID: "a", Owner: "TAMPERED"}
	if got, _ := s.Get("a"); got.Owner != "o1" {
		t.Errorf("Snapshot did not deep-copy: store owner = %q", got.Owner)
	}
}
