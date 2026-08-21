package pac

// lifecycle_store_test.go — unit coverage for the node-local lifecycle store:
// missing-file no-op, corrupt-file quarantine-and-degrade, disk round-trip,
// Delete, and Snapshot/Restore isolation.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLifecycleStore_LoadMissingIsNoOp(t *testing.T) {
	var s LifecycleStore
	if err := s.Load(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Fatalf("missing file should be a no-op, got %v", err)
	}
	if _, ok := s.Get("x"); ok {
		t.Error("empty store should have no records")
	}
}

func TestLifecycleStore_LoadCorruptQuarantinesAndDegrades(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pac_profiles_lifecycle.json")
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var s LifecycleStore
	err := s.Load(path)
	if err == nil {
		t.Fatal("corrupt file should surface an error (for the caller to log)")
	}
	// Degrade, not crash: the store must come up empty and usable...
	if _, ok := s.Get("x"); ok {
		t.Error("store should be empty after quarantine")
	}
	if err := s.Put(&ProfileLifecycle{ProfileID: "x"}); err != nil {
		t.Fatalf("store must be usable after quarantine: %v", err)
	}
	// ...and the bad file must be moved aside.
	if _, statErr := os.Stat(path + ".corrupt"); statErr != nil {
		t.Errorf("corrupt file should be quarantined to %s.corrupt", path)
	}
}

func TestLifecycleStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lc.json")
	var s LifecycleStore
	if err := s.Load(path); err != nil {
		t.Fatal(err)
	}
	lc := &ProfileLifecycle{
		ProfileID: "hq", ActiveN: 2,
		Revisions: []PublishedRevision{
			{N: 1, Author: "a", TS: "t1", Spec: Profile{ID: "hq", Rules: []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect}}}},
			{N: 2, Author: "b", TS: "t2", Spec: Profile{ID: "hq"}},
		},
	}
	if err := s.Put(lc); err != nil {
		t.Fatal(err)
	}
	// Reload from disk into a fresh store.
	var s2 LifecycleStore
	if err := s2.Load(path); err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("hq")
	if !ok || got.ActiveN != 2 || len(got.Revisions) != 2 {
		t.Fatalf("round-trip lost data: %+v", got)
	}
	if got.Revisions[0].Spec.Rules[0].Pattern != "x.example" {
		t.Error("nested rule spec did not round-trip")
	}
	// Get returns a deep copy — mutating it must not affect the store.
	got.Revisions[0].Spec.Rules[0].Pattern = "mutated"
	again, _ := s2.Get("hq")
	if again.Revisions[0].Spec.Rules[0].Pattern != "x.example" {
		t.Error("Get must return a deep copy")
	}
}

func TestLifecycleStore_Delete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lc.json")
	var s LifecycleStore
	_ = s.Load(path)
	_ = s.Put(&ProfileLifecycle{ProfileID: "hq"})
	if err := s.Delete("hq"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("hq"); ok {
		t.Error("record should be gone after Delete")
	}
	if err := s.Delete("hq"); err != nil {
		t.Errorf("deleting a missing record should be a no-op, got %v", err)
	}
}

func TestLifecycleStore_SnapshotRestore(t *testing.T) {
	var s LifecycleStore
	_ = s.Load(filepath.Join(t.TempDir(), "lc.json"))
	_ = s.Put(&ProfileLifecycle{ProfileID: "hq", ActiveN: 1})
	snap := s.Snapshot()
	_ = s.Put(&ProfileLifecycle{ProfileID: "other", ActiveN: 9})
	s.Restore(snap)
	if _, ok := s.Get("other"); ok {
		t.Error("Restore should have removed the post-snapshot record")
	}
	if got, ok := s.Get("hq"); !ok || got.ActiveN != 1 {
		t.Error("Restore should have kept the snapshotted record")
	}
}
