package pac

// lifecycle_store_test.go — unit coverage for the node-local lifecycle store:
// missing-file no-op, corrupt-file quarantine-and-degrade, disk round-trip,
// Delete, and Snapshot/Restore isolation.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	// ...and the bad file must be moved aside (never deleted), into a
	// timestamped quarantine named by the DURABLE history-reset record
	// (2F-B correction, C1) — the loss is visible, not silent.
	if !errors.Is(err, ErrHistoryReset) {
		t.Fatalf("a quarantine must be reported as a history reset: %v", err)
	}
	r := s.HistoryResetRecord()
	if r == nil || r.QuarantinedTo == "" || !strings.HasPrefix(r.QuarantinedTo, path+".corrupt.") {
		t.Fatalf("reset record must name the quarantined file: %+v", r)
	}
	if _, statErr := os.Stat(r.QuarantinedTo); statErr != nil {
		t.Errorf("corrupt file should be quarantined to %s: %v", r.QuarantinedTo, statErr)
	}
	if _, statErr := os.Stat(resetPathFor(path)); statErr != nil {
		t.Errorf("the reset record must be durable beside the store: %v", statErr)
	}
	// Until acknowledged, every active profile is affected (unscoped); an
	// acknowledgement is per profile and persist-before-swap.
	if !s.ResetAffects("x", true) || s.ResetAffects("x", false) {
		t.Fatal("an unscoped reset affects every ACTIVE profile")
	}
	if err := s.NoteActiveAtReset([]string{"x"}); err != nil {
		t.Fatal(err)
	}
	if !s.ResetAffects("x", true) || s.ResetAffects("y", true) {
		t.Fatal("a scoped reset affects only the profiles active at the reset")
	}
	if err := s.AcknowledgeReset("x", HistoryResetAck{OperationID: "op", By: "admin", At: "t", ActiveRevision: 3, ActiveSpecDigest: "sha256:ab"}); err != nil {
		t.Fatal(err)
	}
	if s.ResetAffects("x", true) {
		t.Fatal("an acknowledged profile is no longer affected")
	}
	// The record (with the acknowledgement) survives a reload.
	var again LifecycleStore
	if err := again.Load(path); err != nil {
		t.Fatalf("reload after quarantine: %v", err)
	}
	if again.ResetAffects("x", true) {
		t.Fatal("acknowledgement must be durable across a reload")
	}
	if r := again.HistoryResetRecord(); r == nil || !r.Scoped || r.Acknowledged["x"].OperationID != "op" {
		t.Fatalf("reset record must reload intact: %+v", r)
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
