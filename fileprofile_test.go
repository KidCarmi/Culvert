package main

// fileprofile_test.go — focused tests for FileProfileStore persistence
// after saveLocked was hardened to write via atomicWriteFile (P3.1
// follow-up #2). Each test uses a fresh &FileProfileStore{} bound to a
// t.TempDir() — no globalProfileStore mutation, safe under -shuffle=on.

import (
	"path/filepath"
	"testing"
)

// Round-trip: a profile created on one store instance must be readable
// from a fresh store instance pointed at the same file.
func TestFileProfileStore_Save_PersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")

	a := &FileProfileStore{}
	if err := a.Load(path); err != nil {
		t.Fatalf("Load (first-run seed): %v", err)
	}
	prof, err := a.Create("Custom", []string{".x", ".y"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if prof.ID == "" {
		t.Fatal("Create returned empty ID")
	}

	b := &FileProfileStore{}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load (reopen): %v", err)
	}
	got := b.GetByName("Custom")
	if got == nil {
		t.Fatal("profile not present after reload")
	}
	if len(got.Extensions) != 2 || got.Extensions[0] != ".x" || got.Extensions[1] != ".y" {
		t.Fatalf("Extensions = %v, want [.x .y]", got.Extensions)
	}
}

// atomicWriteFile creates *.tmp.* files in the parent dir and renames
// them into place. After Create/Update/Delete the parent dir must
// contain the JSON file only — no orphaned tmp files.
func TestFileProfileStore_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")

	s := &FileProfileStore{}
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	prof, err := s.Create("Custom", []string{".a"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Update(prof.ID, "Custom", []string{".b"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := s.Delete(prof.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	assertNoTmpLeak(t, dir)
}

// Overwrite path: after Update, a fresh store must read the updated
// extensions, not the original ones. Pins the rename-over-rename
// behaviour now that each save produces a new inode.
func TestFileProfileStore_Save_OverwritePersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")

	a := &FileProfileStore{}
	if err := a.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	prof, err := a.Create("Custom", []string{".old"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := a.Update(prof.ID, "Custom", []string{".new"}); err != nil {
		t.Fatalf("Update: %v", err)
	}

	b := &FileProfileStore{}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load (reopen): %v", err)
	}
	got := b.GetByID(prof.ID)
	if got == nil {
		t.Fatal("profile missing after reload")
	}
	if len(got.Extensions) != 1 || got.Extensions[0] != ".new" {
		t.Fatalf("Extensions = %v, want [.new]", got.Extensions)
	}
}

// ── ReplaceAll persistence (P3.1 follow-up #3) ────────────────────────────

// ReplaceAll persists the new profile set so DP nodes survive restart with
// the latest cluster-pushed state.
func TestFileProfileStore_ReplaceAll_PersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")

	a := &FileProfileStore{}
	if err := a.Load(path); err != nil {
		t.Fatalf("Load (first-run seed): %v", err)
	}
	a.ReplaceAll([]FileExtProfile{
		{ID: "p1", Name: "Cluster", Extensions: []string{".cl"}},
		{ID: "p2", Name: "Cluster2", Extensions: []string{".cl2"}},
	})

	b := &FileProfileStore{}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load (reopen): %v", err)
	}
	got := b.List()
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Name != "Cluster" || got[1].Name != "Cluster2" {
		t.Fatalf("names = [%q %q], want [Cluster Cluster2]", got[0].Name, got[1].Name)
	}
}

// ReplaceAll's atomicWriteFile path must not orphan *.tmp.* files in the
// parent directory.
func TestFileProfileStore_ReplaceAll_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")

	s := &FileProfileStore{}
	if err := s.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	s.ReplaceAll([]FileExtProfile{
		{ID: "x", Name: "X", Extensions: []string{".x"}},
	})
	s.ReplaceAll([]FileExtProfile{
		{ID: "y", Name: "Y", Extensions: []string{".y"}},
	})

	assertNoTmpLeak(t, dir)
}

// ReplaceAll is replacement, not merge: any pre-existing profile must be
// gone after the call, both in memory and on disk.
func TestFileProfileStore_ReplaceAll_OverwritesPreviousState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileprofiles.json")

	a := &FileProfileStore{}
	if err := a.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := a.Create("Old", []string{".o"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	a.ReplaceAll([]FileExtProfile{
		{ID: "p1", Name: "New", Extensions: []string{".n"}},
	})

	b := &FileProfileStore{}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load (reopen): %v", err)
	}
	if b.GetByName("Old") != nil {
		t.Error("Old profile still present after ReplaceAll")
	}
	if got := b.GetByName("New"); got == nil {
		t.Fatal("New profile missing after ReplaceAll")
	}
}

// With no path configured, saveLocked early-returns. ReplaceAll must still
// apply the in-memory swap and must not panic.
func TestFileProfileStore_ReplaceAll_EmptyPathNoOps(t *testing.T) {
	s := &FileProfileStore{}
	s.ReplaceAll([]FileExtProfile{
		{ID: "p1", Name: "InMem", Extensions: []string{".m"}},
	})
	got := s.List()
	if len(got) != 1 || got[0].Name != "InMem" {
		t.Fatalf("List = %+v, want [InMem]", got)
	}
}

// Persistence is best-effort: if saveLocked fails (parent directory
// missing), the in-memory swap still happens and the call must not panic.
func TestFileProfileStore_ReplaceAll_PersistFailureDoesNotPanic(t *testing.T) {
	ensureFileblockTestLogger(t)

	dir := t.TempDir()
	// Path under a directory that doesn't exist — atomicWriteFile fails at
	// os.CreateTemp because the parent dir is missing.
	path := filepath.Join(dir, "missing", "fileprofiles.json")

	s := &FileProfileStore{}
	s.path = path // bypass Load — Load would fail in the same place

	s.ReplaceAll([]FileExtProfile{
		{ID: "p1", Name: "InMem", Extensions: []string{".m"}},
	})

	got := s.List()
	if len(got) != 1 || got[0].Name != "InMem" {
		t.Fatalf("List = %+v, want [InMem]", got)
	}
}
