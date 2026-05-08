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
