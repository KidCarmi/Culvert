package fileblock

// CL-13 engine regression coverage for FileBlocker.ReplaceAll. Moved from
// package main during the internal/fileblock extraction (ADR-0002). The
// applyConfigSnapshot integration test stays in package main (it exercises
// controlplane wiring, not the engine). These use a fresh FileBlocker instance
// per test for isolation (the prior global-snapshot idiom is unnecessary here).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestCL13_FileBlocker_ReplaceAll_ContentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fb := &FileBlocker{extensions: map[string]bool{}}
	fb.SetPath(path)

	fb.ReplaceAll([]string{".exe", ".bat", ".scr"})

	// On disk: the file blocker's save format is a JSON []string. Read and verify.
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var diskExts []string
	if err := json.Unmarshal(raw, &diskExts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sort.Strings(diskExts)
	want := []string{".bat", ".exe", ".scr"}
	if !reflect.DeepEqual(diskExts, want) {
		t.Errorf("on-disk extensions = %v, want %v", diskExts, want)
	}

	// In-memory: List() should round-trip the same set.
	gotList := fb.List()
	sort.Strings(gotList)
	if !reflect.DeepEqual(gotList, want) {
		t.Errorf("List() = %v, want %v", gotList, want)
	}
}

func TestCL13_FileBlocker_ReplaceAll_NormalisationMatchesAdd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fb := &FileBlocker{extensions: map[string]bool{}}
	fb.SetPath(path)

	// Per-element semantics mirror Add:
	//   - lowercase + TrimSpace
	//   - leading-dot inserted if missing
	//   - empty after normalisation → skipped
	//   - bare "." after normalisation → skipped
	//   - duplicates collapsed by the set semantics
	input := []string{
		"EXE",      // → ".exe" (lowercase, leading dot inserted)
		".EXE",     // → ".exe" (lowercase, dup of above)
		"  .bat  ", // → ".bat" (trim)
		"",         // → skipped
		".",        // → skipped
		"scr",      // → ".scr" (leading dot)
		".SCR",     // → ".scr" (dup)
	}
	fb.ReplaceAll(input)

	gotList := fb.List()
	sort.Strings(gotList)
	want := []string{".bat", ".exe", ".scr"}
	if !reflect.DeepEqual(gotList, want) {
		t.Errorf("List() = %v, want %v", gotList, want)
	}
	if fb.Count() != len(want) {
		t.Errorf("Count() = %d, want %d", fb.Count(), len(want))
	}
}

func TestCL13_FileBlocker_ReplaceAll_ReplacesEntireSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fb := &FileBlocker{extensions: map[string]bool{}}
	fb.SetPath(path)

	// Seed an initial set via Add.
	fb.Add(".old1")
	fb.Add(".old2")
	if fb.Count() != 2 {
		t.Fatalf("seed Count() = %d, want 2", fb.Count())
	}

	// ReplaceAll with a disjoint set; the old entries must be GONE.
	fb.ReplaceAll([]string{".new1", ".new2", ".new3"})

	gotList := fb.List()
	sort.Strings(gotList)
	want := []string{".new1", ".new2", ".new3"}
	if !reflect.DeepEqual(gotList, want) {
		t.Errorf("List() = %v, want %v (old entries should have been removed)", gotList, want)
	}

	// And the disk file must reflect only the new set.
	raw, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var diskExts []string
	if err := json.Unmarshal(raw, &diskExts); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sort.Strings(diskExts)
	if !reflect.DeepEqual(diskExts, want) {
		t.Errorf("on-disk extensions = %v, want %v", diskExts, want)
	}
}

func TestCL13_FileBlocker_ReplaceAll_EmptyClearsSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fb := &FileBlocker{extensions: map[string]bool{}}
	fb.SetPath(path)

	fb.Add(".gone")
	if fb.Count() != 1 {
		t.Fatalf("seed Count() = %d, want 1", fb.Count())
	}

	fb.ReplaceAll(nil)
	if fb.Count() != 0 {
		t.Errorf("after ReplaceAll(nil): Count() = %d, want 0", fb.Count())
	}

	fb.Add(".back")
	fb.ReplaceAll([]string{})
	if fb.Count() != 0 {
		t.Errorf("after ReplaceAll([]string{}): Count() = %d, want 0", fb.Count())
	}
}
