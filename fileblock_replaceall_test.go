package main

// fileblock_replaceall_test.go — CL-13 regression coverage for
// FileBlocker.ReplaceAll and the applyConfigSnapshot
// FileBlockExtensions branch that uses it.
//
// Background
// ==========
// roadmap/CLUSTER-RUNTIME-DISCOVERY.md §13 CL-13 flagged the
// pre-fix applyConfigSnapshot pattern:
//
//   fileBlocker.ClearAll()
//   for _, ext := range snap.FileBlockExtensions {
//       fileBlocker.Add(ext)
//   }
//
// Each ClearAll/Add call invokes fileBlocker.save() → atomicWriteFile,
// so this loop triggered N+1 fsynced writes per snapshot apply
// (cap 10_000 per maxSnapFileBlockExtensions). Correctness was fine
// (every state was durable), but the I/O was wasteful at steady state
// when the snapshot's extension list was unchanged from the prior
// apply (every cluster heartbeat triggered N+1 redundant writes).
//
// Fix (this PR)
// =============
// fileblock.go gains FileBlocker.ReplaceAll([]string) which:
//   - normalises each extension via fb.norm (same lowercase + trim
//     + leading-dot rule as Add);
//   - skips empty and bare-dot entries (same as Add);
//   - replaces the in-memory map atomically under fb.mu.Lock;
//   - calls fb.save() exactly once via the existing
//     atomicWriteFile path.
//
// controlplane.go now uses ReplaceAll instead of the ClearAll +
// per-Add loop.
//
// Tests in this file verify:
//   1. ReplaceAll's content round-trips through the on-disk file.
//   2. ReplaceAll's per-element semantics exactly match Add
//      (lowercase + trim + leading-dot, skip empty / skip bare dot,
//      duplicates collapsed).
//   3. applyConfigSnapshot's FileBlockExtensions branch persists
//      the snapshot content correctly post-fix.
//
// What this file does NOT assert
// ==============================
// The "only one save call" property is not asserted directly — the
// user brief explicitly allowed skipping it if it required invasive
// refactor (it does: would need a save-counter hook on the type),
// and the property is structurally evident from a 6-line reading of
// the new ReplaceAll body (exactly one fb.save() call after the
// in-place swap). The regression-catch surface is content
// correctness + Add-semantic equivalence, both covered below.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// snapshotFileBlocker captures and restores the package-global
// fileBlocker state for the duration of the test. PR #241 / #245
// whitebox snapshot idiom.
func snapshotFileBlocker(t *testing.T) {
	t.Helper()
	fileBlocker.mu.Lock()
	origPath := fileBlocker.path
	origExts := make(map[string]bool, len(fileBlocker.extensions))
	for k, v := range fileBlocker.extensions {
		origExts[k] = v
	}
	fileBlocker.mu.Unlock()
	t.Cleanup(func() {
		fileBlocker.mu.Lock()
		fileBlocker.path = origPath
		fileBlocker.extensions = origExts
		fileBlocker.mu.Unlock()
	})
}

// ─── Direct ReplaceAll tests ─────────────────────────────────────────

func TestCL13_FileBlocker_ReplaceAll_ContentRoundTrip(t *testing.T) {
	snapshotFileBlocker(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	// SetPath() will try to load the file; we want a clean slate.
	fileBlocker.SetPath(path)
	fileBlocker.mu.Lock()
	fileBlocker.extensions = map[string]bool{}
	fileBlocker.mu.Unlock()

	fileBlocker.ReplaceAll([]string{".exe", ".bat", ".scr"})

	// On disk: the file blocker's save format is a JSON []string
	// (fileblock.go:53–67). Read and verify.
	raw, err := os.ReadFile(path)
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
	gotList := fileBlocker.List()
	sort.Strings(gotList)
	if !reflect.DeepEqual(gotList, want) {
		t.Errorf("List() = %v, want %v", gotList, want)
	}
}

func TestCL13_FileBlocker_ReplaceAll_NormalisationMatchesAdd(t *testing.T) {
	snapshotFileBlocker(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fileBlocker.SetPath(path)
	fileBlocker.mu.Lock()
	fileBlocker.extensions = map[string]bool{}
	fileBlocker.mu.Unlock()

	// Per-element semantics mirror Add (fileblock.go:80–89):
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
	fileBlocker.ReplaceAll(input)

	gotList := fileBlocker.List()
	sort.Strings(gotList)
	want := []string{".bat", ".exe", ".scr"}
	if !reflect.DeepEqual(gotList, want) {
		t.Errorf("List() = %v, want %v", gotList, want)
	}
	if fileBlocker.Count() != len(want) {
		t.Errorf("Count() = %d, want %d", fileBlocker.Count(), len(want))
	}
}

func TestCL13_FileBlocker_ReplaceAll_ReplacesEntireSet(t *testing.T) {
	snapshotFileBlocker(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fileBlocker.SetPath(path)
	fileBlocker.mu.Lock()
	fileBlocker.extensions = map[string]bool{}
	fileBlocker.mu.Unlock()

	// Seed an initial set via Add.
	fileBlocker.Add(".old1")
	fileBlocker.Add(".old2")
	if fileBlocker.Count() != 2 {
		t.Fatalf("seed Count() = %d, want 2", fileBlocker.Count())
	}

	// ReplaceAll with a disjoint set; the old entries must be GONE.
	fileBlocker.ReplaceAll([]string{".new1", ".new2", ".new3"})

	gotList := fileBlocker.List()
	sort.Strings(gotList)
	want := []string{".new1", ".new2", ".new3"}
	if !reflect.DeepEqual(gotList, want) {
		t.Errorf("List() = %v, want %v (old entries should have been removed)", gotList, want)
	}

	// And the disk file must reflect only the new set.
	raw, err := os.ReadFile(path)
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
	snapshotFileBlocker(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fileBlocker.SetPath(path)
	fileBlocker.mu.Lock()
	fileBlocker.extensions = map[string]bool{}
	fileBlocker.mu.Unlock()

	fileBlocker.Add(".gone")
	if fileBlocker.Count() != 1 {
		t.Fatalf("seed Count() = %d, want 1", fileBlocker.Count())
	}

	fileBlocker.ReplaceAll(nil)
	if fileBlocker.Count() != 0 {
		t.Errorf("after ReplaceAll(nil): Count() = %d, want 0", fileBlocker.Count())
	}

	fileBlocker.Add(".back")
	fileBlocker.ReplaceAll([]string{})
	if fileBlocker.Count() != 0 {
		t.Errorf("after ReplaceAll([]string{}): Count() = %d, want 0", fileBlocker.Count())
	}
}

// ─── applyConfigSnapshot integration test ───────────────────────────

func TestCL13_ApplyConfigSnapshot_FileBlockExtensions_UsesReplaceAll(t *testing.T) {
	snapshotFileBlocker(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fileBlocker.SetPath(path)
	fileBlocker.mu.Lock()
	fileBlocker.extensions = map[string]bool{".pre-existing": true}
	fileBlocker.mu.Unlock()

	snap := ConfigSnapshot{
		Version:             1,
		FileBlockExtensions: []string{".exe", ".bat", ".scr"},
	}
	applyConfigSnapshot(snap)

	// Disk content should now exactly match the snapshot; the
	// pre-existing entry must be gone.
	raw, err := os.ReadFile(path)
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
		t.Errorf("on-disk extensions = %v, want %v (pre-existing entry should have been replaced)", diskExts, want)
	}
}
