package main

// CL-13 integration coverage: applyConfigSnapshot's FileBlockExtensions branch
// must persist the snapshot content via FileBlocker.ReplaceAll.
//
// The engine-level ReplaceAll unit tests moved to internal/fileblock with the
// FileBlocker type (ADR-0002); this file keeps only the applyConfigSnapshot
// integration test (controlplane wiring), which must run in package main.
//
// Isolation: the engine type now lives in internal/fileblock, so the global
// fileBlocker's internals are no longer reachable here. snapshotFileBlocker
// therefore snapshots/restores via the exported API (List / SetPath / ReplaceAll)
// instead of the prior whitebox field copy.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// snapshotFileBlocker preserves the package-global fileBlocker across the test
// using only the exported engine API, restoring its extension set and disabling
// the test's persistence path on cleanup.
func snapshotFileBlocker(t *testing.T) {
	t.Helper()
	orig := fileBlocker.List()
	t.Cleanup(func() {
		fileBlocker.SetPath("") // drop the test's temp persistence path
		fileBlocker.ReplaceAll(orig)
	})
}

func TestCL13_ApplyConfigSnapshot_FileBlockExtensions_UsesReplaceAll(t *testing.T) {
	snapshotFileBlocker(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "fileblock.json")
	fileBlocker.SetPath(path)
	// Seed a pre-existing entry via the exported API (whitebox field access is
	// no longer available now that FileBlocker lives in internal/fileblock).
	fileBlocker.ReplaceAll([]string{".pre-existing"})

	snap := ConfigSnapshot{
		Version:             1,
		FileBlockExtensions: []string{".exe", ".bat", ".scr"},
	}
	applyConfigSnapshot(snap)

	// Disk content should now exactly match the snapshot; the
	// pre-existing entry must be gone.
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
		t.Errorf("on-disk extensions = %v, want %v (pre-existing entry should have been replaced)", diskExts, want)
	}
}
