package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two synchronisation seams of AtomicWrite (FE-6B.0 round 3): a
// pre-rename fault leaves the target untouched and is an ordinary error; a
// post-rename fault leaves the REPLACEMENT in place and is
// ErrReplacedNotSynced, which SyncParentDir then resolves.

func TestAtomicWrite_PreRenameSyncFaultLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "obj")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	var seen string
	restore := SetSyncHookForTest(func(kind, path string) error {
		if kind == "atomic-file" && strings.HasPrefix(filepath.Base(path), "obj.tmp.") {
			seen = path
			return errors.New("injected file fsync fault")
		}
		return nil
	})
	defer restore()
	err := AtomicWrite(target, []byte("new"), 0o600)
	if err == nil || errors.Is(err, ErrReplacedNotSynced) {
		t.Fatalf("pre-rename fault must be an ordinary failure, got %v", err)
	}
	if seen == "" {
		t.Fatal("the atomic-file seam was not consulted")
	}
	if got, _ := os.ReadFile(target); string(got) != "old" {
		t.Fatalf("target changed on a pre-rename fault: %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temp file leaked: %d entries", len(entries))
	}
}

func TestAtomicWrite_PostRenameSyncFaultIsReplacedNotSynced(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "obj")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	faults := 0
	restore := SetSyncHookForTest(func(kind, path string) error {
		if kind == "atomic-dir" && path == target {
			faults++
			return errors.New("injected dir fsync fault")
		}
		return nil
	})
	defer restore()
	err := AtomicWrite(target, []byte("new"), 0o600)
	if !errors.Is(err, ErrReplacedNotSynced) {
		t.Fatalf("post-rename fault must be ErrReplacedNotSynced, got %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "new" {
		t.Fatalf("the replacement must be visible after a post-rename fault: %q", got)
	}
	if faults != 1 {
		t.Fatalf("seam consulted %d times", faults)
	}
	// The doubt is resolved by a later directory sync of the same parent.
	if err := SyncParentDir(target); err != nil {
		t.Fatalf("SyncParentDir: %v", err)
	}
}

func TestSyncParentDir_ReportsAFaultThroughTheDirSeam(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "obj")
	restore := SetSyncHookForTest(func(kind, path string) error {
		if kind == "dir" && path == dir {
			return errors.New("injected dir fsync fault")
		}
		return nil
	})
	defer restore()
	if err := SyncParentDir(target); err == nil {
		t.Fatal("a directory sync fault must be reported")
	}
	restore()
	if err := SyncParentDir(target); err != nil {
		t.Fatalf("clean sync: %v", err)
	}
}
