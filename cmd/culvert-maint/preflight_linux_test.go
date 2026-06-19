//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirTraversable(t *testing.T) {
	// A normal temp dir is searchable by its owner.
	dir := t.TempDir()
	if err := dirTraversable(dir); err != nil {
		t.Fatalf("expected %q traversable, got %v", dir, err)
	}

	// A non-existent path is not traversable.
	if err := dirTraversable(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Fatal("expected error for non-existent path")
	}

	// A directory with no execute bit is not traversable into its child.
	// (Skip when running as root, which bypasses permission bits.)
	if os.Geteuid() != 0 {
		noX := filepath.Join(dir, "nox")
		if err := os.Mkdir(noX, 0o600); err != nil { // rw-, no search bit
			t.Fatalf("mkdir: %v", err)
		}
		child := filepath.Join(noX, "child")
		if err := dirTraversable(child); err == nil {
			t.Fatal("expected error traversing through a non-searchable parent")
		}
	}
}
