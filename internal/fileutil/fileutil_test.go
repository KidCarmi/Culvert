package fileutil

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAtomicWrite_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	want := []byte(`{"k":"v"}`)
	if err := AtomicWrite(path, want, 0o600); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestAtomicWrite_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := AtomicWrite(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if string(got) != "second" {
		t.Fatalf("after overwrite = %q, want %q", got, "second")
	}
}

func TestAtomicWrite_BadDirErrors(t *testing.T) {
	// A non-existent parent directory must surface an error (no temp file can be
	// created), never silently succeed.
	if err := AtomicWrite("/nonexistent-dir-xyz/f", []byte("x"), 0o600); err == nil {
		t.Fatal("AtomicWrite into a missing directory must return an error")
	}
}

// TestRewriteInPlace_SameBytesSameModeNewInode pins the boot-rewrite primitive:
// the content and permission bits are unchanged (a non-0600 mode proves the
// mode comes from the original, not AtomicWrite's usual caller default), the
// rename really happened (new inode), and no temp file is left behind.
func TestRewriteInPlace_SameBytesSameModeNewInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")
	want := []byte("[{\"username\":\"a\"}]\n") // a legacy bare-array roster, byte for byte
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- fixture mode under test
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	sumBefore := sha256.Sum256(want)

	if err := RewriteInPlace(path, want, before); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sumBefore {
		t.Errorf("content changed: %q -> %q", want, got)
	}
	if after.Mode() != before.Mode() {
		t.Errorf("mode changed: %v -> %v", before.Mode(), after.Mode())
	}
	if os.SameFile(before, after) {
		t.Error("same inode after RewriteInPlace: the rename over the target did not happen")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("RewriteInPlace left files behind: %q", names)
	}
}

// TestRewriteInPlace_NotifiesNoObserver: a content-preserving rewrite is not a
// store write, so neither outcome reaches the storage-health observers, while
// AtomicWrite (the control) notifies both.
func TestRewriteInPlace_NotifiesNoObserver(t *testing.T) {
	var fails, oks atomic.Int64
	SetWriteFailureObserver(func(string, error) { fails.Add(1) })
	SetWriteSuccessObserver(func(string) { oks.Add(1) })
	t.Cleanup(func() {
		SetWriteFailureObserver(nil)
		SetWriteSuccessObserver(nil)
	})

	path := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteInPlace(path, []byte("x"), fi); err != nil {
		t.Fatalf("RewriteInPlace: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "missing", "f.json")
	if err := RewriteInPlace(missing, []byte("x"), fi); err == nil {
		t.Fatal("RewriteInPlace into a missing directory succeeded")
	}
	if fails.Load() != 0 || oks.Load() != 0 {
		t.Fatalf("RewriteInPlace notified observers: %d failures, %d successes", fails.Load(), oks.Load())
	}

	if err := AtomicWrite(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(missing, []byte("x"), 0o600); err == nil {
		t.Fatal("AtomicWrite into a missing directory succeeded")
	}
	if fails.Load() != 1 || oks.Load() != 1 {
		t.Fatalf("control: AtomicWrite notified %d failures, %d successes; want 1 and 1", fails.Load(), oks.Load())
	}
}

// TestRewriteInPlace_FailsLikeAtomicWrite: the same stage refuses both, with
// the same error shape, and the target is left untouched.
func TestRewriteInPlace_FailsLikeAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Renaming a file over a non-empty directory fails for every uid,
	// including root, at the rename stage — the stage a sticky directory
	// refuses to a non-owner.
	blocker := filepath.Join(dir, "blocker")
	if err := os.MkdirAll(filepath.Join(blocker, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	rwErr := RewriteInPlace(blocker, []byte("y"), fi)
	awErr := AtomicWrite(blocker, []byte("y"), 0o600)
	if rwErr == nil || awErr == nil {
		t.Fatalf("rename over a non-empty directory succeeded: rewrite %v, atomic %v", rwErr, awErr)
	}
	if !strings.Contains(rwErr.Error(), ": rename: ") || !strings.Contains(awErr.Error(), ": rename: ") {
		t.Errorf("errors do not name the rename stage: rewrite %q, atomic %q", rwErr, awErr)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte("x")) { // #nosec G304 -- test temp path
		t.Errorf("unrelated target changed: %q", got)
	}
}
