package fileutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// Gates for Codex P2 4317365510 on PR #1601: failing to open the parent
// directory for its fsync is not success. The rename has landed, so the
// write is ErrReplacedNotSynced (visible, durability unproven), exactly as a
// failed fsync is.

func injectParentDirOpen(t *testing.T, err error) {
	t.Helper()
	prev := openParentDir
	openParentDir = func(name string) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	t.Cleanup(func() { openParentDir = prev })
}

// TestAtomicWrite_UnopenableParentDirIsNotSynced: an injected EACCES or EPERM
// opening the directory yields ErrReplacedNotSynced, with the new content
// already in place. Treating the open failure as success fails this test.
func TestAtomicWrite_UnopenableParentDirIsNotSynced(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.json")
			injectParentDirOpen(t, errno)
			err := AtomicWrite(path, []byte("new"), 0o600)
			if !errors.Is(err, ErrReplacedNotSynced) || !errors.Is(err, errno) {
				t.Fatalf("err = %v, want ErrReplacedNotSynced wrapping %v", err, errno)
			}
			got, rerr := os.ReadFile(path) // #nosec G304 -- test temp path
			if rerr != nil || !bytes.Equal(got, []byte("new")) {
				t.Errorf("target = %q (err %v), want the new content in place", got, rerr)
			}
		})
	}
}

// TestAtomicWrite_RealUnreadableParentDirIsNotSynced: a real 0300 directory
// (write and search, no read) lets the rename land but not the directory
// open. Root bypasses the mode bits, so this skips there and the injected
// test above covers it.
func TestAtomicWrite_RealUnreadableParentDirIsNotSynced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits; TestAtomicWrite_UnopenableParentDirIsNotSynced injects the EACCES")
	}
	dir := filepath.Join(t.TempDir(), "wx")
	if err := os.Mkdir(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore so TempDir cleanup can remove it
	if err := AtomicWrite(filepath.Join(dir, "f.json"), []byte("new"), 0o600); !errors.Is(err, ErrReplacedNotSynced) {
		t.Fatalf("err = %v, want ErrReplacedNotSynced", err)
	}
}
