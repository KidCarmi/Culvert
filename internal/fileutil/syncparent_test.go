package fileutil

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
)

// Gates for Codex P1 4319946917 on PR #1601: AtomicWrite keeps main's
// behaviour when the parent directory cannot be opened for its fsync (nil,
// and a SUCCESS observer notification — its callers roll back on any error,
// and the file did land), while AtomicWriteInfo reports the strict answer in
// WriteResult.DirSynced. A failed fsync is still ErrReplacedNotSynced.

func injectParentDirOpen(t *testing.T, err error) {
	t.Helper()
	prev := openParentDir
	openParentDir = func(name string) (*os.File, error) {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	t.Cleanup(func() { openParentDir = prev })
}

func injectDirSync(t *testing.T, err error) {
	t.Helper()
	prev := syncDir
	syncDir = func(*os.File) error { return err }
	t.Cleanup(func() { syncDir = prev })
}

func countObservers(t *testing.T) (fails, oks *atomic.Int64) {
	t.Helper()
	fails, oks = &atomic.Int64{}, &atomic.Int64{}
	SetWriteFailureObserver(func(string, error) { fails.Add(1) })
	SetWriteSuccessObserver(func(string) { oks.Add(1) })
	t.Cleanup(func() {
		SetWriteFailureObserver(nil)
		SetWriteSuccessObserver(nil)
	})
	return fails, oks
}

// TestAtomicWrite_UnopenableParentDirIsMainCompatible: an injected EACCES or
// EPERM opening the directory leaves AtomicWrite exactly as on main — nil, one
// success notification, no failure notification — with the content in place;
// AtomicWriteInfo reports DirSynced false. Returning the open failure as an
// error (the regression) fails this test.
func TestAtomicWrite_UnopenableParentDirIsMainCompatible(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EACCES, syscall.EPERM} {
		t.Run(errno.Error(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.json")
			injectParentDirOpen(t, errno)
			fails, oks := countObservers(t)
			if err := AtomicWrite(path, []byte("new"), 0o600); err != nil {
				t.Fatalf("AtomicWrite = %v, want nil as on main", err)
			}
			if fails.Load() != 0 || oks.Load() != 1 {
				t.Errorf("observers saw %d failure(s) and %d success(es), want 0 and 1 as on main", fails.Load(), oks.Load())
			}
			got, err := os.ReadFile(path) // #nosec G304 -- test temp path
			if err != nil || !bytes.Equal(got, []byte("new")) {
				t.Errorf("target = %q (err %v), want the new content", got, err)
			}
			res, err := AtomicWriteInfo(path, []byte("newer"), 0o600)
			if err != nil || res.DirSynced || res.Landed == nil {
				t.Errorf("AtomicWriteInfo = (%+v, %v), want landed, DirSynced false, nil error", res, err)
			}
		})
	}
}

// TestAtomicWrite_FailedDirFsyncIsStillNotSynced: a real fsync failure keeps
// main's ErrReplacedNotSynced (and failure notification).
func TestAtomicWrite_FailedDirFsyncIsStillNotSynced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.json")
	injectDirSync(t, syscall.EIO)
	fails, oks := countObservers(t)
	res, err := AtomicWriteInfo(path, []byte("new"), 0o600)
	if !errors.Is(err, ErrReplacedNotSynced) || !errors.Is(err, syscall.EIO) || res.DirSynced || res.Landed == nil {
		t.Fatalf("AtomicWriteInfo = (%+v, %v), want landed, not synced, ErrReplacedNotSynced", res, err)
	}
	if fails.Load() != 1 || oks.Load() != 0 {
		t.Errorf("observers saw %d failure(s) and %d success(es), want 1 and 0", fails.Load(), oks.Load())
	}
}

// TestAtomicWriteInfo_SyncedDirectory: the normal case reports DirSynced.
func TestAtomicWriteInfo_SyncedDirectory(t *testing.T) {
	res, err := AtomicWriteInfo(filepath.Join(t.TempDir(), "f.json"), []byte("x"), 0o600)
	if err != nil || !res.DirSynced || res.Landed == nil {
		t.Fatalf("AtomicWriteInfo = (%+v, %v), want landed and synced", res, err)
	}
}

// TestAtomicWrite_RealUnreadableParentDirIsMainCompatible: a real 0300
// directory (write and search, no read). Root bypasses the mode bits, so this
// skips there and the injected test above covers it.
func TestAtomicWrite_RealUnreadableParentDirIsMainCompatible(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permission bits do not apply on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits; TestAtomicWrite_UnopenableParentDirIsMainCompatible injects the EACCES")
	}
	dir := filepath.Join(t.TempDir(), "wx")
	if err := os.Mkdir(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // #nosec G302 -- restore so TempDir cleanup can remove it
	res, err := AtomicWriteInfo(filepath.Join(dir, "f.json"), []byte("new"), 0o600)
	if err != nil || res.DirSynced {
		t.Fatalf("AtomicWriteInfo = (%+v, %v), want nil error and DirSynced false", res, err)
	}
}
