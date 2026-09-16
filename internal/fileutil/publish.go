package fileutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
)

// PublishExclusive durably creates path with data EXACTLY ONCE across
// concurrent and crashing writers (FE-6A.2 round 3, Blocker 2 — the
// node-local candidate-commitment key):
//
//  1. the content is written to a unique temp file in the same directory
//     (perm applied), a SHORT write is an error, and the file is fsynced;
//  2. the temp file is published with link(2), which FAILS with EEXIST when
//     another writer already published — so exactly one generation wins and
//     every loser reads the winner's bytes (created == false, err == nil);
//  3. the directory is fsynced so the name survives a crash.
//
// A failure at any step leaves NO partial target: the target only ever
// appears complete, or not at all; the temp file is removed on every
// path. A directory-fsync failure AFTER the link is still reported as an
// error (the name's durability is unknown), with the complete file left in
// place for a later boot to find. Every synchronisation runs through the
// package's test hooks (SetSyncHookForTest / SetSyncObserverForTest), and
// the write/link steps through SetPublishIOHookForTest, so a caller's
// fail-closed reaction to each fault is provable.
func PublishExclusive(path string, data []byte, perm os.FileMode) (created bool, err error) {
	tmp, err := writeTempSynced(path, data, perm)
	if err != nil {
		return false, err
	}
	cleanup := func() { _ = os.Remove(tmp) } // #nosec G104 -- best-effort cleanup
	if err := publishHookStep("link"); err != nil {
		cleanup()
		return false, fmt.Errorf("publish %s: link: %w", path, err)
	}
	if err := os.Link(tmp, path); err != nil {
		cleanup()
		if errors.Is(err, fs.ErrExist) {
			return false, nil // another writer published first; read theirs
		}
		return false, fmt.Errorf("publish %s: link: %w", path, err)
	}
	cleanup() // the content now lives under its published name only
	if err := syncParentDir(path); err != nil {
		return true, err
	}
	return true, nil
}

// writeTempSynced writes data to a unique temp file beside path (perm
// applied), refuses a short write, fsyncs and closes it. On any failure
// the temp file is removed and the error returned.
func writeTempSynced(path string, data []byte, perm os.FileMode) (tmp string, err error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	f, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return "", fmt.Errorf("publish %s: create temp: %w", path, err)
	}
	tmp = f.Name()
	fail := func(step string, e error) (string, error) {
		_ = f.Close()
		_ = os.Remove(tmp) // #nosec G104 -- best-effort cleanup
		return "", fmt.Errorf("publish %s: %s: %w", path, step, e)
	}
	if err := f.Chmod(perm); err != nil {
		return fail("chmod", err)
	}
	if err := publishHookStep("write"); err != nil {
		return fail("write", err)
	}
	toWrite := data
	if publishHookStep("short_write") != nil {
		toWrite = data[:len(data)/2] // injected: the kernel accepted fewer bytes
	}
	n, werr := f.Write(toWrite)
	if werr == nil && n != len(data) {
		werr = fmt.Errorf("%w: %d of %d bytes", errShortPublishWrite, n, len(data))
	}
	if werr != nil {
		return fail("write", werr)
	}
	if err := beforeSync("file", tmp); err != nil {
		return fail("fsync", err)
	}
	if err := f.Sync(); err != nil {
		return fail("fsync", err)
	}
	noteSync("file", tmp)
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp) // #nosec G104 -- best-effort cleanup
		return "", fmt.Errorf("publish %s: close: %w", path, err)
	}
	return tmp, nil
}

// syncParentDir fsyncs path's directory so a freshly linked name survives a
// crash; filesystems that cannot sync a directory are tolerated.
func syncParentDir(path string) error {
	dir := filepath.Dir(path)
	if err := beforeSync("dir", dir); err != nil {
		return fmt.Errorf("publish %s: parent dir fsync: %w", path, err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("publish %s: open parent dir: %w", path, err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		return fmt.Errorf("publish %s: parent dir fsync: %w", path, syncErr)
	}
	if closeErr != nil && syncErr == nil {
		return fmt.Errorf("publish %s: parent dir close: %w", path, closeErr)
	}
	noteSync("dir", dir)
	return nil
}

// errShortPublishWrite: the kernel accepted fewer bytes than offered.
var errShortPublishWrite = errors.New("short write")

// publishIOHook is a TEST-ONLY fault seam for the non-sync steps of
// PublishExclusive: "write" (the write call fails), "short_write" (the
// write returns fewer bytes), "link" (the exclusive publication fails).
// Behaviour-neutral when unset.
var publishIOHook atomic.Pointer[func(step string) error]

// SetPublishIOHookForTest installs fn and returns a restore func.
func SetPublishIOHookForTest(fn func(step string) error) (restore func()) {
	var old *func(step string) error
	if fn == nil {
		old = publishIOHook.Swap(nil)
	} else {
		old = publishIOHook.Swap(&fn)
	}
	return func() { publishIOHook.Store(old) }
}

func publishHookStep(step string) error {
	if p := publishIOHook.Load(); p != nil {
		return (*p)(step)
	}
	return nil
}
