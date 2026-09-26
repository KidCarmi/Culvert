// Package fileutil provides durable filesystem helpers shared by package main
// and internal/* packages (ADR-0003). It has no dependency on the rest of
// Culvert (stdlib only).
package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
)

// ── Durable-write failure observability (CHAOS-45) ───────────────────────────
//
// AtomicWrite is the single durable-write chokepoint for every persisted store
// in the product (~50 call sites across 35 files). A dozen of those call sites
// discard the returned error entirely (`_ = fileutil.AtomicWrite(...)`) because
// the store's Save() signature returns nothing — so a data directory that goes
// read-only or full AFTER boot loses every subsequent config mutation with no
// log line, no metric, and no alert. The admin API answers 200, the UI shows
// the new state from memory, and the change evaporates on restart.
//
// Rather than churn eight Save() signatures (and every one of their call
// sites), this seam reports the failure from the chokepoint itself: package
// main publishes an observer at init, counts the failures, degrades the
// storage row of the operator contract, exports a metric, and fires a
// rate-limited alert. Callers that DO check the error are unaffected — the
// observer is notified in addition to, never instead of, the returned error.
//
// Contract for observers:
//   - called synchronously on the failing goroutine, possibly while the caller
//     holds a store lock — it MUST NOT block and MUST NOT re-enter AtomicWrite
//     (see storage_health.go's alert-path recursion guard in package main).
//   - never called on success; the SUCCESS observer below is the separate seam
//     for that, so a consumer can tell "no failures" from "no writes at all".
var writeFailObserver atomic.Pointer[func(path string, err error)]

// writeOKObserver is notified after a fully successful AtomicWrite. It exists
// so a consumer can establish RECOVERY BY EVIDENCE rather than by elapsed time:
// silence is not proof that a read-only or full filesystem healed, it is only
// proof that nothing tried to write. Durable writes are admin-action-rate (the
// fsync alone dominates), so the extra atomic load on the success path is not
// a hot-path cost.
var writeOKObserver atomic.Pointer[func(path string)]

// SetWriteFailureObserver publishes the durable-write failure observer.
// Published once at startup by package main. A nil fn clears the observer,
// which is what tests use to restore the default no-op state.
func SetWriteFailureObserver(fn func(path string, err error)) {
	if fn == nil {
		writeFailObserver.Store(nil)
		return
	}
	writeFailObserver.Store(&fn)
}

// SetWriteSuccessObserver publishes the durable-write success observer. Nil
// clears it. See writeOKObserver for why successes are observed at all.
func SetWriteSuccessObserver(fn func(path string)) {
	if fn == nil {
		writeOKObserver.Store(nil)
		return
	}
	writeOKObserver.Store(&fn)
}

// noteWriteSuccess notifies the success observer (if any).
func noteWriteSuccess(path string) {
	if p := writeOKObserver.Load(); p != nil {
		(*p)(path)
	}
}

// ErrReplacedNotSynced marks an AtomicWrite failure that occurred AFTER the
// rename: the target file already carries the new content (visible to every
// reader, and on the overwhelming majority of filesystems durable), but the
// parent-directory sync failed, so the rename's durability across an
// immediate crash is not guaranteed. Callers running compensating rollbacks
// must NOT restore prior in-memory state on this error — memory would then
// contradict the visible file, and a restart would load the "rolled back"
// content anyway. Test with errors.Is.
var ErrReplacedNotSynced = errors.New("atomic write: target replaced but parent directory not synced")

// noteWriteFailure notifies the observer (if any) and returns err unchanged so
// every failure branch of AtomicWrite can stay a one-line `return`.
func noteWriteFailure(path string, err error) error {
	if p := writeFailObserver.Load(); p != nil {
		(*p)(path, err)
	}
	return err
}

// AtomicWrite writes data to path atomically: it writes to a unique temp file in
// the same directory, chmods, fsyncs the file, renames over the target, and
// best-effort fsyncs the parent directory. A crash mid-write never leaves a
// partial or corrupt target file. Moved verbatim from package main's
// atomicWriteFile (ADR-0003); behaviour is unchanged.
//
// Every failure branch additionally notifies the write-failure observer
// (CHAOS-45) so error-discarding callers cannot fail silently.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	f, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: create temp: %w", path, err))
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) } // #nosec G104 -- best-effort cleanup

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: write: %w", path, err))
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		cleanup()
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: chmod: %w", path, err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: fsync: %w", path, err))
	}
	if err := f.Close(); err != nil {
		cleanup()
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: close: %w", path, err))
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: rename: %w", path, err))
	}

	d, err := os.Open(dir)
	if err != nil {
		// Best-effort: opening a directory for sync is not portable. The data
		// is already renamed into place, so this is a successful durable write.
		noteWriteSuccess(path)
		return nil
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		// Post-rename failure: the target already carries the new content —
		// mark it so compensating-rollback callers can tell (see
		// ErrReplacedNotSynced).
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: parent dir fsync: %w: %w", path, syncErr, ErrReplacedNotSynced))
	}
	if closeErr != nil && syncErr == nil {
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: parent dir close: %w: %w", path, closeErr, ErrReplacedNotSynced))
	}
	noteWriteSuccess(path)
	return nil
}

// ── Predictable-path secret writes (SEC-SECRETWRITE-1) ───────────────────────

// WriteFileExclusive is the safe counterpart to AtomicWrite for the few
// callers that CANNOT use a random temp name because the path itself is a
// rendezvous another code path looks for by name (the CDR renewal's
// "<bundle>.tmp" files, which reconcileCredentialLineage finds at the next
// boot to finish an interrupted swap).
//
// It exists because os.WriteFile is unsafe for secret material on a
// predictable path, in two ways that are easy to miss and were each
// reproduced against this tree:
//
//   - IT FOLLOWS SYMLINKS. O_CREATE without O_EXCL opens the link's TARGET,
//     so an entry planted at the path before the first write sends the bytes
//     somewhere the writer never chose — outside the data directory
//     entirely. For a key file the read side makes this worse rather than
//     better: os.ReadFile on a DANGLING link reports fs.ErrNotExist, which is
//     exactly the condition every mint path treats as "no key yet, create
//     one".
//   - ITS perm ARGUMENT APPLIES ONLY ON CREATION. Writing over a file that
//     already exists keeps that file's mode, so a 0666 file planted at the
//     path receives the secret and stays world-readable however carefully
//     0600 was passed.
//
// WriteFileExclusive removes any pre-existing entry — link or file, which is
// what makes the create exclusive rather than merely racy — then creates the
// path with O_EXCL at perm, writes, fsyncs and closes. Removing first keeps
// the drop-in semantics of os.WriteFile (a stale rendezvous file from an
// interrupted predecessor is superseded, exactly as a truncating write
// superseded it before); O_EXCL then guarantees the descriptor refers to a
// file THIS call created, at THIS mode, at THIS path.
//
// Anything the remove cannot clear — a non-empty directory, a parent that
// denies unlink — fails the call CLOSED, with nothing written and the
// existing entry untouched. An EMPTY directory is cleared like a stale file;
// that is a deliberate widening over os.WriteFile's EISDIR, since nothing
// security-relevant distinguishes an empty directory at a rendezvous path
// from no entry at all.
//
// Callers that do NOT need a predictable path must use AtomicWrite instead:
// it is the durable-write chokepoint, it is atomic against readers, and its
// rename-over-the-target replaces a planted symlink rather than writing
// through it.
//
// Deliberately NOT wired to the AtomicWrite observers (CHAOS-45): this is not
// that chokepoint, and every call site checks the returned error itself.
// Notifying only the failure seam would degrade the storage row with no
// success seam able to clear it by evidence.
func WriteFileExclusive(path string, data []byte, perm os.FileMode) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("exclusive write %s: clear existing: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return fmt.Errorf("exclusive write %s: create: %w", path, err)
	}
	// perm is filtered through the process umask at creation, so a umask
	// that masks owner bits would leave the rendezvous unreadable after a
	// restart. Apply the requested mode explicitly, as AtomicWrite does.
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return exclusiveFail(path, "chmod", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return exclusiveFail(path, "write", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return exclusiveFail(path, "fsync", err)
	}
	if err := f.Close(); err != nil {
		return exclusiveFail(path, "close", err)
	}
	// The file's fsync makes its CONTENT durable, not its directory entry:
	// after a power loss the freshly created name can vanish, and a
	// rendezvous that vanished is exactly what the next boot's recovery
	// cannot finish. So the parent directory is synced too, with the same
	// unsupported-filesystem tolerance AtomicWrite applies.
	if err := exclusiveSyncDir(filepath.Dir(path)); err != nil {
		return exclusiveFail(path, "parent dir fsync", err)
	}
	return nil
}

// exclusiveFail undoes a WriteFileExclusive that failed after creating the
// file, and makes the undo DURABLE: the unlink is verified and the parent
// directory synced again, so "failed closed" means the path is empty after a
// crash too. A cleanup that could not be verified or synced is joined into
// the returned error, so the caller is never told the path is clear when it
// may still hold (or, after a crash, regain) the partially written file.
func exclusiveFail(path, stage string, cause error) error {
	err := fmt.Errorf("exclusive write %s: %s: %w", path, stage, cause)
	if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		return errors.Join(err, fmt.Errorf("exclusive write %s: cleanup: remove: %w", path, rerr))
	}
	if serr := exclusiveSyncDir(filepath.Dir(path)); serr != nil {
		return errors.Join(err, fmt.Errorf("exclusive write %s: cleanup: parent dir fsync: %w", path, serr))
	}
	return err
}

// exclusiveSyncDir is the parent-directory fsync WriteFileExclusive runs
// before reporting success. A package var so a test can observe that it
// runs and that its failure fails the write closed.
var exclusiveSyncDir = syncDirTolerant

// syncDirTolerant fsyncs dir. Opening a directory for sync is not portable,
// so an open failure is best-effort (same as AtomicWrite), and a filesystem
// that does not support directory fsync (EINVAL/ENOTSUP/EOPNOTSUPP) is
// treated as success.
func syncDirTolerant(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		return syncErr
	}
	if syncErr == nil && closeErr != nil {
		return closeErr
	}
	return nil
}
