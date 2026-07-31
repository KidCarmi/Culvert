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
//   - never called on success: the success path performs no atomic load.
var writeFailObserver atomic.Pointer[func(path string, err error)]

// SetWriteFailureObserver publishes the durable-write failure observer.
// Published once at startup by package main (init order is irrelevant — the
// success path never reads it). A nil fn clears the observer, which is what
// tests use to restore the default no-op state.
func SetWriteFailureObserver(fn func(path string, err error)) {
	if fn == nil {
		writeFailObserver.Store(nil)
		return
	}
	writeFailObserver.Store(&fn)
}

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
		// Best-effort: opening a directory for sync is not portable.
		return nil
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: parent dir fsync: %w", path, syncErr))
	}
	if closeErr != nil && syncErr == nil {
		return noteWriteFailure(path, fmt.Errorf("atomic write %s: parent dir close: %w", path, closeErr))
	}
	return nil
}
