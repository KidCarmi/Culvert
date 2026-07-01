// Package fileutil provides durable filesystem helpers shared by package main
// and internal/* packages (ADR-0003). It has no dependency on the rest of
// Culvert (stdlib only).
package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// AtomicWrite writes data to path atomically: it writes to a unique temp file in
// the same directory, chmods, fsyncs the file, renames over the target, and
// best-effort fsyncs the parent directory. A crash mid-write never leaves a
// partial or corrupt target file. Moved verbatim from package main's
// atomicWriteFile (ADR-0003); behaviour is unchanged.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	f, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return fmt.Errorf("atomic write %s: create temp: %w", path, err)
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) } // #nosec G104 -- best-effort cleanup

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("atomic write %s: write: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("atomic write %s: chmod: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("atomic write %s: fsync: %w", path, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("atomic write %s: close: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return fmt.Errorf("atomic write %s: rename: %w", path, err)
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
		return fmt.Errorf("atomic write %s: parent dir fsync: %w", path, syncErr)
	}
	if closeErr != nil && syncErr == nil {
		return fmt.Errorf("atomic write %s: parent dir close: %w", path, closeErr)
	}
	return nil
}
