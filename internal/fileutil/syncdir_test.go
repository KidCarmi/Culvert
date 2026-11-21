package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// frozenFsyncDirResult is a frozen copy of the decision the saas-feed
// generation store's fsyncDir made in package main before SyncDir replaced it
// (saas_feed_genstore.go at main c5674f2). It is the differential oracle: do
// not "simplify" it to call dirSyncResult.
func frozenFsyncDirResult(syncErr, closeErr error) error {
	benign := errors.Is(syncErr, syscall.EINVAL) ||
		errors.Is(syncErr, syscall.ENOTSUP) ||
		errors.Is(syncErr, syscall.EOPNOTSUPP)
	if syncErr != nil && !benign {
		return syncErr
	}
	if closeErr != nil && syncErr == nil {
		return closeErr
	}
	return nil
}

// frozenSyncDirTolerantResult is the same for this package's own
// syncDirTolerant, whose tail now delegates to dirSyncResult.
func frozenSyncDirTolerantResult(syncErr, closeErr error) error {
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

func TestDirSyncResult_MatchesBothFrozenOriginals(t *testing.T) {
	pathErr := func(op string, errno syscall.Errno) error {
		return &os.PathError{Op: op, Path: "/d", Err: errno}
	}
	syncErrs := []error{
		nil,
		syscall.EINVAL, syscall.ENOTSUP, syscall.EOPNOTSUPP,
		syscall.EIO, syscall.ENOSPC, syscall.EROFS, syscall.EBADF,
		pathErr("sync", syscall.EINVAL), pathErr("sync", syscall.ENOTSUP),
		pathErr("sync", syscall.EOPNOTSUPP), pathErr("sync", syscall.EIO),
		fmt.Errorf("wrapped: %w", syscall.EINVAL),
		fmt.Errorf("wrapped: %w", syscall.EIO),
		errors.New("opaque"),
		os.ErrClosed,
	}
	closeErrs := []error{nil, syscall.EIO, pathErr("close", syscall.EBADF), os.ErrClosed}
	for _, se := range syncErrs {
		for _, ce := range closeErrs {
			got := dirSyncResult(se, ce)
			if want := frozenFsyncDirResult(se, ce); got != want {
				t.Errorf("sync=%v close=%v: got %v, generation-store original returned %v", se, ce, got, want)
			}
			if want := frozenSyncDirTolerantResult(se, ce); got != want {
				t.Errorf("sync=%v close=%v: got %v, syncDirTolerant original returned %v", se, ce, got, want)
			}
		}
	}
}

// The one real difference between the two originals, and the reason the
// generation store did not use this package's tolerant form: a directory that
// cannot be opened is an ERROR for SyncDir and success for syncDirTolerant.
func TestSyncDir_UnopenableDirectoryIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	err := SyncDir(missing)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SyncDir(missing) = %v, want the open error (ErrNotExist)", err)
	}
	var pe *os.PathError
	if !errors.As(err, &pe) || pe.Op != "open" || pe.Path != missing {
		t.Fatalf("SyncDir(missing) = %#v, want the unwrapped *os.PathError from os.Open", err)
	}
	if err := syncDirTolerant(missing); err != nil {
		t.Fatalf("syncDirTolerant(missing) = %v, want nil (best-effort open is unchanged)", err)
	}
}

func TestSyncDir_ExistingDirectorySucceeds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir(existing dir) = %v, want nil", err)
	}
	if err := syncDirTolerant(dir); err != nil {
		t.Fatalf("syncDirTolerant(existing dir) = %v, want nil", err)
	}
}
