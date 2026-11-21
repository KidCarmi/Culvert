package fileutil

import (
	"errors"
	"os"
	"syscall"
)

// Directory fsync: the one owner of the rule every durable-write path in this
// repository applies after it creates, renames or removes a directory entry.
//
// The rule has two parts that used to be copied per caller:
//
//   - which fsync errors mean "this filesystem cannot fsync a directory at
//     all" (DirSyncUnsupported) and are therefore not a durability failure;
//   - how the fsync result and the close result of the directory handle
//     combine (syncAndClose): a real fsync error wins, a close error is
//     reported only when the fsync itself succeeded.
//
// What differs between callers is a decision, not a copy, and it stays with
// each of them: whether a directory that cannot be OPENED is a failure.
// SyncDir returns the open error (the saas-feed generation store and its GC
// treat an unsyncable root as "nothing was committed"). AtomicWrite and
// WriteFileExclusive skip an unopenable parent, because opening a directory
// for sync is not portable and their data has already been renamed into
// place.

// DirSyncUnsupported reports whether err, the result of fsyncing a directory,
// is one of the codes a filesystem returns when it does not support directory
// fsync (EINVAL, ENOTSUP, EOPNOTSUPP). Such a filesystem has already given
// every durability guarantee it has, so callers treat the sync as done.
func DirSyncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP)
}

// SyncDir opens dir and fsyncs it so that entries created, renamed or removed
// inside it are durable. It is the strict form: a directory that cannot be
// opened is an error, returned unwrapped. A filesystem without directory
// fsync support (DirSyncUnsupported) is success. The handle is always closed;
// its close error is returned only when the fsync itself succeeded.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return syncAndClose(d)
}

// dirHandle is the part of *os.File the sync rule uses. It is an interface so
// the rule can be tested against every (sync, close) outcome without a real
// failing filesystem and without a package-level test seam.
type dirHandle interface {
	Sync() error
	Close() error
}

// syncAndClose fsyncs and closes an opened directory and combines the two
// results: an fsync error other than DirSyncUnsupported is returned; a close
// error is returned only when the fsync returned nil; anything else is nil.
func syncAndClose(d dirHandle) error {
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && !DirSyncUnsupported(syncErr) {
		return syncErr
	}
	if syncErr == nil && closeErr != nil {
		return closeErr
	}
	return nil
}

// syncDirTolerant is SyncDir for callers whose data is already in place: an
// open failure is best-effort (same as AtomicWrite) and reported as success.
func syncDirTolerant(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	return syncAndClose(d)
}
