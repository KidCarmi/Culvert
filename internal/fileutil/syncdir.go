package fileutil

import (
	"errors"
	"os"
	"syscall"
)

// SyncDir fsyncs dir so a create, rename or unlink inside it is durable.
//
// It is the STRICT directory sync: a directory that cannot be opened is an
// error, because the caller asked for durability and did not get it. The
// saas-feed generation store and its collector use it for exactly that reason;
// AtomicWrite and WriteFileExclusive deliberately do not (they treat an
// unopenable parent as best-effort, see syncDirTolerant).
//
// A filesystem that does not support directory fsync (EINVAL, ENOTSUP,
// EOPNOTSUPP) is treated as success, as everywhere else in this package.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	return dirSyncResult(syncErr, closeErr)
}

// dirSyncResult is the one rule for what a directory fsync and the close that
// follows it report: a real sync failure wins, an unsupported sync is success,
// and a close failure is reported only after a sync that succeeded.
func dirSyncResult(syncErr, closeErr error) error {
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
