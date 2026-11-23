//go:build !unix

package journal

import "errors"

// ErrLockHeld means another process holds the reconcile lock.
var ErrLockHeld = errors.New("journal: reconcile lock held by another process")

// ReconcileLock is a held instance lock (never granted on this platform).
type ReconcileLock struct{}

// Release is a no-op.
func (l *ReconcileLock) Release() error { return nil }

// LockReconcile is unsupported here: without an instance lock the startup
// reconcile must not act, so it always fails.
func (j *Journal) LockReconcile() (*ReconcileLock, error) {
	return nil, errors.New("journal: reconcile lock unsupported on this platform")
}
