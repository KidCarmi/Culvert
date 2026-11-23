//go:build unix

package journal

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockFileName is the startup-reconcile instance lock inside the reconcile
// directory. It does not end in .json, so List never reads it as a record.
const lockFileName = ".lock"

// ErrLockHeld means another process holds the reconcile lock.
var ErrLockHeld = errors.New("journal: reconcile lock held by another process")

// ReconcileLock is a held instance lock. Release drops it; closing the
// process drops it too, so a crashed holder never strands it.
type ReconcileLock struct{ f *os.File }

// Release drops the lock. Safe on a nil lock and idempotent.
func (l *ReconcileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close() // closing the descriptor releases the flock
	l.f = nil
	return err
}

// LockReconcile takes an exclusive, non-blocking flock on
// <stateDir>/reconcile/.lock. The file is opened O_NOFOLLOW, so a symlink
// planted at that path is refused rather than followed. ErrLockHeld means a
// live process holds it; any other error means the lock could not be taken
// and the caller must not act.
func (j *Journal) LockReconcile() (*ReconcileLock, error) {
	path := filepath.Join(j.dir, lockFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, fileMode) // #nosec G304 -- fixed name under the agent-owned reconcile dir
	if err != nil {
		return nil, fmt.Errorf("journal: open reconcile lock: %w", err)
	}
	if ferr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); ferr != nil { // #nosec G115 -- a file descriptor fits in int
		_ = f.Close()
		if errors.Is(ferr, syscall.EWOULDBLOCK) {
			return nil, ErrLockHeld
		}
		return nil, fmt.Errorf("journal: flock reconcile lock: %w", ferr)
	}
	return &ReconcileLock{f: f}, nil
}
