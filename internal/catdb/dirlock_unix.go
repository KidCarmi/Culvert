//go:build unix

package catdb

// dirlock_unix.go — CHAOS-50: is anybody else using this store right now?
//
// Quarantine renames the store directory. Doing that to a directory another
// process has open is destructive, so every quarantine is gated on this probe.
// It mirrors badger's own mechanism exactly (badger/dir_unix.go
// acquireDirectoryLock): a non-blocking exclusive flock on the DIRECTORY, not
// on a file inside it. Acquiring and immediately releasing it is enough to know
// no live badger holds the store — a flock is released by the kernel when its
// owner dies, so a process that was SIGKILLed inside Open leaves no lock behind,
// which is precisely the case we DO want to recover.

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// dirLockFree reports whether the store directory is currently unlocked.
// An error means "could not determine" and callers must treat that as
// not-free — the fail-safe default is to leave the disk alone.
func dirLockFree(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck // read-only probe handle; close error is not actionable

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// EWOULDBLOCK (== EAGAIN on Linux) means a live holder. Any other errno
		// is an environment we cannot reason about. Both answers are "not free",
		// so neither can authorise a quarantine.
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	// Release immediately: the caller is about to rename this directory, and
	// holding a lock on it while doing so would serve no purpose.
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return true, nil
}
