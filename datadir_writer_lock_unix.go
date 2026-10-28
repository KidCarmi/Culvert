//go:build unix

package main

// datadir_writer_lock_unix.go — the one syscall the single-writer guard needs.
//
// Deliberately NOT reused from internal/storeguard, whose flockFile is the same
// three lines: that package's locks are PER-ATTEMPT markers armed and released
// around a single badger.Open, and its doc comment explains at length why the
// marker must not be shared. A process-lifetime lock on the volume has the
// opposite lifetime, so it owns its own handle rather than borrowing machinery
// whose contract says the opposite. What must never be duplicated there is the
// empirically-derived badger message table, and none of that is copied here.

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// flockExclusiveNonBlocking takes an exclusive, non-blocking advisory lock on an
// already-open file. It reports (false, nil) when a LIVE process holds the lock
// and an error when the lock state cannot be determined — the caller refuses the
// boot only on the former, so a filesystem that does not implement flock
// degrades instead of becoming unbootable.
func flockExclusiveNonBlocking(f *os.File) (bool, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// EWOULDBLOCK (== EAGAIN on Linux) is the only "somebody else has it"
		// answer flock gives. Everything else is an inability to answer.
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
