//go:build unix

package writerlock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// flockExclusiveNonBlocking takes an exclusive, non-blocking advisory lock on an
// already-open file. It reports (false, nil) when a LIVE process holds the lock
// and an error when the lock state cannot be determined, so a filesystem that
// does not implement flock yields Undetermined and not Held.
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
