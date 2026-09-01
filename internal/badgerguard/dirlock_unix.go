//go:build unix

package badgerguard

// dirlock_unix.go — the one primitive the recovery path trusts (CHAOS-50, §19;
// generalised to every Badger store by CHAOS-57, §25).
//
// Two questions have to be answered before a damaged store can be moved aside,
// and both reduce to "is a live process holding this?":
//
//   - is anybody using the store directory right now? Quarantine renames it, and
//     doing that to a directory a live badger owns is destructive.
//   - does an open-attempt marker belong to a process that is still running, or
//     to one that died inside badger.Open?
//
// flock answers both, because the kernel releases it when its owner dies — a
// process SIGKILLed inside Open leaves no lock behind, which is exactly the case
// we want to recover, while a live opener is unmistakably alive. This mirrors
// badger's own mechanism (badger/dir_unix.go acquireDirectoryLock), which flocks
// the DIRECTORY rather than a file inside it.

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// flockFile takes a non-blocking exclusive flock on an already-open file or
// directory. It returns (false, nil) when a live holder has it, and an error
// when the lock state cannot be determined — callers must treat BOTH as
// "not free": the fail-safe default is to leave the disk alone.
func flockFile(f *os.File) (bool, error) {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		// EWOULDBLOCK (== EAGAIN on Linux) means a live holder.
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// unlockFile releases a lock taken by flockFile. Closing the file would also
// release it; this makes the hand-off explicit at the call sites that keep the
// handle open across a rename.
func unlockFile(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
