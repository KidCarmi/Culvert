//go:build unix

package fileutil

import (
	"os"
	"syscall"
)

// holdInode returns a duplicate descriptor of f's inode, or nil if one could
// not be made. AtomicWriteInfo fstats it after the rename.
//
// syscall.ForkLock is held for reading across the dup AND the FD_CLOEXEC that
// follows it, which is what the syscall package documents for any code that
// creates a descriptor: dup(2) cannot set the flag itself, so between the two
// calls the duplicate is inheritable, and a fork+exec started in that window
// hands the child a READ descriptor of the file being written. AtomicWrite is
// the chokepoint for every durable write here — key-at-rest material, cluster
// CA keys, enrollment receipts and the admin roster among them — so the
// window is closed at the source rather than left to depend on no caller ever
// execing (CWE-403). forkExec takes the lock for writing, so no exec can
// begin while this holds it.
func holdInode(f *os.File) *os.File {
	syscall.ForkLock.RLock()
	fd, err := syscall.Dup(int(f.Fd()))
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil
	}
	return os.NewFile(uintptr(fd), f.Name()) // #nosec G115 -- a descriptor is non-negative
}
