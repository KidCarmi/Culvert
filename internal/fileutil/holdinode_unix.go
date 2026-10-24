//go:build unix

package fileutil

import (
	"os"
	"syscall"
)

// holdInode returns a duplicate descriptor of f's inode, or nil if one could
// not be made. AtomicWriteInfo fstats it after the rename.
func holdInode(f *os.File) *os.File {
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return nil
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), f.Name()) // #nosec G115 -- a descriptor is non-negative
}
