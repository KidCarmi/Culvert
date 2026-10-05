//go:build linux

// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md) — not part of upstream ristretto.

package z

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// preallocate reserves real blocks for [off, off+size) of f, so a store into a
// mapped page of that range never needs the filesystem to allocate one. On a
// full filesystem that allocation fails inside a page fault, which the kernel
// reports as SIGBUS (a crash); fallocate reports the same shortage as ENOSPC.
//
// A filesystem that cannot reserve space (EOPNOTSUPP/ENOSYS) keeps upstream's
// sparse behaviour rather than refusing to open the store at all.
func preallocate(f *os.File, off, size int64) error {
	if size <= 0 {
		return nil
	}
	for {
		err := unix.Fallocate(int(f.Fd()), 0, off, size)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS):
			return nil
		default:
			return &os.PathError{Op: "fallocate", Path: f.Name(), Err: err}
		}
	}
}
