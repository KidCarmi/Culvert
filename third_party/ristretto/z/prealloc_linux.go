//go:build linux

// CULVERT PATCH (F-DISK-1, CULVERT-PATCH.md) — not part of upstream ristretto.

package z

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// fallocate is unix.Fallocate; a variable so the unsupported-filesystem
// fallback can be exercised on a filesystem that does support it.
var fallocate = unix.Fallocate

// preallocate reserves real blocks for [off, off+size) of f, so a store into a
// mapped page of that range never needs the filesystem to allocate one. On a
// full filesystem that allocation fails inside a page fault, which the kernel
// reports as SIGBUS (a crash); fallocate reports the same shortage as ENOSPC.
//
// A filesystem without fallocate (EOPNOTSUPP/ENOSYS) is NOT left sparse — that
// would keep the fault — but gets glibc's posix_fallocate emulation: a zero
// byte written into every block that reads back zero. That allocates the
// blocks (so ENOSPC is an error here, not a SIGBUS later) and never changes
// data. Copy-on-write filesystems can still need new blocks on a later store;
// no preallocation can prevent that, and the supported data filesystems are
// recorded in CULVERT-PATCH.md.
func preallocate(f *os.File, off, size int64) error {
	if size <= 0 {
		return nil
	}
	for {
		err := fallocate(int(f.Fd()), 0, off, size)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOSYS):
			noteEmulatedPrealloc(f.Name())
			return zeroFill(f, off, size)
		default:
			return &os.PathError{Op: "fallocate", Path: f.Name(), Err: err}
		}
	}
}

var emulatedPreallocOnce sync.Once

// noteEmulatedPrealloc reports, once per process, that reservations are being
// emulated (slower: one write per block).
func noteEmulatedPrealloc(name string) {
	emulatedPreallocOnce.Do(func() {
		_, _ = os.Stderr.WriteString("ristretto: fallocate unsupported for " + name +
			"; reserving space by writing each block (posix_fallocate emulation)\n")
	})
}

// zeroFill allocates [off, off+size) by writing one zero byte per block,
// skipping blocks whose probed byte is already non-zero (they hold data and
// are allocated). Writing a zero over a zero byte changes nothing, so existing
// content is never modified.
func zeroFill(f *os.File, off, size int64) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return &os.PathError{Op: "fstat", Path: f.Name(), Err: err}
	}
	bs := int64(st.Blksize)
	if bs <= 0 {
		bs = 4096
	}
	end := off + size
	one := []byte{0}
	// The last byte of the range first, so the file reaches its full length
	// even when the range ends mid-block; then the first byte of every block.
	for _, at := range append([]int64{end - 1}, blockStarts(off, end, bs)...) {
		if at < st.Size {
			if n, err := f.ReadAt(one, at); err != nil && n != 1 {
				return &os.PathError{Op: "posix_fallocate emulation", Path: f.Name(), Err: err}
			} else if one[0] != 0 {
				one[0] = 0
				continue
			}
		}
		if _, err := f.WriteAt([]byte{0}, at); err != nil {
			return &os.PathError{Op: "posix_fallocate emulation", Path: f.Name(), Err: err}
		}
	}
	return nil
}

// blockStarts lists the first offset inside [off, end) of every bs-aligned block.
func blockStarts(off, end, bs int64) []int64 {
	out := []int64{off}
	for b := (off/bs + 1) * bs; b < end; b += bs {
		out = append(out, b)
	}
	return out
}
