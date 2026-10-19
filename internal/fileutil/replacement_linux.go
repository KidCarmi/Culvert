//go:build linux

package fileutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// The ONE predicate for "rename(2) would refuse to replace this target
// itself", shared by RewriteInPlace's precheck and by callers that probe a
// target live without writing (ReplacementBlocked; Codex P2 4319694761 on PR
// #1601), so the two can never disagree.

// dirStatxAttributes returns the statx attributes of dir by path, without
// opening it (a write+search-only directory cannot be opened for reading). A
// seam only for this package's white-box tests.
var dirStatxAttributes = func(dir string) (uint64, error) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, dir, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS, &stx); err != nil {
		return 0, err
	}
	return stx.Attributes & stx.Attributes_mask, nil
}

// replacementBlockedBy is the predicate. flags and attrs are the target's
// inode flags (FS_IOC_GETFLAGS) and statx attributes, dirAttrs its
// directory's statx attributes. rename(2) refuses to replace a target that
// is immutable or append-only (EPERM), one that is a mount point — a
// bind-mounted file (EBUSY) — and any entry of an append-only or immutable
// directory (EPERM). The remaining refusals rename(2) decides by ownership
// (a sticky directory) or by the directory's permissions are the caller's to
// check: they depend on who renames, not on the target.
func replacementBlockedBy(flags uint32, attrs, dirAttrs uint64) error {
	switch {
	case flags&(fsImmutableFL|fsAppendFL) != 0, attrs&(unix.STATX_ATTR_IMMUTABLE|unix.STATX_ATTR_APPEND) != 0:
		return fmt.Errorf("%w: it is immutable or append-only (chattr +i/+a): %w", ErrReplacementBlocked, unix.EPERM)
	case attrs&unix.STATX_ATTR_MOUNT_ROOT != 0:
		return fmt.Errorf("%w: it is a mount point (a bind-mounted file): %w", ErrReplacementBlocked, unix.EBUSY)
	case dirAttrs&(unix.STATX_ATTR_IMMUTABLE|unix.STATX_ATTR_APPEND) != 0:
		return fmt.Errorf("%w: its directory is immutable or append-only (chattr +i/+a): %w",
			ErrReplacementBlocked, unix.EPERM)
	}
	return nil
}

// readDirAttrs is dirStatxAttributes with a kernel lacking statx reporting
// none. Any other failure is returned.
func readDirAttrs(dir string) (uint64, error) {
	a, err := dirStatxAttributes(dir)
	if errors.Is(err, unix.ENOSYS) {
		return 0, nil
	}
	return a, err
}

// ReplacementBlocked reports, without writing anything, whether rename(2)
// would refuse to replace the file at path itself: it returns an error
// wrapping ErrReplacementBlocked (and EPERM or EBUSY) for an immutable or
// append-only file (inode flags or statx), a mount point, or an immutable or
// append-only directory; nil when none applies; any other error when the
// target could not be inspected. It is the same predicate RewriteInPlace's
// precheck applies. The inode flags are read only from a regular file (an
// ioctl on a device node would reach its driver).
func ReplacementBlocked(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the caller's own path
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	fd := int(f.Fd())
	var flags uint32
	if fi.Mode().IsRegular() {
		if flags, err = readInodeFlags(fd); err != nil {
			return err
		}
	}
	attrs, err := readStatxAttributes(fd)
	if err != nil {
		return err
	}
	dirAttrs, err := readDirAttrs(filepath.Dir(path))
	if err != nil {
		return err
	}
	return replacementBlockedBy(flags, attrs, dirAttrs)
}
