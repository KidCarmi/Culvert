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

// ReplacementBlocked is a READ-ONLY check (it opens the target for reading
// and stats its directory; it never writes): whether rename(2) would refuse
// to replace a file at all, whoever renames (Codex P2 4319694761 on PR #1601).

// Inode flags (linux/fs.h FS_*_FL; x/sys/unix does not export them).
const (
	fsImmutableFL = 0x00000010
	fsAppendFL    = 0x00000020
)

// Seams only for this package's white-box tests, which inject flags and
// attributes the test filesystem or privileges cannot set.
var (
	inodeFlags      = func(fd int) (uint32, error) { return unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS) }
	statxAttributes = func(fd int) (uint64, error) {
		var stx unix.Statx_t
		if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx); err != nil {
			return 0, err
		}
		return stx.Attributes & stx.Attributes_mask, nil
	}
	// dirStatxAttributes reads the directory by path, without opening it (a
	// write+search-only directory cannot be opened for reading).
	dirStatxAttributes = func(dir string) (uint64, error) {
		var stx unix.Statx_t
		if err := unix.Statx(unix.AT_FDCWD, dir, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS, &stx); err != nil {
			return 0, err
		}
		return stx.Attributes & stx.Attributes_mask, nil
	}
)

// replacementBlockedBy is the predicate. flags and attrs are the target's
// inode flags (FS_IOC_GETFLAGS) and statx attributes, dirAttrs its
// directory's statx attributes. rename(2) refuses to replace a target that
// is immutable or append-only (EPERM) or a mount point — a bind-mounted file
// (EBUSY) — and any entry of an immutable or append-only directory (EPERM).
// The refusals rename(2) decides by who renames (sticky-directory ownership,
// the directory's permissions) are the caller's to check.
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

// unsupported reports an interface the filesystem or kernel does not offer:
// the file then has no such flags or attributes.
func unsupported(err error) bool {
	return errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS)
}

// ReplacementBlocked reports, without writing anything, whether rename(2)
// would refuse to replace the file at path itself: it returns an error
// wrapping ErrReplacementBlocked (and EPERM or EBUSY) for an immutable or
// append-only file (inode flags or statx), a mount point, or an immutable or
// append-only directory; nil when none applies; any other error when the
// target could not be inspected. The inode flags are read only from a
// regular file (an ioctl on a device node would reach its driver).
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
		if flags, err = inodeFlags(fd); err != nil && !unsupported(err) {
			return fmt.Errorf("read inode flags: %w", err)
		}
	}
	attrs, err := statxAttributes(fd)
	if err != nil && !unsupported(err) {
		return fmt.Errorf("statx: %w", err)
	}
	dirAttrs, err := dirStatxAttributes(filepath.Dir(path))
	if err != nil && !unsupported(err) {
		return fmt.Errorf("statx of the directory: %w", err)
	}
	return replacementBlockedBy(flags, attrs, dirAttrs)
}
