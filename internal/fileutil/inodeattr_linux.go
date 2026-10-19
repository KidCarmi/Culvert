//go:build linux

package fileutil

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The two per-inode metadata interfaces beyond stat, FS_IOC_GETFLAGS and the
// extended attributes (Codex P2 4317024211 on PR #1601): FS_IOC_FSGETXATTR's
// struct fsxattr (XFS-style flags, extent-size hints and the project quota
// ID, also on ext4, btrfs and f2fs) and statx's stx_attributes. Like the
// inode flags they are compared, never set. The contract is in rewrite.go.

// fsxattr is linux/fs.h struct fsxattr (28 bytes).
type fsxattr struct {
	Xflags     uint32
	Extsize    uint32
	Nextents   uint32 // allocation state, not metadata: never compared
	Projid     uint32
	Cowextsize uint32
	_          [8]byte
}

// fsxMeta is the part of struct fsxattr that is per-inode metadata.
type fsxMeta struct {
	xflags, extsize, projid, cowextsize uint32
}

// FS_XFLAG_* bits (linux/fs.h).
const (
	fsXflagPrealloc    = 0x00000002
	fsXflagImmutable   = 0x00000008
	fsXflagAppend      = 0x00000010
	fsXflagSync        = 0x00000020
	fsXflagNoatime     = 0x00000040
	fsXflagNodump      = 0x00000080
	fsXflagProjinherit = 0x00000200
	fsXflagDax         = 0x00008000
	fsXflagHasattr     = 0x80000000

	// fsXflagsIgnored are xflags not compared: the ones that merely mirror an
	// FS_IOC_GETFLAGS bit already compared there (immutable, append, sync,
	// noatime, nodump, project inherit, dax), and the filesystem-internal
	// ones (prealloc: space was fallocated; hasattr: XFS has an attribute
	// fork). Every other xflag (realtime, rtinherit, nosymlinks, extsize,
	// extszinherit, nodefrag, filestream, cowextsize, and any future one) is
	// compared.
	fsXflagsIgnored = fsXflagImmutable | fsXflagAppend | fsXflagSync | fsXflagNoatime | fsXflagNodump |
		fsXflagProjinherit | fsXflagDax | fsXflagPrealloc | fsXflagHasattr
)

// fsIocFsgetxattr is FS_IOC_FSGETXATTR, _IOR('X', 31, struct fsxattr), which
// x/sys/unix does not export. The direction bits sit at a different shift on
// some architectures (mips, powerpc, sparc), so they are taken from
// FS_IOC_GETFLAGS, also an _IOR, whose size field (4 or 8) leaves the top
// three bits to the direction alone.
const fsIocFsgetxattr = uint(unix.FS_IOC_GETFLAGS)&0xE0000000 | uint(unsafe.Sizeof(fsxattr{}))<<16 | 'X'<<8 | 31

// Seams only for this package's white-box tests: the test filesystem may not
// support project IDs or report every statx attribute, so differences and
// unsupported results are injected here.
var (
	fsGetxattr = func(fd int) (fsxattr, error) {
		var x fsxattr
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(fsIocFsgetxattr), uintptr(unsafe.Pointer(&x))) // #nosec G103 -- ioctl argument, as the kernel ABI requires
		if errno != 0 {
			return fsxattr{}, errno
		}
		return x, nil
	}
	statxAttributes = func(fd int) (uint64, error) {
		var stx unix.Statx_t
		if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS, &stx); err != nil {
			return 0, err
		}
		return stx.Attributes & stx.Attributes_mask, nil
	}
)

// readFsxMeta returns fd's struct fsxattr metadata. Where the ioctl is
// unsupported (ENOTTY, ENOTSUP) the filesystem keeps none.
func readFsxMeta(fd int) (fsxMeta, error) {
	x, err := fsGetxattr(fd)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOTSUP) {
		return fsxMeta{}, nil
	}
	if err != nil {
		return fsxMeta{}, fmt.Errorf("read FS_IOC_FSGETXATTR: %w", err)
	}
	return fsxMeta{xflags: x.Xflags &^ fsXflagsIgnored, extsize: x.Extsize, projid: x.Projid, cowextsize: x.Cowextsize}, nil
}

// readStatxAttributes returns the statx attributes the kernel reports for fd
// (stx_attributes masked by stx_attributes_mask: compressed, immutable,
// append, nodump, encrypted, automount, mount root, verity, dax, atomic
// write, and any future one). A kernel without statx (ENOSYS) reports none.
func readStatxAttributes(fd int) (uint64, error) {
	a, err := statxAttributes(fd)
	if errors.Is(err, unix.ENOSYS) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("statx: %w", err)
	}
	return a, nil
}
