//go:build linux

package fileutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// RewriteInPlace's metadata preservation as ONE ordered, verified step (Codex
// P2s 4316064806, 4316401892, 4316645541 and 4316645546 on PR #1601). The
// list of what is and is not preserved is the contract in rewrite.go; this
// file is its only implementation.

// fileMeta is the metadata RewriteInPlace preserves exactly.
type fileMeta struct {
	uid, gid uint32
	mode     uint32 // all 12 mode bits: rwx for user, group and other, plus setuid, setgid and sticky
	flags    uint32 // inode (chattr) flags, state-carrying bits only (see inodeFlagsImplementation)
	xattrs   xattrSet
}

// Inode flags (linux/fs.h FS_*_FL; x/sys/unix does not export them).
const (
	fsImmutableFL  = 0x00000010
	fsAppendFL     = 0x00000020
	fsDirtyFL      = 0x00000100
	fsComprBlkFL   = 0x00000200
	fsEncryptFL    = 0x00000800
	fsIndexFL      = 0x00001000
	fsHugeFileFL   = 0x00040000
	fsExtentFL     = 0x00080000
	fsEAInodeFL    = 0x00200000
	fsEOFBlocksFL  = 0x00400000
	fsInlineDataFL = 0x10000000

	// inodeFlagsImplementation are flags the filesystem sets on its own to
	// describe how it stores the inode (extents, inline data, huge-file
	// accounting, compression internals, directory indexing), plus
	// encryption, whose policy a file inherits from its directory and which
	// the kernel refuses to exchange across (EXDEV). They are not operator
	// state and may legitimately differ between the roster and a fresh temp
	// file, so they are masked out. Every other flag — nodump, noatime, sync,
	// compress, nocow, dax, verity, project inherit, and so on — must match
	// exactly or nothing is exchanged: RewriteInPlace does not set flags
	// (FS_IOC_SETFLAGS), it refuses.
	inodeFlagsImplementation = fsDirtyFL | fsComprBlkFL | fsEncryptFL | fsIndexFL | fsHugeFileFL |
		fsExtentFL | fsEAInodeFL | fsEOFBlocksFL | fsInlineDataFL
)

// Seams only for this package's white-box tests. The tests run as root, which
// may give a file away, set any special bit and read any flag, so the EPERM,
// the silent setgid drop and the ioctl results an unprivileged process or
// another filesystem produces are injected here. fsyncFile also lets a test
// see that the metadata is fsynced after the last metadata step.
var (
	fchown     = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	fchmod     = unix.Fchmod
	inodeFlags = func(fd int) (uint32, error) { return unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS) }
	fsyncFile  = func(f *os.File) error { return f.Sync() }
)

// errTargetImmutable: the target is immutable or append-only (chattr +i/+a).
// rename(2) refuses to replace such a file (EPERM), so no save can land: this
// is write-refusal evidence, not unpreservable metadata.
var errTargetImmutable = errors.New("the target is immutable or append-only (chattr +i/+a), so no save can replace it")

// readInodeFlags returns fd's state-carrying inode flags. A filesystem without
// inode flags (the ioctl is ENOTTY or ENOTSUP there) has none to lose.
func readInodeFlags(fd int) (uint32, error) {
	fl, err := inodeFlags(fd)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.ENOTSUP) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read inode flags: %w", err)
	}
	return fl &^ inodeFlagsImplementation, nil
}

// readMeta reads f's fileMeta. Inode flags are read only from a regular file:
// the descriptor may name whatever was at the target, and an ioctl on a
// device node would reach its driver.
func readMeta(f *os.File) (fileMeta, error) {
	fi, err := f.Stat()
	if err != nil {
		return fileMeta{}, fmt.Errorf("stat: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileMeta{}, errors.New("no owner or mode information")
	}
	m := fileMeta{uid: st.Uid, gid: st.Gid, mode: st.Mode & 0o7777}
	fd := int(f.Fd())
	if fi.Mode().IsRegular() {
		if m.flags, err = readInodeFlags(fd); err != nil {
			return fileMeta{}, err
		}
	}
	if m.xattrs, err = readXattrs(fd); err != nil {
		return fileMeta{}, err
	}
	return m, nil
}

// differs names the first way m and o differ, or "" when they are identical.
func (m fileMeta) differs(o fileMeta) string {
	switch {
	case m.uid != o.uid || m.gid != o.gid:
		return "owner or group"
	case m.mode != o.mode:
		return "mode (permission, setuid, setgid or sticky bits)"
	case m.flags != o.flags:
		return "inode flags (chattr)"
	case !m.xattrs.equal(o.xattrs):
		return "extended attributes (or ACL)"
	}
	return ""
}

// targetMeta reads the metadata of the file at path through an O_NOFOLLOW
// descriptor, after confirming it is still orig with orig's owner and mode. A
// target that vanished, became a symlink, is another file or was chowned or
// chmodded since it was loaded is a concurrent change; an immutable or
// append-only target is a write refusal; any other failure means its metadata
// cannot be preserved. Nothing is written in any case.
func targetMeta(op, path string, orig os.FileInfo) (fileMeta, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- the caller's own path
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
			return fileMeta{}, fmt.Errorf("%s %s: open to read its metadata: %w: %w", op, path, err, ErrConcurrentChange)
		}
		return fileMeta{}, fmt.Errorf("%s %s: open to read its metadata: %w: %w", op, path, err, ErrMetadataNotPreservable)
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	if fi, err := f.Stat(); err == nil && (!os.SameFile(fi, orig) || fi.Mode() != orig.Mode() || !sameOwner(fi, orig)) {
		return fileMeta{}, fmt.Errorf("%s %s: the target is no longer the loaded file: %w", op, path, ErrConcurrentChange)
	}
	m, err := readMeta(f)
	if err != nil {
		return fileMeta{}, fmt.Errorf("%s %s: read metadata: %w: %w", op, path, err, ErrMetadataNotPreservable)
	}
	if m.flags&(fsImmutableFL|fsAppendFL) != 0 {
		return fileMeta{}, fmt.Errorf("%s %s: %w: %w", op, path, errTargetImmutable, unix.EPERM)
	}
	return m, nil
}

// preserveMetadata gives the open temp file f exactly want's metadata, in the
// only order that works, and then fsyncs it:
//
//  1. fchown to want's owner and group — first, because a chown clears
//     setuid, setgid and security.capability;
//  2. fchmod with the full 12-bit mode;
//  3. the extended attributes, the access ACL last (it rewrites the group
//     bits from its mask), and removal of any the temp inherited that want
//     lacks;
//  4. an exact read-back of owner, group, full mode, inode flags and
//     attributes. Any mismatch — including a special bit the kernel dropped
//     silently (an unprivileged setgid on a file whose group the process is
//     not in), an inode flag the temp lacks or inherited, or a chown that
//     had no effect — is a failure;
//  5. an unconditional fsync, so the metadata is as durable as the bytes
//     before the exchange makes the temp the roster.
//
// A failure in steps 1–4 wraps ErrMetadataNotPreservable.
func preserveMetadata(f *os.File, want fileMeta) error {
	notPreservable := func(stage string, err error) error {
		return fmt.Errorf("preserve metadata: %s: %w: %w", stage, err, ErrMetadataNotPreservable)
	}
	fd := int(f.Fd())
	if err := fchown(f, int(want.uid), int(want.gid)); err != nil {
		return notPreservable(fmt.Sprintf("chown the replacement to %d:%d", want.uid, want.gid), err)
	}
	if err := fchmod(fd, want.mode); err != nil {
		return notPreservable(fmt.Sprintf("chmod the replacement to %04o", want.mode), err)
	}
	if err := copyXattrs(fd, want.xattrs); err != nil {
		return notPreservable("extended attributes", err)
	}
	got, err := readMeta(f)
	if err != nil {
		return notPreservable("read back the replacement", err)
	}
	if what := want.differs(got); what != "" {
		return notPreservable("verify", fmt.Errorf("the replacement's %s differs from the target's", what))
	}
	if err := fsyncFile(f); err != nil {
		return fmt.Errorf("preserve metadata: fsync the replacement: %w", err)
	}
	return nil
}
