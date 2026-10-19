package fileutil

import "errors"

// RewriteInPlace(path, data, orig) writes data — the bytes the caller just
// read from path, whose FileInfo is orig — back onto path, to obtain exact
// evidence that a later AtomicWrite to the same target can land: replacing
// the real target is the step a read-only mount, a sticky directory or an
// ACL-restricted directory refuses to a non-owner, which no scratch-file test
// reproduces.
//
// It must never change the file's metadata just because the process started
// (Codex P2s 4316064806, 4316401892, 4316645541, 4316645546 and 4317024211
// on PR #1601). It covers every interface through which Linux exposes
// per-inode metadata to user space — stat, statx, FS_IOC_GETFLAGS,
// FS_IOC_FSGETXATTR and the extended attributes — so this is the complete
// list; metadata_linux.go (with xattr_linux.go and inodeattr_linux.go) is
// its one implementation.
//
// PRESERVED EXACTLY, or nothing is exchanged:
//   - stat: the content, byte for byte (never re-serialised); owner and
//     group (uid, gid); all 12 mode bits — rwx for user, group and other,
//     plus setuid, setgid and sticky;
//   - extended attributes: every one this process can list, names and
//     values — the POSIX access ACL (system.posix_acl_access), the SELinux
//     or other LSM label (security.*), file capabilities
//     (security.capability), user.*, and trusted.* when the process has
//     CAP_SYS_ADMIN;
//   - FS_IOC_GETFLAGS inode (chattr) flags such as nodump, noatime, sync,
//     compress, nocow, verity, dax — compared, never set. Ignored: only the
//     filesystem's own storage flags (extents, inline data, huge file,
//     compression internals, directory index, EA inode) and encryption
//     (inherited from the directory; the kernel refuses to exchange across
//     policies);
//   - FS_IOC_FSGETXATTR struct fsxattr: the project quota ID, the extent-size
//     and CoW extent-size hints, and the xflags — compared, never set.
//     Ignored: the xflags that mirror a compared FS_IOC_GETFLAGS bit
//     (immutable, append, sync, noatime, nodump, project inherit, dax), the
//     filesystem-internal prealloc and hasattr, and fsx_nextents (allocation,
//     not metadata);
//   - statx: stx_attributes masked by stx_attributes_mask (compressed,
//     immutable, append, nodump, encrypted, automount, mount root, verity,
//     dax, atomic write) — compared, never set.
//
// A filesystem where an ioctl is unsupported (ENOTTY, ENOTSUP), or a kernel
// without statx (ENOSYS), keeps no such metadata; any other failure to read
// any item refuses. Because flags, fsxattr and statx attributes are compared
// rather than set, a roster carrying one a fresh file lacks — or a temp file
// that inherits one from its directory — is not rewritten. An fs-verity or
// DAX roster is refused outright.
//
// The temp file gets them in the only working order — fchown (it clears
// setuid, setgid and security.capability), then fchmod with the full mode,
// then the extended attributes with the access ACL last (it rewrites the
// group bits from its mask), then removal of any attribute the temp
// inherited that the target lacks (a directory's default ACL) — and is then
// read back: every item above must equal the target's exactly, which also
// catches a chown with no effect and a special bit the kernel dropped
// silently (an unprivileged setgid on a file whose group the process is not
// in). The temp is then fsynced, always, before the exchange. If any step
// fails, the temp is removed, the target is untouched and
// ErrMetadataNotPreservable is returned, wrapping the cause. A target
// rename(2) would refuse to replace — immutable or append-only (chattr
// +i/+a, or statx reporting it), a mount point, or in an immutable or
// append-only directory — is not exchanged either: every save over it would
// be refused, so that is ErrReplacementBlocked wrapping EPERM (EBUSY for a
// mount point). ReplacementBlocked applies the same predicate without
// writing.
//
// NOT PRESERVED: the inode number and its timestamps (atime, mtime, ctime and
// birth time are the replacement's own), other hard links to the old inode
// (they keep the old inode, with identical content), and trusted.*
// attributes when the process lacks CAP_SYS_ADMIN (Linux does not list them
// to it, so it can neither see nor keep them).
//
// It must never destroy content it did not load. A check-then-rename cannot
// promise that: an external writer (a configuration manager, an operator) can
// replace path between the check and the rename, which then silently puts the
// older bytes back. So on Linux the temp file is EXCHANGED with the target
// (renameat2 RENAME_EXCHANGE), and what was live just before the swap — now at
// the temp path — is compared with data and with every preserved item above
// as read from the target before the exchange. Identical: the rewrite landed
// and the temp is removed. Anything else: the exchange is undone at once,
// restoring the newer file to path, and ErrConcurrentChange is returned. If
// undoing it fails, the newer content stays at the temp path, which is never
// deleted, and ErrExchangeBackFailed names it.
//
// Where the exchange is unavailable (any non-Linux platform, or a Linux
// kernel or filesystem that rejects RENAME_EXCHANGE) nothing is written and
// ErrRewriteUnsupported is returned: the caller has no write evidence.
//
// A writer that keeps a descriptor to the old file open across the exchange
// and writes through it only after the comparison loses that write to the
// unlinked inode — the same as against any rename-based save, AtomicWrite's
// included; a writer that replaces the file by path never loses content.
//
// Unlike AtomicWrite it does NOT notify the write observers. Such a rewrite
// persists no new state, so reporting it to the storage-health plane would be
// wrong in both directions: a failure would count and log as lost persisted
// state (and consume the storage_write_failed alert gate), and a success would
// be taken as recovery evidence for an unrelated failing store.
//
// ErrReplacedNotSynced keeps its AtomicWrite meaning: the rewrite landed and
// only the parent-directory fsync failed.

var (
	// ErrRewriteUnsupported means no atomic exchange is available here, so
	// RewriteInPlace wrote nothing (the target is untouched).
	ErrRewriteUnsupported = errors.New("rewrite in place: atomic exchange not supported on this platform or filesystem")
	// ErrConcurrentChange means the target was not the content the caller loaded
	// when the exchange ran; the newer file was restored to the target (or
	// was never displaced) and the rewrite is not evidence of anything.
	ErrConcurrentChange = errors.New("rewrite in place: the target changed concurrently; the newer file was kept")
	// ErrExchangeBackFailed means a concurrent change was detected but restoring
	// the newer file to the target failed. The newer content is preserved at
	// the temp path named in the error, which is left in place.
	ErrExchangeBackFailed = errors.New("rewrite in place: a concurrent change was detected and could not be restored to the target")
	// ErrReplacementBlocked means rename(2) would refuse to replace the target
	// itself — it is immutable or append-only, a mount point, or in an
	// immutable or append-only directory — so no save can land there.
	// Returned by RewriteInPlace's precheck and by ReplacementBlocked, which
	// share one predicate. Not detected outside Linux.
	ErrReplacementBlocked = errors.New("the target cannot be replaced by any save")
	// ErrMetadataNotPreservable means some preserved metadata of the target
	// (owner, group, mode bits, inode flags, an extended attribute or ACL)
	// could not be read, or could not be given exactly to the replacement, so
	// RewriteInPlace exchanged nothing (the target is untouched) and the
	// caller has no write evidence.
	ErrMetadataNotPreservable = errors.New("rewrite in place: the file's owner, group, mode, inode flags, extended attributes or ACL could not be preserved exactly; nothing was replaced")
)
