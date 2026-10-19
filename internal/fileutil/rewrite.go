package fileutil

import "errors"

// RewriteInPlace(path, data, orig) writes data — the bytes the caller just
// read from path, whose FileInfo is orig — back onto path, to obtain exact
// evidence that a later AtomicWrite to the same target can land: replacing
// the real target is the step a read-only mount, a sticky directory or an
// ACL-restricted directory refuses to a non-owner, which no scratch-file test
// reproduces. The temp file carries orig's permission bits, owner and group.
// Ownership is not best effort (Codex P2 4316401892 on PR #1601): a process
// that may replace another account's file (a writable, non-sticky directory)
// but not give the replacement away would otherwise take the file over, so a
// refused or ineffective chown means nothing is exchanged and
// ErrMetadataNotPreservable is returned, wrapping the chown error.
//
// It must never change the file's security metadata either (Codex P2
// 4316064806 on PR #1601). A new inode carries no extended attributes, so a
// bare exchange would silently strip a POSIX ACL (system.posix_acl_access),
// an SELinux label (security.selinux) or any other user.*, trusted.* or
// security.* attribute just because the process started. So on Linux every
// extended attribute of the target is read from an O_NOFOLLOW descriptor of
// it, set on the temp file after its chmod and chown (the access ACL and the
// mode interact, and a chown clears security.capability), any attribute the
// temp inherited but the target lacks (a directory's default ACL) is removed,
// and the temp's attribute set and permission bits are then read back and
// must equal the target's exactly. If any attribute cannot be read, set or
// removed, nothing is exchanged: the temp is removed, the target is untouched
// and ErrMetadataNotPreservable is returned. The post-exchange comparison
// below includes the attribute set (names and values), so a concurrent
// metadata change is a concurrent change like any other. Limit: listxattr
// shows trusted.* attributes only to a process with CAP_SYS_ADMIN, so an
// unprivileged process can neither see nor preserve them.
//
// It must never destroy content it did not load. A check-then-rename cannot
// promise that: an external writer (a configuration manager, an operator) can
// replace path between the check and the rename, which then silently puts the
// older bytes back. So on Linux the temp file is EXCHANGED with the target
// (renameat2 RENAME_EXCHANGE), and what was live just before the swap — now at
// the temp path — is compared with data, mode, owner and extended
// attributes. Identical: the rewrite landed and the temp is removed. Anything
// else: the exchange is undone at once, restoring the newer file to path, and ErrConcurrentChange is
// returned. If undoing it fails, the newer content stays at the temp path,
// which is never deleted, and ErrExchangeBackFailed names it.
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
	// ErrMetadataNotPreservable means the target's owner and group, or an
	// extended attribute (an ACL, a security label, a user attribute), could
	// not be read or set exactly on the replacement, so RewriteInPlace
	// exchanged nothing (the target is untouched) and the caller has no write
	// evidence.
	ErrMetadataNotPreservable = errors.New("rewrite in place: the file's owner, group, extended attributes or ACL could not be preserved exactly; nothing was replaced")
)
