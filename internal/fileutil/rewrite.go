package fileutil

import "errors"

// RewriteInPlace(path, data, orig) writes data — the bytes the caller just
// read from path, whose FileInfo is orig — back onto path, to obtain exact
// evidence that a later AtomicWrite to the same target can land: replacing
// the real target is the step a read-only mount, a sticky directory or an
// ACL-restricted directory refuses to a non-owner, which no scratch-file test
// reproduces. The temp file carries orig's permission bits and, best effort,
// its owner and group.
//
// It must never destroy content it did not load. A check-then-rename cannot
// promise that: an external writer (a configuration manager, an operator) can
// replace path between the check and the rename, which then silently puts the
// older bytes back. So on Linux the temp file is EXCHANGED with the target
// (renameat2 RENAME_EXCHANGE), and what was live just before the swap — now at
// the temp path — is compared with data, mode and owner. Identical: the
// rewrite landed and the temp is removed. Anything else: the exchange is
// undone at once, restoring the newer file to path, and ErrConcurrentChange is
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
)
