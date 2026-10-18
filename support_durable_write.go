package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// support_durable_write.go — the support domain's durable-write seam.

// supportStatePerm is the mode every durable support-state file carries. All of
// it is operator-or-TAC material (upload credential, recipient keys, sealed
// bundles, approval state), so the mode is a domain invariant rather than a
// per-call-site choice — which is why durableSupportWrite takes no perm
// argument (golangci `unparam` on PR #1658: every caller passed 0o600).
const supportStatePerm os.FileMode = 0o600

// supportDurableWriter is the injection point for tests; production is always
// fileutil.AtomicWrite, the repository's durable-write chokepoint.
var supportDurableWriter = fileutil.AtomicWrite

// durableSupportWrite persists support state through the AtomicWrite chokepoint
// and treats fileutil.ErrReplacedNotSynced as COMMITTED.
//
// That sentinel is returned only AFTER the rename has succeeded: the target
// already carries the new bytes, and every reader sees them — including
// readBundleState, which feeds the mandatory-preview download gate. What is
// unproven on that branch is narrower: the rename's durability across an
// immediate crash, because the parent-directory fsync (or close) failed.
//
// Reporting that as a plain failure made the HTTP response and the audit trail
// contradict the state actually on disk. apiSupportBundleApprove returns 500
// and `return`s BEFORE its auditEvent, so a bundle could be READY and
// downloadable with no support.bundle.approve record of who authorized the
// export — on the one control that gates export of a bundle's INTERNAL
// sections. The same audit-after-save shape covers the support.upload.config
// egress posture flip and the debug-level elevation. Reported by Codex review
// on PR #1658; the divergence arrived with the chokepoint conversion, because
// the previous os.WriteFile+os.Rename pair returned nil whenever the rename
// succeeded and so had no error-after-landing case at all.
//
// Nothing is concealed. AtomicWrite notifies the write-failure observer on this
// branch before returning, so by the time this function sees the sentinel the
// failure is already counted, logged as "DURABLE WRITE FAILED", dispatched as a
// storage_write_failed alert and reflected in storageDegraded(). The operator
// still sees degraded storage; the caller sees the state that landed. This is
// also exactly what ErrReplacedNotSynced's own contract asks of callers: never
// restore prior state on it, or memory contradicts the visible file.
func durableSupportWrite(path string, data []byte) error {
	if err := supportDurableWriter(path, data, supportStatePerm); err != nil &&
		!errors.Is(err, fileutil.ErrReplacedNotSynced) {
		return err
	}
	return nil
}

// mkdirDurableSupport creates dir and makes the new directory ENTRIES durable,
// which os.MkdirAll alone does not do.
//
// AtomicWrite fsyncs the directory holding the file it wrote, so a file's own
// entry is durable. A directory's entry lives in its PARENT, which nothing in
// that path ever syncs. So after creating <bundles>/<id>/ and writing a fully
// fsynced manifest into it, a power loss could still take the whole directory —
// every artifact in it included — after createSupportBundle had already
// returned the bundle id to the operator. Raised by CodeRabbit on PR #1658.
//
// Note the direction: losing the directory loses the gate state WITH the
// payload, so it stays fail-closed (no bundle, nothing to export) and is not a
// gate bypass. It is a durability gap, not a security one.
//
// Only the parents of directories this call actually creates are synced, so the
// common case — the parent already exists and MkdirAll is a no-op — costs one
// stat and no fsync. Sync errors follow AtomicWrite's posture: a filesystem that
// cannot fsync a directory (EINVAL/ENOTSUP/EOPNOTSUPP) has already given every
// guarantee it has, and an unopenable directory is skipped rather than failing a
// create that succeeded.
func mkdirDurableSupport(dir string, perm os.FileMode) error {
	// Record the chain MkdirAll will have to create, deepest first.
	var missing []string
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			break
		}
		missing = append(missing, p)
		if parent := filepath.Dir(p); parent == p { // reached the root
			break
		}
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	// Each created directory's entry lives in its parent, so sync those —
	// shallowest first, so an outer entry is never durable before the inner one
	// it will come to contain.
	for i := len(missing) - 1; i >= 0; i-- {
		syncDirBestEffort(filepath.Dir(missing[i]))
	}
	return nil
}

// syncDirBestEffort fsyncs a directory, tolerating the filesystems that cannot.
func syncDirBestEffort(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return // not portable to open a directory everywhere; nothing more to offer
	}
	syncErr := d.Sync()
	_ = d.Close() //nolint:errcheck // read-only handle; Sync above is the signal
	if syncErr != nil &&
		!errors.Is(syncErr, syscall.EINVAL) &&
		!errors.Is(syncErr, syscall.ENOTSUP) &&
		!errors.Is(syncErr, syscall.EOPNOTSUPP) {
		logger.Printf("Support: directory fsync failed for %q: %v", sanitizeLog(filepath.Base(dir)), sanitizeLog(syncErr.Error()))
	}
}
