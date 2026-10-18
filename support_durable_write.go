package main

import (
	"errors"
	"os"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// support_durable_write.go — the support domain's durable-write seam.
//
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
func durableSupportWrite(path string, data []byte, perm os.FileMode) error {
	if err := supportDurableWriter(path, data, perm); err != nil &&
		!errors.Is(err, fileutil.ErrReplacedNotSynced) {
		return err
	}
	return nil
}
