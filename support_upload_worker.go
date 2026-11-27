package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// support_upload_worker.go — M6 Secure Upload, PR-5: the bounded background worker
// that drains the upload queue on the appliance's OWN outbound schedule.
//
// Cloud-independence (SECURE-UPLOAD-ARCHITECTURE.md §5): the worker never blocks
// the proxy hot path and never holds the collection lock. It drains due entries
// one at a time through the SSRF-guarded client; an unreachable cloud just leaves
// entries queued (retried with bounded backoff), and the offline-export path stays
// available throughout. The worker only ever transfers bundles an operator
// EXPLICITLY consented to upload (they reach the queue solely via the consent gate
// in support_upload_wire.go), so there is no auto-upload — it is the delivery arm
// of a consented action, not a trigger.
//
// The worker consults uploadEnabled() each tick and idles (no dials) when upload is
// disabled, so disabling upload immediately pauses egress even with entries queued.
// It lives here (not in a *_startup.go file) so TestNoAutoUpload's scan of
// startup/background sources for the upload gate stays green — the startup layer
// only starts the goroutine; the gate check is inside the worker.

const (
	// supportUploadTick is the worker's poll cadence — the appliance's own outbound
	// schedule. Fixed (not tunable); a queued bundle is not latency-sensitive.
	supportUploadTick = 30 * time.Second

	// crashComponentSupportUpload names this worker in the crash record the
	// per-round guard writes (CHAOS-105).
	crashComponentSupportUpload = "support_upload"
	// supportUploadResumeChunk is the chunk size used when RESUMING a session whose
	// gateway-chosen size we no longer have. The gateway accepts a PUT at any
	// offset, so this only sizes our own reads.
	supportUploadResumeChunk = 4 << 20 // 4 MiB
)

// startSupportUploadWorker runs the drain loop until ctx is cancelled. Parented to
// the app lifecycle ctx (started from the persistent-admin-state loader, after
// LoadAdminSettings has restored the upload posture), so it exits cleanly on
// shutdown with no dedicated hook.
func startSupportUploadWorker(ctx context.Context) {
	t := time.NewTicker(supportUploadTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// CHAOS-105: this round dials the TAC gateway and walks on-disk
			// queue entries, so its inputs are partly remote and partly
			// whatever survived a crash. A fault in one entry costs one tick.
			runGuarded(crashComponentSupportUpload, func() { drainDueUploads(ctx, realUploadFunc) })
		}
	}
}

// drainDueUploads transfers every currently-due entry once, serially. Gated on
// uploadEnabled() so it is inert (no dials) when upload is disabled. Injected
// uploadFunc keeps it testable without a live gateway.
func drainDueUploads(ctx context.Context, upload uploadFunc) {
	// CHAOS-128: land any outcome still held in RAM FIRST, and above the
	// uploadEnabled() gate. Committing a held outcome is a local disk write
	// plus an audit record for an attempt that already happened — it dials
	// nothing. Disabling upload must pause EGRESS, not strand the record of a
	// transfer the node already made.
	retryHeldUploadCommits()
	if !uploadEnabled() {
		return
	}
	now := time.Now()
	due := dueUploadEntries(now)
	for i := range due {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// CHAOS-128: the on-disk entry for a held bundle is STALE — it still
		// reads `queued`, so dueUploadEntries offers it again every tick. The
		// authoritative outcome is the one in RAM, and re-sending the bundle
		// here is exactly the egress amplification the hold exists to prevent.
		if uploadCommitIsHeld(due[i].BundleID) {
			continue
		}
		finishUploadDrain(ctx, due[i], upload)
	}
}

// finishUploadDrain runs one attempt, persists the result, and — once that
// write has LANDED — records the outcome and removes the on-disk sealed blob.
//
// CHAOS-128: the persist is authoritative. It used to be log-only, and the two
// irreversible side effects below ran whether or not it succeeded.
func finishUploadDrain(ctx context.Context, e uploadQueueEntry, upload uploadFunc) {
	updated := drainUploadEntry(ctx, e, upload, time.Now())
	if err := saveUploadQueueEntry(updated); err != nil {
		holdUploadCommit(updated, err)
		return
	}
	commitUploadOutcome(updated)
}

// commitUploadOutcome performs the side effects a PERSISTED outcome authorizes:
// the terminal audit record, and (for a terminal state) deleting the sealed
// blob. Never called for an outcome whose write did not land.
func commitUploadOutcome(updated uploadQueueEntry) {
	switch updated.State {
	case uploadStateUploaded:
		removeSealedUpload(updated.BundleID)
		sig := ""
		if updated.Receipt != nil {
			sig = updated.Receipt.Sig
		}
		// Durable record: the receipt lives on the persisted queue entry; the audit
		// event surfaces the delivery (actor = system; the operator's consent was
		// audited as support.upload at enqueue time).
		auditSystem("support.bundle.upload", updated.BundleID, "receipt "+sanitizeLog(sig))
	case uploadStateRejected:
		removeSealedUpload(updated.BundleID)
		auditSystem("support.bundle.upload_rejected", updated.BundleID, sanitizeLog(updated.LastError))
	case uploadStateDeferred:
		auditSystem("support.bundle.upload_deferred", updated.BundleID, sanitizeLog(updated.LastError))
	}
}

// ── CHAOS-128: an outcome whose durable write failed ────────────────────────
//
// A terminal outcome has two IRREVERSIBLE side effects — deleting the sealed
// blob and writing the audit record that claims delivery — and both are valid
// only if the post-attempt queue entry reached the disk. Before CHAOS-128 a
// failed persist was logged and the side effects ran regardless, so on an
// ENOSPC/EROFS/EIO volume one consented upload lost BOTH the only copy of the
// bytes BundleSHA256 was computed over and the gateway's signed receipt — the
// node's only proof of delivery — while `support.bundle.upload` recorded a
// delivery it could no longer substantiate. The stale on-disk entry then sent
// the next attempt at the deleted blob, where a plain ENOENT is not a
// GatewayError and is therefore classified TRANSIENT, burning the attempt
// budget down to `deferred`: the operator surface and the audit trail ended up
// asserting opposite outcomes for the same bundle.
//
// The same failed write also broke the retry ladder for a NON-terminal attempt.
// A transient failure increments Attempts and sets a backoff NextRetryAt; if
// that write is lost, the disk keeps `attempts=0, next_retry_at=0`, the entry
// is immediately due again, and the bounded 6-attempt ladder becomes an
// unbounded re-send every supportUploadTick that can never reach `deferred`.
//
// So the outcome is HELD IN RAM until its write lands, whatever its state.
// Holding does two jobs at once: the receipt is not thrown away, and the
// bundle is not re-sent. The second matters as much as the first — simply
// returning before the side effects would leave the retained entry due on
// every tick, turning a local disk fault into a full re-upload of the bundle
// to the vendor every 30 s for as long as the volume stayed unwritable.
//
// A restart drops the hold, and that is the correct deterministic recovery
// rather than a gap: the in-RAM receipt is genuinely gone, the durable entry
// still reads `queued` and the sealed blob is still on disk, so the bundle is
// re-sent and a receipt the node CAN prove is recorded. Nothing that was ever
// durable is lost, and nothing is deleted on the strength of a write that
// failed.
//
// The map is bounded by the queue itself: a key is only ever a BundleID that
// dueUploadEntries returned, and that population is bounded by maxUploadQueue.
var (
	uploadCommitMu   sync.Mutex
	uploadCommitHeld = map[string]uploadQueueEntry{}
)

// supportUploadCommitHeldTotal counts outcomes whose durable write failed, so a
// zero `uploaded` count is not read as "nothing was delivered". Cumulative: one
// per failed persist attempt, including a retry of an already-held outcome.
var supportUploadCommitHeldTotal atomic.Int64

// holdUploadCommit retains e until its durable write succeeds, and logs the
// receipt when there is one. The log line is deliberate: the receipt is the
// node's only proof of delivery and it is NOT on disk, so this is the one form
// in which it survives the failure.
func holdUploadCommit(e uploadQueueEntry, err error) {
	uploadCommitMu.Lock()
	uploadCommitHeld[e.BundleID] = e
	uploadCommitMu.Unlock()
	supportUploadCommitHeldTotal.Add(1)
	logger.Printf("support: upload outcome for bundle %q could not be persisted (%v) — state %q held in memory, sealed blob RETAINED, no delivery recorded and no re-send attempted until the write lands",
		sanitizeLog(e.BundleID), err, sanitizeLog(string(e.State)))
	if e.Receipt != nil {
		logger.Printf("support: unpersisted delivery receipt for bundle %q: %q (the queue entry did not reach disk; this log line is the only record)",
			sanitizeLog(e.BundleID), sanitizeLog(e.Receipt.Sig))
	}
}

// uploadCommitIsHeld reports whether bundleID's authoritative outcome is the
// one in memory rather than the one on disk.
func uploadCommitIsHeld(bundleID string) bool {
	uploadCommitMu.Lock()
	defer uploadCommitMu.Unlock()
	_, held := uploadCommitHeld[bundleID]
	return held
}

// uploadCommitsHeld is the number of outcomes currently waiting in RAM for a
// durable write (the gauge beside supportUploadCommitHeldTotal).
func uploadCommitsHeld() int {
	uploadCommitMu.Lock()
	defer uploadCommitMu.Unlock()
	return len(uploadCommitHeld)
}

// retryHeldUploadCommits re-attempts the durable write for every held outcome
// and commits the ones that land. A still-failing write leaves the outcome held
// — it is never dropped, and the side effects never run ahead of it.
func retryHeldUploadCommits() {
	uploadCommitMu.Lock()
	pending := make([]uploadQueueEntry, 0, len(uploadCommitHeld))
	for id := range uploadCommitHeld { // keyed, not value-copied: the entry is large
		pending = append(pending, uploadCommitHeld[id])
	}
	uploadCommitMu.Unlock()

	for i := range pending {
		if err := saveUploadQueueEntry(pending[i]); err != nil {
			supportUploadCommitHeldTotal.Add(1)
			continue // still unwritable; the outcome stays in RAM
		}
		uploadCommitMu.Lock()
		delete(uploadCommitHeld, pending[i].BundleID)
		uploadCommitMu.Unlock()
		logger.Printf("support: held upload outcome for bundle %q persisted on retry — state %q now durable",
			sanitizeLog(pending[i].BundleID), sanitizeLog(string(pending[i].State)))
		commitUploadOutcome(pending[i])
	}
}
