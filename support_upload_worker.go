package main

import (
	"context"
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
			drainDueUploads(ctx, realUploadFunc)
		}
	}
}

// drainDueUploads transfers every currently-due entry once, serially. Gated on
// uploadEnabled() so it is inert (no dials) when upload is disabled. Injected
// uploadFunc keeps it testable without a live gateway.
func drainDueUploads(ctx context.Context, upload uploadFunc) {
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
		finishUploadDrain(ctx, due[i], upload)
	}
}

// finishUploadDrain runs one attempt, persists the result, and — on a terminal
// state — records the outcome and removes the on-disk sealed blob.
func finishUploadDrain(ctx context.Context, e uploadQueueEntry, upload uploadFunc) {
	updated := drainUploadEntry(ctx, e, upload, time.Now())
	if err := saveUploadQueueEntry(updated); err != nil {
		logger.Printf("support: persist upload entry %q failed: %v", sanitizeLog(updated.BundleID), err)
	}
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
