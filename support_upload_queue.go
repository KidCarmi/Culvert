package main

import (
	"context"
	"path/filepath"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
	"github.com/KidCarmi/Culvert/internal/supportupload/uploadqueue"
)

// support_upload_queue.go — M6 Secure Upload, PR-3: main's binding to the
// persistent, node-local upload queue.
//
// The queue engine (the entry record, its per-bundle files, the state machine,
// retry/backoff and the capacity bounds) is internal/supportupload/uploadqueue
// (IM-029, ADR-0062). This file keeps what is main's: where the queue lives
// under dataDir, which ids name a bundle, the durable-write chokepoint the
// entries go through, the log sanitizer the persisted error text goes through,
// and the four bounds. The names below are the ones the consent gate, the
// worker and the tests already used.
//
// A bundle the operator has CONSENTED to upload (the consent gate is
// support_upload_wire.go) is enqueued here; the background worker
// (support_upload_worker.go) drains it through the PR-2 client.

// The five states, under the names main used before the move.
const (
	uploadStateQueued    = uploadqueue.StateQueued
	uploadStateUploading = uploadqueue.StateUploading
	uploadStateUploaded  = uploadqueue.StateUploaded
	uploadStateDeferred  = uploadqueue.StateDeferred
	uploadStateRejected  = uploadqueue.StateRejected
)

// The queue's bounds. maxUploadQueue bounds the number of distinct
// non-terminal (queued/uploading/deferred) bundles. maxUploadTerminal bounds
// retained TERMINAL (uploaded/rejected) records so completed uploads cannot
// accumulate on disk without limit (cross-milestone invariant #4: every
// persisted state under <dataDir>/support is bounded). Each entry is ~a few
// hundred bytes, so the two caps together bound the queue's on-disk footprint
// to well under a megabyte — the retention cap IS the disk-safety mechanism
// here (a heavyweight free-space preflight for a sub-KB write would be
// disproportionate).
const (
	maxUploadQueue    = 256
	maxUploadTerminal = 256
	maxUploadAttempts = 6 // transient-failure attempts before DEFERRED
	maxUploadErrLen   = 256
)

// uploadQueueEntry is one bundle's upload lifecycle record.
type uploadQueueEntry = uploadqueue.Entry

func uploadQueueDir() string { return filepath.Join(dataDir, "support", "upload_queue") }

// supportUploadQueue is the process's one upload queue. It reads dataDir on
// every call, validates every id against supportBundleIDRe so a filename can
// never traverse, and commits entries at 0600 through the support domain's
// fileutil.AtomicWrite chokepoint.
var supportUploadQueue = uploadqueue.New(uploadqueue.Options{
	Dir:         uploadQueueDir,
	ValidID:     func(id string) bool { return supportBundleIDRe.MatchString(id) },
	Mkdir:       mkdirDurableSupport,
	Write:       durableSupportWrite,
	Sanitize:    sanitizeLog,
	MaxPending:  maxUploadQueue,
	MaxTerminal: maxUploadTerminal,
	MaxAttempts: maxUploadAttempts,
	MaxErrLen:   maxUploadErrLen,
})

func uploadQueuePath(bundleID string) string { return supportUploadQueue.Path(bundleID) }

// listUploadQueue returns every persisted entry (oldest-first) for the status/UI.
func listUploadQueue() []uploadQueueEntry { return supportUploadQueue.List() }

// saveUploadQueueEntry persists one entry (the worker calls this after a drain).
func saveUploadQueueEntry(e uploadQueueEntry) error { return supportUploadQueue.Save(e) }

// loadUploadQueueEntry returns one bundle's upload record for the status/receipt
// surface. Absent/corrupt ⇒ (zero, false).
func loadUploadQueueEntry(bundleID string) (uploadQueueEntry, bool) {
	return supportUploadQueue.Load(bundleID)
}

// enqueueUpload records a consented bundle for upload (idempotent; a
// DEFERRED/REJECTED bundle is re-armed; bounded by maxUploadQueue).
func enqueueUpload(bundleID, caseID, keyID, sha256 string, now time.Time) (uploadQueueEntry, error) {
	return supportUploadQueue.Enqueue(bundleID, caseID, keyID, sha256, now)
}

// uploadFunc performs the actual transfer for an entry and returns the receipt
// plus the gateway upload session id. It is injected so the worker is testable
// without a live client; realUploadFunc is the production implementation. It
// MUST NOT be called while holding the queue's mutex (it does network I/O);
// the engine's Attempt never does. The uploadID contract is recorded on
// uploadqueue.Queue.Attempt.
type uploadFunc func(ctx context.Context, e uploadQueueEntry) (rec *supportupload.Receipt, uploadID string, err error)

// drainUploadEntry runs ONE attempt for an entry and returns the updated entry
// (the caller persists it via saveUploadQueueEntry).
func drainUploadEntry(ctx context.Context, e uploadQueueEntry, upload uploadFunc, now time.Time) uploadQueueEntry {
	return supportUploadQueue.Attempt(ctx, e, upload, now)
}

// dueUploadEntries returns queued entries whose backoff has elapsed (the worker's
// work-list).
func dueUploadEntries(now time.Time) []uploadQueueEntry { return supportUploadQueue.Due(now) }

// boundUploadErr sanitizes (CWE-117) and length-bounds an error string before it
// is persisted into an entry's LastError.
func boundUploadErr(s string) string { return supportUploadQueue.BoundErr(s) }
