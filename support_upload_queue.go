package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// support_upload_queue.go — M6 Secure Upload, PR-3: the persistent, node-local
// upload queue + state machine.
//
// A bundle the operator has CONSENTED to upload (the consent gate is PR-5) is
// enqueued here; a background worker (also PR-5) drains it through the PR-2
// client. This slice ships the queue ENGINE only — persistence, the state
// machine, retry/backoff, and the capacity bound — and wires NO background loop;
// it is invoked by nothing, so it adds no egress path (TestNoAutoUpload stays
// green).
//
// Cloud-independence (SECURE-UPLOAD-ARCHITECTURE.md §5): the appliance degrades
// to "queued + offline-export available", never a stall. An unreachable cloud
// leaves entries queued; transient failures retry with bounded backoff; once the
// attempt cap is hit the entry is DEFERRED for the operator to re-arm or export
// offline; a gateway rejection (entitlement/format/hash) is terminal. The queue
// entries are tiny (the bundle bytes stay under bundles/<id>/), and no queue
// operation blocks the proxy hot path.

type uploadState string

const (
	uploadStateQueued    uploadState = "queued"    // awaiting an outbound attempt
	uploadStateUploading uploadState = "uploading" // an attempt is in flight
	uploadStateUploaded  uploadState = "uploaded"  // receipt received + hash matched
	uploadStateDeferred  uploadState = "deferred"  // retries exhausted; operator re-arms / offline-exports
	uploadStateRejected  uploadState = "rejected"  // gateway refused (entitlement/format/hash) — no retry
)

const (
	maxUploadAttempts = 6                // transient-failure attempts before DEFERRED
	uploadRetryBase   = 2 * time.Second  // first backoff; doubles each attempt
	uploadRetryCap    = 10 * time.Minute // backoff ceiling
	maxUploadErrLen   = 256
)

// maxUploadQueue bounds the number of distinct non-terminal (queued/uploading/
// deferred) bundles. maxUploadTerminal bounds retained TERMINAL (uploaded/
// rejected) records so completed uploads cannot accumulate on disk without limit
// (cross-milestone invariant #4: every persisted state under <dataDir>/support
// is bounded). Both vars so tests can exercise the caps cheaply; never mutated in
// production. Each entry is ~a few hundred bytes, so the two caps together bound
// the queue's on-disk footprint to well under a megabyte — the retention cap IS
// the disk-safety mechanism here (a heavyweight free-space preflight for a
// sub-KB write would be disproportionate).
var (
	maxUploadQueue    = 256
	maxUploadTerminal = 256
)

// uploadQueueEntry is one bundle's upload lifecycle record. Node-local and tiny:
// only the state rides here; the (encrypted) bundle bytes stay under bundles/<id>/.
type uploadQueueEntry struct {
	BundleID     string                 `json:"bundle_id"`
	CaseID       string                 `json:"case_id"`
	KeyID        string                 `json:"key_id,omitempty"`
	BundleSHA256 string                 `json:"bundle_sha256,omitempty"`
	State        uploadState            `json:"state"`
	Attempts     int                    `json:"attempts"`
	NextRetryAt  int64                  `json:"next_retry_at,omitempty"` // unix seconds; a queued entry is due when now >= this
	UploadID     string                 `json:"upload_id,omitempty"`     // gateway session id, persisted for cross-restart resume
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
	LastError    string                 `json:"last_error,omitempty"` // bounded + sanitized
	Receipt      *supportupload.Receipt `json:"receipt,omitempty"`    // set on uploaded
}

// errUploadQueueFull is returned when a new enqueue (or a rejected→queued re-arm)
// would push the non-terminal queue past maxUploadQueue.
var errUploadQueueFull = errors.New("upload queue is full")

var uploadQueueMu sync.Mutex

// pendingUploadCountLocked counts the non-terminal (queued/uploading/deferred)
// entries — the population maxUploadQueue bounds. Caller holds uploadQueueMu.
func pendingUploadCountLocked() int {
	pending := 0
	entries := listUploadQueueLocked()
	for i := range entries {
		switch entries[i].State {
		case uploadStateQueued, uploadStateUploading, uploadStateDeferred:
			pending++
		}
	}
	return pending
}

func uploadQueueDir() string { return filepath.Join(dataDir, "support", "upload_queue") }

func uploadQueuePath(bundleID string) string {
	return filepath.Join(uploadQueueDir(), bundleID+".json")
}

// saveUploadQueueEntryLocked atomically persists one entry at 0600. Caller holds
// uploadQueueMu. The bundle id is validated against supportBundleIDRe so the
// filename can never traverse.
func saveUploadQueueEntryLocked(e uploadQueueEntry) error {
	if !supportBundleIDRe.MatchString(e.BundleID) {
		return errors.New("invalid bundle id")
	}
	if err := os.MkdirAll(uploadQueueDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	tmp := uploadQueuePath(e.BundleID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, uploadQueuePath(e.BundleID))
}

// loadUploadQueueEntryLocked reads one entry. Absent/corrupt ⇒ (zero, false).
// Caller holds uploadQueueMu.
func loadUploadQueueEntryLocked(bundleID string) (uploadQueueEntry, bool) {
	if !supportBundleIDRe.MatchString(bundleID) {
		return uploadQueueEntry{}, false
	}
	b, err := os.ReadFile(uploadQueuePath(bundleID))
	if err != nil {
		return uploadQueueEntry{}, false
	}
	var e uploadQueueEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return uploadQueueEntry{}, false
	}
	// The filename (validated above) is the authority: reject an entry whose
	// persisted BundleID disagrees with the file it came from. A hand-edited or
	// corrupted-but-valid-JSON record could otherwise carry a BundleID pointing at
	// a DIFFERENT file, and terminal pruning (os.Remove(uploadQueuePath(BundleID)))
	// would then delete the wrong path instead of skipping the bad record.
	if e.BundleID != bundleID {
		return uploadQueueEntry{}, false
	}
	return e, true
}

// listUploadQueueLocked returns every persisted entry, oldest-first. A corrupt
// file is skipped (fail-open on read: one bad entry never hides the rest).
// Caller holds uploadQueueMu.
func listUploadQueueLocked() []uploadQueueEntry {
	des, err := os.ReadDir(uploadQueueDir())
	if err != nil {
		return nil
	}
	var out []uploadQueueEntry
	for _, de := range des {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if e, ok := loadUploadQueueEntryLocked(strings.TrimSuffix(name, ".json")); ok {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// listUploadQueue returns every persisted entry (oldest-first) for the status/UI.
func listUploadQueue() []uploadQueueEntry {
	uploadQueueMu.Lock()
	defer uploadQueueMu.Unlock()
	return listUploadQueueLocked()
}

// saveUploadQueueEntry persists one entry (the worker calls this after a drain).
func saveUploadQueueEntry(e uploadQueueEntry) error {
	uploadQueueMu.Lock()
	defer uploadQueueMu.Unlock()
	return saveUploadQueueEntryLocked(e)
}

// enqueueUpload records a consented bundle for upload. Idempotent: a re-enqueue
// of an already delivered (uploaded) or pending (queued/uploading) bundle is a
// no-op; a re-enqueue of a DEFERRED/REJECTED bundle re-arms it to queued with a
// fresh attempt budget (the operator "retry" action). Bounded by maxUploadQueue
// over non-terminal entries.
func enqueueUpload(bundleID, caseID, keyID, sha256 string, now time.Time) (uploadQueueEntry, error) {
	uploadQueueMu.Lock()
	defer uploadQueueMu.Unlock()
	if !supportBundleIDRe.MatchString(bundleID) {
		return uploadQueueEntry{}, errors.New("invalid bundle id")
	}
	nowStr := now.UTC().Format(time.RFC3339)
	rearm := func(e uploadQueueEntry) (uploadQueueEntry, error) {
		e.State = uploadStateQueued
		e.Attempts = 0
		e.NextRetryAt = 0
		e.LastError = ""
		e.UpdatedAt = nowStr
		return e, saveUploadQueueEntryLocked(e)
	}
	if existing, ok := loadUploadQueueEntryLocked(bundleID); ok {
		switch existing.State {
		case uploadStateUploaded, uploadStateQueued, uploadStateUploading:
			return existing, nil // already delivered or pending — no-op
		case uploadStateDeferred:
			return rearm(existing) // already counted as pending — consumes no new capacity
		default: // rejected (terminal) → re-arm moves it back into a live state, so it
			// must respect the same capacity bound a fresh enqueue does; without this
			// check, repeated operator retries of rejected records could push the
			// non-terminal queue past maxUploadQueue.
			if pendingUploadCountLocked() >= maxUploadQueue {
				return uploadQueueEntry{}, errUploadQueueFull
			}
			return rearm(existing)
		}
	}
	if pendingUploadCountLocked() >= maxUploadQueue {
		return uploadQueueEntry{}, errUploadQueueFull
	}
	e := uploadQueueEntry{
		BundleID: bundleID, CaseID: caseID, KeyID: keyID, BundleSHA256: sha256,
		State: uploadStateQueued, CreatedAt: nowStr, UpdatedAt: nowStr,
	}
	if err := saveUploadQueueEntryLocked(e); err != nil {
		return uploadQueueEntry{}, err
	}
	pruneTerminalUploadEntriesLocked()
	return e, nil
}

// pruneTerminalUploadEntriesLocked evicts the oldest TERMINAL (uploaded/rejected)
// records beyond maxUploadTerminal so completed uploads cannot grow unbounded.
// Non-terminal entries (queued/uploading/deferred) are always kept — they are
// live or operator-actionable. Caller holds uploadQueueMu.
func pruneTerminalUploadEntriesLocked() {
	var terminal []uploadQueueEntry
	all := listUploadQueueLocked() // already oldest-first by CreatedAt
	for i := range all {
		if all[i].State == uploadStateUploaded || all[i].State == uploadStateRejected {
			terminal = append(terminal, all[i])
		}
	}
	if len(terminal) <= maxUploadTerminal {
		return
	}
	evict := terminal[:len(terminal)-maxUploadTerminal]
	for i := range evict {
		_ = os.Remove(uploadQueuePath(evict[i].BundleID)) //nolint:errcheck // best-effort eviction
	}
}

// uploadFunc performs the actual transfer for an entry and returns the receipt
// plus the gateway upload session id. It is injected so the queue engine is
// testable without a live client; PR-5 wires the real implementation
// (encrypt-to-TAC → PR-2 client). It MUST NOT be called while holding
// uploadQueueMu (it does network I/O).
//
// The uploadID return carries the gateway session id even when err != nil: an
// attempt that reaches init (obtaining a fresh upload_id) and THEN hits a
// transient error must be able to hand that id back, so the persisted entry
// records it and the next attempt — including one after a restart — can resume
// from the received offset instead of re-initing. A blank uploadID leaves the
// entry's existing UploadID untouched.
type uploadFunc func(ctx context.Context, e uploadQueueEntry) (rec *supportupload.Receipt, uploadID string, err error)

// drainUploadEntry runs ONE attempt for an entry and returns the updated entry
// (the caller persists it via saveUploadQueueEntry). It does NOT take the queue
// mutex — the injected upload does network I/O and must not block other queue
// operations. Classification:
//   - success → uploaded (+ receipt)
//   - GatewayError 4xx (entitlement/format/hash) → rejected (terminal; no retry)
//   - any other error → attempts++, then re-queued with a backoff NextRetryAt,
//     or DEFERRED once the attempt cap is reached.
func drainUploadEntry(ctx context.Context, e uploadQueueEntry, upload uploadFunc, now time.Time) uploadQueueEntry {
	nowStr := now.UTC().Format(time.RFC3339)
	e.State = uploadStateUploading
	e.UpdatedAt = nowStr

	rec, uploadID, err := upload(ctx, e)
	if uploadID != "" {
		// Capture the gateway session id on EVERY path (success or transient
		// failure) so a drop after init persists the resume point.
		e.UploadID = uploadID
	}
	if err == nil {
		e.State = uploadStateUploaded
		e.Receipt = rec
		e.NextRetryAt = 0
		e.LastError = ""
		e.UpdatedAt = nowStr
		return e
	}

	e.Attempts++
	e.LastError = boundUploadErr(err.Error())
	e.UpdatedAt = nowStr

	var ge *supportupload.GatewayError
	if errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500 {
		e.State = uploadStateRejected // terminal: the gateway refused it
		e.NextRetryAt = 0
		return e
	}
	if e.Attempts >= maxUploadAttempts {
		e.State = uploadStateDeferred // retries exhausted; operator re-arms / offline-exports
		e.NextRetryAt = 0
		return e
	}
	e.State = uploadStateQueued
	e.NextRetryAt = now.Add(uploadRetryBackoff(e.Attempts)).Unix()
	return e
}

// uploadRetryBackoff is the deterministic exponential backoff (2s, 4s, 8s, …)
// capped at uploadRetryCap. Deterministic (no jitter): the queue is per-node and
// serial, so there is no thundering-herd to smooth, and determinism keeps the
// backoff test exact.
func uploadRetryBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 20 { // guard the shift against overflow
		return uploadRetryCap
	}
	d := uploadRetryBase << (attempts - 1)
	if d <= 0 || d > uploadRetryCap {
		return uploadRetryCap
	}
	return d
}

// dueUploadEntries returns queued entries whose backoff has elapsed (the worker's
// work-list). uploading/deferred/rejected/uploaded are never due.
func dueUploadEntries(now time.Time) []uploadQueueEntry {
	uploadQueueMu.Lock()
	defer uploadQueueMu.Unlock()
	var due []uploadQueueEntry
	entries := listUploadQueueLocked()
	for i := range entries {
		if entries[i].State == uploadStateQueued && entries[i].NextRetryAt <= now.Unix() {
			due = append(due, entries[i])
		}
	}
	return due
}

// boundUploadErr sanitizes (CWE-117) and length-bounds an error string before it
// is persisted into an entry's LastError.
func boundUploadErr(s string) string {
	s = sanitizeLog(s)
	if len(s) > maxUploadErrLen {
		return s[:maxUploadErrLen] + "…"
	}
	return s
}
