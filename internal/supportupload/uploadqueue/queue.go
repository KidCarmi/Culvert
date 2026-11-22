package uploadqueue

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

// State is one bundle's position in the upload lifecycle. The five values are
// persisted in every entry and returned by the admin API, so they are wire
// vocabulary.
type State string

// The states an entry is persisted in.
const (
	StateQueued    State = "queued"    // awaiting an outbound attempt
	StateUploading State = "uploading" // an attempt is in flight
	StateUploaded  State = "uploaded"  // receipt received + hash matched
	StateDeferred  State = "deferred"  // retries exhausted; operator re-arms / offline-exports
	StateRejected  State = "rejected"  // gateway refused (entitlement/format/hash) — no retry
)

const (
	retryBase = 2 * time.Second  // first backoff; doubles each attempt
	retryCap  = 10 * time.Minute // backoff ceiling
)

// Entry is one bundle's upload lifecycle record. Node-local and tiny: only the
// state rides here; the (encrypted) bundle bytes stay under bundles/<id>/.
type Entry struct {
	BundleID     string                 `json:"bundle_id"`
	CaseID       string                 `json:"case_id"`
	KeyID        string                 `json:"key_id,omitempty"`
	BundleSHA256 string                 `json:"bundle_sha256,omitempty"`
	State        State                  `json:"state"`
	Attempts     int                    `json:"attempts"`
	NextRetryAt  int64                  `json:"next_retry_at,omitempty"` // unix seconds; a queued entry is due when now >= this
	UploadID     string                 `json:"upload_id,omitempty"`     // gateway session id, persisted for cross-restart resume
	CreatedAt    string                 `json:"created_at"`
	UpdatedAt    string                 `json:"updated_at"`
	LastError    string                 `json:"last_error,omitempty"` // bounded + sanitized
	Receipt      *supportupload.Receipt `json:"receipt,omitempty"`    // set on uploaded
}

// Options is everything a Queue is given. It has no defaults: a missing
// function or a zero bound makes the affected operation refuse (see New).
type Options struct {
	// Dir answers the queue directory. It is asked on every operation, so the
	// owner may move the data directory between calls.
	Dir func() string
	// ValidID decides which bundle ids may name a file. It is the only thing
	// between a caller-supplied id and a path, so it must refuse separators,
	// dots and traversal elements.
	ValidID func(id string) bool
	// Mkdir creates the queue directory durably; Write commits one entry
	// durably at the owner's mode. Both belong to the owner's durable-write
	// chokepoint, which also reports failures to storage health.
	Mkdir func(dir string, perm os.FileMode) error
	Write func(path string, data []byte) error
	// Sanitize scrubs an error text before it is persisted (CWE-117).
	Sanitize func(string) string

	// MaxPending bounds the non-terminal (queued/uploading/deferred) entries.
	// MaxTerminal bounds the retained terminal (uploaded/rejected) records, so
	// completed uploads cannot accumulate on disk without limit. Each entry is
	// a few hundred bytes, so the two together are the disk-safety mechanism.
	MaxPending  int
	MaxTerminal int
	// MaxAttempts is the number of transient failures before an entry is
	// deferred. MaxErrLen bounds the persisted error text, in bytes.
	MaxAttempts int
	MaxErrLen   int
}

// Queue is the persistent, node-local upload queue of one data directory: one
// file per bundle, read back on every call, and one mutex over the files.
//
// Cloud-independence (SECURE-UPLOAD-ARCHITECTURE.md §5): the appliance degrades
// to "queued + offline-export available", never a stall. An unreachable cloud
// leaves entries queued; transient failures retry with bounded backoff; once the
// attempt cap is hit the entry is DEFERRED for the operator to re-arm or export
// offline; a gateway rejection (entitlement/format/hash) is terminal. The queue
// entries are tiny (the bundle bytes stay under bundles/<id>/), and no queue
// operation blocks the proxy hot path.
//
// A Queue starts no goroutine and holds no file open. Its mutex is never held
// across Attempt, which does the owner's network I/O.
type Queue struct {
	o  Options
	mu sync.Mutex
}

// errFull is returned when a new enqueue (or a rejected→queued re-arm) would
// push the non-terminal queue past MaxPending.
var errFull = errors.New("upload queue is full")

var (
	errInvalidID = errors.New("invalid bundle id")
	errNotWired  = errors.New("upload queue has no durable writer")
)

// New returns a Queue over o. Nothing is defaulted, and every gap fails
// closed: with no Dir or no ValidID every id is invalid and the queue lists
// nothing; with no Mkdir or no Write nothing is saved; with no Sanitize the
// error text is withheld, not stored raw; a zero MaxPending refuses every
// enqueue and a zero MaxAttempts defers on the first failure.
func New(o Options) *Queue { return &Queue{o: o} }

func (q *Queue) validID(id string) bool {
	return q.o.Dir != nil && q.o.ValidID != nil && q.o.ValidID(id)
}

// Path is the file one bundle's entry is kept in. It does not validate id.
func (q *Queue) Path(bundleID string) string {
	dir := ""
	if q.o.Dir != nil {
		dir = q.o.Dir()
	}
	return filepath.Join(dir, bundleID+".json")
}

// pendingCountLocked counts the non-terminal (queued/uploading/deferred)
// entries — the population MaxPending bounds. Caller holds q.mu.
func (q *Queue) pendingCountLocked() int {
	pending := 0
	entries := q.listLocked()
	for i := range entries {
		switch entries[i].State {
		case StateQueued, StateUploading, StateDeferred:
			pending++
		}
	}
	return pending
}

// saveLocked durably persists one entry through the owner's chokepoint. Caller
// holds q.mu. The bundle id is validated so the filename can never traverse.
func (q *Queue) saveLocked(e Entry) error {
	if !q.validID(e.BundleID) {
		return errInvalidID
	}
	if q.o.Mkdir == nil || q.o.Write == nil {
		return errNotWired
	}
	if err := q.o.Mkdir(q.o.Dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return q.o.Write(q.Path(e.BundleID), b)
}

// loadLocked reads one entry. Absent/corrupt ⇒ (zero, false). Caller holds q.mu.
func (q *Queue) loadLocked(bundleID string) (Entry, bool) {
	if !q.validID(bundleID) {
		return Entry{}, false
	}
	b, err := os.ReadFile(q.Path(bundleID))
	if err != nil {
		return Entry{}, false
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return Entry{}, false
	}
	// The filename (validated above) is the authority: reject an entry whose
	// persisted BundleID disagrees with the file it came from. A hand-edited or
	// corrupted-but-valid-JSON record could otherwise carry a BundleID pointing at
	// a DIFFERENT file, and terminal pruning (os.Remove(q.Path(BundleID)))
	// would then delete the wrong path instead of skipping the bad record.
	if e.BundleID != bundleID {
		return Entry{}, false
	}
	return e, true
}

// listLocked returns every persisted entry, oldest-first. A corrupt file is
// skipped (fail-open on read: one bad entry never hides the rest). Caller
// holds q.mu.
func (q *Queue) listLocked() []Entry {
	if q.o.Dir == nil {
		return nil
	}
	des, err := os.ReadDir(q.o.Dir())
	if err != nil {
		return nil
	}
	var out []Entry
	for _, de := range des {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if e, ok := q.loadLocked(strings.TrimSuffix(name, ".json")); ok {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt < out[j].CreatedAt })
	return out
}

// List returns every persisted entry (oldest-first) for the status/UI.
func (q *Queue) List() []Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.listLocked()
}

// Save persists one entry (the worker calls this after an Attempt).
func (q *Queue) Save(e Entry) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.saveLocked(e)
}

// Load returns one bundle's upload record for the status/receipt surface.
// Absent/corrupt ⇒ (zero, false).
func (q *Queue) Load(bundleID string) (Entry, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.loadLocked(bundleID)
}

// Enqueue records a consented bundle for upload. Idempotent: a re-enqueue of
// an already delivered (uploaded) or pending (queued/uploading) bundle is a
// no-op; a re-enqueue of a DEFERRED/REJECTED bundle re-arms it to queued with a
// fresh attempt budget (the operator "retry" action). Bounded by MaxPending
// over non-terminal entries.
func (q *Queue) Enqueue(bundleID, caseID, keyID, sha256 string, now time.Time) (Entry, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.validID(bundleID) {
		return Entry{}, errInvalidID
	}
	nowStr := now.UTC().Format(time.RFC3339)
	rearm := func(e Entry) (Entry, error) {
		// A re-arm follows a FRESH re-seal (the consent path writes a new,
		// nondeterministic upload.csb.sealed and passes its new hash/key), so adopt
		// that metadata and drop any prior session/receipt — the old UploadID points
		// at bytes that no longer exist on disk, and resuming it would verify the new
		// blob against the stale hash and be rejected. Fresh blob ⇒ fresh session.
		e.State = StateQueued
		e.Attempts = 0
		e.NextRetryAt = 0
		e.LastError = ""
		e.CaseID = caseID
		e.KeyID = keyID
		e.BundleSHA256 = sha256
		e.UploadID = ""
		e.Receipt = nil
		e.UpdatedAt = nowStr
		return e, q.saveLocked(e)
	}
	if existing, ok := q.loadLocked(bundleID); ok {
		switch existing.State {
		case StateUploaded, StateQueued, StateUploading:
			return existing, nil // already delivered or pending — no-op
		case StateDeferred:
			return rearm(existing) // already counted as pending — consumes no new capacity
		default: // rejected (terminal) → re-arm moves it back into a live state, so it
			// must respect the same capacity bound a fresh enqueue does; without this
			// check, repeated operator retries of rejected records could push the
			// non-terminal queue past MaxPending.
			if q.pendingCountLocked() >= q.o.MaxPending {
				return Entry{}, errFull
			}
			return rearm(existing)
		}
	}
	if q.pendingCountLocked() >= q.o.MaxPending {
		return Entry{}, errFull
	}
	e := Entry{
		BundleID: bundleID, CaseID: caseID, KeyID: keyID, BundleSHA256: sha256,
		State: StateQueued, CreatedAt: nowStr, UpdatedAt: nowStr,
	}
	if err := q.saveLocked(e); err != nil {
		return Entry{}, err
	}
	q.pruneTerminalLocked()
	return e, nil
}

// pruneTerminalLocked evicts the oldest TERMINAL (uploaded/rejected) records
// beyond MaxTerminal so completed uploads cannot grow unbounded. Non-terminal
// entries (queued/uploading/deferred) are always kept — they are live or
// operator-actionable. Caller holds q.mu.
func (q *Queue) pruneTerminalLocked() {
	var terminal []Entry
	all := q.listLocked() // already oldest-first by CreatedAt
	for i := range all {
		if all[i].State == StateUploaded || all[i].State == StateRejected {
			terminal = append(terminal, all[i])
		}
	}
	if len(terminal) <= q.o.MaxTerminal {
		return
	}
	evict := terminal[:len(terminal)-q.o.MaxTerminal]
	for i := range evict {
		_ = os.Remove(q.Path(evict[i].BundleID)) //nolint:errcheck // best-effort eviction
	}
}

// Attempt runs ONE attempt for an entry and returns the updated entry (the
// caller persists it via Save). It does NOT take the queue mutex — the injected
// upload does network I/O and must not block other queue operations.
// Classification:
//   - success → uploaded (+ receipt)
//   - GatewayError 4xx (entitlement/format/hash) → rejected (terminal; no retry)
//   - any other error → attempts++, then re-queued with a backoff NextRetryAt,
//     or DEFERRED once the attempt cap is reached.
//
// upload performs the actual transfer and returns the receipt plus the gateway
// upload session id. The uploadID return carries the gateway session id even
// when err != nil: an attempt that reaches init (obtaining a fresh upload_id)
// and THEN hits a transient error must be able to hand that id back, so the
// persisted entry records it and the next attempt — including one after a
// restart — can resume from the received offset instead of re-initing. A blank
// uploadID leaves the entry's existing UploadID untouched.
func (q *Queue) Attempt(
	ctx context.Context, e Entry,
	upload func(ctx context.Context, e Entry) (rec *supportupload.Receipt, uploadID string, err error),
	now time.Time,
) Entry {
	nowStr := now.UTC().Format(time.RFC3339)
	e.State = StateUploading
	e.UpdatedAt = nowStr

	rec, uploadID, err := upload(ctx, e)
	if uploadID != "" {
		// Capture the gateway session id on EVERY path (success or transient
		// failure) so a drop after init persists the resume point.
		e.UploadID = uploadID
	}
	if err == nil {
		e.State = StateUploaded
		e.Receipt = rec
		e.NextRetryAt = 0
		e.LastError = ""
		e.UpdatedAt = nowStr
		return e
	}

	e.Attempts++
	e.LastError = q.BoundErr(err.Error())
	e.UpdatedAt = nowStr

	var ge *supportupload.GatewayError
	if errors.As(err, &ge) && ge.Status >= 400 && ge.Status < 500 {
		e.State = StateRejected // terminal: the gateway refused it
		e.NextRetryAt = 0
		return e
	}
	if e.Attempts >= q.o.MaxAttempts {
		e.State = StateDeferred // retries exhausted; operator re-arms / offline-exports
		e.NextRetryAt = 0
		return e
	}
	e.State = StateQueued
	e.NextRetryAt = now.Add(retryBackoff(e.Attempts)).Unix()
	return e
}

// retryBackoff is the deterministic exponential backoff (2s, 4s, 8s, …)
// capped at retryCap. Deterministic (no jitter): the queue is per-node and
// serial, so there is no thundering-herd to smooth, and determinism keeps the
// backoff test exact.
func retryBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > 20 { // guard the shift against overflow
		return retryCap
	}
	d := retryBase << (attempts - 1)
	if d <= 0 || d > retryCap {
		return retryCap
	}
	return d
}

// Due returns queued entries whose backoff has elapsed (the worker's
// work-list). uploading/deferred/rejected/uploaded are never due.
func (q *Queue) Due(now time.Time) []Entry {
	q.mu.Lock()
	defer q.mu.Unlock()
	var due []Entry
	entries := q.listLocked()
	for i := range entries {
		if entries[i].State == StateQueued && entries[i].NextRetryAt <= now.Unix() {
			due = append(due, entries[i])
		}
	}
	return due
}

// errTextWithheld stands in for an error text when the owner supplied no
// sanitizer: an unscrubbed remote string is never written to disk.
const errTextWithheld = "error text withheld: no sanitizer"

// BoundErr sanitizes (CWE-117) and length-bounds an error string before it is
// persisted into an entry's LastError.
func (q *Queue) BoundErr(s string) string {
	if q.o.Sanitize == nil {
		return errTextWithheld
	}
	s = q.o.Sanitize(s)
	if len(s) > q.o.MaxErrLen {
		return s[:q.o.MaxErrLen] + "…"
	}
	return s
}
