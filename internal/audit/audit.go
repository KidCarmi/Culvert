// Package audit is the admin-action audit trail engine: a bounded in-memory
// ring (the newest MaxRing entries), optional append-only JSONL persistence
// with rotation, paginated/time-filtered reads over both, and the Data-Plane
// → Control-Plane push queue. Extracted from package main's store.go per
// ADR-0002 (store.go decomposition Phase B).
//
// package main keeps the surfaces: the auditEvent/auditEventDiff request
// wrappers (actor enrichment from the session cookie), the C2c
// audit-completion middleware (which observes the wrappers, not this
// engine), the API handlers, and the CP push loop (which drains/requeues
// through this package). Two inversion points: the SIEM hook (main wires a
// closure over its syslog singleton — the forwarder is runtime-configured,
// so the closure reads it at call time) and the DP-mode flag (set by main's
// cluster wiring; when on, Add also queues for CP push).
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// Entry captures every configuration change made through the UI/API so
// operators can answer "Who changed What, and When?" — a core SOC
// requirement. Actor is the client IP of the UI caller, enriched with the
// authenticated admin identity when available. Action follows a
// "resource.verb" naming scheme (e.g. "policy.add").
type Entry struct {
	TS       int64  `json:"ts"`                 // Unix milliseconds
	Time     string `json:"time"`               // human-readable "2006-01-02 15:04:05"
	Actor    string `json:"actor"`              // client IP (or authenticated username)
	Action   string `json:"action"`             // "policy.add" | "blocklist.remove" | …
	Object   string `json:"object"`             // the specific item that changed (human-readable name)
	ObjectID string `json:"objectId,omitempty"` // stable ULID of the changed item, when it has one — survives rename, so an object's audit trail is correlatable by ID (§1 identity seam)
	Detail   string `json:"detail"`             // extra context (never contains credentials)
	Before   string `json:"before,omitempty"`   // JSON snapshot before the change
	After    string `json:"after,omitempty"`    // JSON snapshot after the change
}

// MaxRing bounds the in-memory ring. Tests MUST NOT assert on len() deltas
// of Get() — under cumulative suites the ring saturates and adding an entry
// evicts the oldest (see the CLAUDE.md test-authoring pitfall).
const MaxRing = 500

var (
	mu          sync.Mutex
	ring        []Entry
	persist     io.Writer // JSONL file; nil = in-memory only
	persistC    io.Closer // closed on shutdown via Close
	persistPath string    // path for paginated reads
)

// ─── Durable-write health (CHAOS-24 / register item ST-8) ────────────────────
//
// The JSONL file is the DURABLE compliance record — the in-memory ring holds
// only the newest MaxRing entries and is wiped on every restart. Until this
// counter existed, Add discarded the write error outright, so a full disk, a
// read-only remount, an EIO, or a failed post-rotation reopen destroyed the
// "who changed what" trail with NO counter, NO metric, NO alert and NO log
// line, while the admin UI kept rendering entries from the volatile ring. An
// attacker who can fill the volume could therefore switch off durable audit
// logging and then act with the record surviving only in a 500-entry buffer
// they can evict by generating further events (CWE-778, OWASP A09:2021).
//
// The contract mirrors internal/reqlog exactly: count EVERY failure, log only
// the FIRST (a failing disk fails every write, and this runs on the admin-API
// goroutine). Persistence stays best-effort — a failing disk must not make the
// admin API reject configuration changes — but it is no longer silent.
var (
	writeErrors    int64       // entries that never reached the JSONL file
	writeErrLogged atomic.Bool // one-shot gate for the log line

	// needsBoundaryRepair records that the last write left a LINE FRAGMENT on
	// disk (bytes accepted, record incomplete). See persistEntry.
	needsBoundaryRepair atomic.Bool
)

// writeFailObserver is the durable-write failure seam. package main publishes
// the process-wide storage-health observer here (storage_health.go), which
// owns the rate-limited log line, the degraded operator-contract row, the
// Prometheus series and the `storage_write_failed` alert.
//
// CONTRACT: the observer runs SYNCHRONOUSLY on the goroutine whose audit write
// just failed and MUST NOT call Add (directly or transitively). Re-entering Add
// from the observer would recurse without bound on a persistently failing disk
// — every recovery write failing and re-invoking the observer. The production
// observer (noteStorageWriteFailure) writes no audit entry; it only records
// counters and dispatches a webhook alert, which is audit-free by construction.
var writeFailObserver atomic.Pointer[func(path string, err error)]

// SetWriteFailureObserver publishes the durable-write failure observer. A nil
// fn clears it (the counter and the one-shot log line still apply), so a
// mis-wired or un-wired startup can never silence the loss entirely.
func SetWriteFailureObserver(fn func(path string, err error)) {
	if fn == nil {
		writeFailObserver.Store(nil)
		return
	}
	writeFailObserver.Store(&fn)
}

// writeSuccessObserver is the durable-write SUCCESS seam, and it is not
// optional bookkeeping: the storage-health plane clears its degraded state only
// on an OBSERVED successful write ("silence is not recovery"). A failure
// producer without a matching success producer therefore pins the node
// degraded forever after one transient blip — reproducible on a node whose only
// durable writes are audit entries (an audited diagnostic or download action
// performs no fileutil.AtomicWrite of its own). package main wires
// noteStorageWriteSuccess here, which short-circuits on a single atomic load
// until the first failure, so the healthy path stays cheap.
var writeSuccessObserver atomic.Pointer[func(path string)]

// SetWriteSuccessObserver publishes the durable-write success observer. A nil
// fn clears it. Same re-entrancy contract as SetWriteFailureObserver: the
// observer MUST NOT call Add.
func SetWriteSuccessObserver(fn func(path string)) {
	if fn == nil {
		writeSuccessObserver.Store(nil)
		return
	}
	writeSuccessObserver.Store(&fn)
}

// noteWriteSuccess reports a fully-written record. Contained like the failure
// path: a panicking observer must not take down the admin plane.
func noteWriteSuccess(path string) {
	if p := writeSuccessObserver.Load(); p != nil {
		defer func() { _ = recover() }()
		(*p)(path)
	}
}

// WriteErrors returns the cumulative count of audit entries that did NOT reach
// the persistent JSONL file (process lifetime; never reset). Non-zero means the
// durable audit trail is incomplete — surfaced on GET /api/stats, /healthz and
// /metrics so the gap is never silent.
func WriteErrors() int64 { return atomic.LoadInt64(&writeErrors) }

// countWriteError charges ONE lost entry, logs the first failure only, and
// notifies the observer. Never panics on a panicking observer: audit loss must
// not take down the admin plane it is recording.
//
// Unlike internal/reqlog's batched equivalent, this always charges exactly one:
// audit persistence is per-entry and unbuffered, so there is no batch to lose.
func countWriteError(path string, err error) {
	atomic.AddInt64(&writeErrors, 1)
	if writeErrLogged.CompareAndSwap(false, true) {
		// CWE-117: the error text embeds the operator-configured path and, for
		// a wrapped syscall error, arbitrary OS-supplied bytes. Sanitise it
		// before it reaches the log line, per the project logging convention.
		detail := ""
		if err != nil {
			detail = obs.Sanitize(err.Error())
		}
		obs.Printf("ERROR audit log: persistent write failed — the durable audit trail is incomplete (further failures counted silently): %q", detail)
	}
	if p := writeFailObserver.Load(); p != nil {
		func() {
			defer func() { _ = recover() }()
			(*p)(path, err)
		}()
	}
}

// siem is the SIEM-forwarding hook (nil = disabled). Set once at main's init;
// the closure is responsible for its own nil/runtime checks.
var siem func(Entry)

// SetSIEM installs the SIEM forwarding hook called after every Add.
func SetSIEM(fn func(Entry)) { siem = fn }

// dpMode reports whether this node runs as a cluster Data Plane; when true,
// Add also queues each entry for the CP push loop.
var dpMode atomic.Bool

// SetDPMode marks this node as a Data Plane (enables CP push queuing).
func SetDPMode(on bool) { dpMode.Store(on) }

// DPMode reports whether DP-mode queuing is active.
func DPMode() bool { return dpMode.Load() }

// Init opens path for append-only JSONL persistence with rotation.
// Existing entries are loaded into the in-memory ring on startup.
// If path is empty this is a no-op (backwards-compatible).
// F18: Rotates at 50 MB (same as the system log) to prevent unbounded disk
// growth.
func Init(path string) error {
	if path == "" {
		return nil
	}
	// Load existing entries first.
	if data, err := os.ReadFile(path); err == nil { // #nosec G304 -- operator-configured path
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var e Entry
			if json.Unmarshal([]byte(line), &e) == nil {
				ring = append(ring, e)
			}
		}
		if len(ring) > MaxRing {
			ring = ring[len(ring)-MaxRing:]
		}
	}
	rf, err := fileutil.NewRotatingFile(path, 50) // 50 MB max before rotation
	if err != nil {
		return fmt.Errorf("audit log open %s: %w", path, err)
	}
	persist = rf
	persistC = rf
	persistPath = path
	return nil
}

// Close releases the persistent file handle (best-effort; shutdown hook).
// Safe when persistence was never initialised.
func Close() error {
	if persistC == nil {
		return nil
	}
	err := persistC.Close()
	return err
}

// persistEntry writes one JSONL record to the durable sink, keeping the file's
// line boundary intact and charging every entry that does not reach it.
//
// The boundary is the subtle part. A PARTIAL write — the sink accepted some
// bytes and then failed, or returned a short count — leaves a fragment with no
// terminating newline. Appending the next record straight onto it produces a
// single unparseable line, so GetPersistent (and the startup ring load) skip it
// and BOTH entries are lost while only the first was ever counted: the very
// under-reporting this counter exists to prevent. So a pending fragment is
// closed with a leading newline before the next record, which leaves the
// fragment standing alone as its own already-charged invalid line and lets the
// new record land intact. Blank lines are skipped by every reader, so the
// repair is harmless when it turns out not to have been needed.
func persistEntry(f io.Writer, path string, e Entry) {
	b, err := json.Marshal(e)
	if err != nil {
		// Defensive: Entry is all scalars today, so this cannot fail in
		// practice. It was nevertheless a silent-drop branch — the entry never
		// reaches the file — so it is charged like any other loss.
		countWriteError(path, fmt.Errorf("marshal audit entry: %w", err))
		return
	}
	b = append(b, '\n')
	// Only one concurrent Add wins the CAS, so the repair newline is written
	// once. Audit writes come from the admin plane, where concurrency is low.
	repaired := needsBoundaryRepair.CompareAndSwap(true, false)
	if repaired {
		b = append([]byte{'\n'}, b...)
	}

	n, werr := f.Write(b)

	// Re-derive the pending-fragment state from what actually reached the file,
	// rather than assuming the repair succeeded: a write that moved zero bytes
	// left the on-disk boundary exactly as it was, so a repair we consumed must
	// be handed back or the fragment would never be closed.
	switch {
	case n == 0:
		if repaired {
			needsBoundaryRepair.Store(true)
		}
	case n < len(b):
		needsBoundaryRepair.Store(true)
	}

	// A short write with a NIL error is a real loss too. os.File.Write reports
	// it as io.ErrShortWrite, but the sink is an io.Writer seam, so check the
	// count explicitly rather than trusting every implementation to do so.
	switch {
	case werr != nil:
		countWriteError(path, werr)
	case n < len(b):
		countWriteError(path, io.ErrShortWrite)
	default:
		noteWriteSuccess(path)
	}
}

// Add appends an entry to the in-memory ring and, when configured, to the
// persistent JSONL file, the SIEM hook, and the DP push queue.
func Add(e Entry) {
	mu.Lock()
	ring = append(ring, e)
	if len(ring) > MaxRing {
		ring = ring[len(ring)-MaxRing:]
	}
	f := persist
	path := persistPath
	mu.Unlock()

	// Persist to JSONL file (outside the lock to avoid blocking callers).
	// Persistence remains best-effort — a failing disk must not make an admin
	// configuration change fail — but every lost entry is now COUNTED, so the
	// gap in the durable compliance record is visible instead of silent.
	if f != nil {
		persistEntry(f, path, e)
	}
	// Forward to syslog/SIEM if configured.
	if siem != nil {
		siem(e)
	}
	// Queue for CP push when running as Data Plane.
	if dpMode.Load() {
		queueForCluster(e)
	}
}

// Get returns a newest-first snapshot of the in-memory ring.
func Get() []Entry {
	mu.Lock()
	cp := make([]Entry, len(ring))
	copy(cp, ring)
	mu.Unlock()
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// GetMemory returns paginated, optionally time-filtered entries from the
// in-memory ring (newest-first).
func GetMemory(offset, limit int, fromTS, toTS int64) (page []Entry, total int) {
	return paginate(filterByTime(Get(), fromTS, toTS), offset, limit)
}

// GetPersistent reads the JSONL audit log file with pagination.
// Returns entries newest-first. If from/to are non-zero, filters by
// timestamp. Falls back to the in-memory ring if no file is configured.
func GetPersistent(offset, limit int, fromTS, toTS int64) (page []Entry, total int) {
	if persistPath == "" {
		return GetMemory(offset, limit, fromTS, toTS)
	}

	data, err := os.ReadFile(persistPath) // #nosec G304 -- operator-configured path
	if err != nil {
		return Get(), 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		var e Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			if fromTS > 0 && e.TS < fromTS {
				continue
			}
			if toTS > 0 && e.TS > toTS {
				continue
			}
			entries = append(entries, e)
		}
	}
	// Reverse to newest-first.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return paginate(entries, offset, limit)
}

// filterByTime keeps entries within [fromTS, toTS] (0 = unbounded side).
func filterByTime(all []Entry, fromTS, toTS int64) []Entry {
	if fromTS <= 0 && toTS <= 0 {
		return all
	}
	filtered := make([]Entry, 0, len(all))
	for i := range all {
		if fromTS > 0 && all[i].TS < fromTS {
			continue
		}
		if toTS > 0 && all[i].TS > toTS {
			continue
		}
		filtered = append(filtered, all[i])
	}
	return filtered
}

// paginate slices [offset, offset+limit) out of all, reporting the total.
func paginate(all []Entry, offset, limit int) (page []Entry, total int) {
	total = len(all)
	if offset >= total {
		return nil, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return all[offset:end], total
}

// ── Pending audit events for Data Plane → Control Plane push ────────────────

// maxPending caps the DP push queue to prevent unbounded growth if the CP is
// unreachable (newest kept).
const maxPending = 1000

var (
	pendingMu sync.Mutex
	pending   []Entry
)

// queueForCluster adds an audit event to the pending queue for CP push.
// Called by Add when DP mode is on.
func queueForCluster(e Entry) {
	pendingMu.Lock()
	pending = append(pending, e)
	if len(pending) > maxPending {
		pending = pending[len(pending)-maxPending:]
	}
	pendingMu.Unlock()
}

// Drain returns and clears the pending audit event queue.
func Drain() []Entry {
	pendingMu.Lock()
	defer pendingMu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	events := pending
	pending = nil
	return events
}

// Requeue prepends failed events back into the pending queue so they are
// retried on the next push interval instead of being lost (newest kept
// under the cap).
func Requeue(events []Entry) {
	pendingMu.Lock()
	pending = append(events, pending...)
	if len(pending) > maxPending {
		pending = pending[len(pending)-maxPending:]
	}
	pendingMu.Unlock()
}

// ── Test support ─────────────────────────────────────────────────────────────

// ResetForTest snapshots and clears the ring + persistence state, returning
// a restore func. Replaces the pre-extraction pattern of tests swapping the
// package globals directly.
func ResetForTest() (restore func()) {
	mu.Lock()
	oldRing, oldW, oldC, oldPath := ring, persist, persistC, persistPath
	ring, persist, persistC, persistPath = nil, nil, nil, ""
	mu.Unlock()
	return func() {
		mu.Lock()
		ring, persist, persistC, persistPath = oldRing, oldW, oldC, oldPath
		mu.Unlock()
	}
}

// SwapRingForTest snapshots and clears ONLY the in-memory ring, returning a
// restore func (persistence state untouched).
func SwapRingForTest() (restore func()) {
	mu.Lock()
	old := ring
	ring = nil
	mu.Unlock()
	return func() {
		mu.Lock()
		ring = old
		mu.Unlock()
	}
}

// SetPersistForTest points JSONL persistence at w (path stays empty so reads
// keep using the ring), returning a restore func.
func SetPersistForTest(w io.Writer) (restore func()) {
	mu.Lock()
	oldW, oldC := persist, persistC
	persist = w
	persistC = nil
	mu.Unlock()
	return func() {
		mu.Lock()
		persist, persistC = oldW, oldC
		mu.Unlock()
	}
}

// ResetWriteErrorsForTest zeroes the durable-write failure counter, the
// one-shot log gate and the observer, returning a restore func. Test-only:
// the production counters are process-lifetime and never reset.
func ResetWriteErrorsForTest() (restore func()) {
	oldN := atomic.SwapInt64(&writeErrors, 0)
	oldLogged := writeErrLogged.Swap(false)
	oldRepair := needsBoundaryRepair.Swap(false)
	oldObs := writeFailObserver.Swap(nil)
	oldOK := writeSuccessObserver.Swap(nil)
	return func() {
		atomic.StoreInt64(&writeErrors, oldN)
		writeErrLogged.Store(oldLogged)
		needsBoundaryRepair.Store(oldRepair)
		writeFailObserver.Store(oldObs)
		writeSuccessObserver.Store(oldOK)
	}
}

// setPersistPathForTest sets the configured path reported to the write-failure
// observer, returning a restore func. Unexported: SetPersistForTest keeps the
// path empty (so reads stay on the ring), but the observer contract carries the
// path, so the failure tests need to set it independently.
func setPersistPathForTest(path string) (restore func()) {
	mu.Lock()
	old := persistPath
	persistPath = path
	mu.Unlock()
	return func() {
		mu.Lock()
		persistPath = old
		mu.Unlock()
	}
}

// ClearPersistForTest drops the persistence wiring without closing it (used
// after a shutdown-hook test has already closed the file, so a later restore
// or Close cannot double-close).
func ClearPersistForTest() {
	mu.Lock()
	persist, persistC, persistPath = nil, nil, ""
	mu.Unlock()
}

// PersistActive reports whether a persistent file handle is wired. Used both
// by tests (shutdown-hook coverage) and by the admin API (GET /api/stats) to
// surface a silent Init failure: compare against the caller's own configured
// path to detect an operator-configured log that fell back to volatile
// in-memory storage.
func PersistActive() bool {
	mu.Lock()
	defer mu.Unlock()
	return persistC != nil
}
