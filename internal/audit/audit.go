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

// Add appends an entry to the in-memory ring and, when configured, to the
// persistent JSONL file, the SIEM hook, and the DP push queue.
func Add(e Entry) {
	mu.Lock()
	ring = append(ring, e)
	if len(ring) > MaxRing {
		ring = ring[len(ring)-MaxRing:]
	}
	f := persist
	mu.Unlock()

	// Persist to JSONL file (outside the lock to avoid blocking callers).
	if f != nil {
		if b, err := json.Marshal(e); err == nil {
			b = append(b, '\n')
			f.Write(b) //nolint:errcheck // best-effort persistence, matches pre-extraction behavior
		}
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
