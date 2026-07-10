// Package reqlog is the request-log engine: a bounded in-memory ring (the
// newest MaxRing entries), an optional persistent JSONL layer with rotation
// and a count-once-log-first write-error contract, a bounded newest-first
// read over the persistent file with a short-TTL shared-parse cache, and the
// status→level mapping. Extracted from package main's store.go per ADR-0002
// (store.go decomposition Phase C — the slice that closes the program).
//
// package main keeps the surfaces: AuthLogFields and its applyTo (welded to
// the frozen AuthOutcome contract), the recordRequest*/persistLogEntry
// fan-out (stats globals + syslog forwarding + this layer), and the API
// handlers. One inversion point: the queryable-history hook (SetHistory) —
// main wires a closure performing the same lock-free atomic load the inline
// code did, so runtime enable/disable of the history store stays race-free
// on the hot path.
package reqlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/logstore"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// Entry is the request-log record. The history store (internal/logstore)
// owns the wire/SIEM field contract; this engine rings, persists, and reads
// the same type so there is exactly one schema.
type Entry = logstore.Entry

// MaxRing bounds the in-memory ring buffer.
const MaxRing = 5000

// MaxPersistentReturn caps the newest-N entries returned from the
// persistent JSONL request log so admin queries remain bounded regardless of
// the on-disk rotation size. Roughly one day of traffic at ~100 req/s.
const MaxPersistentReturn = 20000

// readCacheTTL bounds staleness; the dashboard polls every 3 s.
const readCacheTTL = 2 * time.Second

// The in-memory ring is a fixed-capacity circular buffer. Add overwrites the
// oldest slot in place, so the steady state allocates nothing: the previous
// append-then-retrim slice pattern re-allocated a ~2 MB backing array and
// copied all MaxRing entries (328 B each) under ringMu every ~MaxRing/4 adds
// — ~1.5 KB of amortized garbage per logged request plus a periodic 1.6 MB
// copy while every request goroutine contends on the lock.
var (
	ringMu   sync.Mutex
	ringBuf  []Entry // allocated to MaxRing on first Add; nil until then
	ringHead int     // next write slot
	ringLen  int     // valid entries (≤ MaxRing)
)

// Persistent JSONL layer. Assigned once at startup (Init) and read lock-free
// on the hot path — the same publication pattern the pre-extraction package
// globals used.
var (
	writer   io.Writer // *fileutil.RotatingFile; nil = file persistence disabled
	closer   io.Closer
	filePath string // path to JSONL file for paginated reads; "" = disabled
)

// Persistent request-log failure counters. A full disk or corrupt file must
// not silently destroy the request history — both are counted, surfaced via
// /metrics, /api/stats, and /healthz, and logged once (not per occurrence).
var (
	writeErrors  int64 // failed JSONL marshals/writes in Add
	skippedLines int64 // corrupt JSONL lines skipped on read
)

// readCache memoises the parsed persistent log for a short TTL so N
// concurrent dashboard pollers share one file parse instead of each
// re-reading up to MaxPersistentReturn JSON lines per request. Keyed by path
// so a re-init (config change, tests) never serves entries from the old
// file. Cached entries are shared read-only between callers — never mutate
// them.
var readCache struct {
	mu      sync.Mutex
	path    string
	expires time.Time
	entries []Entry
}

// history is the queryable-history hook called after every Add (nil =
// disabled). Set once at main's init; the closure is responsible for its own
// nil/runtime checks.
var history func(Entry)

// SetHistory installs the queryable-history hook called after every Add.
func SetHistory(fn func(Entry)) { history = fn }

// LevelForStatus maps a request status to the log level driving the admin
// UI's tab grouping (INFO = allowed, WARN = blocked & threats, ERROR = auth
// failures and anything unexpected).
func LevelForStatus(status string) string {
	switch status {
	case "OK", "POLICY_ALLOW", "TUNNEL_CLOSED":
		return "INFO"
	case "BLOCKED", "THREAT_BLOCKED", "FILE_BLOCKED", "SCAN_BLOCKED",
		"DPI_BLOCKED", "POLYGLOT_BLOCKED", "CDR_BLOCKED", "CDR_SANITIZED",
		"RATE_LIMITED", "IP_BLOCKED",
		"POLICY_BLOCK", "POLICY_DROP", "POLICY_REDIRECT", "POLICY_DEFAULT_DENY":
		return "WARN"
	default: // AUTH_FAIL, CDR_ERROR, and anything unexpected
		return "ERROR"
	}
}

// Init opens a rotating JSONL file for persistent request logging. Each
// Entry is appended as a single JSON line. The file rotates at maxMB.
// If path is empty this is a no-op (backwards-compatible).
func Init(path string, maxMB int) error {
	if path == "" {
		return nil
	}
	if maxMB <= 0 {
		maxMB = 100
	}
	rf, err := fileutil.NewRotatingFile(path, maxMB)
	if err != nil {
		return fmt.Errorf("request log open %s: %w", path, err)
	}
	writer = rf
	closer = rf
	filePath = path

	// Drop any cached parse from a previous file.
	readCache.mu.Lock()
	readCache.path = ""
	readCache.entries = nil
	readCache.mu.Unlock()
	return nil
}

// Close releases the persistent file handle (best-effort; shutdown hook).
// Safe when persistence was never initialised.
func Close() error {
	if closer == nil {
		return nil
	}
	return closer.Close()
}

// Add appends an entry to the in-memory ring and, when configured, to the
// persistent JSONL file and the queryable-history hook.
func Add(e Entry) {
	ringMu.Lock()
	if ringBuf == nil {
		ringBuf = make([]Entry, MaxRing)
	}
	ringBuf[ringHead] = e
	ringHead = (ringHead + 1) % MaxRing
	if ringLen < MaxRing {
		ringLen++
	}
	ringMu.Unlock()

	// Persist to JSONL file (outside the lock to avoid blocking callers).
	if w := writer; w != nil {
		b, err := json.Marshal(e)
		if err == nil {
			b = append(b, '\n')
			_, err = w.Write(b)
		}
		if err != nil {
			// A full disk must not silently destroy the request history:
			// count every failure, log only the first to avoid flooding.
			if atomic.AddInt64(&writeErrors, 1) == 1 {
				obs.Printf("ERROR request log: persistent write failed (further failures counted silently): %v", err)
			}
		}
	}

	// Persist to the queryable history store (async, non-blocking, nil-safe).
	if h := history; h != nil {
		h(e)
	}
}

// Get returns a newest-first snapshot of the in-memory ring.
func Get() []Entry {
	ringMu.Lock()
	// Copy oldest→newest with at most two bulk copies (the buffer wraps at
	// ringHead), keeping the lock hold to plain memmoves.
	cp := make([]Entry, ringLen)
	tail := (ringHead - ringLen + MaxRing) % MaxRing
	n := copy(cp, ringBuf[tail:min(tail+ringLen, MaxRing)])
	copy(cp[n:], ringBuf[:ringLen-n])
	ringMu.Unlock()
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// WriteErrors reports the number of failed JSONL marshals/writes in Add.
func WriteErrors() int64 { return atomic.LoadInt64(&writeErrors) }

// SkippedLines reports the number of corrupt JSONL lines skipped on read.
func SkippedLines() int64 { return atomic.LoadInt64(&skippedLines) }

// ReadPersistent streams the persistent JSONL request log file and returns
// the newest-first slice of parsed entries, capped at MaxPersistentReturn so
// memory stays bounded regardless of file size. Callers should apply their
// own filter + pagination loop on top — the same loop they use on the
// in-memory ring buffer — so there is a single filter code path to maintain.
//
// Returns (nil, nil) when persistence is disabled (no file configured) or
// when the file has not yet been created. Only the active (non-rotated) log
// file is consulted; the rotated ".1" archive is intentionally skipped to
// keep each query bounded to one rotation window.
func ReadPersistent() ([]Entry, error) {
	path := filePath
	if path == "" {
		return nil, nil
	}
	// Serialise readers through the cache lock: the first poller parses the
	// file, concurrent pollers wait and then reuse the fresh cached result.
	readCache.mu.Lock()
	defer readCache.mu.Unlock()
	if readCache.path == path && time.Now().Before(readCache.expires) {
		return readCache.entries, nil
	}

	f, err := os.Open(path) // #nosec G304 -- operator-configured path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("request log open: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only close

	sc := bufio.NewScanner(f)
	// SSL-inspected entries with long identity/rule strings occasionally
	// exceed the 64 KB default scanner buffer; lift the ceiling to 1 MB.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// Amortized O(N) truncate-to-cap: grow up to 2× cap, then drop the oldest
	// half. Peak memory is ~2× cap parsed structs (~8 MB at cap=20k).
	const cap_ = MaxPersistentReturn
	buf := make([]Entry, 0, 2*cap_)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// Count corrupt lines instead of dropping them invisibly; log only
			// the first so a damaged file cannot flood the logger.
			if atomic.AddInt64(&skippedLines, 1) == 1 {
				obs.Printf("WARN request log: skipping corrupt JSONL line (further occurrences counted silently): %v", err)
			}
			continue
		}
		buf = append(buf, e)
		if len(buf) >= 2*cap_ {
			copy(buf, buf[len(buf)-cap_:])
			buf = buf[:cap_]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("request log scan: %w", err)
	}
	if len(buf) > cap_ {
		buf = buf[len(buf)-cap_:]
	}
	// Reverse in place to newest-first.
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	readCache.path = path
	readCache.expires = time.Now().Add(readCacheTTL)
	readCache.entries = buf
	return buf, nil
}

// ── Test support ─────────────────────────────────────────────────────────────

// SwapRingForTest swaps the in-memory ring for an empty one, returning a
// restore func, so Add side-effects don't leak across tests.
func SwapRingForTest() (restore func()) {
	ringMu.Lock()
	oldBuf, oldHead, oldLen := ringBuf, ringHead, ringLen
	ringBuf, ringHead, ringLen = nil, 0, 0
	ringMu.Unlock()
	return func() {
		ringMu.Lock()
		ringBuf, ringHead, ringLen = oldBuf, oldHead, oldLen
		ringMu.Unlock()
	}
}

// SetWriterForTest points JSONL persistence at w (closer and path stay as
// they are), returning a restore func. Used to inject failing writers.
func SetWriterForTest(w io.Writer) (restore func()) {
	old := writer
	writer = w
	return func() { writer = old }
}

// SetFilePathForTest points persistent reads at path without opening a
// writer, returning a restore func.
func SetFilePathForTest(path string) (restore func()) {
	old := filePath
	filePath = path
	return func() { filePath = old }
}

// SwapPersistenceForTest snapshots and clears the writer/closer/path trio,
// returning a restore func. The restore closes whatever handle the test
// left wired (so a re-init inside the test cannot leak) before reinstating
// the snapshot.
func SwapPersistenceForTest() (restore func()) {
	oldW, oldC, oldP := writer, closer, filePath
	writer, closer, filePath = nil, nil, ""
	return func() {
		if closer != nil {
			_ = closer.Close()
		}
		writer, closer, filePath = oldW, oldC, oldP
	}
}

// ResetForTest unwires the persistent layer so tests can safely re-init
// without leaking file handles or paths across tests. Safe to call whether
// or not persistence was initialised. (No restore — mirrors the
// pre-extraction resetRequestLogState helper's exact semantics.)
func ResetForTest() {
	if closer != nil {
		_ = closer.Close()
	}
	closer, writer, filePath = nil, nil, ""
}

// PinCacheForTest pushes the read-cache expiry far into the future so a
// "served from cache" assertion cannot flake on a slow host.
func PinCacheForTest() {
	readCache.mu.Lock()
	readCache.expires = time.Now().Add(time.Hour)
	readCache.mu.Unlock()
}

// ExpireCacheForTest zeroes the read-cache expiry so the next ReadPersistent
// re-parses the file.
func ExpireCacheForTest() {
	readCache.mu.Lock()
	readCache.expires = time.Time{}
	readCache.mu.Unlock()
}

// PersistActive reports whether a persistent file handle is wired (test
// support for the startup/shutdown-hook coverage).
func PersistActive() bool { return closer != nil }

// FilePath reports the configured persistent JSONL path ("" = disabled).
func FilePath() string { return filePath }
