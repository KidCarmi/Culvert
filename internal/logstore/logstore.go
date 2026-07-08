// Package logstore is the Badger-backed, time-ordered persistent request-log
// history engine. Extracted from package main's logstore.go + the deletion
// passes of logguard.go per ADR-0002 (BadgerDB containment, the catdb
// rationale).
//
// It complements the two main-side surfaces rather than replacing them:
//   - the in-memory ring (main store.go `logs`) backs the live tail / SSE feed;
//   - the JSONL writer (main initRequestLog) remains for plain-text export;
//   - this store is the queryable, retention-managed HISTORY that survives
//     restart and supports deep pagination ("page 20 = yesterday").
//
// Key layout:   8-byte big-endian unix-millis ++ 4-byte big-endian seq  (12 B)
//
//	The timestamp prefix keeps entries in chronological order so a reverse
//	iterator yields newest-first; the seq disambiguates entries within the
//	same millisecond and preserves insertion order.
//
// Value layout: JSON-encoded Entry.
//
// Retention is two-dimensional, matching the admin's choice (time + size):
//   - Age: a per-key Badger TTL (native, reliable). Expired entries are
//     skipped on read and reclaimed during compaction/GC.
//   - Size: a best-effort janitor that, when the on-disk size exceeds the cap,
//     deletes the oldest entries in bounded batches and runs value-log GC.
//     Cleanup removes LOW-priority entries (access/traffic, Level INFO/DEBUG)
//     before HIGH-priority security entries (WARN/ERROR) whenever possible.
//
// What stays in package main: the process-wide singleton + enable/disable/
// purge lifecycle, the disk-pressure ORCHESTRATOR (disk usage, minimal-mode
// state, audit trail, GUI status), and the admin retention API. The engine
// exposes two inversion points for it: the `minimal` hook injected at OpenTTL
// (Add's emergency skip reads main's minimal-mode state) and RunRetention
// returning its cleanup results so main records the audit/pressure event.
package logstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"golang.org/x/crypto/pbkdf2"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// Entry is one request-log record (moved from package main's LogEntry; main
// re-exposes it via a type alias). It is the wire type shared by the
// in-memory ring, the JSONL writer, the SSE live feed, and this store.
type Entry struct {
	TS          int64  `json:"ts"`
	Time        string `json:"time"`
	IP          string `json:"ip"`
	Identity    string `json:"identity,omitempty"` // authenticated username/email, empty if unauthenticated
	Method      string `json:"method"`
	Host        string `json:"host"`
	URI         string `json:"uri,omitempty"`        // full request URL (host+path, no query); only set when the matched rule has LogFullURI
	Status      string `json:"status"`               // OK | BLOCKED | AUTH_FAIL | RATE_LIMITED | IP_BLOCKED | POLICY_*
	Level       string `json:"level"`                // INFO | WARN | ERROR
	RuleMatched string `json:"ruleMatched"`          // policy rule name that matched, if any
	ActionTaken string `json:"actionTaken"`          // policy action taken, if any
	BytesSent   int64  `json:"bytesSent,omitempty"`  // bytes sent to upstream (request body / tunnel client→dest)
	BytesRecv   int64  `json:"bytesRecv,omitempty"`  // bytes received from upstream (response body / tunnel dest→client)
	SSLAction   string `json:"sslAction,omitempty"`  // "inspect", "bypass", or empty (non-CONNECT)
	DurationMs  int64  `json:"durationMs,omitempty"` // connection lifetime; set on TUNNEL_CLOSED accounting entries

	// Normalized authentication-policy SIEM fields (Phase 0 seam, §1.8; the
	// auth_* observability block is finalized in Phase 1 Slice 5). Declared as the
	// durable SIEM contract but populated only when an auth decision supplies them
	// — all are omitempty so wire output stays byte-identical for requests with no
	// auth decision. NO identity is carried in the auth_* block: an Exempt decision
	// is logged by outcome + rule id/name (+ low-cardinality subject predicate
	// types and the matched rule's subject schema version) only.
	SchemaVersion         int      `json:"schema_version,omitempty"`           // event schema version
	AuthSource            string   `json:"auth_source,omitempty"`              // categorical: idp|local|oidc:x|saml:x|exempt|unauth
	AuthOutcome           string   `json:"auth_outcome,omitempty"`             // Stage-1 outcome (e.g. "Exempt"); "" = none
	AuthPolicyRuleID      string   `json:"auth_policy_rule_id,omitempty"`      // ULID of matched Stage-1 rule
	AuthPolicyRuleName    string   `json:"auth_policy_rule_name,omitempty"`    // display name of matched Stage-1 rule
	AccessRuleID          string   `json:"access_rule_id,omitempty"`           // ULID of matched Stage-2 rule
	AuthSubjectMatchTypes []string `json:"auth_subject_match_types,omitempty"` // low-cardinality predicate type names (e.g. ["cidr"])
	AuthSchemaVersion     int      `json:"auth_schema_version,omitempty"`      // matched rule's SubjectMatch schema version
}

// LowPriority classifies an entry's storage priority by level. INFO, DEBUG,
// and empty are LOW priority (access/traffic); WARN and ERROR are HIGH
// priority (security: threats, malware, auth failures, policy violations).
func LowPriority(level string) bool {
	switch level {
	case "WARN", "ERROR":
		return false
	default:
		return true
	}
}

const keyLen = 12 // 8-byte ts(ms) + 4-byte seq

// scanCap bounds the number of entries any single query or stats scan will
// walk, so a pathological time range cannot pin a core.
const scanCap = 500000

// pruneBatch is the number of oldest entries the size janitor deletes per
// pass. A package var (not const) so in-package tests can lower it.
var pruneBatch = 10000

// maxQueryLimit caps a single Query's page size so a caller-supplied limit
// cannot drive an excessive result count.
const maxQueryLimit = 10000

// queryAllocHint is the fixed initial capacity for a query result slice.
// Constant (not the user-supplied limit) so the allocation size never depends
// on user input; append grows it as needed.
const queryAllocHint = 256

// Encryption-at-rest (Badger AES). The key is derived from a passphrase via
// PBKDF2-SHA256 (mirroring main's CA bundle) and a random per-store salt
// persisted in a sidecar file so the key is stable across restarts.
const (
	encIters   = 600_000 // matches ca.go pbkdf2Iter (NIST SP 800-132)
	encSaltLen = 32
	encKeyLen  = 32 // AES-256
)

// ErrEncMismatch is returned when an existing store can't be opened with the
// configured key (passphrase added/changed, or store was plaintext). The
// remediation is to purge the on-disk store and re-enable.
var ErrEncMismatch = errors.New("saved logs use a different encryption key")

// EncKey derives the AES key from the configured passphrase plus a persistent
// random salt (sidecar file dir+".salt"). Returns (nil, nil) when no
// passphrase is configured (encryption disabled).
func EncKey(dir, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, nil
	}
	saltPath := dir + ".salt"
	salt, err := os.ReadFile(saltPath) //nolint:gosec // path is server-configured
	if err != nil || len(salt) != encSaltLen {
		salt = make([]byte, encSaltLen)
		if _, e := rand.Read(salt); e != nil {
			return nil, fmt.Errorf("logstore salt: %w", e)
		}
		if e := os.WriteFile(saltPath, salt, 0o600); e != nil {
			return nil, fmt.Errorf("write logstore salt: %w", e)
		}
	}
	return pbkdf2.Key([]byte(passphrase), salt, encIters, encKeyLen, sha256.New), nil
}

// Package-level observability counters (read by main's /metrics exposition
// and dashboard health view).
var (
	statDropped int64 // entries dropped because the async queue was full
	statPruned  int64 // entries deleted by the size-cap janitor
)

// Dropped returns the cumulative count of entries dropped at the full queue.
func Dropped() int64 { return atomic.LoadInt64(&statDropped) }

// Pruned returns the cumulative count of entries deleted by the size janitor.
func Pruned() int64 { return atomic.LoadInt64(&statPruned) }

// Store is the history store handle. Nil-safe on all methods.
type Store struct {
	db *badger.DB

	// ttlNanos (age limit) and maxBytes (size cap) are runtime-adjustable from
	// the admin UI, so they are accessed atomically. 0 disables that dimension.
	ttlNanos int64 // atomic
	maxBytes int64 // atomic

	// bytesUsed is the tracked logical size (key+value bytes) used by the size
	// cap. It is reconciled from disk on open, incremented on write, and
	// decremented on prune. Badger's own db.Size() lags writes (memtable/WAL
	// aren't counted until compaction), so it is unusable as a prompt trigger;
	// the logical counter is deterministic. TTL-expired entries are not
	// decremented, so the counter can drift slightly high over time — which
	// prunes marginally early, the safe direction for a hard ceiling.
	bytesUsed int64 // atomic

	seq uint32 // atomic; disambiguates same-millisecond entries
	ch  chan Entry
	wg  sync.WaitGroup

	// minimal is the emergency minimal-mode hook injected at OpenTTL (nil =
	// never minimal). When it reports true, Add stops persisting low-priority
	// (access/traffic) entries so the store stops growing under disk pressure;
	// security (WARN/ERROR) events are still recorded. The state itself lives
	// in package main (logguard); immutable after open.
	minimal func() bool

	// cancelJanitor stops this store's retention janitor goroutine; called by
	// Close so a disable/enable cycle doesn't leak janitor goroutines. Set by
	// main's enable path via SetCancelJanitor before the store is published.
	cancelJanitor context.CancelFunc

	// closeMu guards the closed flag and the send/close of ch. Add and
	// retention passes take it for reading (they may run concurrently); Close
	// takes it for writing so it cannot close the channel — or the *badger.DB —
	// while an Add send or a retention pass is in flight (prevents a send-on-
	// closed channel panic and use of a closed DB during shutdown).
	closeMu sync.RWMutex
	closed  bool

	encrypted bool // AES-at-rest enabled (immutable after open)
}

// Encrypted reports whether this store is encrypted at rest. Nil-safe.
func (s *Store) Encrypted() bool { return s != nil && s.encrypted }

// BytesUsed returns the tracked logical size (the same counter the size cap
// uses). Nil-safe.
func (s *Store) BytesUsed() int64 {
	if s == nil {
		return 0
	}
	return atomic.LoadInt64(&s.bytesUsed)
}

// SetCancelJanitor records the cancel func for this store's janitor goroutine
// so Close can stop it. Called by main's enable path before the store is
// published; not synchronized (publish-before-share, like `minimal`).
func (s *Store) SetCancelJanitor(cancel context.CancelFunc) { s.cancelJanitor = cancel }

// OpenTTL opens (or creates) the history store. It is the low-level
// constructor: main's enable path converts the admin's retention settings
// (days, GB) and passes the derived TTL/byte limits, the encryption key from
// EncKey (nil = unencrypted), and the minimal-mode hook (nil = never
// minimal). Tests use it directly for sub-day TTLs and tiny byte caps.
func OpenTTL(dir string, ttl time.Duration, maxBytes int64, encKey []byte, minimal func() bool) (*Store, error) {
	opts := badger.DefaultOptions(dir).
		WithValueLogFileSize(128 << 20). // bound peak mmap inside containers
		WithLogger(nil)                  // the proxy's own logger handles output
	if len(encKey) > 0 {
		// Badger requires an index cache when encryption is enabled.
		opts = opts.WithEncryptionKey(encKey).WithIndexCacheSize(16 << 20)
	}
	db, err := badger.Open(opts)
	if err != nil {
		// A key/plaintext mismatch (passphrase added, changed, lost, or salt
		// gone) surfaces here; map it to a clear, actionable sentinel so the
		// handler can guide the admin to purge rather than echo a raw Badger
		// error. Match the exported sentinels first, with a string fallback.
		if errors.Is(err, badger.ErrEncryptionKeyMismatch) ||
			errors.Is(err, badger.ErrInvalidEncryptionKey) ||
			strings.Contains(strings.ToLower(err.Error()), "encrypt") {
			return nil, ErrEncMismatch
		}
		return nil, err
	}
	s := &Store{
		db:        db,
		ch:        make(chan Entry, 4096),
		encrypted: len(encKey) > 0,
		minimal:   minimal,
	}
	if ttl > 0 {
		s.ttlNanos = int64(ttl)
	}
	s.maxBytes = maxBytes
	// Reconcile the logical byte counter from any data already on disk so the
	// size cap is correct immediately after a restart (bounded by the scan cap).
	s.bytesUsed = s.scanLogicalBytes()
	s.wg.Add(1)
	go s.writeLoop()
	return s, nil
}

// itemLogicalSize is the bytesUsed contribution of one stored entry: key bytes
// plus value bytes. It MUST match the flush-time accounting (len(key)+len(val))
// so reconcile-on-open, flush increments, and prune decrements all use the same
// measure — otherwise the size cap drifts. ValueSize reads the entry meta, not
// the value log, so it is cheap with PrefetchValues=false.
func itemLogicalSize(item *badger.Item) int64 {
	return int64(len(item.Key())) + item.ValueSize()
}

// scanLogicalBytes sums the key+value bytes of stored entries (bounded by the
// scan cap) — no value fetch required. Called once at open before the store is
// published, so it needs no close guard.
func (s *Store) scanLogicalBytes() int64 {
	var total int64
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		n := 0
		for it.Rewind(); it.Valid(); it.Next() {
			total += itemLogicalSize(it.Item())
			n++
			if n >= scanCap {
				break
			}
		}
		return nil
	})
	return total
}

func storeKey(tsMs int64, seq uint32) []byte {
	k := make([]byte, keyLen)
	binary.BigEndian.PutUint64(k[0:8], uint64(tsMs)) // #nosec G115 -- ts is positive millis
	binary.BigEndian.PutUint32(k[8:12], seq)
	return k
}

func storeKeyTS(k []byte) int64 {
	if len(k) < 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(k[0:8])) // #nosec G115 -- round-trips storeKey
}

// Add enqueues an entry for asynchronous batched persistence. It never blocks
// the caller (the proxy hot path): a full queue drops the entry and bumps a
// counter rather than stalling request handling.
func (s *Store) Add(e Entry) {
	if s == nil {
		return
	}
	// Emergency minimal mode: stop persisting low-priority (access/traffic)
	// entries so the store stops growing under disk pressure; keep security
	// (WARN/ERROR) events. The in-memory live feed still receives everything.
	if s.minimal != nil && s.minimal() && LowPriority(e.Level) {
		return
	}
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return
	}
	select {
	case s.ch <- e:
	default:
		atomic.AddInt64(&statDropped, 1)
	}
}

// writeLoop drains the queue, batching writes and flushing on a timer so the
// store keeps up with bursty traffic without a fsync per entry.
func (s *Store) writeLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]Entry, 0, 256)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		wb := s.db.NewWriteBatch()
		var added int64
		for i := range batch {
			b, err := json.Marshal(batch[i])
			if err != nil {
				continue
			}
			key := storeKey(batch[i].TS, atomic.AddUint32(&s.seq, 1))
			ent := badger.NewEntry(key, b)
			if ttl := time.Duration(atomic.LoadInt64(&s.ttlNanos)); ttl > 0 {
				ent = ent.WithTTL(ttl)
			}
			_ = wb.SetEntry(ent)
			added += int64(len(key) + len(b))
		}
		if err := wb.Flush(); err != nil {
			obs.Printf("WARN logstore: batch flush: %v", err)
			batch = batch[:0]
			return
		}
		atomic.AddInt64(&s.bytesUsed, added)
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// Close drains pending writes and closes the database. Safe to call once.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	close(s.ch)
	s.closeMu.Unlock()
	if s.cancelJanitor != nil {
		s.cancelJanitor() // stop the retention janitor (no leak on disable)
	}
	// Wait outside the lock: writeLoop coordinates via the channel close + wg
	// (it never takes closeMu), and any in-flight Add/retention pass released
	// their read lock before Close acquired the write lock.
	s.wg.Wait()
	return s.db.Close()
}

// PurgeAll deletes all stored history (Badger DropAll) and resets the byte
// counter. The store stays open and usable. Held under the read lock so Close
// cannot close the DB mid-purge.
func (s *Store) PurgeAll() error {
	if s == nil {
		return nil
	}
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return nil
	}
	if err := s.db.DropAll(); err != nil {
		return err
	}
	atomic.StoreInt64(&s.bytesUsed, 0)
	return nil
}

// Query returns up to limit entries newest-first within [fromMs, toMs],
// applying filter, skipping offset, and reporting the total number of matches
// in the window (capped at the scan cap). offset/limit over a frozen time
// window give stable deep pagination. fromMs<=0 means "from the beginning",
// toMs<=0 means "up to now".
func (s *Store) Query(fromMs, toMs int64, offset, limit int, filter func(*Entry) bool) ([]Entry, int, error) {
	if s == nil {
		return nil, 0, nil
	}
	// Read lock for the whole transaction so Close can't close the DB mid-query
	// (use-after-close guard).
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return nil, 0, nil
	}
	if toMs <= 0 {
		toMs = math.MaxInt64
	}
	if limit <= 0 {
		limit = 1000
	}
	// Bound the result count at the store layer (defense in depth; the API also
	// clamps). The loop below stops at len(out) == limit.
	if limit > maxQueryLimit {
		limit = maxQueryLimit
	}
	// Fixed initial capacity (not the caller-supplied limit) so the allocation
	// size never depends on user input — append grows as needed, still bounded
	// by limit in the loop (CWE-770/789).
	out := make([]Entry, 0, queryAllocHint)
	total := 0
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()

		seek := storeKey(toMs, math.MaxUint32)
		scanned := 0
		for it.Seek(seek); it.Valid(); it.Next() {
			item := it.Item()
			if storeKeyTS(item.Key()) < fromMs {
				break
			}
			scanned++
			if scanned > scanCap {
				break
			}
			var e Entry
			if err := item.Value(func(v []byte) error { return json.Unmarshal(v, &e) }); err != nil {
				continue
			}
			if filter != nil && !filter(&e) {
				continue
			}
			if total >= offset && len(out) < limit {
				out = append(out, e)
			}
			total++
		}
		return nil
	})
	return out, total, err
}

// Stats reports current usage for the admin retention panel.
type Stats struct {
	Bytes    int64 `json:"bytes"`              // tracked logical size (same counter as the size cap)
	Count    int64 `json:"count"`              // entries scanned (capped)
	Capped   bool  `json:"capped"`             // true when Count hit the scan cap
	OldestMs int64 `json:"oldestMs,omitempty"` // timestamp of the oldest entry
}

// Stats returns the tracked logical usage plus a bounded entry count and the
// oldest timestamp. Bytes is the same logical counter the size cap uses (see
// the bytesUsed field comment). The count scan is bounded by the scan cap so
// a huge store cannot make the panel expensive.
func (s *Store) Stats() Stats {
	var st Stats
	if s == nil {
		return st
	}
	// Read lock so Close can't close the DB mid-scan (use-after-close guard).
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return st
	}
	st.Bytes = atomic.LoadInt64(&s.bytesUsed)
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		first := true
		for it.Rewind(); it.Valid(); it.Next() {
			if first {
				st.OldestMs = storeKeyTS(it.Item().KeyCopy(nil))
				first = false
			}
			st.Count++
			if st.Count >= scanCap {
				st.Capped = true
				break
			}
		}
		return nil
	})
	return st
}

// RunRetention enforces the size cap: when the tracked size exceeds maxBytes
// it removes entries (low-priority first) until back under the cap and runs
// value-log GC. Age retention is handled natively by per-key TTL. One bounded
// pass per call; main's janitor calls it on a timer so the cap converges
// across passes despite lazy LSM size accounting. Returns what was cleaned so
// the caller can record the audit/pressure event (count == 0 → nothing ran).
func (s *Store) RunRetention() (freed, count int64, levels map[string]int64) {
	if s == nil {
		return 0, 0, nil
	}
	maxBytes := atomic.LoadInt64(&s.maxBytes)
	if maxBytes <= 0 {
		return 0, 0, nil
	}
	used := atomic.LoadInt64(&s.bytesUsed)
	if used <= maxBytes {
		return 0, 0, nil
	}
	return s.CleanupBytes(used - maxBytes)
}

// SetRetention updates the retention policy at runtime. The new TTL applies to
// newly written entries only (Badger TTL is fixed per key at write time); the
// size cap takes effect on the next janitor pass. days<=0 disables age expiry;
// gb<=0 disables the size cap.
func (s *Store) SetRetention(days int, gb float64) {
	if s == nil {
		return
	}
	var ttlNanos int64
	if days > 0 {
		ttlNanos = int64(time.Duration(days) * 24 * time.Hour)
	}
	var maxBytes int64
	if gb > 0 {
		maxBytes = int64(gb * (1 << 30))
	}
	atomic.StoreInt64(&s.ttlNanos, ttlNanos)
	atomic.StoreInt64(&s.maxBytes, maxBytes)
}

// RetentionDays returns the current age limit in whole days (0 = no limit).
func (s *Store) RetentionDays() int {
	if s == nil {
		return 0
	}
	return int(time.Duration(atomic.LoadInt64(&s.ttlNanos)) / (24 * time.Hour))
}

// RetentionMaxGB returns the current size cap in GB (0 = no limit).
func (s *Store) RetentionMaxGB() float64 {
	if s == nil {
		return 0
	}
	return float64(atomic.LoadInt64(&s.maxBytes)) / (1 << 30)
}

// ── Priority-aware cleanup (the logguard deletion passes) ────────────────────

// CleanupBytes deletes stored entries to free at least `need` logical bytes,
// removing LOW-priority entries (oldest first) before HIGH-priority ones.
// Returns bytes freed, entries removed, and a per-level category breakdown.
// Held under the close read-lock; bounded by the scan cap per pass. Called by
// RunRetention (size cap) and by main's disk-critical handler (which owns the
// disk-usage check, minimal-mode state, and audit recording).
func (s *Store) CleanupBytes(need int64) (freed, count int64, levels map[string]int64) {
	levels = map[string]int64{}
	if s == nil || need <= 0 {
		return freed, count, levels
	}
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return freed, count, levels
	}
	// One call deletes at most pruneBatch entries total (the janitor converges
	// across passes); within that budget, Pass 1 removes low-priority entries
	// first and Pass 2 (only if still short) sacrifices any priority, oldest
	// first — security logs go only when nothing else remains.
	budget := int64(pruneBatch)
	for _, lowOnly := range []bool{true, false} {
		if freed >= need || count >= budget {
			break
		}
		f, c := s.deletePass(need-freed, budget-count, lowOnly, levels)
		freed += f
		count += c
	}
	if count > 0 {
		for { // clamp-subtract the logical counter (race-safe vs concurrent flush)
			old := atomic.LoadInt64(&s.bytesUsed)
			nv := old - freed
			if nv < 0 {
				nv = 0
			}
			if atomic.CompareAndSwapInt64(&s.bytesUsed, old, nv) {
				break
			}
		}
		atomic.AddInt64(&statPruned, count)
		_ = s.db.RunValueLogGC(0.5) // reclaim disk; ErrNoRewrite expected/ignored
	}
	return freed, count, levels
}

// deletePass deletes oldest entries until `need` bytes are freed or limits are
// hit. When lowOnly is true, only LOW-priority entries are deleted (others are
// skipped). Records deleted entries' levels into the shared breakdown. Caller
// holds closeMu.RLock.
//
// "Low-before-high" is best-effort ("when possible"): pass 1 scans at most
// scanCap (500k) entries hunting for low-priority keys. In the pathological
// case where the oldest 500k entries are ALL high-priority (WARN/ERROR) and
// low-priority entries exist only deeper in the store, pass 1 finds none and
// pass 2 (lowOnly=false) deletes the oldest security records instead. This is
// an accepted limitation: the bounded scan caps value-read cost, and
// preventing disk exhaustion outranks the ordering preference — so deleting
// the oldest records to free space is correct even when they happen to be
// security logs. The case requires >500k consecutive oldest security entries,
// which does not arise in normal traffic where access/traffic logs dominate.
func (s *Store) deletePass(need, maxKeys int64, lowOnly bool, levels map[string]int64) (freed, count int64) {
	if maxKeys <= 0 {
		return 0, 0
	}
	keys := make([][]byte, 0, 1024)
	klevels := make([]string, 0, 1024)
	var pending int64
	scanned := 0
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true // need the value to read Level
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid() && pending < need && int64(len(keys)) < maxKeys; it.Next() {
			scanned++
			if scanned > scanCap {
				break
			}
			item := it.Item()
			level := "INFO"
			_ = item.Value(func(v []byte) error {
				var e Entry
				if json.Unmarshal(v, &e) == nil && e.Level != "" {
					level = e.Level
				}
				return nil
			})
			if lowOnly && !LowPriority(level) {
				continue // keep high-priority security logs in pass 1
			}
			keys = append(keys, item.KeyCopy(nil))
			klevels = append(klevels, level)
			pending += itemLogicalSize(item)
		}
		return nil
	})
	if len(keys) == 0 {
		return 0, 0
	}
	wb := s.db.NewWriteBatch()
	for _, k := range keys {
		_ = wb.Delete(k)
	}
	if err := wb.Flush(); err != nil {
		obs.Printf("WARN logstore: cleanup delete: %v", err)
		return 0, 0
	}
	for _, lvl := range klevels {
		levels[lvl]++
	}
	return pending, int64(len(keys))
}
