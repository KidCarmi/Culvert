package main

// logStore is a Badger-backed, time-ordered persistent request-log history.
//
// It complements the two existing surfaces rather than replacing them:
//   - the in-memory ring (store.go `logs`) backs the live tail / SSE feed;
//   - the JSONL writer (initRequestLog) remains for plain-text export;
//   - this store is the queryable, retention-managed HISTORY that survives
//     restart and supports deep pagination ("page 20 = yesterday").
//
// Storage: BadgerDB v4 (already vendored for catdb.go — no new dependency).
//
// Key layout:   8-byte big-endian unix-millis ++ 4-byte big-endian seq  (12 B)
//   The timestamp prefix keeps entries in chronological order so a reverse
//   iterator yields newest-first; the seq disambiguates entries within the
//   same millisecond and preserves insertion order.
// Value layout: JSON-encoded LogEntry.
//
// Retention is two-dimensional, matching the admin's choice (time + size):
//   - Age: a per-key Badger TTL (native, reliable). Expired entries are
//     skipped on read and reclaimed during compaction/GC.
//   - Size: a best-effort janitor that, when the on-disk size exceeds the cap,
//     deletes the oldest entries in bounded batches and runs value-log GC.
//     On-disk size accounting in an LSM store is lazy, so the size cap
//     converges over a few janitor passes rather than instantly.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"sync"
	"sync/atomic"
	"time"

	badger "github.com/dgraph-io/badger/v4"
)

const logStoreKeyLen = 12 // 8-byte ts(ms) + 4-byte seq

// logStoreScanCap bounds the number of entries any single query or stats scan
// will walk, so a pathological time range cannot pin a core.
const logStoreScanCap = 500000

// logStorePruneBatch is the number of oldest entries the size janitor deletes
// per pass. A package var (not const) so tests can lower it.
var logStorePruneBatch = 10000

// globalLogStore is the process-wide history store; nil when disabled.
var globalLogStore *logStore

var (
	statLogStoreDropped int64 // entries dropped because the async queue was full
	statLogStorePruned  int64 // entries deleted by the size-cap janitor
)

type logStore struct {
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
	ch  chan LogEntry
	wg  sync.WaitGroup

	// closeMu guards the closed flag and the send/close of ch. Add and
	// RunRetention take it for reading (they may run concurrently); Close takes
	// it for writing so it cannot close the channel — or the *badger.DB — while
	// an Add send or a retention pass is in flight (prevents a send-on-closed
	// channel panic and use of a closed DB during shutdown).
	closeMu sync.RWMutex
	closed  bool
}

// openLogStore opens (or creates) the history store, converting the admin's
// retention settings (days, GB) into the internal TTL/byte limits.
func openLogStore(dir string, retentionDays int, maxGB float64) (*logStore, error) {
	var ttl time.Duration
	if retentionDays > 0 {
		ttl = time.Duration(retentionDays) * 24 * time.Hour
	}
	var maxBytes int64
	if maxGB > 0 {
		maxBytes = int64(maxGB * (1 << 30))
	}
	return openLogStoreTTL(dir, ttl, maxBytes)
}

// openLogStoreTTL is the low-level constructor used directly by tests so they
// can pass sub-day TTLs and tiny byte caps.
func openLogStoreTTL(dir string, ttl time.Duration, maxBytes int64) (*logStore, error) {
	opts := badger.DefaultOptions(dir).
		WithValueLogFileSize(128 << 20). // bound peak mmap inside containers
		WithLogger(nil)                  // proxy's own logger handles output
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	s := &logStore{
		db: db,
		ch: make(chan LogEntry, 4096),
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
func (s *logStore) scanLogicalBytes() int64 {
	var total int64
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		n := 0
		for it.Rewind(); it.Valid(); it.Next() {
			total += itemLogicalSize(it.Item())
			if n++; n >= logStoreScanCap {
				break
			}
		}
		return nil
	})
	return total
}

func logStoreKey(tsMs int64, seq uint32) []byte {
	k := make([]byte, logStoreKeyLen)
	binary.BigEndian.PutUint64(k[0:8], uint64(tsMs)) // #nosec G115 -- ts is positive millis
	binary.BigEndian.PutUint32(k[8:12], seq)
	return k
}

func logStoreKeyTS(k []byte) int64 {
	if len(k) < 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(k[0:8])) // #nosec G115 -- round-trips logStoreKey
}

// Add enqueues an entry for asynchronous batched persistence. It never blocks
// the caller (the proxy hot path): a full queue drops the entry and bumps a
// counter rather than stalling request handling.
func (s *logStore) Add(e LogEntry) {
	if s == nil {
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
		atomic.AddInt64(&statLogStoreDropped, 1)
	}
}

// writeLoop drains the queue, batching writes and flushing on a timer so the
// store keeps up with bursty traffic without a fsync per entry.
func (s *logStore) writeLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	batch := make([]LogEntry, 0, 256)

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
			key := logStoreKey(batch[i].TS, atomic.AddUint32(&s.seq, 1))
			ent := badger.NewEntry(key, b)
			if ttl := time.Duration(atomic.LoadInt64(&s.ttlNanos)); ttl > 0 {
				ent = ent.WithTTL(ttl)
			}
			_ = wb.SetEntry(ent) //nolint:errcheck -- flush surfaces the error
			added += int64(len(key) + len(b))
		}
		if err := wb.Flush(); err != nil {
			logger.Printf("WARN logstore: batch flush: %v", err)
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
func (s *logStore) Close() error {
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
	// Wait outside the lock: writeLoop coordinates via the channel close + wg
	// (it never takes closeMu), and any in-flight Add/RunRetention released
	// their read lock before Close acquired the write lock.
	s.wg.Wait()
	return s.db.Close()
}

// Query returns up to limit entries newest-first within [fromMs, toMs],
// applying filter, skipping offset, and reporting the total number of matches
// in the window (capped at logStoreScanCap). offset/limit over a frozen time
// window give stable deep pagination. fromMs<=0 means "from the beginning",
// toMs<=0 means "up to now".
func (s *logStore) Query(fromMs, toMs int64, offset, limit int, filter func(*LogEntry) bool) ([]LogEntry, int, error) {
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
	out := make([]LogEntry, 0, limit)
	total := 0
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()

		seek := logStoreKey(toMs, math.MaxUint32)
		scanned := 0
		for it.Seek(seek); it.Valid(); it.Next() {
			item := it.Item()
			if logStoreKeyTS(item.Key()) < fromMs {
				break
			}
			if scanned++; scanned > logStoreScanCap {
				break
			}
			var e LogEntry
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

// logStoreStats reports current usage for the admin retention panel.
type logStoreStats struct {
	Bytes    int64 `json:"bytes"`              // on-disk size (LSM + value log)
	Count    int64 `json:"count"`              // entries scanned (capped)
	Capped   bool  `json:"capped"`             // true when Count hit the scan cap
	OldestMs int64 `json:"oldestMs,omitempty"` // timestamp of the oldest entry
}

// Stats returns the tracked logical usage plus a bounded entry count and the
// oldest timestamp. Bytes is the same logical counter the size cap uses (see
// the bytesUsed field comment). The count scan is bounded by logStoreScanCap
// so a huge store cannot make the panel expensive.
func (s *logStore) Stats() logStoreStats {
	var st logStoreStats
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
				st.OldestMs = logStoreKeyTS(it.Item().KeyCopy(nil))
				first = false
			}
			if st.Count++; st.Count >= logStoreScanCap {
				st.Capped = true
				break
			}
		}
		return nil
	})
	return st
}

// RunRetention enforces the size cap: when on-disk size exceeds maxBytes it
// deletes the oldest logStorePruneBatch entries and runs value-log GC. Age
// retention is handled natively by per-key TTL, so this only addresses size.
// One bounded pass per call; the janitor calls it on a timer so the cap
// converges across passes despite lazy LSM size accounting.
func (s *logStore) RunRetention() {
	if s == nil {
		return
	}
	// Hold the read lock for the whole pass so Close cannot close the DB
	// underneath an in-flight prune (shutdown safety).
	s.closeMu.RLock()
	defer s.closeMu.RUnlock()
	if s.closed {
		return
	}
	maxBytes := atomic.LoadInt64(&s.maxBytes)
	if maxBytes <= 0 || atomic.LoadInt64(&s.bytesUsed) <= maxBytes {
		return
	}
	keys := make([][]byte, 0, logStorePruneBatch)
	var freed int64
	_ = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid() && len(keys) < logStorePruneBatch; it.Next() {
			item := it.Item()
			keys = append(keys, item.KeyCopy(nil))
			freed += itemLogicalSize(item)
		}
		return nil
	})
	if len(keys) == 0 {
		return
	}
	wb := s.db.NewWriteBatch()
	for _, k := range keys {
		_ = wb.Delete(k) //nolint:errcheck -- flush surfaces the error
	}
	if err := wb.Flush(); err != nil {
		logger.Printf("WARN logstore: retention delete: %v", err)
		return
	}
	// Decrement the logical counter, clamping at zero (EstimatedSize is an
	// estimate and TTL may have already removed some accounted bytes). A CAS
	// loop keeps the clamp atomic against a concurrent flush increment — a
	// plain Add-then-Store could wipe a flush that landed in between.
	for {
		old := atomic.LoadInt64(&s.bytesUsed)
		nv := old - freed
		if nv < 0 {
			nv = 0
		}
		if atomic.CompareAndSwapInt64(&s.bytesUsed, old, nv) {
			break
		}
	}
	atomic.AddInt64(&statLogStorePruned, int64(len(keys)))
	_ = s.db.RunValueLogGC(0.5) // reclaim disk; ErrNoRewrite is expected and ignored
}

// SetRetention updates the retention policy at runtime. The new TTL applies to
// newly written entries only (Badger TTL is fixed per key at write time); the
// size cap takes effect on the next janitor pass. days<=0 disables age expiry;
// gb<=0 disables the size cap.
func (s *logStore) SetRetention(days int, gb float64) {
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
func (s *logStore) RetentionDays() int {
	if s == nil {
		return 0
	}
	return int(time.Duration(atomic.LoadInt64(&s.ttlNanos)) / (24 * time.Hour))
}

// RetentionMaxGB returns the current size cap in GB (0 = no limit).
func (s *logStore) RetentionMaxGB() float64 {
	if s == nil {
		return 0
	}
	return float64(atomic.LoadInt64(&s.maxBytes)) / (1 << 30)
}

// logStoreHealth reports history-store usage for the dashboard/admin panels.
// enabled=false (and zeroed fields) when the history store is disabled.
func logStoreHealth() map[string]any {
	if globalLogStore == nil {
		return map[string]any{"enabled": false}
	}
	st := globalLogStore.Stats()
	return map[string]any{
		"enabled":  true,
		"bytes":    st.Bytes,
		"count":    st.Count,
		"capped":   st.Capped,
		"oldestMs": st.OldestMs,
		"dropped":  atomic.LoadInt64(&statLogStoreDropped),
		"pruned":   atomic.LoadInt64(&statLogStorePruned),
	}
}

// logStoreRetentionView is the GET /api/logs/retention payload: the current
// retention policy plus live usage stats.
func logStoreRetentionView() map[string]any {
	if globalLogStore == nil {
		return map[string]any{
			"enabled":        false,
			"retentionDays":  0,
			"retentionMaxGB": 0,
			"usage":          logStoreHealth(),
		}
	}
	return map[string]any{
		"enabled":        true,
		"retentionDays":  globalLogStore.RetentionDays(),
		"retentionMaxGB": globalLogStore.RetentionMaxGB(),
		"usage":          logStoreHealth(),
	}
}

// startLogStoreRetention runs the size janitor every interval until ctx is
// cancelled (graceful shutdown).
func startLogStoreRetention(ctx context.Context, s *logStore, interval time.Duration) {
	if s == nil || ctx == nil {
		return // nil ctx would panic on <-ctx.Done(); guard defensively
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.RunRetention()
			}
		}
	}()
}
