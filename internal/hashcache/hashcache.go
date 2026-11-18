// Package hashcache provides a size-bounded, TTL-evicting cache of security
// scan results keyed on the SHA-256 digest of scanned content. It is a
// self-contained leaf (stdlib only, no Culvert coupling) extracted from the
// flat package main per ADR-0002.
//
// Avoids redundant ClamAV / YARA scans by caching the outcome of each scan
// keyed on the SHA-256 digest of the scanned content. The same executable or
// document delivered from multiple hosts is therefore scanned only once per TTL
// window, dramatically reducing CPU load on busy proxies.
//
// Design:
//   - Fixed-capacity map with TTL expiry, plus a min-heap of the same entries
//     ordered by expiry.
//   - On capacity overflow: expired entries are reaped from the heap root first
//     (a bounded batch per insert); if none is expired, the single entry
//     closest to expiry is dropped. Every insert is O(log n) under the lock,
//     independent of capacity (see evictLocked).
//   - All operations are mutex-protected; hit/miss counters use atomic int64.
package hashcache

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// ScanCacheResult records the outcome of a security scan for a content hash.
type ScanCacheResult struct {
	Clean     bool   // true = no threat detected
	Reason    string // virus name or YARA rule name when not clean
	Source    string // "clamav", "yara", or "clean"
	ScannedAt time.Time
}

// hashCacheEntry wraps a result with an absolute expiry timestamp.
//
// result and expiresAt are immutable once the entry is published in the map:
// Get reads result AFTER releasing the read lock, so an overwrite always
// installs a new entry rather than mutating the old one. key and idx are
// heap bookkeeping, written only under the write lock and never read by Get.
type hashCacheEntry struct {
	result    ScanCacheResult
	expiresAt time.Time
	key       string
	idx       int // position in HashCache.byExpiry
}

// expiryHeap is a min-heap of entries ordered by expiresAt (container/heap).
type expiryHeap []*hashCacheEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h expiryHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx = i
	h[j].idx = j
}

// Push implements heap.Interface; it records the entry's slot.
func (h *expiryHeap) Push(x any) {
	e := x.(*hashCacheEntry)
	e.idx = len(*h)
	*h = append(*h, e)
}

// Pop implements heap.Interface.
func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old) - 1
	e := old[n]
	old[n] = nil // do not retain the dropped entry through the backing array
	*h = old[:n]
	return e
}

// HashCache is a size-bounded, TTL-evicting cache of SHA-256 scan results.
type HashCache struct {
	mu      sync.RWMutex
	entries map[string]*hashCacheEntry
	// byExpiry holds exactly the entries in the map, ordered by expiresAt, so
	// eviction finds an expired entry — or the one closest to expiry — at the
	// root instead of sweeping the whole map under the write lock.
	byExpiry expiryHeap
	maxSize  int
	ttl      time.Duration
	hits     atomic.Int64
	misses   atomic.Int64

	// gen is the invalidation epoch: Clear advances it, under mu held for
	// writing, so "no Clear happened since generation g was read" is exactly
	// "gen still equals g". It is an atomic only so Generation stays off the
	// lock at scan start; every WRITE happens under mu, and SetIfGeneration
	// compares it under mu, which is what makes the compare and the store one
	// step with respect to Clear.
	gen atomic.Uint64
}

// New returns a HashCache with the given capacity and TTL.
// Sensible defaults are used when size ≤ 0 or ttl ≤ 0.
func New(maxSize int, ttl time.Duration) *HashCache {
	if maxSize <= 0 {
		maxSize = 10_000
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &HashCache{
		entries: make(map[string]*hashCacheEntry, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// SHA256Hex computes the SHA-256 digest of data and returns it as a lowercase
// hex string.  Used as the cache key for scanned content.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Get retrieves a cached result for the given hash.
// Returns (result, true) on a valid, non-expired cache hit.
func (c *HashCache) Get(hash string) (ScanCacheResult, bool) {
	c.mu.RLock()
	e, ok := c.entries[hash]
	expired := ok && time.Now().After(e.expiresAt)
	c.mu.RUnlock()

	if !ok || expired {
		c.misses.Add(1)
		return ScanCacheResult{}, false
	}
	c.hits.Add(1)
	return e.result, true
}

// Set stores a scan result under the given content hash, with the cache's
// configured TTL.
func (c *HashCache) Set(hash string, result ScanCacheResult) {
	c.SetTTL(hash, result, 0)
}

// SetTTL stores a scan result with an explicit lifetime; ttl ≤ 0 uses the
// cache's configured TTL.
//
// It exists for verdicts that are ABOUT THE SCANNER rather than about the
// content — a fail-closed scan-timeout refusal, for instance. Those must not
// inherit the content TTL: a scanner that was briefly slow would otherwise keep
// blocking a specific object for the rest of the hour, long after it recovered.
func (c *HashCache) SetTTL(hash string, result ScanCacheResult, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.storeLocked(hash, result, ttl)
}

// SetTTLUnless stores result under hash with the given lifetime unless keep
// reports that the entry already present must be preserved. It returns whether
// the write happened; ttl ≤ 0 uses the cache's configured TTL.
//
// The test and the write are one atomic step under the cache lock. A caller
// doing Get-then-Set instead would leave a window in which a stronger verdict
// lands between the two and is overwritten anyway — which is the exact race
// this exists to close. keep is called only with a present, unexpired entry
// (an expired one counts as absent), and hit/miss counters are untouched:
// this is a write path, not a lookup.
func (c *HashCache) SetTTLUnless(hash string, result ScanCacheResult, ttl time.Duration, keep func(existing ScanCacheResult) bool) bool {
	if ttl <= 0 {
		ttl = c.ttl
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[hash]; ok && keep != nil && !time.Now().After(e.expiresAt) && keep(e.result) {
		return false
	}
	c.storeLocked(hash, result, ttl)
	return true
}

// Generation returns the cache's current invalidation epoch, for a caller that
// is about to compute a verdict and must not publish it if the cache is
// invalidated before it finishes (see SetIfGeneration).
func (c *HashCache) Generation() uint64 { return c.gen.Load() }

// SetIfGeneration stores result with the cache's configured TTL only if no
// Clear has happened since gen was obtained from Generation, and reports
// whether it stored.
//
// It exists for verdicts that take time to compute. A Clear means "everything
// computed before this point is no longer trusted" — new signatures, changed
// rules, an operator flush — and a verdict whose computation STARTED before the
// Clear but finished after it belongs to the distrusted side. A plain Set would
// land it in the freshly cleared cache, where nothing would ever invalidate it
// again for the rest of the TTL. The generation compare and the store happen
// under the same write lock Clear takes, so there is no window in which a Clear
// can slip between them.
func (c *HashCache) SetIfGeneration(hash string, result ScanCacheResult, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.gen.Load() != gen {
		return false
	}
	c.storeLocked(hash, result, c.ttl)
	return true
}

// storeLocked installs result under hash with the given lifetime. Caller holds
// c.mu for writing.
//
// An overwrite REPLACES the entry object in its heap slot (see hashCacheEntry
// for why it never mutates the published one) and needs no eviction: the key
// count does not change. Only a new key at capacity evicts.
func (c *HashCache) storeLocked(hash string, result ScanCacheResult, ttl time.Duration) {
	now := time.Now()
	ne := &hashCacheEntry{result: result, expiresAt: now.Add(ttl), key: hash}
	if old, ok := c.entries[hash]; ok {
		ne.idx = old.idx
		c.byExpiry[ne.idx] = ne
		c.entries[hash] = ne
		heap.Fix(&c.byExpiry, ne.idx)
		return
	}
	if len(c.entries) >= c.maxSize {
		c.evictLocked(now)
	}
	c.entries[hash] = ne
	heap.Push(&c.byExpiry, ne)
}

// removeLocked drops e from both the map and the heap. Caller holds c.mu for
// writing; e must currently be in the cache.
func (c *HashCache) removeLocked(e *hashCacheEntry) {
	delete(c.entries, e.key)
	heap.Remove(&c.byExpiry, e.idx)
}

// Stats returns (hits, misses, currentSize) for Prometheus / admin UI.
func (c *HashCache) Stats() (hits, misses int64, currentSize int) {
	c.mu.RLock()
	currentSize = len(c.entries)
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), currentSize
}

// Evict removes a specific hash from the cache.
// Returns true if the entry existed (regardless of expiry).
func (c *HashCache) Evict(hash string) bool {
	c.mu.Lock()
	e, ok := c.entries[hash]
	if ok {
		c.removeLocked(e)
	}
	c.mu.Unlock()
	return ok
}

// Clear removes all entries from the cache and advances its invalidation
// epoch, so a SetIfGeneration for a verdict begun before the Clear is refused.
func (c *HashCache) Clear() { c.Invalidate() }

// Invalidate is Clear that also reports how many entries it dropped. The epoch
// advances even when the cache is empty: an empty cache says nothing about
// verdicts still being COMPUTED, and those are exactly what the epoch exists to
// refuse. The count is read under the same lock as the drop, so it is exact.
func (c *HashCache) Invalidate() (dropped int) {
	c.mu.Lock()
	dropped = len(c.entries)
	c.entries = make(map[string]*hashCacheEntry, c.maxSize)
	c.byExpiry = nil
	c.gen.Add(1)
	c.mu.Unlock()
	return dropped
}

// evictExpiredBatch caps how many expired entries one eviction reaps. Reaping
// is O(log n) per entry, so this bounds the worst single lock hold — a full
// cache left idle past its TTL and then hit by one Set — to a constant number
// of heap operations instead of one per cached entry. Expired entries beyond
// the batch are never served (Get checks expiry) and are reaped by later
// evictions; each reap frees a slot, so they are consumed before any live
// entry is dropped.
const evictExpiredBatch = 64

// evictLocked makes room for one new key in a full cache. Must be called with
// c.mu held for writing.
//
// Policy, in order:
//
//  1. Reap up to evictExpiredBatch expired entries from the heap root. The
//     heap is ordered by expiry, so expired entries are exactly a prefix of
//     its pop order: a LIVE entry is never dropped while an expired one
//     remains (the invariant TestSet_EvictsExpiredFirst pins).
//  2. If nothing was expired, drop the single live entry closest to expiry —
//     the one with the least remaining value. A short-lived scan-timeout
//     cooldown therefore goes before an hour-long content verdict.
//
// Cost: O(log maxSize) per evicted entry, at most evictExpiredBatch of them.
// This replaces a full-map expiry sweep plus a 25 % arbitrary drop that ran on
// the Set path under this same exclusive lock, stalling every concurrent Get
// for O(cache_size): measured on an idle 4-vCPU host, ~100 ms per call at
// cache_size 1 000 000 with nothing expired and ~200 ms with everything
// expired. cache_size is an operator knob that is floored but never capped,
// so that stall grew with configuration; this one does not. See
// roadmap/SCAN-CACHE-EVICTION-COST.md and BenchmarkSetIntoFull_*.
//
// Dropping a verdict early is never a security change: a miss re-scans, and
// an entry is never served past its own expiry.
func (c *HashCache) evictLocked(now time.Time) {
	for n := 0; n < evictExpiredBatch && len(c.byExpiry) > 0 && now.After(c.byExpiry[0].expiresAt); n++ {
		c.removeLocked(c.byExpiry[0])
	}
	if len(c.entries) >= c.maxSize && len(c.byExpiry) > 0 {
		c.removeLocked(c.byExpiry[0])
	}
}
