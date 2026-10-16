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
//   - Fixed-capacity map with TTL expiry.
//   - On capacity overflow: expired entries are evicted first; if still full,
//     ~25 % of entries are dropped (simple, avoids per-entry LRU bookkeeping).
//   - All operations are mutex-protected; hit/miss counters use atomic int64.
package hashcache

import (
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
type hashCacheEntry struct {
	result    ScanCacheResult
	expiresAt time.Time
}

// HashCache is a size-bounded, TTL-evicting cache of SHA-256 scan results.
type HashCache struct {
	mu      sync.RWMutex
	entries map[string]*hashCacheEntry
	maxSize int
	ttl     time.Duration
	hits    atomic.Int64
	misses  atomic.Int64
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

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[hash] = &hashCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
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
	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[hash] = &hashCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
	}
	return true
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
	_, ok := c.entries[hash]
	if ok {
		delete(c.entries, hash)
	}
	c.mu.Unlock()
	return ok
}

// Clear removes all entries from the cache.
func (c *HashCache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*hashCacheEntry, c.maxSize)
	c.mu.Unlock()
}

// evictLocked removes all expired entries.  If the map is still at capacity
// afterward, it drops approximately 25 % of the remaining entries.
// Must be called with c.mu held for writing.
//
// ── Measured cost (Go 1.26, 4-vCPU amd64, 64-hex-char keys as SHA256Hex
// produces, hashcache_evict_bench_test.go; 2026-10-16 on a ~3x-oversubscribed
// shared host, so read the figures as upper-biased) ───────────────────────────
//
// This runs on the Set path, synchronously, under the EXCLUSIVE write lock, on
// whichever scan arrives when the map is full — so its duration stalls every
// concurrent verdict lookup, not just that one caller. The expiry sweep is
// O(maxSize): proving no entry is expired means looking at all of them. The
// 25 % drop then makes room for maxSize/4 inserts, over which one call's cost
// amortizes:
//
//	cache_size │ one evictLocked │ recurs every      │ amortized per Set
//	   10 000  │    0.54 ms      │ 2 500 inserts     │  ~218 ns
//	  100 000  │    10.4 ms      │ 25 000 inserts    │  ~414 ns
//	1 000 000  │     150 ms      │ 250 000 inserts   │  ~600 ns
//
// (10-sample medians in the busy steady state: nothing expired. This is NOT
// the worst case: at 10 000 the all-expired case measured ~0.94 ms against
// 0.54 ms. The realistic worst case, a full cache idle past its TTL and then
// one Set, is therefore HIGHER and is not yet bounded at 100 000 or
// 1 000 000; BenchmarkEvictLocked_AllExpired_100k/_1M exist to bound it on an
// idle host. The 1 000 000 row is BenchmarkEvictLocked_NothingExpired_1M and
// is the noisiest: read it as 150-300 ms. The amortized
// column is this implementation's own per-Set cost; do not confuse it with
// the base-vs-candidate difference reported in the roadmap note.)
//
// cache_size is an operator YAML knob that config validation only FLOORS
// (non-positive → 10 000) and never caps, so the spike grows with it without
// anything warning the operator. Eviction also gets SLOWER the more
// reclaimable the cache is (0.94 ms at 10 000 fully expired, against 0.54 ms
// with none expired), because a sweep that finds expired entries also deletes
// them.
//
// At the 10 000 default this is deliberately left alone: ~218 ns amortized per
// Set. When at least one engine (ClamAV or YARA) is active, a Set follows a
// scan MISS that costs a scan measured in MILLISECONDS, three to four orders of
// magnitude more. With NO engine configured (YARA disabled and no ClamAV),
// ScanBody still caches a clean result without scanning
// (TestYARA_DisabledSkipsScanAndDiagnosticsWarn pins that). The Set then
// follows only a SHA-256 of the body, and how the eviction cost compares with
// that is UNMEASURED. That covers the Set path only. Cache HITS also wait behind the exclusive lock
// hold, and the reader tail-latency impact is UNMEASURED, pending a contention
// run on an idle host. Bounding it independent of
// maxSize means giving up the "no expired entry survives an eviction"
// invariant that TestSet_EvictsExpiredFirst pins (an early exit cannot know
// what it did not look at) or sharding the map — both change observable
// behaviour and need their own change and review.
//
// Do not reach for the obvious layout fix without reading the measurements
// first. Holding entries by value instead of behind a pointer makes this sweep
// 9-62 % faster (no change when everything has expired) and removes one
// allocation per Set. It also costs ~10 ns (+27 %) on every Get miss, and the
// steady-state Set cost showed no significant change at either 10 000 or
// 100 000. That is a MIXED and IMMATERIAL result at the default size, so it
// was measured and NOT shipped, for want of a payoff rather than because it is
// harmful. At large cache_size the real fix is bounding or sharding the
// eviction, not a constant-factor layout change.
// roadmap/SCAN-CACHE-EVICTION-COST.md has the interleaved benchstat numbers,
// the superseded short-key figures, and the retraction of an earlier,
// stronger claim that the comparison refuted it.
func (c *HashCache) evictLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	// If we're still over capacity, drop 25 % of current entries.
	if len(c.entries) >= c.maxSize {
		toDrop := c.maxSize / 4
		for k := range c.entries {
			delete(c.entries, k)
			toDrop--
			if toDrop <= 0 {
				break
			}
		}
	}
}
