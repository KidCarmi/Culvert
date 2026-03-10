package main

// SHA256 Scan Result Cache
//
// Avoids redundant ClamAV / YARA scans by caching the outcome of each scan
// keyed on the SHA-256 digest of the scanned content.  The same executable or
// document delivered from multiple hosts is therefore scanned only once per TTL
// window, dramatically reducing CPU load on busy proxies.
//
// Design:
//   - Fixed-capacity map with TTL expiry.
//   - On capacity overflow: expired entries are evicted first; if still full,
//     ~25 % of entries are dropped (simple, avoids per-entry LRU bookkeeping).
//   - All operations are mutex-protected; hit/miss counters use atomic int64.

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

// newHashCache returns a HashCache with the given capacity and TTL.
// Sensible defaults are used when size ≤ 0 or ttl ≤ 0.
func newHashCache(maxSize int, ttl time.Duration) *HashCache {
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
	c.mu.RUnlock()

	if !ok || time.Now().After(e.expiresAt) {
		c.misses.Add(1)
		return ScanCacheResult{}, false
	}
	c.hits.Add(1)
	return e.result, true
}

// Set stores a scan result under the given content hash.
func (c *HashCache) Set(hash string, result ScanCacheResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[hash] = &hashCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Stats returns (hits, misses, currentSize) for Prometheus / admin UI.
func (c *HashCache) Stats() (int64, int64, int) {
	c.mu.RLock()
	size := len(c.entries)
	c.mu.RUnlock()
	return c.hits.Load(), c.misses.Load(), size
}

// evictLocked removes all expired entries.  If the map is still at capacity
// afterward, it drops approximately 25 % of the remaining entries.
// Must be called with c.mu held for writing.
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
