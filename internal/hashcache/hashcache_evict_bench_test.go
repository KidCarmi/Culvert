package hashcache

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ── Scan-cache eviction cost ─────────────────────────────────────────────────
//
// The scan cache is consulted once per scanned object and written once per scan
// miss, so its Set path sits behind every ClamAV/YARA verdict. evictLocked runs
// there synchronously under the EXCLUSIVE write lock whenever the map is full,
// which makes its duration a stall for every concurrent verdict lookup rather
// than a cost to the one caller that tripped it. Nothing measured that before
// this file; see the cost table on evictLocked for what it found and for the
// part of the shape that a layout change does not fix.
//
// Run: go test ./internal/hashcache/ -run XXX -bench Evict -benchtime 1s

// fillCache seeds a cache to exactly maxSize entries, the first expiredFrac of
// them already expired. It writes c.entries directly: going through Set would
// trip eviction partway and leave the map in a shape the benchmark did not ask
// for.
func fillCache(maxSize int, expiredFrac float64) *HashCache {
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	c := New(maxSize, time.Hour)
	now := time.Now()
	nExpired := int(float64(maxSize) * expiredFrac)
	for j := 0; j < maxSize; j++ {
		expiresAt := now.Add(time.Hour)
		if j < nExpired {
			expiresAt = now.Add(-time.Minute)
		}
		c.entries["k"+strconv.Itoa(j)] = &hashCacheEntry{result: res, expiresAt: expiresAt}
	}
	return c
}

// benchEvictLocked times ONE evictLocked call on a full cache. Each iteration
// needs a fresh full cache — an evicted one is no longer at capacity — so the
// caches are built up front and excluded from the timed region.
func benchEvictLocked(b *testing.B, maxSize int, expiredFrac float64) {
	caches := make([]*HashCache, b.N)
	for i := range caches {
		caches[i] = fillCache(maxSize, expiredFrac)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		caches[i].evictLocked()
	}
}

// The stall, by configured cache size, in the state a busy gateway holds: the
// cache full and nothing expired yet, so the sweep looks at every entry and
// finds nothing to drop. This is the worst realistic case and the one whose
// growth with cache_size matters, cache_size being floored by config
// validation and never capped.
func BenchmarkEvictLocked_NothingExpired_10k(b *testing.B)  { benchEvictLocked(b, 10_000, 0) }
func BenchmarkEvictLocked_NothingExpired_100k(b *testing.B) { benchEvictLocked(b, 100_000, 0) }

// Eviction cost RISES with how reclaimable the cache is: a sweep that finds
// expired entries also deletes them, and at 100 % it deletes the whole map
// instead of the 25 % the capacity drop would have taken. Worth pinning so the
// relationship stays visible — it is the opposite of the intuitive direction.
func BenchmarkEvictLocked_HalfExpired_10k(b *testing.B) { benchEvictLocked(b, 10_000, 0.5) }
func BenchmarkEvictLocked_AllExpired_10k(b *testing.B)  { benchEvictLocked(b, 10_000, 1.0) }

// Amortized Set cost at steady-state churn above capacity — the throughput
// number, as opposed to the lock-hold spike above. Every maxSize/4 inserts pay
// one eviction between them, so this is where a regression in the amortized
// shape would show. ReportAllocs covers the per-Set allocations: the key string
// and the hashCacheEntry itself. Folding the entry into the map by value
// removes one of them and was measured — it is NOT a win overall; see
// roadmap/SCAN-CACHE-EVICTION-COST.md before trying it again.
func benchChurn(b *testing.B, maxSize int) {
	c := New(maxSize, time.Hour)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	for j := 0; j < maxSize; j++ {
		c.Set("k"+strconv.Itoa(j), res)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("n"+strconv.Itoa(i), res)
	}
}

func BenchmarkSetChurn_AtCapacity_10k(b *testing.B)  { benchChurn(b, 10_000) }
func BenchmarkSetChurn_AtCapacity_100k(b *testing.B) { benchChurn(b, 100_000) }

// Get on a hit: the path every scanned object takes before the scanners are
// consulted at all, and the path the eviction stall blocks.
func BenchmarkGet_Hit(b *testing.B) {
	c := fillCache(10_000, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get("k512"); !ok {
			b.Fatal("seeded entry must hit")
		}
	}
}

func BenchmarkGet_Miss(b *testing.B) {
	c := fillCache(10_000, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get("absent"); ok {
			b.Fatal("unseeded entry must miss")
		}
	}
}

// Concurrent read throughput under the RWMutex, with the cache full and no
// writer present: the ceiling the eviction stall interrupts.
func BenchmarkGet_Parallel(b *testing.B) {
	c := fillCache(10_000, 0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get("k" + strconv.Itoa(i%10_000))
			i++
		}
	})
}

// Readers contending with a writer that keeps tripping eviction — the shape
// that makes the lock hold a system-wide cost rather than a local one: reads
// cost ~3x their uncontended figure here. Reader throughput is what a bounded
// eviction would be trying to protect, so this is the benchmark to re-read if
// that follow-up is attempted — and the one that caught the rejected layout
// change making this case 13% WORSE while the stall itself got faster.
func BenchmarkGet_ParallelDuringEviction(b *testing.B) {
	const maxSize = 10_000
	c := fillCache(maxSize, 0)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}

	stop := make(chan struct{})
	ready := make(chan struct{})
	var writes atomic.Int64
	go func() {
		// Land the first write BEFORE the readers are timed, and announce it.
		// Without the handshake the calibration call (b.N=1) returns and closes
		// stop before this goroutine is ever scheduled, so the benchmark would
		// measure uncontended reads and then fail on the assertion below.
		c.Set("w0", res)
		writes.Add(1)
		close(ready)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c.Set("w"+strconv.Itoa(i), res)
			writes.Add(1)
		}
	}()
	<-ready

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			c.Get("k" + strconv.Itoa(i%maxSize))
			i++
		}
	})
	b.StopTimer()
	close(stop)
	if writes.Load() == 0 {
		b.Fatal("writer never ran; the contention this measures did not happen")
	}
}
