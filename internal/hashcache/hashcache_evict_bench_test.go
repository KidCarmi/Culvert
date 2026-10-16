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
// needs a fresh full cache, because an evicted one is no longer at capacity.
//
// The fixture is rebuilt inside the loop with the timer stopped, so exactly one
// cache is live at a time. Building all b.N of them up front instead would
// retain b.N x maxSize entries, and b.N grows with -benchtime: at the
// -benchtime 1s suggested above that is ~2 GB for the 10 000 case and ~1.3 GB
// for the 100 000 one, which exhausts a constrained runner before the first
// timed call. The StopTimer/StartTimer pair costs ~100 ns against a measured
// 0.5-9 ms, so it does not move the figures.
func benchEvictLocked(b *testing.B, maxSize int, expiredFrac float64) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		c := fillCache(maxSize, expiredFrac)
		b.StartTimer()
		c.evictLocked()
		b.StopTimer()
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

// readParallel runs c.Get across a keyspace on every available core and returns
// how many of those lookups HIT. The caller reports it as a %hit metric.
//
// The hit rate is reported because it is not a constant across these two
// benchmarks: a writer that trips eviction deletes seeded keys, so the
// contended benchmark below reads a mix of hits and misses where the
// uncontended one reads hits only. A miss is CHEAPER than a hit (roughly 24 ns
// against 77 ns), so a falling hit rate pushes ns/op DOWN and cannot manufacture
// the slowdown the contended case shows — but the two are not a like-for-like
// read workload, and %hit is what lets a reader see by how much. Hits are
// counted in a per-goroutine local and folded in once at the end, so the
// counting costs nothing measurable inside the loop.
func readParallel(b *testing.B, c *HashCache, prefix string, keyspace int) (hits, total int64) {
	var h, t atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		var localHits, localTotal int64
		i := 0
		for pb.Next() {
			if _, ok := c.Get(prefix + strconv.Itoa(i%keyspace)); ok {
				localHits++
			}
			localTotal++
			i++
		}
		h.Add(localHits)
		t.Add(localTotal)
	})
	return h.Load(), t.Load()
}

// reportHitRate publishes the %hit metric. The caller stops the timer, because
// only the caller knows what else it needs to sample at the edge of the timed
// region (see the write accounting in BenchmarkGet_ParallelDuringEviction).
func reportHitRate(b *testing.B, hits, total int64) {
	if total > 0 {
		b.ReportMetric(float64(hits)/float64(total)*100, "%hit")
	}
}

// Concurrent read throughput under the RWMutex, with the cache full and no
// writer present: the ceiling the eviction stall interrupts. Nothing evicts
// here, so this one reads a fully populated keyspace (%hit = 100).
func BenchmarkGet_Parallel(b *testing.B) {
	c := fillCache(10_000, 0)
	b.ReportAllocs()
	b.ResetTimer()
	hits, total := readParallel(b, c, "k", 10_000)
	b.StopTimer()
	reportHitRate(b, hits, total)
}

// Readers contending with a writer that keeps tripping eviction — the shape
// that makes the lock hold a system-wide cost rather than a local one.
//
// Read %hit against BenchmarkGet_Parallel's before drawing a ratio from the two.
// The writer runs for the whole benchmark, and each Set it lands at capacity
// evicts 25 % of the map, so the seeded k keys are steadily displaced by the
// writer's own w keys: measured, this reads only **a few percent hits** against
// the uncontended benchmark's 100 % — 4.7 % at -benchtime 500ms, 1.4 % at 1s,
// falling as the run lengthens and the writer displaces more. (An earlier
// revision of this comment guessed ~75 % from the first eviction alone; the
// %hit metric exists because that guess was wrong by more than an order of
// magnitude.) The pair therefore INDICATES contention rather than isolating it.
//
// It does not flatter the contended side: a miss costs ~24 ns against a hit's
// ~75 ns, so the changed mix pushes this figure DOWN, and it is still ~3x
// slower while doing the cheaper work. But the raw ratio is not attributable
// to lock contention alone, and %hit on both is what makes that visible.
//
// Reader throughput is what a bounded eviction would be trying to protect, so
// this is the benchmark to re-read if that follow-up is attempted. The pre-fix
// A/B of the rejected layout change reported this case 13 % WORSE. That run
// used the fixture-retention harness that has since been corrected, and the
// corrected A/B shows no significant change (p=0.083;
// roadmap/SCAN-CACHE-EVICTION-COST.md).
// minContendedWindow is the shortest timed window in which the contention
// benchmarks require at least one writer Set to have landed: several multiples
// of the Go scheduler's 10 ms preemption slice, so a runnable writer must have
// had a turn.
const minContendedWindow = 50 * time.Millisecond

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

	// Count writes that land INSIDE the timed window, not writes that ever
	// happened. The handshake above already guarantees one Set before timing
	// starts, which made an earlier `writes.Load() == 0` guard vacuous: it
	// could not fail, so a run whose writer never got scheduled during
	// RunParallel would report UNCONTENDED reads under a name promising
	// contention and still pass (Codex P2, PR #1604).
	//
	// The counter is sampled immediately either side of RunParallel, so the
	// only writes it can misattribute are those landing in the statement
	// between the sample and the first/last read. That is not airtight by
	// construction — proving overlap would need the readers themselves to
	// observe writer progress, and a shared atomic in the measured read path
	// would distort the ns/op this benchmark exists to report (CodeRabbit
	// minor, PR #1604). With ~200 000 writes landing in a half-second timed
	// window, a false pass needs zero of them inside it and one in a
	// two-statement gap, so the count is evidence rather than proof.
	b.ReportAllocs()
	b.ResetTimer()
	writesBefore := writes.Load()
	hits, total := readParallel(b, c, "k", maxSize)
	landed := writes.Load() - writesBefore
	b.StopTimer()
	close(stop)

	reportHitRate(b, hits, total)
	b.ReportMetric(float64(landed), "writes")

	// Calibration passes time windows of microseconds to a few milliseconds,
	// in which the writer legitimately may not be scheduled at all: with every
	// P running a reader, a runnable writer can wait for the scheduler's ~10 ms
	// preemption tick (observed: b.N=9512, 1.87 ms timed, 0 writes). Gating on
	// b.N let that pass fail spuriously, so gate on the timed duration instead:
	// assert only once the window spans several preemption ticks, where no
	// overlapping write means something is actually wrong.
	if b.Elapsed() >= minContendedWindow && landed == 0 {
		b.Fatal("no write landed inside the timed window; the contention this benchmark measures did not happen")
	}
}

// ── Like-for-like contention control ────────────────────────────────────────
//
// The pair above cannot isolate lock contention, because the writer displaces
// the seeded keys and so the contended run reads a different keyspace from the
// uncontended one. These two pin BOTH sides to a keyspace nothing ever inserts
// — neither fillCache's "k" entries nor the writer's "w" ones — so every lookup
// is a guaranteed MISS and the read workload is identical with and without the
// writer. The delta between them is then attributable to the writer rather than
// to a shifting hit rate (construction suggested by CodeRabbit, PR #1604).
//
// Read it as a control, not as a replacement: it measures the MISS path, which
// is cheaper than the hit path the scanners actually take, and the writer's
// cost here is eviction plus ordinary Set work, not eviction alone. What it
// does establish is that the slowdown survives holding the workload fixed.

// benchMissOnlyParallel reads a never-inserted keyspace on every core, with an
// eviction-tripping writer when withWriter is set. %hit must be 0 in both.
func benchMissOnlyParallel(b *testing.B, withWriter bool) {
	const maxSize = 10_000
	c := fillCache(maxSize, 0)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}

	stop := make(chan struct{})
	var writes atomic.Int64
	if withWriter {
		ready := make(chan struct{})
		go func() {
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
	}

	b.ReportAllocs()
	b.ResetTimer()
	writesBefore := writes.Load()
	hits, total := readParallel(b, c, "m", maxSize) // "m" is never inserted
	landed := writes.Load() - writesBefore
	b.StopTimer()
	close(stop)

	reportHitRate(b, hits, total)
	if hits != 0 {
		b.Fatalf("control benchmark must read only misses, got %d hits", hits)
	}
	if withWriter {
		b.ReportMetric(float64(landed), "writes")
		if b.Elapsed() >= minContendedWindow && landed == 0 { // see BenchmarkGet_ParallelDuringEviction
			b.Fatal("no write landed inside the timed window; nothing was contended")
		}
	}
}

func BenchmarkGet_ParallelMissOnly(b *testing.B) { benchMissOnlyParallel(b, false) }
func BenchmarkGet_ParallelMissOnlyDuringEviction(b *testing.B) {
	benchMissOnlyParallel(b, true)
}
