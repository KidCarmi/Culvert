package hashcache

import (
	"encoding/hex"
	"runtime"
	"strconv"
	"sync"
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
// (the 1 000 000-entry case is skipped under -short).

// ── Production-shaped keys ───────────────────────────────────────────────────
//
// Production reaches this cache only through SHA256Hex, so every real key is a
// 64-character lowercase hex string. Map hashing and deletion cost grows with
// key length, so short keys such as "k0" measure a cheaper map than the one a
// gateway holds (Codex, PR #1604). Every key these benchmarks insert or look
// up is therefore 64 hex characters.
//
// Fixture and reader keys are real SHA256Hex digests. Keys minted INSIDE a
// timed loop (churn inserts, the contention writer) cannot afford a SHA-256
// each, so seqKey builds a 64-hex key of the same length and alphabet from a
// counter. The counter goes in the leading characters so that keys differ
// early, as digests do.
//
// No package-level fixture state (Codex, PR #1604). An earlier revision
// memoized key tables in a package-level map. That kept ~80 MB of 1 000 000-
// entry keys live for the rest of `-bench .` and skewed GC pacing for every
// later benchmark, including the pointer-versus-value A/B. Each benchmark now
// builds its own keys once, outside the b.N loop. They die when it returns,
// and startTimedAfterGC collects setup garbage before timing.
// TestBenchFiles_NoPackageLevelVars walls this: no _test.go file in this
// package may declare a package-level var.

// keyTable returns SHA256Hex(ns + i) for i in [0, n), freshly allocated.
func keyTable(ns string, n int) []string {
	t := make([]string, n)
	for i := range t {
		t[i] = SHA256Hex([]byte(ns + strconv.Itoa(i)))
	}
	return t
}

// Namespaces for seqKey: one hex digit each, written into the key so the
// churn, writer and top-up keyspaces never collide.
const (
	nsChurn  = 'a'
	nsWriter = 'b'
	nsTopUp  = 'c'

	// seqKeyTail fills the rest of a seqKey after its 16 counter digits and
	// one namespace digit: 47 fixed hex characters, so every key is 64 long.
	seqKeyTail = "5f0e9c2d7b4a8613e2c9d05b7a1f6e3c8d2b9a4f7e1c605"
)

// seqKey returns a 64-hex-character key for counter i in namespace ns. One
// allocation, no hashing, so it is cheap enough for a timed loop.
func seqKey(ns byte, i int) string {
	var buf [64]byte
	var n [8]byte
	u := uint64(i)
	for b := 0; b < 8; b++ {
		n[b] = byte(u >> (8 * b)) // little-endian: the fastest-changing byte first
	}
	hex.Encode(buf[:16], n[:])
	buf[16] = ns
	copy(buf[17:], seqKeyTail)
	return string(buf[:])
}

// fillCache seeds a cache to exactly len(keys) entries, the first expiredFrac
// of them already expired. It writes c.entries directly: going through Set
// would trip eviction partway and leave the map in a shape the benchmark did
// not ask for.
func fillCache(keys []string, expiredFrac float64) *HashCache {
	maxSize := len(keys)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	c := New(maxSize, time.Hour)
	now := time.Now()
	nExpired := int(float64(maxSize) * expiredFrac)
	for j := 0; j < maxSize; j++ {
		expiresAt := now.Add(time.Hour)
		if j < nExpired {
			expiresAt = now.Add(-time.Minute)
		}
		c.entries[keys[j]] = &hashCacheEntry{result: res, expiresAt: expiresAt}
	}
	return c
}

// startTimedAfterGC finishes any GC cycle the setup started, then resets the
// timer. Every benchmark here seeds a cache (fillCache, or Set in a loop)
// before timing, and those allocations can leave a concurrent GC cycle running
// into the timed region. The pointer layout allocates one object per entry and
// the by-value candidate does not, so that GC would bias the layout A/B
// unevenly (Codex, PR #1604). benchEvictLocked does the same per iteration.
// In the contention benchmarks the writer keeps allocating after this point,
// and the GC it causes is part of the workload being measured.
func startTimedAfterGC(b *testing.B) {
	b.Helper()
	runtime.GC()
	b.ResetTimer()
}

// benchEvictLocked times ONE evictLocked call on a full cache. Each iteration
// needs a fresh full cache, because an evicted one is no longer at capacity.
//
// The fixture is rebuilt inside the loop with the timer stopped, so exactly one
// cache is live at a time. Building all b.N of them up front instead would
// retain b.N x maxSize entries, and b.N grows with -benchtime: at the
// -benchtime 1s suggested above that is ~2 GB for the 10 000 case and ~1.3 GB
// for the 100 000 one, which exhausts a constrained runner before the first
// timed call. The StopTimer/StartTimer pair is tiny next to an eviction over
// thousands of entries, so it does not move the figures.
//
// Building a fixture allocates maxSize entries, which can leave a concurrent
// GC cycle running into the timed call and charge its work to evictLocked
// (Codex, PR #1604). runtime.GC() after each build, with the timer stopped,
// finishes that cycle before timing starts.
func benchEvictLocked(b *testing.B, maxSize int, expiredFrac float64) {
	b.StopTimer()
	keys := keyTable("k", maxSize) // once per benchmark run, outside the b.N loop
	for i := 0; i < b.N; i++ {
		c := fillCache(keys, expiredFrac)
		runtime.GC()
		b.StartTimer()
		c.evictLocked()
		b.StopTimer()
	}
}

// The stall, by configured cache size, in the busy steady state (nothing
// expired): the cache is full and nothing has expired yet, so the sweep looks
// at every entry and finds nothing to drop. It is NOT the worst case. A full
// cache left idle past its TTL and then hit by one Set expires everything at
// once, and that costs more (AllExpired below). Its growth with cache_size
// matters because cache_size is floored by config validation and never capped.
func BenchmarkEvictLocked_NothingExpired_10k(b *testing.B)  { benchEvictLocked(b, 10_000, 0) }
func BenchmarkEvictLocked_NothingExpired_100k(b *testing.B) { benchEvictLocked(b, 100_000, 0) }

// The operator cliff the roadmap note and the evictLocked comment quote:
// cache_size: 1000000, which config validation accepts. Each iteration rebuilds
// a million-entry fixture with the timer stopped, so a run takes several
// seconds of wall time; it is skipped under -short.
func BenchmarkEvictLocked_NothingExpired_1M(b *testing.B) {
	if testing.Short() {
		b.Skip("1 000 000-entry fixture; skipped under -short")
	}
	benchEvictLocked(b, 1_000_000, 0)
}

// Eviction cost RISES with how reclaimable the cache is: a sweep that finds
// expired entries also deletes them, and at 100 % it deletes the whole map
// instead of the 25 % the capacity drop would have taken. Worth pinning so the
// relationship stays visible — it is the opposite of the intuitive direction.
//
// All-expired is the realistic WORST case: a full cache idle past its TTL,
// then one Set. The 100 000 and 1 000 000 cases exist so an idle-host run can
// bound it at larger sizes. Like the other large
// fixtures they are skipped under -short.
func BenchmarkEvictLocked_HalfExpired_10k(b *testing.B) { benchEvictLocked(b, 10_000, 0.5) }
func BenchmarkEvictLocked_AllExpired_10k(b *testing.B)  { benchEvictLocked(b, 10_000, 1.0) }

func BenchmarkEvictLocked_AllExpired_100k(b *testing.B) {
	if testing.Short() {
		b.Skip("100 000-entry all-expired fixture; skipped under -short")
	}
	benchEvictLocked(b, 100_000, 1.0)
}

func BenchmarkEvictLocked_AllExpired_1M(b *testing.B) {
	if testing.Short() {
		b.Skip("1 000 000-entry all-expired fixture; skipped under -short")
	}
	benchEvictLocked(b, 1_000_000, 1.0)
}

// Amortized Set cost at steady-state churn above capacity — the throughput
// number, as opposed to the lock-hold spike above. Every maxSize/4 inserts pay
// one eviction between them, so this is where a regression in the amortized
// shape would show. ReportAllocs covers the per-Set allocations: the key string
// and the hashCacheEntry itself. Folding the entry into the map by value
// removes one of them. It was measured, with a mixed result, and not shipped; see
// roadmap/SCAN-CACHE-EVICTION-COST.md before trying it again.
func benchChurn(b *testing.B, maxSize int) {
	c := New(maxSize, time.Hour)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	for _, k := range keyTable("k", maxSize) {
		c.Set(k, res)
	}
	b.ReportAllocs()
	startTimedAfterGC(b)
	for i := 0; i < b.N; i++ {
		c.Set(seqKey(nsChurn, i), res)
	}
}

func BenchmarkSetChurn_AtCapacity_10k(b *testing.B)  { benchChurn(b, 10_000) }
func BenchmarkSetChurn_AtCapacity_100k(b *testing.B) { benchChurn(b, 100_000) }

// Get on a hit: the path every scanned object takes before the scanners are
// consulted at all, and the path the eviction stall blocks.
func BenchmarkGet_Hit(b *testing.B) {
	keys := keyTable("k", 10_000)
	c := fillCache(keys, 0)
	hit := keys[512]
	b.ReportAllocs()
	startTimedAfterGC(b)
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get(hit); !ok {
			b.Fatal("seeded entry must hit")
		}
	}
}

func BenchmarkGet_Miss(b *testing.B) {
	c := fillCache(keyTable("k", 10_000), 0)
	absent := keyTable("absent", 1)[0] // 64 hex chars, never inserted
	b.ReportAllocs()
	startTimedAfterGC(b)
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get(absent); ok {
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
// uncontended one reads hits only. A miss is CHEAPER than a hit, so a falling
// hit rate pushes ns/op DOWN.
// The two are not a like-for-like read workload, and %hit is what lets a
// reader see by how much. Hits are
// counted in a per-goroutine local and folded in once at the end, so the
// counting costs nothing measurable inside the loop.
//
// keys is a memoized keyTable, so the measured loop indexes a prebuilt 64-hex
// key instead of formatting one per lookup.
func readParallel(b *testing.B, c *HashCache, keys []string) (hits, total int64) {
	var h, t atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		var localHits, localTotal int64
		i := 0
		for pb.Next() {
			if _, ok := c.Get(keys[i%len(keys)]); ok {
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
	keys := keyTable("k", 10_000) // built before the timer starts
	c := fillCache(keys, 0)
	b.ReportAllocs()
	startTimedAfterGC(b)
	hits, total := readParallel(b, c, keys)
	b.StopTimer()
	reportHitRate(b, hits, total)
}

// minContendedWindow is the shortest timed window in which the contention
// benchmarks require at least one writer Set to have landed: several multiples
// of the Go scheduler's 10 ms preemption slice, so a runnable writer must have
// had a turn.
const minContendedWindow = 50 * time.Millisecond

// evictingWriter is the contention benchmarks' writer goroutine. It Sets unique
// 64-hex keys into a full cache as fast as it can, so it keeps tripping
// evictLocked under the exclusive lock.
//
// Two guarantees the timed window depends on (Codex, PR #1604):
//
//   - An eviction lands INSIDE the window, not only before it. The handshake
//     Set evicts, which leaves maxSize/4 free slots. Without help, a short run
//     or a high GOMAXPROCS could time only ordinary Set locking. So, before
//     announcing ready, the writer tops the cache back up to exactly maxSize.
//     Its next Set, the first one that can land in the window, evicts.
//   - Evictions are COUNTED without touching the read path or hashcache.go.
//     The writer is the only mutator, its keys are unique and nothing expires
//     (TTL 1 h), so it tracks the map size itself. A Set at size >= maxSize
//     evicts exactly maxSize/4 entries. halt cross-checks that model against
//     the real size and fails the benchmark if they ever disagree.
type evictingWriter struct {
	stop      chan struct{}
	done      sync.WaitGroup
	writes    atomic.Int64
	evictions atomic.Int64
	size      int // owned by the writer goroutine; read only after halt's Wait
}

func startEvictingWriter(c *HashCache, maxSize int, res ScanCacheResult) *evictingWriter {
	w := &evictingWriter{stop: make(chan struct{})}
	_, _, w.size = c.Stats()
	ready := make(chan struct{})
	w.done.Add(1)
	go func() {
		defer w.done.Done()
		set := func(key string) {
			evicts := w.size >= maxSize
			c.Set(key, res)
			if evicts {
				w.size -= maxSize / 4
				w.evictions.Add(1) // counted once the evicting Set has returned
			}
			w.size++
			w.writes.Add(1)
		}
		// Land a write before the readers are timed. Without the handshake
		// the calibration call (b.N=1) can return and stop the writer before
		// it is ever scheduled.
		set(seqKey(nsWriter, 0))
		for j := 0; w.size < maxSize; j++ {
			set(seqKey(nsTopUp, j)) // top up: the next Set evicts
		}
		close(ready)
		for i := 1; ; i++ {
			select {
			case <-w.stop:
				return
			default:
			}
			set(seqKey(nsWriter, i))
		}
	}()
	<-ready
	return w
}

// halt stops the writer and waits for it, so it never outlives the benchmark
// function, then checks the eviction model. Call it with the timer stopped.
func (w *evictingWriter) halt(b *testing.B, c *HashCache) {
	b.Helper()
	close(w.stop)
	w.done.Wait()
	if _, _, n := c.Stats(); n != w.size {
		b.Fatalf("writer's eviction model drifted: model size %d, cache size %d", w.size, n)
	}
}

// assertContended reports the in-window writes and evictions and fails a run
// whose timed window was long enough to be meaningful but saw no eviction.
// Calibration passes time windows of microseconds to a few milliseconds, in
// which the writer legitimately may not be scheduled at all. With every P
// running a reader, a runnable writer can wait for the scheduler's ~10 ms
// preemption tick (observed: b.N=9512, 1.87 ms timed, 0 writes). So the
// assertion is gated on the timed duration, not on b.N.
func assertContended(b *testing.B, writes, evictions int64) {
	b.Helper()
	b.ReportMetric(float64(writes), "writes")
	b.ReportMetric(float64(evictions), "evictions")
	if b.Elapsed() >= minContendedWindow && evictions == 0 {
		b.Fatalf("no eviction inside the %v timed window (%d writes landed); the contention this benchmark measures did not happen", b.Elapsed(), writes)
	}
}

// Readers contending with a writer that keeps tripping eviction — the shape
// that makes the lock hold a system-wide cost rather than a local one.
//
// Read %hit against BenchmarkGet_Parallel's before drawing a ratio from the
// two. The writer runs for the whole benchmark and each eviction drops 25 % of
// the map, so the seeded keys are steadily displaced by the writer's own keys.
// This benchmark therefore reads far fewer hits than the uncontended one, and
// fewer the longer it runs. Because a miss is cheaper than a hit, the changed
// mix makes the contended side cheaper per read. The pair cannot isolate
// contention, so use the miss-only control below. The roadmap note records
// what earlier runs saw, labelled as historical.
//
// Reader throughput is what a bounded eviction would be trying to protect, so
// this is the benchmark to re-read if that follow-up is attempted.
func BenchmarkGet_ParallelDuringEviction(b *testing.B) {
	const maxSize = 10_000
	keys := keyTable("k", maxSize) // built before the timer starts
	c := fillCache(keys, 0)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	w := startEvictingWriter(c, maxSize, res)

	// Count writes and evictions that land INSIDE the timed window. The
	// counters are sampled immediately either side of RunParallel, so the
	// only ones they can misattribute are those landing in the statement
	// between the sample and the first/last read. Proving overlap exactly
	// would need the readers to observe writer progress, and a shared atomic
	// in the measured read path would distort the ns/op this benchmark exists
	// to report (CodeRabbit minor, PR #1604). The count is evidence, not proof.
	b.ReportAllocs()
	startTimedAfterGC(b)
	writesBefore, evictionsBefore := w.writes.Load(), w.evictions.Load()
	hits, total := readParallel(b, c, keys)
	landed, evicted := w.writes.Load()-writesBefore, w.evictions.Load()-evictionsBefore
	b.StopTimer()
	w.halt(b, c)

	reportHitRate(b, hits, total)
	assertContended(b, landed, evicted)
}

// ── Like-for-like contention control ────────────────────────────────────────
//
// The pair above cannot isolate lock contention, because the writer displaces
// the seeded keys and so the contended run reads a different keyspace from the
// uncontended one. These two pin BOTH sides to a keyspace nothing ever inserts
// (namespace "m", which neither fillCache's "k" keys nor the writer's "w" keys
// ever use), so every lookup
// is a guaranteed MISS and the read workload is identical with and without the
// writer. The delta between them is then attributable to the writer rather than
// to a shifting hit rate (construction suggested by CodeRabbit, PR #1604).
//
// Read it as a control, not as a replacement: it measures the MISS path, which
// is cheaper than the hit path the scanners actually take, and the writer's
// cost here is eviction plus ordinary Set work, not eviction alone. No ratio
// from it is established yet; the roadmap note records the historical runs.
// Re-run it on an idle host before quoting one.

// benchMissOnlyParallel reads a never-inserted keyspace on every core, with an
// eviction-tripping writer when withWriter is set. %hit must be 0 in both.
func benchMissOnlyParallel(b *testing.B, withWriter bool) {
	const maxSize = 10_000
	c := fillCache(keyTable("k", maxSize), 0)
	keys := keyTable("m", maxSize) // never inserted; built before the timer starts
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}

	var w *evictingWriter
	if withWriter {
		w = startEvictingWriter(c, maxSize, res)
	}

	b.ReportAllocs()
	startTimedAfterGC(b)
	var writesBefore, evictionsBefore int64
	if w != nil {
		writesBefore, evictionsBefore = w.writes.Load(), w.evictions.Load()
	}
	hits, total := readParallel(b, c, keys) // namespace "m" is never inserted
	var landed, evicted int64
	if w != nil {
		landed, evicted = w.writes.Load()-writesBefore, w.evictions.Load()-evictionsBefore
	}
	b.StopTimer()
	if w != nil {
		w.halt(b, c)
	}

	reportHitRate(b, hits, total)
	if hits != 0 {
		b.Fatalf("control benchmark must read only misses, got %d hits", hits)
	}
	if w != nil {
		assertContended(b, landed, evicted)
	}
}

func BenchmarkGet_ParallelMissOnly(b *testing.B) { benchMissOnlyParallel(b, false) }
func BenchmarkGet_ParallelMissOnlyDuringEviction(b *testing.B) {
	benchMissOnlyParallel(b, true)
}
