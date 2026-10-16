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
// gateway holds: on the same host, 64-byte keys raised AllExpired_10k from
// ~0.67 ms to ~0.84 ms (Codex, PR #1604). Every key these benchmarks insert or
// look up is therefore 64 hex characters.
//
// Fixture and reader keys are real SHA256Hex digests, built once per namespace
// and memoized. The table only ever grows to the largest fixture size (1 000 000
// entries, ~80 MB), so what is retained is bounded by the benchmark matrix,
// never by b.N. Keys minted INSIDE a timed loop (churn inserts, the contention
// writer) cannot afford a SHA-256 each, so seqKey builds a 64-hex key of the
// same length and alphabet from a counter. The counter goes in the leading
// characters so that keys differ early, as digests do.

var (
	keyTablesMu sync.Mutex
	keyTables   = map[string][]string{}
)

// keyTable returns SHA256Hex(ns + i) for i in [0, n), memoized per namespace.
func keyTable(ns string, n int) []string {
	keyTablesMu.Lock()
	defer keyTablesMu.Unlock()
	t := keyTables[ns]
	for i := len(t); i < n; i++ {
		t = append(t, SHA256Hex([]byte(ns+strconv.Itoa(i))))
	}
	keyTables[ns] = t
	return t[:n]
}

// seqKey returns a 64-hex-character key for counter i in namespace ns: the 16
// hex digits of i, then 48 characters of SHA256Hex(ns). One allocation, no
// hashing, so it is cheap enough for a timed loop.
func seqKey(ns string, i int) string {
	var buf [64]byte
	var n [8]byte
	u := uint64(i)
	for b := 0; b < 8; b++ {
		n[b] = byte(u >> (8 * b)) // little-endian: the fastest-changing byte first
	}
	hex.Encode(buf[:16], n[:])
	copy(buf[16:], seqKeySuffix(ns))
	return string(buf[:])
}

var seqSuffixes sync.Map // ns -> string (48 hex chars)

func seqKeySuffix(ns string) string {
	if v, ok := seqSuffixes.Load(ns); ok {
		return v.(string)
	}
	v, _ := seqSuffixes.LoadOrStore(ns, SHA256Hex([]byte("seq:" + ns))[:48])
	return v.(string)
}

// fillCache seeds a cache to exactly maxSize entries, the first expiredFrac of
// them already expired, keyed by keyTable("k", maxSize). It writes c.entries
// directly: going through Set would trip eviction partway and leave the map in
// a shape the benchmark did not ask for.
func fillCache(maxSize int, expiredFrac float64) *HashCache {
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	c := New(maxSize, time.Hour)
	now := time.Now()
	nExpired := int(float64(maxSize) * expiredFrac)
	keys := keyTable("k", maxSize)
	for j := 0; j < maxSize; j++ {
		expiresAt := now.Add(time.Hour)
		if j < nExpired {
			expiresAt = now.Add(-time.Minute)
		}
		c.entries[keys[j]] = &hashCacheEntry{result: res, expiresAt: expiresAt}
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
// 0.5 ms-300 ms, so it does not move the figures.
//
// Building a fixture allocates maxSize entries, which can leave a concurrent
// GC cycle running into the timed call and charge its work to evictLocked
// (Codex, PR #1604). runtime.GC() after each build, with the timer stopped,
// finishes that cycle before timing starts.
func benchEvictLocked(b *testing.B, maxSize int, expiredFrac float64) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		c := fillCache(maxSize, expiredFrac)
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
// then one Set. At 10 000 it measured ~0.94 ms against 0.54 ms with nothing
// expired. The 100 000 and 1 000 000 cases exist so an idle-host run can bound
// it at larger sizes; no figure from them is quoted yet. Like the other large
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
// removes one of them and was measured — it is NOT a win overall; see
// roadmap/SCAN-CACHE-EVICTION-COST.md before trying it again.
func benchChurn(b *testing.B, maxSize int) {
	c := New(maxSize, time.Hour)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	for _, k := range keyTable("k", maxSize) {
		c.Set(k, res)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set(seqKey("n", i), res)
	}
}

func BenchmarkSetChurn_AtCapacity_10k(b *testing.B)  { benchChurn(b, 10_000) }
func BenchmarkSetChurn_AtCapacity_100k(b *testing.B) { benchChurn(b, 100_000) }

// Get on a hit: the path every scanned object takes before the scanners are
// consulted at all, and the path the eviction stall blocks.
func BenchmarkGet_Hit(b *testing.B) {
	c := fillCache(10_000, 0)
	hit := keyTable("k", 10_000)[512]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Get(hit); !ok {
			b.Fatal("seeded entry must hit")
		}
	}
}

func BenchmarkGet_Miss(b *testing.B) {
	c := fillCache(10_000, 0)
	absent := keyTable("absent", 1)[0] // 64 hex chars, never inserted
	b.ReportAllocs()
	b.ResetTimer()
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
// uncontended one reads hits only. A miss is CHEAPER than a hit (roughly 38 ns
// against 124 ns with 64-hex keys), so a falling hit rate pushes ns/op DOWN.
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
	c := fillCache(10_000, 0)
	keys := keyTable("k", 10_000) // built before the timer starts
	b.ReportAllocs()
	b.ResetTimer()
	hits, total := readParallel(b, c, keys)
	b.StopTimer()
	reportHitRate(b, hits, total)
}

// minContendedWindow is the shortest timed window in which the contention
// benchmarks require at least one writer Set to have landed: several multiples
// of the Go scheduler's 10 ms preemption slice, so a runnable writer must have
// had a turn.
const minContendedWindow = 50 * time.Millisecond

// Readers contending with a writer that keeps tripping eviction — the shape
// that makes the lock hold a system-wide cost rather than a local one.
//
// Read %hit against BenchmarkGet_Parallel's before drawing a ratio from the two.
// The writer runs for the whole benchmark, and each Set it lands at capacity
// evicts 25 % of the map, so the seeded keys are steadily displaced by the
// writer's own keys: measured, this reads only **a few percent hits** against
// the uncontended benchmark's 100 % (a median 6.6 % at -benchtime 300ms with
// 64-hex keys; the superseded short-key runs read 4.7 % at 500ms and 1.4 % at
// 1s), falling as the run lengthens and the writer displaces more. (An earlier
// revision of this comment guessed ~75 % from the first eviction alone; the
// %hit metric exists because that guess was wrong by more than an order of
// magnitude.) The pair therefore cannot isolate contention.
//
// The changed mix makes the contended side CHEAPER per read, since misses cost
// ~38 ns against a hit's ~124 ns. In the short-key runs it was still ~3x
// slower despite that. In the 64-hex-key A/B on an oversubscribed host it was
// faster (95 ns against 174 ns), so this pair proves nothing about contention
// by itself. Use the miss-only control below, on an idle host.
//
// Reader throughput is what a bounded eviction would be trying to protect, so
// this is the benchmark to re-read if that follow-up is attempted. The pre-fix
// A/B of the rejected layout change reported this case 13 % WORSE. That run
// used the fixture-retention harness that has since been corrected, and the
// corrected A/Bs show no significant change (p=0.083 with short keys, p=0.328
// with 64-hex keys; roadmap/SCAN-CACHE-EVICTION-COST.md).
func BenchmarkGet_ParallelDuringEviction(b *testing.B) {
	const maxSize = 10_000
	c := fillCache(maxSize, 0)
	keys := keyTable("k", maxSize) // built before the timer starts
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}

	stop := make(chan struct{})
	ready := make(chan struct{})
	var writes atomic.Int64
	go func() {
		// Land the first write BEFORE the readers are timed, and announce it.
		// Without the handshake the calibration call (b.N=1) returns and closes
		// stop before this goroutine is ever scheduled, so the benchmark would
		// measure uncontended reads and then fail on the assertion below.
		c.Set(seqKey("w", 0), res)
		writes.Add(1)
		close(ready)
		for i := 1; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c.Set(seqKey("w", i), res)
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
	hits, total := readParallel(b, c, keys)
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
// (namespace "m", which neither fillCache's "k" keys nor the writer's "w" keys
// ever use), so every lookup
// is a guaranteed MISS and the read workload is identical with and without the
// writer. The delta between them is then attributable to the writer rather than
// to a shifting hit rate (construction suggested by CodeRabbit, PR #1604).
//
// Read it as a control, not as a replacement: it measures the MISS path, which
// is cheaper than the hit path the scanners actually take, and the writer's
// cost here is eviction plus ordinary Set work, not eviction alone. With short
// keys it showed a 2.0-2.7x slowdown. The 64-hex-key run, on a ~3x
// oversubscribed host, showed only a 1.26x median with heavily overlapping
// ranges, which does not establish one (roadmap/SCAN-CACHE-EVICTION-COST.md).
// Re-run it on an idle host before quoting a ratio.

// benchMissOnlyParallel reads a never-inserted keyspace on every core, with an
// eviction-tripping writer when withWriter is set. %hit must be 0 in both.
func benchMissOnlyParallel(b *testing.B, withWriter bool) {
	const maxSize = 10_000
	c := fillCache(maxSize, 0)
	keys := keyTable("m", maxSize) // never inserted; built before the timer starts
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}

	stop := make(chan struct{})
	var writes atomic.Int64
	if withWriter {
		ready := make(chan struct{})
		go func() {
			c.Set(seqKey("w", 0), res)
			writes.Add(1)
			close(ready)
			for i := 1; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				c.Set(seqKey("w", i), res)
				writes.Add(1)
			}
		}()
		<-ready
	}

	b.ReportAllocs()
	b.ResetTimer()
	writesBefore := writes.Load()
	hits, total := readParallel(b, c, keys) // namespace "m" is never inserted
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
