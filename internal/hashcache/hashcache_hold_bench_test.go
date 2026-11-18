package hashcache

import (
	"sort"
	"testing"
	"time"
)

// benchSetIntoFull measures what a reader actually waits behind: the
// exclusive-lock hold of each Set into a cache that is ALREADY FULL, starting
// from a fixture whose first expiredFrac entries have already expired.
//
// It uses only the public API, so the identical workload runs against any
// eviction design (the fixture's expired entries are written with SetTTL and a
// 1 ns lifetime, which is expired by the time timing starts). ns/op is the
// amortized Set cost; max-hold-ns and p999-hold-ns are the worst and 99.9th
// percentile single Set over the run, i.e. the longest any concurrent Get can
// have been stalled by one writer. Each Set is timed individually, so ns/op
// includes ~2 clock reads on every design alike.
//
// The fixture is built once per benchmark run and the timed loop never refills
// it: every design keeps the cache at capacity under unique-key churn, so the
// first Set evicts and every later one runs at capacity too.
func benchSetIntoFull(b *testing.B, maxSize int, expiredFrac float64) {
	c := New(maxSize, time.Hour)
	res := ScanCacheResult{Clean: true, Source: "clean", ScannedAt: time.Now()}
	nExpired := int(float64(maxSize) * expiredFrac)
	for j, k := range keyTable("k", maxSize) {
		if j < nExpired {
			c.SetTTL(k, res, time.Nanosecond)
		} else {
			c.Set(k, res)
		}
	}
	time.Sleep(time.Millisecond) // the 1 ns entries are now unambiguously expired
	holds := make([]int64, 0, min(b.N, 1<<20))
	b.ReportAllocs()
	startTimedAfterGC(b)
	var next uint64
	var maxHold int64
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		c.Set(seqKey(nsChurn, next), res)
		d := int64(time.Since(t0))
		next++
		if d > maxHold {
			maxHold = d
		}
		if len(holds) < cap(holds) {
			holds = append(holds, d)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(maxHold), "max-hold-ns")
	if len(holds) > 0 {
		sort.Slice(holds, func(i, j int) bool { return holds[i] < holds[j] })
		b.ReportMetric(float64(holds[len(holds)*999/1000]), "p999-hold-ns")
	}
	if _, _, n := c.Stats(); n > maxSize {
		b.Fatalf("cache grew past its bound: %d > %d", n, maxSize)
	}
}

func BenchmarkSetIntoFull_NothingExpired_10k(b *testing.B)  { benchSetIntoFull(b, 10_000, 0) }
func BenchmarkSetIntoFull_NothingExpired_100k(b *testing.B) { benchSetIntoFull(b, 100_000, 0) }
func BenchmarkSetIntoFull_AllExpired_100k(b *testing.B)     { benchSetIntoFull(b, 100_000, 1) }

// The operator cliff: cache_size is floored but never capped.
func BenchmarkSetIntoFull_NothingExpired_1M(b *testing.B) {
	if testing.Short() {
		b.Skip("1 000 000-entry fixture; skipped under -short")
	}
	benchSetIntoFull(b, 1_000_000, 0)
}

func BenchmarkSetIntoFull_AllExpired_1M(b *testing.B) {
	if testing.Short() {
		b.Skip("1 000 000-entry fixture; skipped under -short")
	}
	benchSetIntoFull(b, 1_000_000, 1)
}
