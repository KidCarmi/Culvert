package main

// metrics_rulehit_bench_test.go — evidence for the lock-free per-rule hit
// counter (ruleMetrics.RecordHit, metrics.go).
//
// RecordHit runs once per proxied request that matches a policy rule
// (applyPolicyDecision, proxy.go). In the Zero-Trust posture Culvert ships
// that is every allowed request, so its fixed cost is paid on 100% of served
// traffic.
//
// BenchmarkRuleHit_Locked below runs the VERBATIM pre-fix body against the same
// data in the same binary, so the comparison needs no checkout of the parent
// commit and stays reproducible as the machine changes.
//
// Run:
//
//	go test -run '^$' -bench 'RuleHit' -benchmem -cpu=1,2,4 -count=7 .
//
// Measured (linux/amd64, Intel Xeon @ 2.80GHz, go1.26, 20 registered rules,
// -benchtime=1s, medians of -count=7). RunParallel reports wall-clock ns per
// op, so ops/s is 1e9/ns regardless of core count:
//
//	                  GOMAXPROCS=1        =2                =4
//	  Locked (before)  105 ns  9.51M   218 ns  4.58M   207 ns  4.84M
//	  View   (after)   103 ns  9.72M    77 ns 13.01M    60 ns 16.61M
//	                    ±0%             -65%            -71%
//
// The finding is the SHAPE, not the multiplier. Before the change, adding
// cores SUBTRACTED throughput: four cores delivered 4.84M ops/s against 9.51M
// on ONE core — 0.51x. sync.RWMutex.RLock is an atomic read-modify-write on
// ONE shared word, so every request in the process wrote the same cache line
// purely to read an index that in steady state never changes, and each losing
// core's retry generated the coherence traffic that made the next round lose.
// After the change four cores buy 1.71x one core (3.4x the old four-core
// ceiling), and the gap widens on the 16/32-core hardware the appliance ships
// to.
//
// The single-core column is unchanged (105 → 103 ns), so there is no
// low-concurrency price for the win at scale.
//
// The residual non-linearity after the fix is NOT the lock: it is the counter
// cell itself. Several cores incrementing the SAME int64 is real coherence
// traffic, and that is irreducible here — the cell IS the metric. Sharding it
// the way the latency histogram was sharded is deliberately NOT done: the
// histogram's accumulator is written by 100% of requests, whereas a rule's
// counter is already split across the rulebase, so the same 128-shard padding
// would cost 200 rules' worth of cache lines to relieve a fraction of the
// pressure. That is a separate concern with a much worse cost/benefit.
//
// Both shapes are 0 allocs/op; this was never an allocation finding.

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// benchRuleNames registers n rule names on rm and returns them.
func benchRuleNames(rm *ruleMetrics, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = "bench-rule-" + strconv.Itoa(i)
		rm.RecordHit(names[i])
	}
	return names
}

// benchRuleHitRounds drives one RecordHit-shaped call per iteration, cycling
// through the registered names so the map probe is not served from one hot key.
func benchRuleHitRounds(b *testing.B, names []string, hit func(string)) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hit(names[i%len(names)])
			i++
		}
	})
}

// BenchmarkRuleHit_View is the shipped path.
func BenchmarkRuleHit_View(b *testing.B) {
	rm := newRuleMetrics()
	names := benchRuleNames(rm, 20)
	benchRuleHitRounds(b, names, rm.RecordHit)
}

// BenchmarkRuleHit_Locked is the pre-fix body, kept in-tree so the comparison
// above is reproducible. It is NOT reachable from production code.
func BenchmarkRuleHit_Locked(b *testing.B) {
	lrm := newLockedRuleMetrics()
	names := make([]string, 20)
	for i := range names {
		names[i] = "bench-rule-" + strconv.Itoa(i)
		lrm.recordHit(names[i])
	}
	benchRuleHitRounds(b, names, lrm.recordHit)
}

// BenchmarkRuleHit_IndexCopyAtCap measures the whole cost of the cold path: the
// index copy a first-hit registration pays under the write lock, at the worst
// cardinality the cap allows. Registration runs at most maxRuleMetrics (200)
// times per process, so this cost is bounded by construction — the benchmark
// exists to show the copy-on-write price is small and not pathological, not
// because the number is on any hot path.
//
// Measured at the cap: 24.6 µs, 16.6 KB, 7 allocs per copy — so registering a
// FULL 200-rule rulebase costs on the order of 5 ms of one-time work spread
// over the process lifetime, against a per-request saving on 100% of traffic.
func BenchmarkRuleHit_IndexCopyAtCap(b *testing.B) {
	rm := newRuleMetrics()
	benchRuleNames(rm, maxRuleMetrics)
	full := rm.view()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink := full.clone()
		if len(sink.hits) != maxRuleMetrics {
			b.Fatalf("clone lost entries: %d", len(sink.hits))
		}
	}
}

// ── The pre-fix implementation, frozen ──────────────────────────────────────

// lockedRuleMetrics reproduces the RWMutex-guarded index RecordHit used before
// the view. Kept verbatim so BenchmarkRuleHit_Locked measures the real thing.
type lockedRuleMetrics struct {
	mu    sync.RWMutex
	hits  map[string]*int64
	last  map[string]*int64
	order []string
}

func newLockedRuleMetrics() *lockedRuleMetrics {
	return &lockedRuleMetrics{hits: make(map[string]*int64), last: make(map[string]*int64)}
}

func (rm *lockedRuleMetrics) recordHit(ruleName string) {
	if ruleName == "" {
		return
	}
	now := time.Now().Unix()
	rm.mu.RLock()
	ctr, ok := rm.hits[ruleName]
	lastPtr := rm.last[ruleName]
	rm.mu.RUnlock()
	if ok {
		atomic.AddInt64(ctr, 1)
		if lastPtr != nil {
			atomicStoreMax(lastPtr, now)
		}
		return
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if ctr, ok = rm.hits[ruleName]; ok {
		atomic.AddInt64(ctr, 1)
		if lp := rm.last[ruleName]; lp != nil {
			atomicStoreMax(lp, now)
		}
		return
	}
	if len(rm.hits) >= maxRuleMetrics {
		return
	}
	v := int64(1)
	rm.hits[ruleName] = &v
	lv := now
	rm.last[ruleName] = &lv
	rm.order = append(rm.order, ruleName)
}
