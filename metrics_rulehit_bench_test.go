package main

// metrics_rulehit_bench_test.go — the before/after evidence for the lock-free
// per-rule hit counter read path (ruleMetrics.view, metrics.go).
//
// ruleMet.RecordHit runs on EVERY proxied request that matched a policy rule, so
// its scaling in core count is the number that matters, not its cost at
// GOMAXPROCS=1.
//
// The pre-view shape is FROZEN here as legacyRuleMetrics so the comparison stays
// reproducible in-tree and — more importantly — so both variants are measured in
// the SAME process under the SAME machine load. Absolute ns/op on a shared or
// virtualised runner drifts by 2x between runs; the legacy/view RATIO within one
// run does not. This mirrors BenchmarkHTTPForward_LegacyClientPerRequest.
//
//	go test -run '^$' -bench BenchmarkRecordHit -cpu=1,2,4 -count=11 .
//
// Measured medians are recorded on the ruleCounter block comment in metrics.go.

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// legacyRuleMetrics is the VERBATIM pre-view RecordHit shape, kept only so the
// before/after comparison runs against the same machine load in one process.
type legacyRuleMetrics struct {
	mu    sync.RWMutex
	hits  map[string]*int64
	last  map[string]*int64
	order []string
}

func (rm *legacyRuleMetrics) RecordHit(ruleName string) {
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
	if ctr, ok := rm.hits[ruleName]; ok {
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

func benchNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = "rule-" + strconv.Itoa(i)
	}
	return names
}

func benchViewRM() *ruleMetrics {
	rm := &ruleMetrics{
		hits: make(map[string]*int64), last: make(map[string]*int64),
		byID: make(map[string]persistedRuleCounter), loadedByName: make(map[string]persistedRuleCounter),
		appliedByName: make(map[string]int64),
	}
	for _, n := range benchNames(50) {
		rm.RecordHit(n)
	}
	return rm
}

func benchLegacyRM() *legacyRuleMetrics {
	rm := &legacyRuleMetrics{hits: make(map[string]*int64), last: make(map[string]*int64)}
	for _, n := range benchNames(50) {
		rm.RecordHit(n)
	}
	return rm
}

// Spread across 50 distinct rules: 50 distinct counters, so no two requests
// share a counter cache line. This ISOLATES the shared lock from the shared
// counter.
func BenchmarkRecordHit_Spread_Legacy(b *testing.B) {
	rm, names := benchLegacyRM(), benchNames(50)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rm.RecordHit(names[i%len(names)])
			i++
		}
	})
}

func BenchmarkRecordHit_Spread_View(b *testing.B) {
	rm, names := benchViewRM(), benchNames(50)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rm.RecordHit(names[i%len(names)])
			i++
		}
	})
}

// All traffic on ONE rule: the realistic "one hot allow rule" shape. The shared
// counter cache line remains in BOTH variants — that cost is inherent.
func BenchmarkRecordHit_Hot_Legacy(b *testing.B) {
	rm := benchLegacyRM()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rm.RecordHit("rule-7")
		}
	})
}

func BenchmarkRecordHit_Hot_View(b *testing.B) {
	rm := benchViewRM()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rm.RecordHit("rule-7")
		}
	})
}
