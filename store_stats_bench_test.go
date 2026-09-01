package main

// store_stats_bench_test.go — benchmarks + deterministic regression gate for
// the per-request stats accounting hot path (recordStats). Every proxied
// request — HTTP, CONNECT, WebSocket, SOCKS5 — runs tsRecordResult, and every
// allowed request additionally runs topHosts.Record, so both are global
// serialization points on 100% of traffic. The benchmarks measure the
// steady-state cases those requests actually hit: an already-tracked host and
// a same-minute bucket increment. The parallel variants expose lock
// contention, the way BenchmarkAddParallel does for the reqlog ring.
//
// Measured outcome (4-core, 2026-07): converting topHosts.Record to
// RLock+atomic cut the parallel tracked-host path 363→124 ns/op (2.9x) —
// counters for different hosts live on different cache lines, so atomic adds
// parallelize. The same conversion for tsRecordResult measured FLAT (~154
// ns/op both ways), and was read at the time as "every request bumps the SAME
// current-minute bucket, so the shared cache line, not the mutex, is the
// bound".
//
// That reading was half right and it is why these benchmarks must be run
// ACROSS CORE COUNTS, not at one. RWMutex cannot help a path that mutates, so
// the flat result said nothing about the bound; and the shared cache line is
// only inherent while the counter stays shared. Sharding the current minute
// (2026-09, store.go) took tsRecordResult from 172.6 → 38.7 ns/op at
// GOMAXPROCS=4 with no cost at GOMAXPROCS=1, and the full recordStats fan-out
// from 275.8 → 131.6 ns/op. The ceiling, not the constant, is the thing these
// benchmarks exist to expose:
//
//	                        │ -cpu=1 │ -cpu=2 │ -cpu=4 │
//	tsRecordResult   before │  87.4  │   —    │ 172.6  │  cores SUBTRACTED throughput
//	tsRecordResult    after │  87.6  │  66.3  │  38.7  │
//	recordStats      before │ 142.9  │   —    │ 275.8  │
//	recordStats       after │ 136.4  │ 163.9  │ 131.6  │
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkTopHosts|BenchmarkTSRecord|BenchmarkRecordStats' -benchmem -cpu=1,2,4 .

import (
	"fmt"
	"testing"
)

// benchHostCounter returns a counter pre-filled with n tracked hosts, so
// Record measures the steady-state already-tracked path — the case ~all
// production traffic hits (the distinct-host working set repeats heavily).
func benchHostCounter(n int) *hostCounter {
	hc := freshHostCounter()
	for _, h := range benchHostNames(n) {
		hc.Record(h)
	}
	return hc
}

// benchHostNames precomputes the working-set hostnames so the timed loops
// index a slice instead of calling fmt.Sprintf per iteration (which would
// fold formatting + allocator contention into the measurement).
func benchHostNames(n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("host-%d.example.com", i)
	}
	return names
}

// BenchmarkTopHostsRecord_Hit measures the serial cost of counting one
// request against an already-tracked host.
func BenchmarkTopHostsRecord_Hit(b *testing.B) {
	hc := benchHostCounter(512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hc.Record("host-7.example.com")
	}
}

// BenchmarkTopHostsRecord_HitParallel measures the tracked-host path under
// concurrent request goroutines — the production shape: many in-flight
// requests, a hot working set of repeated hosts.
func BenchmarkTopHostsRecord_HitParallel(b *testing.B) {
	hc := benchHostCounter(512)
	hosts := benchHostNames(512)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			hc.Record(hosts[i%512])
			i++
		}
	})
}

// BenchmarkTSRecordResult measures the serial cost of the per-request
// time-series bucket increment (same-minute steady state).
func BenchmarkTSRecordResult(b *testing.B) {
	tsRecordResult(true) // arm lastMin so the loop measures the same-minute path
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tsRecordResult(i%8 != 0)
	}
}

// BenchmarkTSRecordResultParallel measures the bucket increment under
// concurrent request goroutines.
func BenchmarkTSRecordResultParallel(b *testing.B) {
	tsRecordResult(true)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tsRecordResult(true)
		}
	})
}

// BenchmarkRecordStatsAllowedParallel measures the full per-request stats
// fan-out for the dominant traffic class (an allowed request): statTotal,
// the time-series bucket, and the top-hosts counter, under concurrency.
// Uses the package globals — exactly what handleRequest exercises.
func BenchmarkRecordStatsAllowedParallel(b *testing.B) {
	hosts := benchHostNames(512)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			recordStats("203.0.113.7", hosts[i%512], "OK", "allow-rule", "Allow")
			i++
		}
	})
}

// TestStatsHotPath_ZeroAllocSteadyState is the deterministic regression gate
// for the stats hot path (mirrors reqlog's TestAdd_ZeroAllocSteadyState):
// counting a request against an already-tracked host and bumping the
// same-minute time-series bucket must not allocate. Allocation counts are
// hardware-independent, so this fails on any runner if a per-request
// allocation sneaks into recordStats' accounting.
func TestStatsHotPath_ZeroAllocSteadyState(t *testing.T) {
	hc := freshHostCounter()
	hc.Record("hot.example.com")
	if allocs := testing.AllocsPerRun(1000, func() { hc.Record("hot.example.com") }); allocs != 0 {
		t.Errorf("REGRESSION: topHosts.Record allocates %.1f/op on the tracked-host path, want 0", allocs)
	}

	tsRecordResult(true) // arm lastMin
	if allocs := testing.AllocsPerRun(1000, func() { tsRecordResult(true) }); allocs != 0 {
		t.Errorf("REGRESSION: tsRecordResult allocates %.1f/op on the same-minute path, want 0", allocs)
	}
}
