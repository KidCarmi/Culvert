package reqlog

// clock_bench_test.go — the render in isolation. The full per-request record
// build is measured from package main (store_logclock_bench_test.go), which
// also records the before/after figures.
//
// Run locally:
//
//	go test -run '^$' -bench 'BenchmarkLogClockStamp' -benchmem ./internal/reqlog

import (
	"testing"
	"time"
)

// BenchmarkLogClockStamp measures the steady-state render — the case ~all
// production traffic hits, since any rate above 1 req/s produces repeated
// calls inside the same wall-clock second.
func BenchmarkLogClockStamp(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = Stamp(time.Now())
	}
	_ = s
}

// BenchmarkLogClockStampFormat is the pre-change baseline it replaces, kept so
// the delta stays reproducible on any runner rather than only in a comment.
func BenchmarkLogClockStampFormat(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = time.Now().Format(TimeLayout)
	}
	_ = s
}

// BenchmarkLogClockStampParallel exposes any contention the memo introduces.
// Readers take a single atomic pointer load, so the expectation is that it
// scales; a regression here would mean the cache line has become a bottleneck.
func BenchmarkLogClockStampParallel(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = Stamp(time.Now())
		}
	})
}
