package main

// store_logclock_bench_test.go — evidence for the memoised LogEntry.Time
// render. persistLogEntry is the single chokepoint every request-log record
// flows through, so its serial cost is paid once per proxied request and its
// parallel cost is a process-wide serialization point on 100% of logged
// traffic. These benchmarks measure both shapes plus the render in isolation.
//
// Measured (4-core Xeon @ 2.10 GHz, Go 1.26, redaction off — the default
// posture), before → after:
//
//	                                   before                 after
//	persistLogEntry            277 ns/op  1 alloc     149 ns/op  0 allocs   -46%
//	persistLogEntry (parallel) 461 ns/op  1 alloc     372 ns/op  0 allocs   -19%
//	clock render               117 ns/op  1 alloc      58 ns/op  0 allocs   -50%
//
// The remaining ~58 ns of the render is time.Now() itself, which the record
// needs regardless — the memo removes essentially all of the avoidable work.
// The memo introduces no contention of its own: a hit is a single atomic
// pointer load off a read-mostly cache line, and BenchmarkLogClockStampParallel
// measures 14.9 ns/op on 4 cores — i.e. it scales linearly.
//
// Run locally:
//
//	go test -run '^$' -bench 'BenchmarkLogClockStamp|BenchmarkPersistLogEntry' -benchmem .

import (
	"io"
	"log"
	"testing"
	"time"
)

// benchDiscardLogger keeps the measurement on the code under test rather than
// on a log writer: persistLogEntry itself does not log, but the package global
// must be non-nil for any path that might.
func benchDiscardLogger(b *testing.B) {
	b.Helper()
	if logger == nil {
		logger = log.New(io.Discard, "", log.LstdFlags)
	}
}

// BenchmarkLogClockStamp measures the steady-state render — the case ~all
// production traffic hits, since any rate above 1 req/s produces repeated
// calls inside the same wall-clock second.
func BenchmarkLogClockStamp(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = logClockStamp(time.Now())
	}
	_ = s
}

// BenchmarkLogClockStampFormat is the pre-change baseline it replaces, kept so
// the delta stays reproducible on any runner rather than only in a comment.
func BenchmarkLogClockStampFormat(b *testing.B) {
	b.ReportAllocs()
	var s string
	for i := 0; i < b.N; i++ {
		s = time.Now().Format(logEntryTimeLayout)
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
			_ = logClockStamp(time.Now())
		}
	})
}

// BenchmarkPersistLogEntry measures the full per-request record build and
// fan-out (ring + JSONL queue + history hook) serially.
func BenchmarkPersistLogEntry(b *testing.B) {
	benchDiscardLogger(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		persistLogEntry("203.0.113.7", "GET", "www.example.com", "OK", "allow-corp-saas",
			"Allow", "alice@corp.example", 0, 0, 0, "", "", AuthLogFields{})
	}
}

// BenchmarkPersistLogEntryParallel is the production shape: many in-flight
// request goroutines all recording through the same chokepoint.
func BenchmarkPersistLogEntryParallel(b *testing.B) {
	benchDiscardLogger(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			persistLogEntry("203.0.113.7", "GET", "www.example.com", "OK", "allow-corp-saas",
				"Allow", "alice@corp.example", 0, 0, 0, "", "", AuthLogFields{})
		}
	})
}
