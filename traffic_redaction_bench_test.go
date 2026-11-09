package main

import (
	"sync/atomic"
	"testing"
)

// traffic_redaction_bench_test.go — root-side benchmarks and the recordStats benchgate
// for the destination pseudonymizer. The engine's correctness wall (reference-HMAC
// oracle, key fence, concurrency) and its alloc benchgate moved with the engine to
// internal/pseudonym (ADR-0044); these exercise the root wrappers and the fan-out.

func benchTrafficPostureOn(b *testing.B) {
	b.Helper()
	prevKey := getTrafficPseudonymKey()
	prevOn := decRedactHosts()
	setTrafficPseudonymKey([]byte(testTrafficKey))
	setDecRedactHosts(true)
	b.Cleanup(func() { setDecRedactHosts(prevOn); setTrafficPseudonymKey(prevKey) })
}

func BenchmarkPseudonymizeHost(b *testing.B) {
	benchTrafficPostureOn(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchTokenSink = pseudonymizeHost("cdn.example.com:443")
	}
}

// BenchmarkPseudonymizeHostParallel is the contention benchmark: the pool must scale
// with cores rather than serialize. This is the shape production sees — many request
// goroutines pseudonymizing concurrently.
//
// The sink is deliberately goroutine-LOCAL inside the timed loop, published once per
// worker afterwards. A shared package-level sink would be both a data race under
// `go test -race -bench` and — worse for a benchmark whose whole job is to measure
// scaling — a shared cache line that every worker writes on every iteration, so it
// would report the cost of false sharing rather than the cost of the pool.
func BenchmarkPseudonymizeHostParallel(b *testing.B) {
	benchTrafficPostureOn(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var local string
		for pb.Next() {
			local = pseudonymizeHost("cdn.example.com:443")
		}
		benchTokenSinkParallel.Store(&local) // one synchronized publish per worker
	})
}

// BenchmarkRecordStats measures the full per-request stats fan-out with the posture ON
// vs OFF — the OFF arm is the "feature costs nothing when unused" guarantee, the ON arm
// is what the pooling plus the recordStats de-duplication improve.
func BenchmarkRecordStats(b *testing.B) {
	b.Run("posture_on", func(b *testing.B) {
		benchTrafficPostureOn(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow")
		}
	})
	b.Run("posture_off", func(b *testing.B) {
		prev := decRedactHosts()
		setDecRedactHosts(false)
		b.Cleanup(func() { setDecRedactHosts(prev) })
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow")
		}
	})
}

// benchTokenSink keeps the serial benchmarks' results live so the compiler cannot
// elide the call under test. benchTokenSinkParallel is its concurrency-safe counterpart
// for RunParallel workers — see BenchmarkPseudonymizeHostParallel.
var (
	benchTokenSink         string
	benchTokenSinkParallel atomic.Pointer[string]
)

// ── Benchgate ────────────────────────────────────────────────────────────────

// recordStatsRedactedMaxHMACs pins the de-duplication in recordStats: the alert sink and
// the top-hosts sink share ONE derived pseudonym, so an allowed request must derive the
// token exactly once. Counting is indirect but exact — allocations scale linearly with
// the number of pseudonymizeHost calls, so a second derivation shows up as a step.
func TestBenchGate_RecordStatsDerivesPseudonymOnce(t *testing.T) {
	swapDecRedact(t, true)
	swapTrafficKey(t, []byte(testTrafficKey))
	recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow") // prime

	one := testing.AllocsPerRun(200, func() {
		benchTokenSink = pseudonymizeHost("cdn.example.com:443")
	})
	stats := testing.AllocsPerRun(200, func() {
		recordStats("10.0.0.1", "cdn.example.com:443", "OK", "allow-all", "Allow")
	})
	// Two derivations would put recordStats at >= 2x the single-token cost. One
	// derivation plus the fan-out's own bookkeeping stays well under that.
	if stats >= 2*one {
		t.Fatalf("recordStats allocated %.0f/op vs %.0f/op for a single token — the destination pseudonym looks like it is derived twice", stats, one)
	}
}
