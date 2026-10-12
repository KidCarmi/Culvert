package reqlog

import (
	"fmt"
	"testing"
)

// benchEntry builds a representative request-log entry: realistic string
// widths so the per-Add copy cost matches production, index-varied host so
// the ring is not artificially deduplicated by the compiler.
func benchEntry(i int) Entry {
	return Entry{
		TS:          1700000000000 + int64(i),
		Time:        "15:04:05",
		IP:          "203.0.113.42",
		Identity:    "alice@example.com",
		Method:      "CONNECT",
		Host:        fmt.Sprintf("host-%d.example.com:443", i%512),
		Status:      "OK",
		Level:       "INFO",
		RuleMatched: "allow-saas-collab",
		ActionTaken: "Allow",
		SSLAction:   "bypass",
	}
}

// fillRing brings the in-memory ring to steady state (MaxRing entries) so the
// benchmark measures the at-capacity path — the state a production proxy is
// in within minutes of startup — not the initial fill.
func fillRing(b *testing.B) {
	b.Helper()
	for i := 0; i < MaxRing; i++ {
		Add(benchEntry(i))
	}
}

// BenchmarkAdd measures the steady-state cost of ringing one request-log
// entry (persistence and history disabled — the default configuration).
// The interesting number is allocated bytes/op: the ring itself should not
// generate steady-state garbage.
func BenchmarkAdd(b *testing.B) {
	restore := SwapRingForTest()
	defer restore()
	restoreW := SwapPersistenceForTest()
	defer restoreW()
	fillRing(b)
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Add(e)
	}
}

// BenchmarkAddParallel measures Add under concurrent callers — the proxy
// records entries from many request goroutines, so ringMu hold time is
// contention on the request hot path.
//
// Read it against BenchmarkAddLegacyGateParallel (persist_gate_bench_test.go),
// which is the same path with the pre-change persistMu gate still in it.
//
// This benchmark is still ~FLAT in core count after that gate was removed
// (49.0 / 96.1 / 157.4 ns at GOMAXPROCS 1/2/4 on the Xeon the gate comment
// records). The remaining ceiling is ringMu itself: every logged request
// copies a 328-byte Entry under one process-wide exclusive lock. That is NOT
// the same kind of finding as the gate was — the lock guards real shared
// state, not a nil check — and removing it means changing what Get()
// guarantees about ordering (a lock-free shared ring would race the reader;
// sharding it would reorder entries inside a millisecond, which is all the
// resolution Entry.TS has). Measure before building either.
func BenchmarkAddParallel(b *testing.B) {
	restore := SwapRingForTest()
	defer restore()
	restoreW := SwapPersistenceForTest()
	defer restoreW()
	fillRing(b)
	e := benchEntry(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			Add(e)
		}
	})
}

// BenchmarkGet measures the newest-first snapshot the dashboard/API takes of
// a full ring.
func BenchmarkGet(b *testing.B) {
	restore := SwapRingForTest()
	defer restore()
	restoreW := SwapPersistenceForTest()
	defer restoreW()
	fillRing(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := Get()
		if len(got) != MaxRing {
			b.Fatalf("got %d entries, want %d", len(got), MaxRing)
		}
	}
}

// TestAdd_ZeroAllocSteadyState is the deterministic regression gate for the
// circular-buffer ring: once the buffer exists, Add must not allocate. The
// pre-fix append-then-retrim slice pattern amortized ~1.5 KB of backing-array
// garbage per logged request; any reintroduction of per-Add allocation fails
// here regardless of runner speed (allocs are hardware-independent).
func TestAdd_ZeroAllocSteadyState(t *testing.T) {
	restore := SwapRingForTest()
	defer restore()
	restoreW := SwapPersistenceForTest()
	defer restoreW()
	oldHistory := history
	history = nil
	defer func() { history = oldHistory }()

	for i := 0; i < MaxRing; i++ {
		Add(benchEntry(i))
	}
	e := benchEntry(1)
	if allocs := testing.AllocsPerRun(1000, func() { Add(e) }); allocs != 0 {
		t.Errorf("REGRESSION: Add allocates %.1f/op at steady state, want 0 — "+
			"the ring must overwrite in place, never grow", allocs)
	}
}
