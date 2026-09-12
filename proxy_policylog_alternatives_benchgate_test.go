//go:build benchgate

package main

// Live re-derivation of the two facts behind the REJECTED hand-rolled
// policy-decision line. Read the header of proxy_policylog_alternatives_test.go
// first — it carries the finding, the decomposition and the verdict; this file
// only keeps the verdict honest.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyDecisionLineHandRolled' -v .
//
// It lives behind the benchgate tag, beside TestBenchGate_PolicyDecisionLineAllocs,
// because it drives two testing.Benchmark runs and costs a few seconds — a price
// worth paying in the gate lane that already owns the allocation contracts, not
// on every developer's `go test ./...`.

import (
	"io"
	"testing"
)

// TestBenchGate_PolicyDecisionLineHandRolledTradeoffStillHolds is the LIVE half
// of the frozen alternative: it re-derives, on every run, the two facts the rejection rests on.
//
// It is keyed on allocation COUNT and allocated BYTES, never on ns/op — those
// two are deterministic and hardware-independent, so the gate means the same
// thing on any runner, under -race, at any load, while a timing assertion on a
// 7% margin would flake and then get muted (the reason bench_regression_test.go
// and the sanitizeLog scan-count gate are both structural).
//
// If a future Go release stops boxing these arguments on the heap, or makes the
// string conversion free, the second assertion flips and this test says so —
// which is the point. The rejection is a measurement, not a doctrine, and it
// should be revisited exactly when the measurement changes.
func TestBenchGate_PolicyDecisionLineHandRolledTradeoffStillHolds(t *testing.T) {
	restore := plSwapLogger(io.Discard)
	production := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plCurrentAllowLine(plRule, plPriority)
		}
	})
	alternative := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plHandRolled(plRule, plPriority)
		}
	})
	restore()

	t.Logf("production %d allocs/op %d B/op %d ns/op → hand-rolled %d allocs/op %d B/op %d ns/op",
		production.AllocsPerOp(), production.AllocedBytesPerOp(), production.NsPerOp(),
		alternative.AllocsPerOp(), alternative.AllocedBytesPerOp(), alternative.NsPerOp())

	if alternative.AllocsPerOp() >= production.AllocsPerOp() {
		t.Errorf("the hand-rolled alternative no longer allocates fewer OBJECTS (%d/op vs %d/op) — "+
			"the premise of this comparison has changed; re-measure before trusting the header.",
			alternative.AllocsPerOp(), production.AllocsPerOp())
	}
	if alternative.AllocedBytesPerOp() <= production.AllocedBytesPerOp() {
		t.Errorf("the hand-rolled alternative now allocates no more BYTES than production "+
			"(%d B/op vs %d B/op). That was the main reason it was rejected — the object count "+
			"fell but the byte rate rose, and byte rate is what drives GC frequency. Re-run the "+
			"benchmarks in this file and reconsider; see the header for the full trade.",
			alternative.AllocedBytesPerOp(), production.AllocedBytesPerOp())
	}
}
