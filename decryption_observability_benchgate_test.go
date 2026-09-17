//go:build benchgate

package main

// Allocation-regression gate for the ADR-0011 decryption-outcome projection —
// the per-session work every CONNECT tunnel close performs.
//
//	go test -tags benchgate -run 'TestBenchGate_Decryption' -v .

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// TestBenchGate_DecryptionProjectionAllocs locks in the allocation contract for
// toBlock and for the coverage-metric label projection.
//
// GATE DESIGN, following TestBenchGate_PolicyDecisionLineAllocs.
//
// (1) It measures the PRODUCTION functions — the real toBlock applyPolicyDecision's
// tunnel-close path calls, and the real decEnumOr calls recordDecryptSession makes —
// not a replica. A gate that cannot fail for the regression it names manufactures
// confidence.
//
// (2) It is keyed on ALLOCATIONS PER OP, not ns/op: alloc counts are deterministic
// and hardware-independent, so the gate means the same thing on any runner, under
// -race, at any load. ns/op on a shared CI box does not.
//
// The bounds are CONSTANTS and tight rather than padded. toBlock's ONE allocation
// is the returned *logstore.DecryptionBlock itself, which the caller keeps — there
// is nothing else left to remove, and every enum field is projected without boxing.
// The label projection's bound is ZERO: it returns strings that already exist
// inside the enum values, so it has no legitimate reason to touch the heap at all.
//
// The fixtures are package-level VARIABLES (decBenchInspected / decBenchBypassed in
// decryption_observability_bench_test.go), never composite literals at the call
// site: Go boxes a constant into an interface at compile time into read-only data,
// so a constant fixture would measure a cost production never has and would have
// reported the pre-change shape as nearly free — the trap plArgs documents for the
// policy decision line.
//
// Both fixtures are gated. The inspected one is the worst case (all seven bounded
// enums populated, so the pre-change shape boxed all seven); the bypassed one is
// the common case on a mixed-policy gateway, and it is gated too because its mostly
// empty enums are what made the waste easy to miss — an empty string boxes for free.
func TestBenchGate_DecryptionProjectionAllocs(t *testing.T) {
	cases := []struct {
		name      string
		maxAllocs int64
		run       func()
	}{
		{"toBlock/inspected", 1, func() { decSink = decBenchInspected.toBlock(false) }},
		{"toBlock/bypassed", 1, func() { decSink = decBenchBypassed.toBlock(false) }},
		{"toBlock/inspected+redacted", 1, func() { decSink = decBenchInspected.toBlock(true) }},
		{"sessionMetricLabels", 0, func() {
			o := decBenchInspected
			strSink = decEnumOr(o.Outcome, decryptobs.OutcomeNotDecrypted)
			strSink = decEnumOr(o.DecisionSource, decryptobs.DecisionNonTLSFallback)
			strSink = decEnumOr(o.TLSVersion, decryptobs.TLSVersionUnknown)
		}},
	}

	for _, tc := range cases {
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tc.run()
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("%s: %d allocs/op (bound %d), %d B/op, %d ns/op",
			tc.name, allocs, tc.maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
		if allocs > tc.maxAllocs {
			t.Errorf("REGRESSION: the per-session %s projection allocates %d/op, exceeds bound %d — "+
				"an allocation has returned to the decryption-outcome projection on the tunnel hot "+
				"path. The usual cause is decEnumOr losing its type parameter and taking interfaces "+
				"again, which boxes every named-string enum onto the heap. See the contract comment "+
				"above decEnumOr in decryption_observability.go.", tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestBenchGate_DecryptionProjectionBeatsLegacy is the CONTROL for the gate above.
//
// A constant alloc bound proves the projection is cheap; it does not prove the type
// parameter is what made it cheap, and a bound alone would still pass if someone
// reverted the change and simultaneously loosened the number. Measuring the
// production projection against the frozen interface shape in the SAME run, on the
// same hardware, makes the comparison self-contained: production must allocate
// strictly less. Strictly-less is a real assertion and not a tautology — the two
// produce byte-identical records (TestToBlock_MatchesInterfaceProjection), so
// nothing but the removed boxing separates them.
func TestBenchGate_DecryptionProjectionBeatsLegacy(t *testing.T) {
	legacy := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decSink = legacyOutcomeToBlock(decBenchInspected, false)
		}
	})
	current := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decSink = decBenchInspected.toBlock(false)
		}
	})

	t.Logf("legacy %d allocs/op %d B/op %d ns/op → production %d allocs/op %d B/op %d ns/op",
		legacy.AllocsPerOp(), legacy.AllocedBytesPerOp(), legacy.NsPerOp(),
		current.AllocsPerOp(), current.AllocedBytesPerOp(), current.NsPerOp())

	if current.AllocsPerOp() >= legacy.AllocsPerOp() {
		t.Errorf("REGRESSION: the production projection allocates %d/op, not fewer than the frozen "+
			"interface shape's %d/op — decEnumOr is boxing its arguments again.",
			current.AllocsPerOp(), legacy.AllocsPerOp())
	}
	if current.AllocedBytesPerOp() >= legacy.AllocedBytesPerOp() {
		t.Errorf("REGRESSION: the production projection allocates %d B/op, not fewer than the frozen "+
			"interface shape's %d B/op.", current.AllocedBytesPerOp(), legacy.AllocedBytesPerOp())
	}
}
