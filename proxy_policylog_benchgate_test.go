//go:build benchgate

package main

// Allocation-regression gate for the per-request policy-decision log line.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyDecisionLine' -v .

import "testing"

// TestBenchGate_PolicyDecisionLineAllocs locks in the allocation contract for
// the one log line applyPolicyDecision writes per proxied request.
//
// GATE DESIGN. Keyed on ALLOCATIONS PER OP, not ns/op, for the reason
// bench_regression_test.go states: allocation counts are deterministic and
// hardware-independent, so this gate means the same thing on any runner, under
// -race, at any load. ns/op on a shared CI box does not.
//
// The bound is a CONSTANT and it is the point of the gate. Both defects this
// change removed were of the same shape — a per-request allocation hidden
// inside an argument list, where it reads as formatting rather than as work:
//
//   - strings.ReplaceAll(fmt.Sprintf("%d", Priority), "\n", "") rendered an int
//     to a string and scanned it for a newline it could not contain. Two allocs
//     (the Sprintf result, then boxing it into the Printf argument list).
//   - sanitizeLog(match.Rule.Name) appeared twice on the same line.
//
// Measured after the fix: 5 allocs/op, 80 B/op (from 7 and 99). The bound is 5,
// tight rather than padded, because every remaining allocation is accounted for
// — the []any argument slice plus the boxing of the four string arguments that
// escape — and there is no legitimate reason for this line to grow another one.
// A change that needs a sixth should say so here with its justification, not
// slip past a generous bound.
func TestBenchGate_PolicyDecisionLineAllocs(t *testing.T) {
	const maxAllocs int64 = 5

	res := testing.Benchmark(func(b *testing.B) {
		dst := discardLogger()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plCurrentAllowLine(dst, plRule, plPriority)
		}
	})

	allocs := res.AllocsPerOp()
	t.Logf("policy decision line: %d allocs/op (bound %d), %d B/op, %d ns/op",
		allocs, maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: the per-request policy decision line allocates %d/op, exceeds bound %d — "+
			"an allocation has returned to the log-argument construction on the request hot path "+
			"(a re-introduced fmt.Sprintf over a non-string value, or a duplicated sanitizeLog call?). "+
			"See proxy_policylog_bench_test.go for the before/after measurement.", allocs, maxAllocs)
	}
}

// TestBenchGate_PolicyDecisionLineBeatsLegacy is the CONTROL for the gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring both shapes in the
// SAME run, on the same hardware, makes the comparison self-contained: the
// current shape must allocate strictly less than the frozen pre-change shape.
// Strictly-less is a real assertion here and not a tautology — the two shapes
// render byte-identical output (TestPolicyDecisionLine_RenderIsByteIdentical),
// so nothing but the removed waste separates them.
func TestBenchGate_PolicyDecisionLineBeatsLegacy(t *testing.T) {
	legacy := testing.Benchmark(func(b *testing.B) {
		dst := discardLogger()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plLegacyAllowLine(dst, plRule, plPriority)
		}
	})
	current := testing.Benchmark(func(b *testing.B) {
		dst := discardLogger()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plCurrentAllowLine(dst, plRule, plPriority)
		}
	})

	t.Logf("legacy %d allocs/op %d B/op %d ns/op → current %d allocs/op %d B/op %d ns/op",
		legacy.AllocsPerOp(), legacy.AllocedBytesPerOp(), legacy.NsPerOp(),
		current.AllocsPerOp(), current.AllocedBytesPerOp(), current.NsPerOp())

	if current.AllocsPerOp() >= legacy.AllocsPerOp() {
		t.Errorf("REGRESSION: the current decision line allocates %d/op, not fewer than the frozen "+
			"pre-change shape's %d/op — the Sprintf-over-an-int and/or the duplicated sanitizeLog "+
			"call has returned to applyPolicyDecision.", current.AllocsPerOp(), legacy.AllocsPerOp())
	}
	if current.AllocedBytesPerOp() >= legacy.AllocedBytesPerOp() {
		t.Errorf("REGRESSION: the current decision line allocates %d B/op, not fewer than the frozen "+
			"pre-change shape's %d B/op.", current.AllocedBytesPerOp(), legacy.AllocedBytesPerOp())
	}
}
