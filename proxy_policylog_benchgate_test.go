//go:build benchgate

package main

// Allocation-regression gate for the per-request policy-decision log lines.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyDecisionLine' -v .

import (
	"testing"
)

// TestBenchGate_PolicyDecisionLineAllocs locks in the allocation contract for
// the one log line applyPolicyDecision writes per proxied request.
//
// GATE DESIGN. Two properties make this gate mean something.
//
// (1) It measures the PRODUCTION emitters — logPolicyAllow and its siblings,
// the exact functions applyPolicyDecision calls — not a copy of them. An
// earlier draft benchmarked a test-local replica of the same formatting, which
// would have stayed green while someone reintroduced fmt.Sprintf or a second
// sanitizeLog call into the real request path: a gate that cannot fail for the
// regression it names is worse than no gate, because it manufactures confidence
// (Codex review, PR #1256). Taking the RAW rule name as a parameter is part of
// this — it puts the sanitize-once decision inside the measured function.
//
// (2) It is keyed on ALLOCATIONS PER OP, not ns/op, for the reason
// bench_regression_test.go states: alloc counts are deterministic and
// hardware-independent, so the gate means the same thing on any runner, under
// -race, at any load. ns/op on a shared CI box does not.
//
// The bounds are CONSTANTS and tight rather than padded. They are now the SAME
// for every branch, which is itself the contract: the decision lines are
// assembled into a stack-resident scratch buffer, so the branch's argument count
// no longer buys allocations. Measured on the production emitters: 1 alloc/op
// everywhere (from 8/8/7/7, and 10/10/9/9 before that).
//
// The ONE remaining allocation is the finished line — string(b) in
// emitPolicyLine, which log.Logger.Output requires as a string. It is also what
// keeps the caller's scratch array off the heap, since the conversion copies.
// A bound of 1 therefore pins BOTH properties at once: go above it and either
// the interface boxing has returned or the scratch array has started escaping.
// A change that needs a second allocation should say so here with its
// justification, not slip past a generous bound.
//
// The arguments come from plArgs (variables), never the pl* constants. Go boxes
// a constant into an interface at compile time into read-only data, so passing
// constants would make the gate measure a cost production never has — an
// earlier draft did exactly that and reported 5 allocs/op for a line that
// really does 8.
//
// All four branches are gated, not just the hot allow path: block and drop run
// hardest under a scanning or beaconing flood, which is exactly when the
// gateway can least afford the waste.
func TestBenchGate_PolicyDecisionLineAllocs(t *testing.T) {
	cases := []struct {
		name      string
		maxAllocs int64
		emit      func()
	}{
		{"allow", 1, func() {
			logPolicyAllow(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
		{"redirect", 1, func() {
			logPolicyRedirect(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.redirectURL, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
		{"block", 1, func() {
			logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
		{"drop", 1, func() {
			logPolicyDrop(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
	}

	for _, tc := range cases {
		restore := plSwapLogger(plDiscard{})
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tc.emit()
			}
		})
		restore()

		allocs := res.AllocsPerOp()
		t.Logf("%s decision line: %d allocs/op (bound %d), %d B/op, %d ns/op",
			tc.name, allocs, tc.maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
		if allocs > tc.maxAllocs {
			t.Errorf("REGRESSION: the per-request %s decision line allocates %d/op, exceeds bound %d — "+
				"an allocation has returned to the log-argument construction on the request hot path "+
				"(a re-introduced fmt.Sprintf over a non-string value, or a duplicated sanitizeLog call?). "+
				"See the contract comment above logPolicyAllow in proxy.go.", tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsLegacy is the CONTROL for the gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring the production
// emitter against the frozen pre-change shapes in the SAME run, on the same
// hardware, makes the comparison self-contained. Strictly-fewer-objects is a
// real assertion and not a tautology — all three shapes render byte-identical
// output (TestPolicyDecisionLine_AllBranchesRenderIdenticallyToFmt), so nothing
// but the removed waste separates them.
//
// Both historical baselines are kept, because they pin different steps:
// plLegacy is the pri=%s shape (10 allocs), plPrintf the variadic-Printf shape
// that replaced it (8 allocs), and production is the assembled line (1).
//
// ── Why this gate no longer asserts fewer BYTES ─────────────────────────────
//
// It used to, and that assertion is now false BY DESIGN rather than by
// regression. The previous step removed whole allocations, so objects and bytes
// fell together. Assembling the line trades MANY SMALL objects for ONE LARGER
// one: ten 16-byte interface boxes plus a pointer-bearing []any argument slice
// (147 B/op) become a single right-sized string (192 B/op). Bytes rise ~31%
// while objects fall 90%.
//
// That is the right trade, and the reason is what the byte counter cannot see.
// GC cost tracks the number of objects to mark and the pointers to chase, not
// the bytes in them: the old shape handed the collector a scannable slice and
// ten string headers to trace, the new one hands it a single pointer-free byte
// blob that is swept without scanning. The wall-clock measurement agrees — the
// assembled line is ~1.5x faster against a real sink.
//
// So the byte figure is held to a CEILING instead of a direction. The ceiling
// exists to catch the failure the direction used to catch: the line growing
// without bound (a scratch buffer that starts escaping, or a second copy of the
// finished line). It is expressed as a multiple of the frozen baseline so it
// stays meaningful if the representative arguments change.
func TestBenchGate_PolicyDecisionLineBeatsLegacy(t *testing.T) {
	restore := plSwapLogger(plDiscard{})
	bench := func(fn func()) testing.BenchmarkResult {
		return testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn()
			}
		})
	}
	legacy := bench(func() { plLegacy(plRule, plPriority) })
	printf := bench(func() { plPrintf(plRule, plPriority) })
	current := bench(func() { plCurrentAllowLine(plRule, plPriority) })
	restore()

	for _, r := range []struct {
		name string
		res  testing.BenchmarkResult
	}{{"legacy(pri=%s)", legacy}, {"printf", printf}, {"production", current}} {
		t.Logf("%-16s %d allocs/op %4d B/op %5d ns/op",
			r.name, r.res.AllocsPerOp(), r.res.AllocedBytesPerOp(), r.res.NsPerOp())
	}

	for _, base := range []struct {
		name string
		res  testing.BenchmarkResult
	}{{"legacy pri=%s", legacy}, {"variadic Printf", printf}} {
		if current.AllocsPerOp() >= base.res.AllocsPerOp() {
			t.Errorf("REGRESSION: the production decision line allocates %d objects/op, not fewer than the "+
				"frozen %s shape's %d/op — interface boxing has returned to the policy decision path, "+
				"or the scratch buffer has started escaping to the heap.",
				current.AllocsPerOp(), base.name, base.res.AllocsPerOp())
		}
	}

	// Deliberate, bounded: see the byte-trade note above.
	const byteCeilingFactor = 3
	if ceiling := legacy.AllocedBytesPerOp() * byteCeilingFactor; current.AllocedBytesPerOp() > ceiling {
		t.Errorf("REGRESSION: the production decision line allocates %d B/op, above the %dx ceiling of %d B/op "+
			"over the frozen shape's %d B/op. One right-sized string per line is expected to exceed the "+
			"boxed-argument total; several times it is not — has the scratch array started escaping, or is "+
			"the finished line being copied twice?",
			current.AllocedBytesPerOp(), byteCeilingFactor, ceiling, legacy.AllocedBytesPerOp())
	}
}
