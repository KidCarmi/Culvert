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
// GATE DESIGN. Three properties make this gate mean something.
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
// (3) It writes to plSink, a REAL writer. It used to write to io.Discard, which
// log.Logger short-circuits before it formats anything — so the ns/op and B/op
// this gate logged for the fmt shape were the cost of boxing nine arguments and
// throwing them away, about a third of the truth. The alloc count the gate keys
// on was unaffected, but a diagnostic figure that is wrong by 3x is how a future
// reader mis-sizes the next change, and the trap is pinned separately by
// TestPolicyDecisionLine_BenchSinkReachesFmt.
//
// The bound is a CONSTANT and tight rather than padded. All four lines now
// render by appending into a pooled buffer and reach the logger as ONE argument,
// so the branches no longer differ (they used to be 8/8/7/7, one box per format
// argument, and 10/10/9/9 before that): every emitter allocates exactly ONE
// object per call, the boxing of the finished buffer into Printf's single %s
// argument. Nothing else on the path allocates — the buffer is recycled, the
// rule name is sanitized once, sanitizeLog returns its input unchanged for the
// clean values that dominate, strconv.Append* write in place, and fmt copies the
// bytes into log.Logger's own reused buffer without building an intermediate
// string. A change that needs one more should say so here with its
// justification, not slip past a generous bound.
//
// The arguments come from plArgs (variables), never the pl* constants. Go boxes
// a constant into an interface at compile time into read-only data, so passing
// constants would make the gate measure a cost production never has — an
// earlier draft did exactly that and reported 5 allocs/op for a line that
// really did 8.
//
// All four branches are gated, not just the hot allow path: block and drop run
// hardest under a scanning or beaconing flood, which is exactly when the
// gateway can least afford the waste.
func TestBenchGate_PolicyDecisionLineAllocs(t *testing.T) {
	// One bound for every branch — see the note above on why they converged.
	const maxAllocs = 1

	cases := []struct {
		name string
		emit func()
	}{
		{"allow", func() {
			logPolicyAllow(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
		{"redirect", func() {
			logPolicyRedirect(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.redirectURL, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
		{"block", func() {
			logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
		{"drop", func() {
			logPolicyDrop(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}},
	}

	for _, tc := range cases {
		restore := plSwapSink()
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tc.emit()
			}
		})
		restore()

		allocs := res.AllocsPerOp()
		t.Logf("%s decision line: %d allocs/op (bound %d), %d B/op, %d ns/op",
			tc.name, allocs, maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: the per-request %s decision line allocates %d/op, exceeds bound %d — "+
				"an allocation has returned to the log path on the request hot path (a multi-argument "+
				"logger.Printf rebuilt out of the append form, an intermediate string on the way to the "+
				"logger, a render buffer no longer recycled, or a duplicated sanitizeLog call?). "+
				"See \"Decision-line rendering\" in proxy.go.", tc.name, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsItsPredecessors is the CONTROL for the
// gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring the production
// emitter against the frozen pre-change shapes in the SAME run, on the same
// hardware, makes the comparison self-contained: the production line must
// allocate strictly less, in both objects and bytes.
//
// BOTH predecessors are compared, and that is the point of the round-2 row. A
// control against the oldest shape alone would stay green if someone reverted
// just the append rendering and went back to the nine-argument fmt call, which
// is the regression this gate now exists to catch; the round-1 row stays because
// it is the one that proves the earlier Sprintf-over-an-int and duplicate
// sanitizeLog have not returned either.
//
// Strictly-less is a real assertion and not a tautology — all three render
// byte-identical output (TestPolicyDecisionLine_RenderIsByteIdentical,
// TestPolicyDecisionLine_AllEmittersMatchTheirFmtShape and
// FuzzPolicyDecisionLine), so nothing but the removed waste separates them.
func TestBenchGate_PolicyDecisionLineBeatsItsPredecessors(t *testing.T) {
	run := func(fn func()) testing.BenchmarkResult {
		return testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn()
			}
		})
	}

	restore := plSwapSink()
	legacy := run(func() { plLegacy(plRule, plPriority) })
	fmtShape := run(func() { plFmtShape(plRule, plPriority) })
	current := run(func() { plCurrentAllowLine(plRule, plPriority) })
	restore()

	report := func(name string, r testing.BenchmarkResult) {
		t.Logf("%-10s %d allocs/op %4d B/op %5d ns/op", name, r.AllocsPerOp(), r.AllocedBytesPerOp(), r.NsPerOp())
	}
	report("round-0", legacy)
	report("round-1", fmtShape)
	report("current", current)

	for _, prev := range []struct {
		name string
		res  testing.BenchmarkResult
		hint string
	}{
		{"round-0 (Sprintf priority + duplicated sanitizeLog)", legacy,
			"the Sprintf-over-an-int and/or the duplicated sanitizeLog call has returned to the policy decision path"},
		{"round-1 (nine-argument logger.Printf)", fmtShape,
			"the multi-argument fmt call has returned — every argument of it is an interface box on the request path"},
	} {
		if current.AllocsPerOp() >= prev.res.AllocsPerOp() {
			t.Errorf("REGRESSION vs %s: the production decision line allocates %d objects/op, not fewer than %d — %s.",
				prev.name, current.AllocsPerOp(), prev.res.AllocsPerOp(), prev.hint)
		}
		if current.AllocedBytesPerOp() >= prev.res.AllocedBytesPerOp() {
			t.Errorf("REGRESSION vs %s: the production decision line allocates %d B/op, not fewer than %d — %s.",
				prev.name, current.AllocedBytesPerOp(), prev.res.AllocedBytesPerOp(), prev.hint)
		}
	}
}
