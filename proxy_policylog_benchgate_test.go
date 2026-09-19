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
// (3) It writes to a plBlackhole, never io.Discard. That is not a detail: it is
// the difference between this gate measuring the line and measuring nothing.
// log.Logger.output returns on its isDiscard flag BEFORE formatting, so against
// io.Discard a Printf-shaped emitter skips the entire format it is being graded
// on. See the plBlackhole doc comment in proxy_policylog_bench_test.go.
//
// THE BOUND IS ONE, AND ONE IS THE FLOOR, NOT A TARGET WITH SLACK. A decision
// line is built into a stack-resident strings.Builder and handed to
// logger.Output as a plain string parameter, so the only heap object left is
// the line's own bytes — which the logger must be given and cannot borrow.
// Every branch measured exactly 1 allocs/op (from 8/8/7/7 before). There is no
// legitimate reason for these lines to grow another one; a change that needs
// one should say why here rather than slip past a padded number.
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
		restore := plSwapLogger(&plBlackhole{})
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
				"an allocation has returned to the request hot path. The usual causes: the line went "+
				"back through a variadic ...any (every string argument is one interface box), the "+
				"strings.Builder escaped to the heap (growPolicyLine takes it as a parameter for "+
				"exactly this reason), or the size hint stopped covering an ordinary line so the "+
				"builder regrows. See proxy_policylog.go.", tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsLegacy is the CONTROL for the gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring the production
// emitter against the frozen pre-change shape in the SAME run, on the same
// hardware, makes the comparison self-contained and machine-independent. The two
// render byte-identical output (TestPolicyDecisionLine_AllBranchesMatchFmt), so
// nothing but the removed waste separates them.
//
// BYTES ARE DELIBERATELY NOT REQUIRED TO FALL, and the earlier version of this
// gate asserting that they would was wrong. The fmt shape allocated ~8 small
// pointer-bearing interface boxes (147 B/op) and formatted into the logger's
// own reusable buffer; the built shape allocates ONE pointer-free ~208-byte
// string. Bytes per op therefore rise by ~60 while objects per op fall 8x, and
// the objects are the number that matters here: they are what the collector
// must sweep and scan, and the pointer-free line costs the scanner nothing at
// all. Asserting a fall in bytes would fail this trade on purpose. What is
// asserted instead is the trade's premise — strictly fewer objects, and not
// slower — plus a ceiling so the byte cost cannot quietly run away.
func TestBenchGate_PolicyDecisionLineBeatsLegacy(t *testing.T) {
	// A decision line's bytes are bounded by its content, so this ceiling is
	// generous against the measured 208 B/op while still catching a builder
	// that started over-reserving or copying twice.
	const maxBytesPerLine = 512

	restore := plSwapLogger(&plBlackhole{})
	legacy := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plLegacy(plRule, plPriority)
		}
	})
	current := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plCurrentAllowLine(plRule, plPriority)
		}
	})
	restore()

	t.Logf("legacy %d allocs/op %d B/op %d ns/op → production %d allocs/op %d B/op %d ns/op",
		legacy.AllocsPerOp(), legacy.AllocedBytesPerOp(), legacy.NsPerOp(),
		current.AllocsPerOp(), current.AllocedBytesPerOp(), current.NsPerOp())

	if current.AllocsPerOp() >= legacy.AllocsPerOp() {
		t.Errorf("REGRESSION: the production decision line allocates %d objects/op, not fewer than the "+
			"frozen pre-change shape's %d/op — the per-request line has gone back through fmt's "+
			"variadic argument list.", current.AllocsPerOp(), legacy.AllocsPerOp())
	}
	if b := current.AllocedBytesPerOp(); b > maxBytesPerLine {
		t.Errorf("REGRESSION: the production decision line allocates %d B/op, over the %d B ceiling — "+
			"the size hint is over-reserving, or the line is being copied more than once.",
			b, maxBytesPerLine)
	}
	// Same-run wall-clock comparison, with a deliberately loose bound. The
	// measured margin is ~2x (1299 ns → 648 ns), so requiring only "no slower"
	// leaves a full factor of headroom: this cannot flake on a loaded runner,
	// but it does catch a rewrite that trades all the time back for the
	// allocations — which is exactly what the first draft of this change did,
	// and what the io.Discard harness hid.
	if current.NsPerOp() > legacy.NsPerOp() {
		t.Errorf("REGRESSION: the production decision line takes %d ns/op, SLOWER than the frozen "+
			"pre-change shape's %d ns/op. Fewer allocations are not worth more latency on a "+
			"per-request path.", current.NsPerOp(), legacy.NsPerOp())
	}
}
