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
// The bounds are CONSTANTS and tight rather than padded. Since PR #1377 the
// emitters assemble their line in a stack buffer instead of handing fmt an
// []any, so the count is ONE for every branch — the string conversion handed to
// Logger.Output — where it used to be 8/8/7/7 (one []any slice plus one
// interface box per distinct string argument), and 10/10/9/9 before #1256.
// Every remaining allocation is accounted for, so there is no legitimate reason
// for these lines to grow another one: a bound of 1 means a NEW allocation is
// the only way to fail, most likely a reintroduced fmt call or a scratch buffer
// that escaped. A change that needs one more should say so here with its
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
		restore := plSilentLogger()
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
				"(a re-introduced fmt call, or a scratch buffer that now escapes to the heap?). "+
				"See the contract comment above logPolicyAllow in proxy.go.", tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsLegacy is the CONTROL for the gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring the production
// emitter against the frozen pre-change shape in the SAME run, on the same
// hardware, makes the comparison self-contained: the production line must
// allocate strictly fewer OBJECTS. Strictly-fewer is a real assertion and not a
// tautology — the two render byte-identical output
// (TestPolicyDecisionLine_RenderIsByteIdentical), so nothing but the removed
// waste separates them.
//
// It is deliberately keyed on object COUNT alone, and no longer also on
// allocated BYTES. Since PR #1377 production emits one 192-byte string where
// the legacy shape emitted ten small objects totalling 147 bytes, so a
// bytes-must-fall assertion would now fail on a change that is a large win: the
// eight interface boxes it removed are pointer-bearing and must be scanned by
// the GC on every cycle, while the one string body it adds is pointer-free and
// never scanned. Counting bytes without counting what is IN them measures the
// wrong thing here.
func TestBenchGate_PolicyDecisionLineBeatsLegacy(t *testing.T) {
	restore := plSilentLogger()
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
			"frozen pre-change shape's %d/op — fmt argument boxing has returned to the policy decision "+
			"path.", current.AllocsPerOp(), legacy.AllocsPerOp())
	}
}
