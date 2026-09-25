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
// (2) It runs against plSwapBenchLogger, NOT io.Discard. log.Logger skips
// formatting entirely when its writer IS io.Discard, so the previous harness
// timed argument construction and nothing else and under-reported this line by
// 3.6x. The allocation figure happened to survive that bug — the arguments were
// boxed at the call site, before Printf could short-circuit — but a gate must
// not be right by accident. See the harness note in proxy_policylog_bench_test.go
// and TestLogBenchHarness_DiscardShortCircuitsTheLogger.
//
// (3) It is keyed on ALLOCATIONS PER OP, not ns/op, for the reason
// bench_regression_test.go states: alloc counts are deterministic and
// hardware-independent, so the gate means the same thing on any runner, under
// -race, at any load. ns/op on a shared CI box does not.
//
// THE BOUND IS ONE, FOR EVERY BRANCH, and it is tight rather than padded. The
// emitters build their line by appending into a stack buffer, so the single
// remaining allocation is the []byte -> string conversion that hands the
// finished line to logger.Output. There is no legitimate reason for these lines
// to grow a second one: another allocation here means either a format argument
// has come back (boxing an []any), or the line has outgrown
// policyLineBufSize and the stack buffer is spilling — the latter is a sizing
// question, not a licence to raise the bound. A change that genuinely needs one
// more should say so here with its justification.
//
// The previous shape allocated 8/8/7/7 (allow/redirect/block/drop): the []any
// argument slice plus one runtime.convTstring per distinct string argument.
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
	// maxBytes is a CEILING, not a saving, and it is the SECONDARY signal here.
	// Bytes per op went UP with this shape (128 -> 192 for allow, 240 for
	// redirect): one right-sized string replaces eight small boxes. That trade
	// is deliberate — GC mark cost is per OBJECT, so 8 -> 1 is the term that
	// matters. A stack-buffer spill shows up as a SECOND allocation and is
	// caught by the alloc bound above; this ceiling only stops the line from
	// quietly growing into a kilobyte. It is set well clear of the redirect
	// branch's 240 B so that an ordinary wording change cannot trip it — a gate
	// that fires on benign edits is a gate that gets muted.
	const maxBytes = 384

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
		restore := plSwapBenchLogger()
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				tc.emit()
			}
		})
		restore()

		allocs := res.AllocsPerOp()
		t.Logf("%s decision line: %d allocs/op (bound %d), %d B/op (ceiling %d), %d ns/op",
			tc.name, allocs, tc.maxAllocs, res.AllocedBytesPerOp(), maxBytes, res.NsPerOp())
		if allocs > tc.maxAllocs {
			t.Errorf("REGRESSION: the per-request %s decision line allocates %d/op, exceeds bound %d — "+
				"an allocation has returned to the log-argument construction on the request hot path "+
				"(a re-introduced logger.Printf argument list, or a duplicated sanitizeLog call?). "+
				"See the contract comment above emitPolicyDecision in proxy.go.", tc.name, allocs, tc.maxAllocs)
		}
		if got := res.AllocedBytesPerOp(); got > maxBytes {
			t.Errorf("REGRESSION: the per-request %s decision line allocates %d B/op, exceeds ceiling %d — "+
				"the line has most likely outgrown policyLineBufSize and the stack buffer is spilling "+
				"to the heap on every request.", tc.name, got, maxBytes)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsPrintf is the CONTROL for the gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring the production
// emitter against the frozen pre-change shape in the SAME run, on the same
// hardware, makes the comparison self-contained: the production line must
// allocate strictly less. Strictly-less is a real assertion and not a
// tautology — the two render byte-identical output
// (TestPolicyDecisionLine_RenderIsByteIdentical), so nothing but the removed
// waste separates them.
//
// The timing ratio is LOGGED, never asserted. A same-run ratio of two
// sequential testing.Benchmark calls cancels the clock but not scheduling or
// load changes between the two arms, so on a shared runner it can cross any
// bound tight enough to catch a revert — the lesson this repo already recorded
// for sanitizeLog's scan-count gate (a gate that can flake gets muted). The
// allocation comparison is deterministic and is what this gate enforces; the
// ns/op saving (~0.43x, 1014 -> 435 ns on a 4-core Xeon @2.10GHz) stays with
// the benchmarks in proxy_policylog_bench_test.go and benchstat.
func TestBenchGate_PolicyDecisionLineBeatsPrintf(t *testing.T) {
	restore := plSwapBenchLogger()
	printf := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plPrintf(plRule, plPriority)
		}
	})
	current := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			plCurrentAllowLine(plRule, plPriority)
		}
	})
	restore()

	ratio := float64(current.NsPerOp()) / float64(printf.NsPerOp())
	t.Logf("printf shape %d allocs/op %d B/op %d ns/op → production %d allocs/op %d B/op %d ns/op (ratio %.2f, informational)",
		printf.AllocsPerOp(), printf.AllocedBytesPerOp(), printf.NsPerOp(),
		current.AllocsPerOp(), current.AllocedBytesPerOp(), current.NsPerOp(), ratio)

	if current.AllocsPerOp() >= printf.AllocsPerOp() {
		t.Errorf("REGRESSION: the production decision line allocates %d/op, not fewer than the frozen "+
			"logger.Printf shape's %d/op — the nine-argument Printf call has returned to the policy "+
			"decision path.", current.AllocsPerOp(), printf.AllocsPerOp())
	}
}
