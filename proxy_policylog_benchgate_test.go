//go:build benchgate

package main

// Allocation-regression gate for the per-request policy-decision log lines.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyDecisionLine' -v .

import (
	"io"
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
// (3) It writes through plNullSink, NOT io.Discard. log.New(io.Discard, …) sets
// the Logger's isDiscard flag and Logger.output returns on it before formatting
// anything, so a gate pointed at io.Discard cannot see a regression that
// reintroduces fmt — only the boxing that comes with it. That blind spot is
// exactly how the fmt cost survived the previous pass over these functions.
//
// The bound is ONE allocation per line, on every branch, and it is a constant
// rather than a padded number. That one is the string conversion
// logger.Output requires; everything else — the format buffer, the quoting, the
// integer rendering — happens in a stack buffer that does not escape. The four
// rule-matched branches used to allocate 8/8/7/7 and the default-deny branch 6,
// all of it fmt argument boxing. A change that needs a second allocation should
// say so here with its justification, not slip past a generous bound.
//
// All five branches are gated, not just the hot allow path: block and drop run
// hardest under a scanning or beaconing flood, and default-deny is the hottest
// of the five on a deployment whose rulebase does not yet cover its traffic —
// which is exactly when a gateway can least afford the waste.
func TestBenchGate_PolicyDecisionLineAllocs(t *testing.T) {
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
		{"default_deny", func() {
			logPolicyDefaultDeny(plArgs.clientIP, plArgs.method, plArgs.host, plArgs.reqID, plArgs.identity)
		}},
		// The long-but-plausible line must stay at one allocation too: that is
		// what policyLineBufSize is sized for, and a shrink would show up here
		// as the heap regrow it causes rather than as a silent slowdown.
		{"allow_long_values", func() {
			logPolicyAllow(plLongArgs.rule, 4242, plArgs.clientIP, plArgs.method, plLongArgs.host, plLongArgs.cond, plArgs.reqID, plLongArgs.identity)
		}},
	}

	for _, tc := range cases {
		restore := plSwapLoggerNull()
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
				"an allocation has returned to the log-line construction on the request hot path "+
				"(fmt reintroduced? a second sanitizeLog call? a format buffer that now escapes, or "+
				"one too small for the line?). See the contract comment at the top of proxy_policylog.go.",
				tc.name, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsFmt is the CONTROL for the gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the fix is
// what made it cheap, and a bound alone would still pass if someone reverted the
// change and simultaneously loosened the number. Measuring the production
// emitter against the frozen pre-change shapes in the SAME run, on the same
// hardware, makes the comparison self-contained and machine-independent: the
// production line must allocate strictly less and take strictly less time than
// both the logger.Printf shape it replaced and the older pre-#1256 shape.
//
// Strictly-less is a real assertion and not a tautology — all three render
// byte-identical output (TestPolicyDecisionLine_MatchesFrozenFmtShapes), so
// nothing but the removed work separates them.
//
// The ns/op arm is safe to assert here, unlike an absolute ns bound, because
// both shapes are timed in one run on one machine and the measured gap is
// ~2.5x. It is the arm that would catch a revert to fmt that kept the
// allocation count low by some other means.
func TestBenchGate_PolicyDecisionLineBeatsFmt(t *testing.T) {
	restore := plSwapLoggerNull()
	run := func(fn func()) testing.BenchmarkResult {
		return testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn()
			}
		})
	}
	legacy := run(func() { plLegacy(plRule, plPriority) })
	fmtShape := run(func() { plFmtCurrentAllowLine(plRule, plPriority) })
	current := run(func() { plCurrentAllowLine(plRule, plPriority) })
	restore()

	report := func(name string, r testing.BenchmarkResult) {
		t.Logf("%-8s %d allocs/op %d B/op %d ns/op", name, r.AllocsPerOp(), r.AllocedBytesPerOp(), r.NsPerOp())
	}
	report("legacy", legacy)
	report("fmt", fmtShape)
	report("current", current)

	for _, baseline := range []struct {
		name string
		res  testing.BenchmarkResult
	}{{"pre-#1256 legacy", legacy}, {"the logger.Printf shape", fmtShape}} {
		if current.AllocsPerOp() >= baseline.res.AllocsPerOp() {
			t.Errorf("REGRESSION: the production decision line allocates %d/op, not fewer than %s's %d/op — "+
				"fmt argument boxing has returned to the policy decision path.",
				current.AllocsPerOp(), baseline.name, baseline.res.AllocsPerOp())
		}
		if current.NsPerOp() >= baseline.res.NsPerOp() {
			t.Errorf("REGRESSION: the production decision line costs %d ns/op, not less than %s's %d ns/op, "+
				"measured in the same run on the same hardware.",
				current.NsPerOp(), baseline.name, baseline.res.NsPerOp())
		}
	}
}

// TestBenchGate_PolicyLogSinkIsNotIoDiscard is the control for the CONTROL: it
// pins the measurement methodology the two gates above depend on.
//
// If plSwapLoggerNull ever pointed the logger at io.Discard, both gates would
// keep passing while measuring roughly a third of the real cost — a
// reintroduced fmt.Appendf would be invisible in ns/op and would show only the
// boxing in allocs/op. So assert the property directly: with the benchmark sink
// installed, the logger must actually format and write, which is observable as
// bytes reaching the sink.
func TestBenchGate_PolicyLogSinkIsNotIoDiscard(t *testing.T) {
	// log.New compares its writer against io.Discard by interface value; that
	// exact comparison is what the benchmark sink must never satisfy.
	if plBenchWriter == io.Discard {
		t.Fatal("the benchmark sink IS io.Discard — log.New would set isDiscard and skip formatting")
	}

	// Substitute a counting writer for the real sink and drive the swap the
	// gates use. Bytes must reach it: that proves plSwapLoggerNull routes
	// through plBenchWriter AND that the resulting logger formats rather than
	// returning early. Asserting on plNullSink's type alone would stay green
	// against a plSwapLoggerNull that quietly hardcoded io.Discard.
	var counted countingSink
	prev := plBenchWriter
	plBenchWriter = &counted
	restore := plSwapLoggerNull()
	logPolicyAllow(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	restore()
	plBenchWriter = prev

	if counted.bytes == 0 {
		t.Fatal("the benchmark log sink swallowed the line without formatting it — the gates above are " +
			"measuring argument construction only. plSwapLoggerNull must NOT use io.Discard: log.New " +
			"special-cases it and Logger.output returns before fmt runs.")
	}
}

type countingSink struct{ bytes int }

func (c *countingSink) Write(p []byte) (int, error) { c.bytes += len(p); return len(p), nil }
