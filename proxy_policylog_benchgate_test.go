//go:build benchgate

package main

// Allocation-regression gate for the per-request policy-decision log lines.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyDecisionLine' -v .

import "testing"

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
// for all four branches — ONE allocation each — because the branches no longer
// differ in the way that used to matter. While the lines went through
// logger.Printf, cost tracked the ARGUMENT COUNT (allow and redirect passed
// nine, block and drop eight, and each argument was an interface box), so the
// bounds were 8/8/7/7. The emitters now build their bytes with append and
// strconv and hand the finished message to logger.Output, so the only thing
// left to allocate is that message string, and a longer line is more BYTES,
// never another object.
//
// ONE is therefore the floor for this shape, not a target with headroom:
// log.Logger exposes no []byte entry point, so a decision line cannot reach the
// process log without one string. A bound of 1 means any regression at all
// fails the gate, which is the strongest statement this gate can make.
//
// It also pins something the bound does not obviously say. The scratch buffer
// is `make([]byte, 0, policyLineScratch)` declared INSIDE each emitter, which
// the compiler keeps on the stack only while it does not escape. Move it to a
// helper that returns one, to a struct field, or to a pool, and it escapes:
// the line then measures 2 allocs/op and this gate goes red. That is deliberate
// — it is the cheapest available proof of stack residency, and it needs no
// -gcflags plumbing to make it run in CI.
//
// The arguments come from plArgs (variables), never the pl* constants. Go boxes
// a constant into an interface at compile time into read-only data, so passing
// constants to the frozen fmt baselines would make them look cheaper than
// production ever was — an earlier draft did exactly that and reported 5
// allocs/op for a line that really did 8.
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
		restore := plSwapLogger(&plCountingSink{})
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
				"an allocation has returned to the request hot path. The two ways that happens: the "+
				"line went back to fmt (logger.Printf boxes every argument into an interface), or the "+
				"scratch buffer stopped being stack-resident (it must be declared inside the emitter "+
				"with a constant capacity and must not escape). "+
				"See the contract comment above logPolicyAllow in proxy.go.", tc.name, allocs, tc.maxAllocs)
		}
	}
}

// TestBenchGate_PolicyDecisionLineBeatsEveryFrozenShape is the CONTROL for the
// gate above.
//
// A constant alloc bound proves the line is cheap; it does not prove the change
// is what made it cheap, and a bound alone would still pass if someone reverted
// the code and loosened the number in the same commit. Measuring the production
// emitter against the frozen shapes in the SAME run, on the same hardware, makes
// the comparison self-contained.
//
// BOTH frozen shapes are compared, not just the oldest. plLegacy is the
// pre-first-round fmt line (the Sprintf-over-an-int and the duplicated
// sanitizeLog); plPrintfAllowLine is the pre-second-round fmt line, which had
// already had those removed and still boxed eight arguments into an interface
// slice. Checking only the oldest would let a revert of the second round pass,
// which is precisely the regression this gate is now here to catch. The
// strictly-less assertion is real and not a tautology: all three render
// byte-identical output for every input
// (TestPolicyDecisionLine_AppendRenderMatchesFmt, FuzzPolicyDecisionLine), so
// nothing but the removed waste separates them.
//
// THE BYTE COMPARISON IS DELIBERATELY NOT "STRICTLY LESS", AND THAT IS THE ONE
// THING IN THIS FILE WORTH ARGUING WITH. The append shape allocates MORE bytes
// than either fmt shape — one ~192-byte message string instead of eight 16-byte
// interface boxes — so an inherited strictly-less bytes assertion would go red
// on a change that is the right one. The honest statement is a bound plus the
// reasoning, not a comparison that happens to favour the new code:
//
//   - Object count fell 8 → 1. Every removed object was a mallocgc call on the
//     request goroutine, and each was a string header, i.e. POINTER-BEARING and
//     therefore scanned by the collector. The survivor is a byte string:
//     pointer-free, never scanned.
//   - Byte count rose 128 → 192. Bytes drive how OFTEN a GC cycle runs, and +64
//     B is ~1% of the 6.1 KB handleRequest allocates per request (measured,
//     alloc_space over BenchmarkPerfQual_ProxyHTTPForward at -memprofilerate=1),
//     against seven fewer objects for every cycle to mark.
//
// So the bytes are BOUNDED rather than compared: the line may not balloon, and
// the bound sits above the natural size class for a decision line built from
// realistic arguments. A rewrite that grew the line trips it; a scratch buffer
// that escaped to the heap trips the allocation bound above first (measured 2
// allocs/op, 448 B/op).
//
// The bound has HEADROOM FOR -race, which is not padding for its own sake. The
// race detector's allocation accounting reports more bytes for the same work:
// this line measures 192 B/op normally and 245 B/op under -race. CI runs the
// benchgate without -race, but a bound that goes red the first time somebody
// runs the gate locally with it is a bound that gets loosened in a hurry by
// whoever is unlucky, which is how a tight number becomes a meaningless one.
// 320 clears the instrumented figure and still leaves the gate able to see a
// line that genuinely grew.
const plMaxLineBytes = 320

func TestBenchGate_PolicyDecisionLineBeatsEveryFrozenShape(t *testing.T) {
	restore := plSwapLogger(&plCountingSink{})
	run := func(fn func()) testing.BenchmarkResult {
		return testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn()
			}
		})
	}
	legacy := run(func() { plLegacy(plRule, plPriority) })
	printfShape := run(func() {
		plPrintfAllowLine(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	})
	current := run(func() { plCurrentAllowLine(plRule, plPriority) })
	restore()

	for _, b := range []struct {
		name string
		res  testing.BenchmarkResult
	}{{"legacy (pre-round-1 fmt)", legacy}, {"printf (pre-round-2 fmt)", printfShape}, {"production (append)", current}} {
		t.Logf("%-26s %d allocs/op %4d B/op %5d ns/op", b.name, b.res.AllocsPerOp(), b.res.AllocedBytesPerOp(), b.res.NsPerOp())
	}

	for _, frozen := range []struct {
		name string
		res  testing.BenchmarkResult
	}{{"legacy", legacy}, {"printf", printfShape}} {
		if current.AllocsPerOp() >= frozen.res.AllocsPerOp() {
			t.Errorf("REGRESSION: the production decision line allocates %d/op, not fewer than the frozen "+
				"%s shape's %d/op — the fmt-based argument construction has returned to the policy "+
				"decision path.", current.AllocsPerOp(), frozen.name, frozen.res.AllocsPerOp())
		}
	}

	if got := current.AllocedBytesPerOp(); got > plMaxLineBytes {
		t.Errorf("REGRESSION: the production decision line allocates %d B/op, above the %d B bound — "+
			"either the scratch buffer escaped to the heap or the line itself grew. The bound is "+
			"explained above; raising it needs a reason, not a bigger number.", got, plMaxLineBytes)
	}
}
