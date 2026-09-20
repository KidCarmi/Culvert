package main

// Per-request policy-decision log-line cost (Performance Guardian).
//
// applyPolicyDecision emits exactly one decision line per proxied request
// (POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT). Profiling the
// end-to-end forward benchmark (BenchmarkPerfQual_ProxyHTTPForward, alloc_objects)
// attributed 65,538 of the 99,878 objects handleRequest allocates OUTSIDE the
// upstream round trip to that single line's argument construction — roughly two
// thirds of the dispatch pipeline's own allocation, before any policy, auth or
// transport work is counted.
//
// Two of its allocations were pure waste; see the contract comment above
// logPolicyAllow in proxy.go for what they were and why removing them is sound.
//
// EVERYTHING BELOW MEASURES THE PRODUCTION FUNCTIONS. logPolicyAllow and its
// siblings are the real emitters applyPolicyDecision calls, so a change that
// reintroduces an allocation on the request path shows up here and in the gate.
// The one exception is plLegacyAllowLine, which deliberately freezes the
// PRE-CHANGE shape so the before/after comparison stays reproducible in-tree on
// any runner — the convention BenchmarkHTTPForward_LegacyClientPerRequest
// already follows. It is the baseline, never the thing under test.
//
//	go test -run '^$' -bench 'BenchmarkPolicyDecisionLine' -benchmem -count=6 .

import (
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
)

// Representative arguments: an ordinary allowed request through a named rule.
// Nothing here carries a control character, which is the overwhelmingly common
// case and therefore the one worth measuring.
const (
	plRule     = "corp-saas-allow"
	plPriority = 100
	plClientIP = "203.0.113.7"
	plMethod   = "GET"
	plHost     = "files.example.com"
	plCond     = "fqdn,category"
	plReqID    = "0123456789abcdef"
	plIdentity = "alice@corp.example.com"
)

// plLegacyAllowFmt is the POLICY_ALLOW format string verbatim as it stood
// before this change. It differs from the production one in exactly one verb:
// pri=%s (a pre-rendered string) became pri=%d (the int itself), which
// TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb pins.
const plLegacyAllowFmt = "POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"

// plLegacyAllowLine reproduces the pre-change argument construction verbatim,
// writing to the same package logger the production emitter uses.
//
// It takes the SAME parameter list as logPolicyAllow, and that is load-bearing
// rather than cosmetic. An earlier draft referenced the pl* constants directly
// inside the function body; Go boxes a constant into an interface at compile
// time into read-only data, so every one of those arguments went into the
// Printf argument list for free. That understated BOTH shapes (the replica
// measured 5 allocs/op where production does 8) and, worse, understated them
// UNEQUALLY once the production side started receiving runtime values as
// parameters — comparing a constant-folded baseline against a real one would
// have made the fix look like a regression. Both sides now receive identical
// runtime strings, so the only difference left between them is the fmt.Sprintf
// over the int and the second sanitizeLog call.
func plLegacyAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	logger.Printf(plLegacyAllowFmt,
		sanitizeLog(rule),
		strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", ""),
		clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions),
		reqID, sanitizeLog(identity), sanitizeLog(rule))
}

// plArgs is the representative argument set, held in variables rather than used
// as constants at the call sites so the boxing cost is measured, not folded away.
var plArgs = struct{ clientIP, method, host, cond, reqID, identity, redirectURL string }{
	plClientIP, plMethod, plHost, plCond, plReqID, plIdentity, "https://portal.example.com/blocked",
}

// plLegacy runs the frozen pre-change shape with the standard arguments.
func plLegacy(rule string, priority int) {
	plLegacyAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plCurrentAllowLine calls the PRODUCTION emitter with the same inputs.
func plCurrentAllowLine(rule string, priority int) {
	logPolicyAllow(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plBlackhole is a writer that costs as little as a writer can while still
// being a REAL one.
//
// It exists because io.Discard is not usable here and using it silently voided
// every benchmark in this file. log.Logger records at construction whether its
// destination is the io.Discard sentinel, and log.Logger.output returns on that
// flag BEFORE it calls the closure that formats the line:
//
//	func (l *Logger) output(pc uintptr, calldepth int, appendOutput func([]byte) []byte) error {
//		if l.isDiscard.Load() { return nil }
//
// So a Printf-shaped emitter pointed at io.Discard pays its argument boxing and
// then formats NOTHING, while an emitter that builds its line before calling
// the logger pays the formatting in full. Against io.Discard the fmt shape
// measured 393 ns/op and the built shape 716 ns/op; against this writer, which
// production resembles, the same two are 1299 ns/op and 648 ns/op — the
// comparison does not merely shift, it INVERTS. A harness that reports the
// faster shape as the slower one is worse than no harness.
//
// It deliberately does not count or store anything beyond a length: the point
// is to defeat the sentinel check, not to add work to the measurement.
type plBlackhole struct{ n int64 }

func (d *plBlackhole) Write(p []byte) (int, error) { d.n += int64(len(p)); return len(p), nil }

// plSwapLogger points the package logger at w with NO prefix and NO flags, and
// returns a restore func. This is the CORRECTNESS shape, used by plCapture.
//
// The flags MUST stay 0 here. log.LstdFlags stamps a wall-clock second into
// every line, and the differential tests capture the production emitter and the
// frozen fmt copy in two SEPARATE plCapture calls — so a clock tick between
// them makes two byte-identical renderings compare unequal and the suite
// reports a divergence that is purely the timestamp. It is a time-dependent
// flake: rare on a fast box, near-certain under -race in CI, where those tests
// make thousands of capture pairs over many seconds. That is exactly how it
// reached CI, on the commit that gave the BENCHMARK harness production flags
// and changed this shared helper to do it (verified by forcing one tick:
// "…00:48:27 POLICY_ALLOW…" vs "…00:48:28 POLICY_ALLOW…").
//
// Benchmarks have the opposite requirement — they must pay the header
// formatting a real line pays — so they use plSwapProdLogger. Two requirements,
// two helpers; do not merge them back into one.
func plSwapLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "", 0)
	return func() { logger = prev }
}

// plSwapProdLogger points the package logger at w with the PRODUCTION prefix
// and flags (setupLogger's "[Culvert] " + log.LstdFlags), so a benchmark pays
// the same header formatting every real line does.
//
// Benchmarks pass a plBlackhole, never io.Discard (see above). The log sink's
// I/O is still excluded — in production it is asynchronous anyway
// (internal/logsink). Never use this from a test that compares rendered bytes.
func plSwapProdLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "[Culvert] ", log.LstdFlags)
	return func() { logger = prev }
}

// ── Before vs after ─────────────────────────────────────────────────────────

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	defer plSwapProdLogger(&plBlackhole{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plLegacy(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	defer plSwapProdLogger(&plBlackhole{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plCurrentAllowLine(plRule, plPriority)
	}
}

// ── Concurrency ─────────────────────────────────────────────────────────────
//
// A gateway serves many requests at once, so the figure that matters is the
// per-op cost when every core is emitting a decision line simultaneously.
// log.Logger serialises internally on its own mutex, which is what production
// does too, so these numbers include that contention — the same for both shapes,
// so the comparison stays honest.

func BenchmarkPolicyDecisionLine_LegacyParallel(b *testing.B) {
	defer plSwapProdLogger(&plBlackhole{})()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plLegacy(plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	defer plSwapProdLogger(&plBlackhole{})()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plCurrentAllowLine(plRule, plPriority)
		}
	})
}

// ── The other three decision lines ──────────────────────────────────────────
//
// Block and drop are the branches that run hottest under a scanning or
// beaconing flood, so they are measured too rather than assumed to match.

func BenchmarkPolicyDecisionLine_Block(b *testing.B) {
	defer plSwapProdLogger(&plBlackhole{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Drop(b *testing.B) {
	defer plSwapProdLogger(&plBlackhole{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyDrop(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

// ── Isolated: the priority rendering alone ──────────────────────────────────

func BenchmarkPolicyPriority_LegacySprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = strings.ReplaceAll(fmt.Sprintf("%d", plPriority), "\n", "")
	}
}

// ── Correctness: the rendered line must not change ──────────────────────────

// plCapture runs fn with the package logger redirected into a buffer and
// returns what was written.
func plCapture(fn func()) string {
	var buf strings.Builder
	restore := plSwapLogger(&buf)
	fn()
	restore()
	return buf.String()
}

// TestPolicyDecisionLine_RenderIsByteIdentical is the half that outranks every
// benchmark here. The decision lines are consumed by SIEM forwarders and log
// parsers, so this change is only acceptable if the emitted bytes are unchanged.
// %d on an int emits exactly the digits fmt.Sprintf("%d", …) produced, and the
// ReplaceAll it fed could never match, so the PRODUCTION emitter must agree with
// the frozen legacy shape for every priority — including negative and
// multi-digit values — and for rule names carrying the control characters
// sanitizeLog exists to scrub.
func TestPolicyDecisionLine_RenderIsByteIdentical(t *testing.T) {
	priorities := []int{0, 1, 7, 42, 100, 999, 2147483647, -1, -32768}
	rules := []string{
		"corp-saas-allow",
		"",
		"rule with spaces",
		"rule\nwith\nnewlines",
		"rule\rwith\rCR",
		"rule\twith\ttabs",
		"rule\x00with\x1bcontrol",
		"ünïcode-rule-名前",
		`quotes"and\backslashes`,
	}
	for _, rule := range rules {
		for _, pri := range priorities {
			legacy := plCapture(func() { plLegacy(rule, pri) })
			current := plCapture(func() { plCurrentAllowLine(rule, pri) })
			if legacy != current {
				t.Errorf("rendered line diverged for rule=%q pri=%d:\n legacy: %q\ncurrent: %q",
					rule, pri, legacy, current)
			}
		}
	}
}

// TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb pins the claim the
// equivalence test rests on: the production format string is the legacy template
// with pri=%s replaced by pri=%d. Read out of the emitted bytes rather than a
// duplicated constant, so it tracks proxy.go rather than a copy of it — if a
// future edit changes anything else about the line, this fails and the
// equivalence test above stops being evidence for it.
func TestPolicyDecisionLine_FormatsDifferOnlyInThePriorityVerb(t *testing.T) {
	// A priority whose rendering is unmistakable in the output.
	const pri = 4242
	got := plCapture(func() { plCurrentAllowLine(plRule, pri) })
	want := plCapture(func() {
		logger.Printf(strings.Replace(plLegacyAllowFmt, "pri=%s", "pri=%d", 1),
			sanitizeLog(plRule), pri, plClientIP, plMethod, sanitizeLog(plHost),
			sanitizeLog(plCond), plReqID, sanitizeLog(plIdentity), sanitizeLog(plRule))
	})
	if got != want {
		t.Errorf("production POLICY_ALLOW line is not the legacy template with pri=%%s -> pri=%%d:\n  want: %q\n   got: %q", want, got)
	}
}

// TestPolicyDecisionLine_SanitizesTheRuleNameOnBothOccurrences pins that
// sanitizing the rule name ONCE and using it twice is not a shortcut that
// weakens the CWE-117 guarantee: a rule name carrying newlines must come out
// scrubbed in BOTH the leading rule=%q and the trailing rule=%s, and the whole
// line must stay on one physical line.
func TestPolicyDecisionLine_SanitizesTheRuleNameOnBothOccurrences(t *testing.T) {
	emitters := map[string]func(){
		"allow":    func() { logPolicyAllow("ev\nil", 1, plClientIP, plMethod, plHost, plCond, plReqID, plIdentity) },
		"block":    func() { logPolicyBlock("ev\nil", 1, plClientIP, plHost, plCond, plReqID, plIdentity) },
		"drop":     func() { logPolicyDrop("ev\nil", 1, plClientIP, plHost, plCond, plReqID, plIdentity) },
		"redirect": func() { logPolicyRedirect("ev\nil", 1, plClientIP, plHost, "https://x/", plCond, plReqID, plIdentity) },
	}
	for name, emit := range emitters {
		out := strings.TrimSuffix(plCapture(emit), "\n")
		if strings.Contains(out, "\n") {
			t.Errorf("%s: emitted line was split across physical lines (log forging): %q", name, out)
		}
		if strings.Contains(out, "ev\nil") {
			t.Errorf("%s: raw newline survived into the line: %q", name, out)
		}
		if n := strings.Count(out, "ev_il"); n != 2 {
			t.Errorf("%s: want the sanitized rule name twice (rule=%%q and the trailing rule=%%s), got %d in %q", name, n, out)
		}
	}
}
