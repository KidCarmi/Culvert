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
// The line has been cut down in two steps, and both baselines below are kept so
// each stays measurable:
//
//	pri=%s over a pre-rendered int   plLegacy  10 allocs/op  147 B/op  1145 ns/op
//	variadic Printf, pri=%d          plPrintf   8 allocs/op  128 B/op  1031 ns/op
//	assembled into a stack buffer    PRODUCTION  1 alloc/op  192 B/op   598 ns/op
//
// The first step removed two wasted allocations (an int formatted to a string,
// then boxed back). The second removed the argument list itself: nine runtime
// values handed to a variadic ...any are nine interface boxes, charged on the
// request path before fmt formats anything. Bytes rise while objects fall 90% —
// one right-sized, pointer-free string instead of ten small pointer-bearing
// boxes — which is the trade TestBenchGate_PolicyDecisionLineBeatsLegacy
// documents. See the contract comment above logPolicyAllow in proxy.go.
//
// EVERYTHING BELOW MEASURES THE PRODUCTION FUNCTIONS. logPolicyAllow and its
// siblings are the real emitters applyPolicyDecision calls, so a change that
// reintroduces an allocation on the request path shows up here and in the gate.
// The exceptions are plLegacyAllowLine and plPrintfAllowLine, which deliberately
// freeze the two earlier shapes so the before/after comparison stays
// reproducible in-tree on any runner — the convention
// BenchmarkHTTPForward_LegacyClientPerRequest already follows. They are
// baselines, never the thing under test.
//
// The logger goes to plDiscard, NOT io.Discard, and that is load-bearing: see
// plDiscard and TestPolicyDecisionLine_IoDiscardElidesFormatting. With
// io.Discard these benchmarks measure no formatting at all, which reports the
// assembled line as SLOWER than the Printf one it replaced (508 vs 530 ns/op)
// when a real sink measures it 1.7x faster.
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

// plDiscard throws its input away exactly like io.Discard — and is deliberately
// NOT io.Discard.
//
// log.New records whether its writer IS io.Discard, and Logger.output returns on
// that check BEFORE it invokes the closure that formats the record. So a logger
// pointed at io.Discard does not merely skip the write: it skips fmt.Appendf,
// the header, everything. Benchmarks here used to use io.Discard while their
// comment claimed they measured "argument construction and formatting"; they
// measured construction and none of the formatting, which flattered any shape
// whose cost lives in fmt and made the assembled shape look slower than the
// Printf one it replaced. Production writes to the async logsink, never to
// io.Discard, so this is the shape a gateway actually pays.
//
// Pinned by TestPolicyDecisionLine_IoDiscardElidesFormatting.
type plDiscard struct{}

func (plDiscard) Write(p []byte) (int, error) { return len(p), nil }

// plSwapLogger points the package logger at w and returns a restore func.
// Callers pass plDiscard{} so the formatting work the request goroutine really
// performs is measured, without the log sink's I/O — which is asynchronous in
// production anyway (internal/logsink).
func plSwapLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "", 0)
	return func() { logger = prev }
}

// plPrintfAllowLine freezes the production shape as it stood immediately before
// the decision lines were assembled by hand: the same rendered bytes, produced
// by handing nine runtime values to a variadic Printf. It is the baseline for
// the assembly change, the way plLegacyAllowLine is the baseline for the
// priority-verb change before it. Baseline only — never the thing under test.
func plPrintfAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf("POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}",
		safeRule, priority, clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

// plPrintf runs the frozen Printf shape with the standard arguments.
func plPrintf(rule string, priority int) {
	plPrintfAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// ── Before vs after ─────────────────────────────────────────────────────────

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plLegacy(plRule, plPriority)
	}
}

// BenchmarkPolicyDecisionLine_Printf is the baseline for the assembly change:
// the same rendered line, built by a variadic Printf.
func BenchmarkPolicyDecisionLine_Printf(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plPrintf(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plCurrentAllowLine(plRule, plPriority)
	}
}

// BenchmarkPolicyDecisionLine_PrintfParallel pairs with the parallel benchmarks
// below so the before/after comparison exists at every concurrency level.
func BenchmarkPolicyDecisionLine_PrintfParallel(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plPrintf(plRule, plPriority)
		}
	})
}

// ── Concurrency ─────────────────────────────────────────────────────────────
//
// A gateway serves many requests at once, so the figure that matters is the
// per-op cost when every core is emitting a decision line simultaneously.
// log.Logger serialises internally on its own mutex, which is what production
// does too, so these numbers include that contention — the same for both shapes,
// so the comparison stays honest.

func BenchmarkPolicyDecisionLine_LegacyParallel(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plLegacy(plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
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
	defer plSwapLogger(plDiscard{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Drop(b *testing.B) {
	defer plSwapLogger(plDiscard{})()
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

// TestPolicyDecisionLine_AllBranchesRenderIdenticallyToFmt is the correctness
// wall for assembling the decision lines by hand, and it outranks every
// benchmark in this file.
//
// These four lines are consumed by SIEM forwarders and log parsers, so hand
// assembly is only acceptable if every branch emits the bytes fmt emitted. The
// oracle is the verbatim pre-change format string for each branch, so this
// tracks the contract rather than a restatement of the new code: %q must be
// strconv.AppendQuote (fmt's %q for a string IS strconv.Quote) and %d must be
// strconv.AppendInt, on every separator, in every branch.
//
// RenderIsByteIdentical above covers the allow line only. Redirect is the branch
// that most needs its own case: it is the one with two quoted values and the
// ` => ` separator between them, so a misplaced separator there would render a
// plausible-looking line that no parser matches.
func TestPolicyDecisionLine_AllBranchesRenderIdenticallyToFmt(t *testing.T) {
	const (
		allowFmt    = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
		dropFmt     = "POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}"
		blockFmt    = "POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}"
		redirectFmt = "POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}"
	)

	// Inputs chosen for the ways a hand-built line can diverge from fmt:
	// emptiness, the control bytes sanitizeLog scrubs, quote/backslash escaping,
	// multi-byte UTF-8, invalid UTF-8 (which %q renders as \xNN), and a value
	// long enough to overflow the stack scratch buffer onto the heap.
	type args struct{ rule, clientIP, method, host, redirect, cond, reqID, identity string }
	cases := []args{
		{plRule, plClientIP, plMethod, plHost, plArgs.redirectURL, plCond, plReqID, plIdentity},
		{"", "", "", "", "", "", "", ""},
		{"rule\nnl\rcr\ttab", "198.51.100.9", "POST", "ex\x00ample.com", "https://x/\x1b", "a=b\nc=d", "rid\x07", "bob\x7f"},
		{`q"uote\back`, "::1", "CONNECT", `h"ost`, `https://x/?a="b"`, `c="d"`, "r", `u"v`},
		{"ünïcode-名前-😀", "2001:db8::1", "GET", "héllo.example", "https://héllo/", "geo=DE,cat=News", "r2", "cn=Ünïcode,dc=corp"},
		{"bad\xffutf8", "203.0.113.1", "GET", "host\xc3", "https://x/\xff", "c\xff", "r3", "id\xfe"},
		{strings.Repeat("long-rule-", 40), "203.0.113.2", "GET", strings.Repeat("sub.", 50) + "example.com",
			"https://" + strings.Repeat("r", 300), strings.Repeat("cond=v,", 40), "r4", "cn=" + strings.Repeat("x", 300)},
	}
	priorities := []int{0, 1, -1, 100, -32768, 2147483647}

	for i, c := range cases {
		for _, pri := range priorities {
			safeRule := sanitizeLog(c.rule)
			checks := []struct {
				name string
				got  string
				want string
			}{
				{"allow",
					plCapture(func() {
						logPolicyAllow(c.rule, pri, c.clientIP, c.method, c.host, c.cond, c.reqID, c.identity)
					}),
					plCapture(func() {
						logger.Printf(allowFmt, safeRule, pri, c.clientIP, c.method, sanitizeLog(c.host),
							sanitizeLog(c.cond), c.reqID, sanitizeLog(c.identity), safeRule)
					})},
				{"drop",
					plCapture(func() {
						logPolicyDrop(c.rule, pri, c.clientIP, c.host, c.cond, c.reqID, c.identity)
					}),
					plCapture(func() {
						logger.Printf(dropFmt, safeRule, pri, c.clientIP, sanitizeLog(c.host),
							sanitizeLog(c.cond), c.reqID, sanitizeLog(c.identity), safeRule)
					})},
				{"block",
					plCapture(func() {
						logPolicyBlock(c.rule, pri, c.clientIP, c.host, c.cond, c.reqID, c.identity)
					}),
					plCapture(func() {
						logger.Printf(blockFmt, safeRule, pri, c.clientIP, sanitizeLog(c.host),
							sanitizeLog(c.cond), c.reqID, sanitizeLog(c.identity), safeRule)
					})},
				{"redirect",
					plCapture(func() {
						logPolicyRedirect(c.rule, pri, c.clientIP, c.host, c.redirect, c.cond, c.reqID, c.identity)
					}),
					plCapture(func() {
						logger.Printf(redirectFmt, safeRule, pri, c.clientIP, sanitizeLog(c.host),
							sanitizeLog(c.redirect), sanitizeLog(c.cond), c.reqID, sanitizeLog(c.identity), safeRule)
					})},
			}
			for _, ck := range checks {
				if ck.got != ck.want {
					t.Errorf("case %d %s pri=%d: assembled line diverged from fmt\n got: %q\nwant: %q",
						i, ck.name, pri, ck.got, ck.want)
				}
			}
		}
	}
}

// TestPolicyDecisionLine_IoDiscardElidesFormatting pins the property that makes
// plDiscard necessary, so the harness above cannot quietly revert to io.Discard.
//
// log.Logger records whether its writer IS io.Discard and returns on that check
// before running the closure that formats the record. A benchmark pointed at
// io.Discard therefore measures argument construction and NONE of the
// formatting — it under-reports every fmt-heavy shape, and it under-reports them
// UNEQUALLY, which is how the pre-change harness made the assembled decision
// line look slower than the Printf one it replaced (io.Discard: 508 vs 530
// ns/op; a real sink: 1264 vs 839).
//
// The proof is behavioural rather than a claim about stdlib internals: a logger
// on io.Discard must write nothing to a format argument that records being
// asked to render itself, while the same logger on an equivalent non-io.Discard
// writer must render it.
func TestPolicyDecisionLine_IoDiscardElidesFormatting(t *testing.T) {
	var rendered bool
	arg := plFormatProbe{rendered: &rendered}

	restore := plSwapLogger(io.Discard)
	logger.Printf("%s", arg)
	restore()
	if rendered {
		t.Fatalf("io.Discard no longer elides formatting — plDiscard may be unnecessary, " +
			"but re-measure the decision-line benchmarks before simplifying the harness")
	}

	rendered = false
	restore = plSwapLogger(plDiscard{})
	logger.Printf("%s", arg)
	restore()
	if !rendered {
		t.Fatalf("plDiscard elided formatting too — the benchmarks are measuring nothing; " +
			"plDiscard must not be io.Discard and must not be detected as equivalent to it")
	}
}

// plFormatProbe records whether fmt was asked to render it.
type plFormatProbe struct{ rendered *bool }

func (p plFormatProbe) String() string { *p.rendered = true; return "probe" }

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
