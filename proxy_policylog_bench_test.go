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
// Two rounds have landed against that finding. The first removed two allocations
// that were pure waste (a fmt.Sprintf over an int, and a duplicated
// sanitizeLog). The second replaced fmt with append + strconv, which removed
// the remaining seven interface boxes and left ONE allocation: the message
// string. See the contract comment above logPolicyAllow in proxy.go for the
// measurements and the trade.
//
// The oracles below are FROZEN SHAPES, one per round, and they are the point of
// this file. plLegacy*Line is the pre-first-round fmt shape; plPrintf*Line is
// the pre-second-round fmt shape. The production emitters must render
// BYTE-IDENTICAL output to both, for every input, because these lines are
// parsed by SIEM forwarders — a faster line that is not the same line is not a
// win, it is an incident. That equivalence is what makes the allocation
// comparison meaningful at all.
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
	"sync/atomic"
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

// plSwapLogger points the package logger at w and returns a restore func.
//
// THE WRITER MUST NOT BE io.Discard, AND THAT IS A CORRECTION. log.Logger's
// output() begins with `if l.isDiscard.Load() { return nil }`, so a logger
// wired to io.Discard returns BEFORE it formats anything: every benchmark here
// used to measure the caller's argument boxing and nothing else, and reported
// roughly a third of the work a real gateway performs on the same line. The
// gap is not small — the allow line measures 397 ns/op into io.Discard and
// 1238 ns/op into a writer that merely counts bytes.
//
// plCountingSink is that writer. It is a real io.Writer, so the formatting
// happens; it only counts, so no syscall or file I/O contaminates the figure.
// That is the right isolation for this path: in production the destination is
// internal/logsink, which is asynchronous, so what the request goroutine
// actually pays is argument construction plus formatting plus a buffer copy.
func plSwapLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "", 0)
	return func() { logger = prev }
}

// plCountingSink is a real io.Writer that discards the bytes without being
// io.Discard, so log.Logger cannot take its short circuit. See plSwapLogger.
type plCountingSink struct{ n atomic.Int64 }

func (s *plCountingSink) Write(p []byte) (int, error) {
	s.n.Add(int64(len(p)))
	return len(p), nil
}

// ── Before vs after ─────────────────────────────────────────────────────────

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	defer plSwapLogger(&plCountingSink{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plLegacy(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	defer plSwapLogger(&plCountingSink{})()
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
	defer plSwapLogger(&plCountingSink{})()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plLegacy(plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	defer plSwapLogger(&plCountingSink{})()
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
	defer plSwapLogger(&plCountingSink{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Drop(b *testing.B) {
	defer plSwapLogger(&plCountingSink{})()
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

// ── The frozen fmt shapes: the differential oracle ──────────────────────────
//
// These four reproduce the production emitters EXACTLY as they stood before the
// append rewrite — same format strings, same sanitizeLog placement, same
// sanitize-the-rule-once contract. They exist for one reason: the rewrite is
// only acceptable if the bytes are unchanged, and the cheapest way to be sure
// of that is to keep the thing it replaced and compare against it on every run
// rather than to reason about strconv.AppendQuote matching %q.
//
// They are the BASELINE, never the thing under test. Nothing in proxy.go calls
// them.

const (
	plPrintfAllowFmt    = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
	plPrintfDropFmt     = "POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}"
	plPrintfBlockFmt    = "POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}"
	plPrintfRedirectFmt = "POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}"
)

func plPrintfAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfAllowFmt,
		safeRule, priority, clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plPrintfDropLine(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfDropFmt,
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plPrintfBlockLine(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfBlockFmt,
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plPrintfRedirectLine(rule string, priority int, clientIP, host, redirectURL, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfRedirectFmt,
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(redirectURL), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

// plLineArgs is one full argument set for every branch. The differential drives
// all four emitters from a single struct so no field can be exercised on one
// branch and quietly skipped on another.
type plLineArgs struct {
	rule        string
	priority    int
	clientIP    string
	method      string
	host        string
	redirectURL string
	cond        string
	reqID       string
	identity    string
}

// plRenderPairs returns, for one argument set, the rendered output of each
// production emitter beside the frozen fmt shape it must match.
func plRenderPairs(a plLineArgs) map[string][2]string {
	return map[string][2]string{
		"allow": {
			plCapture(func() {
				logPolicyAllow(a.rule, a.priority, a.clientIP, a.method, a.host, a.cond, a.reqID, a.identity)
			}),
			plCapture(func() {
				plPrintfAllowLine(a.rule, a.priority, a.clientIP, a.method, a.host, a.cond, a.reqID, a.identity)
			}),
		},
		"drop": {
			plCapture(func() { logPolicyDrop(a.rule, a.priority, a.clientIP, a.host, a.cond, a.reqID, a.identity) }),
			plCapture(func() { plPrintfDropLine(a.rule, a.priority, a.clientIP, a.host, a.cond, a.reqID, a.identity) }),
		},
		"block": {
			plCapture(func() { logPolicyBlock(a.rule, a.priority, a.clientIP, a.host, a.cond, a.reqID, a.identity) }),
			plCapture(func() { plPrintfBlockLine(a.rule, a.priority, a.clientIP, a.host, a.cond, a.reqID, a.identity) }),
		},
		"redirect": {
			plCapture(func() {
				logPolicyRedirect(a.rule, a.priority, a.clientIP, a.host, a.redirectURL, a.cond, a.reqID, a.identity)
			}),
			plCapture(func() {
				plPrintfRedirectLine(a.rule, a.priority, a.clientIP, a.host, a.redirectURL, a.cond, a.reqID, a.identity)
			}),
		},
	}
}

// plDivergenceShapes is the hand-picked corpus. Randomised input finds the
// ordinary cases; these are the ones where an append-and-strconv rewrite could
// plausibly diverge from fmt and a fuzzer would be unlikely to construct.
var plDivergenceShapes = []string{
	"corp-saas-allow",
	"",                     // empty: %q renders "" and append renders nothing
	"rule with spaces",     // no quoting effect
	"rule\nwith\nnewlines", // sanitizeLog territory
	"rule\rwith\rCR",
	"rule\twith\ttabs",
	"rule\x00with\x1bcontrol", // NUL and ESC: %q escapes, sanitizeLog scrubs first
	"\x7f",                    // DEL, the top end of sanitizeLog's range
	"\x20",                    // SP, the first byte sanitizeLog leaves alone
	"ünïcode-rule-名前",         // multi-byte: %q must not mangle it
	"\xff\xfe",                // invalid UTF-8: %q renders \xff, append must too
	`quotes"and\backslashes`,  // the bytes %q itself escapes
	"a`backquoted`string",     // %q never picks backquotes without the # flag
	strings.Repeat("x", 400),  // longer than policyLineScratch: forces one grow
}

// TestPolicyDecisionLine_AppendRenderMatchesFmt is the half that outranks every
// benchmark in this file.
//
// It drives ALL FOUR production emitters against the frozen fmt shapes over the
// full cross product of the divergence corpus, on every string field rather
// than only the rule name. The previous round's equivalence test covered the
// allow branch and the rule name alone, which was enough for a one-verb change
// and is not enough for a rewrite that replaces the formatter itself: %q, %d
// and %s each had to be reproduced by hand, and a mistake in any one of them
// would land on a different field of a different branch.
func TestPolicyDecisionLine_AppendRenderMatchesFmt(t *testing.T) {
	base := plLineArgs{
		rule: plRule, priority: plPriority, clientIP: plClientIP, method: plMethod,
		host: plHost, redirectURL: plArgs.redirectURL, cond: plCond, reqID: plReqID, identity: plIdentity,
	}
	// Each field is varied in turn across the whole corpus, so a divergence is
	// reported against the field that caused it rather than a soup of them.
	fields := map[string]func(*plLineArgs, string){
		"rule":        func(a *plLineArgs, v string) { a.rule = v },
		"clientIP":    func(a *plLineArgs, v string) { a.clientIP = v },
		"method":      func(a *plLineArgs, v string) { a.method = v },
		"host":        func(a *plLineArgs, v string) { a.host = v },
		"redirectURL": func(a *plLineArgs, v string) { a.redirectURL = v },
		"cond":        func(a *plLineArgs, v string) { a.cond = v },
		"reqID":       func(a *plLineArgs, v string) { a.reqID = v },
		"identity":    func(a *plLineArgs, v string) { a.identity = v },
	}
	priorities := []int{0, 1, 7, 42, 100, 999, 2147483647, -1, -32768, -2147483648}

	for field, set := range fields {
		for _, v := range plDivergenceShapes {
			for _, pri := range priorities {
				a := base
				a.priority = pri
				set(&a, v)
				for branch, pair := range plRenderPairs(a) {
					if pair[0] != pair[1] {
						t.Fatalf("%s branch diverged with %s=%q pri=%d:\n  append: %q\n     fmt: %q",
							branch, field, v, pri, pair[0], pair[1])
					}
				}
			}
		}
	}
}

// FuzzPolicyDecisionLine is the randomised half of the same claim. The corpus
// above covers the shapes a human thought of; this covers the ones nobody did.
//
//	go test -run '^$' -fuzz FuzzPolicyDecisionLine -fuzztime=60s .
func FuzzPolicyDecisionLine(f *testing.F) {
	f.Add("corp-saas-allow", 100, "203.0.113.7", "GET", "files.example.com", "https://p/x", "fqdn", "abc", "alice@example.com")
	f.Add("", 0, "", "", "", "", "", "", "")
	f.Add("r\nn", -1, "\x00", "\x7f", `h"q`, "\xff", "\t", "\x1b", "ünï")
	f.Fuzz(func(t *testing.T, rule string, priority int, clientIP, method, host, redirectURL, cond, reqID, identity string) {
		a := plLineArgs{
			rule: rule, priority: priority, clientIP: clientIP, method: method,
			host: host, redirectURL: redirectURL, cond: cond, reqID: reqID, identity: identity,
		}
		for branch, pair := range plRenderPairs(a) {
			if pair[0] != pair[1] {
				t.Fatalf("%s branch diverged:\n  append: %q\n     fmt: %q", branch, pair[0], pair[1])
			}
		}
	})
}

// TestPolicyDecisionLine_StaysOnOnePhysicalLine pins the CWE-117 property
// directly on the new construction, for every branch and every string field.
//
// The append rewrite moved these lines off fmt, which is where the %q escaping
// used to live, so "the emitted record cannot be forged into two records" is
// now a property of code in proxy.go rather than of the standard library. It
// deserves its own assertion instead of riding on the equivalence test: if a
// future edit ever changes BOTH the production emitter and the frozen oracle
// the same wrong way, equivalence would still hold and this would not.
func TestPolicyDecisionLine_StaysOnOnePhysicalLine(t *testing.T) {
	const forge = "x\ny\rz"
	base := plLineArgs{
		rule: plRule, priority: plPriority, clientIP: plClientIP, method: plMethod,
		host: plHost, redirectURL: plArgs.redirectURL, cond: plCond, reqID: plReqID, identity: plIdentity,
	}
	fields := map[string]func(*plLineArgs){
		"rule":        func(a *plLineArgs) { a.rule = forge },
		"host":        func(a *plLineArgs) { a.host = forge },
		"redirectURL": func(a *plLineArgs) { a.redirectURL = forge },
		"cond":        func(a *plLineArgs) { a.cond = forge },
		"identity":    func(a *plLineArgs) { a.identity = forge },
	}
	for field, set := range fields {
		a := base
		set(&a)
		for branch, pair := range plRenderPairs(a) {
			body := strings.TrimSuffix(pair[0], "\n")
			if strings.ContainsAny(body, "\n\r") {
				t.Errorf("%s branch: a raw newline or CR in %s split the record (log forging): %q", branch, field, body)
			}
		}
	}
}

// TestPolicyDecisionLine_CallDepthNamesTheEmitter pins the one observable the
// switch from logger.Printf to logger.Output could have changed silently.
//
// Output takes an explicit call depth where Printf hard-codes its own, and
// getting it wrong does not fail anything under the log.LstdFlags composition
// Culvert ships — the flags never ask for a caller, so the depth is simply not
// read. It becomes visible the moment anyone debugging turns on log.Lshortfile,
// and at that point a wrong depth attributes every policy decision to log.go or
// to applyPolicyDecision instead of to the emitter that wrote it.
//
// The assertion is on the FILE, not the line: Printf and Output are on
// different source lines by construction, so a line-for-line comparison would
// be pinning an accident rather than the property that matters.
func TestPolicyDecisionLine_CallDepthNamesTheEmitter(t *testing.T) {
	emitters := map[string]func(){
		"allow": func() { logPolicyAllow(plRule, plPriority, plClientIP, plMethod, plHost, plCond, plReqID, plIdentity) },
		"drop":  func() { logPolicyDrop(plRule, plPriority, plClientIP, plHost, plCond, plReqID, plIdentity) },
		"block": func() { logPolicyBlock(plRule, plPriority, plClientIP, plHost, plCond, plReqID, plIdentity) },
		"redirect": func() {
			logPolicyRedirect(plRule, plPriority, plClientIP, plHost, plArgs.redirectURL, plCond, plReqID, plIdentity)
		},
	}
	for name, emit := range emitters {
		var buf strings.Builder
		prev := logger
		logger = log.New(&buf, "", log.Lshortfile)
		emit()
		logger = prev

		out := buf.String()
		if !strings.HasPrefix(out, "proxy.go:") {
			t.Errorf("%s: with Lshortfile the decision line is attributed to %q, want a proxy.go site — "+
				"the logger.Output call depth in the emitter is wrong, so a debugging build would "+
				"blame the logging package instead of the policy path.",
				name, strings.SplitN(out, " ", 2)[0])
		}
	}
}

// ── Before vs after: the append rewrite ─────────────────────────────────────

func BenchmarkPolicyDecisionLine_PrintfShape(b *testing.B) {
	defer plSwapLogger(&plCountingSink{})()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plPrintfAllowLine(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_PrintfShapeParallel(b *testing.B) {
	defer plSwapLogger(&plCountingSink{})()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plPrintfAllowLine(plRule, plPriority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
		}
	})
}
