package main

// Per-request policy-decision log-line cost (Performance Guardian).
//
// applyPolicyDecision emits exactly one decision line per proxied request
// (POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT /
// POLICY_DEFAULT_DENY), so the line sits on 100% of the dispatch hot path.
//
// ── The sink these benchmarks use is load-bearing ───────────────────────────
//
// log.New(io.Discard, …) sets the Logger's isDiscard flag and Logger.output
// returns on that flag BEFORE calling fmt.Appendf, so a benchmark pointed at
// io.Discard measures the ARGUMENT BOXING ONLY and never the formatting. Every
// benchmark and gate in this file therefore writes to plNullSink — a plain
// discarding io.Writer that is deliberately NOT io.Discard — so what is
// measured is what a gateway pays. The difference is not a detail: against
// io.Discard the pre-change POLICY_ALLOW line measured 415 ns/op; against a
// real sink it measured 1240.
//
// That blind spot is why the fmt cost survived the previous pass over these
// same functions (PR #1256, which removed two of ten allocations and measured
// the remainder against io.Discard). DO NOT point these at io.Discard again.
//
// ── What the current shape replaced ─────────────────────────────────────────
//
// Two frozen shapes are kept here as oracles, and both are baselines, never the
// thing under test:
//
//   plLegacy*   the shape before PR #1256: pri rendered via
//               strings.ReplaceAll(fmt.Sprintf("%d", …), "\n", "") and the rule
//               name sanitized twice.
//   plFmt*      the shape before THIS change: one logger.Printf per branch with
//               the format string verbatim as it stood.
//
// plFmt* is what TestPolicyDecisionLine_MatchesFrozenFmtShapes compares the
// production emitters against, byte for byte, so the equivalence claim rests on
// a verbatim copy of the replaced code rather than on a re-description of it.
//
// EVERYTHING ELSE HERE MEASURES THE PRODUCTION FUNCTIONS — logPolicyAllow and
// its siblings are the real emitters applyPolicyDecision calls, so a change
// that reintroduces fmt or an allocation on the request path shows up here and
// in the gate.
//
//	go test -run '^$' -bench 'BenchmarkPolicyDecisionLine' -benchmem -count=6 .

import (
	"fmt"
	"io"
	"log"
	"math"
	"strconv"
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

// plSwapLogger points the package logger at w and returns a restore func.
func plSwapLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "", 0)
	return func() { logger = prev }
}

// plNullSink discards every write, like io.Discard, while being a DIFFERENT
// type — which is the entire point. log.New special-cases io.Discard by value
// and sets the Logger's isDiscard flag, and Logger.output returns on that flag
// before it formats anything, so benchmarking through io.Discard measures the
// argument boxing and skips fmt entirely. Writing through an ordinary writer
// exercises the same code path a production sink does (internal/logsink, whose
// Write is a channel send) minus the I/O.
type plNullSink struct{}

func (plNullSink) Write(p []byte) (int, error) { return len(p), nil }

// plBenchWriter is the writer plSwapLoggerNull installs. It is a variable so
// TestBenchGate_PolicyLogSinkIsNotIoDiscard can substitute a counting writer
// and prove that the swap really routes through it — i.e. that the benchmarks
// are formatting and writing, not short-circuiting on log's isDiscard flag.
// Checking the TYPE of plNullSink instead would not catch a plSwapLoggerNull
// that hardcodes io.Discard past it.
var plBenchWriter io.Writer = plNullSink{}

// plSwapLoggerNull is what every benchmark and gate in this file uses.
func plSwapLoggerNull() func() { return plSwapLogger(plBenchWriter) }

// ── The frozen fmt shapes (oracles for THIS change) ─────────────────────────
//
// Verbatim copies of the five logger.Printf calls as they stood immediately
// before the hand-appended emitters replaced them, format strings included.
// They are the oracle the differential test compares production against, and
// the baseline the before/after benchmarks measure against. Nothing else may
// call them.

const (
	plFmtAllowFmt       = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
	plFmtDropFmt        = "POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}"
	plFmtBlockFmt       = "POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}"
	plFmtRedirectFmt    = "POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}"
	plFmtDefaultDenyFmt = "POLICY_DEFAULT_DENY %s %s %q {req_id=%s identity=%s action=deny}"
)

func plFmtAllow(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtAllowFmt,
		safeRule, priority, clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtDrop(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtDropFmt,
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtBlock(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtBlockFmt,
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtRedirect(rule string, priority int, clientIP, host, redirectURL, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plFmtRedirectFmt,
		safeRule, priority, clientIP, sanitizeLog(host), sanitizeLog(redirectURL), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plFmtDefaultDeny(clientIP, method, host, reqID, identity string) {
	logger.Printf(plFmtDefaultDenyFmt, clientIP, method, sanitizeLog(host), reqID, sanitizeLog(identity))
}

// plFmtCurrentAllowLine is the frozen fmt allow line with the standard arguments.
func plFmtCurrentAllowLine(rule string, priority int) {
	plFmtAllow(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// ── Long-but-plausible arguments ────────────────────────────────────────────
//
// A descriptive rule name, a deep subdomain, an email identity and a full
// condition list: ~390 bytes of line, the shape that decides whether the
// emitter's stack buffer is big enough to keep the whole thing at one
// allocation. Nothing exotic — every field is something a real deployment
// configures.
var plLongArgs = struct{ rule, host, cond, identity string }{
	rule:     "corp-saas-allow-with-a-fairly-long-descriptive-rule-name",
	host:     "very-long-subdomain-name.department.region.example-corporation.com",
	cond:     "fqdn,category,geo,schedule,source-cidr,identity-group,time-window",
	identity: "firstname.lastname+tag@department.example-corporation.co.uk",
}

// ── Before vs after ─────────────────────────────────────────────────────────
//
// Three shapes, all timed in the same run on the same hardware so the
// comparison is self-contained and needs no re-baselining per runner:
// _Legacy (pre-#1256), _Fmt (the logger.Printf shape this change replaced) and
// _Current (production).

func BenchmarkPolicyDecisionLine_Fmt(b *testing.B) {
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plFmtCurrentAllowLine(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_FmtParallel(b *testing.B) {
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plFmtCurrentAllowLine(plRule, plPriority)
		}
	})
}

// The long-value shape: the emitter's stack buffer must absorb it without
// spilling to a heap regrow, and the fmt shape's per-argument cost grows with
// it while the hand-appended one does not.

func BenchmarkPolicyDecisionLine_FmtLong(b *testing.B) {
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plFmtAllow(plLongArgs.rule, 4242, plArgs.clientIP, plArgs.method, plLongArgs.host, plLongArgs.cond, plArgs.reqID, plLongArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_CurrentLong(b *testing.B) {
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyAllow(plLongArgs.rule, 4242, plArgs.clientIP, plArgs.method, plLongArgs.host, plLongArgs.cond, plArgs.reqID, plLongArgs.identity)
	}
}

// The quoting helper on its own: two of these run per allow line, and they were
// the largest remaining item once fmt was gone.

func BenchmarkPolicyQuote_Fast(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = appendQuotedLogValue(buf[:0], plHost)
	}
}

func BenchmarkPolicyQuote_StrconvQuote(b *testing.B) {
	buf := make([]byte, 0, 128)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = strconv.AppendQuote(buf[:0], plHost)
	}
}

func BenchmarkPolicyDecisionLine_DefaultDeny(b *testing.B) {
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyDefaultDeny(plArgs.clientIP, plArgs.method, plArgs.host, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plLegacy(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	defer plSwapLoggerNull()()
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
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plLegacy(plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	defer plSwapLoggerNull()()
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
	defer plSwapLoggerNull()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Drop(b *testing.B) {
	defer plSwapLoggerNull()()
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

// TestPolicyDecisionLine_MatchesFrozenFmtShapes is the half that outranks every
// benchmark in this file.
//
// The five decision lines are consumed by SIEM forwarders and log parsers, so
// replacing fmt with hand-appended bytes is acceptable ONLY if the emitted
// bytes are unchanged. Each production emitter is compared against a verbatim
// copy of the logger.Printf call it replaced — not against a re-description of
// the format — over the inputs where a hand-rolled formatter can plausibly
// diverge from fmt:
//
//   - %q: quotes, backslashes, control bytes, DEL, non-ASCII, invalid UTF-8,
//     and the empty string (the fast path in appendQuotedLogValue);
//   - %d: zero, negative, and the int boundaries (strconv.AppendInt vs fmt);
//   - lines long enough to overflow the emitter's stack buffer, where append
//     switches to a heap regrow mid-line.
func TestPolicyDecisionLine_MatchesFrozenFmtShapes(t *testing.T) {
	priorities := []int{0, 1, 7, 42, 100, 999, 2147483647, -1, -32768, math.MinInt, math.MaxInt}
	values := []string{
		"corp-saas-allow",
		"",
		"rule with spaces",
		"rule\nwith\nnewlines",
		"rule\rwith\rCR",
		"rule\twith\ttabs",
		"rule\x00with\x1bcontrol",
		"del\x7fbyte",
		"ünïcode-rule-名前",
		`quotes"and\backslashes`,
		"invalid\xffutf8\xfe",
		"\xed\xa0\x80surrogate",
		strings.Repeat("long-", 60), // overflows the emitter's stack buffer
	}
	for _, v := range values {
		for _, pri := range priorities {
			cases := map[string][2]func(){
				"allow": {
					func() { plFmtAllow(v, pri, plArgs.clientIP, plArgs.method, v, v, plArgs.reqID, v) },
					func() { logPolicyAllow(v, pri, plArgs.clientIP, plArgs.method, v, v, plArgs.reqID, v) },
				},
				"drop": {
					func() { plFmtDrop(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) },
					func() { logPolicyDrop(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) },
				},
				"block": {
					func() { plFmtBlock(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) },
					func() { logPolicyBlock(v, pri, plArgs.clientIP, v, v, plArgs.reqID, v) },
				},
				"redirect": {
					func() { plFmtRedirect(v, pri, plArgs.clientIP, v, v, v, plArgs.reqID, v) },
					func() { logPolicyRedirect(v, pri, plArgs.clientIP, v, v, v, plArgs.reqID, v) },
				},
				"default_deny": {
					func() { plFmtDefaultDeny(plArgs.clientIP, plArgs.method, v, plArgs.reqID, v) },
					func() { logPolicyDefaultDeny(plArgs.clientIP, plArgs.method, v, plArgs.reqID, v) },
				},
			}
			for name, pair := range cases {
				want, got := plCapture(pair[0]), plCapture(pair[1])
				if want != got {
					t.Errorf("%s diverged for value=%q pri=%d:\n  fmt: %q\n  got: %q", name, v, pri, want, got)
				}
			}
		}
	}
}

// TestAppendQuotedLogValue_MatchesStrconvQuote pins the fast path against the
// function it shortcuts, over the boundary bytes randomness is least likely to
// produce on its own. FuzzAppendQuotedLogValue covers the rest of the space.
func TestAppendQuotedLogValue_MatchesStrconvQuote(t *testing.T) {
	cases := []string{
		"", " ", "~", "plain-ascii", "files.example.com",
		"\x1f", "\x20", "\x7e", "\x7f", "\x80", "\xff",
		`"`, `\`, `a"b`, `a\b`, `""`,
		"tab\there", "nl\nhere", "nul\x00here",
		"ünïcode", "名前", "emoji😀", "\xed\xa0\x80", "\xfe\xff",
		strings.Repeat("x", 300),
	}
	for _, s := range cases {
		got := string(appendQuotedLogValue(nil, s))
		if want := strconv.Quote(s); got != want {
			t.Errorf("appendQuotedLogValue(%q) = %q, strconv.Quote = %q", s, got, want)
		}
	}
	// Appending must preserve whatever was already in the buffer, on both paths.
	for _, s := range []string{"plain", "needs\x00escape"} {
		got := string(appendQuotedLogValue([]byte("prefix:"), s))
		if want := "prefix:" + strconv.Quote(s); got != want {
			t.Errorf("append onto a non-empty buffer: got %q want %q", got, want)
		}
	}
}

// FuzzAppendQuotedLogValue is the general equivalence proof: for ANY string the
// fast path must produce exactly what strconv.Quote produces, since that is
// what fmt's %q produced before.
func FuzzAppendQuotedLogValue(f *testing.F) {
	for _, seed := range []string{"", "corp-saas-allow", `a"b\c`, "ünï-名前", "\xff\xfe", "\x7f\x20", strings.Repeat("q", 200)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := string(appendQuotedLogValue(nil, s)), strconv.Quote(s); got != want {
			t.Fatalf("s=%q: appendQuotedLogValue = %q, strconv.Quote = %q", s, got, want)
		}
	})
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
