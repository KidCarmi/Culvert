package main

// Per-request policy-decision log-line cost (Performance Guardian).
//
// applyPolicyDecision emits exactly one decision line per proxied request
// (POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT). Profiling the
// end-to-end forward benchmark (BenchmarkPerfQual_ProxyHTTPForward,
// alloc_objects, -memprofilerate=1) ranks it the LARGEST Culvert-owned
// allocation site in the whole run — 28,007 objects across 4,000 requests, 7
// per request, behind only net/http's own request/response machinery, two
// thirds of which belongs to the in-process client and backend rather than the
// proxy.
//
// ── THE HARNESS BUG THAT HID TWO THIRDS OF THE COST ─────────────────────────
//
// Every benchmark in this file used to silence the logger with
// log.New(io.Discard, …). log.Logger.output opens with
//
//	if l.isDiscard.Load() { return nil }
//
// and SetOutput sets that flag on `w == io.Discard` exactly. So the logger was
// not merely writing nowhere — it never FORMATTED. The benchmarks timed the
// argument construction and nothing else, and reported roughly a third of the
// real cost:
//
//	POLICY_ALLOW, 4-core Xeon @2.10GHz, medians of n=8
//	  against io.Discard      283 ns/op   (formatting skipped entirely)
//	  against a real sink    1042 ns/op   (what production pays)
//
// The allocation figure survived the bug — the nine arguments are boxed at the
// CALL SITE, before Printf can short-circuit — which is why the gate's 8
// allocs/op bound was right while its timing was not. It also means the
// previously recorded "419 -> 272 ns" improvement from PR #1256 was really
// 1143 -> 1042 ns: a 9% gain reported as 35%.
//
// plNullSink therefore replaces io.Discard everywhere below. It throws the
// bytes away exactly as io.Discard does, but log.Logger cannot recognise it, so
// the formatting path runs. THE ONE THING A BENCHMARK OF A LOG LINE MUST NOT DO
// IS SILENCE IT WITH io.Discard; TestLogBenchHarness_DiscardShortCircuitsTheLogger
// pins the trap so it cannot come back by habit.
//
// EVERYTHING BELOW MEASURES THE PRODUCTION FUNCTIONS. logPolicyAllow and its
// siblings are the real emitters applyPolicyDecision calls. The two pl*Line
// functions deliberately freeze SUPERSEDED shapes so the before/after
// comparisons stay reproducible in-tree on any runner — the convention
// BenchmarkHTTPForward_LegacyClientPerRequest already follows. They are
// baselines, never the thing under test.
//
//	go test -run '^$' -bench 'BenchmarkPolicyDecisionLine' -benchmem -count=6 .

import (
	"fmt"
	"io"
	"log"
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

// ── Frozen shapes ───────────────────────────────────────────────────────────

// plLegacyAllowFmt is the POLICY_ALLOW format string verbatim as it stood
// before PR #1256. It differs from the one that replaced it in exactly one
// verb: pri=%s (a pre-rendered string) became pri=%d.
const plLegacyAllowFmt = "POLICY_ALLOW rule=%q pri=%s %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"

// plPrintfFmt holds the four format strings as they stood BEFORE this change,
// when each emitter was a single logger.Printf. They are the executable
// specification the hand-built lines are checked against
// (TestPolicyDecisionLine_RenderIsByteIdentical) — the reason the appends in
// emitPolicyDecision are safe to read is that nothing takes them on trust.
const (
	plPrintfAllowFmt    = "POLICY_ALLOW rule=%q pri=%d %s %s %q [%s] {req_id=%s identity=%s rule=%s action=allow}"
	plPrintfDropFmt     = "POLICY_DROP rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=drop}"
	plPrintfBlockFmt    = "POLICY_BLOCK rule=%q pri=%d %s -> %q [%s] {req_id=%s identity=%s rule=%s action=block}"
	plPrintfRedirectFmt = "POLICY_REDIRECT rule=%q pri=%d %s -> %q => %q [%s] {req_id=%s identity=%s rule=%s action=redirect}"
)

// plLegacyAllowLine reproduces the pre-#1256 argument construction verbatim,
// writing to the same package logger the production emitter uses.
//
// It takes the SAME parameter list as logPolicyAllow, and that is load-bearing
// rather than cosmetic. An earlier draft referenced the pl* constants directly
// inside the function body; Go boxes a constant into an interface at compile
// time into read-only data, so every one of those arguments went into the
// Printf argument list for free. That understated BOTH shapes and, worse,
// understated them UNEQUALLY once the production side started receiving
// runtime values as parameters — comparing a constant-folded baseline against a
// real one would have made the fix look like a regression. Both sides now
// receive identical runtime strings.
func plLegacyAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	logger.Printf(plLegacyAllowFmt,
		sanitizeLog(rule),
		strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", ""),
		clientIP, method, sanitizeLog(host), sanitizeLog(matchedConditions),
		reqID, sanitizeLog(identity), sanitizeLog(rule))
}

// plPrintfAllowLine freezes the shape this change replaces: one logger.Printf
// with nine arguments. It is the baseline for the append-vs-Printf comparison.
func plPrintfAllowLine(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfAllowFmt,
		safeRule, priority, clientIP, method, sanitizeLog(host),
		sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plPrintfDropLine(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfDropFmt, safeRule, priority, clientIP, sanitizeLog(host),
		sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plPrintfBlockLine(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfBlockFmt, safeRule, priority, clientIP, sanitizeLog(host),
		sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

func plPrintfRedirectLine(rule string, priority int, clientIP, host, redirectURL, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	logger.Printf(plPrintfRedirectFmt, safeRule, priority, clientIP, sanitizeLog(host),
		sanitizeLog(redirectURL), sanitizeLog(matchedConditions), reqID, sanitizeLog(identity), safeRule)
}

// plArgs is the representative argument set, held in variables rather than used
// as constants at the call sites so the boxing cost is measured, not folded away.
var plArgs = struct{ clientIP, method, host, cond, reqID, identity, redirectURL string }{
	plClientIP, plMethod, plHost, plCond, plReqID, plIdentity, "https://portal.example.com/blocked",
}

// plLegacy runs the frozen pre-#1256 shape with the standard arguments.
func plLegacy(rule string, priority int) {
	plLegacyAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plPrintf runs the frozen pre-this-change shape with the standard arguments.
func plPrintf(rule string, priority int) {
	plPrintfAllowLine(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// plCurrentAllowLine calls the PRODUCTION emitter with the same inputs.
func plCurrentAllowLine(rule string, priority int) {
	logPolicyAllow(rule, priority, plArgs.clientIP, plArgs.method, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
}

// ── Sinks ───────────────────────────────────────────────────────────────────

// plNullSink discards everything written to it, like io.Discard, but is a
// distinct type so log.Logger's `w == io.Discard` check does not fire and the
// formatting path actually runs. See the harness note at the top of this file.
type plNullSink struct{ n int64 }

func (s *plNullSink) Write(p []byte) (int, error) { s.n += int64(len(p)); return len(p), nil }

// plSwapLogger points the package logger at w and returns a restore func.
// Used by the capture-based correctness tests, which need the bytes and want
// no prefix or timestamp in the way.
func plSwapLogger(w io.Writer) func() {
	prev := logger
	logger = log.New(w, "", 0)
	return func() { logger = prev }
}

// plSwapBenchLogger installs a logger with the PRODUCTION prefix and flags over
// a sink that formats but writes nowhere, and returns a restore func.
//
// The prefix and LstdFlags matter: formatHeader renders a date and a time into
// every line, so a benchmark run with flags 0 would leave that work out of both
// arms. The sink stands in for internal/logsink, which in production takes the
// bytes on a channel rather than a syscall, so the I/O this omits is I/O the
// request goroutine does not pay for either.
func plSwapBenchLogger() func() {
	prev := logger
	logger = log.New(&plNullSink{}, "[Culvert] ", log.LstdFlags)
	return func() { logger = prev }
}

// ── Before vs after ─────────────────────────────────────────────────────────
//
// Three shapes, one run, same hardware: the pre-#1256 Sprintf form, the Printf
// form this change replaces, and the production append form.

func BenchmarkPolicyDecisionLine_Legacy(b *testing.B) {
	defer plSwapBenchLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plLegacy(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Printf(b *testing.B) {
	defer plSwapBenchLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		plPrintf(plRule, plPriority)
	}
}

func BenchmarkPolicyDecisionLine_Current(b *testing.B) {
	defer plSwapBenchLogger()()
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
// does too, so these numbers include that contention — the same for both
// shapes, so the comparison stays honest. Expect a SMALLER relative gain here
// than serially: once four cores queue on that one mutex, the mutex is a larger
// share of the cost than the formatting this change removes.

func BenchmarkPolicyDecisionLine_PrintfParallel(b *testing.B) {
	defer plSwapBenchLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			plPrintf(plRule, plPriority)
		}
	})
}

func BenchmarkPolicyDecisionLine_CurrentParallel(b *testing.B) {
	defer plSwapBenchLogger()()
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
	defer plSwapBenchLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyBlock(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Drop(b *testing.B) {
	defer plSwapBenchLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyDrop(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

func BenchmarkPolicyDecisionLine_Redirect(b *testing.B) {
	defer plSwapBenchLogger()()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logPolicyRedirect(plRule, plPriority, plArgs.clientIP, plArgs.host, plArgs.redirectURL, plArgs.cond, plArgs.reqID, plArgs.identity)
	}
}

// ── Isolated: the two costs this change removes ─────────────────────────────

func BenchmarkPolicyPriority_LegacySprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = strings.ReplaceAll(fmt.Sprintf("%d", plPriority), "\n", "")
	}
}

// BenchmarkPolicyQuote_* isolate the %q verb. strconv.AppendQuote decodes rune
// by rune through strconv.IsPrint; the fast path settles printable ASCII with
// one byte scan. Two of these run per decision line.

var plQuoteSink []byte

func BenchmarkPolicyQuote_StrconvAppendQuote(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plQuoteSink = strconv.AppendQuote(buf[:0], plHost)
	}
}

func BenchmarkPolicyQuote_FastPath(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plQuoteSink = appendQuotedForLog(buf[:0], plHost)
	}
}

// BenchmarkPolicyQuote_FastPathMiss measures the fallback: a value the fast
// path must refuse (non-ASCII), so the cost of the scan is paid on top of
// AppendQuote. That is the price of the fast path when it does not apply.
func BenchmarkPolicyQuote_FastPathMiss(b *testing.B) {
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		plQuoteSink = appendQuotedForLog(buf[:0], "fïles.exåmple.com")
	}
}
