package main

// Per-request policy-decision line construction.
//
// applyPolicyDecision emits exactly ONE of these lines per proxied request —
// POLICY_ALLOW / POLICY_BLOCK / POLICY_DROP / POLICY_REDIRECT — on every
// protocol, so the cost is paid on 100% of traffic.
//
// The emitters used to hand nine values to logger.Printf. An EXACT allocation
// profile of the end-to-end forward benchmark (-memprofilerate=1,
// BenchmarkPerfQual_ProxyHTTPForward/rules=100) put SEVEN allocations per
// request on that argument list and NOTHING anywhere else in the call:
//
//	     14007      14007   800:  safeRule, priority, clientIP, method, …
//
// flat == cum for logPolicyAllow, i.e. the whole Printf tree — the formatting,
// the %q quoting, the write — allocated nothing beyond the arguments
// themselves. log.Logger reuses its own output buffer, so the only cost was
// the []any slice and one string->interface box per value. Seven allocations
// per request bought nothing but the ability to pass the values through a
// variadic ...any.
//
// Measured against everything else on the path, that single line was the
// largest Culvert-owned allocation site in the proxy: of the 13.6 allocations
// handleRequest makes OUTSIDE the upstream round trip, it was 7.0 — 51%.
//
// So the line is built directly. The template is fixed and uses exactly three
// verbs, each with a byte-identical append-form:
//
//	%q  ->  strconv.AppendQuote  (what fmt's fmtQ calls for a plain string)
//	%d  ->  strconv.AppendInt
//	%s  ->  append
//
// Byte-identity is NOT assumed. proxy_policylog_bench_test.go keeps a verbatim
// copy of the previous fmt-based implementation and pins the two against each
// other over hand-picked divergence shapes, randomised inputs and a fuzz
// target — the convention plLegacyAllowLine and TestIPFilterView_Differential
// AgainstLegacy already follow.
//
// SANITISATION IS UNCHANGED AND IS WALLED. Every value that reaches a line is
// still either a sanitizeLog() result or one of three bare values that cannot
// carry client-chosen bytes (see policyLineSafeBare in the test). The CWE-117
// barrier CodeQL recognises lives inside sanitizeLog — its leading
// strings.ReplaceAll is the FIRST statement and reassigns s, so it is on every
// return path — and that function is untouched here. Nothing in this file
// widens what reaches the log; it only changes how the bytes are assembled.

import (
	"strconv"
	"strings"
)

// policyLineSizeHint is the builder's starting capacity, in bytes, on top of
// the variable-length values a line carries.
//
// It covers the longest fixed template (POLICY_REDIRECT, 78 bytes), the
// priority's digits, and the two quote characters each %q field adds. It is a
// HINT, never a bound: strings.Builder grows on its own if a heavily-escaped
// %q field overruns it, so an underestimate costs one extra allocation and
// never a wrong byte.
const policyLineSizeHint = 96

// growPolicyLine sizes b so an ordinary decision line needs exactly ONE
// allocation — the line itself, which strings.Builder then hands to the caller
// without copying it again.
//
// It takes the builder as a parameter rather than returning one, and that is a
// measured decision, not a style choice: returning a *strings.Builder makes the
// builder itself escape to the heap, which cost a second allocation per line.
// strings.Builder's copyCheck uses abi.NoEscape on its self-pointer precisely
// so the struct can stay on the caller's stack, and it only does when the
// caller owns it. Pinned by TestBenchGate_PolicyDecisionLineAllocs.
//
// The variadic slice does not escape either — the loop only reads it — so it
// stays on the stack too.
func growPolicyLine(b *strings.Builder, fields ...string) {
	n := policyLineSizeHint
	for _, f := range fields {
		n += len(f)
	}
	b.Grow(n)
}

// policyLineHead writes the part every decision line opens with:
//
//	<verb> rule=<quoted rule> pri=<priority> <clientIP>
//
// It stops immediately after clientIP; the caller's middle section supplies
// its own leading separator, exactly as each format string does.
func policyLineHead(b *strings.Builder, verb, safeRule string, priority int, clientIP string) {
	b.WriteString(verb)
	b.WriteString(" rule=")
	writeQuoted(b, safeRule)
	b.WriteString(" pri=")
	writeInt(b, priority)
	b.WriteByte(' ')
	b.WriteString(clientIP)
}

// policyLineTail writes the part every decision line closes with:
//
//	[<conditions>] {req_id=<id> identity=<identity> rule=<rule> action=<action>}
func policyLineTail(b *strings.Builder, safeConditions, reqID, safeIdentity, safeRule, action string) {
	b.WriteString(" [")
	b.WriteString(safeConditions)
	b.WriteString("] {req_id=")
	b.WriteString(reqID)
	b.WriteString(" identity=")
	b.WriteString(safeIdentity)
	b.WriteString(" rule=")
	b.WriteString(safeRule)
	b.WriteString(" action=")
	b.WriteString(action)
	b.WriteByte('}')
}

// writeQuoted renders s exactly as fmt's %q verb does for a plain string.
//
// fmt.fmt.fmtQ calls strconv.AppendQuote for a string with no plus or sharp
// flag, so the SLOW PATH below is literally the code fmt would have run, byte
// for byte — including for invalid UTF-8, which renders as \xNN escapes.
//
// The fast path exists because quoting is the single most expensive thing left
// in a decision line: a CPU profile of the built line put strconv's
// appendQuotedWith + appendEscapedRune at 32% of it, because appendQuotedWith
// has no bulk path — it decodes a rune and calls appendEscapedRune (which
// consults strconv.IsPrint) for EVERY rune, even in a string that needs no
// escaping at all. Measured standalone on an ordinary 17-byte hostname:
// 123 ns/op.
//
// For a string of plain printable ASCII carrying no quote and no backslash,
// strconv.Quote's output is exactly the input wrapped in quotes: every such
// byte is its own rune, strconv.IsPrint is true across 0x20-0x7E, and neither
// of the two characters Quote escapes unconditionally is present. So the scan
// below decides, in one pass with no decoding, whether that holds — and falls
// back to strconv for everything else rather than reimplementing any escape.
//
// This is the common case BY CONSTRUCTION, not by luck: every value that
// reaches here has already been through sanitizeLog, which replaces every byte
// below 0x20 and DEL with '_'. What remains are hostnames, rule names,
// identities and condition lists.
//
// The equivalence is not argued, it is pinned: TestPolicyDecisionLine_Quoting
// MatchesFmt walks every byte value in both paths and FuzzPolicyDecisionLine
// Quoting compares the two against arbitrary input.
func writeQuoted(b *strings.Builder, s string) {
	if quotableAsIs(s) {
		b.WriteByte('"')
		b.WriteString(s)
		b.WriteByte('"')
		return
	}
	var scratch [64]byte
	b.Write(strconv.AppendQuote(scratch[:0], s))
}

// quotableAsIs reports whether strconv.Quote(s) is exactly `"` + s + `"`.
//
// Deliberately conservative: it answers yes only for printable ASCII with no
// quote and no backslash. A false NO costs one trip through strconv and is
// always safe; a false YES would corrupt a log line, which is why the bound is
// the narrow byte range rather than anything cleverer.
func quotableAsIs(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7E || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// writeInt renders n exactly as fmt's %d verb does for an int, negatives
// included.
func writeInt(b *strings.Builder, n int) {
	var scratch [20]byte
	b.Write(strconv.AppendInt(scratch[:0], int64(n), 10))
}

// emitPolicyLine writes one fully-built decision line through the package
// logger.
//
// Output takes the line as a plain string PARAMETER rather than through
// ...any, which is what keeps the emission itself allocation-free — it is the
// same sink Printf funnels into, so the async logsink, the rotating file and
// the JSON record writer all see exactly what they saw before (one Write per
// record).
//
// The calldepth is inert: setupLogger builds the logger with log.LstdFlags, or
// with 0 in JSON mode, and Output consults calldepth only for Lshortfile /
// Llongfile. Pinned by TestPolicyDecisionLine_LoggerCarriesNoCallerPositionFlag
// so that adding a caller-position flag fails here rather than silently
// mislabelling these four lines.
func emitPolicyLine(line string) {
	// Printf discarded this error too; the writer's health is the log sink's
	// concern, not the request path's.
	_ = logger.Output(2, line)
}
