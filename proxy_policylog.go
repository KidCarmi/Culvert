package main

// Per-request policy-decision log lines.
//
// applyPolicyDecision emits exactly ONE of these per proxied request — ALLOW,
// BLOCK, DROP, REDIRECT, or DEFAULT_DENY — so they sit on 100% of the dispatch
// hot path, on every protocol, and their construction is the largest single
// piece of CPU handleRequest spends outside the upstream round trip.
//
// ── Why these are hand-appended rather than one logger.Printf ────────────────
//
// They used to be a single logger.Printf per branch, which is the idiomatic
// spelling and was assumed to be cheap. Measured against a PRODUCTION-SHAPED
// sink (see the measurement note below for why that qualifier is the whole
// story) one POLICY_ALLOW line cost 1240 ns and 8 heap objects on the request
// goroutine, decomposing as:
//
//	~181 ns  log.Logger's own floor: time.Now, formatHeader, the write
//	~110 ns  the four sanitizeLog scans (allocation-free on clean input)
//	~949 ns  fmt: boxing nine arguments into an []any (all 8 objects) and
//	         fmt.Appendf's reflective walk over nine verbs, two of them %q
//
// So roughly 77% of the line was fmt overhead over a format string that is a
// compile-time constant with a fixed, known shape. Appending the same bytes by
// hand into a stack buffer and handing the finished line to logger.Output
// removes the boxing and the reflective walk entirely: 1240 -> 474 ns and
// 8 -> 1 allocations per proxied request, with byte-identical output
// (pinned by TestPolicyDecisionLine_MatchesFrozenFmtShapes and the fuzz target
// over the quoting helper).
//
// The one remaining allocation is the string conversion logger.Output requires.
// It could be removed with unsafe.String over the stack buffer, or by writing
// the header and the line straight to logger.Writer(); both are deliberately
// NOT done. A string pointing into a frame the runtime may move is the wrong
// risk to take on a security appliance's forensic log for 60 ns, the same
// judgement the sanitizeLog SWAR experiment was rejected under; and bypassing
// log.Logger would give up the outMu that serialises writes against every other
// logger user, which is not worth 192 bytes.
//
// B/op moves the other way and that is a real trade, stated rather than
// glossed: 128 B (eight 16-byte interface boxes) becomes one 192-byte string.
// Measured in ISOLATION — 2M lines and nothing else allocating — that is 256 MB
// against 384 MB and 59 GC cycles against 88, because Go's pacer triggers on
// bytes, not objects. At the real duty cycle it is the other way round: one
// proxied request allocates ~14.7 KB across ~185 objects end to end, so this
// line moves the request's heap bytes by +0.4% (inside run-to-run variance in
// BenchmarkPerfQual_ProxyHTTPForward) while removing 6 of its 185 objects. The
// CPU saving is not a trade at all.
//
// ── Measurement note: io.Discard hides most of this, so never benchmark with it ─
//
// log.New(io.Discard, …) sets the Logger's isDiscard flag, and Logger.output
// returns on that flag BEFORE it calls fmt.Appendf. A benchmark that points the
// package logger at io.Discard therefore measures the ARGUMENT BOXING ONLY and
// never the formatting — it reported 415 ns for a line that really costs 1337.
// That blind spot is why this cost survived the earlier pass over these very
// functions (PR #1256, which removed two of ten allocations and measured the
// rest against io.Discard). The benchmarks and the allocation gate now use a
// plain discarding io.Writer that is NOT io.Discard; see plSwapLogger.
//
// ── Contracts every one of these lines keeps ────────────────────────────────
//
//   - Byte-identical output. These lines are consumed by SIEM forwarders and
//     log parsers; the emitted bytes are frozen, and the differential test
//     compares each emitter against a verbatim copy of the fmt shape it
//     replaced rather than against a re-description of it.
//
//   - The rule name is sanitized ONCE and used for both the leading rule=%q and
//     the trailing rule=%s. Taking the RAW name as the parameter is deliberate:
//     it puts the sanitize-once decision inside the measured function, where
//     reintroducing a second call fails TestBenchGate_PolicyDecisionLineAllocs.
//
//   - Every string-typed argument that can carry client- or admin-supplied data
//     still goes through sanitizeLog — the same values, at the same points, in
//     the same order as the format arguments they replaced, so the CWE-117
//     barrier the code conventions require is exactly where it was. The
//     unsanitized ones are unsanitized for the same reasons as before:
//     clientIP is a net.SplitHostPort product of the kernel-supplied peer
//     address, method and reqID are proxy-generated. appendQuotedLogValue is a
//     renderer and NOT a sanitiser — it is what %q was, and it is fed values
//     sanitizeLog has already scrubbed.
//
//   - The priority stays unsanitized and is rendered with strconv.AppendInt.
//     That rule covers STRING values reaching a log sink; Priority is an int
//     field of the admin-configured rulebase, carries no client-controlled
//     data, and base-10 rendering of an int can only ever emit [-0-9] — exactly
//     the digits %d emitted, over the whole int range including math.MinInt
//     (pinned by the differential test). It was spelled
//     strings.ReplaceAll(fmt.Sprintf("%d", …), "\n", "") until PR #1256, i.e.
//     an int formatted to a string and then scanned for a byte a decimal
//     integer cannot contain; do not restore that.

import "strconv"

// policyLineBufSize is the stack buffer each emitter formats into. An ordinary
// decision line is ~185 bytes; 512 covers the long-but-plausible shape (a
// descriptive rule name, a deep subdomain, an email identity and a full
// condition list, measured at ~390 bytes) so that case also completes in one
// allocation instead of spilling into a heap regrow first. The buffer never
// escapes — the line is copied out by the string conversion — so the cost of
// the extra headroom is stack zeroing, measured at under 10 ns and invisible
// beside what the change removes.
const policyLineBufSize = 512

// policyLineCallDepth is what Logger.Printf passes internally. Printf calls
// l.output(0, 2, …) while Output(n) calls l.output(0, n+1, …), so Output(1)
// resolves the identical frame. It is inert either way — the process logger is
// built with log.LstdFlags (or no flags in JSON mode) and calldepth is read
// only for Lshortfile/Llongfile — but matching Printf exactly means a future
// flag change cannot silently move which frame these lines report.
const policyLineCallDepth = 1

// appendQuotedLogValue appends s quoted exactly as fmt's %q verb would, i.e.
// exactly strconv.Quote(s).
//
// strconv.Quote decodes and re-encodes rune by rune and consults strconv.IsPrint
// for each one; on the two quoted fields of a decision line that measured ~280 ns
// per request, the single largest item left after fmt was removed. Every byte in
// [0x20,0x7e] other than '"' and '\\' is a printable ASCII rune that Quote emits
// verbatim, so for a value made only of those the answer is the value with a
// quote on each end and no decoding is needed. Anything else — a quote, a
// backslash, DEL, or any byte >= 0x80, including invalid UTF-8 — falls through to
// strconv.Quote itself, so the fast path can only ever be an exact shortcut and
// never an approximation. Equivalence is pinned by FuzzAppendQuotedLogValue and
// by a table of hand-picked boundary shapes.
//
// Callers pass values that sanitizeLog has already scrubbed; this function is a
// renderer, not a sanitiser, exactly as %q was.
func appendQuotedLogValue(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			return strconv.AppendQuote(b, s)
		}
	}
	b = append(b, '"')
	b = append(b, s...)
	return append(b, '"')
}

// appendPolicyHead appends `<TAG> rule="<rule>" pri=<n>`, the opening every
// rule-matched decision line shares.
func appendPolicyHead(b []byte, tag, safeRule string, priority int) []byte {
	b = append(b, tag...)
	b = append(b, " rule="...)
	b = appendQuotedLogValue(b, safeRule)
	b = append(b, " pri="...)
	return strconv.AppendInt(b, int64(priority), 10)
}

// appendPolicyTail appends ` [<conditions>] {req_id=… identity=… rule=… action=…}`,
// the closing every rule-matched decision line shares. safeRule is the
// already-sanitized name the head quoted, reused rather than re-scanned.
func appendPolicyTail(b []byte, matchedConditions, reqID, identity, safeRule, action string) []byte {
	b = append(b, " ["...)
	b = append(b, sanitizeLog(matchedConditions)...)
	b = append(b, "] {req_id="...)
	b = append(b, reqID...)
	b = append(b, " identity="...)
	b = append(b, sanitizeLog(identity)...)
	b = append(b, " rule="...)
	b = append(b, safeRule...)
	b = append(b, " action="...)
	b = append(b, action...)
	return append(b, '}')
}

// emitPolicyLine hands the finished line to the package logger. Output appends
// the string to the logger's own pooled buffer and adds the newline, which is
// precisely what Printf's fmt.Appendf callback did.
func emitPolicyLine(b []byte) {
	_ = logger.Output(policyLineCallDepth, string(b)) //nolint:errcheck // log write failure is not actionable on the request path; Printf discarded it identically
}

// logPolicyAllow emits the POLICY_ALLOW decision line. host is r.Host (the
// authority as the client sent it), not the port-stripped host the block
// branches log — preserved from the pre-extraction call sites verbatim.
func logPolicyAllow(rule string, priority int, clientIP, method, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	var buf [policyLineBufSize]byte
	b := appendPolicyHead(buf[:0], "POLICY_ALLOW", safeRule, priority)
	b = append(b, ' ')
	b = append(b, clientIP...)
	b = append(b, ' ')
	b = append(b, method...)
	b = append(b, ' ')
	b = appendQuotedLogValue(b, sanitizeLog(host))
	b = appendPolicyTail(b, matchedConditions, reqID, identity, safeRule, "allow")
	emitPolicyLine(b)
}

// logPolicyDrop emits the POLICY_DROP decision line.
func logPolicyDrop(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	var buf [policyLineBufSize]byte
	b := appendPolicyHead(buf[:0], "POLICY_DROP", safeRule, priority)
	b = append(b, ' ')
	b = append(b, clientIP...)
	b = append(b, " -> "...)
	b = appendQuotedLogValue(b, sanitizeLog(host))
	b = appendPolicyTail(b, matchedConditions, reqID, identity, safeRule, "drop")
	emitPolicyLine(b)
}

// logPolicyBlock emits the POLICY_BLOCK decision line.
func logPolicyBlock(rule string, priority int, clientIP, host, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	var buf [policyLineBufSize]byte
	b := appendPolicyHead(buf[:0], "POLICY_BLOCK", safeRule, priority)
	b = append(b, ' ')
	b = append(b, clientIP...)
	b = append(b, " -> "...)
	b = appendQuotedLogValue(b, sanitizeLog(host))
	b = appendPolicyTail(b, matchedConditions, reqID, identity, safeRule, "block")
	emitPolicyLine(b)
}

// logPolicyRedirect emits the POLICY_REDIRECT decision line. Reached only after
// isSafeRedirectURL has accepted redirectURL.
func logPolicyRedirect(rule string, priority int, clientIP, host, redirectURL, matchedConditions, reqID, identity string) {
	safeRule := sanitizeLog(rule)
	var buf [policyLineBufSize]byte
	b := appendPolicyHead(buf[:0], "POLICY_REDIRECT", safeRule, priority)
	b = append(b, ' ')
	b = append(b, clientIP...)
	b = append(b, " -> "...)
	b = appendQuotedLogValue(b, sanitizeLog(host))
	b = append(b, " => "...)
	b = appendQuotedLogValue(b, sanitizeLog(redirectURL))
	b = appendPolicyTail(b, matchedConditions, reqID, identity, safeRule, "redirect")
	emitPolicyLine(b)
}

// logPolicyDefaultDeny emits the POLICY_DEFAULT_DENY line — the Zero Trust
// fall-through, reached when no rule matched and passthrough is off. It names no
// rule, so it shares neither the head nor the tail helper; it is here because it
// is the fifth per-request decision line and paid the same fmt cost as the other
// four. On a deployment whose rulebase does not yet cover its traffic this is
// the HOTTEST of the five, which is exactly when a gateway can least afford it.
//
// host is r.Host and method is r.Method, matching the call site verbatim.
func logPolicyDefaultDeny(clientIP, method, host, reqID, identity string) {
	var buf [policyLineBufSize]byte
	b := append(buf[:0], "POLICY_DEFAULT_DENY "...)
	b = append(b, clientIP...)
	b = append(b, ' ')
	b = append(b, method...)
	b = append(b, ' ')
	b = appendQuotedLogValue(b, sanitizeLog(host))
	b = append(b, " {req_id="...)
	b = append(b, reqID...)
	b = append(b, " identity="...)
	b = append(b, sanitizeLog(identity)...)
	b = append(b, " action=deny}"...)
	emitPolicyLine(b)
}
