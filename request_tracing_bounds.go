package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// SEC-REQID-1 — the request path's client-supplied tracing headers
//
// setupRequestTracing (proxy.go) is the SECOND statement in handleRequest, so it
// runs on 100% of proxied traffic on every protocol — HTTP, CONNECT, WebSocket
// and SOCKS5's HTTP legs alike — ahead of the connection limiter, the IP filter
// and authentication. It reads two headers the CLIENT chooses, X-Request-Id and
// Traceparent, and until this file existed it bounded neither.
//
// The accepted X-Request-Id then reached, per request:
//
//  1. ~20 process-log sites (AUTH_FAIL, IP_BLOCKED, RATE_LIMITED, BLOCKED,
//     INVALID_HOST, and every POLICY_* decision line), as a bare `%s` inside the
//     `{req_id=… identity=… action=…}` block;
//  2. the response header, echoed back verbatim;
//  3. the forwarded request header, and so the upstream's logs too.
//
// The only sanitisation was `strings.ReplaceAll` for "\n" and "\r". That is the
// CWE-117 barrier CodeQL recognises and it correctly stops whole-record forgery,
// but it is NOT what sanitizeLog does: sanitizeLog scrubs every byte < 0x20 and
// 0x7F. So ESC, NUL, BEL, VT, FF and DEL all reached the forensic log verbatim,
// and nothing bounded the value's LENGTH at all.
//
// Both halves were measured against the real handler before this fix:
//
//   - CONTROL CHARACTERS. `X-Request-Id: abc\x1b[2Kdef\x00ghi\x07jkl\x7fmno`
//     came back out of setupRequestTracing byte-identical, where sanitizeLog
//     would have rendered "abc_[2Kdef_ghi_jkl_mno". An ESC sequence in a log an
//     operator tails rewrites what they see (the ANSI erase-line above deletes
//     the rest of the rendered line); a NUL truncates the record for readers
//     that treat it as a terminator.
//
//   - LENGTH. The proxy listener (main.go) sets no MaxHeaderBytes, so net/http's
//     1 MiB DefaultMaxHeaderBytes is the only ceiling. Eight requests carrying a
//     512 KiB X-Request-Id wrote 4,194,968 bytes into the process log — within
//     rounding of the 4,195,672 bytes CHAOS-63 measured from eight requests into
//     the audit log, and reached here through the UNAUTHENTICATED data plane
//     rather than the admin API. The process log is a fileutil.RotatingFile
//     capped at 50 MB keeping exactly ONE archive, so the whole retained record
//     — including whatever a responder would need to explain the incident — is
//     100 MB and rotates away in seconds. Every one of those writes SUCCEEDS, so
//     the logsink backpressure counter and every storage-health surface stay
//     green while the evidence is destroyed (CWE-778, OWASP A09:2021).
//
// THE FIX IS A BOUND AT THE ENTRY POINT, which is the CHAOS-63 rule: the guard
// has to sit in front of every sink that retains the value, and there is exactly
// one place both headers are read.
//
// WHAT A REJECTION DOES, and why it is not a refusal. A correlation id is a
// diagnostic aid, never a security-decision input, so refusing the REQUEST over
// one would convert a hardening change into an availability incident on an
// in-line gateway — the trade this repository refuses everywhere else (a stale
// threat feed does not block traffic; an unbindable admin UI does not kill the
// proxy). An unusable value is therefore treated exactly as an ABSENT one: the
// existing mint-a-fresh-id path runs, the minted id overwrites the hostile value
// in the request header (so it does not reach the upstream either) and on the
// response, and the request proceeds unchanged. A value we are unwilling to log
// is a value we could not have correlated on anyway.
//
// Deliberately NOT done:
//
//   - No truncation. Truncating still lets the caller choose the retained bytes
//     and silently corrupts trace correlation, which is worse than minting a
//     value that is honestly ours.
//   - No sanitizeLog at the ~20 log sites. That is ~20 edits on the hottest path
//     in the process, adds a scan per site per request, and leaves the length
//     unbounded — the response header and the upstream's logs are downstream of
//     this function too, and no amount of log-site scrubbing reaches them. One
//     check at the entry makes every sink safe by construction.
//   - No MaxHeaderBytes change on the proxy listener. Lowering it would change
//     which ordinary requests a forward proxy accepts, which is a product
//     decision and not this concern; it is recorded as a follow-up.
// ---------------------------------------------------------------------------

// maxClientRequestIDLen bounds a client-supplied X-Request-Id. Generous next to
// every correlation id in real use — a UUID is 36 bytes, nginx's $request_id 32,
// a ULID 26, a W3C trace-id 32 — so a legitimate upstream's value passes through
// and keeps its trace chain, while an invented one cannot pay for itself in log
// bytes. Culvert's own generated id is requestIDHexLen (16).
const maxClientRequestIDLen = 128

// maxClientTraceparentLen bounds a client-supplied Traceparent. A W3C version-00
// traceparent is exactly traceparentLen (55) bytes; the bound is deliberately
// far above that rather than exact, because the spec explicitly reserves longer
// values for future versions and a forward-compatible gateway must not drop a
// well-formed newer traceparent. It is a BYTE bound, not a format check: this
// file is closing an input-bounds hole, not deciding trace-context semantics.
const maxClientTraceparentLen = 255

// tracingHeaderRejected counts rejections per header. Two fixed series, never a
// caller-derived label — an unbounded label set is the WK-12/RS-5 defect, and
// the value being rejected here is by definition attacker-chosen.
var (
	requestIDRejected   atomic.Int64
	traceparentRejected atomic.Int64
)

// tracingBoundsLogWindow rate-limits the rejection log line. A mitigation for a
// write-amplification defect must not be one itself: onset is logged
// immediately, then at most one line per window, with the magnitude carried by
// the counters (the CHAOS-54/63 rule).
const tracingBoundsLogWindow = time.Minute

var (
	tracingBoundsLogMu   sync.Mutex
	tracingBoundsLogLast time.Time
)

// acceptableTracingHeaderValue reports whether a client-supplied tracing header
// value may be retained — logged, echoed and forwarded — as it stands.
//
// The charset is VISIBLE ASCII WITH NO WHITESPACE (0x21..0x7E), and each end of
// that range is load-bearing:
//
//   - below 0x21 excludes every C0 control character, which is what sanitizeLog
//     scrubs everywhere else in this tree and what makes a log line forgeable or
//     a terminal rewritable; it also excludes the SPACE at 0x20, because the
//     decision lines render the id inside a space-separated
//     `{req_id=… identity=… action=…}` block, so a value containing a space can
//     inject additional key=value tokens that a first-wins log parser reads in
//     preference to the real ones. Barring space makes that block unforgeable
//     without needing the parsers to be careful.
//   - 0x7E is the last printable ASCII byte, so 0x7F (DEL) and every non-ASCII
//     byte are excluded. Non-ASCII is not dangerous in itself, but a correlation
//     id has no need of it and admitting it would mean reasoning about UTF-8
//     validity, normalisation and width in a log line.
//
// An empty value is NOT acceptable: it carries no correlation and the caller
// already treats it as absent. The scan is bounded by the caller's length check,
// allocation-free, and exits on the first offending byte.
func acceptableTracingHeaderValue(v string, maxLen int) bool {
	if v == "" || len(v) > maxLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

// acceptClientRequestID reports whether a client-supplied X-Request-Id may be
// adopted as this request's correlation id.
func acceptClientRequestID(v string) bool {
	return acceptableTracingHeaderValue(v, maxClientRequestIDLen)
}

// acceptClientTraceparent reports whether a client-supplied Traceparent may be
// propagated rather than replaced with a freshly generated one.
func acceptClientTraceparent(v string) bool {
	return acceptableTracingHeaderValue(v, maxClientTraceparentLen)
}

// noteRejectedRequestID records a refused X-Request-Id: the counter always, a
// log line at most once per window.
//
// The refused VALUE is never logged, in either the line or the counter. It is
// attacker-chosen, unbounded and (by the fact that it was refused) carries bytes
// this file exists to keep out of the log — echoing it to explain why it was
// rejected would perform the exact amplification being prevented. The length and
// the running count are what an operator needs.
func noteRejectedRequestID(clientIP string, n int) {
	requestIDRejected.Add(1)
	if noteTracingBoundsLog() {
		logWarnf("Tracing: replaced an unusable client %s from %s (%d bytes, limit %d, visible-ASCII only); %d replaced since boot",
			headerRequestID, sanitizeLog(clientIP), n, maxClientRequestIDLen, requestIDRejected.Load())
	}
}

// noteRejectedTraceparent records a refused Traceparent. Same contract as
// noteRejectedRequestID: counter always, value never.
func noteRejectedTraceparent(clientIP string, n int) {
	traceparentRejected.Add(1)
	if noteTracingBoundsLog() {
		logWarnf("Tracing: replaced an unusable client %s from %s (%d bytes, limit %d, visible-ASCII only); %d replaced since boot",
			headerTraceparent, sanitizeLog(clientIP), n, maxClientTraceparentLen, traceparentRejected.Load())
	}
}

// noteTracingBoundsLog reports whether a rejection may emit a log line, arming
// the window when it does. The window is SHARED by both headers on purpose: a
// source sending one hostile tracing header is overwhelmingly likely to be
// sending the other, and two independent windows would double the log bandwidth
// a flood can buy for no extra operator signal.
func noteTracingBoundsLog() bool {
	now := time.Now()
	tracingBoundsLogMu.Lock()
	defer tracingBoundsLogMu.Unlock()
	if !tracingBoundsLogLast.IsZero() && now.Sub(tracingBoundsLogLast) < tracingBoundsLogWindow {
		return false
	}
	tracingBoundsLogLast = now
	return true
}

// resetTracingBoundsStateForTest clears the process-global counters and the log
// gate so tests do not inherit each other's state. Production never calls it.
func resetTracingBoundsStateForTest() {
	requestIDRejected.Store(0)
	traceparentRejected.Store(0)
	tracingBoundsLogMu.Lock()
	tracingBoundsLogLast = time.Time{}
	tracingBoundsLogMu.Unlock()
}
