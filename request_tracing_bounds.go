package main

import (
	"net/http"
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
// 0x7F. So nothing bounded the value's CHARSET beyond CR/LF, and nothing bounded
// its LENGTH at all.
//
// WHAT IS ACTUALLY DELIVERABLE — MEASURED OVER A SOCKET, AND A CORRECTION
// (SEC-REQID-2, request_tracing_wire_bounds_test.go). The first version of this
// note said that "ESC, NUL, BEL, VT, FF and DEL all reached the forensic log
// verbatim" and offered `abc\x1b[2Kdef\x00ghi\x07jkl\x7fmno` as a payload that
// "came back out of setupRequestTracing byte-identical". That was measured by
// calling this function with httptest.NewRequest + Header.Set, which installs a
// header value THE WIRE CANNOT DELIVER — precisely the trap that
// bootstrap_host_injection_test.go exists for one subsystem over, in its own
// words: "httptest.NewRequest lets a test set an r.Host the wire could never
// deliver, which would make the gate prove less than it claims". Driven through
// a REAL net/http server instead: of 256 byte values, 224 are delivered into a
// header value verbatim and 32 draw a 400 BEFORE the handler runs — exactly
// C0 minus TAB, plus DEL (0x7F), refused by net/http's own
// textproto.ReadMIMEHeader. And
// setupRequestTracing has exactly ONE caller — handleRequest, whose request is
// always produced by that parser (the inspected-H2 server dispatches to
// h2InspectStream, and the SSL-inspect inner loop's http.ReadRequest runs the
// same validation) — so no ESC or NUL ever reached a log line by any path.
//
// The bound is NOT redundant for that. It is load-bearing on 130 byte values
// net/http carries happily, and the reachable exposures are these:
//
//   - TAB (0x09) and SPACE (0x20). These are the dangerous deliverable bytes,
//     and the reason recorded on acceptableTracingHeaderValue is the right one:
//     the decision lines render the id inside a space-separated
//     `{req_id=… identity=… action=…}` block, so a value carrying either
//     injects additional key=value tokens that a first-wins log parser reads in
//     preference to the real ones. Reachable over the wire, and closed here.
//
//   - EVERY BYTE 0x80..0xFF, which net/http does not restrict at all, so a
//     correlation id could carry arbitrary non-ASCII into the log, the response
//     and the upstream.
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

// tracingBoundsLogLast is the last emission instant in Unix nanoseconds, held as
// an ATOMIC rather than behind a mutex.
//
// The CHAOS-63 precedent (noteLoginOversizeLog) uses a sync.Mutex, and that is
// correct THERE: the admin login endpoint sits behind the 60-mutating-POST/min
// per-IP API limiter, so the gate is reachable about once a second. This gate is
// reached from setupRequestTracing — the second statement in handleRequest,
// ahead of the connection limiter, the IP filter and the rate limiter — so under
// the very flood it exists to bound, an unsharded process-wide mutex would be
// taken once per hostile request by every serving goroutine at once. That is the
// throughput ceiling internal/connlimit and the per-IP rate limiter were sharded
// to remove, reintroduced in front of both. The atomic keeps the suppressed path
// — which is every path during a flood — to one uncontended load and a compare.
var tracingBoundsLogLast atomic.Int64

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

// tracingHeaderBytes totals the bytes across every field value of a repeated
// tracing header, so a rejection reports what the client actually tried to put
// there rather than only the first value's length. Allocation-free; the slice is
// the one net/http already built.
func tracingHeaderBytes(vals []string) int {
	n := 0
	for i := range vals {
		n += len(vals[i])
	}
	return n
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
// IT TAKES THE REQUEST, NOT A RESOLVED CLIENT IP, AND THAT IS THE WHOLE POINT
// (Codex P1, PR #1406). The first shape resolved realClientIP at the CALL SITE,
// so every rejection paid for it. Behind a configured trusted proxy —
// i.e. Culvert's ordinary deployment behind a load balancer — realClientIP joins
// EVERY X-Forwarded-For field line into one string and splits it on every comma,
// then parses each token. Against a near-1 MiB XFF that is a ~1 MiB copy plus a
// slice with one header per comma (hundreds of thousands of them), per rejection,
// TWICE when both tracing headers are hostile — and it ran ahead of the
// connection limiter, the IP filter and the rate limiter, from an unauthenticated
// request. This file's own rule ("a mitigation for a write-amplification defect
// must not be one itself") was applied to the log LINE and not to the work that
// produced its arguments: the bound stopped bytes reaching the log and opened a
// CPU-and-allocation amplifier in front of every limiter.
//
// Resolution is therefore DEFERRED behind the rate gate: it happens at most once
// per tracingBoundsLogWindow, on the one request in a flood that actually emits a
// line. The operator still gets the real client IP rather than the proxy's, which
// is the reason not to simply log the direct peer instead.
//
// The refused VALUE is never logged, in either the line or the counter. It is
// attacker-chosen, unbounded and (by the fact that it was refused) carries bytes
// this file exists to keep out of the log — echoing it to explain why it was
// rejected would perform the exact amplification being prevented. The length and
// the running count are what an operator needs.
func noteRejectedRequestID(r *http.Request, n int) {
	requestIDRejected.Add(1)
	if noteTracingBoundsLog() {
		logWarnf("Tracing: replaced an unusable client %s from %s (%d bytes, limit %d, visible-ASCII only); %d replaced since boot",
			headerRequestID, sanitizeLog(realClientIP(r)), n, maxClientRequestIDLen, requestIDRejected.Load())
	}
}

// noteRejectedTraceparent records a refused Traceparent. Same contract as
// noteRejectedRequestID: counter always, value never, and the client IP resolved
// only behind the rate gate.
func noteRejectedTraceparent(r *http.Request, n int) {
	traceparentRejected.Add(1)
	if noteTracingBoundsLog() {
		logWarnf("Tracing: replaced an unusable client %s from %s (%d bytes, limit %d, visible-ASCII only); %d replaced since boot",
			headerTraceparent, sanitizeLog(realClientIP(r)), n, maxClientTraceparentLen, traceparentRejected.Load())
	}
}

// noteTracingBoundsLog reports whether a rejection may emit a log line, arming
// the window when it does.
//
// The window is SHARED by both headers on purpose: a source sending one hostile
// tracing header is overwhelmingly likely to be sending the other, and two
// independent windows would double the log bandwidth a flood can buy for no extra
// operator signal.
//
// The suppressed path — every path during a flood — is one atomic load and a
// compare, taking no lock; see tracingBoundsLogLast for why a mutex is wrong
// HERE even though the CHAOS-63 precedent correctly uses one. The CAS makes
// exactly one racing caller the winner of each window; the losers suppress, which
// is the same answer they would have got from a mutex.
//
// A clock that went BACKWARDS re-arms rather than suppressing (a negative delta
// falls through to the CAS). Suppressing would silence the operator for however
// far back the clock went, and the CHAOS-61 rule is that a negative age fails
// toward the safe answer — here, still reporting.
func noteTracingBoundsLog() bool {
	now := time.Now().UnixNano()
	last := tracingBoundsLogLast.Load()
	if last != 0 {
		if d := now - last; d >= 0 && d < int64(tracingBoundsLogWindow) {
			return false
		}
	}
	return tracingBoundsLogLast.CompareAndSwap(last, now)
}

// resetTracingBoundsStateForTest clears the process-global counters and the log
// gate so tests do not inherit each other's state. Production never calls it.
func resetTracingBoundsStateForTest() {
	requestIDRejected.Store(0)
	traceparentRejected.Store(0)
	tracingBoundsLogLast.Store(0)
}
