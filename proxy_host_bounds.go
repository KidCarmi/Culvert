package main

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------------------------------------------------------------------
// CHAOS-66 — the client-supplied destination authority on the proxy data path
//
// Register row PX-21 opened this: `handleRequest` copies `r.Host` into the
// process log and the request-log entry, `sanitizeLog` neutralises control
// characters and bounds NOTHING, and the proxy `http.Server` sets no
// MaxHeaderBytes — so net/http admits net/http's 1 MiB default of request line
// plus headers and every byte of the authority reaches both rotating sinks.
// That is the §32 (CHAOS-63) write-amplification defect on a port every client
// on the network can reach rather than on the admin login endpoint.
//
// Measuring it found something considerably worse. The authority is not only
// COPIED, it is WALKED — label by label — by every destination matcher on the
// request path, and two of those walks are QUADRATIC in its length:
//
//   - internal/urlcat `lookupIn` (reached by every DestCategoryGroup rule via
//     `categoryGroupMatchesHostScratch` → `hostCatScratch.fusion()`) probes the
//     host and then EVERY suffix that starts just past a '.' against the
//     reverse host index. The index is non-empty on any deployment (the shipped
//     default taxonomy is 657 patterns), so each probe hashes its whole suffix:
//     Σ suffix lengths ≈ L²/4.
//   - internal/catdb `CommunityDB.Lookup` walks parent domains and opens ONE
//     BadgerDB read transaction per label. `-cat-feed-db /data/catfeeddb` is
//     enabled by DEFAULT in the shipped docker-compose.
//
// Measured on a 4-core box through the REAL handleRequest, with one ordinary
// DestCategoryGroup rule and the Layer-2 feed present:
//
//	host bytes      wall clock
//	       251        0.45 ms
//	     4 095       19.6 ms
//	    16 383      260   ms
//	    65 535     3 940   ms
//
// Clean quadratic — 4x the length is ~15x the time — so at net/http's 1 MiB
// header default ONE request costs on the order of SIXTEEN MINUTES of a core.
// It is spent inside the request goroutine, holding the client connection, an
// FD and a per-IP connlimit slot, and it is reached BEFORE authentication: the
// gate order in handleRequest is connlimit → IP filter → rate limit → auth →
// policy, and all three front-door limiters ship DISABLED (`-rate-limit`
// defaults to 0; see §25/CHAOS-57). ~256 KB/s from one client saturates a
// four-core gateway. The engine primitives on their own: urlcat LookupHost is
// 5.38 s at 1 MiB, catdb Lookup is 4.09 s at 64 KiB (≈32 767 badger
// transactions) and quadratic above that.
//
// **THE BOUND HAS TO BE AT THE ENTRY POINT, AND — UNLIKE CHAOS-63 — THERE IS
// NO STRUCTURAL HALF AVAILABLE IN THE LEAF.** §32 could clamp inside
// internal/lockout because a clamped key is still a usable key. A length guard
// inside the matchers cannot work the same way: the suffix walk exists so that
// `a.b.example.com` matches a stored `example.com`, so an over-long host still
// has SHORT suffixes that may legitimately match, and skipping the walk on
// length would change the verdict — fail-OPEN for a block rule, which is
// strictly worse than the cost it saves. Refusing the request outright is the
// only bound that is both free and semantics-preserving, which is exactly the
// shape row PX-21 predicted ("rejecting an over-long host outright is
// defensible and probably correct").
//
// Refusing is safe because a DNS name this long cannot exist. RFC 1035 §2.3.4
// caps a wire-format name at 255 octets, which is 253 characters in
// presentation form (RFC 1123 §2.1), and `idna.ToASCII` is called here under
// the zero-option Punycode profile whose DNS-length check is DISABLED — which
// is precisely why hostutil's strict gate let a megabyte through. An IP literal
// is far shorter, bracketed or not. So the refused set contains no destination
// any resolver would answer for.
//
// Deliberately NOT done here:
//
//   - **No MaxHeaderBytes change on the proxy server.** It bounds the whole
//     header block, not the authority, so lowering it would cut the worst case
//     by a constant while breaking clients with large cookie or token headers.
//     It is the wrong instrument for a bound on one field.
//   - **No length guard inside urlcat/catdb/blocklist**, for the fail-open
//     reason above. Recorded rather than traded away.
//   - **No bound on the inner request path or URI.** The inspected H1/H2 loops
//     attribute every inner request to `hostOnly`, the CONNECT target, which
//     this gate already bounded; the inner `req.URL.Path` is a separate
//     unbounded untrusted value (register row PX-22) that needs a decryption
//     profile and an allowed destination to reach, so it is its own finding.
// ---------------------------------------------------------------------------

// maxDestHostLen is the longest hostname that can exist: RFC 1035 §2.3.4 caps a
// wire-format domain name at 255 octets, which is 253 characters in
// presentation form (RFC 1123 §2.1). It is the DERIVATION constant for the
// authority bound below, and is pinned by test so the arithmetic stays
// checkable in code rather than only in this comment.
const maxDestHostLen = 253

// maxDestAuthorityLen is the bound actually enforced, on the RAW authority as
// the client sent it: the longest possible host, optional IPv6 brackets, and a
// port.
//
//	"[" + 253 + "]" + ":" + "65535"  =  1 + 253 + 1 + 1 + 5  =  261
//
// One length compare on the raw string is deliberately the whole gate. It is
// O(1), it runs before anything parses or copies the value, and because the
// host is a substring of the authority it bounds every downstream walk by
// construction — 261² is ~68k byte operations, i.e. nothing. Splitting the port
// off first to apply maxDestHostLen exactly would refuse a slightly larger set
// for no measurable gain and would cost a parse on every proxied request.
const maxDestAuthorityLen = 261

// proxyOversizeHostRejected counts requests refused for an over-long
// destination authority, on every protocol. Exported on /metrics as
// culvert_proxy_oversize_host_rejected_total.
//
// It is the operator's ONLY signal. The caller gets a 400 (or a SOCKS5 failure
// reply) and nothing else moves: the request never reaches the request log, the
// stats fan-out, the policy engine or any alert producer, precisely because
// reaching them is the defect. A climbing counter means a client is probing the
// proxy port with authorities no resolver could answer for.
var proxyOversizeHostRejected atomic.Int64

// The log line is rate-limited to one per window: a mitigation for a
// write-amplification defect must not be one itself (the CHAOS-63 rule). Onset
// is logged immediately, then at most one line per window, each naming the
// cumulative count so the magnitude is never lost.
var (
	oversizeHostLogMu   sync.Mutex
	oversizeHostLogLast time.Time
)

const oversizeHostLogWindow = time.Minute

// destAuthorityOversize reports whether an AUTHORITY — a host that may carry a
// port, and may be a bracketed IPv6 literal — exceeds the bound. This is the
// predicate for `r.Host` on the HTTP/CONNECT/WebSocket path and for the
// admin-supplied host on the diagnostic endpoints, where a pasted `host:port`
// must not be refused.
func destAuthorityOversize(authority string) bool {
	return len(authority) > maxDestAuthorityLen
}

// destHostOversize reports whether a BARE HOST — no port, no brackets —
// exceeds the bound. This is the predicate for the SOCKS5 destination, which
// RFC 1928 §4 carries as a DOMAINNAME with the port in its own two-byte field.
//
// **Applying destAuthorityOversize there instead would have been DEAD CODE, and
// that is the sharpest trap in this change.** RFC 1928 length-prefixes
// DOMAINNAME with ONE byte, so the protocol caps the destination at 255 — which
// is BELOW the 261-byte authority bound, so an authority-shaped check on that
// value can never fire, and a test asserting only "no oversize host reached the
// request log" passes vacuously because 255 is under the limit it asserts
// against. Caught in self-review; `TestChaos66_DefectSOCKS5RefusesOversizeDestination`
// now asserts the REFUSAL and the counter, so the gate cannot go dead again.
//
// Two predicates rather than one is a drift risk, which is why
// maxDestAuthorityLen is DERIVED from maxDestHostLen and the derivation is
// pinned by TestChaos66_ControlBoundIsInclusiveAndDerived. The alternative —
// one predicate applied to values of two different kinds — is how the SOCKS5
// gate became unreachable in the first place. Match the predicate to the KIND
// of the value, not to the call site's convenience.
func destHostOversize(host string) bool {
	return len(host) > maxDestHostLen
}

// noteOversizeHostLog reports whether this rejection may emit a log line,
// arming the window when it does.
func noteOversizeHostLog() bool {
	now := time.Now()
	oversizeHostLogMu.Lock()
	defer oversizeHostLogMu.Unlock()
	if !oversizeHostLogLast.IsZero() && now.Sub(oversizeHostLogLast) < oversizeHostLogWindow {
		return false
	}
	oversizeHostLogLast = now
	return true
}

// noteOversizeHostRejection charges the counter and emits the rate-limited log
// line. proto names the protocol for the operator ("HTTP", "SOCKS5",
// "api/url-lookup"); clientIP is a kernel-supplied peer address or a
// realClientIP product, never a client-chosen string.
//
// NOTHING here echoes the authority. Logging even a prefix of it would reopen
// the amplification on the rate-limited path, and a truncated copy is worth
// less to an operator than the LENGTH, which is the fact that decides whether
// this is a probe or a broken client. That is the one deliberate divergence
// from CHAOS-63's truncated audit actor: a username identifies an account an
// operator may recognise, whereas an authority past 253 bytes identifies
// nothing that can exist.
func noteOversizeHostRejection(proto, clientIP string, n int) {
	proxyOversizeHostRejected.Add(1)
	if noteOversizeHostLog() {
		logger.Printf("OVERSIZE_HOST %s %s {bytes=%d limit=%d total=%d action=block}",
			sanitizeLog(proto), sanitizeLog(clientIP), n, maxDestAuthorityLen,
			proxyOversizeHostRejected.Load())
	}
}

// rejectOversizeDestHost refuses an HTTP/CONNECT/WebSocket request whose
// destination authority exceeds the bound, reporting true when it has written
// the response.
//
// It runs as the FIRST thing in handleRequest that consults r.Host, and ahead
// of the connection limiter, the IP filter, the rate limiter, authentication
// and policy evaluation — so a rejected request creates NO state at all: no
// limiter entry, no request-log row, no top-hosts key, no alert, no label walk.
// Ordering is the whole contract, not an optimisation: `IP_BLOCKED` and
// `RATE_LIMITED` both write `r.Host` into the request log, so a gate placed at
// the host-canonicalization step (where RISK-013's IDNA gate sits) would sit
// BEHIND two sinks that had already retained the megabyte.
//
// 400 is the honest answer: an authority longer than any name that can be
// resolved is a malformed request, not a forbidden destination, and its LENGTH
// is not a secret. The response body names the limit and never echoes the value
// — §32's own gates had to suppress test output because the pre-fix handler
// reflected the oversize input back, which is the amplification arriving by a
// third road.
func rejectOversizeDestHost(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if !destAuthorityOversize(r.Host) {
		return false
	}
	// Counted as a block, matching what the INVALID_HOST branch further down
	// already does for the other malformed-destination refusal on this path
	// (and its SOCKS5 twin). An atomic counter is not a RETAINING sink, so this
	// does not weaken the "a rejected request creates no state" property — that
	// property is about the log rows, map keys and limiter entries an attacker
	// could grow, not about a single process-wide int. Leaving it out on this
	// path while the SOCKS5 gate counted it was an inconsistency in the first
	// version of this change, caught in self-review: two refusals of the same
	// class must not disagree about whether they happened.
	atomic.AddInt64(&statBlocked, 1)
	noteOversizeHostRejection("HTTP", clientIP, len(r.Host))
	http.Error(w, fmt.Sprintf("Bad Request: destination host must be at most %d bytes", maxDestAuthorityLen),
		http.StatusBadRequest)
	return true
}

// resetOversizeHostStateForTest clears the counter and the log gate. Process
// globals, so a test that asserts on either must isolate them.
func resetOversizeHostStateForTest() {
	proxyOversizeHostRejected.Store(0)
	oversizeHostLogMu.Lock()
	oversizeHostLogLast = time.Time{}
	oversizeHostLogMu.Unlock()
}
