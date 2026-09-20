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

// maxDestHostLen is the longest hostname that can exist, in its CANONICAL
// A-label form: RFC 1035 §2.3.4 caps a wire-format domain name at 255 octets,
// which is 253 characters in presentation form (RFC 1123 §2.1).
//
// **This bound is applied to the NORMALIZED host, never to the raw bytes**, and
// the difference is the whole of the Codex P2 finding on PR #1446. An
// internationalized domain name arrives as UTF-8 and is converted to A-labels by
// `idna.ToASCII`, which SHRINKS it: measured against the real x/net/idna,
// `é`×40 in four labels is 323 raw bytes and 187 A-label bytes — a perfectly
// ordinary IDN that the first version of this bound refused with a 400. The
// worst legitimate case measured is **899 raw bytes → 255 A-label bytes**. A
// forward proxy that cannot reach international destinations is a customer
// outage, so a raw-byte bound at the DNS limit is not a conservative choice, it
// is a wrong one.
const maxDestHostLen = 253

// maxDestAuthorityLen bounds the CANONICAL authority: the longest possible
// A-label host, optional IPv6 brackets, and a port.
//
//	"[" + 253 + "]" + ":" + "65535"  =  1 + 253 + 1 + 1 + 5  =  261
const maxDestAuthorityLen = 261

// maxRawDestAuthorityBytes is the PRE-CAP on the raw authority as the client
// sent it, enforced at the entry point before anything parses, copies or walks
// the value. It exists because the canonical bound above cannot be evaluated
// until the host has been normalized, and normalizing is itself work done on
// attacker-chosen bytes.
//
// It is derived from the maximum expansion an IDN can undergo, so no legitimate
// destination can exceed it. An A-label is at most 63 bytes (RFC 1035 §2.3.1) =
// "xn--" plus at most 59 bytes of Punycode; Punycode emits at least one byte per
// encoded code point (RFC 3492 §3), so a label encodes at most 59 code points,
// each at most 4 UTF-8 bytes — at most 236 raw bytes per label. Packing a
// 253-byte A-label authority with maximal labels gives ~940 raw bytes, and the
// empirical maximum found by driving the real `idna.ToASCII` is **899**
// (pinned by TestChaos66_ControlRawCapExceedsMaximumIDNExpansion). 1024 clears
// both with margin.
//
// **The cost it buys, stated honestly.** Measured through the real
// handleRequest with one category-group rule and the Layer-2 feed present:
// 251 B → 111 µs, 511 B → 396 µs, 1023 B → 1.28 ms, 2047 B → 4.72 ms. So this
// cap alone bounds the worst case at ~1.3 ms, against 3.94 s at 64 KiB and ~16
// minutes at net/http's 1 MiB header default — but 1.3 ms is still ~12x an
// ordinary request, which is why it is NOT the only bound. The canonical bound
// refuses the shape an attacker actually wants (dot-dense ASCII does not shrink
// under IDNA, so a 1 000-byte ASCII authority normalizes to 1 000 bytes and is
// refused), leaving the realistic worst case at the 253-byte figure while the
// 899-byte IDN goes through. Two tiers, because one cannot do both jobs.
const maxRawDestAuthorityBytes = 1024

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

// rawAuthorityOversize reports whether the RAW authority — the bytes as the
// client sent them, before any normalization — exceeds the pre-cap. This is the
// predicate for the entry-point gate on every path.
func rawAuthorityOversize(authority string) bool {
	return len(authority) > maxRawDestAuthorityBytes
}

// canonicalHostOversize reports whether a NORMALIZED host — the A-label form
// hostutil.NormalizeHostStrict produced, with no port and no brackets — exceeds
// what DNS can carry.
//
// This is the bound that refuses the shape an attacker wants, and it must be
// given the CANONICAL form: dot-dense ASCII does not shrink under IDNA, so a
// 1 000-byte ASCII authority still measures 1 000 bytes here and is refused,
// while an 899-byte IDN measures 255 and goes through.
func canonicalHostOversize(normHost string) bool {
	return len(normHost) > maxDestHostLen
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
func noteOversizeHostRejection(proto, clientIP string, n int, tier string) {
	proxyOversizeHostRejected.Add(1)
	if noteOversizeHostLog() {
		limit := maxRawDestAuthorityBytes
		if tier == "canonical" {
			limit = maxDestHostLen
		}
		logger.Printf("OVERSIZE_HOST %s %s {tier=%s bytes=%d limit=%d total=%d action=block}",
			sanitizeLog(proto), sanitizeLog(clientIP), sanitizeLog(tier), n, limit,
			proxyOversizeHostRejected.Load())
	}
}

// rejectOversizeDestHost refuses an HTTP/CONNECT/WebSocket request whose RAW
// destination authority exceeds the pre-cap, reporting true when it has written
// the response.
//
// It runs as the FIRST thing in handleRequest that consults r.Host, and ahead of
// the connection limiter, the IP filter, the rate limiter, authentication and
// policy — so a rejected request creates NO state at all: no limiter entry, no
// request-log row, no top-hosts key, no alert, no label walk. Ordering is the
// whole contract, not an optimisation: `IP_BLOCKED` and `RATE_LIMITED` both write
// `r.Host` into the request log, so a gate placed at the host-canonicalization
// step (where RISK-013's IDNA gate sits) would sit BEHIND two sinks that had
// already retained the megabyte.
//
// This is the RAW tier. The canonical tier (rejectOversizeCanonicalHost) runs at
// the canonicalization gate, because it needs the normalized form — and it can
// safely sit there precisely because this cap has already bounded what those two
// sinks can retain to 1 KiB.
//
// 400 is the honest answer: an authority longer than any name that can be
// resolved is a malformed request, not a forbidden destination, and its LENGTH is
// not a secret. The response body names the limit and never echoes the value —
// §32's own gates had to suppress test output because the pre-fix handler
// reflected the oversize input back, and the pre-fix proxy does the same
// (measured: a 68 392-byte body for a 64 KiB authority).
func rejectOversizeDestHost(w http.ResponseWriter, r *http.Request, clientIP string) bool {
	if !rawAuthorityOversize(r.Host) {
		return false
	}
	// Counted as a block, matching what the INVALID_HOST branch further down
	// already does for the other malformed-destination refusal on this path (and
	// its SOCKS5 twin). An atomic counter is not a RETAINING sink, so this does
	// not weaken the "a rejected request creates no state" property — that
	// property is about the log rows, map keys and limiter entries an attacker
	// could grow, not about a single process-wide int.
	atomic.AddInt64(&statBlocked, 1)
	noteOversizeHostRejection("HTTP", clientIP, len(r.Host), "raw")
	http.Error(w, fmt.Sprintf("Bad Request: destination host must be at most %d bytes", maxRawDestAuthorityBytes),
		http.StatusBadRequest)
	return true
}

// rejectOversizeCanonicalHost refuses a request whose host, ONCE NORMALIZED to
// its A-label form, exceeds what DNS can carry. It reports true when it has
// written the response.
//
// It runs immediately after hostutil.NormalizeHostStrict succeeds, on both the
// HTTP and SOCKS5 paths, and is the tier that makes the bound tight: the raw
// pre-cap has to be generous enough for IDN expansion (1 KiB), which on its own
// still admits a 1 000-byte dot-dense ASCII authority costing ~1.3 ms. Measuring
// the canonical form instead refuses exactly that, because ASCII does not shrink
// under IDNA — while the 899-byte IDN it protects normalizes to 255 and passes.
func rejectOversizeCanonicalHost(w http.ResponseWriter, r *http.Request, clientIP, normHost string) bool {
	if !canonicalHostOversize(normHost) {
		return false
	}
	atomic.AddInt64(&statBlocked, 1)
	noteOversizeHostRejection("HTTP", clientIP, len(normHost), "canonical")
	http.Error(w, fmt.Sprintf("Bad Request: destination host must be at most %d bytes", maxDestHostLen),
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
