package main

import (
	"fmt"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// CHAOS-92 — the client-supplied request PATH, where it is retained
//
// Register row PX-22, instantiated as X-1 by the 2026-10-13 round, is the last
// unbounded client-chosen string on the data path. Its two siblings are closed:
// SEC-REQID-1 (request_tracing_bounds.go) bounds the tracing headers and
// CHAOS-69 (proxy_host_bounds.go) bounds the destination authority. Neither
// reaches the path, and CHAOS-69's own note says so in as many words — "No
// bound on the inner request path or URI … (register row PX-22) … so it is its
// own finding."
//
// WHAT THE PATH REACHES. `r.URL.Path` is copied, unbounded, into:
//
//  1. the process log, at five sites — `FILE_BLOCKED` and `FILE_BLOCKED (policy
//     profile)` in proxy.go, `FILE_BLOCKED (%s)` in proxy_http.go, and the two
//     `SSL_INNER` lines in proxy_tunnel.go / proxy_tunnel_h2.go;
//  2. a BUFFERED HTML RESPONSE BODY, at five sites, all through
//     `serveBlockPage(w, r.Host+r.URL.Path, …)`, which renders the value into
//     `internal/blockpage`'s template — `bytes.Buffer` first, then one `Write`;
//  3. the request-log entry's `URI` field (logstore.Entry.URI → the in-memory
//     ring, the persisted JSONL, syslog/SIEM and the redaction pipeline), at
//     four sites, all through `policyLogURI`.
//
// MEASURED, through the real `handleRequest`, with the SHIPPED default
// extension list (`fileblock.DefaultBlockedExts`, loaded at startup when no
// config override is provided, so this is a stock install):
//
//	path bytes   fill   process log      response body
//	     1 029    'A'         1 084              3 875
//	    65 541    'A'        65 596             68 387
//	 1 048 581    'A'     1 048 636          1 051 427
//	 1 048 581   '\''     1 048 636          5 245 731
//	 1 048 581    '<'     1 048 636          4 197 155
//
// So one request buys ~1 MiB of process log AND a ~5 MiB HTML page held in
// memory and written back — a 5x amplifier, because `html/template` escapes
// `'` to `&#39;` and `<` to `&lt;`. The multiplier is the attacker's to choose.
//
// THE PATH IS DELIVERABLE AT THAT LENGTH, OVER A REAL SOCKET, which is the
// check SEC-REQID-2 exists to insist on: driven through a real net/http server,
// a 1 048 581-byte request target of raw `'` arrives as `r.URL.Path` BYTE FOR
// BYTE (200), and 2 MiB draws a 431 before the handler runs. net/http's
// `initialReadLimitSize` is `MaxHeaderBytes + 4096`, and the proxy listener
// sets no `MaxHeaderBytes`, so the 1 MiB default governs the request line too.
// `'` needs no percent-encoding (RFC 3986 sub-delim), so the worst case costs
// an attacker exactly one wire byte per retained byte.
//
// IT IS REACHED BEFORE AUTHENTICATION AND WITH NO OPT-IN. The `FILE_BLOCKED`
// branch needs only a blocked extension, and `.exe` is in the shipped default
// list; the three front-door limiters all ship disabled (§25/CHAOS-57). The
// process log is a `fileutil.RotatingFile` capped at 50 MB keeping ONE archive,
// so ~100 MB of retained evidence rotates away in seconds while every write
// SUCCEEDS — the logsink backpressure counter and every storage-health surface
// stay green while the record is destroyed (CWE-778, OWASP A09:2021). That is
// the CHAOS-63 defect, on a port every client on the network can reach.
//
// WHY THIS BOUND TRUNCATES WHERE ITS TWO SIBLINGS REFUSE. The shape of the fix
// is forced by what the value is, and the two precedents point opposite ways:
//
//   - CHAOS-69 refuses the request, because a 1 MiB authority cannot name a
//     destination any resolver would answer for (RFC 1035 §2.3.4 caps a name at
//     255 octets), so the refused set contains nothing legitimate.
//   - SEC-REQID-1 refuses the VALUE and mints its own, because truncating a
//     correlation id silently corrupts trace correlation — a truncated id is
//     not a usable id.
//
// A request path has NEITHER property. No RFC caps it, long signed and
// capability-bearing URLs are ordinary, and a forward proxy that answers 414 to
// a path a customer's application uses is an egress outage — the trade this
// repository refuses everywhere else. But a truncated path IS a usable log
// value, which is precisely the "structural half available in the leaf" that
// §32/CHAOS-63 had and CHAOS-69 did not: an operator reading `host/a/b/c…` plus
// an explicit byte count learns the destination, the beginning of the resource
// and that there was more. So the bound goes on RETENTION, not on admission.
//
// ENFORCEMENT KEEPS THE WHOLE VALUE, AND THAT SEPARATION IS THE POINT.
// `fileBlocker.CheckPath`, `globalSecScanner.CheckRequestURL` and every policy
// matcher still see `r.URL.Path` intact. Clamping the value they decide on
// would be fail-OPEN — truncating the end removes the extension a file-block
// rule matches on, so a 2 KiB `…/payload.exe` would stop being blocked. The
// clamp is applied only where a copy is KEPT or REFLECTED, never where a
// verdict is formed.
//
// Deliberately NOT done here:
//
//   - **No refusal tier, and no MaxHeaderBytes change on the proxy listener.**
//     Apache's `LimitRequestLine` (8190) and nginx's
//     `large_client_header_buffers` (8k) mean no mainstream origin accepts a
//     longer URI than ~8 KiB, so refusing a path above that would forward
//     nothing an origin would have answered — but WHICH requests a forward
//     proxy admits is a product decision, the same one CHAOS-69 and
//     SEC-REQID-1 each declined to make unilaterally. Recorded in §53 as an
//     owner decision, with the measurement, rather than taken here. The clamp
//     below does not need it: it removes the amplification outright, leaving
//     one net/http-bounded copy of the path in the request object, which is the
//     cost of any header.
//   - **No clamp on the CDR sidecar's `Filename`.** `cdrFilenameFromURL` is
//     `path.Base`, so a 1 MiB path with no `/` is forwarded whole to the
//     sidecar as a filename. It is a real third sink, but the sidecar matches a
//     CDR profile BY EXTENSION, so truncating the end there would be
//     fail-open — the same hazard as clamping the matcher input. It needs a
//     keep-the-extension bound and a CDR-domain decision, so it is recorded as
//     its own row rather than fixed with this helper.
//   - **No `sanitizeLog` removal.** The clamp runs INSIDE the argument, before
//     `sanitizeLog`, so the scan and its possible 1 MiB copy are bounded too.
//     The CWE-117 barrier is unchanged.
// ---------------------------------------------------------------------------

// maxRetainedRequestPath bounds a client-supplied request path at the point a
// copy is retained or reflected.
//
// 2048 is the de-facto URL ceiling the whole ecosystem already assumes: it is
// above the historical 2083-byte Internet Explorer limit that web applications
// were built against for two decades, and well above the longest path in
// ordinary use — the long part of a long URL is almost always the QUERY, which
// `r.URL.Path` excludes by construction (and `policyLogURI` re-checks). It is
// deliberately generous rather than exact, for the same reason
// maxClientTraceparentLen is: this is an input-bounds hole being closed, not a
// decision about what a URL may be.
//
// The figure is also what makes truncation honest. 2 KiB keeps the host, the
// directory structure and the resource name of every realistic URL, so the
// retained value is still the forensic artifact an operator needs; a bound
// tight enough to cut ordinary paths would trade one silent evidence loss for
// another.
const maxRetainedRequestPath = 2048

// maxRetainedBlockPageURL bounds the already-composed `host + path` string the
// block page renders. The authority half is bounded at maxDestAuthorityLen by
// CHAOS-69, so the sum is the real ceiling — carried as its own constant
// because serveBlockPage is a CHOKEPOINT and must bound whatever a caller
// passes, including a caller that composed the string some other way.
const maxRetainedBlockPageURL = maxDestAuthorityLen + maxRetainedRequestPath

// retainedPathTruncationMarker is appended to a clamped value. It carries the
// ORIGINAL length, which is the number an operator actually needs: it says both
// that bytes were dropped and how many, so a truncated line can never be
// mistaken for a complete one.
//
// It is plain visible ASCII, for the acceptableTracingHeaderValue reason — a
// marker that a log viewer renders as a control sequence or that a JSON encoder
// has to escape would be a new problem in the mitigation.
//
// A client CAN end a short path with this literal and forge the appearance of a
// truncation; nothing is retained that would not have been retained anyway, and
// the value is `%q`-quoted at every log site, so the forgery costs an attacker
// a visibly-quoted suffix and buys no additional bytes. Stated rather than
// defended against: the alternative is an unforgeable out-of-band marker on
// every sink, which is a schema change to the request-log wire contract.
const retainedPathTruncationMarker = "...[truncated; %d bytes total]"

// retainedPathTruncated counts clamped values. It is a single series with no
// caller-derived label — an unbounded label set keyed on an attacker-chosen
// value is the WK-12/RS-5 defect this file exists next to.
//
// There is deliberately NO log line on truncation. The marker is already
// inline in the record being written, so an operator sees the event at the
// place it happened; emitting a second line per truncation would make the
// mitigation for a write-amplification defect into one, which is the rule
// request_tracing_bounds.go states and then has to apply to itself.
var retainedPathTruncated atomic.Int64

// clampRetained is the shared body of the two entry points below: the cut, the
// UTF-8 back-off, the marker and the counter in one place, so the two bounds
// cannot drift apart in behavior while differing only in their limit.
//
// The cut BACKS OFF TO A UTF-8 BOUNDARY. A path arrives percent-decoded from
// net/url, so it can carry arbitrary bytes, and a cut through a multi-byte rune
// would put invalid UTF-8 into a record that is JSON-encoded downstream
// (logstore.Entry.URI → the persisted JSONL and the SIEM feed), where
// `encoding/json` would substitute U+FFFD and change the bytes an investigator
// reads. Backing off drops at most three bytes and adds no allocation the
// concatenation did not already need. An invalid sequence that was ALREADY in
// the value is left alone — this is a cut-site correction, not a sanitizer;
// sanitizeLog and the JSON encoder own what the bytes may be.
func clampRetained(v string, limit int) string {
	if len(v) <= limit {
		return v
	}
	cut := limit
	// 0b10xxxxxx is a UTF-8 continuation byte: step back off one. A rune is at
	// most 4 bytes, so at most 3 steps, and the loop cannot run off the front
	// because both limits are far larger than 3.
	for cut > 0 && v[cut]&0xC0 == 0x80 {
		cut--
	}
	retainedPathTruncated.Add(1)
	return v[:cut] + fmt.Sprintf(retainedPathTruncationMarker, len(v))
}

// boundRetainedPath bounds a client-supplied request PATH. Use it at any sink
// that keeps or reflects a copy — never on the value a matcher decides on, for
// the fail-open reason in this file's header.
func boundRetainedPath(p string) string { return clampRetained(p, maxRetainedRequestPath) }

// boundRetainedBlockPageURL bounds the composed `host + path` string a block
// page renders. It is a separate entry point rather than a second call to
// boundRetainedPath because the value and the limit are both different: this
// one is already composed, and it is the sink carrying the 5x escaping
// multiplier.
func boundRetainedBlockPageURL(u string) string { return clampRetained(u, maxRetainedBlockPageURL) }

// resetRetainedPathStateForTest clears the process-global counter so tests do
// not inherit each other's state. Production never calls it.
func resetRetainedPathStateForTest() { retainedPathTruncated.Store(0) }
