package main

import (
	"net"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// ── Inner-host pinning on a TLS-inspected tunnel ─────────────────────────────
//
// A CONNECT request is authorized ONCE, against the authority the client named
// in the CONNECT line. handleTunnelInspect derives hostOnly from that authority
// and everything downstream is decided against it: policyStore.Evaluate ran on
// it, the decryption profile resolved on it, the forged leaf is issued FOR it
// (internal/ca: DNSNames is exactly []string{host}), the upstream TLS
// ServerName is it, and every log row, scan verdict and CDR decision this
// tunnel produces is attributed to it (runInspectExchange threads ex.host, never
// ex.req.Host, into inspectFileBlocked and scanInspectBody).
//
// The decrypted stream, however, carries its OWN destination on every inner
// request: the HTTP/1.1 Host header, or the HTTP/2 :authority pseudo-header. The
// inspection pipeline forwarded that value upstream VERBATIM — rq.Write writes
// req.Host on the H1 leg, and upstreamCC.RoundTrip sends req.Host/req.URL.Host
// as :authority on the H2 leg — while still deciding and recording against the
// CONNECT host. Nothing compared the two.
//
// That is a policy-enforcement gap, not merely a logging one. The upstream
// connection is pinned to the CONNECT target's IP, so this is not SSRF; but a
// shared front end — a CDN, a cloud load balancer, any multi-tenant vhost —
// routes by Host/:authority, so the request that comes back is the one the
// CLIENT named, not the one policy allowed:
//
//	CONNECT allowed.example.com:443      → evaluated, allowed, MITM established
//	  GET / Host: blocked.example.com    → forwarded; the shared front end
//	                                       serves blocked.example.com
//
// Policy is consulted once, on a host the client then declines to use, and the
// request log records allowed.example.com for a retrieval of
// blocked.example.com — so the bypass is also invisible to the operator
// reviewing traffic afterwards. Scanning and CDR verdicts are mis-keyed the same
// way.
//
// ── Why refusing a mismatch is safe ──────────────────────────────────────────
//
// It cannot break a conforming client. HTTP/1.1 requires Host to name the
// request target's authority, which over this connection is the tunnel
// destination. HTTP/2 permits a client to reuse a connection for another origin
// (RFC 9113 §9.1.1 coalescing) ONLY when the server's certificate is
// authoritative for that origin — and the forged leaf carries a SINGLE SAN
// (internal/ca: DNSNames is exactly []string{host}, minted per client SNI via
// the GetCertificate hook), so no second origin is ever covered. A mismatched
// authority on an inspected tunnel is therefore a misconfigured client or
// deliberate evasion, never legitimate coalescing.
//
// ── Scope: a NAMED CONNECT target only ───────────────────────────────────────
//
// The pin compares the inner host against the CONNECT authority, because that is
// the value POLICY evaluated — not against the client's SNI. Pinning to the SNI
// would be weaker in exactly the case that matters: a client may present
// SNI = Host = blocked.example.com while CONNECTing to allowed.example.com, so
// SNI and Host agree with each other and still name a destination policy never
// saw. The authorizing value is the only safe anchor.
//
// When the CONNECT authority is an IP LITERAL the pin does not fire, and that is
// deliberate rather than an oversight. A client that resolved the name itself
// legitimately CONNECTs to an address and names the origin in SNI and Host
// (curl --resolve, a client with its own resolver, and the shape this
// repository's own inspect harness models by passing target and serverName
// separately — see connectAndTLS). The proxy holds no name for such a
// destination, so there is nothing to compare: refusing would break supported
// traffic, and comparing an address against a name would refuse every one of
// those requests.
//
// What that leaves open is stated plainly, because it is NOT closed by this
// gate: a deployment whose rules authorize a destination by IP or CIDR gets no
// name-level enforcement on the inner request, exactly as before. Closing it
// properly means EVALUATING POLICY on the inner host rather than comparing it —
// re-running the rulebase, the decryption profile and the attribution per inner
// request — which is a policy-engine change, not a gate, and is the documented
// follow-up. This gate closes the case that is both exploitable today and
// decidable here: a tunnel authorized for a NAME, reused for a different name.
//
// 421 Misdirected Request is the standards-correct answer and is what the H2
// path's own TODO anticipated ("strict :authority pinning / 421 handling"), but
// blockResponder is deliberately frozen to one pre-commit shape (see
// inspect_block.go), which emits 403 on both protocols. A 403 is the honest
// answer here too: the destination the client actually asked for was never
// authorized by policy. Refusing costs the client nothing it is entitled to — it
// may open a CONNECT tunnel for the host it really wants, which then receives
// its OWN policy decision, which is precisely the property being restored.
//
// Fail-closed, per the repository's posture: a host that cannot be canonicalized
// on either side is refused rather than compared loosely, and an exchange with
// no recorded tunnel destination is refused rather than forwarded on a
// client-chosen host.

// proxyInnerHostMismatchBlocked counts inner requests refused because their
// Host/:authority did not name the CONNECT target the tunnel was authorized for.
// Exported on /metrics as culvert_proxy_inner_host_mismatch_blocked_total.
//
// It is the operator's signal for this class: a climbing counter means a client
// is reusing an authorized tunnel to reach a destination policy never saw.
var proxyInnerHostMismatchBlocked atomic.Int64

// innerHostPinnedToTunnel reports whether an inner request's host names the same
// destination as the CONNECT target this tunnel was authorized for.
//
// Both sides are reduced the same way — port and IPv6 brackets stripped, then
// IDNA-canonicalized — so the comparison cannot be defeated by a spelling the
// matchers would have folded anyway (case, a trailing dot, a U-label against the
// A-label the CONNECT carried, "host:443" against "host"). The port is NOT part
// of the comparison: the TCP connection already fixes it, so a port claim in the
// header cannot redirect anything.
//
// An EMPTY inner host is REFUSED (Codex P1 on PR #1632, verified and correct).
// The first revision of this gate treated it as pinned, reasoning that it names
// no competing destination and that an origin requiring a Host would reject it
// on its own. Both halves of that were wrong, and the second half was the real
// error: it assumed the ORIGIN's behaviour instead of enforcing here, which is
// the same fail-open asymmetry this gate exists to remove.
//
// Measured against the tree, not argued: runH1InspectLoop reads inner requests
// with http.ReadRequest, NOT through an http.Server, so the server's "missing
// required Host header" 400 never runs — ReadRequest accepts
// "GET / HTTP/1.1\r\n\r\n" and yields req.Host == "" with req.URL.Host == "".
// Request.Write then serializes that as a literal "Host: " and returns no error,
// so the Host-less request reached the upstream. A shared front end with a
// default or fallback virtual host (an nginx "server_name _", a CDN catch-all)
// answers such a request from that vhost — a destination policy never evaluated,
// with the scan verdicts and the log row still attributed to the CONNECT host.
// That is the very bypass this gate closes, arriving through the one branch that
// waved it through.
//
// Refusing costs nothing a client is entitled to. It demonstrably knows the host
// — it named it in the CONNECT line and again in the TLS SNI — and no origin can
// route a Host-less HTTP/1.1 request to a specific vhost anyway. The refusal is
// taken BEFORE the IP-literal scope skip below, because the default-vhost
// concern does not depend on whether the CONNECT target was a name or an
// address.
//
// Substituting the authorized authority instead of refusing was considered and
// rejected: it would have the gateway synthesize a Host the client never sent,
// changing request semantics to make a malformed request succeed. Fail closed.
//
// An empty TUNNEL host is NOT pinned. It means this exchange has no recorded
// authorized destination, and forwarding a client-chosen host in that state is
// exactly what this gate exists to prevent. It is unreachable in production:
// handleTunnelInspect appends ":443" when the CONNECT authority carries no port,
// so SplitHostPort always succeeds and hostOnly is non-empty for any CONNECT
// that got far enough to dial an upstream.
//
// An IP-LITERAL tunnel host is pinned — see "Scope" above — but only once the
// empty-inner-host refusal above has run. The check is on the TUNNEL side only:
// an inner host that is an IP literal while the tunnel names a host is still a
// mismatch, because no conforming client sends an address in Host for a
// connection it opened to a name.
func innerHostPinnedToTunnel(innerHost, tunnelHost string) bool {
	if innerHost == "" {
		// No authority at all: Request.Write serializes a literal "Host: " and a
		// shared front end may answer it from its default vhost. See above.
		return false
	}
	if tunnelHost == "" {
		return false
	}
	tunnelBare := hostutil.StripHostPort(tunnelHost)
	if net.ParseIP(tunnelBare) != nil {
		// CONNECT by address: the proxy holds no name for this destination, so
		// there is nothing to pin the inner host against.
		return true
	}
	inner, innerOK := hostutil.NormalizeHostStrict(hostutil.StripHostPort(innerHost))
	if !innerOK || inner == "" {
		return false
	}
	tunnel, tunnelOK := hostutil.NormalizeHostStrict(tunnelBare)
	if !tunnelOK || tunnel == "" {
		return false
	}
	return inner == tunnel
}

// blockInnerHostMismatch charges the counters, logs the refusal and emits the
// block through the protocol-neutral responder — the same shape the sibling
// tunnel blocks use (dpiBlock, scanBlockConn, emitFileBlock), so an H2 stream
// block does not close the shared connection and the H1 loop still owns
// teardown.
//
// BOTH hosts are logged, because the pair is the finding: either one alone says
// nothing. Both are client-influenced, so both go through sanitizeLog and %q
// (CWE-117).
func blockInnerHostMismatch(br blockResponder, clientIP, tunnelHost, innerHost string) {
	proxyInnerHostMismatchBlocked.Add(1)
	atomic.AddInt64(&statBlocked, 1)
	logger.Printf("INNER_HOST_MISMATCH %s tunnel=%q inner=%q {action=block}",
		sanitizeLog(clientIP), sanitizeLog(tunnelHost), sanitizeLog(innerHost))
	const body = "Blocked: request host does not match the authorized tunnel destination\r\n"
	br.blockBeforeResponse("text/plain; charset=utf-8", body)
}

// resetInnerHostMismatchStateForTest clears the counter. A process global, so a
// test asserting on it must isolate it.
func resetInnerHostMismatchStateForTest() {
	proxyInnerHostMismatchBlocked.Store(0)
}
