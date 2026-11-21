package hostpin

import (
	"net"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Pinned reports whether an inner request's host names the same
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
// Refusing costs nothing a client is entitled to. It named its destination in
// the CONNECT line, so it is not being asked for anything it has not already
// supplied, and no origin can route a Host-less HTTP/1.1 request to a specific
// vhost anyway. The refusal is taken BEFORE the IP-literal scope skip below,
// because the default-vhost concern does not depend on whether the CONNECT
// target was a name or an address.
//
// The entitlement rests on the CONNECT line ALONE, deliberately — not on "and
// again in the TLS SNI", which an earlier revision of this comment claimed
// (CodeRabbit on PR #1632, correct). Because the refusal above covers an
// IP-literal CONNECT target, and RFC 6066 §3 forbids a literal IPv4/IPv6
// address in the SNI HostName, there is no SNI name to appeal to in exactly the
// case this branch was extended to cover; SNI is optional besides. The CONNECT
// authority is the authorizing value and the only one always present, which is
// the same reason the pin anchors on it rather than on the SNI (see "Scope"
// in the package comment).
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
// An IP-LITERAL tunnel host is pinned — see "Scope" in the package comment —
// but only once the empty-inner-host refusal above has run. The check is on
// the TUNNEL side only:
// an inner host that is an IP literal while the tunnel names a host is still a
// mismatch, because no conforming client sends an address in Host for a
// connection it opened to a name.
func Pinned(innerHost, tunnelHost string) bool {
	if innerHost == "" {
		// No authority at all: Request.Write serializes a literal "Host: " and a
		// shared front end may answer it from its default vhost. See above.
		return false
	}
	if tunnelHost == "" {
		return false
	}
	if !bracketsValid(innerHost) {
		// Brackets that do not enclose an IP literal: a malformed authority the
		// comparison would repair but the wire would not. See the function.
		// Checked on the RAW value, before the canonicalization below, which
		// de-brackets and would hide it.
		return false
	}
	wireHost, wireOK := authorityAsSent(innerHost)
	if !wireOK {
		return false
	}
	// Compare the bytes the upstream will RECEIVE, not the bytes the client
	// sent. See authorityAsSent.
	innerHost = wireHost
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

// authorityAsSent reduces a client-supplied inner authority to the bytes
// the UPSTREAM will actually receive, or reports that the request will carry no
// usable authority at all (SEC-TUNHOST-2).
//
// It closes the generalization of the bracket defect above. That defect was
// "the pin compares a REPAIRED value while the origin receives an UNREPAIRED
// one"; the repair that mattered there was hostutil.StripHostPort's bracket
// trim, and two further repairs do the same thing:
//
//   - THE PORT IS NEVER VALIDATED. StripHostPort ends in net.SplitHostPort,
//     which splits on the last colon and accepts any byte after it. So
//     "allowed.example.com:0/x", "allowed.example.com:443?x" and
//     "allowed.example.com:@blocked.example.com" all reduce to the authorized
//     host and PINNED. The wire does not agree: Request.write runs
//     httpguts.ValidHostHeader on the raw value, finds the '/', '?' or '@',
//     and — because Request.Write passes usingProxy=false — ZEROES the host
//     and emits a literal "Host: " (net/http/request.go, go1.27; go.dev/issue
//     /61431 replaced the older truncate-at-'/' behaviour with this). That is
//     byte-for-byte the state the empty-inner-host branch above refuses, and
//     for the same reason: a shared front end answers an authority-less
//     HTTP/1.1 request from its default or fallback vhost, a destination
//     policy never evaluated, while the log row, scan verdicts and CDR
//     decisions still name the CONNECT host. The gate was reached THROUGH the
//     comparison instead of around it.
//
//   - IDNA CASE IS NOT PRESERVED THROUGH PUNYCODE. The comment below claimed a
//     U-label inner host is safe because "Request.Write converts it to the
//     A-label on the wire, so the forwarded bytes already match what the pin
//     authorized". That holds only for an already-lowercase U-label.
//     hostutil.NormalizeHostStrict lowercases BEFORE idna.ToASCII, while
//     httpguts.PunycodeHostPort does not, and Punycode encodes case in its
//     payload — so for tunnel "xn--bcher-kva.example.com", an inner
//     "BÜCHER.example.com" pinned while the wire carried
//     "xn--BCHER-2pa.example.com", and "Bücher.example.com" pinned while the
//     wire carried "xn--Bcher-kva.example.com". Different A-labels, i.e. names
//     policy never evaluated. (Measured, go1.27.3.)
//
// Both are fixed by one rule rather than by enumerating shapes: canonicalize
// through the SAME helpers net/http and the HTTP/2 header encoder use, and
// refuse anything they would not forward verbatim. The pin then cannot drift
// from the wire, because it is reading the wire's own definition — which is
// also why this does not hand-roll a port or character check. A shape neither
// stdlib path will send is a shape this gate must refuse, whatever it looks
// like.
//
// It deliberately does NOT widen the accepted set: every spelling the existing
// equivalence table pins (a trailing root dot, a lowercase U-label, "host:443"
// against "host", a bracketed IPv6 literal, an IP-literal tunnel) survives
// unchanged, because net/http sends all of them verbatim.
func authorityAsSent(authority string) (string, bool) {
	// PunycodeHostPort is what Request.write and the h2 encoder apply first; it
	// A-labels any U-label and leaves an ASCII authority (and an IPv6 literal's
	// brackets) alone.
	canon, err := httpguts.PunycodeHostPort(authority)
	if err != nil {
		return "", false
	}
	// ValidHostHeader is the same predicate whose failure makes Request.write
	// drop the authority entirely and makes the h2 encoder fail the request.
	// An empty result is refused by the caller's empty-inner-host branch, but
	// check it here too so this function's contract stands on its own.
	if canon == "" || !httpguts.ValidHostHeader(canon) {
		return "", false
	}
	return canon, true
}

// bracketsValid reports whether any square brackets in a
// client-supplied inner authority are the RFC 3986 IPv6-literal form. Brackets
// are legal ONLY around an IP literal.
//
// It exists because the pin compares a REPAIRED value while the origin receives
// an UNREPAIRED one, and that gap is exploitable (Codex P1 on PR #1632,
// verified). Measured against the stdlib: http.ReadRequest accepts
// "Host: [allowed.example.com]" and yields req.Host with the brackets intact,
// and Request.Write forwards those bytes verbatim. hostutil.StripHostPort,
// meanwhile, ends in strings.Trim(host, "[]") — correct for its own callers,
// which must accept the de-bracketed IPv6 shapes that reach scan/bypass
// lookups — so it silently turns "[allowed.example.com]" into
// "allowed.example.com". The pin would therefore see a match for the authorized
// host and forward a bracketed authority no vhost is configured for, letting a
// shared front end answer from its default vhost: the same unevaluated-
// destination bypass this gate exists to close, reached through the comparison
// rather than around it.
//
// The check belongs HERE and not in hostutil.StripHostPort. That helper is a
// shared seam the threat feed, the DPI scanner, the scan-exclusion matcher, the
// autoexclude cache and the traffic redactor all read through, and its
// bracket-trimming is deliberate for them; tightening it for this gate's needs
// would change behaviour for every one of those callers.
//
// Only the INNER side is checked. The tunnel side cannot carry brackets:
// handleTunnelInspect derives hostOnly through net.SplitHostPort, which removes
// them, so a bracketed CONNECT authority is already de-bracketed consistently
// for policy, the dial and the upstream ServerName before this gate runs.
//
// The sibling spellings the probe covered are deliberately NOT refused here,
// because they are not this defect:
//
//   - A LOWERCASE U-label inner host is safe: Request.Write converts it to the
//     A-label on the wire (measured — "bücher.example.com" is sent as
//     "xn--bcher-kva.example.com"), so the forwarded bytes already match what
//     the pin authorized. This bullet read "a U-label inner host" without the
//     qualifier and was WRONG for a mixed-case one, because punycode carries
//     case in its payload: "BÜCHER.example.com" is sent as
//     "xn--BCHER-2pa.example.com", a different label from the authorized
//     "xn--bcher-kva.example.com". authorityAsSent now refuses that, and
//     carries the measurement (SEC-TUNHOST-2).
//   - Case is safe for an ASCII authority: the Host field is case-insensitive,
//     so an origin cannot route on it differently. That is about ASCII case
//     only — it is not an argument about the U-label case above, which changes
//     the punycode payload rather than the case of a label.
//   - A trailing root dot is a VALID authority for the same DNS name and is
//     treated as equivalent by the origin stacks that matter, so refusing it
//     would reject conforming clients. It is the one accepted spelling whose
//     forwarded bytes still differ from the authorized form; see §6 of the
//     review document.
func bracketsValid(authority string) bool {
	if !strings.ContainsAny(authority, "[]") {
		return true
	}
	bare := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		// "[v6]:port" — SplitHostPort removes the brackets for this shape.
		bare = h
	} else if len(bare) >= 2 && bare[0] == '[' && bare[len(bare)-1] == ']' {
		bare = bare[1 : len(bare)-1]
	} else {
		return false // a bracket present without a matched surrounding pair
	}
	if strings.ContainsAny(bare, "[]") {
		return false // nested or stray brackets
	}
	return net.ParseIP(bare) != nil
}
