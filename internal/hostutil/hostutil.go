// Package hostutil provides pure host-string normalization helpers shared
// across the proxy (policy matching, category lookups, scan/bypass keys). It is
// a self-contained seam (stdlib + golang.org/x/net/idna, no Culvert coupling)
// extracted from package main per ADR-0002 / ADR-0003 to unblock the catdb and
// scan clusters, which both depend on these helpers.
package hostutil

import (
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// NormalizeHost applies IDNA2008 normalization (RFC 5890) to a hostname,
// converting Unicode/Punycode domains to their canonical ASCII form. This
// prevents IDN homograph attacks where visually similar Unicode characters
// (e.g., Cyrillic 'а' vs Latin 'a') bypass blocklists and policy rules.
//
// Returns the lowercased, IDNA-normalized host. If normalization fails the
// input is returned lowercased — fail-open, which is acceptable ONLY for
// canonicalizing admin-entered patterns and store keys (a pattern that fails
// IDNA simply matches literally, so nothing is admitted that a valid pattern
// would have blocked). Request-path host validation must use
// NormalizeHostStrict so a malformed host is REJECTED, not passed through
// (RISK-013).
func NormalizeHost(host string) string {
	norm, ok := NormalizeHostStrict(host)
	if !ok {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return norm
}

// NormalizeHostStrict is NormalizeHost's fail-closed core: it reports
// ok=false when IDNA conversion fails instead of falling back to the raw
// input. Security gates on the request path (proxy dispatch, SOCKS5) use it
// to reject hosts that cannot be canonicalized — a host the normalizer
// cannot map to canonical ASCII would otherwise flow into FQDN/blocklist/
// category matching un-normalized, and a fail-open in the canonicalization
// step is exactly the asymmetry evasion techniques target (RISK-013).
// Empty input returns ok=true: emptiness is a separate upstream validity
// concern, and rejecting it here would change unrelated dispatch behavior.
func NormalizeHostStrict(host string) (norm string, ok bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return host, true
	}
	// ── Already-canonical fast path ───────────────────────────────────────────
	// idna.ToASCII is provably the IDENTITY function on a host that is pure ASCII
	// and carries no ACE ("xn--") label, so for such a host neither it nor the
	// IP-literal probe below can change the result — both would return `host`
	// verbatim. Taking the decision here instead costs one byte scan and NOTHING
	// else: no allocation, no tables, no error construction.
	//
	// The cost avoided is larger than idna alone. net.ParseIP allocates on its
	// FAILURE path (it builds a netip parse error for every non-IP string) and is
	// called twice, so the pre-fix body spent ~333ns and 2 allocations on every
	// ordinary hostname. That is paid ~10x per proxied request, because the same
	// destination is independently normalized by the strict dispatch gate, the
	// blocklist, the threat feed, policy FQDN matching, category lookup, the
	// SSL-bypass matcher, autoexclude, and auth policy — each correctly
	// normalizing its own input. Measured: 333ns/2 allocs → 24ns/0 allocs
	// (hostutil_bench_test.go).
	//
	// The equivalence is exact, not approximate: ToASCII uses the zero-option
	// Punycode profile, under which validateLabel returns nil immediately, the
	// bidi and DNS-length checks are disabled, and the only branches that
	// transform the input or raise an error are the ACE-decode branch (gated on
	// the "xn--" prefix) and the punycode-encode branch (gated on a non-ASCII
	// label). Excluding both leaves the input returned verbatim with a nil error.
	// TestNormalizeHostStrict_FastPathMatchesToASCII, the pre-fast-path
	// differential test, and FuzzNormalizeHostStrict pin that equivalence against
	// the real idna.ToASCII, so an upstream x/net behaviour change fails CI
	// rather than silently diverging.
	if isCanonicalASCIIHost(host) {
		return host, true
	}
	// IP literals have no IDNA form — accept them explicitly. This covers both
	// the bare form ("2001:db8::1") and the BRACKETED IPv6 form
	// ("[2001:db8::1]"), which reaches here on the default-port HTTP path
	// (r.Host carries brackets when no port is present) and from the SOCKS5
	// IPv6 ATYP. We do NOT rely on idna.ToASCII leniently passing a bracketed
	// string (it happens to today, but that is accidental and could tighten in
	// a future x/net) — the strict gate must accept valid IPv6 literals by
	// construction. Return the ORIGINAL host so downstream matchers see the
	// shape they already expect.
	//
	// Every IP literal is pure ASCII and ACE-free, so today the fast path above
	// already returns it (identically — `host` verbatim, ok=true) and this branch
	// is a redundant guard rather than the live route. It is KEPT deliberately, as
	// defense in depth: it is the only place the "valid IPv6 literals are accepted
	// by construction" guarantee is stated in code, and it must survive any future
	// NARROWING of isCanonicalASCIIHost (e.g. adding an STD3 character check, which
	// would reject ':' and '[' and silently push IPv6 literals into idna).
	// TestNormalizeHostStrict_IPLiteralsAcceptedByConstruction pins the guarantee
	// independently of which branch delivers it.
	if net.ParseIP(host) != nil || net.ParseIP(stripIPv6Brackets(host)) != nil {
		return host, true
	}
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return "", false
	}
	return strings.ToLower(ascii), true
}

// isCanonicalASCIIHost reports whether host is pure ASCII and contains no label
// beginning with the ACE prefix "xn--" — the condition under which idna.ToASCII
// is the identity function (see NormalizeHostStrict). host is assumed already
// lowercased, so the prefix test is case-sensitive by construction.
//
// Both properties are decided in a single pass: a label starts at index 0 and
// after every '.', so the ACE test only runs at those positions.
func isCanonicalASCIIHost(host string) bool {
	labelStart := true
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= utf8.RuneSelf {
			return false // non-ASCII: ToASCII must punycode-encode this label
		}
		if labelStart && c == 'x' && len(host)-i >= len(acePrefix) &&
			host[i+1] == 'n' && host[i+2] == '-' && host[i+3] == '-' {
			return false // ACE label: ToASCII must decode and validate it
		}
		labelStart = c == '.'
	}
	return true
}

// acePrefix is the IDNA ASCII Compatible Encoding prefix (RFC 5890 §2.3.2.5),
// mirroring the unexported constant of the same name in x/net/idna.
const acePrefix = "xn--"

// stripIPv6Brackets removes a single matched surrounding [ ] pair (the
// bracketed-IPv6-literal shape), leaving any other input untouched.
func stripIPv6Brackets(h string) string {
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}

// MatchFQDN reports whether host matches pattern under the proxy's canonical
// FQDN-glob semantics, normalizing both inputs first. Moved from package
// main's policy engine (ADR-0002, policy.go decomposition Phase B) — shared
// by policy rule matching and the SSL-bypass matcher, whose agreement is
// pinned by main's policy_bypass_security_test.go.
func MatchFQDN(pattern, host string) bool {
	return MatchFQDNNorm(NormalizeHost(pattern), NormalizeHost(host))
}

// MatchFQDNNorm is MatchFQDN's core, operating on inputs that are ALREADY
// IDNA-normalized. The policy hot path passes a once-normalized host and a
// rule's precomputed normalized pattern, avoiding the two per-rule
// NormalizeHost allocations.
func MatchFQDNNorm(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(host, suffix) || host == pattern[2:]
	}
	// Palo Alto-style: a bare domain implicitly includes all its subdomains.
	// "example.com" matches "example.com" AND "www.example.com".
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

// StripHostPort removes a trailing :port and IPv6 brackets from a host value,
// accepting all shapes that reach scan/bypass lookups: "host:port",
// "[v6]:port", "[v6]", bare "v6", and bare "host". A naive
// LastIndex(host, ":") cut corrupts bare IPv6 literals (already de-bracketed
// by net.SplitHostPort upstream) — "2001:db8::1" would become "2001:db8:".
func StripHostPort(host string) string {
	// ── Already-portless fast path ────────────────────────────────────────────
	// A host carrying neither ':' nor a bracket is returned VERBATIM by the body
	// below — and the body pays an allocation to discover that. net.SplitHostPort
	// builds a *net.AddrError ("missing port in address") for every portless
	// host, and that error is discarded on the very next line. So the COMMON
	// shape was the expensive one, exactly inverted:
	//
	//	StripHostPort("www.example.com")      41.3 ns/op   32 B/op   1 allocs/op
	//	StripHostPort("www.example.com:443")  19.6 ns/op    0 B/op   0 allocs/op
	//
	// After: 9.3 ns/op and 0 allocs for the portless shape. Full before/after
	// table, including the shapes that got marginally slower, in
	// hostutil_striphostport_test.go.
	//
	// That is the shape this function actually sees on the request path: the
	// dispatch gate splits the port off r.Host before any engine looks at the
	// destination, so the threat feed, DPI scanner, scan-exclusion matcher,
	// autoexclude cache and traffic redactor each re-strip a port that is
	// already gone — several discarded errors per proxied request, on every
	// protocol.
	//
	// The equivalence is exact, not approximate. Without a ':' SplitHostPort
	// cannot succeed, so `host` is never reassigned; without a '[' or ']'
	// strings.Trim(host, "[]") is the identity. Both statements therefore leave
	// the input unchanged, which is what this returns. Pinned by
	// FuzzStripHostPort against the pre-fast-path body.
	if !hasHostPortSyntax(host) {
		return host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// hasHostPortSyntax reports whether StripHostPort's body can transform host.
// It is the exact negation of "both statements below are no-ops":
//
//   - net.SplitHostPort can only SUCCEED on a value containing ':' — it locates
//     the port by the last colon and otherwise reports "missing port in
//     address". So without a colon, `host` is never reassigned.
//   - strings.Trim(host, "[]") cuts only from the ENDS, so it is the identity
//     unless the first or last byte is a bracket.
//
// Scanning for the colon from the RIGHT is deliberate: in every shape that has
// one it sits near the end ("host:443", "[v6]:443"), so the port-carrying
// shapes — which still take the full body — pay only a few bytes of scan rather
// than a walk of the whole hostname. net.SplitHostPort locates it the same way,
// so this costs one already-warm pass. No allocation, no tables.
func hasHostPortSyntax(host string) bool {
	if host == "" {
		return false
	}
	return strings.LastIndexByte(host, ':') >= 0 ||
		isBracket(host[0]) || isBracket(host[len(host)-1])
}

func isBracket(c byte) bool { return c == '[' || c == ']' }
