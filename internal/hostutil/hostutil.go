// Package hostutil provides pure host-string normalization helpers shared
// across the proxy (policy matching, category lookups, scan/bypass keys). It is
// a self-contained seam (stdlib + golang.org/x/net/idna, no Culvert coupling)
// extracted from package main per ADR-0002 / ADR-0003 to unblock the catdb and
// scan clusters, which both depend on these helpers.
package hostutil

import (
	"net"
	"strings"

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
	// Skip IDNA for IP addresses (fast path — avoids allocation; IP literals
	// have no IDNA form).
	if net.ParseIP(host) != nil {
		return host, true
	}
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return "", false
	}
	return strings.ToLower(ascii), true
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
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}
