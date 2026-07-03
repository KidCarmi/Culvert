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
// Returns the lowercased, IDNA-normalized host. If normalization fails
// (e.g., the host is an IP address or already ASCII), the input is returned
// lowercased — fail-open for usability since most hosts are pure ASCII.
func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return host
	}
	// Skip IDNA for IP addresses and already-pure-ASCII hostnames
	// (fast path — avoids allocation for the common case).
	if net.ParseIP(host) != nil {
		return host
	}
	ascii, err := idna.ToASCII(host)
	if err != nil {
		return host // fail-open: return lowercased original
	}
	return strings.ToLower(ascii)
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
