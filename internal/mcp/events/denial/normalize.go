// Package denial implements the attacker-mintable denial lane (MCP-EVENT-007):
// pre-queue admission control and attacker-rate-independent coalescing for
// authentication-failure and authorization-denial events, so N equivalent denials
// in one bucket/window cost O(1) durable records. The aggregator holds bounded
// in-memory aggregates keyed by capability/listener × normalized source bucket ×
// denial reason × bounded time window (plus verified tenant/principal only where
// identity exists — never invented before identity). It NEVER commits to disk
// itself and NEVER consumes the P-CRIT reserve; the manager commits the flushed
// aggregates into P-DEN and, on failure, records the DISTINCT denial-loss counter
// and enters denial-lane-degraded. A denial-lane failure never blocks
// authenticated work and never enters critical-durability-degraded.
package denial

import (
	"net/netip"
	"strings"
)

// maxSourceBytes bounds a normalized source token so an attacker cannot drive
// unbounded key sizes with a huge source string.
const maxSourceBytes = 128

// NormalizeSource collapses a raw source address into a stable, bounded bucket
// token, following the repository precedent for client-evidence tokens: an IPv6
// address is collapsed to its /64 prefix (so per-host churn within a /64 folds
// into one bucket), an IPv4 address is kept raw (a /24 would over-collapse a NAT
// fleet), and a non-IP source is sanitized and bounded. The result is a bucket
// key, never a raw unbounded source text.
func NormalizeSource(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "src:unknown"
	}
	// Strip a :port if present and the remainder parses as host:port.
	host := raw
	if h, _, ok := splitHostPort(raw); ok {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() || addr.Is4In6() {
			return "ip4:" + addr.Unmap().String()
		}
		// IPv6 → /64.
		p, perr := addr.Prefix(64)
		if perr == nil {
			return "ip6:" + p.String()
		}
		return "ip6:" + addr.String()
	}
	// Non-IP source: sanitize to a bounded printable token.
	return "src:" + sanitizeToken(host)
}

// splitHostPort splits a trailing :port when the host is unambiguous. It handles
// bracketed IPv6 ([::1]:443) and host:port, and reports ok=false when there is no
// clear port to strip (bare IPv6 with colons).
func splitHostPort(s string) (host, port string, ok bool) {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			host = s[1:i]
			rest := s[i+1:]
			if strings.HasPrefix(rest, ":") {
				return host, rest[1:], true
			}
			return host, "", true
		}
		return "", "", false
	}
	if strings.Count(s, ":") == 1 {
		i := strings.LastIndex(s, ":")
		return s[:i], s[i+1:], true
	}
	return "", "", false
}

// sanitizeToken renders an untrusted source token safe and bounded: printable
// ASCII only, control/space bytes replaced, length-capped with a marker.
func sanitizeToken(s string) string {
	if len(s) > maxSourceBytes {
		s = s[:maxSourceBytes]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			b.WriteByte('_')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
