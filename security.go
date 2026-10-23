package main

import (
	"net"

	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// normalizeHost and stripHostPort moved to internal/hostutil (ADR-0002/0003).
// These thin wrappers keep the unqualified package-main call sites (policy,
// store, catdb, scanner, security_scan) and the existing tests unchanged.
func normalizeHost(host string) string { return hostutil.NormalizeHost(host) }
func stripHostPort(host string) string { return hostutil.StripHostPort(host) }

// normalizeHostStrict is the fail-closed variant used by the request-path
// dispatch gates (handleRequest, SOCKS5): ok=false means the host cannot be
// IDNA-canonicalized and the request must be REJECTED rather than evaluated
// against policy/blocklist with an un-normalized host (RISK-013).
func normalizeHostStrict(host string) (string, bool) { return hostutil.NormalizeHostStrict(host) }

// ─── SSRF guard (moved to internal/ssrf, ADR-0002) ──────────────────────────
// The CIDR table, DNS-cached host check, and connect-time dialer control live
// in internal/ssrf. These thin wrappers keep every unqualified call site (and
// the CodeQL inline-guard convention at those sites) unchanged.

// isPrivateIP reports whether ip falls within any private/internal range.
func isPrivateIP(ip net.IP) bool { return ssrf.PrivateIP(ip) }

// isPrivateHost resolves host (host or host:port) and returns an error if any
// resolved IP falls within a private/internal range (30s-TTL DNS cache;
// fail-closed on resolution errors).
func isPrivateHost(hostport string) error { return ssrf.PrivateHost(hostport) }

// ssrfControl is the connect-time guard (net.Dialer.Control) — rejects dials
// whose resolved address is private/internal. Re-exposed for the CONNECT and
// SOCKS5 paths, which build their own dialers.
var ssrfControl = ssrf.Control

// errSSRFBlocked is the sentinel a connect-time ssrfControl rejection wraps, so
// a dial-error site can errors.Is() a DNS-rebinding/private-IP security block
// apart from a genuine unreachable-origin dial error.
var errSSRFBlocked = ssrf.ErrBlocked

// ssrfSafeDialContext is a net.Dialer.DialContext replacement that rejects
// connections to private/internal IPs at connect time (DNS-rebinding safe).
//
// Declared as a variable so that tests can temporarily replace it with a
// plain dialer that permits localhost webhook targets.
var ssrfSafeDialContext = ssrf.SafeDialContext
