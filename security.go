package main

import (
	"context"
	"net"
	"time"

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

// isPrivateHostContext is isPrivateHost with the DNS lookup bounded by ctx.
//
// CHAOS-87: isPrivateHost resolves under context.Background(), so a wedged
// resolver blocks for the OS budget. On a path that already owns a deadline —
// an IdP metadata fetch during boot or a config sync — a pre-flight guard that
// outlives that deadline is the unbounded-resolver-call shape CHAOS-60/64
// closed, reintroduced by the guard rather than by the request. Use this form
// wherever the caller has a deadline; the guard must never be the unbounded
// step in a bounded operation.
func isPrivateHostContext(ctx context.Context, hostport string) error {
	return ssrf.PrivateHostContext(ctx, hostport)
}

// tunnelGuardBudget caps the pre-flight guard's DNS lookup on the data-plane
// tunnel paths (CONNECT bypass/inspect, WebSocket, SOCKS5). It equals the 10 s
// those paths already allow their upstream dial — which re-resolves the same
// name — so no destination that could have been dialled is newly refused. A
// var (not const) so tests can shrink it; production never reassigns it.
var tunnelGuardBudget = 10 * time.Second

// isPrivateHostBounded is isPrivateHostContext with the miss-path lookup also
// capped at tunnelGuardBudget. The tunnel paths previously called
// isPrivateHost, whose lookup runs under context.Background(): a resolver that
// stopped answering held each request goroutine (plus its client connection
// and connection-limiter slot) for the OS resolver budget, past the 10 s dial
// bound behind it and past the client hanging up. Same verdicts, same cache,
// same fail-closed result; see ssrf.PrivateHostBudget.
func isPrivateHostBounded(ctx context.Context, hostport string) error {
	return ssrf.PrivateHostBudget(ctx, hostport, tunnelGuardBudget)
}

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
