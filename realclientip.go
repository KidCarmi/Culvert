package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
)

// realclientip.go — trusted-proxy-aware client-IP resolution (RISK-019).
//
// Every admin-UI per-IP decision (login lockout, admin-API rate limit, UI IP
// allowlist, audit attribution) historically keyed on the DIRECT peer IP
// (net.SplitHostPort(r.RemoteAddr)). Behind an L7 reverse proxy that
// terminates TCP, every request presents the proxy's IP, so those per-IP
// mechanisms all collapse onto one shared key: an attacker's 5 failures lock
// out the real admin, one IP exhausts the rate limit for everyone, and every
// audit line names the proxy.
//
// realClientIP resolves the true client ONLY when the direct peer is itself a
// configured trusted proxy (trustedProxyNets). It reads X-Forwarded-For and
// returns the rightmost hop that is NOT a trusted proxy — the client that
// handed the request to the innermost trusted proxy. When no trusted proxies
// are configured, or the peer is not one of them, X-Forwarded-For is IGNORED
// and the direct peer is returned. That gate is the whole security argument:
// a direct attacker cannot spoof X-Forwarded-For to forge a victim's IP,
// because their own peer address is not in the trusted set.
var (
	trustedProxyNetsMu sync.RWMutex
	trustedProxyNets   []*net.IPNet
)

// parseIPOrCIDR accepts a CIDR ("10.0.0.0/8") or a bare IP ("10.0.0.1",
// treated as a /32 or /128) and returns the network.
func parseIPOrCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP/CIDR: %s", s)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

// SetTrustedProxyCIDRs replaces the trusted-proxy set. An empty/blank list
// clears it (the safe default: no X-Forwarded-For is ever trusted). Returns an
// error WITHOUT mutating state if any entry is invalid.
func SetTrustedProxyCIDRs(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if strings.TrimSpace(c) == "" {
			continue
		}
		n, err := parseIPOrCIDR(c)
		if err != nil {
			return err
		}
		nets = append(nets, n)
	}
	trustedProxyNetsMu.Lock()
	trustedProxyNets = nets
	trustedProxyNetsMu.Unlock()
	return nil
}

// ListTrustedProxyCIDRs returns the current trusted-proxy set as strings.
func ListTrustedProxyCIDRs() []string {
	trustedProxyNetsMu.RLock()
	defer trustedProxyNetsMu.RUnlock()
	out := make([]string, len(trustedProxyNets))
	for i, n := range trustedProxyNets {
		out[i] = n.String()
	}
	return out
}

// ipInNets reports whether ip is contained in any of nets.
func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// peerHost extracts the host from a RemoteAddr, tolerating a missing port.
func peerHost(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// realClientIP returns the effective client IP for an admin-UI per-IP
// decision. It returns the direct peer unless that peer is a configured
// trusted proxy, in which case it returns the rightmost X-Forwarded-For hop
// that is not itself a trusted proxy (the real client behind the proxy
// chain). See the package comment for the security rationale.
func realClientIP(r *http.Request) string {
	peer := peerHost(r.RemoteAddr)

	trustedProxyNetsMu.RLock()
	trusted := trustedProxyNets
	trustedProxyNetsMu.RUnlock()
	if len(trusted) == 0 {
		return peer // no trusted proxies configured — never trust XFF
	}
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !ipInNets(peerIP, trusted) {
		return peer // request did not arrive through a trusted proxy
	}

	// Join ALL X-Forwarded-For field lines, not just the first. Header.Get
	// returns only the first field value, so a proxy that APPENDS its hop as a
	// SEPARATE X-Forwarded-For header (rather than comma-appending to the
	// client's existing one) would leave the real client IP in a later field
	// that Get() drops — and we'd walk only the client-controlled first field,
	// honoring a spoofed value because the peer is trusted. Per RFC 7230 §3.2.2,
	// repeated field lines are equivalent to one comma-joined value in order, so
	// joining is correct and closes that spoof (Codex P1). The right-to-left
	// walk then still selects the rightmost (proxy-appended) untrusted hop.
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer
	}
	xff := strings.Join(values, ",")
	// XFF is "client, proxy1, proxy2, …" (left = original client, right = most
	// recent hop). Walk from the right; the first hop NOT in the trusted set is
	// the client that handed off to our innermost trusted proxy.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			continue // malformed hop — skip, don't trust it as a client
		}
		if !ipInNets(ip, trusted) {
			// Return the CANONICAL form, not the raw header text: two textual
			// spellings of one IP (e.g. "::ffff:1.2.3.4" vs "1.2.3.4") must not
			// fork the per-IP lockout/rate-limit key (review F2).
			return ip.String()
		}
	}
	// Every hop was a trusted proxy (fully-internal chain) — fall back to the
	// peer rather than guess.
	return peer
}
