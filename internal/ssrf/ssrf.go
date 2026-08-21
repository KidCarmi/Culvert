// Package ssrf is the SSRF (server-side request forgery) guard: the
// private/internal CIDR table, host resolution checks with a short-TTL DNS
// cache, and the connect-time dialer control that closes the DNS-rebinding
// TOCTOU window. Extracted from package main (proxy.go + security.go) per
// ADR-0002 so outbound-fetching leaves (blocklist feeds, threat feeds) can
// move without importing main. package main keeps thin wrappers
// (isPrivateIP / isPrivateHost / the swappable ssrfSafeDialContext var) so
// every existing call site — and the CodeQL inline-guard convention at those
// sites — is unchanged.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// ErrBlocked is the sentinel every connect-time Control rejection wraps, so a
// caller can errors.Is() an SSRF security block (a DNS-rebinding/private-IP
// target refused at connect) apart from a genuine unreachable-origin dial error.
var ErrBlocked = errors.New("ssrf control: destination blocked")

// privateRanges lists every non-routable / internal-infrastructure range that
// must never be exposed to an untrusted client (SSRF guard) and must never be
// forwarded to upstream servers in headers such as X-Forwarded-For.
//
// Coverage goes beyond RFC 1918 on purpose: CGN (100.64/10) can reach a
// carrier's management plane, 0.0.0.0/8 is treated as "this host" by many
// stacks, and the IPv4-mapped IPv6 form ::ffff:0:0/96 is a known SSRF bypass
// if only IPv4 ranges are listed. Multicast (224/4, ff00::/8) and reserved
// (240/4) ranges are included because they have no legitimate proxy target.
//
// This slice is the SINGLE source of truth for the guard table; both entry
// points below classify against the prefixes compiled from it.
var privateRanges = []string{
	"0.0.0.0/8",      // "this network" / local host on most stacks
	"10.0.0.0/8",     // RFC 1918
	"100.64.0.0/10",  // RFC 6598 — carrier-grade NAT
	"127.0.0.0/8",    // loopback (IPv4)
	"169.254.0.0/16", // link-local (IPv4) — AWS/GCP/Azure metadata lives here
	"172.16.0.0/12",  // RFC 1918
	"192.168.0.0/16", // RFC 1918
	"198.18.0.0/15",  // benchmark network
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved / broadcast (includes 255.255.255.255)
	"::/128",         // unspecified (IPv6)
	"::1/128",        // loopback (IPv6)
	"64:ff9b::/96",   // NAT64
	"100::/64",       // discard prefix
	"fc00::/7",       // ULA (IPv6)
	"fe80::/10",      // link-local (IPv6)
	"ff00::/8",       // multicast (IPv6)
	// IPv4-mapped IPv6 (::ffff:0:0/96) is intentionally NOT listed here:
	// classification unmaps the input first, so a mapped address like
	// ::ffff:127.0.0.1 is still caught by 127.0.0.0/8 above. Listing
	// ::ffff:0:0/96 directly would match ALL IPv4 addresses and block every
	// destination.
}

// guardTable is the compiled guard table, split by address family.
//
// netip.Prefix is a comparable VALUE (no pointer chase, no per-check To4
// conversion), which matters because the table is scanned linearly on hot paths:
// every hop of every X-Forwarded-For header the proxy scrubs, on every proxied
// request. A public address — the common case — matches nothing and therefore
// always pays the FULL scan of its family.
//
// The split is behaviour-preserving by construction rather than by convention:
// classification unmaps first, so the address is then unambiguously IPv4 or
// IPv6, and netip.Prefix.Contains is defined to return false whenever the
// address and the prefix disagree on bit length (32 vs 128). Prefixes of the
// other family could therefore never match, and skipping them removes ~40% of
// the comparisons on the hottest branch.
//
// Measured on the public-IPv4 worst case: ~260 ns/op for the original
// []*net.IPNet + net.IPNet.Contains table, ~100 ns/op for a single netip slice,
// ~60 ns/op here (BenchmarkPrivateAddr_PublicV4 vs
// BenchmarkPrivateIP_LegacyTable, kept in the tests so the comparison is
// reproducible from the tree rather than quoted).
type guardTable struct {
	v4 []netip.Prefix
	v6 []netip.Prefix
}

// forAddr returns the only family bucket that can possibly match addr.
func (g guardTable) forAddr(addr netip.Addr) []netip.Prefix {
	if addr.Is4() {
		return g.v4
	}
	return g.v6
}

// privatePrefixes is the live guard table. It is replaced wholesale (never
// mutated in place) so a reader always sees a consistent pair of buckets.
var privatePrefixes = compileGuardTable(privateRanges)

func compileGuardTable(ranges []string) guardTable {
	var g guardTable
	for _, r := range ranges {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			continue
		}
		p = p.Masked()
		if p.Addr().Is4() {
			g.v4 = append(g.v4, p)
		} else {
			g.v6 = append(g.v6, p)
		}
	}
	return g
}

// PrivateAddr reports whether addr falls within any private/internal range.
//
// It is the allocation-free classification entry point: callers holding a
// netip.Addr (netip.ParseAddr never heap-allocates, unlike net.ParseIP) reach
// the guard table without materialising a net.IP.
//
// Two normalisations reproduce net.IPNet.Contains semantics exactly, and both
// are load-bearing for the guard:
//
//   - Unmap: netip.Prefix.Contains returns false when an IPv4-mapped IPv6
//     address is tested against an IPv4 prefix, whereas net.IPNet.Contains
//     called To4() first. Without the unmap, ::ffff:127.0.0.1 would be
//     classified PUBLIC — the exact mapped-form bypass the table comment above
//     warns about.
//   - Zone strip: netip.Prefix.Contains returns false for ANY address carrying
//     a zone, so fe80::1%eth0 would likewise read as public.
func PrivateAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false // parity with Contains(nil): an invalid address matches nothing
	}
	a := addr.Unmap().WithZone("")
	table := privatePrefixes
	for _, p := range table.forAddr(a) {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// PrivateIP reports whether ip falls within any private/internal range. It is
// the net.IP-shaped façade over PrivateAddr, kept because the SSRF call sites
// (and the CodeQL inline-guard convention at those sites) pass net.IP.
func PrivateIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		// Neither 4- nor 16-byte: net.IPNet.Contains rejected these on the
		// length check, so they matched nothing. Preserve that.
		return false
	}
	return PrivateAddr(addr)
}

// PrivateHost resolves host (host or host:port) and returns an error if any
// resolved IP falls within a private/internal range. This prevents SSRF via
// proxy CONNECT to loopback, RFC 1918, link-local, or metadata endpoints.
// Results are cached in the package DNS cache (30s TTL) to avoid redundant
// DNS lookups.
func PrivateHost(hostport string) error {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport // no port
	}
	// Check cache first.
	if priv, ok := dnsCache.Lookup(host); ok {
		if priv {
			return fmt.Errorf("destination %s resolves to private address (cached)", host)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		// Fail closed: unresolvable hosts are rejected to prevent DNS-rebinding
		// attacks where the check resolves to a public IP but Dial resolves to
		// a private one after TTL expiry. DNS errors are NOT cached.
		return fmt.Errorf("destination %s: DNS resolution failed: %w", host, err)
	}
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil && PrivateIP(ip) {
			dnsCache.Store(host, true)
			return fmt.Errorf("destination %s resolves to private address %s", host, ipStr)
		}
	}
	dnsCache.Store(host, false)
	return nil
}

// ─── SSRF-safe dialer ────────────────────────────────────────────────────────

// Control rejects a connection when the resolved peer address falls into
// any private/internal range. Installed as net.Dialer.Control, it runs AFTER
// DNS resolution and IMMEDIATELY BEFORE connect(2), closing the TOCTOU window
// that a pre-flight LookupHost leaves open (DNS-rebinding: public IP on the
// pre-check, private IP on the real dial).
//
// address is the resolved IP:port that the kernel is about to connect to
// (never a hostname at this layer), so net.ParseIP always succeeds for a
// well-formed stack. We still fail-closed on any parse anomaly.
func Control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: invalid address %q: %v", ErrBlocked, address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unexpected non-IP %q in dial", ErrBlocked, host)
	}
	if PrivateIP(ip) {
		return fmt.Errorf("%w: refusing %s dial to private address %s", ErrBlocked, network, ip)
	}
	return nil
}

// safeDialer is the canonical SSRF-safe dialer. It resolves DNS once, then
// Go applies Control to every resolved address the dialer attempts.
var safeDialer = &net.Dialer{
	Timeout: 15 * time.Second,
	Control: Control,
}

// SafeDialContext is a net.Dialer.DialContext replacement that rejects
// connections to private/internal IPs. Use as the DialContext in an
// http.Transport to prevent SSRF at the network level, independent of URL
// validation. Safe against DNS rebinding because the check runs on the
// post-resolution address that will actually be connected.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return safeDialer.DialContext(ctx, network, addr)
}

// ─── DNS result cache for SSRF checks ────────────────────────────────────────
// Avoids repeated DNS lookups in PrivateHost() for the same host within a
// short window. Entries expire after cacheTTL. Negative results (DNS errors)
// are NOT cached so that transient failures remain fail-closed.

const cacheTTL = 30 * time.Second

type cacheEntry struct {
	private bool // true if any resolved IP was private
	expires time.Time
}

type resultCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

var dnsCache = &resultCache{entries: make(map[string]cacheEntry)}

// Lookup returns (isPrivate, found). If found is false the caller must do a
// live DNS lookup and call Store.
func (c *resultCache) Lookup(host string) (private, found bool) {
	c.mu.RLock()
	e, ok := c.entries[host]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return false, false
	}
	return e.private, true
}

// Store records a positive (resolved) result. DNS errors are not stored.
func (c *resultCache) Store(host string, private bool) {
	c.mu.Lock()
	c.entries[host] = cacheEntry{
		private: private,
		expires: time.Now().Add(cacheTTL),
	}
	c.mu.Unlock()
}

// CacheCleanup evicts expired entries (called periodically from the main
// tick loop, connlimit_startup.go).
func CacheCleanup() {
	dnsCache.mu.Lock()
	now := time.Now()
	for k, e := range dnsCache.entries {
		if now.After(e.expires) {
			delete(dnsCache.entries, k)
		}
	}
	dnsCache.mu.Unlock()
}

// CacheStore seeds a DNS verdict directly. Test support: lets tests mark
// loopback hosts public so local httptest servers pass the guard; pair with
// CacheDelete in cleanup.
func CacheStore(host string, private bool) { dnsCache.Store(host, private) }

// CacheDelete removes a host's cached verdict (test support).
func CacheDelete(host string) {
	dnsCache.mu.Lock()
	delete(dnsCache.entries, host)
	dnsCache.mu.Unlock()
}

// CacheReset replaces the DNS verdict cache with an empty one (test support;
// pairs with AllowLoopbackForTest so stale verdicts don't leak across the
// guard-table swap).
func CacheReset() {
	dnsCache.mu.Lock()
	dnsCache.entries = make(map[string]cacheEntry)
	dnsCache.mu.Unlock()
}

// AllowLoopbackForTest removes the loopback ranges from the guard's CIDR
// table and returns a restore func. Test support for E2E fixtures that must
// CONNECT/dial to 127.0.0.1 through the real proxy path — never call from
// production code. The DNS verdict cache is reset on both swap and restore.
func AllowLoopbackForTest() (restore func()) {
	orig := privatePrefixes
	lo4 := netip.MustParseAddr("127.0.0.1")
	lo6 := netip.MustParseAddr("::1")
	drop := func(in []netip.Prefix) []netip.Prefix {
		out := make([]netip.Prefix, 0, len(in))
		for _, p := range in {
			if p.Contains(lo4) || p.Contains(lo6) {
				continue // drop loopback ranges
			}
			out = append(out, p)
		}
		return out
	}
	privatePrefixes = guardTable{v4: drop(orig.v4), v6: drop(orig.v6)}
	CacheReset()
	return func() {
		privatePrefixes = orig
		CacheReset()
	}
}
