// Package destination is the PR-7 destination-safety engine: destination
// extraction, URL/host/IP canonicalization, immutable destination policy, an
// INJECTED DNS resolver, connect-time pinned resolution + peer verification
// (MCP-INSP-005 rebinding guard), and a shared reusable redirect guard
// (MCP-INSP-006). SSRF classification reuses the AUTHORITATIVE private/internal
// ranges from internal/ssrf (ssrf.PrivateIP) — there is no second, divergent
// private-address table.
//
// Load-bearing properties, all asserted by tests:
//
//   - Reuse the one SSRF table. Every private/link-local/metadata/loopback/
//     reserved/multicast decision goes through ssrf.PrivateIP (and the same
//     ssrf.Control at connect). No parallel CIDR list.
//   - Pinned resolve→connect. Resolution happens ONCE (Resolve) and produces an
//     immutable PinnedDestination whose permitted IP set the connect-time
//     VerifyPeer checks; the core never re-resolves a hostname for connect. A DNS
//     answer that mixes public and private addresses fails closed as a whole.
//   - Injected resolver. The core NEVER uses net.DefaultResolver directly; the
//     resolver is an interface a caller injects, so unit tests use no real DNS.
//   - Canonical facts. Canonicalization rejects userinfo, fragments-as-policy,
//     malformed ports, control chars, ambiguous percent-encoding, non-canonical
//     numeric-IP spellings, IPv6 zone identifiers, and (in V1) non-ASCII hosts;
//     policy facts use exact canonical values.
//   - Request-local redirect state. The redirect guard holds per-request state
//     (hop count, origin); there is one shared implementation, not per-client
//     copies, and every hop is independently re-canonicalized, re-SSRF-checked and
//     re-pinned.
package destination

import (
	"net"
	"net/netip"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// Class is the safe, bounded destination classification used as a policy fact and
// in evidence. It never carries the raw host/URL.
type Class uint8

const (
	// ClassUnknown — not classified (fails closed for high-risk).
	ClassUnknown Class = iota
	// ClassPublic — a public, routable address (the only permitted class).
	ClassPublic
	// ClassLoopback — 127.0.0.0/8, ::1.
	ClassLoopback
	// ClassPrivate — RFC1918 / ULA / CGN internal ranges.
	ClassPrivate
	// ClassLinkLocal — 169.254/16, fe80::/10 (link-local).
	ClassLinkLocal
	// ClassMetadata — a cloud metadata endpoint (169.254.169.254 / fd00:ec2::254).
	ClassMetadata
	// ClassReserved — unspecified/reserved/benchmark ranges.
	ClassReserved
	// ClassMulticast — multicast ranges.
	ClassMulticast
	// ClassBlockedScheme — a rejected URL scheme (file/data/javascript/…).
	ClassBlockedScheme
	// ClassMalformed — a URL/host/IP that failed canonicalization.
	ClassMalformed
)

// String returns the stable class label.
func (c Class) String() string {
	switch c {
	case ClassPublic:
		return "public"
	case ClassLoopback:
		return "loopback"
	case ClassPrivate:
		return "private"
	case ClassLinkLocal:
		return "link_local"
	case ClassMetadata:
		return "metadata"
	case ClassReserved:
		return "reserved"
	case ClassMulticast:
		return "multicast"
	case ClassBlockedScheme:
		return "blocked_scheme"
	case ClassMalformed:
		return "malformed"
	default:
		return "unknown"
	}
}

// Permitted reports whether a class may be dialed (only ClassPublic).
func (c Class) Permitted() bool { return c == ClassPublic }

// Canonical is the immutable canonicalized destination. It holds only exact
// canonical facts — never the raw URL, never a query string with secrets.
type Canonical struct {
	Scheme string
	Host   string // canonical host (lowercased ASCII, or canonical IP literal text)
	Port   string // explicit or scheme-default port, always present
	IsIP   bool
	IP     netip.Addr // valid iff IsIP
	// HasQuery/HasUserinfo/HasFragment are booleans (facts), never the values.
	HasQuery bool
	// path/query are kept unexported: they are used ONLY for internal loop-key
	// computation and are NEVER surfaced in evidence (a query may carry secrets).
	path  string
	query string
}

// Origin returns the canonical scheme://host:port origin string (safe evidence).
func (c Canonical) Origin() string { return c.Scheme + "://" + c.Host + ":" + c.Port }

// fullKey is the internal loop-detection key: origin + path + query. It is never
// exposed as evidence.
func (c Canonical) fullKey() string { return c.Origin() + c.path + "?" + c.query }

// PinnedDestination is the immutable resolve-time pin the connect leg verifies
// against. It is produced ONCE by Resolve and consumed by VerifyPeer; a future
// upstream client MUST dial only an address in AllowedIPs, never re-resolve Host.
type PinnedDestination struct {
	Scheme           string
	Host             string
	Port             string
	AllowedIPs       []netip.Addr // every entry already passed the SSRF check
	ResolverRevision uint64       // profile/resolver revision the pin was made under
	Expiry           time.Time    // bounded pin lifetime (resolver deadline)
}

// Stale reports whether the pin has expired relative to now (fail closed on a
// zero/expired deadline).
func (p PinnedDestination) Stale(now time.Time) bool {
	return p.Expiry.IsZero() || !now.Before(p.Expiry)
}

// Contains reports whether ip is a member of the pinned permitted set.
func (p PinnedDestination) Contains(ip netip.Addr) bool {
	ipn := ip.Unmap()
	for _, a := range p.AllowedIPs {
		if a.Unmap() == ipn {
			return true
		}
	}
	return false
}

// RedirectEvidence is one bounded, safe redirect-hop record (no raw URL, only the
// canonical origin and hop index).
type RedirectEvidence struct {
	Hop        int
	FromOrigin string
	ToOrigin   string
	DestClass  Class
}

// Status is the safe result of destination inspection for one candidate.
type Status struct {
	Class     Class
	Canonical Canonical
	Reason    mcperr.Reason // ReasonNone when permitted
}

// classifyIP maps an address to a Class using the AUTHORITATIVE ssrf table for the
// block decision and netip predicates for the finer label. metadata endpoints are
// refined out of the link-local/private bucket for evidence clarity.
func classifyIP(ip netip.Addr) Class {
	ip = ip.Unmap()
	if isMetadataIP(ip) {
		return ClassMetadata
	}
	if ip.IsLoopback() {
		return ClassLoopback
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return ClassLinkLocal
	}
	if ip.IsMulticast() {
		return ClassMulticast
	}
	if ip.IsUnspecified() {
		return ClassReserved
	}
	// The authoritative private/internal decision (RFC1918/ULA/CGN/benchmark/
	// mapped-bypass/etc.) — never a second table. Unmap above already collapsed
	// IPv4-mapped IPv6 to its 4-byte form, so a ::ffff:10.0.0.1 bypass is caught.
	if ssrf.PrivateIP(ipToNetIP(ip)) {
		return ClassPrivate
	}
	if !ip.IsValid() || !ip.IsGlobalUnicast() {
		return ClassReserved
	}
	return ClassPublic
}

// ipToNetIP converts a netip.Addr to the net.IP the ssrf table consumes.
func ipToNetIP(ip netip.Addr) net.IP { return net.IP(ip.AsSlice()) }

// isMetadataIP flags the well-known cloud metadata endpoints.
func isMetadataIP(ip netip.Addr) bool {
	if ip.Is4() && ip == netip.AddrFrom4([4]byte{169, 254, 169, 254}) {
		return true
	}
	// AWS IPv6 metadata fd00:ec2::254
	md6 := netip.MustParseAddr("fd00:ec2::254")
	return ip == md6
}

func destErr(r mcperr.Reason, detail string) error {
	return mcperr.New(r, "destination", detail)
}
