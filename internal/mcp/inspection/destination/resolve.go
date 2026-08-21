package destination

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// Resolver is the INJECTED DNS resolver. The core inspector never uses
// net.DefaultResolver directly — a caller supplies a bounded implementation, so
// unit tests use no real external DNS. Production wiring passes an adapter over a
// bounded net.Resolver.
type Resolver interface {
	// LookupIP resolves host to a set of IP addresses (already deduplicated is not
	// required). It MUST honor ctx (deadline/cancel). It returns addresses only —
	// never CNAME chains — so CNAME depth is bounded inside the implementation.
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// Resolve performs bounded, pinned resolution of a canonical destination. For an
// IP literal it pins the single address; for a hostname it resolves via the
// injected resolver, rejects an empty/oversized/malformed answer, fails the WHOLE
// answer closed if ANY address is private/forbidden (mixed public/private is a
// single private-address poison), and builds an immutable PinnedDestination. It
// never re-resolves for connect — VerifyPeer checks the pinned set. now + ttl
// bound the pin lifetime. Resolution is single-shot; there is no per-address
// goroutine.
func Resolve(ctx context.Context, c Canonical, pol Policy, r Resolver, lim limits.InspectionLimits, now time.Time, ttl time.Duration) (PinnedDestination, Status, error) {
	if c.IsIP {
		return resolveLiteral(c, pol, now, ttl)
	}
	if r == nil {
		return PinnedDestination{}, Status{Class: ClassUnknown, Canonical: c, Reason: mcperr.ReasonDNSResolutionFailed},
			destErr(mcperr.ReasonDNSResolutionFailed, "no resolver injected")
	}
	addrs, err := r.LookupIP(ctx, c.Host)
	if err != nil {
		return PinnedDestination{}, Status{Class: ClassUnknown, Canonical: c, Reason: mcperr.ReasonDNSResolutionFailed},
			destErr(mcperr.ReasonDNSResolutionFailed, "resolver error")
	}
	if len(addrs) == 0 {
		return PinnedDestination{}, Status{Class: ClassUnknown, Canonical: c, Reason: mcperr.ReasonDNSResolutionFailed},
			destErr(mcperr.ReasonDNSResolutionFailed, "empty dns answer")
	}
	if len(addrs) > lim.MaxDNSAddresses() {
		return PinnedDestination{}, Status{Class: ClassUnknown, Canonical: c, Reason: mcperr.ReasonDNSResolutionFailed},
			destErr(mcperr.ReasonDNSResolutionFailed, "dns answer overflow")
	}
	return classifyAnswer(c, pol, addrs, now, ttl)
}

func resolveLiteral(c Canonical, pol Policy, now time.Time, ttl time.Duration) (PinnedDestination, Status, error) {
	class := classifyIP(c.IP)
	if !class.Permitted() && !pol.allowPrivate {
		return PinnedDestination{}, Status{Class: class, Canonical: c, Reason: mcperr.ReasonSSRFBlocked},
			destErr(mcperr.ReasonSSRFBlocked, "literal destination is not public")
	}
	pin := PinnedDestination{
		Scheme: c.Scheme, Host: c.Host, Port: c.Port,
		AllowedIPs: []netip.Addr{c.IP.Unmap()}, ResolverRevision: pol.resolverRevision,
		Expiry: now.Add(ttl),
	}
	return pin, Status{Class: class, Canonical: c}, nil
}

func classifyAnswer(c Canonical, pol Policy, addrs []netip.Addr, now time.Time, ttl time.Duration) (PinnedDestination, Status, error) {
	var permitted []netip.Addr
	sawPublic, sawForbidden := false, false
	for _, a := range addrs {
		if !a.IsValid() {
			return PinnedDestination{}, Status{Class: ClassMalformed, Canonical: c, Reason: mcperr.ReasonDNSResolutionFailed},
				destErr(mcperr.ReasonDNSResolutionFailed, "malformed resolved address")
		}
		cl := classifyIP(a)
		if cl.Permitted() {
			sawPublic = true
			permitted = append(permitted, a.Unmap())
			continue
		}
		if pol.allowPrivate {
			permitted = append(permitted, a.Unmap())
			continue
		}
		sawForbidden = true
	}
	if sawForbidden {
		reason := mcperr.ReasonSSRFBlocked
		if sawPublic {
			reason = mcperr.ReasonDNSAnswerMixed // a public+private mix poisons the whole answer
		}
		return PinnedDestination{}, Status{Class: ClassPrivate, Canonical: c, Reason: reason},
			destErr(reason, "dns answer contains a forbidden address")
	}
	pin := PinnedDestination{
		Scheme: c.Scheme, Host: c.Host, Port: c.Port,
		AllowedIPs: permitted, ResolverRevision: pol.resolverRevision, Expiry: now.Add(ttl),
	}
	return pin, Status{Class: ClassPublic, Canonical: c}, nil
}

// VerifyPeer is the connect-time rebinding guard (MCP-INSP-005). It confirms the
// actual peer (1) still passes the AUTHORITATIVE ssrf.Control (a private peer is
// refused even if it somehow reached the pin), (2) is a MEMBER of the immutable
// pinned set (the resolved answer did not change between resolve and connect), and
// (3) the pin is not stale. Any failure fails closed with a typed reason. It does
// NOT re-resolve the hostname.
func VerifyPeer(pin PinnedDestination, peer netip.Addr, pol Policy, now time.Time) error {
	if pin.Stale(now) {
		return destErr(mcperr.ReasonDNSPinMismatch, "stale pin")
	}
	if !peer.IsValid() {
		return destErr(mcperr.ReasonSSRFBlocked, "invalid peer address")
	}
	if !pol.allowPrivate {
		// Execute the real ssrf.Control on the resolved peer address (the same guard
		// the SWG dial path uses). A private/rebinding peer is refused here.
		if err := ssrf.Control("tcp", net.JoinHostPort(peer.String(), pin.Port), noRawConn()); err != nil {
			return destErr(mcperr.ReasonSSRFBlocked, "peer refused by ssrf control")
		}
		if !classifyIP(peer).Permitted() {
			return destErr(mcperr.ReasonSSRFBlocked, "peer is not public")
		}
	}
	if !pin.Contains(peer) {
		return destErr(mcperr.ReasonDNSPinMismatch, "peer not in pinned set")
	}
	return nil
}

// noRawConn returns the nil RawConn ssrf.Control accepts (it uses only the address).
func noRawConn() syscall.RawConn { return nil }
