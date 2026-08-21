package destination

import (
	"net/url"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// RedirectGuard is the single, shared, reusable redirect guard (MCP-INSP-006). It
// holds REQUEST-LOCAL state (hop count, previous origin, visited set) — there is
// one implementation, never a per-client copy. A future upstream MCP client
// consumes this guard: every hop is independently re-canonicalized,
// re-SSRF-checked (for IP-literal targets) and must be re-pinned by the caller
// (Resolve on the returned Canonical), authorization is never carried across an
// origin (cross-origin is rejected by default), and the chain is bounded.
type RedirectGuard struct {
	pol      Policy
	lim      limits.InspectionLimits
	hops     int
	prev     Canonical
	visited  map[string]struct{}
	Evidence []RedirectEvidence
}

// NewRedirectGuard starts a guard at the initial canonical destination.
func NewRedirectGuard(initial Canonical, pol Policy, lim limits.InspectionLimits) *RedirectGuard {
	g := &RedirectGuard{pol: pol, lim: lim, prev: initial, visited: map[string]struct{}{}}
	g.visited[initial.fullKey()] = struct{}{}
	return g
}

// Next validates ONE redirect hop given the Location value (absolute or relative).
// It returns the new canonical destination (which the caller MUST re-resolve and
// re-pin) or a typed rejection. It rejects hop-count overflow, loops, scheme
// downgrade, userinfo, cross-origin (unless allowed), a malformed relative target,
// and — for an IP-literal target — a public→private/metadata escape.
func (g *RedirectGuard) Next(location string) (Canonical, error) {
	g.hops++
	if g.hops > g.lim.MaxRedirectHops() {
		return Canonical{}, destErr(mcperr.ReasonRedirectLimitExceeded, "too many redirects")
	}
	abs, err := g.resolveReference(location)
	if err != nil {
		return Canonical{}, err
	}
	next, class, err := Canonicalize(abs, g.pol, g.lim)
	if err != nil {
		// A malformed/blocked-scheme/userinfo redirect target is a rejection.
		return Canonical{}, destErr(mcperr.ReasonRedirectRejected, "redirect target rejected")
	}
	if err := g.checkTransition(next, class); err != nil {
		return Canonical{}, err
	}
	// Loop detection: revisiting a full URL (origin+path+query) already in the chain.
	if _, seen := g.visited[next.fullKey()]; seen {
		return Canonical{}, destErr(mcperr.ReasonRedirectRejected, "redirect loop")
	}
	g.recordEvidence(next, class)
	g.visited[next.fullKey()] = struct{}{}
	g.prev = next
	return next, nil
}

func (g *RedirectGuard) resolveReference(location string) (string, error) {
	if location == "" || len(location) > g.lim.MaxURLBytes() {
		return "", destErr(mcperr.ReasonRedirectRejected, "malformed redirect location")
	}
	base := &url.URL{Scheme: g.prev.Scheme, Host: g.prev.Host + ":" + g.prev.Port}
	ref, err := url.Parse(location)
	if err != nil {
		return "", destErr(mcperr.ReasonRedirectRejected, "unparseable redirect location")
	}
	return base.ResolveReference(ref).String(), nil
}

// checkTransition enforces the per-hop cross-origin, scheme-downgrade and
// SSRF-escape rules.
func (g *RedirectGuard) checkTransition(next Canonical, class Class) error {
	if g.prev.Scheme == "https" && next.Scheme == "http" && !g.pol.allowSchemeDowngrade {
		return destErr(mcperr.ReasonRedirectRejected, "https to http downgrade")
	}
	if next.Origin() != g.prev.Origin() && !g.pol.allowCrossOriginRedirect {
		// Cross-origin: rejected by default, which also guarantees no authorization
		// header is ever forwarded across an origin.
		return destErr(mcperr.ReasonRedirectRejected, "cross-origin redirect")
	}
	// For an IP-literal target, re-run the SSRF classification directly (public→
	// private / public→metadata escape). A hostname target's class is verified when
	// the caller re-resolves + re-pins.
	if next.IsIP && !class.Permitted() && !g.pol.allowPrivate {
		return destErr(mcperr.ReasonRedirectRejected, "redirect to non-public address")
	}
	return nil
}

func (g *RedirectGuard) recordEvidence(next Canonical, class Class) {
	if len(g.Evidence) >= g.lim.MaxRedirectEvidence() {
		return
	}
	g.Evidence = append(g.Evidence, RedirectEvidence{
		Hop: g.hops, FromOrigin: g.prev.Origin(), ToOrigin: next.Origin(), DestClass: class,
	})
}

// ForwardAuthAllowed reports whether an authorization/credential header may be
// forwarded to next given the current origin. It is false across origins — the
// future client must strip credentials on any cross-origin hop.
func (g *RedirectGuard) ForwardAuthAllowed(next Canonical) bool {
	return next.Origin() == g.prev.Origin()
}
