package main

import (
	"net"
	"net/http"
)

// auth_state_client.go — the fairness key for the bounded interactive-login
// state stores (internal/authstate: OIDC PKCE, SAML AuthnRequest).
//
// Those stores are populated by UNAUTHENTICATED requests (the proxy's
// no-credentials captive-portal path and the public /auth/select page), so the
// key that decides who gets evicted under pressure has to be something a
// requester cannot mint at will. See the internal/authstate package comment
// for the eviction policy this feeds.

// authStateClientKey derives the eviction-fairness key for r.
//
// Three deliberate choices:
//
//   - It goes through realClientIP, so an X-Forwarded-For header is honoured
//     ONLY when the direct peer is a configured trusted proxy. Keying on a
//     freely spoofable header would hand an attacker an unlimited supply of
//     distinct buckets and defeat the fair-share policy outright — the same
//     reason RISK-019 gated the lockout and rate-limit keys.
//
//   - IPv6 collapses to its /64. A single host legitimately owns a whole /64
//     (SLAAC / privacy addressing), so keying on the full address would let
//     one machine present thousands of "clients"; the same /64 collapse is
//     already the project's convention for per-client evidence (see
//     clientEvidence in autoexclude_resolve.go). IPv4 stays RAW: a /24 is a
//     network of many distinct devices, and folding it would penalise a
//     legitimate enterprise subnet.
//
//   - An unresolvable address yields "", which is a valid key: all such
//     entries share one bucket and can only evict each other. It never widens
//     anything — the key is used for eviction ordering only, never for
//     lookup, authentication, or authorization.
func authStateClientKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := net.ParseIP(realClientIP(r))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
