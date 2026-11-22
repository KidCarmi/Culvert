package main

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/authstate"
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
// It goes through realClientIP, so an X-Forwarded-For header is honoured ONLY
// when the direct peer is a configured trusted proxy. Keying on a freely
// spoofable header would hand an attacker an unlimited supply of distinct
// buckets and defeat the fair-share policy outright — the same reason RISK-019
// gated the lockout and rate-limit keys. The key shape itself (raw IPv4, IPv6
// collapsed to its /64, "" for an unresolvable address) is authstate.ClientKey.
func authStateClientKey(r *http.Request) string {
	if r == nil {
		return ""
	}
	return authstate.ClientKey(realClientIP(r))
}
