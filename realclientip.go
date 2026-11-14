package main

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/realclientip"
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
// The trust set and the X-Forwarded-For walk are owned by
// internal/realclientip (ADR-0045). Main owns this one application instance,
// its persistence in admin settings, and the call sites; the names below are
// thin wrappers so no caller changed.
var clientIPResolver realclientip.Resolver

// SetTrustedProxyCIDRs replaces the trusted-proxy set. An empty/blank list
// clears it (the safe default: no X-Forwarded-For is ever trusted). Returns an
// error WITHOUT mutating state if any entry is invalid.
func SetTrustedProxyCIDRs(cidrs []string) error {
	return clientIPResolver.SetTrustedProxies(cidrs)
}

// ListTrustedProxyCIDRs returns the current trusted-proxy set as strings.
func ListTrustedProxyCIDRs() []string { return clientIPResolver.TrustedProxies() }

// realClientIP returns the effective client IP for an admin-UI per-IP
// decision: the direct peer unless that peer is a configured trusted proxy,
// in which case the rightmost X-Forwarded-For hop that is not itself a
// trusted proxy.
func realClientIP(r *http.Request) string { return clientIPResolver.ClientIP(r) }
