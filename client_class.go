package main

import (
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 Slice 1 — deterministic client classifier.
//
// classifyClient is the single, deterministic source of truth for whether a
// request comes from an interactive browser (eligible for a captive-portal SSO
// redirect), an opaque CONNECT tunnel (never redirectable), or a non-browser /
// service client. It is introduced ahead of the SSORequired runtime (Phase 3
// Slice 4) and is INTENTIONALLY not yet consulted on the request hot path.
//
// Per Plan Freeze #5 (roadmap/AUTH-POLICY-PHASE1-PLAN.md), portal eligibility
// must NOT depend on User-Agent heuristics: the deterministic mechanism is
// "non-CONNECT AND HTML-navigable (Accept: contains text/html, optionally
// corroborated by Sec-Fetch-Mode: navigate)". classifyClient therefore reads NO
// User-Agent — it adds no UA dependence. The legacy "Mozilla" substring check is
// QUARANTINED in browserRedirectEligibleLegacy (the unchanged Default path) and
// is replaced when SSORequired ships.
//
// Consequence: classifyClient and browserRedirectEligibleLegacy are DISTINCT
// predicates with different purposes — they intentionally diverge on a
// Mozilla-UA request that carries no HTML-navigation signal (legacy treats it as
// redirect-eligible for backward compatibility; classifyClient treats it as
// NonBrowser, so an SSORequired rule will fail closed deterministically rather
// than issue a 302 the client cannot follow). This is the frozen design, not a
// superset relationship.
// ─────────────────────────────────────────────────────────────────────────────

// ClientClass is the deterministic classification of a request's client for the
// purpose of authentication-challenge mechanics.
type ClientClass int

const (
	// clientNonBrowser is a programmatic / service client that cannot complete
	// an interactive browser SSO redirect (curl, SDKs, API clients) — including
	// a client that merely advertises a Mozilla-compatible User-Agent without an
	// HTML-navigation signal.
	clientNonBrowser ClientClass = iota
	// clientBrowser is an interactive browser eligible for a captive-portal
	// redirect (a top-level navigation that can follow a 302 to an IdP).
	clientBrowser
	// clientConnect is an opaque CONNECT tunnel. A 302 is meaningless to a
	// CONNECT client, so it is never browser-eligible regardless of any header.
	clientConnect
)

// classifyClient deterministically classifies a request using ONLY the method
// and HTML-navigation signal headers (never the User-Agent — Plan Freeze #5).
// Pure: no side effects, no global state.
//
// Resolution order (first match wins):
//  1. CONNECT method            → clientConnect  (opaque tunnel, not redirectable)
//  2. Sec-Fetch-Mode: navigate  → clientBrowser  (explicit top-level navigation)
//  3. Accept contains text/html → clientBrowser  (RFC-correct navigation signal)
//  4. otherwise                 → clientNonBrowser
func classifyClient(r *http.Request) ClientClass {
	if r.Method == http.MethodConnect {
		return clientConnect
	}
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return clientBrowser
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return clientBrowser
	}
	return clientNonBrowser
}

// browserRedirectEligibleLegacy is the EXACT predicate the no-credentials Default
// path used inline before Phase 3 Slice 1 (proxy.go: `isBrowser && method !=
// CONNECT`, where isBrowser was a "Mozilla" User-Agent substring match). It is
// extracted verbatim so this file owns all client-classification logic and the
// Slice-1 proxy.go change stays a behavior-preserving extract-method. This is the
// QUARANTINE for the legacy User-Agent heuristic (Plan Freeze #5): it remains
// confined to the unchanged Default path and is NOT consulted by classifyClient.
// When SSORequired ships (Slice 4), the Default path's reliance on this legacy
// predicate is revisited (DR-5).
func browserRedirectEligibleLegacy(r *http.Request) bool {
	return r.Method != http.MethodConnect &&
		strings.Contains(r.Header.Get("User-Agent"), "Mozilla")
}
