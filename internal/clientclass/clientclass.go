// Package clientclass is the deterministic client classifier: whether a request
// comes from an interactive browser (eligible for a captive-portal SSO
// redirect), an opaque CONNECT tunnel (never redirectable), or a non-browser
// service client. It is a self-contained leaf (stdlib only) extracted from
// package main per ADR-0002.
//
// Per Plan Freeze #5 (roadmap/AUTH-POLICY-PHASE1-PLAN.md), portal eligibility
// must NOT depend on User-Agent heuristics: the deterministic mechanism is
// "non-CONNECT AND HTML-navigable". Classify therefore reads NO User-Agent. The
// legacy "Mozilla" substring check is quarantined in BrowserRedirectEligibleLegacy
// (the unchanged Default path) and is replaced when SSORequired ships.
package clientclass

import (
	"net/http"
	"strings"
)

// Class is the deterministic classification of a request's client for the
// purpose of authentication-challenge mechanics.
type Class int

const (
	// NonBrowser is a programmatic / service client that cannot complete an
	// interactive browser SSO redirect (curl, SDKs, API clients) — including a
	// client that merely advertises a Mozilla-compatible User-Agent without an
	// HTML-navigation signal.
	NonBrowser Class = iota
	// Browser is an interactive browser eligible for a captive-portal redirect
	// (a top-level navigation that can follow a 302 to an IdP).
	Browser
	// Connect is an opaque CONNECT tunnel. A 302 is meaningless to a CONNECT
	// client, so it is never browser-eligible regardless of any header.
	Connect
)

// Classify deterministically classifies a request using ONLY the method and
// HTML-navigation signal headers (never the User-Agent — Plan Freeze #5). Pure:
// no side effects, no global state.
//
// Resolution order (first match wins):
//  1. CONNECT method            → Connect    (opaque tunnel, not redirectable)
//  2. Sec-Fetch-Mode: navigate  → Browser    (explicit top-level navigation)
//  3. Accept contains text/html → Browser    (RFC-correct navigation signal)
//  4. otherwise                 → NonBrowser
func Classify(r *http.Request) Class {
	if r.Method == http.MethodConnect {
		return Connect
	}
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return Browser
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return Browser
	}
	return NonBrowser
}

// BrowserRedirectEligibleLegacy is the EXACT predicate the no-credentials
// Default path used inline before Phase 3 Slice 1 (`isBrowser && method !=
// CONNECT`, where isBrowser was a "Mozilla" User-Agent substring match). It is
// the QUARANTINE for the legacy User-Agent heuristic (Plan Freeze #5): it
// remains confined to the unchanged Default path and is NOT consulted by
// Classify.
func BrowserRedirectEligibleLegacy(r *http.Request) bool {
	return r.Method != http.MethodConnect &&
		strings.Contains(r.Header.Get("User-Agent"), "Mozilla")
}
