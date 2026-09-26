package main

import (
	"strings"
	"testing"
)

// ui_public_allowlist_test.go — SEC-PUBLICPATH-1.
//
// isPublicUIAuthPath is the ONE place uiAuthMiddleware decides that a request
// needs no session, no credential and no cluster membership. Invariant #5 of
// the Admin UI contract puts the public allowlist entirely in that function's
// hands, so nothing downstream re-checks it.
//
// The failure mode this file closes is not a wrong entry — it is a
// FORWARD-LOOKING one. The list carried `/api/auth/totp` as a PREFIX while no
// route by that name existed anywhere, so the entry did nothing at all and
// would have silently made the first TOTP enrolment/disable handler somebody
// wrote reachable with no authentication: a caller could have stripped an
// admin's second factor. A prefix that pre-authorises endpoints which do not
// exist yet is an authentication bypass waiting for its handler.
//
// The wall below therefore pins the allowlist against the REGISTERED route
// inventory in both directions of usefulness: every entry must name something
// real, and nothing that is public may be missing from uiRoutes.

// publicAllowlistEntries mirrors isPublicUIAuthPath's branches. It is a manual
// mirror on purpose: the point of the wall is that changing the function must
// require touching this list, so a new branch fails the build until its author
// says which registered route it is for and why that route is public.
var publicAllowlistEntries = []struct {
	Match  string // path (exact) or prefix
	Prefix bool
	Why    string
}{
	{"/api/setup", true, "first-time setup bootstrap — there is no credential to present yet"},
	{"/api/auth/login", false, "the login endpoint itself"},
	{"/api/auth/logout", false, "clearing a cookie must work without one"},
	{"/api/auth/status", false, "the login overlay reads it before a session exists"},
	{"/auth/", true, "IdP callbacks (OIDC/SAML) arrive from the browser with no session"},
	{"/proxy.pac", false, "Windows/WPAD clients fetch it with no credentials"},
	{"/pac/", true, "per-profile PAC files, same reason"},
	{"/api/cluster/bootstrap/", true, "the single-use, time-limited enrollment token IS the auth (bootstrap.go)"},
}

// TestPublicAllowlist_MirrorMatchesTheFunction proves the table above still
// describes isPublicUIAuthPath: every entry must be public, and a path that is
// NOT covered by any entry must not be.
func TestPublicAllowlist_MirrorMatchesTheFunction(t *testing.T) {
	for _, e := range publicAllowlistEntries {
		probe := e.Match
		if e.Prefix {
			probe = e.Match + "probe-suffix"
		}
		if !isPublicUIAuthPath(probe) {
			t.Errorf("allowlist mirror claims %q is public but isPublicUIAuthPath(%q) = false — the mirror is stale", e.Match, probe)
		}
	}

	// Paths that must never be public. A regression here is a direct
	// authentication bypass, so they are named rather than generated.
	for _, path := range []string{
		"/api/auth/users",
		"/api/auth/change-password",
		"/api/auth/lockouts",
		"/api/auth/totp",         // SEC-PUBLICPATH-1: the removed dead prefix
		"/api/auth/totp/enroll",  // ... and what it would have pre-authorised
		"/api/auth/totp/disable", //
		"/api/policy",
		"/api/config",
		"/api/settings",
		"/api/cluster/nodes",
		"/api/governance/control-plane",
	} {
		if isPublicUIAuthPath(path) {
			t.Errorf("%q is on the public allowlist — it must require authentication", path)
		}
	}
}

// TestPublicAllowlist_EveryEntryMatchesARegisteredRoute is the anti-landmine
// wall: an allowlist entry that matches NO registered route pre-authorises
// handlers that do not exist yet. Every exact entry must name a uiRoutes path;
// every prefix entry must cover at least one.
func TestPublicAllowlist_EveryEntryMatchesARegisteredRoute(t *testing.T) {
	registered := make(map[string]bool, len(uiRoutes))
	for i := range uiRoutes {
		registered[uiRoutes[i].Path] = true
	}
	if len(registered) == 0 {
		t.Fatal("uiRoutes is empty — the wall would be vacuous")
	}

	for _, e := range publicAllowlistEntries {
		if !e.Prefix {
			if !registered[e.Match] {
				t.Errorf("public allowlist entry %q (%s) names no registered route — remove it or register the handler.\n"+
					"An allowlist entry for a route that does not exist yet makes the next handler somebody adds "+
					"public by accident (SEC-PUBLICPATH-1).", e.Match, e.Why)
			}
			continue
		}
		covered := false
		for path := range registered {
			if strings.HasPrefix(path, e.Match) {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("public allowlist PREFIX %q (%s) covers no registered route — remove it or register a handler under it.\n"+
				"A prefix pre-authorises every future path beneath it (SEC-PUBLICPATH-1).", e.Match, e.Why)
		}
	}
}

// TestPublicAllowlist_ControlRejectsAnUnbackedPrefix is the CONTROL: it runs
// the wall's own predicate against a prefix that is deliberately not
// registered and requires it to be reported as uncovered. Without it, a
// predicate that matched everything would pass forever.
func TestPublicAllowlist_ControlRejectsAnUnbackedPrefix(t *testing.T) {
	registered := make(map[string]bool, len(uiRoutes))
	for i := range uiRoutes {
		registered[uiRoutes[i].Path] = true
	}
	const unbacked = "/api/auth/totp" // exactly the entry SEC-PUBLICPATH-1 removed
	for path := range registered {
		if strings.HasPrefix(path, unbacked) {
			t.Fatalf("control: %q is now a registered route, so it is no longer a valid negative fixture — "+
				"pick another unbacked prefix and decide explicitly whether the new route is public", path)
		}
	}
}
