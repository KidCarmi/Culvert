package main

import (
	"strings"
	"testing"
)

// ui_public_allowlist_test.go — SEC-PUBLICPATH-1 (RISK-033).
//
// isPublicUIAuthPath is the ONE place uiAuthMiddleware decides that a request
// needs no session and no credential, and nothing downstream re-checks it.
//
// The failure mode this file closes is a FORWARD-LOOKING entry rather than a
// wrong one. The list carried `/api/auth/totp` as a PREFIX while no route by
// that name existed, so the entry did nothing today and would silently have
// made the first TOTP enrolment/disable handler somebody wrote reachable with
// no authentication: an anonymous caller could have bound their own second
// factor to an admin account, or stripped an existing one. A prefix that
// pre-authorises endpoints which do not exist yet is an authentication bypass
// waiting for its handler.
//
// The walls below pin the allowlist against the REGISTERED route inventory:
// every entry must name something real, and the former TOTP paths must never
// be public again.

// publicAllowlistEntry is one branch of isPublicUIAuthPath.
type publicAllowlistEntry struct {
	Match  string // path (exact) or prefix
	Prefix bool
	Why    string
}

// publicAllowlistEntries mirrors isPublicUIAuthPath's branches. It is a manual
// mirror on purpose: changing the function must require touching this list, so
// a new branch has to say which registered route it is for and why that route
// is public.
var publicAllowlistEntries = []publicAllowlistEntry{
	{"/api/setup", true, "first-time setup bootstrap — there is no credential to present yet"},
	{"/api/auth/login", false, "the login endpoint itself"},
	{"/api/auth/logout", false, "clearing a cookie must work without one"},
	{"/api/auth/status", false, "the login overlay reads it before a session exists"},
	{"/auth/", true, "IdP callbacks (OIDC/SAML) arrive from the browser with no session"},
	{"/proxy.pac", false, "Windows/WPAD clients fetch it with no credentials"},
	{"/pac/", true, "per-profile PAC files, same reason"},
	{"/api/cluster/bootstrap/", true, "the single-use, time-limited enrollment token IS the auth (bootstrap.go)"},
}

// registeredUIRoutePaths returns the set of uiRoutes paths.
func registeredUIRoutePaths(t *testing.T) map[string]bool {
	t.Helper()
	registered := make(map[string]bool, len(uiRoutes))
	for i := range uiRoutes {
		registered[uiRoutes[i].Path] = true
	}
	if len(registered) == 0 {
		t.Fatal("uiRoutes is empty — the wall would be vacuous")
	}
	return registered
}

// publicAllowlistEntryIsBacked reports whether e names (exact) or covers
// (prefix) at least one registered route.
func publicAllowlistEntryIsBacked(e publicAllowlistEntry, registered map[string]bool) bool {
	if !e.Prefix {
		return registered[e.Match]
	}
	for path := range registered {
		if strings.HasPrefix(path, e.Match) {
			return true
		}
	}
	return false
}

// TestPublicAllowlist_MirrorMatchesTheFunction proves the table above still
// describes isPublicUIAuthPath, and that the named never-public paths —
// including everything the removed `/api/auth/totp` prefix used to cover —
// require authentication. The TOTP rows fail on the pre-fix tree.
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

	// A regression here is a direct authentication bypass, so the paths are
	// named rather than generated.
	for _, path := range []string{
		"/api/auth/users",
		"/api/auth/change-password",
		"/api/auth/lockouts",
		"/api/auth/totp",         // SEC-PUBLICPATH-1: the removed dead prefix
		"/api/auth/totp/enroll",  // ... and what it would have pre-authorised
		"/api/auth/totp/disable", //
		"/api/auth/totp/setup",   //
		"/api/policy",
		"/api/settings",
	} {
		if isPublicUIAuthPath(path) {
			t.Errorf("%q is on the public allowlist — it must require authentication (SEC-PUBLICPATH-1)", path)
		}
	}
}

// TestPublicAllowlist_EveryEntryMatchesARegisteredRoute is the anti-landmine
// wall: an allowlist entry that matches NO registered route pre-authorises
// handlers that do not exist yet. Every exact entry must name a uiRoutes path;
// every prefix entry must cover at least one.
func TestPublicAllowlist_EveryEntryMatchesARegisteredRoute(t *testing.T) {
	registered := registeredUIRoutePaths(t)
	for _, e := range publicAllowlistEntries {
		if !publicAllowlistEntryIsBacked(e, registered) {
			t.Errorf("public allowlist entry %q (prefix=%v, %s) matches no registered route — remove it or register the handler.\n"+
				"An allowlist entry for a route that does not exist yet makes the next handler somebody adds "+
				"public by accident (SEC-PUBLICPATH-1).", e.Match, e.Prefix, e.Why)
		}
	}
}

// TestPublicAllowlist_Control_UnbackedPrefixIsReported is the CONTROL for the
// wall above: the same predicate must REPORT the removed `/api/auth/totp`
// prefix as unbacked and must accept a real one. Without it, a predicate that
// matched everything would let the wall pass forever.
func TestPublicAllowlist_Control_UnbackedPrefixIsReported(t *testing.T) {
	registered := registeredUIRoutePaths(t)
	removed := publicAllowlistEntry{Match: "/api/auth/totp", Prefix: true}
	if publicAllowlistEntryIsBacked(removed, registered) {
		t.Fatalf("control: %q now covers a registered route, so it is no longer a valid negative fixture — "+
			"decide explicitly whether that route is public, then pick another unbacked prefix", removed.Match)
	}
	if !publicAllowlistEntryIsBacked(publicAllowlistEntry{Match: "/api/auth/status"}, registered) {
		t.Fatal("control: the predicate rejects a registered exact route — the wall would fail every entry")
	}
}
