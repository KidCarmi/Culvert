package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// d0PublicPaths is the locked allowlist that uiAuthMiddleware must let
// through without a session cookie. Mirrors the prefix/exact rules at
// ui_middleware.go:uiAuthMiddleware. A regression here means a previously
// public surface is now hidden behind auth (login screens break) or a
// previously gated route became reachable without credentials.
//
// Categories:
//   - setup bootstrap (prefix /api/setup)
//   - login/logout/status auth endpoints
//   - TOTP enrolment (prefix /api/auth/totp)
//   - IdP browser callbacks (prefix /auth/)
//   - PAC file (Windows clients cannot send credentials)
//   - non-/api/ paths (e.g. /healthz) bypass the API gate entirely
var d0PublicPaths = []string{
	"/api/setup/status",
	"/api/setup/complete",
	"/api/setup/anything-else", // prefix allowlist /api/setup
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/status",
	"/api/auth/totp/enroll", // prefix allowlist /api/auth/totp
	"/api/auth/totp/verify", // prefix allowlist /api/auth/totp
	"/auth/oidc/callback",
	"/auth/saml/callback",
	"/auth/select",
	"/auth/logout",
	"/auth/some-future-callback", // prefix allowlist /auth/
	"/proxy.pac",
	"/pac/default.pac",
	"/healthz", // non-/api/, passes the prefix check
}

// d0NonPublicAPISample is a representative slice of /api/* routes that
// MUST require authentication. We do not enumerate all 100+ non-public
// routes — one per domain is enough to detect a chain-wide regression.
// /api/auth/users is included intentionally: it lives under /api/auth/ but
// is NOT on the public allowlist (only /api/auth/login|logout|status are).
var d0NonPublicAPISample = []string{
	"/api/auth/users", // intentionally NOT public
	"/api/auth/change-password",
	"/api/policy",
	"/api/blocklist",
	"/api/settings",
	"/api/security",
	"/api/cluster/status",
	"/api/diagnostics",
	"/api/audit",
	"/api/cdr/config",
	"/api/update/status",
	"/api/ca/status",
}

// TestD0_PublicRoutes_StayPublic asserts that uiAuthMiddleware lets every
// path in d0PublicPaths reach its underlying handler without a session
// cookie. We test the middleware in isolation against a sentinel handler
// rather than the full chain — using the real chain would conflate "auth
// middleware allowed it" with "downstream handler responded 401" (e.g. the
// SAML callback returns 401 when no provider is configured).
//
// A regression here means a previously public surface is now hidden
// behind auth — login screens, IdP callbacks, or PAC clients will break.
func TestD0_PublicRoutes_StayPublic(t *testing.T) {
	d0EnableLocalAuth(t)

	for _, p := range d0PublicPaths {
		t.Run(p, func(t *testing.T) {
			var reached bool
			sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			handler := uiAuthMiddleware(sentinel)
			req := d0Request(http.MethodGet, p, "198.51.100.10:0")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if !reached {
				t.Errorf("public path %q: uiAuthMiddleware blocked it (status=%d, body=%s)",
					p, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestD0_NonPublicAPI_RejectsUnauth asserts that uiAuthMiddleware refuses
// to call the underlying handler for every sampled non-public /api/* path
// when no session cookie or Basic Auth is supplied. We use a sentinel
// handler so the assertion is unambiguous: if the sentinel runs, the
// middleware has leaked.
//
// A regression here means a previously gated /api/ route now leaks data
// to anonymous callers — the most dangerous class of UI bug.
func TestD0_NonPublicAPI_RejectsUnauth(t *testing.T) {
	d0EnableLocalAuth(t)

	for _, p := range d0NonPublicAPISample {
		t.Run(p, func(t *testing.T) {
			var reached bool
			sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			handler := uiAuthMiddleware(sentinel)
			req := d0Request(http.MethodGet, p, "198.51.100.11:0")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if reached {
				t.Errorf("non-public %q: uiAuthMiddleware leaked an unauthenticated request to the handler", p)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("non-public %q got %d, want 401", p, rec.Code)
			}
		})
	}
}
