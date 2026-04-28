package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ── D0 safety net ─────────────────────────────────────────────────────────
//
// D0 is the regression layer that locks current admin-UI behavior in place
// before Phase C (route metadata + middleware-driven RBAC) lands. None of
// these tests should ever require code changes when adding a new route —
// they only fail when an *existing* invariant breaks. See
// docs/UI_REFACTOR_AUDIT.md §6 (Phase D).
//
// Invariants covered:
//   D0a (this file)              — route inventory locked at 131
//   d0_auth_safety_test.go        — public stays public; non-public → 401
//   d0_rbac_safety_test.go        — admin-only handlers reject viewer+operator
//   d0_mutation_safety_test.go    — CSRF, body limit, rate limit on mutations
//
// All four files share the helpers below; do not duplicate them elsewhere.

// d0WireMux returns a fresh http.ServeMux populated by every register*Routes
// helper, exactly as startUI does. Used by D0 tests to exercise the route
// table without spinning up a live http.Server.
func d0WireMux(t *testing.T) *http.ServeMux {
	t.Helper()
	sub, _ := fs.Sub(staticFiles, "static")
	loadUIShell(sub)
	staticServer := http.FileServer(http.FS(sub))

	mux := http.NewServeMux()
	registerStaticRoutes(mux, staticServer)
	registerSetupRoutes(mux)
	registerAuthRoutes(mux)
	registerDashboardRoutes(mux)
	registerPolicyRoutes(mux)
	registerPACRoutes(mux)
	registerSecurityRoutes(mux)
	registerSettingsRoutes(mux)
	registerClusterRoutes(mux)
	registerUpdateRoutes(mux)
	registerCDRRoutes(mux)
	registerObservabilityRoutes(mux)
	return mux
}

// d0WrappedHandler returns the full middleware chain over the wired mux,
// matching startUI byte-for-byte:
//
//	uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(mux)))
func d0WrappedHandler(t *testing.T) http.Handler {
	t.Helper()
	return uiIPGuardMiddleware(securityMiddleware(uiAuthMiddleware(d0WireMux(t))))
}

// d0EnableLocalAuth enables local username/password auth for the duration of
// a test, then restores the prior state. Required because uiAuthMiddleware
// only enforces session checks when cfg.AuthEnabled() is true; otherwise it
// injects RoleAdmin and lets every request through.
func d0EnableLocalAuth(t *testing.T) {
	t.Helper()
	prevUser := cfg.GetUser()
	if err := cfg.SetAuth("d0_admin", "D0Passw0rd!"); err != nil {
		t.Fatalf("d0EnableLocalAuth: SetAuth failed: %v", err)
	}
	t.Cleanup(func() {
		_ = cfg.SetAuth(prevUser, "")
	})
}

// d0Request builds a bare request with a unique-per-test RemoteAddr so
// rate-limit state from one D0 test does not bleed into another.
func d0Request(method, path, remoteAddr string) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	r.RemoteAddr = remoteAddr
	return r
}

// d0KnownRoutes is the hand-maintained mirror of every UI/admin route
// registered across the 12 register*Routes helpers, sorted alphabetically
// for easy visual scan.
//
// IMPORTANT — coverage is one-directional. The companion test asserts
// that every entry here resolves in the wired mux, so a route REMOVED or
// RENAMED in a helper without updating this list will fail. A route
// ADDED to a helper without updating this list will NOT fail (count
// stays at 131). Closing that reverse-direction gap is a Phase C1 task:
// once the metadata table exists it can become the authoritative
// inventory source and the inventory check can become bidirectional.
var d0KnownRoutes = []string{
	"/",
	"/api/alerts/webhooks",
	"/api/alerts/webhooks/history",
	"/api/alerts/webhooks/test",
	"/api/audit",
	"/api/auth/change-password",
	"/api/auth/login",
	"/api/auth/logout",
	"/api/auth/status",
	"/api/auth/users",
	"/api/blocklist",
	"/api/blocklist/exceptions",
	"/api/blocklist/feed",
	"/api/blocklist/feed/sync",
	"/api/blocklist/mode",
	"/api/blockpage",
	"/api/ca-cert",
	"/api/ca/cache-clear",
	"/api/ca/download",
	"/api/ca/key-provider",
	"/api/ca/rotate",
	"/api/ca/status",
	"/api/category-groups",
	"/api/cdr/config",
	"/api/cdr/health",
	"/api/cdr/instances",
	"/api/cdr/instances/enroll",
	"/api/cdr/instances/revoke",
	"/api/cdr/policies",
	"/api/cdr/test",
	"/api/certs/upload",
	"/api/cluster/audit",
	"/api/cluster/bandwidth",
	"/api/cluster/bootstrap/",
	"/api/cluster/ca",
	"/api/cluster/drain",
	"/api/cluster/ha",
	"/api/cluster/labels",
	"/api/cluster/metrics",
	"/api/cluster/mode",
	"/api/cluster/node-groups",
	"/api/cluster/node-groups/membership",
	"/api/cluster/nodes",
	"/api/cluster/rate-limits",
	"/api/cluster/revocations",
	"/api/cluster/revoke",
	"/api/cluster/rotation",
	"/api/cluster/status",
	"/api/cluster/tokens",
	"/api/config/diff",
	"/api/config/export",
	"/api/config/import",
	"/api/config/versions",
	"/api/connlimit",
	"/api/content-scan",
	"/api/content-scan/bypass",
	"/api/country-traffic",
	"/api/dashboard/health",
	"/api/dashboard/threats",
	"/api/dashboard/top-rules",
	"/api/default-action",
	"/api/diagnostics",
	"/api/events",
	"/api/export",
	"/api/fileblock",
	"/api/fileblock/profiles",
	"/api/geoip",
	"/api/idp",
	"/api/idp/",
	"/api/idp/discover",
	"/api/logger",
	"/api/logs",
	"/api/metrics-config",
	"/api/ocsp",
	"/api/otlp",
	"/api/pac-config",
	"/api/policy",
	"/api/policy/move",
	"/api/policy/reorder",
	"/api/policy/test",
	"/api/rewrite",
	"/api/security",
	"/api/security-scan/cache",
	"/api/security-scan/exclusions",
	"/api/security-scan/feeds/domain-allowlist",
	"/api/security-scan/feeds/sync",
	"/api/security-scan/status",
	"/api/security-scan/svc",
	"/api/security-scan/yara/reload",
	"/api/security-scan/yara/rules",
	"/api/security-scan/yara/rules/",
	"/api/security-scan/yara/settings",
	"/api/security-scan/yara/validate",
	"/api/session-secret",
	"/api/session-timeout",
	"/api/settings",
	"/api/settings/log-level",
	"/api/settings/network",
	"/api/settings/unauth-mode",
	"/api/setup/complete",
	"/api/setup/status",
	"/api/ssl-bypass",
	"/api/stats",
	"/api/syslog",
	"/api/syslog/test",
	"/api/timeseries",
	"/api/top-hosts",
	"/api/ui-allow-ips",
	"/api/update/apply",
	"/api/update/check",
	"/api/update/cluster",
	"/api/update/cluster/status",
	"/api/update/preview",
	"/api/update/registry",
	"/api/update/reports",
	"/api/update/rollback",
	"/api/update/rollback/status",
	"/api/update/session",
	"/api/update/status",
	"/api/upstream",
	"/api/upstream/health",
	"/api/upstream/settings",
	"/api/urlcat",
	"/api/urlcat/host",
	"/api/urlcat/lookup",
	"/auth/logout",
	"/auth/oidc/callback",
	"/auth/saml/callback",
	"/auth/select",
	"/healthz",
	"/proxy.pac",
}

// TestD0_RouteInventory_Locked131 is the regression lock for the
// admin-UI route surface. It enforces two invariants:
//
//  1. d0KnownRoutes contains exactly 131 entries (count locked).
//  2. Every entry resolves through the wired mux to a non-empty pattern
//     (the helper actually registered it).
//
// FAILURE MATRIX (mirrored in d0KnownRoutes' docstring):
//
//   • Add route to a helper, list unchanged          → does NOT fail
//     (count stays 131; the new pattern is not checked). Closing this
//     reverse-direction gap is a Phase C1 deliverable.
//   • Add route to a helper AND to d0KnownRoutes     → fails invariant 1
//     (count goes to 132).
//   • Remove or rename a route in a helper           → fails invariant 2
//     (the now-orphaned list entry resolves to "" pattern).
//   • Remove an entry from d0KnownRoutes only        → fails invariant 1
//     (count goes to 130).
func TestD0_RouteInventory_Locked131(t *testing.T) {
	const want = 131
	if got := len(d0KnownRoutes); got != want {
		t.Fatalf("d0KnownRoutes has %d entries; want %d (route added or removed?)", got, want)
	}

	mux := d0WireMux(t)
	seen := make(map[string]bool, want)
	for _, p := range d0KnownRoutes {
		if seen[p] {
			t.Errorf("duplicate path in d0KnownRoutes: %q", p)
			continue
		}
		seen[p] = true

		req := httptest.NewRequest(http.MethodGet, p, http.NoBody)
		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Errorf("route %q: not registered by any register*Routes helper", p)
		}
	}
}
