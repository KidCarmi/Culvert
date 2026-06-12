package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"sort"
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
//   D0a (this file)              — route inventory locked at 133
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
	registerGovernanceRoutes(mux)
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

// d0KnownRoutes is the alphabetised inventory of every UI/admin route the
// admin server registers. It is DERIVED from uiRoutes (Phase C1 metadata
// table) so the metadata stays the single source of truth.
//
// Coverage history:
//
//   - Pre-C1 — d0KnownRoutes was a hand-maintained list (then 131
//     entries), mirroring the helpers. Coverage was one-directional: a
//     route added to a helper without updating the list was silently
//     missed.
//   - Post-C1 — d0KnownRoutes is derived from uiRoutes, and the
//     reverse-inventory gap is closed by
//     TestC1_RouteMetadata_Reverse_AllMuxRegistrationsHaveMetadata,
//     which AST-scans the helper sources and fails if any registered
//     path is absent from uiRoutes.
//
// Together with the C1 forward test, the bidirectional contract is:
//
//	uiRoutes  ⇔  every register*Routes helper's mux.HandleFunc calls
var d0KnownRoutes = func() []string {
	out := make([]string, 0, len(uiRoutes))
	seen := make(map[string]bool, len(uiRoutes))
	for _, r := range uiRoutes {
		if seen[r.Path] {
			continue // duplicates are flagged by TestC1_RouteMetadata_Locked135
		}
		seen[r.Path] = true
		out = append(out, r.Path)
	}
	sort.Strings(out)
	return out
}()

// TestD0_RouteInventory_Locked135 is the D0 regression lock for the
// admin-UI route surface. After Phase C1 it enforces two invariants
// against d0KnownRoutes (now derived from uiRoutes):
//
//  1. d0KnownRoutes contains exactly 135 entries (count locked).
//  2. Every entry resolves through the wired mux to a non-empty pattern.
//
// Count history:
//   - 131 — pre-C3 baseline (Phase C2/C2c).
//   - 132 — Phase C3 added /api/governance/control-plane.
//   - 133 — SAML SP metadata endpoint added for IdP import.
//   - 135 — Slice 8 added /api/authpolicy + /api/authpolicy/reorder.
//
// POST-C1 FAILURE MATRIX (the table below is the FULL contract; the
// reverse-direction gap that existed in pre-C1 D0 is now closed by
// TestC1_RouteMetadata_Reverse_AllMuxRegistrationsHaveMetadata):
//
//   - Add route to a helper but not to uiRoutes      → fails the C1
//     reverse test (registered route has no metadata entry).
//   - Add route to uiRoutes but not to a helper      → fails the C1
//     forward test AND this D0 test (path doesn't resolve in mux).
//   - Add route to BOTH helper AND uiRoutes           → fails this D0
//     test on count AND the C1 count test.
//   - Remove or rename a route in a helper           → fails the C1
//     forward test AND this D0 test.
//   - Remove an entry from uiRoutes only             → fails C1 reverse
//     (helper-registered route has no metadata) AND this D0 count test.
func TestD0_RouteInventory_Locked135(t *testing.T) {
	const want = 135
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
