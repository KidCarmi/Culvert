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
//   D0a (this file)              — route inventory locked (see `const want`)
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
	registerCDRRoutes(mux)
	registerObservabilityRoutes(mux)
	registerGovernanceRoutes(mux)
	registerReleaseRoutes(mux)
	registerSupportRoutes(mux)
	registerBackupsRoutes(mux)
	registerDiagnoseRoutes(mux)
	registerMCPRoutes(mux)
	registerPolicyLearningRoutes(mux)
	registerFrontendV2Routes(mux)
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
			continue // duplicates are flagged by TestC1_RouteMetadata_Locked141
		}
		seen[r.Path] = true
		out = append(out, r.Path)
	}
	sort.Strings(out)
	return out
}()

// TestD0_RouteInventory_Locked141 is the D0 regression lock for the
// admin-UI route surface. After Phase C1 it enforces two invariants
// against d0KnownRoutes (now derived from uiRoutes):
//
//  1. d0KnownRoutes contains exactly 142 entries (count locked; see `want` below
//     and the Count history — the function name is a stable identifier kept across
//     count bumps, the `const want` is the live lock).
//  2. Every entry resolves through the wired mux to a non-empty pattern.
//
// Count history:
//   - 131 — pre-C3 baseline (Phase C2/C2c).
//   - 132 — Phase C3 added /api/governance/control-plane.
//   - 133 — SAML SP metadata endpoint added for IdP import.
//   - 135 — Slice 8 added /api/authpolicy + /api/authpolicy/reorder.
//   - 136 — Live Feed added its history/retention route.
//   - 141 — P1.6d-0 added 5 /api/releases* dispatch-management routes.
//   - 142 — Live Feed added /api/logs/purge.
//   - 143 — Catalog refresh added /api/releases/catalog-refresh.
//   - 144 — ADR-0004 Slice 1e added /api/cluster/ha/promote (manual failover).
//   - 145 — Terminology governance: added canonical /api/settings/default-auth-outcome
//     alongside the retained legacy /api/settings/unauth-mode alias.
//   - 146 — Added /api/auth/lockouts (list + admin-unlock active login lockouts).
//   - 135 — Legacy updater removal: dropped the 11 /api/update/* routes
//     (status/check/apply/preview/reports/rollback/rollback-status/session/
//     cluster/cluster-status/registry) from the 146 baseline. Updates flow
//     through Release Management.
//   - 136 — policy-refs P0 added /api/objects/references (generic Where-Used
//     dependency walk backing the fail-open delete guards).
//   - 137 — Decryption Profiles added /api/decryption-profiles (named
//     "how to decrypt" object referenced per policy rule).
//   - 138 — Adaptive decryption exclusion added /api/decryption-exclusions
//     (read-only list + evict/clear of the volatile fail-open learn cache).
//   - 142 — F10 added /api/decryption-exclusions/tunables (GET defaults+bounds /
//     PUT admin runtime tunables for the auto-exclusion cache).
//   - 140 — Terminology governance T-10: added canonical /api/dpi and
//     /api/dpi/bypass alongside the retained legacy /api/content-scan and
//     /api/content-scan/bypass aliases (same handlers).
//   - +20 — TAC support framework (M1-M5) added: support status/bundles/
//     {id}(+report,+approve)/health-explain (+6); support/debug-level (+1);
//     diagnose/storage, diagnose/upstream, diagnose/dns, diagnose/tls,
//     diagnose/cluster, diagnose/config, diagnose/all (+7); bundles/{id}/validate (+1);
//     bundles/{id}/download-encrypted (+1); bundles/{id}/download-sealed (+1);
//     bundles/{id}/exports (+1 — per-bundle export/exfil history);
//     support/recipients (+1) + recipients/{name} (+1) — sealing-recipient registry.
//   - 164 — ADR-0011 P2 added /api/decryption/health (read-only decryption
//     coverage + failure-taxonomy aggregate; viewer).
//   - 166 — reconcile parallel-merge drift (support exports + decryption/health
//     both bumped 163→164) and add /api/support/bundles/{id}/manifest (read-only
//     manifest metadata view without downloading the tarball; viewer).
//   - 177 — catch up to main (PAC steering/exception + PEI-P2 governance routes,
//     176) + ADR-0011 §4 added /api/decryption/redaction (host/SNI redaction
//     toggle; GET viewer / PUT admin).
//   - 178 — reconcile parallel-merge drift: Supportability M5 added
//     /api/diagnose/support (bundle-store health self-check) but its lock bump
//     collided with the /api/decryption/redaction merge; the true count is 178.
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
func TestD0_RouteInventory_Locked141(t *testing.T) {
	const want = 241 // 240 (the 2E-C trust-lifecycle-era branch baseline: 238 (the 2E-C-era baseline: 237 (the 2E-B-era baseline: 222 incl. the 3 ADR-0027 LDAP IdP routes + 6 /api/policy-learning/* + 1 /api/backups + 3 FrontendV2 preview routes + 1 /api/urlcat/state + 2 ADR-0034 tool-trust routes + 2 2D-C v2 state reads) + 1 Canary-activation-gate route (/api/mcp/canary/shadow-exit-review — Shadow Exit Review attestation)) + 2 2E-C trust-lifecycle routes (/api/cdr/instances/enroll/recover + /api/cdr/instances/enroll/receipts)) + 1 authoritative rollback rehearsal route merged from main (/api/mcp/rollout/rehearse-rollback-authoritative)
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
