package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// ── Phase C1: metadata-table regression tests (SHADOW MODE) ───────────────
//
// The three TestC1_RouteMetadata_* tests below establish the metadata
// table in uiRoutes as the authoritative inventory source for the admin
// UI. They close the reverse-direction gap that D0's d0KnownRoutes
// could not check (helper-only additions were silent in D0).
//
// All three tests are SHADOW: they verify intent matches the wired mux.
// They do NOT enforce MinRole / Mutating / AuditExpected / Public
// classification at runtime — those are still hand-coded in
// uiAuthMiddleware and per-handler requireRole calls. Phase C2 will
// flip the enforcement switch.

// TestC1_RouteMetadata_Locked141 enforces two structural invariants on
// the uiRoutes table itself:
//
//  1. Length is exactly 141 entries.
//  2. Every Path appears at most once (no accidental duplicates).
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
//   - 144 — ADR-0004 Slice 1e added /api/cluster/ha/promote.
//   - 145 — Terminology governance: added canonical /api/settings/default-auth-outcome
//     alongside the retained legacy /api/settings/unauth-mode alias.
//   - 146 — Added /api/auth/lockouts (list + admin-unlock active login lockouts).
//   - 135 — Legacy updater removal: dropped the 11 /api/update/* routes from the 146 baseline.
//   - 136 — policy-refs P0 added /api/objects/references (Where-Used dependency walk).
//   - 137 — Decryption Profiles added /api/decryption-profiles.
//   - 138 — Adaptive decryption exclusion added /api/decryption-exclusions
//     (read-only list + evict/clear of the volatile fail-open learn cache).
//   - 141 — policy-draft (G2) added /api/policy/draft (+commit +revert):
//     candidate/commit for the rulebase.
//   - 140 — Terminology governance T-10: added canonical /api/dpi and
//     /api/dpi/bypass alongside the retained legacy /api/content-scan and
//     /api/content-scan/bypass aliases (same handlers).
//   - 140 — Supportability M1 Slice 1 added /api/support/bundles (POST create)
//   - /api/support/bundles/{id} (GET download).
//   - 142 — Supportability M1 added /api/support/status + /api/health/explain
//     (the explained operator-contract health verdict).
//   - +N — Supportability M2-M4 added the rest of the TAC support-framework
//     surface (bundle report/approve, debug-level, diagnose/{storage,upstream,
//     dns,tls}, bundle validate + download-encrypted, and related routes); see
//     `const want` below for the current authoritative total.
//   - 164 — ADR-0011 P2 added /api/decryption/health (read-only decryption
//     coverage + failure-taxonomy aggregate; viewer).
//   - 173 — PAC Traffic Steering PR2+PR3 integration: +7 routes over main's 166
//     (/pac/ per-profile PAC file; /api/pac/profiles, /profiles/, /pools,
//     /pools/, /simulate, /analyze).
//   - 174 — PAC Exception Intelligence P0 added /api/pac/posture/inventory
//     (read-only config-derived DIRECT full-bypass inventory; viewer).
//   - 176 — PAC Exception Intelligence P2 added /api/pac/posture/exceptions
//     (governance list; viewer) + /api/pac/posture/exceptions/ (item: viewer
//     GET, admin PUT/DELETE).
//   - 177 — ADR-0011 §4 added /api/decryption/redaction (GET viewer / PUT admin
//     host/SNI redaction toggle).
//   - 178 — reconcile parallel-merge drift: /api/diagnose/support (M5, #834) and
//     /api/decryption/redaction landed together; both carry metadata (parity
//     green) but the const bump for one was overwritten, leaving actual=178 and
//     the lock at 177 (main's Fast Gate was red on this). Bumped to match.
//   - 180 — PAC Exception Intelligence P3 added /api/pac/posture/diff (read-only
//     candidate DIRECT change-diff; viewer POST), on top of main's 179.
//   - 181 — M5 supportability added /api/diagnose/etcd (bounded read-only HA
//     fencing-lease reachability probe; operator POST).
//   - 182 — T3 P1 added /api/cluster/convergence (read-only config-sync fleet
//     convergence / straggler view; viewer).
//   - 183 — M6 secure-upload PR-1 added /api/support/upload/config (node-local
//     default-off upload posture; GET viewer / PUT admin; no egress).
//   - 184 — M6 secure-upload PR-4 added /api/support/tac-trust (read-only resolved
//     TAC recipient trust set for encrypt-to-TAC; GET viewer; no egress).
//   - 186 — M6 secure-upload PR-5 added /api/support/uploads (GET viewer: upload
//     queue list) and /api/support/bundles/{id}/upload (GET viewer status+receipt /
//     POST admin per-bundle upload consent → seal + enqueue).
//   - 187 — M7 Slice 1 added /api/support/telemetry/preview (GET admin: read-only
//     preview of the current support-telemetry sample; no consent, sender, or
//     egress exists yet).
//   - 188 — M7 Slice 2 added /api/support/telemetry/config (GET viewer / PUT
//     admin: node-local telemetry consent + bearer-auth config; still zero
//     egress — no sender exists yet).
//   - 189 — Added /api/urlcat/feed-status (GET viewer: UT1 + SaaS category
//     feed freshness/failure counts, previously Prometheus-only).
func TestC1_RouteMetadata_Locked141(t *testing.T) {
	const want = 243 // 241 (240 (the 2E-C trust-lifecycle-era branch baseline: 238 (the 2E-C-era baseline: 237 (the 2E-B-era baseline: 222 incl. the 3 ADR-0027 LDAP IdP routes + 6 /api/policy-learning/* + 1 /api/backups + 3 FrontendV2 preview routes + 1 /api/urlcat/state + 2 ADR-0034 tool-trust routes + 2 2D-C v2 state reads) + 1 Canary-activation-gate route (/api/mcp/canary/shadow-exit-review — Shadow Exit Review attestation)) + 2 2E-C trust-lifecycle routes (/api/cdr/instances/enroll/recover + /api/cdr/instances/enroll/receipts)) + 1 authoritative rollback rehearsal route merged from main (/api/mcp/rollout/rehearse-rollback-authoritative)) + 2 2F-C Upstream v2 routes (/api/upstream/entries + /api/upstream/entries/)
	if got := len(uiRoutes); got != want {
		t.Fatalf("uiRoutes has %d entries; want %d (route added or removed?)", got, want)
	}
	seen := make(map[string]int, want)
	for i, r := range uiRoutes {
		if prev, dup := seen[r.Path]; dup {
			t.Errorf("duplicate path %q at indices %d and %d", r.Path, prev, i)
		}
		seen[r.Path] = i

		// Sanity: required fields are non-empty so tooling can rely on them.
		if r.Path == "" {
			t.Errorf("uiRoutes[%d]: empty Path", i)
		}
		if r.Handler == "" {
			t.Errorf("uiRoutes[%d] (path=%q): empty Handler", i, r.Path)
		}
		if r.Domain == "" {
			t.Errorf("uiRoutes[%d] (path=%q): empty Domain", i, r.Path)
		}
	}
}

// TestC1_RouteMetadata_Forward_AllMetadataResolvesInMux is the forward
// inventory check: every entry in uiRoutes must resolve to a non-empty
// pattern in the wired mux. A failure here means the metadata table
// declares a route the helper layer no longer registers (e.g. a
// rename/removal that wasn't mirrored to metadata).
func TestC1_RouteMetadata_Forward_AllMetadataResolvesInMux(t *testing.T) {
	mux := d0WireMux(t)
	for _, r := range uiRoutes {
		req := httptest.NewRequest(http.MethodGet, r.Path, http.NoBody)
		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Errorf("metadata route %q (Handler=%s, Domain=%s): not registered by any register*Routes helper",
				r.Path, r.Handler, r.Domain)
		}
	}
}

// TestC1_RouteMetadata_Reverse_AllMuxRegistrationsHaveMetadata closes the
// D0 gap. http.ServeMux does not expose its registered patterns, so we
// discover them by AST-style source inspection of the helper files: any
// `mux.HandleFunc("path", handler)` line in a register*Routes function
// is one registered route. Every such path must appear in uiRoutes.
//
// Failure means a helper registered a route that the metadata table
// does not know about — the previously-silent class of regression.
func TestC1_RouteMetadata_Reverse_AllMuxRegistrationsHaveMetadata(t *testing.T) {
	registered, err := scanRegisteredRoutes()
	if err != nil {
		t.Fatalf("scanRegisteredRoutes: %v", err)
	}
	if len(registered) == 0 {
		t.Fatalf("scanRegisteredRoutes returned 0 entries — source-inspection regex broken?")
	}

	meta := make(map[string]uiRouteMetadata, len(uiRoutes))
	for _, r := range uiRoutes {
		meta[r.Path] = r
	}

	var missing []string
	for path := range registered {
		if _, ok := meta[path]; !ok {
			missing = append(missing, path)
		}
	}
	sort.Strings(missing)
	for _, p := range missing {
		t.Errorf("registered route %q (in %s) has no entry in uiRoutes", p, registered[p])
	}

	// Sanity: registered count should equal metadata count. If they differ
	// without a missing-from-metadata error firing, the forward test will
	// catch it; this is the defence-in-depth check.
	if len(registered) != len(uiRoutes) {
		t.Errorf("registered %d routes vs uiRoutes %d — counts diverge",
			len(registered), len(uiRoutes))
	}
}

// muxHandleFuncRE matches `mux.HandleFunc("path", ...)` calls. Any
// register*Routes helper uses the local variable `mux` for the
// http.ServeMux instance, and only register helpers contain this
// pattern (verified via grep — startUI no longer holds any
// mux.HandleFunc calls after Phase B2, and the scan_svc.go usage is on
// a separately-named mux variable inside ScanService.Start).
var muxHandleFuncRE = regexp.MustCompile(`mux\.HandleFunc\("([^"]+)"`)

// helperSourceFiles enumerates the files that own register*Routes
// helpers. Keep this list in sync with the helper homes documented in
// docs/UI_REFACTOR_AUDIT.md and used by d0WireMux.
var helperSourceFiles = []string{
	"ui_static.go",
	"ui_auth.go",
	"ui_config.go",
	"ui_policy.go",
	"pac.go",
	"ui_security.go",
	"ui_cluster.go",
	"cdr_ui.go",
	"diagnostics.go",
	"ui_governance.go",
	"release_api.go",
	"ui_support.go",
	"backups_api.go",
	"diagnose.go",
	"ui_mcp.go",
	"ui_policy_learning.go",
	"ui_frontend_v2.go",
}

// scanRegisteredRoutes returns every route path registered by a
// register*Routes helper, mapped to the file it was found in. The map
// key is the path; the value is the source filename so test failures
// point at the offender. Returns an error if any source file cannot
// be read.
func scanRegisteredRoutes() (map[string]string, error) {
	out := make(map[string]string)
	for _, name := range helperSourceFiles {
		// Absolute path anchored to the package source dir — NOT CWD — so a
		// concurrent test's os.Chdir cannot make this scan read a wrong/partial
		// file set (the CWD-race flake that intermittently breaks C1 reverse parity).
		data, err := os.ReadFile(filepath.Join(pkgSourceDir(), name))
		if err != nil {
			return nil, err
		}
		for _, m := range muxHandleFuncRE.FindAllSubmatch(data, -1) {
			path := string(m[1])
			if existing, dup := out[path]; dup {
				return nil, &duplicateRegistrationError{path: path, first: existing, second: name}
			}
			out[path] = name
		}
	}
	return out, nil
}

type duplicateRegistrationError struct {
	path          string
	first, second string
}

func (e *duplicateRegistrationError) Error() string {
	return "route " + e.path + " registered in both " + e.first + " and " + e.second
}
