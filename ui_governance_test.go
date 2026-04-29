package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// ── Phase C3 — Governance surface tests ───────────────────────────────────
//
// These tests pin the contract of /api/governance/control-plane:
//
//   - admin → 200 with a structurally-valid governanceSnapshot
//   - operator/viewer/anon → 403 (handler-level requireRole)
//   - non-GET → 405
//   - inventory counts agree with len(uiRoutes) and the per-method
//     totals computed from the metadata table
//   - C2 counters round-trip from the package atomics into the JSON
//     payload
//   - mode reporting follows c2Mode() and is honest about the kill
//     switch ("shadow" ⇒ kill_switch_active=true)
//   - the read path is side-effect-free: it does not bump any C2 counter
//   - top-level JSON keys are stable
//
// The tests reuse helpers from ui_metadata_enforcement_test.go
// (withC2Mode, c2Req) so they cannot drift from the rest of the C2/C2c
// suite.

// govReq builds a governance-endpoint request with the given role.
// Mirrors c2Req's role-injection pattern but defaults the path to
// /api/governance/control-plane.
func govReq(method string, role UIRole) *http.Request {
	return c2Req(method, "/api/governance/control-plane", role)
}

// decodeGovernance parses the response body into a generic map so the
// tests can assert the JSON contract without binding to the Go struct
// names. Field names are the on-the-wire contract for the SPA.
func decodeGovernance(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not valid JSON: %v; body=%s", err, w.Body.String())
	}
	return m
}

// TestApiGovernance_AdminGets200 — happy path: admin role gets 200 +
// a structurally-valid snapshot. Asserts the canonical top-level keys
// the SPA depends on.
func TestApiGovernance_AdminGets200(t *testing.T) {
	w := httptest.NewRecorder()
	apiGovernanceControlPlane(w, govReq(http.MethodGet, RoleAdmin))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	doc := decodeGovernance(t, w)

	for _, key := range []string{
		"schema_version", "generated_at", "routes",
		"c2", "counters", "governance_health", "test_layers",
	} {
		if _, ok := doc[key]; !ok {
			t.Errorf("response missing required top-level key %q", key)
		}
	}
	if v, _ := doc["schema_version"].(float64); int(v) != governanceSchemaVersion {
		t.Errorf("schema_version = %v, want %d", doc["schema_version"], governanceSchemaVersion)
	}
}

// TestApiGovernance_RBAC_AnonOperatorViewerDenied — non-admin roles
// (and the implicit RoleViewer-on-no-context default) must hit the
// handler-level requireRole(RoleAdmin) backstop and 403.
func TestApiGovernance_RBAC_AnonOperatorViewerDenied(t *testing.T) {
	cases := []struct {
		name string
		role UIRole
	}{
		{"viewer", RoleViewer},
		{"operator", RoleOperator},
		{"anon", UIRole("")}, // c2Req skips context injection when role is empty → uiRole() falls back to RoleViewer
		{"unknown", UIRole("none")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			apiGovernanceControlPlane(w, govReq(http.MethodGet, tc.role))
			if w.Code != http.StatusForbidden {
				t.Errorf("role=%s status = %d, want 403; body=%s", tc.role, w.Code, w.Body.String())
			}
		})
	}
}

// TestApiGovernance_MethodGate — the handler is GET-only. Any other
// method must produce 405 BEFORE the RBAC check (so a non-admin
// observing a stray POST gets the same answer the admin does — the
// route shape is not RBAC-sensitive).
func TestApiGovernance_MethodGate(t *testing.T) {
	for _, m := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead,
	} {
		t.Run(m, func(t *testing.T) {
			w := httptest.NewRecorder()
			apiGovernanceControlPlane(w, govReq(m, RoleAdmin))
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s status = %d, want 405", m, w.Code)
			}
		})
	}
}

// TestApiGovernance_NonAdminMutatingMethodsNoDisclosure — pins the
// belt-and-braces contract that a non-admin sending a non-GET method
// (which the route does not even support) cannot pry the snapshot
// out of the handler. The current implementation orders the method
// gate BEFORE requireRole, so the response is 405 rather than 403,
// but in either case the body must not contain any governance field
// names. If the handler order is ever swapped, this test still
// passes — it asserts denial AND non-disclosure, not a specific
// status code.
func TestApiGovernance_NonAdminMutatingMethodsNoDisclosure(t *testing.T) {
	leakyKeys := []string{
		"schema_version", "routes", "counters", "governance_health",
		"test_layers", "would_deny", "by_min_role",
	}
	for _, role := range []UIRole{RoleViewer, RoleOperator, UIRole("")} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(string(role)+"_"+method, func(t *testing.T) {
				w := httptest.NewRecorder()
				apiGovernanceControlPlane(w, govReq(method, role))
				if w.Code == http.StatusOK {
					t.Fatalf("role=%q method=%q got 200 — non-admin must NEVER receive the snapshot", role, method)
				}
				body := w.Body.String()
				for _, k := range leakyKeys {
					if strings.Contains(body, `"`+k+`"`) {
						t.Errorf("role=%q method=%q response body leaked key %q (status=%d, body=%s)", role, method, k, w.Code, body)
					}
				}
			})
		}
	}
}

// TestApiGovernance_InventoryConsistency — the route summary must
// agree with the metadata table on every derivable invariant. This
// catches drift between summariseRoutes and uiRoutes if the schema
// ever evolves.
func TestApiGovernance_InventoryConsistency(t *testing.T) {
	snap := buildGovernanceSnapshot()
	r := snap.Routes

	if r.Total != len(uiRoutes) {
		t.Errorf("routes.total = %d, want len(uiRoutes) = %d", r.Total, len(uiRoutes))
	}
	if r.Public+r.Protected != r.Total {
		t.Errorf("routes.public(%d) + routes.protected(%d) != routes.total(%d)", r.Public, r.Protected, r.Total)
	}

	// Recompute every aggregate from uiRoutes and cross-check.
	var (
		wantPublic, wantMethodAnyRoutes, wantMethodEntries int
		wantMutating, wantAuditExpected, wantMethodAny     int
		wantByRole                                         = map[string]governanceRoleAgg{}
		wantByDomain                                       = map[string]int{}
		wantDomainMethods                                  = map[string]int{}
	)
	for i := range uiRoutes {
		ru := uiRoutes[i]
		if ru.Public {
			wantPublic++
		}
		hasAny := false
		for _, m := range ru.Methods {
			wantMethodEntries++
			if m.Method == MethodAny {
				hasAny = true
				wantMethodAny++
			}
			if m.Mutating {
				wantMutating++
			}
			if m.AuditExpected {
				wantAuditExpected++
			}
			key := string(m.MinRole)
			agg := wantByRole[key]
			agg.Methods++
			if m.Mutating {
				agg.Mutating++
			}
			if m.AuditExpected {
				agg.AuditExpected++
			}
			wantByRole[key] = agg
		}
		if hasAny {
			wantMethodAnyRoutes++
		}
		wantByDomain[ru.Domain]++
		wantDomainMethods[ru.Domain] += len(ru.Methods)
	}

	if r.Public != wantPublic {
		t.Errorf("routes.public = %d, want %d", r.Public, wantPublic)
	}
	if r.MethodAnyRoutes != wantMethodAnyRoutes {
		t.Errorf("routes.method_any_routes = %d, want %d", r.MethodAnyRoutes, wantMethodAnyRoutes)
	}
	if r.MethodEntries != wantMethodEntries {
		t.Errorf("routes.method_entries = %d, want %d", r.MethodEntries, wantMethodEntries)
	}
	if r.Totals.Mutating != wantMutating {
		t.Errorf("totals.mutating = %d, want %d", r.Totals.Mutating, wantMutating)
	}
	if r.Totals.AuditExpected != wantAuditExpected {
		t.Errorf("totals.audit_expected = %d, want %d", r.Totals.AuditExpected, wantAuditExpected)
	}
	if r.Totals.MethodAny != wantMethodAny {
		t.Errorf("totals.method_any = %d, want %d", r.Totals.MethodAny, wantMethodAny)
	}

	// Sum of per-role method counts must equal MethodEntries.
	var sumMethods, sumMutating, sumAudit int
	for _, a := range r.ByMinRole {
		sumMethods += a.Methods
		sumMutating += a.Mutating
		sumAudit += a.AuditExpected
	}
	if sumMethods != r.MethodEntries {
		t.Errorf("sum(by_min_role.methods) = %d, want method_entries = %d", sumMethods, r.MethodEntries)
	}
	if sumMutating != r.Totals.Mutating {
		t.Errorf("sum(by_min_role.mutating) = %d, want totals.mutating = %d", sumMutating, r.Totals.Mutating)
	}
	if sumAudit != r.Totals.AuditExpected {
		t.Errorf("sum(by_min_role.audit_expected) = %d, want totals.audit_expected = %d", sumAudit, r.Totals.AuditExpected)
	}
	for role, want := range wantByRole {
		got, ok := r.ByMinRole[role]
		if !ok {
			t.Errorf("by_min_role missing role %q", role)
			continue
		}
		if got != want {
			t.Errorf("by_min_role[%q] = %+v, want %+v", role, got, want)
		}
	}

	// Per-domain breakdown: alphabetised, totals match.
	prev := ""
	for _, d := range r.ByDomain {
		if prev != "" && d.Domain < prev {
			t.Errorf("by_domain not alphabetised: saw %q after %q", d.Domain, prev)
		}
		prev = d.Domain
		if d.Routes != wantByDomain[d.Domain] {
			t.Errorf("by_domain[%q].routes = %d, want %d", d.Domain, d.Routes, wantByDomain[d.Domain])
		}
		if d.Methods != wantDomainMethods[d.Domain] {
			t.Errorf("by_domain[%q].methods = %d, want %d", d.Domain, d.Methods, wantDomainMethods[d.Domain])
		}
	}

	// The governance domain must be present after C3.
	found := false
	for _, d := range r.ByDomain {
		if d.Domain == "governance" {
			found = true
			break
		}
	}
	if !found {
		t.Error("by_domain has no entry for the new C3 domain 'governance'")
	}
}

// TestApiGovernance_CountersRoundTrip — bump every C2 counter via the
// package atomics, build a snapshot, confirm the JSON payload reflects
// the bump. Uses diffs (before/after) so concurrent counter activity
// in the test process cannot affect the result.
func TestApiGovernance_CountersRoundTrip(t *testing.T) {
	before := c2CounterSnapshot()
	c2ShadowWouldDenyTotal.Add(3)
	c2EnforceDeniedTotal.Add(2)
	c2ShadowMissingMetaTotal.Add(1)
	c2ShadowNoPolicyTotal.Add(4)
	c2AuditMissingTotal.Add(5)
	t.Cleanup(func() {
		// Restore atomics so other tests see the pre-test baseline.
		c2ShadowWouldDenyTotal.Store(before.WouldDeny)
		c2EnforceDeniedTotal.Store(before.EnforceDenied)
		c2ShadowMissingMetaTotal.Store(before.MissingMeta)
		c2ShadowNoPolicyTotal.Store(before.NoPolicy)
		c2AuditMissingTotal.Store(before.AuditMissing)
	})

	snap := buildGovernanceSnapshot()
	if got, want := snap.Counters.WouldDeny-before.WouldDeny, int64(3); got != want {
		t.Errorf("would_deny delta = %d, want %d", got, want)
	}
	if got, want := snap.Counters.EnforceDenied-before.EnforceDenied, int64(2); got != want {
		t.Errorf("enforce_denied delta = %d, want %d", got, want)
	}
	if got, want := snap.Counters.MissingMeta-before.MissingMeta, int64(1); got != want {
		t.Errorf("missing_meta delta = %d, want %d", got, want)
	}
	if got, want := snap.Counters.NoPolicy-before.NoPolicy, int64(4); got != want {
		t.Errorf("no_policy delta = %d, want %d", got, want)
	}
	if got, want := snap.Counters.AuditMissing-before.AuditMissing, int64(5); got != want {
		t.Errorf("audit_missing delta = %d, want %d", got, want)
	}
}

// TestApiGovernance_ModeReporting — c2.mode must follow c2Mode(), and
// kill_switch_active must be true exactly when mode is shadow.
func TestApiGovernance_ModeReporting(t *testing.T) {
	t.Run("enforce", func(t *testing.T) {
		withC2Mode(t, c2ModeEnforce)
		snap := buildGovernanceSnapshot()
		if snap.C2.Mode != c2ModeEnforce {
			t.Errorf("mode = %q, want %q", snap.C2.Mode, c2ModeEnforce)
		}
		if snap.C2.KillSwitchActive {
			t.Error("kill_switch_active = true while mode = enforce")
		}
		if snap.C2.DefaultMode != c2ModeEnforce {
			t.Errorf("default_mode = %q, want %q", snap.C2.DefaultMode, c2ModeEnforce)
		}
		if snap.C2.KillSwitchEnv != c2EnforceEnvVar {
			t.Errorf("kill_switch_env = %q, want %q", snap.C2.KillSwitchEnv, c2EnforceEnvVar)
		}
		if !snap.C2.ReadOnceAtStartup {
			t.Error("read_once_at_startup = false; documents non-runtime mutability")
		}
	})
	t.Run("shadow", func(t *testing.T) {
		withC2Mode(t, c2ModeShadow)
		snap := buildGovernanceSnapshot()
		if snap.C2.Mode != c2ModeShadow {
			t.Errorf("mode = %q, want %q", snap.C2.Mode, c2ModeShadow)
		}
		if !snap.C2.KillSwitchActive {
			t.Error("kill_switch_active = false while mode = shadow")
		}
	})
}

// TestApiGovernance_NoSideEffects — the read path must not bump any
// C2 counter. We hit the endpoint multiple times and assert every
// counter is unchanged.
func TestApiGovernance_NoSideEffects(t *testing.T) {
	before := c2CounterSnapshot()
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		apiGovernanceControlPlane(w, govReq(http.MethodGet, RoleAdmin))
		if w.Code != http.StatusOK {
			t.Fatalf("iter %d: status = %d", i, w.Code)
		}
	}
	after := c2CounterSnapshot()
	if before != after {
		t.Errorf("counters mutated by read path: before=%+v after=%+v", before, after)
	}
}

// TestApiGovernance_HealthDerivation pins the rules in
// deriveGovernanceHealth so SPA logic can rely on them. Table-driven:
// counter combinations × mode → expected status + axis values + issue
// codes.
func TestApiGovernance_HealthDerivation(t *testing.T) {
	cases := []struct {
		name           string
		counters       governanceCounters
		mode           string
		wantStatus     string
		wantParity     string
		wantAudit      string
		wantEnforce    string
		wantIssueCodes []string
	}{
		{
			name:        "all-zero-enforce",
			counters:    governanceCounters{},
			mode:        c2ModeEnforce,
			wantStatus:  statusHealthy,
			wantParity:  healthOK,
			wantAudit:   healthOK,
			wantEnforce: healthOK,
		},
		{
			name:        "all-zero-shadow",
			counters:    governanceCounters{},
			mode:        c2ModeShadow,
			wantStatus:  statusHealthy,
			wantParity:  healthOK,
			wantAudit:   healthOK,
			wantEnforce: healthOK,
		},
		{
			name:           "audit-missing-only",
			counters:       governanceCounters{AuditMissing: 2},
			mode:           c2ModeEnforce,
			wantStatus:     statusWarn,
			wantParity:     healthOK,
			wantAudit:      healthWarn,
			wantEnforce:    healthOK,
			wantIssueCodes: []string{"audit_missing_nonzero"},
		},
		{
			name:           "missing-meta-drift",
			counters:       governanceCounters{MissingMeta: 1},
			mode:           c2ModeEnforce,
			wantStatus:     statusDrift,
			wantParity:     healthDrift,
			wantAudit:      healthOK,
			wantEnforce:    healthOK,
			wantIssueCodes: []string{"missing_metadata_nonzero"},
		},
		{
			// C3.1 severity tweak: no_policy alone is now warn, not drift.
			// Rationale: the counter can be triggered by a client sending
			// a method the route does not accept (PATCH against a GET-only
			// route, scanner probes, etc.) on a route that IS in metadata.
			// Drift is reserved for genuine governance/config anomalies
			// (missing_meta, enforce_denied-in-shadow).
			name:           "no-policy-warn",
			counters:       governanceCounters{NoPolicy: 1},
			mode:           c2ModeEnforce,
			wantStatus:     statusWarn,
			wantParity:     healthWarn,
			wantAudit:      healthOK,
			wantEnforce:    healthOK,
			wantIssueCodes: []string{"no_method_policy_nonzero"},
		},
		{
			// missing_meta + no_policy: drift wins on metadata_parity
			// (drift > warn) and the overall status is drift.
			name:           "missing-meta-plus-no-policy-drift",
			counters:       governanceCounters{MissingMeta: 1, NoPolicy: 1},
			mode:           c2ModeEnforce,
			wantStatus:     statusDrift,
			wantParity:     healthDrift,
			wantAudit:      healthOK,
			wantEnforce:    healthOK,
			wantIssueCodes: []string{"missing_metadata_nonzero", "no_method_policy_nonzero"},
		},
		{
			// no_policy + audit_missing: both are warn-tier, status warn.
			name:           "no-policy-plus-audit-missing-warn",
			counters:       governanceCounters{NoPolicy: 2, AuditMissing: 3},
			mode:           c2ModeEnforce,
			wantStatus:     statusWarn,
			wantParity:     healthWarn,
			wantAudit:      healthWarn,
			wantEnforce:    healthOK,
			wantIssueCodes: []string{"no_method_policy_nonzero", "audit_missing_nonzero"},
		},
		{
			name:           "enforce-denied-in-shadow",
			counters:       governanceCounters{EnforceDenied: 1},
			mode:           c2ModeShadow,
			wantStatus:     statusDrift,
			wantParity:     healthOK,
			wantAudit:      healthOK,
			wantEnforce:    healthDrift,
			wantIssueCodes: []string{"enforce_denied_in_shadow"},
		},
		{
			name:        "enforce-denied-in-enforce-is-fine",
			counters:    governanceCounters{EnforceDenied: 9, WouldDeny: 9},
			mode:        c2ModeEnforce,
			wantStatus:  statusHealthy,
			wantParity:  healthOK,
			wantAudit:   healthOK,
			wantEnforce: healthOK,
		},
		{
			name:           "drift-trumps-warn",
			counters:       governanceCounters{MissingMeta: 1, AuditMissing: 1},
			mode:           c2ModeEnforce,
			wantStatus:     statusDrift,
			wantParity:     healthDrift,
			wantAudit:      healthWarn,
			wantEnforce:    healthOK,
			wantIssueCodes: []string{"missing_metadata_nonzero", "audit_missing_nonzero"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := deriveGovernanceHealth(tc.counters, tc.mode)
			if h.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", h.Status, tc.wantStatus)
			}
			if h.MetadataParity != tc.wantParity {
				t.Errorf("metadata_parity = %q, want %q", h.MetadataParity, tc.wantParity)
			}
			if h.AuditCompletion != tc.wantAudit {
				t.Errorf("audit_completion = %q, want %q", h.AuditCompletion, tc.wantAudit)
			}
			if h.EnforceConsistency != tc.wantEnforce {
				t.Errorf("enforce_consistency = %q, want %q", h.EnforceConsistency, tc.wantEnforce)
			}
			gotCodes := make([]string, 0, len(h.Issues))
			for _, i := range h.Issues {
				gotCodes = append(gotCodes, i.Code)
			}
			sort.Strings(gotCodes)
			want := append([]string(nil), tc.wantIssueCodes...)
			sort.Strings(want)
			if strings.Join(gotCodes, ",") != strings.Join(want, ",") {
				t.Errorf("issue codes = %v, want %v", gotCodes, want)
			}
		})
	}
}

// TestApiGovernance_TestLayerCatalogIsHonest — the test_layers slice
// must label C2/C2c as runtime and D0/C1/C1.5 as CI-only. The
// governance endpoint is forbidden from claiming to re-execute parity
// scanners at request time (per CLAUDE.md / scope).
func TestApiGovernance_TestLayerCatalogIsHonest(t *testing.T) {
	withC2Mode(t, c2ModeEnforce)
	layers := governanceTestLayerCatalog(c2Mode())
	want := map[string]bool{ // id → runtime
		"D0": false, "C1": false, "C1.5": false,
		"C2": true, "C2c": true,
	}
	if len(layers) != len(want) {
		t.Errorf("got %d layers, want %d", len(layers), len(want))
	}
	for _, l := range layers {
		got, ok := want[l.ID]
		if !ok {
			t.Errorf("unexpected layer id %q", l.ID)
			continue
		}
		if l.Runtime != got {
			t.Errorf("layer %q runtime = %v, want %v", l.ID, l.Runtime, got)
		}
		if l.ID == "C2" && l.Mode != c2Mode() {
			t.Errorf("C2 layer mode = %q, want %q", l.Mode, c2Mode())
		}
	}
}

// TestApiGovernance_JSONSchemaStability is a contract check for the
// SPA: the named keys at each level of the response must remain
// stable. Renaming a field is a breaking change and should bump
// schema_version.
func TestApiGovernance_JSONSchemaStability(t *testing.T) {
	w := httptest.NewRecorder()
	apiGovernanceControlPlane(w, govReq(http.MethodGet, RoleAdmin))
	doc := decodeGovernance(t, w)

	mustHave := func(parent map[string]any, keys []string, prefix string) {
		t.Helper()
		for _, k := range keys {
			if _, ok := parent[k]; !ok {
				t.Errorf("%s.%s missing", prefix, k)
			}
		}
	}
	mustHave(doc, []string{"schema_version", "generated_at", "routes", "c2", "counters", "governance_health", "test_layers"}, "$")

	if routes, ok := doc["routes"].(map[string]any); ok {
		mustHave(routes, []string{
			"total", "public", "protected", "method_any_routes",
			"method_entries", "by_min_role", "totals", "by_domain",
		}, "routes")
	} else {
		t.Error("routes is not an object")
	}
	if c2, ok := doc["c2"].(map[string]any); ok {
		mustHave(c2, []string{"mode", "default_mode", "kill_switch_env", "kill_switch_active", "read_once_at_startup"}, "c2")
	} else {
		t.Error("c2 is not an object")
	}
	if ctr, ok := doc["counters"].(map[string]any); ok {
		mustHave(ctr, []string{"would_deny", "enforce_denied", "missing_meta", "no_policy", "audit_missing"}, "counters")
	} else {
		t.Error("counters is not an object")
	}
	if h, ok := doc["governance_health"].(map[string]any); ok {
		mustHave(h, []string{"status", "metadata_parity", "audit_completion", "enforce_consistency", "issues"}, "governance_health")
	} else {
		t.Error("governance_health is not an object")
	}
}
