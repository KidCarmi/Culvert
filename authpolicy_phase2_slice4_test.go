package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Phase 2 Slice 4 — expose CredentialRequired (CR) in the EXISTING Auth Policy
// API / UI / Simulator / Diagnostics surface. No new routes, no RBAC change, no
// runtime behavior change: the backend already validates/persists/simulates/
// diagnoses CR (Slices 1–3); this slice surfaces it in the GUI. proxy.go and
// socks5.go are untouched (enforced by the D0/C1/C1.5/C2 suites + the route pin
// below). The only non-test change is static/index.html plus a comment-only
// refresh in ui_authpolicy.go.

// ── API: /api/authpolicy accepts CredentialRequired ──────────────────────────

func TestP2S4_API_AcceptsCredentialRequired(t *testing.T) {
	withFreshPolicyStore(t)
	withConfigVersionsDir(t)

	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", crRuleMap("p2s4-cr")))
	if w.Code != 200 {
		t.Fatalf("admin POST CR = %d: %s", w.Code, w.Body.String())
	}
	var created authRuleView
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	if created.Auth == nil || created.Auth.Outcome != OutcomeCredentialRequired {
		t.Fatalf("created CR rule malformed: %+v", created)
	}
	mustFindAudit(t, "authpolicy.add", "p2s4-cr")

	// GET lists it with the CredentialRequired outcome.
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleViewer, "GET", "/api/authpolicy", nil))
	if w.Code != 200 {
		t.Fatalf("viewer GET = %d", w.Code)
	}
	var resp struct {
		Rules []authRuleView `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(resp.Rules) != 1 || resp.Rules[0].Auth == nil ||
		resp.Rules[0].Auth.Outcome != OutcomeCredentialRequired {
		t.Fatalf("CR rule not surfaced in list: %+v", resp.Rules)
	}
}

func TestP2S4_API_RejectsCRInvalidForms(t *testing.T) {
	withFreshPolicyStore(t)
	cases := map[string]func(map[string]any){
		"broadExemption on CR": func(m map[string]any) { m["auth"].(map[string]any)["broadExemption"] = true },
		"no destination":       func(m map[string]any) { delete(m, "destFQDN") },
		"providerRefs set":     func(m map[string]any) { m["auth"].(map[string]any)["providerRefs"] = []string{"oidc-corp"} },
		// Note: SSORequired is no longer an "invalid CR form" — it is a valid
		// outcome as of Phase 3 Slice 2 (CR providerRefs stays deferred above).
	}
	for name, mutate := range cases {
		body := crRuleMap("p2s4-bad-" + strings.ReplaceAll(name, " ", "-"))
		mutate(body)
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", name, w.Code)
		}
	}
	if got := len(listAuthRules()); got != 0 {
		t.Errorf("invalid CR rules must not be stored, got %d", got)
	}
}

func TestP2S4_API_PutRoundTripsExemptAndCR(t *testing.T) {
	withFreshPolicyStore(t)
	withConfigVersionsDir(t)

	// Create an Exempt rule, then flip it to CredentialRequired.
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", slice8Rule("p2s4-flip")))
	if w.Code != 200 {
		t.Fatalf("create Exempt = %d: %s", w.Code, w.Body.String())
	}
	var created authRuleView
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	toCR := crRuleMap("p2s4-flip")
	toCR["priority"] = created.Priority
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "PUT", "/api/authpolicy?priority="+itoa(created.Priority), toCR))
	if w.Code != 200 {
		t.Fatalf("PUT Exempt->CR = %d: %s", w.Code, w.Body.String())
	}
	if rules := listAuthRules(); len(rules) != 1 || rules[0].Auth.Outcome != OutcomeCredentialRequired {
		t.Fatalf("Exempt->CR not applied: %+v", rules)
	}

	// Flip back to Exempt.
	toExempt := slice8Rule("p2s4-flip")
	toExempt["priority"] = created.Priority
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "PUT", "/api/authpolicy?priority="+itoa(created.Priority), toExempt))
	if w.Code != 200 {
		t.Fatalf("PUT CR->Exempt = %d: %s", w.Code, w.Body.String())
	}
	if rules := listAuthRules(); len(rules) != 1 || rules[0].Auth.Outcome != OutcomeExempt {
		t.Fatalf("CR->Exempt not applied: %+v", rules)
	}
}

// RBAC is unchanged: CR writes are admin-only (the same contract as Exempt),
// viewer can read.
func TestP2S4_RBAC_CRWritesAdminOnly(t *testing.T) {
	withFreshPolicyStore(t)
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(role, "POST", "/api/authpolicy", crRuleMap("p2s4-rbac")))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s POST CR = %d, want 403", role, w.Code)
		}
	}
	if got := len(listAuthRules()); got != 0 {
		t.Errorf("blocked CR writes must not mutate the store, got %d", got)
	}
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleViewer, "GET", "/api/authpolicy", nil))
	if w.Code != 200 {
		t.Errorf("viewer GET = %d, want 200", w.Code)
	}
}

// ── Simulator: CR renders distinctly from Exempt and Default ─────────────────

func TestP2S4_Simulator_RendersCredentialRequiredDistinctly(t *testing.T) {
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(validCRRule()) // 10.0.5.0/24 → updates.example.com

	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "updates.example.com"})
	if resp.Auth.Outcome != "CredentialRequired" {
		t.Fatalf("auth outcome = %q, want CredentialRequired", resp.Auth.Outcome)
	}
	if resp.Auth.Rule == nil || resp.Auth.Rule.Name != "require-creds-vendor" {
		t.Errorf("matched CR rule missing: %+v", resp.Auth)
	}
	// CR is NOT an access decision and does NOT imply Allow.
	if !strings.Contains(resp.Auth.Note, "NOT Allow") || !strings.Contains(resp.Auth.Note, "challenge") {
		t.Errorf("CR note must frame it as a challenge that is not Allow: %q", resp.Auth.Note)
	}
	// CR must not borrow the Exempt authSource — Stage-2 does not see authSource=exempt.
	if resp.Auth.Stage2AuthSource == "exempt" {
		t.Errorf("CR must not set stage2AuthSource=exempt")
	}
	// Stage-2 stays separate and denies (no access rule, default deny).
	if resp.Matched {
		t.Errorf("no access rule exists — Stage-2 must not match (CR must not imply Allow)")
	}
}

func TestP2S4_Simulator_ExemptStillDistinct(t *testing.T) {
	withFreshPolicyStore(t)
	setDefaultPolicyAction("deny")
	policyStore.Add(validExemptRule())

	resp := runSim(t, map[string]any{"sourceIP": "10.0.5.7", "host": "updates.example.com"})
	if resp.Auth.Outcome != "Exempt" {
		t.Fatalf("auth outcome = %q, want Exempt (regression)", resp.Auth.Outcome)
	}
	if resp.Auth.Stage2AuthSource != "exempt" {
		t.Errorf("Exempt must still set stage2AuthSource=exempt, got %q", resp.Auth.Stage2AuthSource)
	}
}

// ── Diagnostics: CR warnings surface on the operator contract ────────────────

// withCredentialEnv pins cfg + idpRegistry for the duration of the test so the
// CR diagnostics' hasCredentialCapableProvider() input is deterministic.
func withCredentialEnv(t *testing.T, withLocalUser bool) {
	t.Helper()
	origCfg, origReg := cfg, idpRegistry
	t.Cleanup(func() { cfg, idpRegistry = origCfg, origReg })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	idpRegistry = &IdPRegistry{} // no OIDC profile → not credential-capable
	if withLocalUser {
		if err := cfg.SetAuth("alice", "secret"); err != nil {
			t.Fatalf("SetAuth: %v", err)
		}
	}
}

// Slice 3 (S2): under default Exempt a scoped CR rule ENFORCES; the end-to-end
// diagnostics surface the migration WARN (not the removed dead-under-unauth one).
func TestP2S4_Diagnostics_CRDefaultExemptMigration_Warn(t *testing.T) {
	resetPolicyStoreForDiag(t)
	withCredentialEnv(t, true)               // credential-capable, so the no-provider FAIL does not fire
	cfg.SetDefaultAuthOutcome(OutcomeExempt) // open mode (defaultAuthOutcome Exempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	policyStore.Add(validCRRule())

	w := httptest.NewRecorder()
	apiDiagnostics(w, viewerCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/diagnostics", http.NoBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics = %d", w.Code)
	}
	c := decodeContract(t, w)
	if found := findDiagnosticCheck(c, "auth_cr_dead_under_unauth_mode"); found != nil {
		t.Fatalf("removed code auth_cr_dead_under_unauth_mode must not appear: %+v", found)
	}
	found := findDiagnosticCheck(c, "auth_default_exempt_rules_now_enforce")
	if found == nil || found.Status != diagWarn {
		t.Fatalf("auth_default_exempt_rules_now_enforce WARN missing: %+v", found)
	}
}

func TestP2S4_Diagnostics_CRNoProvider_Fail(t *testing.T) {
	resetPolicyStoreForDiag(t)
	withCredentialEnv(t, false) // no credential-capable validator → FAIL
	policyStore.Add(validCRRule())

	w := httptest.NewRecorder()
	apiDiagnostics(w, viewerCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/diagnostics", http.NoBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("diagnostics = %d", w.Code)
	}
	c := decodeContract(t, w)
	found := findDiagnosticCheck(c, "auth_cr_no_credential_provider")
	if found == nil || found.Status != diagFail {
		t.Fatalf("auth_cr_no_credential_provider FAIL missing: %+v", found)
	}
	if c.Verdict != diagFail {
		t.Errorf("a CR rule with no credential provider must drive the verdict to fail, got %q", c.Verdict)
	}
}

// ── No new routes: the authpolicy surface is exactly the two Slice-8 routes ───

func TestP2S4_Routes_NoNewAuthPolicyRoutes(t *testing.T) {
	want := map[string][]string{
		"/api/authpolicy":         {"GET", "POST", "PUT", "DELETE"},
		"/api/authpolicy/reorder": {"POST"},
	}
	got := map[string][]string{}
	for i := range uiRoutes {
		if !strings.HasPrefix(uiRoutes[i].Path, "/api/authpolicy") {
			continue
		}
		methods := make([]string, 0, len(uiRoutes[i].Methods))
		for _, m := range uiRoutes[i].Methods {
			methods = append(methods, m.Method)
			// RBAC unchanged: every authpolicy write stays admin-only.
			if m.Method != "GET" && m.MinRole != RoleAdmin {
				t.Errorf("%s %s MinRole = %q, want admin (RBAC must not change)", uiRoutes[i].Path, m.Method, m.MinRole)
			}
		}
		got[uiRoutes[i].Path] = methods
	}
	if len(got) != len(want) {
		t.Fatalf("authpolicy route set changed: got %v, want keys %v (no new routes allowed)", got, want)
	}
	for path, methods := range want {
		if strings.Join(got[path], ",") != strings.Join(methods, ",") {
			t.Errorf("%s methods = %v, want %v", path, got[path], methods)
		}
	}
}

// ── Static UI: the panel exposes the outcome selector, gating, and CR copy ───

func TestP2S4_UI_OutcomeSelectorAndCopy(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	// Assert on stable identifiers (not whole sentences) so copy edits don't break.
	mustContain := []string{
		`id="ap-outcome"`,                     // outcome selector exists
		`value="CredentialRequired"`,          // CR is selectable
		`value="Exempt"`,                      // Exempt is selectable
		`apOutcomeChanged`,                    // broad-exemption gating handler
		`getElementById('ap-outcome')`,        // apSave reads the selector (no hardcoded Exempt)
		`#i-lock"/></svg> CredentialRequired`, // simulator + list render CR distinctly (lock icon)
		`for reference only`,                  // CR note clarifies the unauth Stage-2 block is not the post-auth decision
		`Auth Policy`,                         // nav/panel renamed from "Auth Exempt"
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html missing %q", sub)
		}
	}
	// apSave must no longer hardcode the Exempt outcome.
	if strings.Contains(s, `outcome:        'Exempt',`) {
		t.Error("apSave still hardcodes outcome:'Exempt' — the selector value must be sent instead")
	}
}
