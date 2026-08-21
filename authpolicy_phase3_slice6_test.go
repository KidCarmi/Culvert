package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Phase 3 Slice 6 (FINAL) — expose SSORequired + providerRefs cleanly in the
// API/UI/Simulator. This slice is static/index.html-only on the production
// side: Slices 2–5 built the full backend (validation, referential checks,
// runtime wiring, diagnostics). These tests pin that the UI surfaces the
// SSORequired outcome and its providerRefs selector, that the simulator renders
// Stage-1 / runtimeOutcome / Stage-2 separately, that unavailable providerRefs
// are preserved on edit, and that the exact GUI payload round-trips through the
// admin API under the existing RBAC contract.

// ── Static UI: outcome selector, providerRefs control, and copy ──────────────

func TestP3S6_UI_ExposesSSORequiredAndProviderRefs(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	// Assert on stable identifiers/substrings (not whole sentences) so copy
	// edits do not break the test.
	mustContain := []string{
		`value="SSORequired"`,             // SSORequired is selectable in the outcome dropdown
		`id="ap-providerrefs-wrap"`,       // providerRefs field wrapper (revealed for SSO only)
		`id="ap-providerrefs"`,            // the multiselect itself
		`for="ap-providerrefs"`,           // its label is associated with the control (a11y/reliability)
		`id="ap-providerrefs-help"`,       // help text for the selector
		`function apPopulateProviderRefs`, // fills the selector from enabled OIDC/SAML IdPs
		`function apOutcomeChanged`,       // gating handler reveals the selector
		`#i-globe"/></svg> SSORequired`,   // distinct badge for the outcome (globe icon)
		`_policyIdPList`,                  // IdP list reused for the selector
		`api('/api/idp')`,                 // viewer-readable source for the selector (no new route)
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html missing %q", sub)
		}
	}
}

// The providerRefs selector must reveal for SSORequired only, and the broad-
// exemption checkbox must be forced off for the challenge outcomes.
func TestP3S6_UI_ProviderRefsGatedToSSOOnly(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	mustContain := []string{
		// apOutcomeChanged reveals the wrap for SSO only.
		`const sso = outcome === 'SSORequired';`,
		`document.getElementById('ap-providerrefs-wrap').style.display = sso ? '' : 'none';`,
		// challenge = CR || SSO, and broad is forced false for challenge outcomes.
		`const challenge = outcome === 'CredentialRequired' || outcome === 'SSORequired';`,
		// apSave only sends providerRefs for SSORequired.
		`if (outcome === 'SSORequired') {`,
		`auth.providerRefs = Array.from(document.getElementById('ap-providerrefs').selectedOptions)`,
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html missing %q", sub)
		}
	}
	// Only enabled OIDC/SAML providers are listed.
	if !strings.Contains(s, `p.enabled && (p.type === 'oidc' || p.type === 'saml')`) {
		t.Error("apPopulateProviderRefs must filter to enabled OIDC/SAML providers only")
	}
}

// Edit-preservation (R3): a previously-saved providerRef that is no longer
// enabled/present must be rendered as a selected "(unavailable)" option so
// saving an edited rule never silently drops it.
func TestP3S6_UI_PreservesUnavailableProviderRefs(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `(unavailable)`) {
		t.Error("apPopulateProviderRefs must render dropped refs as an (unavailable) option")
	}
	// The unavailable option must be rendered selected so it round-trips on save.
	if !strings.Contains(s, `selected>${escHtml(id)} (unavailable)</option>`) {
		t.Error("unavailable providerRef option must be marked selected so editing does not drop it")
	}
	// apEditRule must seed the selector from the rule's existing providerRefs.
	if !strings.Contains(s, `apPopulateProviderRefs((r.auth && r.auth.providerRefs) || [])`) {
		t.Error("apEditRule must seed the providerRefs selector from the rule's saved refs")
	}
}

// Simulator must render Stage-1 outcome, runtimeOutcome, and the Stage-2
// decision as three separate things, with an SSORequired branch that reads as
// a challenge (302/403), never as Allow.
func TestP3S6_UI_SimulatorSeparatesStagesAndHandlesSSO(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	mustContain := []string{
		`const sso = a.outcome === 'SSORequired';`, // simulator recognises the outcome
		`a.runtimeOutcome`,                         // runtimeOutcome is read from the response
		`Runtime outcome`,                          // and rendered on its own line
		`Stage-1 Authentication:`,                  // Stage-1 block label
		`Stage-2 Access Decision:`,                 // Stage-2 block label (separate)
		`browser`,                                  // SSO note mentions browser → redirect
		`fail`,                                     // ...and fail-closed for non-browser/CONNECT
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html simulator missing %q", sub)
		}
	}
	// SSORequired must never be rendered as an allow in the Stage-1 note.
	idx := strings.Index(s, `SSORequired requires an interactive browser`)
	if idx < 0 {
		t.Fatal("simulator SSORequired note not found")
	}
	end := idx + 400
	if end > len(s) {
		end = len(s)
	}
	note := s[idx:end]
	if !strings.Contains(note, "NOT Allow") {
		t.Error("simulator SSORequired note must state it is NOT Allow")
	}
}

// ── API round-trip: the exact GUI payload persists and reads back ────────────

// guiSSORulePayload mirrors what apSave() posts for an SSORequired rule: an
// auth object with outcome=SSORequired, broadExemption forced false, and a
// providerRefs array.
func guiSSORulePayload(name string, refs []string) map[string]any {
	return map[string]any{
		"name":     name,
		"ruleType": "auth",
		"enabled":  true,
		"subjectMatch": map[string]any{
			"schemaVersion": 1,
			"all":           []map[string]any{{"type": "cidr", "values": []string{"10.0.5.0/24"}}},
		},
		"destFQDN": "portal.example.com",
		"auth": map[string]any{
			"outcome":        "SSORequired",
			"owner":          "secops",
			"reason":         "portal requires interactive SSO",
			"broadExemption": false,
			"providerRefs":   refs,
		},
	}
}

func TestP3S6_API_GUISSORulePayloadRoundTrips(t *testing.T) {
	withConfigVersionsDir(t)
	withFreshPolicyStore(t)
	withIdPRegistry(t,
		&IdPProfile{ID: "corp-oidc", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true},
		&IdPProfile{ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true},
	)

	// POST the GUI payload (admin).
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy",
		guiSSORulePayload("gui-sso", []string{"corp-oidc", "corp-saml"})))
	if w.Code != 200 {
		t.Fatalf("POST GUI SSO payload = %d, want 200: %s", w.Code, w.Body.String())
	}

	// GET back (viewer) and confirm providerRefs survived the round-trip.
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleViewer, "GET", "/api/authpolicy", nil))
	if w.Code != 200 {
		t.Fatalf("viewer GET = %d, want 200", w.Code)
	}
	var resp struct {
		Rules []authRuleView `json:"rules"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var got *authRuleView
	for i := range resp.Rules {
		if resp.Rules[i].Name == "gui-sso" {
			got = &resp.Rules[i]
			break
		}
	}
	if got == nil {
		t.Fatal("gui-sso rule not found after POST")
	}
	if got.Auth == nil || got.Auth.Outcome != OutcomeSSORequired {
		t.Fatalf("outcome not round-tripped: %+v", got.Auth)
	}
	if got.Auth.BroadExemption {
		t.Error("broadExemption must be false for an SSORequired rule")
	}
	if len(got.Auth.ProviderRefs) != 2 ||
		got.Auth.ProviderRefs[0] != "corp-oidc" || got.Auth.ProviderRefs[1] != "corp-saml" {
		t.Errorf("providerRefs not round-tripped: %+v", got.Auth.ProviderRefs)
	}
}

// Empty providerRefs (= all compatible enabled IdPs) is the GUI default and
// must be accepted and round-trip as empty.
func TestP3S6_API_EmptyProviderRefsAccepted(t *testing.T) {
	withConfigVersionsDir(t)
	withFreshPolicyStore(t)
	withIdPRegistry(t, &IdPProfile{ID: "corp-oidc", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true})

	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy",
		guiSSORulePayload("gui-sso-empty", []string{})))
	if w.Code != 200 {
		t.Fatalf("POST empty-providerRefs SSO = %d, want 200: %s", w.Code, w.Body.String())
	}
	rules := listAuthRules()
	if len(rules) != 1 || rules[0].Auth.Outcome != OutcomeSSORequired {
		t.Fatalf("rule not stored: %+v", rules)
	}
	if len(rules[0].Auth.ProviderRefs) != 0 {
		t.Errorf("empty providerRefs must stay empty, got %+v", rules[0].Auth.ProviderRefs)
	}
}

// RBAC: viewer/operator may not create SSORequired rules; admin may.
func TestP3S6_API_RBACUnchanged(t *testing.T) {
	withConfigVersionsDir(t)
	withIdPRegistry(t, &IdPProfile{ID: "corp-oidc", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true})
	for _, role := range []UIRole{RoleViewer, RoleOperator} {
		withFreshPolicyStore(t)
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(role, "POST", "/api/authpolicy",
			guiSSORulePayload("rbac-sso", []string{"corp-oidc"})))
		if w.Code == 200 {
			t.Errorf("role %v must not create an SSORequired rule", role)
		}
		if len(listAuthRules()) != 0 {
			t.Errorf("role %v: rule must not be stored", role)
		}
	}
	// Admin succeeds.
	withFreshPolicyStore(t)
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy",
		guiSSORulePayload("rbac-sso-admin", []string{"corp-oidc"})))
	if w.Code != 200 {
		t.Fatalf("admin POST = %d, want 200: %s", w.Code, w.Body.String())
	}
}

// Defense-in-depth: providerRefs on Exempt/CredentialRequired stays rejected at
// the API write door even though the GUI only sends it for SSORequired.
func TestP3S6_API_ProviderRefsStillRejectedForExemptAndCR(t *testing.T) {
	withConfigVersionsDir(t)
	withIdPRegistry(t, &IdPProfile{ID: "corp-oidc", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true})
	for _, outcome := range []string{"Exempt", "CredentialRequired"} {
		withFreshPolicyStore(t)
		body := guiSSORulePayload("bad-"+outcome, []string{"corp-oidc"})
		body["auth"].(map[string]any)["outcome"] = outcome
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s + providerRefs: POST = %d, want 400", outcome, w.Code)
		}
		if len(listAuthRules()) != 0 {
			t.Errorf("%s + providerRefs: rule must not be stored", outcome)
		}
	}
}
