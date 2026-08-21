package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 3 Slice 2 — SSORequired auth rules and SSO providerRefs VALIDATE and
// PERSIST, but remain resolver/runtime-INERT. No proxy.go/socks5.go change, no
// UI exposure, no resolver change. CredentialRequired and Exempt behavior are
// unchanged; CR providerRefs stays deferred (rejected).

// validSSORule returns a valid SSORequired auth rule scoped to 10.0.5.0/24 →
// portal.example.com with no providerRefs (= all compatible enabled IdPs).
func validSSORule() PolicyRule {
	enabled := true
	return PolicyRule{
		Priority: 1,
		Name:     "require-sso-portal",
		RuleType: ruleTypeAuth,
		Enabled:  &enabled,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}},
		},
		DestFQDN: "portal.example.com",
		Auth:     &AuthRuleSpec{Outcome: OutcomeSSORequired, Owner: "secops", Reason: "portal requires interactive SSO"},
	}
}

// ssoRuleMap returns a valid SSORequired rule as a JSON-shaped map for the API.
func ssoRuleMap(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"ruleType": "auth",
		"subjectMatch": map[string]any{
			"schemaVersion": 1,
			"all":           []map[string]any{{"type": "cidr", "values": []string{"10.0.5.0/24"}}},
		},
		"destFQDN": "portal.example.com",
		"auth":     map[string]any{"outcome": "SSORequired", "owner": "secops", "reason": "portal requires interactive SSO"},
	}
}

// withIdPRegistry installs a registry with the given profiles for the test,
// restoring the prior global on cleanup.
func withIdPRegistry(t *testing.T, profiles ...*IdPProfile) {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	idpRegistry = &IdPRegistry{profiles: profiles}
}

// ── Shape validation (pure) ──────────────────────────────────────────────────

func TestP3S2_ValidateAuthRule_AcceptsSSORequired(t *testing.T) {
	if _, err := validateAuthRule(validSSORule()); err != nil {
		t.Fatalf("valid SSORequired rule must be accepted: %v", err)
	}
	// Empty providerRefs is valid (= all compatible enabled interactive IdPs).
	r := validSSORule()
	r.Auth.ProviderRefs = nil
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("SSORequired with empty providerRefs must be accepted: %v", err)
	}
	// Shape-valid providerRefs (registry NOT consulted here).
	r.Auth.ProviderRefs = []string{"corp-oidc", "corp-saml"}
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("SSORequired with well-shaped providerRefs must pass shape validation: %v", err)
	}
}

func TestP3S2_ShapeRejectsInvalidSSORequired(t *testing.T) {
	cases := map[string]func(*PolicyRule){
		"broadExemption on SSO": func(r *PolicyRule) { r.Auth.BroadExemption = true },
		"no destination":        func(r *PolicyRule) { r.DestFQDN = "" },
		"missing owner":         func(r *PolicyRule) { r.Auth.Owner = "" },
		"missing reason":        func(r *PolicyRule) { r.Auth.Reason = "" },
		"socks5 protocol":       func(r *PolicyRule) { r.Auth.Protocol = "socks5" },
		"bad expiry":            func(r *PolicyRule) { r.Auth.ExpiresAt = "not-a-timestamp" },
		"identity predicate": func(r *PolicyRule) {
			r.SubjectMatch.All = []SubjectPredicate{{Type: "directory_group", Values: []string{"eng"}}}
		},
		"empty providerRef":          func(r *PolicyRule) { r.Auth.ProviderRefs = []string{"corp-oidc", "  "} },
		"duplicate providerRef":      func(r *PolicyRule) { r.Auth.ProviderRefs = []string{"corp-oidc", "corp-oidc"} },
		"whitespace-padded ref":      func(r *PolicyRule) { r.Auth.ProviderRefs = []string{" corp-oidc "} },
		"whitespace dup providerRef": func(r *PolicyRule) { r.Auth.ProviderRefs = []string{"corp-oidc", " corp-oidc "} },
		"over-cap providerRefs": func(r *PolicyRule) {
			refs := make([]string, maxAuthProviderRefs+1)
			for i := range refs {
				refs[i] = "idp-" + itoa(i)
			}
			r.Auth.ProviderRefs = refs
		},
	}
	for name, mutate := range cases {
		r := validSSORule()
		mutate(&r)
		if _, err := validateAuthRule(r); err == nil {
			t.Errorf("%s: expected validation error, got nil", name)
		}
	}
}

func TestP3S2_ProviderRefsRejectedForCRAndExempt(t *testing.T) {
	// CredentialRequired + providerRefs → ACCEPTED at shape level since
	// ADR-0025 activated the reserved seam (refs name the credential-capable
	// provider subset; referential checks run at the API write door).
	cr := validCRRule()
	cr.Auth.ProviderRefs = []string{"corp-oidc"}
	if _, err := validateAuthRule(cr); err != nil {
		t.Errorf("CredentialRequired providerRefs must pass shape validation (ADR-0025): %v", err)
	}
	// Exempt + providerRefs → rejected (no provider concept).
	ex := validExemptRule()
	ex.Auth.ProviderRefs = []string{"corp-oidc"}
	if _, err := validateAuthRule(ex); err == nil {
		t.Error("Exempt providerRefs must be rejected")
	}
}

// ── Referential validation (registry-aware, API write door only) ─────────────

func TestP3S2_API_ReferentialProviderRefs(t *testing.T) {
	withConfigVersionsDir(t)
	withIdPRegistry(t,
		&IdPProfile{ID: "corp-oidc", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true},
		&IdPProfile{ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true},
		&IdPProfile{ID: "old-oidc", Name: "Old", Type: IdPTypeOIDC, Enabled: false},
	)

	accept := map[string][]string{
		"empty":     nil,
		"oidc":      {"corp-oidc"},
		"saml":      {"corp-saml"}, // SAML IS valid for SSO
		"oidc+saml": {"corp-oidc", "corp-saml"},
	}
	for name, refs := range accept {
		withFreshPolicyStore(t)
		body := ssoRuleMap("sso-ok-" + name)
		if refs != nil {
			body["auth"].(map[string]any)["providerRefs"] = refs
		}
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
		if w.Code != 200 {
			t.Errorf("%s: POST = %d, want 200: %s", name, w.Code, w.Body.String())
		}
	}

	reject := map[string][]string{
		"missing ref":  {"ghost-idp"},
		"disabled ref": {"old-oidc"},
	}
	for name, refs := range reject {
		withFreshPolicyStore(t)
		body := ssoRuleMap("sso-bad-" + strings.ReplaceAll(name, " ", "-"))
		body["auth"].(map[string]any)["providerRefs"] = refs
		w := httptest.NewRecorder()
		apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", name, w.Code)
		}
		if len(listAuthRules()) != 0 {
			t.Errorf("%s: rejected rule must not be stored", name)
		}
	}
}

// ── Persistence: shape-only, registry-free (DR-4) ────────────────────────────

func TestP3S2_Persistence_LoadReplaceAllShapeOnly(t *testing.T) {
	// Load: valid SSO survives, shape-invalid SSO dropped.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	invalid := validSSORule()
	invalid.Name, invalid.DestFQDN = "sso-no-dest", "" // shape-invalid
	data, err := json.MarshalIndent([]PolicyRule{
		validSSORule(), invalid, {Priority: 9, Name: "plain", Action: ActionAllow},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if findRule(ps.List(), "require-sso-portal") == nil {
		t.Error("valid SSORequired rule must survive Load")
	}
	if findRule(ps.List(), "sso-no-dest") != nil {
		t.Error("shape-invalid SSORequired rule must be dropped fail-closed on Load")
	}
	if r := findRule(ps.List(), "require-sso-portal"); r == nil || r.Auth.Outcome != OutcomeSSORequired {
		t.Errorf("SSORequired outcome not round-tripped: %+v", r)
	}

	// ReplaceAll: valid SSO survives, shape-invalid (missing owner) dropped.
	ps2 := &PolicyStore{}
	bad := validSSORule()
	bad.Name, bad.Auth.Owner = "sso-bad", ""
	ps2.ReplaceAll([]PolicyRule{validSSORule(), bad})
	if findRule(ps2.List(), "require-sso-portal") == nil {
		t.Error("valid SSORequired rule must survive ReplaceAll")
	}
	if findRule(ps2.List(), "sso-bad") != nil {
		t.Error("shape-invalid SSORequired rule must be dropped by ReplaceAll")
	}
}

// DR-4: the bulk persistence gate is registry-free, so a stored SSORequired rule
// whose providerRefs name an IdP that is absent/disabled is KEPT (it will fail
// closed at runtime + diagnostics later) — never dropped from persistence.
func TestP3S2_Persistence_UnknownProviderRefNotDropped(t *testing.T) {
	withIdPRegistry(t) // empty registry — no profiles at all
	ps := &PolicyStore{}
	r := validSSORule()
	r.Auth.ProviderRefs = []string{"ghost-idp"} // shape-valid, references a missing IdP
	ps.ReplaceAll([]PolicyRule{r})
	got := findRule(ps.List(), "require-sso-portal")
	if got == nil {
		t.Fatal("DR-4: a stored SSORequired rule with an unknown providerRef must NOT be dropped by the registry-free bulk gate")
	}
	if len(got.Auth.ProviderRefs) != 1 || got.Auth.ProviderRefs[0] != "ghost-idp" {
		t.Errorf("providerRefs not round-tripped through ReplaceAll: %+v", got.Auth.ProviderRefs)
	}
}

func TestP3S2_Persistence_RollbackImportClusterPreserveSSO(t *testing.T) {
	// Rollback.
	withFreshPolicyStore(t)
	applyConfigBackup(&configBackup{Version: 1, PolicyRules: []PolicyRule{validSSORule()}})
	if findRule(policyStore.List(), "require-sso-portal") == nil {
		t.Error("rollback must round-trip the valid SSORequired rule")
	}
	// Cluster snapshot.
	withFreshPolicyStore(t)
	applyConfigSnapshot(ConfigSnapshot{PolicyRules: []PolicyRule{validSSORule()}})
	if findRule(policyStore.List(), "require-sso-portal") == nil {
		t.Error("cluster snapshot must round-trip the valid SSORequired rule")
	}
	// Import (replace).
	withFreshPolicyStore(t)
	body, err := json.Marshal(configBackup{Version: 1, PolicyRules: []PolicyRule{validSSORule()}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	apiConfigImport(w, adminRequest("POST", "/api/config/import?mode=replace", string(body)))
	if w.Code != 200 {
		t.Fatalf("import = %d: %s", w.Code, w.Body.String())
	}
	if findRule(policyStore.List(), "require-sso-portal") == nil {
		t.Error("import must preserve the valid SSORequired rule")
	}
}

// ── Pure resolver (generalized in Phase 3 Slice 3) ───────────────────────────
//
// As of Slice 2 these asserted the pure resolver returned Default for SSORequired.
// Slice 3 generalized the FULL pure resolver to return SSORequired (priority-
// ordered). The RUNTIME no-credentials path stays SSO-inert and never shadows
// Exempt/CR — that invariant is owned by the Phase 3 Slice 3 suite
// (TestP3S3_Runtime_SSODoesNotShadow). Here we pin the pure-resolver behavior.

func TestP3S2_PureResolver_SSORequiredResolves(t *testing.T) {
	ctx := RequestContext{ClientIP: "10.0.5.7", Host: "portal.example.com", Protocol: "http", Method: "GET"}
	if d := resolveAuthOutcomeFrom([]PolicyRule{validSSORule()}, ctx); d.Outcome != OutcomeSSORequired {
		t.Fatalf("pure resolver must return SSORequired (Phase 3 Slice 3), got %q", d.Outcome)
	}
}

// In the pure resolver, a higher-priority SSORequired rule wins by priority.
func TestP3S2_PureResolver_SSOPriorityOverExempt(t *testing.T) {
	sso := validSSORule()
	sso.Priority = 1
	ex := validExemptRule()
	ex.Name, ex.Priority, ex.DestFQDN = "exempt-2", 2, "portal.example.com"
	ex.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}}}
	ctx := RequestContext{ClientIP: "10.0.5.7", Host: "portal.example.com", Protocol: "http", Method: "GET"}
	if d := resolveAuthOutcomeFrom([]PolicyRule{sso, ex}, ctx); d.Outcome != OutcomeSSORequired {
		t.Fatalf("pure resolver: SSO@1 must win by priority; got %q", d.Outcome)
	}
}

// End-to-end: a no-credentials NON-BROWSER request matching an SSORequired rule
// is failed closed (403, no Basic 407) as of Phase 3 Slice 4 — SSORequired is
// now runtime-active. (Comprehensive SSO runtime coverage lives in the Slice 4
// suite; this pins that the Slice-2-persisted rule actually enforces.)
func TestP3S2_RuntimeActive_NonBrowserFailsClosed(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p3s2-sso.example.test"
	sso := validSSORule()
	sso.Name, sso.DestFQDN = "sso-runtime", host
	sso.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}
	policyStore.Add(sso)

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-browser SSORequired must fail closed (403), got %d", w.Code)
	}
	if w.Header().Get("Proxy-Authenticate") != "" {
		t.Errorf("SSORequired 403 must NOT carry a Basic challenge (no 407 affordance), got %q", w.Header().Get("Proxy-Authenticate"))
	}
}

// ── No regression: CR and Exempt resolver behavior unchanged ─────────────────

func TestP3S2_NoRegression_CRAndExemptResolve(t *testing.T) {
	ctxCR := RequestContext{ClientIP: "10.0.5.7", Host: "updates.example.com", Protocol: "http", Method: "GET"}
	if d := resolveAuthOutcomeFrom([]PolicyRule{validCRRule()}, ctxCR); d.Outcome != OutcomeCredentialRequired {
		t.Errorf("CredentialRequired resolver behavior regressed: got %q", d.Outcome)
	}
	if d := resolveAuthOutcomeFrom([]PolicyRule{validExemptRule()}, ctxCR); d.Outcome != OutcomeExempt {
		t.Errorf("Exempt resolver behavior regressed: got %q", d.Outcome)
	}
}
