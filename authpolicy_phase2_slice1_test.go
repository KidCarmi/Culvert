package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Phase 2 Slice 1 — CredentialRequired (CR) rules are VALIDATED and PERSISTED,
// but remain runtime-inert: the resolver returns Default for them (the
// authRuleMatchesExempt outcome guard is untouched). No proxy.go/socks5.go
// change, no UI, no new runtime behavior.

// validCRRule returns a valid CredentialRequired auth rule scoped to
// 10.0.5.0/24 → updates.example.com.
func validCRRule() PolicyRule {
	enabled := true
	return PolicyRule{
		Priority: 1,
		Name:     "require-creds-vendor",
		RuleType: ruleTypeAuth,
		Enabled:  &enabled,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.5.0/24"}}},
		},
		DestFQDN: "updates.example.com",
		Auth:     &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "secops", Reason: "vendor subnet must authenticate"},
	}
}

// crRuleMap returns a valid CR rule as a JSON-shaped map for the API path.
func crRuleMap(name string) map[string]any {
	return map[string]any{
		"name":     name,
		"ruleType": "auth",
		"subjectMatch": map[string]any{
			"schemaVersion": 1,
			"all":           []map[string]any{{"type": "cidr", "values": []string{"10.0.5.0/24"}}},
		},
		"destFQDN": "updates.example.com",
		"auth":     map[string]any{"outcome": "CredentialRequired", "owner": "secops", "reason": "vendor subnet must authenticate"},
	}
}

// ── Validation: accept ───────────────────────────────────────────────────────

func TestP2S1_ValidateAuthRule_AcceptsCredentialRequired(t *testing.T) {
	warnings, err := validateAuthRule(validCRRule())
	if err != nil {
		t.Fatalf("valid CR rule rejected: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("scoped /24 CR rule should warn nothing, got: %v", warnings)
	}
	// validatePolicyRule (the API/import accept path) accepts it too.
	if err := validatePolicyRule(validCRRule(), nil, -1); err != nil {
		t.Fatalf("validatePolicyRule must accept a valid CR rule: %v", err)
	}
}

func TestP2S1_CR_DestinationViaCategoryOrGroup(t *testing.T) {
	r := validCRRule()
	r.DestFQDN = ""
	r.DestCategory = CategorySocial
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("destCategory should satisfy CR destination scoping: %v", err)
	}
	r.DestCategory = ""
	r.DestCategoryGroup = "vendor-cloud"
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("destCategoryGroup should satisfy CR destination scoping: %v", err)
	}
}

// ── Validation: reject (fail-closed) ─────────────────────────────────────────

func TestP2S1_CR_RejectsInvalid(t *testing.T) {
	cases := map[string]func(*PolicyRule){
		"missing owner":      func(r *PolicyRule) { r.Auth.Owner = "  " },
		"missing reason":     func(r *PolicyRule) { r.Auth.Reason = "" },
		"malformed expiry":   func(r *PolicyRule) { r.Auth.ExpiresAt = "not-a-date" },
		"missing subject":    func(r *PolicyRule) { r.SubjectMatch = nil },
		"non-cidr predicate": func(r *PolicyRule) { r.SubjectMatch.All = []SubjectPredicate{{Type: "tag", Values: []string{"x"}}} },
		"identity predicate": func(r *PolicyRule) {
			r.SubjectMatch.All = []SubjectPredicate{{Type: "directory_group", Values: []string{"eng"}}}
		},
		"providerRefs set": func(r *PolicyRule) { r.Auth.ProviderRefs = []string{"okta"} },
		"protocol socks5":  func(r *PolicyRule) { r.Auth.Protocol = "socks5" },
		"protocol unknown": func(r *PolicyRule) { r.Auth.Protocol = "ftp" },
		"missing dest":     func(r *PolicyRule) { r.DestFQDN = ""; r.DestCategory = ""; r.DestCategoryGroup = "" },
		"broadExemption":   func(r *PolicyRule) { r.DestFQDN = ""; r.Auth.BroadExemption = true },
		"broadExempt+dest": func(r *PolicyRule) { r.Auth.BroadExemption = true }, // even with a dest, broadExemption is invalid on CR
	}
	for name, mutate := range cases {
		r := validCRRule()
		mutate(&r)
		if _, err := validateAuthRule(r); err == nil {
			t.Errorf("%s: CR rule must be rejected, but validated", name)
		}
	}
}

// SSORequired was reserved in Phase 2; Phase 3 Slice 2 activated its validation
// and persistence (still runtime-inert). Acceptance is owned by the Phase 3
// Slice 2 suite; here we only confirm it is no longer rejected at validation.
func TestP2S1_SSORequiredActivatedInPhase3(t *testing.T) {
	r := validCRRule()
	r.Auth.Outcome = OutcomeSSORequired
	if _, err := validateAuthRule(r); err != nil {
		t.Fatalf("SSORequired must validate as of Phase 3 Slice 2: %v", err)
	}
}

// ── API accept path ──────────────────────────────────────────────────────────

func TestP2S1_API_AcceptsCredentialRequired(t *testing.T) {
	withFreshPolicyStore(t)
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", crRuleMap("api-cr")))
	if w.Code != 200 {
		t.Fatalf("admin POST CR = %d: %s", w.Code, w.Body.String())
	}
	rules := listAuthRules()
	if len(rules) != 1 || rules[0].Auth.Outcome != OutcomeCredentialRequired {
		t.Fatalf("CR rule not stored via API: %+v", rules)
	}
	// broadExemption on CR is rejected at the API too.
	bad := crRuleMap("api-cr-broad")
	bad["auth"].(map[string]any)["broadExemption"] = true
	w = httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", bad))
	if w.Code != 400 {
		t.Errorf("CR + broadExemption via API = %d, want 400", w.Code)
	}
}

// ── Persistence: preserve valid / refuse a ruleset holding an invalid rule ────

// A valid CredentialRequired rule round-trips through Load intact. A file that
// ALSO holds an invalid one is refused whole (POL-005): dropping the invalid
// rule and installing the rest would leave clients it names unchallenged.
func TestP2S1_Persistence_LoadPreservesValidRefusesFileWithInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	valid := []PolicyRule{validCRRule(), {Priority: 9, Name: "plain-allow", Action: ActionAllow}}
	data, err := json.MarshalIndent(valid, "", "  ")
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
	got := ps.List()
	if len(got) != 2 {
		t.Fatalf("expected valid CR + plain to be installed, got %d: %+v", len(got), got)
	}
	// Round-trip preserves the CR outcome + spec.
	cr := findRule(got, "require-creds-vendor")
	if cr == nil {
		t.Fatal("valid CR rule must be preserved on load")
	}
	if cr.Auth == nil || cr.Auth.Outcome != OutcomeCredentialRequired {
		t.Errorf("CR outcome not round-tripped: %+v", cr)
	}

	invalid := validCRRule()
	invalid.Name = "cr-no-dest"
	invalid.DestFQDN = "" // invalid: CR requires a destination
	mixed, err := json.MarshalIndent(append([]PolicyRule{invalid}, valid...), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ue := assertLoadRefusedWhole(t, mixed, "cr-no-dest")
	if !strings.Contains(ue.Reason, "invalid auth rule") {
		t.Errorf("refusal reason = %q, want an invalid-auth-rule reason", ue.Reason)
	}
}

// Same pair through ReplaceAll: the valid ruleset is installed; the one holding
// an invalid CR rule is refused whole and the store keeps what it had (POL-005).
func TestP2S1_Persistence_ReplaceAllPreservesValidRefusesRulesetWithInvalid(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{validCRRule(), {Priority: 9, Name: "plain", Action: ActionAllow}})
	if cr := findRule(ps.List(), "require-creds-vendor"); cr == nil || cr.Auth == nil || cr.Auth.Outcome != OutcomeCredentialRequired {
		t.Errorf("valid CR rule must survive ReplaceAll intact: %+v", cr)
	}
	invalid := validCRRule()
	invalid.Name, invalid.Auth.Owner = "cr-bad", "" // missing owner
	assertReplaceAllRefusedWhole(t, []PolicyRule{validCRRule(), invalid, {Priority: 9, Name: "plain", Action: ActionAllow}})
}

func TestP2S1_Persistence_ImportReplaceAndMerge(t *testing.T) {
	for _, mode := range []string{"?mode=replace", ""} {
		withFreshPolicyStore(t)
		body, err := json.Marshal(configBackup{Version: 1, PolicyRules: []PolicyRule{
			validCRRule(),
			{Priority: 2, Name: "import-plain", Action: ActionAllow},
		}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r := adminRequest("POST", "/api/config/import"+mode, string(body))
		w := httptest.NewRecorder()
		apiConfigImport(w, r)
		if w.Code != 200 {
			t.Fatalf("import%s = %d: %s", mode, w.Code, w.Body.String())
		}
		if cr := findRule(policyStore.List(), "require-creds-vendor"); cr == nil || cr.Auth.Outcome != OutcomeCredentialRequired {
			t.Errorf("import%s must preserve the valid CR rule", mode)
		}
	}
}

func TestP2S1_Persistence_RollbackAndClusterSnapshot(t *testing.T) {
	bindFreshAdmissionOwners(t) // the snapshot apply mutates ipf/rl in place (RISK-030)
	// Rollback (applyConfigBackup).
	withFreshPolicyStore(t)
	applyConfigBackup(&configBackup{Version: 1, PolicyRules: []PolicyRule{
		validCRRule(), {Priority: 2, Name: "rb-plain", Action: ActionAllow},
	}})
	if cr := findRule(policyStore.List(), "require-creds-vendor"); cr == nil || cr.Auth.Outcome != OutcomeCredentialRequired {
		t.Error("rollback must round-trip the valid CR rule")
	}
	// Cluster snapshot (applyConfigSnapshot).
	withFreshPolicyStore(t)
	applyConfigSnapshot(ConfigSnapshot{PolicyRules: []PolicyRule{
		validCRRule(), {Priority: 2, Name: "cl-plain", Action: ActionAllow},
	}})
	if cr := findRule(policyStore.List(), "require-creds-vendor"); cr == nil || cr.Auth.Outcome != OutcomeCredentialRequired {
		t.Error("cluster snapshot must round-trip the valid CR rule")
	}
}

// ── Persistence acceptance is independent of resolver activation ─────────────
//
// Slice 1 asserted these resolved to Default; Phase 2 Slice 2 generalizes the
// pure resolver to return CredentialRequired (still runtime-inert — proxy.go
// consumes only Exempt). The CR resolver contract is owned by the Slice 2 suite;
// here we only confirm persistence + that Stage-2 Evaluate still ignores it.

func TestP2S1_CR_PersistedThenStage2Ignores(t *testing.T) {
	withFreshPolicyStore(t)
	policyStore.Add(validCRRule())
	if cr := findRule(policyStore.List(), "require-creds-vendor"); cr == nil {
		t.Fatal("CR rule must persist into the live store")
	}
	// Stage-2 Evaluate ignores the auth rule entirely (unchanged by Slice 2).
	if m := policyStore.Evaluate("10.0.5.50", "", "unauth", "updates.example.com", nil); m != nil && ruleTypeOf(m.Rule) != ruleTypeAccess {
		t.Errorf("Stage-2 Evaluate must ignore the CR auth rule, matched: %+v", m.Rule)
	}
}

// keep time import used (expiry-acceptance smoke for CR).
func TestP2S1_CR_FutureExpiryAccepted(t *testing.T) {
	r := validCRRule()
	r.Auth.ExpiresAt = time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := validateAuthRule(r); err != nil {
		t.Errorf("CR rule with valid future expiry must be accepted: %v", err)
	}
}
