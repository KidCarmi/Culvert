package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Phase 1 Slice 3 — auth-aware PERSISTENCE tests.
//
// VALID auth/exempt rules must round-trip through every bulk path (Load,
// ReplaceAll, import replace/merge, rollback, cluster snapshot) WITHOUT being
// activated at runtime. INVALID auth rules and access rules carrying a
// SubjectMatch must be dropped fail-closed. The companion Slice-2 file asserts
// the accept-path (validatePolicyRule) behavior; the Phase-0 persistence file
// asserts the access-rule-with-SubjectMatch drops still hold.

// invalidAuthRule is a ruleType="auth" rule with no Auth spec — validateAuthRule
// rejects it, so policyRulePersistable must drop it fail-closed on every path.
func invalidAuthRule(name string) PolicyRule {
	return PolicyRule{Priority: 7, Name: name, RuleType: ruleTypeAuth}
}

// findRule returns the rule with the given name, or nil.
func findRule(rules []PolicyRule, name string) *PolicyRule {
	for i := range rules {
		if rules[i].Name == name {
			return &rules[i]
		}
	}
	return nil
}

// assertAuthRulePreserved fails unless the canonical valid exempt rule
// ("legacy-printer", from validExemptRule) survived intact: it is still an auth
// rule and retains its SubjectMatch + Auth spec.
func assertAuthRulePreserved(t *testing.T, rules []PolicyRule) {
	t.Helper()
	const name = "legacy-printer"
	got := findRule(rules, name)
	if got == nil {
		t.Fatalf("valid auth rule %q was not preserved", name)
	}
	if ruleTypeOf(got) != ruleTypeAuth {
		t.Errorf("rule %q lost its ruleType=auth (got %q)", name, ruleTypeOf(got))
	}
	if got.SubjectMatch == nil {
		t.Errorf("rule %q lost its SubjectMatch", name)
	}
	if got.Auth == nil {
		t.Errorf("rule %q lost its Auth spec", name)
	}
}

// ── Load ────────────────────────────────────────────────────────────────────

func TestPolicyStore_Load_PreservesValidAuthRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data, err := json.MarshalIndent([]PolicyRule{
		validExemptRule(),
		{Priority: 2, Name: "plain-allow", Action: ActionAllow},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := ps.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 rules to survive load, got %d: %+v", len(got), got)
	}
	assertAuthRulePreserved(t, got)
}

func TestPolicyStore_Load_DropsInvalidAuthRuleFailClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	data, err := json.MarshalIndent([]PolicyRule{
		invalidAuthRule("bad-auth-should-drop"),
		{Priority: 2, Name: "plain-allow", Action: ActionAllow},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := ps.List()
	if len(got) != 1 {
		t.Fatalf("expected only the valid rule to survive (invalid auth dropped), got %d: %+v", len(got), got)
	}
	if got[0].Name != "plain-allow" {
		t.Errorf("wrong rule survived load: %q", got[0].Name)
	}
	if findRule(got, "bad-auth-should-drop") != nil {
		t.Error("invalid auth rule was persisted on load (must fail-closed)")
	}
}

// ── ReplaceAll ───────────────────────────────────────────────────────────────

func TestPolicyStore_ReplaceAll_PreservesValidAuthRule(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		validExemptRule(),
		{Priority: 2, Name: "plain-allow", Action: ActionAllow},
	})
	got := ps.List()
	if len(got) != 2 {
		t.Fatalf("expected 2 rules to survive ReplaceAll, got %d: %+v", len(got), got)
	}
	assertAuthRulePreserved(t, got)
}

func TestPolicyStore_ReplaceAll_DropsInvalidAuthAndSubjectMatchAccess(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		invalidAuthRule("bad-auth-should-drop"),       // invalid auth → drop
		subjectMatchRule("scoped-access-should-drop"), // access w/ SubjectMatch → drop
		{Priority: 3, Name: "plain-allow", Action: ActionAllow},
	})
	got := ps.List()
	if len(got) != 1 {
		t.Fatalf("expected only the plain rule to survive, got %d: %+v", len(got), got)
	}
	if got[0].Name != "plain-allow" {
		t.Errorf("wrong rule survived: %q", got[0].Name)
	}
	if findRule(got, "bad-auth-should-drop") != nil {
		t.Error("invalid auth rule survived ReplaceAll (must fail-closed)")
	}
	if findRule(got, "scoped-access-should-drop") != nil {
		t.Error("access rule with SubjectMatch survived ReplaceAll (fail-open hazard)")
	}
}

// ── Config import (replace + merge) ──────────────────────────────────────────

func TestConfigImport_ReplaceMode_PreservesValidAuthRule(t *testing.T) {
	withFreshPolicyStore(t)
	body, err := json.Marshal(configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			validExemptRule(),
			{Priority: 2, Name: "import-plain", Action: ActionAllow},
		},
	})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	r := adminRequest("POST", "/api/config/import?mode=replace", string(body))
	w := httptest.NewRecorder()
	apiConfigImport(w, r)
	if w.Code != 200 {
		t.Fatalf("import returned %d: %s", w.Code, w.Body.String())
	}
	assertAuthRulePreserved(t, policyStore.List())
}

func TestConfigImport_MergeMode_PreservesValidAuthRule(t *testing.T) {
	withFreshPolicyStore(t)
	body, err := json.Marshal(configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			validExemptRule(),
			{Priority: 2, Name: "merge-plain", Action: ActionAllow},
		},
	})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	r := adminRequest("POST", "/api/config/import", string(body)) // no mode=replace → merge
	w := httptest.NewRecorder()
	apiConfigImport(w, r)
	if w.Code != 200 {
		t.Fatalf("import returned %d: %s", w.Code, w.Body.String())
	}
	assertAuthRulePreserved(t, policyStore.List())
}

// ── Config rollback ──────────────────────────────────────────────────────────

func TestApplyConfigBackup_RoundTripsValidAuthRule(t *testing.T) {
	withFreshPolicyStore(t)
	applyConfigBackup(&configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			validExemptRule(),
			{Priority: 2, Name: "rollback-plain", Action: ActionAllow},
		},
	})
	assertAuthRulePreserved(t, policyStore.List())
}

// ── Policy test endpoint (diagnostic must mirror Evaluate) ───────────────────

// A persisted auth rule appears in policyStore.List(), but /api/policy/test must
// skip it exactly as Evaluate does — otherwise the diagnostic would report an
// inert auth rule (with an empty access action) as the match instead of the
// access rule / default that real traffic uses.
func TestPolicyTest_SkipsAcceptedAuthRule(t *testing.T) {
	withFreshPolicyStore(t)
	policyStore.ReplaceAll([]PolicyRule{validExemptRule()})
	if findRule(policyStore.List(), "legacy-printer") == nil {
		t.Fatal("auth rule should be persisted in Slice 3")
	}
	w := httptest.NewRecorder()
	apiPolicyTest(w, jsonReq("POST", "/api/policy/test", map[string]any{
		"sourceIP": "10.0.5.10",           // inside the rule's 10.0.5.0/24 source
		"host":     "updates.example.com", // the rule's destFQDN
	}))
	if w.Code != 200 {
		t.Fatalf("policy test returned %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Matched bool `json:"matched"`
		Trace   []struct {
			Name       string `json:"name"`
			SkipReason string `json:"skipReason"`
		} `json:"trace"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Matched {
		t.Error("policy test must not match an inert auth rule (must mirror Evaluate)")
	}
	var found bool
	for _, tr := range resp.Trace {
		if tr.Name == "legacy-printer" {
			found = true
			if tr.SkipReason == "" {
				t.Error("auth rule must be marked skipped in the policy-test trace")
			}
		}
	}
	if !found {
		t.Error("auth rule should appear in the policy-test trace")
	}
}

// ── Cluster ConfigSnapshot ───────────────────────────────────────────────────

func TestApplyConfigSnapshot_RoundTripsValidAuthRule(t *testing.T) {
	withFreshPolicyStore(t)
	applyConfigSnapshot(ConfigSnapshot{
		PolicyRules: []PolicyRule{
			validExemptRule(),
			{Priority: 2, Name: "cluster-plain", Action: ActionAllow},
		},
	})
	assertAuthRulePreserved(t, policyStore.List())
	// Stage-2 access evaluation still ignores the round-tripped auth rule
	// (Evaluate skips non-access rules), so traffic decisions are unchanged: any
	// match it returns must be an access rule, never the exempt auth rule.
	if m := policyStore.Evaluate("10.0.5.10", "", "unauth", "updates.example.com", nil); m != nil && ruleTypeOf(m.Rule) != ruleTypeAccess {
		t.Errorf("Stage-2 Evaluate matched a non-access rule: %+v", m.Rule)
	}
}
