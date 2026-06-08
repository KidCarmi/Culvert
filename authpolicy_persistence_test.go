package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// Phase-0 hardening regression suite: no policy rule carrying a SubjectMatch may
// be persisted or activated through ANY bulk persistence path until the Stage-1
// matcher is wired. The per-rule API/import-merge paths are guarded by
// validatePolicyRule (see authpolicy_test.go); these tests cover the bulk paths
// that call PolicyStore.ReplaceAll and therefore bypass that validator.

func subjectMatchRule(name string) PolicyRule {
	return PolicyRule{
		Priority: 1,
		Name:     name,
		Action:   ActionAllow,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"10.0.0.0/8"}}},
		},
	}
}

// withFreshPolicyStore swaps in an empty global policyStore for the duration of
// a test and restores the original afterwards, so bulk-replace tests do not
// clobber state other tests rely on.
func withFreshPolicyStore(t *testing.T) {
	t.Helper()
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
	policyStore.ReplaceAll(nil)
}

// Path 1 — direct PolicyStore.ReplaceAll (the universal bulk choke point that
// cluster sync, import-replace, and rollback all funnel through).
func TestPolicyStore_ReplaceAll_DropsSubjectMatch(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		subjectMatchRule("scoped-should-drop"),
		{Priority: 2, Name: "plain-allow", Action: ActionAllow},
	})
	got := ps.List()
	if len(got) != 1 {
		t.Fatalf("expected 1 rule to survive (subjectMatch dropped), got %d: %+v", len(got), got)
	}
	if got[0].Name != "plain-allow" {
		t.Errorf("wrong rule survived: %q", got[0].Name)
	}
	for _, r := range got {
		if r.SubjectMatch != nil {
			t.Errorf("rule %q retained a SubjectMatch after ReplaceAll", r.Name)
		}
	}
}

// Path 2 — cluster Control-Plane → Data-Plane sync (applyConfigSnapshot).
func TestApplyConfigSnapshot_DropsSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	applyConfigSnapshot(ConfigSnapshot{
		PolicyRules: []PolicyRule{
			subjectMatchRule("cluster-scoped-should-drop"),
			{Priority: 2, Name: "cluster-plain", Action: ActionAllow},
		},
	})
	for _, r := range policyStore.List() {
		if r.SubjectMatch != nil {
			t.Errorf("cluster sync activated a SubjectMatch rule %q", r.Name)
		}
		if r.Name == "cluster-scoped-should-drop" {
			t.Errorf("cluster sync persisted the scoped rule %q", r.Name)
		}
	}
}

// Path 3 — config-version rollback/restore (applyConfigBackup). This path
// already filters via validatePolicyRule; lock that in as a regression.
func TestApplyConfigBackup_ExcludesSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	applyConfigBackup(&configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			subjectMatchRule("rollback-scoped-should-drop"),
			{Priority: 2, Name: "rollback-plain", Action: ActionAllow},
		},
	})
	for _, r := range policyStore.List() {
		if r.SubjectMatch != nil {
			t.Errorf("rollback activated a SubjectMatch rule %q", r.Name)
		}
		if r.Name == "rollback-scoped-should-drop" {
			t.Errorf("rollback persisted the scoped rule %q", r.Name)
		}
	}
}

// Path 4 — config import in REPLACE mode (apiConfigImport ?mode=replace),
// which calls policyStore.ReplaceAll directly.
func TestConfigImport_ReplaceMode_DropsSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			subjectMatchRule("import-scoped-should-drop"),
			{Priority: 2, Name: "import-plain", Action: ActionAllow},
		},
	}
	body, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	r := adminRequest("POST", "/api/config/import?mode=replace", string(body))
	w := httptest.NewRecorder()
	apiConfigImport(w, r)
	if w.Code != 200 {
		t.Fatalf("import returned %d: %s", w.Code, w.Body.String())
	}
	for _, rule := range policyStore.List() {
		if rule.SubjectMatch != nil {
			t.Errorf("import (replace) activated a SubjectMatch rule %q", rule.Name)
		}
		if rule.Name == "import-scoped-should-drop" {
			t.Errorf("import (replace) persisted the scoped rule %q", rule.Name)
		}
	}
}

// Path 5 — config import in MERGE mode (apiConfigImport default), which uses the
// per-rule validatePolicyRule + Add path.
func TestConfigImport_MergeMode_RejectsSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			subjectMatchRule("merge-scoped-should-skip"),
			{Priority: 2, Name: "merge-plain", Action: ActionAllow},
		},
	}
	body, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	r := adminRequest("POST", "/api/config/import", string(body)) // no mode=replace → merge
	w := httptest.NewRecorder()
	apiConfigImport(w, r)
	if w.Code != 200 {
		t.Fatalf("import returned %d: %s", w.Code, w.Body.String())
	}
	for _, rule := range policyStore.List() {
		if rule.SubjectMatch != nil {
			t.Errorf("import (merge) activated a SubjectMatch rule %q", rule.Name)
		}
		if rule.Name == "merge-scoped-should-skip" {
			t.Errorf("import (merge) persisted the scoped rule %q", rule.Name)
		}
	}
}
