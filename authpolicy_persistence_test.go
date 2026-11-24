package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Phase-0 hardening regression suite: no policy rule carrying a SubjectMatch may
// be persisted or activated through ANY bulk persistence path until the Stage-1
// matcher is wired. The per-rule API/import-merge paths are guarded by
// validatePolicyRule (see authpolicy_test.go); these tests cover the bulk paths
// that call PolicyStore.ReplaceAll and therefore bypass that validator.
//
// POL-005: the bulk doors used to DROP such a rule and install the rest. That
// is fail-open for a rule that restricts, so a ruleset holding one is now
// refused WHOLE and the previous policy stays in place. The tests below pin
// both halves: the rule is never activated, and nothing else changes either.

// lkgRule is a rule a store holds BEFORE a refused replacement, so "unchanged"
// can be told apart from "emptied".
func lkgRule() PolicyRule {
	return PolicyRule{Priority: 1, Name: "last-known-good", DestFQDN: "blocked.example.com", Action: ActionBlockPage}
}

func ruleNamesOf(rules []PolicyRule) string {
	names := make([]string, 0, len(rules))
	for i := range rules {
		names = append(names, rules[i].Name)
	}
	return strings.Join(names, ",")
}

// assertReplaceAllRefusedWhole offers rules to a store that already holds
// lkgRule and requires the POL-005 outcome: the store is exactly as it was and
// Diagnostics carries the unenforceable-rule refusal row.
func assertReplaceAllRefusedWhole(t *testing.T, rules []PolicyRule) {
	t.Helper()
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{lkgRule()})
	ps.ReplaceAll(rules)
	if got := ruleNamesOf(ps.List()); got != "last-known-good" {
		t.Fatalf("after a refused ReplaceAll the store holds [%s], want [last-known-good]: the refusal must be whole, not a partial apply", got)
	}
	rows := checkPolicyRulesetRefused(ps)
	if len(rows) != 1 || rows[0].Code != "policy_ruleset_refused_unenforceable_rule" {
		t.Errorf("Diagnostics rows after a refused ReplaceAll = %+v, want one policy_ruleset_refused_unenforceable_rule", rows)
	}
}

// assertLoadRefusedWhole writes body as a policy file and requires the POL-005
// outcome on both a fresh store (nothing installed) and a store that already
// holds a loaded policy (rules, path and configured count unchanged). It
// returns the typed error from the fresh store.
func assertLoadRefusedWhole(t *testing.T, body []byte, wantRule string) *unenforceableRuleError {
	t.Helper()
	dir := t.TempDir()
	bad := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(bad, body, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	fresh := &PolicyStore{}
	err := fresh.Load(bad)
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) {
		t.Fatalf("Load = %v, want an *unenforceableRuleError", err)
	}
	if ue.Name != wantRule {
		t.Errorf("refusal names rule %q, want %q", ue.Name, wantRule)
	}
	if n := len(fresh.List()); n != 0 {
		t.Errorf("a fresh store installed %d rule(s) from a refused file, want 0", n)
	}

	good := filepath.Join(dir, "good.json")
	data, merr := json.Marshal([]PolicyRule{lkgRule()})
	if merr != nil {
		t.Fatalf("marshal: %v", merr)
	}
	if err := os.WriteFile(good, data, 0o600); err != nil {
		t.Fatalf("write good file: %v", err)
	}
	held := &PolicyStore{}
	if err := held.Load(good); err != nil {
		t.Fatalf("Load of the good file: %v", err)
	}
	if err := held.Load(bad); err == nil {
		t.Fatal("reload of a refused file returned nil")
	}
	if got := ruleNamesOf(held.List()); got != "last-known-good" {
		t.Errorf("after a refused reload the store holds [%s], want [last-known-good]", got)
	}
	if held.path != good {
		t.Errorf("a refused reload adopted path %q, want %q", held.path, good)
	}
	if n := held.ConfiguredRuleCount(); n != 1 {
		t.Errorf("ConfiguredRuleCount after a refused reload = %d, want 1", n)
	}
	return ue
}

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
// cluster sync, import-replace, and rollback all funnel through). A ruleset
// holding a subjectMatch access rule is refused whole (POL-005): the scoped rule
// is never activated and the rules the store already held are untouched.
func TestPolicyStore_ReplaceAll_RefusesRulesetWithSubjectMatch(t *testing.T) {
	assertReplaceAllRefusedWhole(t, []PolicyRule{
		subjectMatchRule("scoped-must-not-activate"),
		{Priority: 2, Name: "plain-allow", Action: ActionAllow},
	})
	// Control: the same ruleset without the scoped rule is accepted.
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 2, Name: "plain-allow", Action: ActionAllow}})
	if got := ruleNamesOf(ps.List()); got != "plain-allow" {
		t.Errorf("clean ruleset not installed: [%s]", got)
	}
	if rows := checkPolicyRulesetRefused(ps); rows != nil {
		t.Errorf("clean ruleset produced a refusal row: %+v", rows)
	}
}

// Path 2 — cluster Control-Plane → Data-Plane sync (applyConfigSnapshot). The
// snapshot is refused before any mutation (POL-005): an error is returned and
// the rules that were running are still running.
func TestApplyConfigSnapshot_RefusesRulesetWithSubjectMatch(t *testing.T) {
	bindFreshAdmissionOwners(t) // the snapshot apply mutates ipf/rl in place (RISK-030)
	withFreshPolicyStore(t)
	policyStore.ReplaceAll([]PolicyRule{lkgRule()})
	err := applyConfigSnapshot(ConfigSnapshot{
		PolicyRules: []PolicyRule{
			subjectMatchRule("cluster-scoped"),
			{Priority: 2, Name: "cluster-plain", Action: ActionAllow},
		},
	})
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) || ue.Name != "cluster-scoped" {
		t.Fatalf("applyConfigSnapshot returned %v, want an unenforceableRuleError naming cluster-scoped", err)
	}
	if got := ruleNamesOf(policyStore.List()); got != lkgRule().Name {
		t.Errorf("running policy after a refused snapshot is %q, want only %q", got, lkgRule().Name)
	}
}

// Path 3 — config-version rollback/restore (applyConfigBackup). A stored
// version holding such a rule is refused whole: an error, and nothing restored.
func TestApplyConfigBackup_RefusesRulesetWithSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	policyStore.ReplaceAll([]PolicyRule{lkgRule()})
	err := applyConfigBackup(&configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			subjectMatchRule("rollback-scoped"),
			{Priority: 2, Name: "rollback-plain", Action: ActionAllow},
		},
	})
	var ue *unenforceableRuleError
	if !errors.As(err, &ue) || ue.Name != "rollback-scoped" {
		t.Fatalf("applyConfigBackup returned %v, want an unenforceableRuleError naming rollback-scoped", err)
	}
	if got := ruleNamesOf(policyStore.List()); got != lkgRule().Name {
		t.Errorf("running policy after a refused restore is %q, want only %q", got, lkgRule().Name)
	}
}

// Path 4 — config import in REPLACE mode (apiConfigImport ?mode=replace). The
// import is refused whole with a 400 (POL-005): the scoped rule is not
// activated, its valid neighbour is not applied, the running policy is as it was.
func TestConfigImport_ReplaceMode_RefusesRulesetWithSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	policyStore.ReplaceAll([]PolicyRule{lkgRule()})
	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			subjectMatchRule("import-scoped-must-not-activate"),
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
	if w.Code != 400 || !strings.Contains(w.Body.String(), "import refused") {
		t.Fatalf("import (replace) = %d %q, want 400 import refused", w.Code, w.Body.String())
	}
	if got := ruleNamesOf(policyStore.List()); got != "last-known-good" {
		t.Errorf("import (replace) left the running policy as [%s], want [last-known-good]: nothing may be applied from a refused import", got)
	}
}

// Path 5 — config import in MERGE mode (apiConfigImport default). It used to
// skip the scoped rule and merge the rest; the gate now runs at the door in both
// modes, so the whole import is refused with a 400 (POL-005).
func TestConfigImport_MergeMode_RefusesRulesetWithSubjectMatch(t *testing.T) {
	withFreshPolicyStore(t)
	t.Cleanup(func() { policyStore.rulesetRefused.Store(nil) })
	policyStore.ReplaceAll([]PolicyRule{lkgRule()})
	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			subjectMatchRule("merge-scoped-must-not-activate"),
			{Priority: 2, Name: "import-plain", Action: ActionAllow},
		},
	}
	body, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}
	r := adminRequest("POST", "/api/config/import", string(body))
	w := httptest.NewRecorder()
	apiConfigImport(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "import refused") {
		t.Fatalf("import (merge) = %d %q, want 400 import refused", w.Code, w.Body.String())
	}
	if got := ruleNamesOf(policyStore.List()); got != "last-known-good" {
		t.Errorf("import (merge) left the running policy as [%s], want [last-known-good]: nothing may be applied from a refused import", got)
	}
}

// Path 6 — PolicyStore.Load (startup and reload) reads policy.json directly. A
// subjectMatch rule from a hand-edited or newer-version file must never be
// activated (Evaluate ignores the selector). The file is refused whole
// (POL-005): nothing is installed from it and a store that already held a
// policy keeps it.
func TestPolicyStore_Load_RefusesFileWithSubjectMatch(t *testing.T) {
	body := `[
		{"priority":1,"name":"scoped-must-not-activate","action":"Allow",
		 "subjectMatch":{"schemaVersion":1,"all":[{"type":"cidr","values":["10.0.0.0/8"]}]}},
		{"priority":2,"name":"plain-allow","action":"Allow"}
	]`
	ue := assertLoadRefusedWhole(t, []byte(body), "scoped-must-not-activate")
	if ue.Count != 1 || !strings.Contains(ue.Reason, "subjectMatch") {
		t.Errorf("refusal = count %d reason %q, want 1 rule refused for its subjectMatch", ue.Count, ue.Reason)
	}
}
