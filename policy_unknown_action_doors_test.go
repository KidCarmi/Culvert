package main

// POL-004 at the doors the first fix did not reach.
//
// An independent review of the retain-and-block change found two stored-data
// paths that still ran the exact INGRESS validator over rules already in the
// rulebase, and so undid the retention:
//
//   - config-version rollback filtered the snapshot before ReplaceAll and
//     silently dropped a retained unknown-action rule, letting its traffic fall
//     through to a lower Allow;
//   - draft commit validated every candidate rule, including the ones inherited
//     from the running policy, so one retained rule made every commit fail.
//
// It also noted the only operator signal was a level-gated log line. The
// diagnostics row below is computed from the live rulebase instead.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pol004RunningRuleNames() string {
	rules := policyStore.List()
	names := make([]string, len(rules))
	for i := range rules {
		names[i] = rules[i].Name + "=" + string(rules[i].Action)
	}
	return strings.Join(names, ",")
}

func TestPOL004_RollbackKeepsARetainedUnknownActionRule(t *testing.T) {
	csrIsolateRollbackStores(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "future-restriction", DestFQDN: "blocked.example.com", Action: "Quarantine"},
		{Priority: 2, Name: "later-allow", DestFQDN: "*", Action: ActionAllow},
	})
	snapshot := captureConfigBackup()

	if warnings := validateConfigBackup(snapshot); strings.Contains(strings.Join(warnings, "\n"), "will be skipped") {
		t.Errorf("rollback preview announces a skipped rule for a snapshot whose only oddity is an unknown action: %v", warnings)
	}
	if err := applyConfigBackup(snapshot); err != nil {
		t.Fatalf("applyConfigBackup: %v", err)
	}

	if got := pol004RunningRuleNames(); got != "future-restriction=Quarantine,later-allow=Allow" {
		t.Fatalf("after rollback the running policy is [%s]; the unknown-action rule must survive with its action intact", got)
	}
	m := policyStore.Evaluate("203.0.113.9", "", "", "blocked.example.com", nil)
	if m == nil || m.Rule == nil || m.Rule.Name != "future-restriction" {
		t.Fatalf("after rollback blocked.example.com matches %+v; POL-004: it must still match the unknown-action rule, not fall through to the Allow behind it", m)
	}
	// Control: a rule that is invalid for another reason is still skipped.
	snapshot.PolicyRules = append(snapshot.PolicyRules, PolicyRule{Priority: 3, Name: "bad-redirect", DestFQDN: "x.example.com", Action: ActionRedirect})
	if err := applyConfigBackup(snapshot); err != nil {
		t.Fatalf("applyConfigBackup: %v", err)
	}
	if got := pol004RunningRuleNames(); strings.Contains(got, "bad-redirect") {
		t.Errorf("a Redirect rule with no URL was restored: [%s]; only an unknown ACTION is tolerated on stored data", got)
	}
}

func TestPOL004_DraftCommitIsNotBlockedByAnInheritedUnknownActionRule(t *testing.T) {
	draftTestSetup(t)
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "future-restriction", DestFQDN: "blocked.example.com", Action: "Quarantine"}})
	setRequireCommit(true)
	createRuleViaAPI(t, "unrelated-new-rule", "")

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq("POST", "/api/policy/draft/commit", map[string]any{"comment": "add an unrelated rule"}))
	if w.Code != http.StatusOK {
		t.Fatalf("commit with an inherited unknown-action rule in the candidate = %d (%s); an administrator must be able to commit unrelated changes without deleting the restriction", w.Code, w.Body.String())
	}
	got := pol004RunningRuleNames()
	if !strings.Contains(got, "future-restriction=Quarantine") || !strings.Contains(got, "unrelated-new-rule=") {
		t.Errorf("after commit the running policy is [%s]; want the retained rule unchanged plus the new one", got)
	}
}

// TestPOL004_CandidateValidationStaysStrictForEverythingElse: the tolerance is
// for a rule inherited unchanged, and nothing wider.
func TestPOL004_CandidateValidationStaysStrictForEverythingElse(t *testing.T) {
	running := []PolicyRule{{ID: "01RUNNING", Priority: 1, Name: "kept", DestFQDN: "a.example.com", Action: "Quarantine"}}
	inherited := retainedUnknownActions(running)

	cand := []PolicyRule{
		{ID: "01RUNNING", Priority: 1, Name: "kept", DestFQDN: "a.example.com", Action: "Quarantine"},      // inherited unchanged
		{ID: "01RUNNING2", Priority: 2, Name: "new-unknown", DestFQDN: "b.example.com", Action: "Isolate"}, // not in running
		{ID: "01RUNNING", Priority: 3, Name: "changed", DestFQDN: "c.example.com", Action: "Isolate"},      // same ID, different unknown action
		{ID: "01OK", Priority: 4, Name: "ok", DestFQDN: "d.example.com", Action: ActionAllow},
	}
	if err := validateCandidateRule(cand, 0, inherited); err != nil {
		t.Errorf("inherited unknown-action rule refused: %v", err)
	}
	for _, i := range []int{1, 2} {
		if err := validateCandidateRule(cand, i, inherited); err == nil {
			t.Errorf("candidate rule %q with unknown action %q was accepted; only a rule inherited unchanged from running may carry one", cand[i].Name, cand[i].Action)
		}
	}
	if err := validateCandidateRule(cand, 3, inherited); err != nil {
		t.Errorf("ordinary Allow rule refused: %v", err)
	}
	// The stored-data validator tolerates the action and nothing else.
	if err := validateStoredPolicyRule(PolicyRule{Priority: 1, Name: "x", DestFQDN: "a.example.com", Action: "Quarantine", SubjectMatch: &SubjectMatch{SchemaVersion: 1}}, nil, -1); err == nil {
		t.Error("validateStoredPolicyRule accepted a subjectMatch-bearing access rule because the action was unknown")
	}
	if err := validateStoredPolicyRule(PolicyRule{Priority: 1, Name: "x", DestFQDN: "a.example.com", Action: "Quarantine"}, nil, -1); err != nil {
		t.Errorf("validateStoredPolicyRule refused an otherwise valid rule with an unknown action: %v", err)
	}
	if err := validateStoredPolicyRule(PolicyRule{Priority: 1, Name: "x", DestFQDN: "a.example.com", Action: "allow"}, nil, -1); err == nil {
		t.Error("validateStoredPolicyRule accepted a sloppy spelling of a KNOWN action; the exemption is for unknown actions only")
	}
}

func TestPOL004_DiagnosticsRowListsRetainedRulesFromTheLiveRulebase(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "known", DestFQDN: "a.example.com", Action: ActionAllow},
		{Priority: 2, Name: "empty", DestFQDN: "b.example.com", Action: ""},
	})
	if rows := checkPolicyRulesUnknownAction(ps); rows != nil {
		t.Fatalf("row reported with no unknown-action rule: %+v", rows)
	}
	ps.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "future-a", DestFQDN: "a.example.com", Action: "Quarantine"},
		{Priority: 2, Name: "evil\nname", DestFQDN: "b.example.com", Action: "Isolate\r\nX"},
		{Priority: 3, Name: "known", DestFQDN: "c.example.com", Action: ActionAllow},
	})
	rows := checkPolicyRulesUnknownAction(ps)
	if len(rows) != 1 || rows[0].Code != "policy_rules_unknown_action" || rows[0].Status != diagWarn {
		t.Fatalf("rows = %+v, want one warn row policy_rules_unknown_action", rows)
	}
	msg := rows[0].Message
	if !strings.HasPrefix(msg, "2 rule(s)") || !strings.Contains(msg, `future-a`) || !strings.Contains(msg, `Quarantine`) {
		t.Errorf("message does not count and name the retained rules: %q", msg)
	}
	if strings.ContainsAny(msg, "\r\n") {
		t.Errorf("message carries a raw line break from a rule name or action: %q", msg)
	}
	// Clears when the rule is gone: it is computed, not remembered.
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "known", DestFQDN: "c.example.com", Action: ActionAllow}})
	if rows := checkPolicyRulesUnknownAction(ps); rows != nil {
		t.Errorf("row still reported after the rule was removed: %+v", rows)
	}
}
