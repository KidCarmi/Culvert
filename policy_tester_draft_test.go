package main

// F4 (ADR-0026 / GAP-POL-03): the Policy Tester evaluates the EFFECTIVE
// rulebase — the draft candidate when Draft Mode is engaged, else running — and
// reports which via the `rulebase` field. It also inherits the canonical
// evaluator core's enforcement semantics: disabled rules are skipped (they can
// never match at runtime), where the pre-ADR-0026 tester walk matched them.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testerRoleReq builds a JSON /api/policy/test request carrying a UI role.
func testerRoleReq(t *testing.T, role UIRole, body any) *http.Request {
	t.Helper()
	r := jsonReq(http.MethodPost, "/api/policy/test", body)
	return r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
}

func decodeTesterResp(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("apiPolicyTest = %d (%s)", w.Code, w.Body.String())
	}
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode tester response: %v (%s)", err, w.Body.String())
	}
	return m
}

// TestPolicyTester_SkipsDisabledRule: a disabled rule that would otherwise match
// is now skipped ("disabled") and never returned as the match — matching the
// enforcement path, which skips disabled rules.
func TestPolicyTester_SkipsDisabledRule(t *testing.T) {
	disabled := false
	rules := []PolicyRule{
		{Priority: 1, Name: "disabled-match", DestFQDN: "*", Action: ActionAllow, Enabled: &disabled},
		{Priority: 2, Name: "enabled-block", DestFQDN: "blocked.example", Action: ActionBlockPage},
	}
	trace, matched := walkPolicyTestRules(rules, "1.2.3.4", "", "unauth", "anything.example", nil)

	if matched != nil {
		t.Fatalf("disabled rule was returned as the match: %q", matched.Name)
	}
	var sawDisabledSkip bool
	for _, row := range trace {
		if row.Name == "disabled-match" {
			if row.SkipReason != accessSkipDisabled {
				t.Errorf("disabled rule trace skip = %q, want %q", row.SkipReason, accessSkipDisabled)
			}
			sawDisabledSkip = true
		}
	}
	if !sawDisabledSkip {
		t.Error("disabled rule missing from the trace")
	}
}

// TestPolicyTester_RunningRulebase: with Draft Mode off, the tester evaluates
// the running store and reports rulebase="running".
func TestPolicyTester_RunningRulebase(t *testing.T) {
	draftTestSetup(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "running-allow", DestFQDN: "*", Action: ActionAllow},
	})
	t.Cleanup(func() { policyStore.ReplaceAll(nil) })

	w := httptest.NewRecorder()
	apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": "example.com"}))
	m := decodeTesterResp(t, w)

	if m["rulebase"] != "running" {
		t.Errorf("rulebase = %v, want running", m["rulebase"])
	}
	if m["matched"] != true {
		t.Errorf("expected a match against the running allow rule; got %v", m["matched"])
	}
	if rule, _ := m["rule"].(map[string]any); rule["name"] != "running-allow" {
		t.Errorf("matched rule = %v, want running-allow", rule["name"])
	}
}

// TestPolicyTester_DraftRulebase: with Draft Mode engaged, the tester evaluates
// the CANDIDATE (not running) and reports rulebase="draft". This is GAP-POL-03
// closed — a proposed rule can be validated before commit.
func TestPolicyTester_DraftRulebase(t *testing.T) {
	draftTestSetup(t)
	// Running is empty (default deny). Before the draft, the tester finds no
	// match; the candidate will add the ONLY allow rule, so a draft-mode match
	// proves the tester evaluated the candidate rather than running.
	policyStore.ReplaceAll(nil)
	t.Cleanup(func() { policyStore.ReplaceAll(nil) })

	// Baseline: running mode, no rules → no match, rulebase=running.
	w0 := httptest.NewRecorder()
	apiPolicyTest(w0, testerRoleReq(t, RoleViewer, map[string]any{"host": "example.com"}))
	m0 := decodeTesterResp(t, w0)
	if m0["rulebase"] != "running" || m0["matched"] != false {
		t.Fatalf("baseline: rulebase=%v matched=%v, want running/false", m0["rulebase"], m0["matched"])
	}

	// Arm Draft Mode and stage the only candidate rule via the canonical path.
	setRequireCommit(true)
	if w := createRuleViaAPI(t, "candidate-allow", ""); w.Code != http.StatusOK {
		t.Fatalf("stage candidate = %d (%s)", w.Code, w.Body.String())
	}
	if !policyDraftEngaged() {
		t.Fatal("draft not engaged after staging")
	}

	w := httptest.NewRecorder()
	apiPolicyTest(w, testerRoleReq(t, RoleViewer, map[string]any{"host": "example.com"}))
	m := decodeTesterResp(t, w)

	if m["rulebase"] != "draft" {
		t.Fatalf("rulebase = %v, want draft", m["rulebase"])
	}
	if m["matched"] != true {
		t.Fatalf("expected a match against the candidate; got %v (body %s)", m["matched"], w.Body.String())
	}
	rule, _ := m["rule"].(map[string]any)
	if rule["name"] != "candidate-allow" {
		t.Errorf("matched rule = %v, want candidate-allow (tester did not evaluate the draft)", rule["name"])
	}

	// Running is untouched by the simulation — still empty.
	if len(policyStore.List()) != 0 {
		t.Errorf("running store changed during a draft-mode simulation: %d rules", len(policyStore.List()))
	}
}
