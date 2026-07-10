package main

// policy_priority_dedup_test.go — Edge-case QA: duplicate-priority store
// corruption via the Add API and config-import merge mode.
//
// Root cause: validatePolicyRule checks for duplicate NAMES but not duplicate
// PRIORITIES. When a caller submits a rule with an explicit Priority that
// already exists in the store, both Add and the import merge path accept it,
// creating two rules at the same priority. Consequences:
//   - Non-deterministic policy evaluation (sort.Slice is unstable for ties).
//   - PermutePriorities fails-closed on any reorder touching that priority
//     (protected since the recent fix) — but the broken state is permanent
//     until the store is manually rebuilt.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// countRulesAtPriority returns the number of rules in the store at the given priority.
func countRulesAtPriority(pri int) int {
	n := 0
	for _, r := range policyStore.List() {
		if r.Priority == pri {
			n++
		}
	}
	return n
}

// TestAddAPI_DuplicatePriority_Rejected verifies that POST /api/policy with an
// explicit priority that already exists in the store is rejected with 409
// Conflict (or 400 Bad Request). Before the fix this returns 200, leaving the
// store with two rules at the same priority.
func TestAddAPI_DuplicatePriority_Rejected(t *testing.T) {
	withFreshPolicyStore(t)

	const clashPri = 500

	// Seed an existing rule at the chosen priority.
	policyStore.Add(PolicyRule{Priority: clashPri, Name: "existing-rule", Action: ActionAllow})
	if countRulesAtPriority(clashPri) != 1 {
		t.Fatalf("setup: expected 1 rule at priority %d", clashPri)
	}

	// Attempt to add a DIFFERENT rule at the SAME priority via the API.
	body := PolicyRule{
		Priority: clashPri,
		Name:     "duplicate-priority-rule",
		Action:   ActionDrop,
	}
	bodyJSON, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/policy", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.1:9999"
	req = adminCtx(req)

	w := httptest.NewRecorder()
	apiPolicy(w, req)

	// The request must be rejected. Before the fix, it returns 200 and
	// creates a duplicate priority.
	if w.Code == http.StatusOK {
		n := countRulesAtPriority(clashPri)
		t.Fatalf("BUG: POST /api/policy with duplicate priority %d returned 200; "+
			"store now has %d rules at that priority (want 1). "+
			"Non-deterministic evaluation and broken reorder will result.",
			clashPri, n)
	}
	if w.Code != http.StatusBadRequest && w.Code != http.StatusConflict {
		t.Errorf("expected 400 or 409 for duplicate priority, got %d: %s", w.Code, w.Body.String())
	}

	// The store must still have exactly ONE rule at the conflicting priority.
	if n := countRulesAtPriority(clashPri); n != 1 {
		t.Errorf("store has %d rules at priority %d after rejected add; want 1", n, clashPri)
	}
}

// TestConfigImportMerge_DuplicatePriority_Rejected verifies that config import
// in merge mode rejects (skips with a warning / fails) a rule whose priority
// already exists in the store. Before the fix, the rule is silently accepted,
// leaving the store with two rules at the same priority.
func TestConfigImportMerge_DuplicatePriority_Rejected(t *testing.T) {
	withFreshPolicyStore(t)

	const clashPri = 501

	// Seed an existing rule.
	policyStore.Add(PolicyRule{Priority: clashPri, Name: "seed-rule", Action: ActionAllow})
	if countRulesAtPriority(clashPri) != 1 {
		t.Fatalf("setup: expected 1 rule at priority %d", clashPri)
	}

	// Build a backup payload with a rule at the same priority (different name).
	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			{Priority: clashPri, Name: "import-clash-rule", Action: ActionDrop},
		},
	}
	bodyJSON, _ := json.Marshal(backup)
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(string(bodyJSON)))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.2:9999"
	req = adminCtx(req)

	w := httptest.NewRecorder()
	apiConfigImport(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("apiConfigImport returned %d: %s", w.Code, w.Body.String())
	}

	// After import the store must still have exactly ONE rule at clashPri.
	// Before the fix it has TWO — one from the original seed, one from the import.
	if n := countRulesAtPriority(clashPri); n != 1 {
		t.Fatalf("BUG: config import (merge mode) created %d rules at priority %d; "+
			"want 1. Store: %v", n, clashPri, policyStore.List())
	}
}

// TestReorderBrokenByDuplicatePriority confirms that once a duplicate priority
// is in the store (via any bug path), PermutePriorities fails-closed and the
// reorder API returns 400 — consistent with the recent fix — but also shows
// that the underlying corruption is a pre-condition that should not arise.
func TestReorderBrokenByDuplicatePriority(t *testing.T) {
	withFreshPolicyStore(t)

	const clashPri = 502
	const otherPri = 503

	// Force two rules with the same priority into the store via ReplaceAll
	// (the backdoor that bypass individual validation — mirrors what config
	// import replace-mode or cluster sync can produce in a degenerate config).
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: clashPri, Name: "dup-x", Action: ActionAllow},
		{Priority: clashPri, Name: "dup-y", Action: ActionAllow},
		{Priority: otherPri, Name: "other", Action: ActionDrop},
	})
	if n := countRulesAtPriority(clashPri); n != 2 {
		t.Fatalf("setup: expected 2 rules at priority %d, got %d", clashPri, n)
	}

	// Any reorder attempt that touches the duplicate priority must fail-closed.
	if ok := policyStore.PermutePriorities([]int{otherPri, clashPri}); ok {
		t.Error("PermutePriorities must return false when store has duplicate priority; got true")
	}

	// Verify the store is unchanged after the failed permutation.
	if n := countRulesAtPriority(clashPri); n != 2 {
		t.Errorf("store mutation occurred despite failed PermutePriorities: %d rules at %d", n, clashPri)
	}
	if n := countRulesAtPriority(otherPri); n != 1 {
		t.Errorf("unrelated rule at %d was affected: %d rules", otherPri, n)
	}

	// The access-only reorder API must surface this as a 400.
	w := httptest.NewRecorder()
	req := jsonReq(http.MethodPost, "/api/policy/reorder", map[string]any{
		"priorities": []int{otherPri, clashPri},
	})
	apiPolicyReorder(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("apiPolicyReorder succeeded despite duplicate priority in store; got 200, want 4xx")
	}
	t.Logf("apiPolicyReorder status with corrupt store: %d (%s)", w.Code, w.Body.String())
}

// TestValidatePolicyRule_DuplicatePriority verifies that validatePolicyRule
// returns an error when the new rule's priority already exists in the existing
// rule set (Add path: editPriority=-1).
func TestValidatePolicyRule_DuplicatePriority(t *testing.T) {
	existing := []PolicyRule{
		{Priority: 10, Name: "existing", Action: ActionAllow},
	}

	newRule := PolicyRule{
		Priority: 10,
		Name:     "new-different-name",
		Action:   ActionDrop,
	}

	err := validatePolicyRule(newRule, existing, -1)
	if err == nil {
		t.Errorf("validatePolicyRule should return an error for duplicate priority 10, got nil")
	} else {
		t.Logf("validatePolicyRule correctly returned: %v", err)
	}
}

// TestValidatePolicyRule_SamePriorityOnUpdate verifies that validatePolicyRule
// allows a rule to keep its own priority during an update (editPriority=10,
// rule.Priority=10 — not a duplicate of itself).
func TestValidatePolicyRule_SamePriorityOnUpdate(t *testing.T) {
	existing := []PolicyRule{
		{Priority: 10, Name: "the-rule", Action: ActionAllow},
		{Priority: 20, Name: "other-rule", Action: ActionDrop},
	}

	// Updating rule at priority 10: body may keep Priority=10 — should be OK.
	updateBody := PolicyRule{
		Priority: 10,
		Name:     "the-rule",
		Action:   ActionDrop, // just changing the action
	}
	if err := validatePolicyRule(updateBody, existing, 10); err != nil {
		t.Errorf("validatePolicyRule should allow keeping the same priority on update; got: %v", err)
	}

	// Updating rule at priority 10 to move to priority 20 (already taken) — must fail.
	moveToTakenPri := PolicyRule{
		Priority: 20,
		Name:     "the-rule",
		Action:   ActionAllow,
	}
	if err := validatePolicyRule(moveToTakenPri, existing, 10); err == nil {
		t.Errorf("validatePolicyRule should reject move to already-used priority 20")
	} else {
		t.Logf("correctly rejected: %v", err)
	}

	// Updating rule at priority 10 to move to priority 30 (free) — must succeed.
	moveToFreePri := PolicyRule{
		Priority: 30,
		Name:     "the-rule",
		Action:   ActionAllow,
	}
	if err := validatePolicyRule(moveToFreePri, existing, 10); err != nil {
		t.Errorf("validatePolicyRule should allow move to free priority 30; got: %v", err)
	}
}

// TestAddAPIAndReorder_GoldenPath verifies the normal workflow works correctly:
// two rules added with distinct priorities can be reordered without error.
func TestAddAPIAndReorder_GoldenPath(t *testing.T) {
	withFreshPolicyStore(t)

	// Add two rules via the API at distinct priorities.
	for _, tc := range []struct {
		pri  int
		name string
	}{
		{600, "golden-a"},
		{601, "golden-b"},
	} {
		b := PolicyRule{Priority: tc.pri, Name: tc.name, Action: ActionAllow}
		bJSON, _ := json.Marshal(b)
		req := httptest.NewRequest(http.MethodPost, "/api/policy", strings.NewReader(string(bJSON)))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.3:9999"
		req = adminCtx(req)
		w := httptest.NewRecorder()
		apiPolicy(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("add rule %q: %d %s", tc.name, w.Code, w.Body.String())
		}
	}

	// Reorder them: swap 600 and 601.
	w := httptest.NewRecorder()
	req := jsonReq(http.MethodPost, "/api/policy/reorder", map[string]any{
		"priorities": []int{601, 600},
	})
	apiPolicyReorder(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("reorder golden path failed: %d %s", w.Code, w.Body.String())
	}

	// The rule formerly at 601 should now be at 600 and vice versa.
	rules := policyStore.List()
	byPri := map[int]string{}
	for _, r := range rules {
		if r.Name == "golden-a" || r.Name == "golden-b" {
			byPri[r.Priority] = r.Name
		}
	}
	if byPri[600] != "golden-b" || byPri[601] != "golden-a" {
		t.Errorf("reorder did not swap correctly: got %v, want {600:golden-b, 601:golden-a}", byPri)
	}
	t.Logf("post-reorder priority map: %v", fmt.Sprintf("%v", byPri))
}
