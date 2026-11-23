package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// policy_tie_api_test.go — POL-006: API, import and draft-commit writes cannot
// create a duplicate priority. Load, rollback and CP→DP stay faithful restores
// (policy_tie_order_test.go).

func requireNoPriorityTies(t *testing.T, rules []PolicyRule) {
	t.Helper()
	if ties := policyPriorityTies(rules); len(ties) > 0 {
		t.Fatalf("rulebase has duplicate priorities: %s", describePolicyPriorityTies(ties, 10))
	}
}

// TestPolicyTies_PutByPriorityWithoutBodyPriorityKeepsStoredSlot: PUT
// /api/policy?priority=N with a body priority of 0 (absent) or below keeps the
// addressed rule's priority, as an id-addressed edit does. Previously the body
// value was stored verbatim, so two such edits put two rules at priority 0.
func TestPolicyTies_PutByPriorityWithoutBodyPriorityKeepsStoredSlot(t *testing.T) {
	draftTestSetup(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 10, Name: "a", Action: ActionAllow},
		{Priority: 20, Name: "b", Action: ActionAllow},
	})
	for _, tc := range []struct {
		addr int
		body map[string]any
	}{
		{10, map[string]any{"name": "a2", "action": "Drop"}},                  // priority absent
		{20, map[string]any{"name": "b2", "action": "Drop", "priority": 0}},   // explicit 0
		{10, map[string]any{"name": "a3", "action": "Allow", "priority": -4}}, // negative
	} {
		w := httptest.NewRecorder()
		apiPolicyUpdate(w, jsonReq(http.MethodPut, "/api/policy?priority="+strconv.Itoa(tc.addr), tc.body))
		if w.Code != http.StatusOK {
			t.Fatalf("PUT ?priority=%d %v = %d (%s)", tc.addr, tc.body, w.Code, w.Body.String())
		}
		if got := priorityOf(policyStore.List(), tc.body["name"].(string)); got != tc.addr {
			t.Errorf("%v stored at priority %d, want the addressed slot %d", tc.body, got, tc.addr)
		}
	}
	requireNoPriorityTies(t, policyStore.List())

	// The store-level guard holds for any caller of Update.
	if !policyStore.Update(20, PolicyRule{Name: "b3", Action: ActionAllow}) {
		t.Fatal("Update failed")
	}
	if got := priorityOf(policyStore.List(), "b3"); got != 20 {
		t.Errorf("Update with priority 0 stored %d, want 20", got)
	}
	requireNoPriorityTies(t, policyStore.List())
}

// TestPolicyTies_DraftCommitRefusesNewTieButKeepsInheritedOne: the draft
// commit's per-rule validation passes each rule's own priority as editPriority
// and is tie-blind; the set-level check refuses a candidate with a NEW shared
// priority (400 naming both rules, nothing activated), while a tie inherited
// unchanged from running does not strand the draft.
func TestPolicyTies_DraftCommitRefusesNewTieButKeepsInheritedOne(t *testing.T) {
	draftTestSetup(t)
	setRequireCommit(true)
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 10, Name: "a", Action: ActionAllow},
		{Priority: 20, Name: "b", Action: ActionAllow},
	})
	running := policyStore.List()

	cand := policyDraft.stageTarget("tester")
	staged := cand.List()
	staged = append(staged, PolicyRule{Priority: 20, Name: "c", Action: ActionDrop})
	cand.ReplaceAll(staged)

	w := httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq(http.MethodPost, "/api/policy/draft/commit", map[string]any{"comment": "tie"}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"b" and "c" share priority 20`) {
		t.Fatalf("commit with a new tie = %d (%s), want 400 naming b and c", w.Code, w.Body.String())
	}
	if got := policyStore.List(); len(got) != len(running) {
		t.Fatalf("refused commit changed running: %d rules", len(got))
	}
	if !policyDraft.active() {
		t.Fatal("refused commit discarded the draft")
	}

	// Inherited tie: running already holds one (a faithful restore); a draft
	// that leaves it alone commits.
	policyDraft.clear()
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 10, Name: "a", Action: ActionAllow},
		{Priority: 10, Name: "a-twin", Action: ActionDrop},
		{Priority: 20, Name: "b", Action: ActionAllow},
	})
	if w := createRuleViaAPI(t, "new-unique", ""); w.Code != http.StatusOK {
		t.Fatalf("stage = %d (%s)", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiPolicyDraftCommit(w, jsonReq(http.MethodPost, "/api/policy/draft/commit", map[string]any{"comment": "inherited"}))
	if w.Code != http.StatusOK {
		t.Fatalf("commit with only an inherited tie = %d (%s)", w.Code, w.Body.String())
	}
	got := tieGroupsByName(policyStore.List())
	if names := got[10]; len(names) != 2 || names[0] != "a" || names[1] != "a-twin" {
		t.Fatalf("inherited tie not kept in stored order: %v", got)
	}
}

// TestPolicyTies_ReplaceImportRefusesDuplicatePriorities: a replace-mode import
// whose rules share a priority answers 400 naming the colliding rules, at
// preview and at commit, and changes nothing. Merge mode is unaffected (Add
// reassigns a taken priority).
func TestPolicyTies_ReplaceImportRefusesDuplicatePriorities(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "live", Action: ActionAllow}})
	backup := configBackup{
		Version: 1,
		PolicyRules: []PolicyRule{
			{Priority: 3, Name: "x", Action: ActionAllow},
			{Priority: 7, Name: "dup-one", Action: ActionAllow},
			{Priority: 7, Name: "dup-two", Action: ActionDrop},
		},
	}
	body, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/config/import?mode=replace&dryRun=true", "/api/config/import?mode=replace"} {
		w := httptest.NewRecorder()
		apiConfigImport(w, adminRequest("POST", path, string(body)))
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `priority 7: "dup-one", "dup-two"`) {
			t.Fatalf("%s = %d (%s), want 400 naming dup-one and dup-two", path, w.Code, w.Body.String())
		}
		if got := policyStore.List(); len(got) != 1 || got[0].Name != "live" {
			t.Fatalf("%s: refused import changed the rulebase: %+v", path, got)
		}
	}

	// Unique priorities import.
	backup.PolicyRules[2].Priority = 8
	body, _ = json.Marshal(backup)
	w := httptest.NewRecorder()
	apiConfigImport(w, adminRequest("POST", "/api/config/import?mode=replace", string(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("unique replace import = %d (%s)", w.Code, w.Body.String())
	}
	requireNoPriorityTies(t, policyStore.List())
}
