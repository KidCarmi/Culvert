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

// TestPolicyTies_ExportReplaceImportRoundTrips: a current rulebase (built
// through the API, so it cannot hold a tie) exported via GET
// /api/config/export?section=policy and imported back in replace mode is
// accepted and restores exactly the same rules in the same evaluation order
// with the same default action. POL-006's replace-import refusal must never
// break the supported backup/restore round trip (owner, 2026-11-23).
func TestPolicyTies_ExportReplaceImportRoundTrips(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	origDefault := defaultPolicyAction()
	t.Cleanup(func() { setDefaultPolicyAction(origDefault) })
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll(nil)

	// Real writers: creates with explicit and absent priorities (a taken
	// priority is refused 409 by the fenced create, so it cannot tie).
	for _, body := range []map[string]any{
		{"name": "rt-a", "action": "Allow", "priority": 10, "destFQDN": "a.rt.example"},
		{"name": "rt-b", "action": "Drop", "priority": 20, "destFQDN": "b.rt.example"},
		{"name": "rt-c", "action": "Allow", "destFQDN": "c.rt.example"},                // absent: next free
		{"name": "rt-d", "action": "Drop", "priority": 30, "destFQDN": "*.rt.example"}, // catch-all after the exact rules
	} {
		w := httptest.NewRecorder()
		apiPolicyCreate(w, jsonReq("POST", "/api/policy", body))
		if w.Code != http.StatusOK {
			t.Fatalf("create %v = %d (%s)", body["name"], w.Code, w.Body.String())
		}
	}
	before := policyStore.List()
	requireNoPriorityTies(t, before)

	w := httptest.NewRecorder()
	apiConfigExport(w, adminRequest("GET", "/api/config/export?section=policy", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("export = %d (%s)", w.Code, w.Body.String())
	}
	exported := w.Body.String()

	// Diverge the live state, then restore from the export.
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "other", Action: ActionAllow}})
	setDefaultPolicyAction("allow")
	for _, path := range []string{"/api/config/import?mode=replace&dryRun=true", "/api/config/import?mode=replace"} {
		w = httptest.NewRecorder()
		apiConfigImport(w, adminRequest("POST", path, exported))
		if w.Code != http.StatusOK {
			t.Fatalf("%s of our own export = %d (%s)", path, w.Code, w.Body.String())
		}
	}

	after := policyStore.List()
	if len(after) != len(before) {
		t.Fatalf("round trip restored %d rules, want %d", len(after), len(before))
	}
	for i := range before {
		b, a := before[i], after[i]
		if a.Name != b.Name || a.Priority != b.Priority || a.Action != b.Action || a.DestFQDN != b.DestFQDN || a.ID != b.ID {
			t.Errorf("rule %d: got {%s p%d %s %s id=%s}, want {%s p%d %s %s id=%s}",
				i, a.Name, a.Priority, a.Action, a.DestFQDN, a.ID, b.Name, b.Priority, b.Action, b.DestFQDN, b.ID)
		}
	}
	if got := defaultPolicyAction(); got != "deny" {
		t.Errorf("default action after round trip = %q, want deny", got)
	}
	// Same decisions, not only the same list: each host is decided by a
	// different rule (or none), so a reorder or a lost rule changes an answer.
	for host, want := range map[string]string{
		"a.rt.example": "rt-a", "b.rt.example": "rt-b", "c.rt.example": "rt-c",
		"x.rt.example": "rt-d", "none.example": "",
	} {
		if bm, am := evalName(before, host), evalName(after, host); bm != want || am != want {
			t.Errorf("%s: decided by %q before and %q after, want %q", host, bm, am, want)
		}
	}
}

// evalName returns the name of the rule a fresh store loaded with rules
// matches for host, or "" for no match.
func evalName(rules []PolicyRule, host string) string {
	ps := &PolicyStore{}
	ps.ReplaceAll(rules)
	if m := ps.Evaluate("10.0.0.1", "", "unauth", host, nil); m != nil {
		return m.Rule.Name
	}
	return ""
}
