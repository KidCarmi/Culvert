package main

// policy_id_addressing_test.go — stable-ID (?id=<ulid>) addressing for policy
// rule update/delete (§1 identity seam). Addressing by mutable priority is racy:
// a concurrent reorder shifts priorities between a client's load and save, so a
// priority-addressed edit/delete can hit the WRONG rule. ID addressing lands on
// the rule the client actually loaded.
//
// Contract pinned here:
//   - UpdateByID/DeleteByID resolve the rule by its stable ULID regardless of
//     its current priority (proven by reordering between load and mutate);
//   - the rule's immutable ULID is preserved across an ID-addressed update;
//   - the ?id= handler path validates, guards auth rules, and mutates.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// findByIDCopy reuses List(), which returns a fully detached definition with
// materialized accounting.

func snapshotPolicyForIDTest(t *testing.T) {
	t.Helper()
	orig := policyStore.List()
	origPath := policyStore.path
	policyStore.path = ""
	t.Cleanup(func() {
		policyStore.ReplaceAll(orig)
		policyStore.path = origPath
	})
	policyStore.ReplaceAll(nil)
}

// TestUpdateByID_SurvivesReorder is the core race proof: address rule A by its
// ULID after a reorder has moved it to a different priority slot; the update
// must still land on A, not on whatever rule now occupies A's old slot.
func TestUpdateByID_SurvivesReorder(t *testing.T) {
	snapshotPolicyForIDTest(t)
	policyStore.Add(PolicyRule{Priority: 1, Name: "rule-A", Action: ActionAllow})
	policyStore.Add(PolicyRule{Priority: 2, Name: "rule-B", Action: ActionAllow})

	var aID string
	for _, r := range policyStore.List() {
		if r.Name == "rule-A" {
			aID = r.ID
		}
	}
	if aID == "" {
		t.Fatal("rule-A has no ID")
	}

	// Concurrent reorder: swap priorities so rule-A now sits at priority 2 and
	// rule-B at priority 1. A stale priority=1 edit would now hit rule-B.
	if !policyStore.PermutePriorities([]int{2, 1}) {
		t.Fatal("reorder failed")
	}

	// Address rule-A by ID and rename it. Must update A regardless of its slot.
	ok := policyStore.UpdateByID(aID, PolicyRule{Priority: 2, Name: "rule-A-renamed", Action: ActionDrop})
	if !ok {
		t.Fatal("UpdateByID returned false for a live id")
	}

	var sawRenamed, sawB bool
	for _, r := range policyStore.List() {
		if r.ID == aID {
			if r.Name != "rule-A-renamed" || r.Action != ActionDrop {
				t.Errorf("id-addressed update landed wrong: %+v", r)
			}
			sawRenamed = true
		}
		if r.Name == "rule-B" {
			sawB = true // rule-B must be untouched
		}
	}
	if !sawRenamed || !sawB {
		t.Errorf("post-update: renamedA=%v untouchedB=%v", sawRenamed, sawB)
	}
}

func TestUpdateByID_PreservesIdentity(t *testing.T) {
	snapshotPolicyForIDTest(t)
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "counted", Action: ActionAllow})

	// The incoming body omits the id (older clients don't send it); UpdateByID
	// must keep the rule's immutable ULID rather than blanking it.
	ok := policyStore.UpdateByID(added.ID, PolicyRule{Priority: 1, Name: "counted-edited", Action: ActionAllow})
	if !ok {
		t.Fatal("UpdateByID false")
	}
	for _, r := range policyStore.List() {
		if r.ID == added.ID {
			if r.Name != "counted-edited" {
				t.Errorf("name not updated: %q", r.Name)
			}
			if r.ID != added.ID {
				t.Errorf("ID must be immutable across edit: %q != %q", r.ID, added.ID)
			}
			return
		}
	}
	t.Fatal("edited rule not found by id")
}

// TestUpdateByID_PreservesCurrentPriority pins the fix for the stale-priority
// hazard: an id-addressed edit whose body carries the rule's OLD priority (a
// reorder moved it after load) must keep the rule at its CURRENT slot, never
// reclaim the old one — otherwise two rules end up sharing a priority.
func TestUpdateByID_PreservesCurrentPriority(t *testing.T) {
	snapshotPolicyForIDTest(t)
	policyStore.Add(PolicyRule{Priority: 1, Name: "pp-A", Action: ActionAllow})
	policyStore.Add(PolicyRule{Priority: 2, Name: "pp-B", Action: ActionAllow})
	var aID string
	for _, r := range policyStore.List() {
		if r.Name == "pp-A" {
			aID = r.ID
		}
	}
	// Reorder: pp-A moves to slot 2, pp-B to slot 1.
	policyStore.PermutePriorities([]int{2, 1})

	// Edit pp-A with a STALE body priority of 1 (what the client loaded).
	policyStore.UpdateByID(aID, PolicyRule{Priority: 1, Name: "pp-A-edited", Action: ActionAllow})

	seen := map[int]string{}
	for _, r := range policyStore.List() {
		if prev, dup := seen[r.Priority]; dup {
			t.Fatalf("duplicate priority %d shared by %q and %q", r.Priority, prev, r.Name)
		}
		seen[r.Priority] = r.Name
		if r.ID == aID && r.Priority != 2 {
			t.Errorf("edited rule should keep its current priority 2, got %d", r.Priority)
		}
	}
}

func TestDeleteByID_SurvivesReorder(t *testing.T) {
	snapshotPolicyForIDTest(t)
	policyStore.Add(PolicyRule{Priority: 1, Name: "del-A", Action: ActionAllow})
	policyStore.Add(PolicyRule{Priority: 2, Name: "del-B", Action: ActionAllow})
	var aID string
	for _, r := range policyStore.List() {
		if r.Name == "del-A" {
			aID = r.ID
		}
	}
	policyStore.PermutePriorities([]int{2, 1}) // move del-A to slot 2

	if !policyStore.DeleteByID(aID) {
		t.Fatal("DeleteByID false")
	}
	for _, r := range policyStore.List() {
		if r.ID == aID {
			t.Fatal("del-A still present after DeleteByID")
		}
		if r.Name != "del-B" {
			t.Errorf("unexpected surviving rule %q — DeleteByID hit the wrong rule", r.Name)
		}
	}
}

func TestUpdateByID_UnknownID_ReturnsFalse(t *testing.T) {
	snapshotPolicyForIDTest(t)
	policyStore.Add(PolicyRule{Priority: 1, Name: "only", Action: ActionAllow})
	if policyStore.UpdateByID("01NONEXISTENTIDNONEXISTENT0", PolicyRule{Name: "x", Action: ActionAllow}) {
		t.Error("UpdateByID should return false for an unknown id")
	}
	if policyStore.DeleteByID("") {
		t.Error("DeleteByID(\"\") must be false")
	}
}

// TestApiPolicyUpdate_ByID drives the handler path: PUT /api/policy?id=<ulid>
// resolves and updates the rule, returning 200.
func TestApiPolicyUpdate_ByID(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyForIDTest(t)
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "api-rule", Action: ActionAllow})

	body := `{"priority":1,"name":"api-rule-edited","action":"Drop"}`
	req := httptest.NewRequest(http.MethodPut, "/api/policy?id="+added.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiPolicyUpdate(w, adminCtx(req))

	if w.Code != http.StatusOK {
		t.Fatalf("PUT ?id= returned %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	found := false
	for _, r := range policyStore.List() {
		if r.ID == added.ID {
			found = true
			if r.Name != "api-rule-edited" || r.Action != ActionDrop {
				t.Errorf("handler id-update landed wrong: %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("rule missing after id-addressed update")
	}
}

func TestApiPolicyDelete_ByID(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyForIDTest(t)
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "api-del", Action: ActionAllow})

	req := httptest.NewRequest(http.MethodDelete, "/api/policy?id="+added.ID, http.NoBody)
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiPolicyDelete(w, adminCtx(req))

	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE ?id= returned %d, want 204 (body=%s)", w.Code, w.Body.String())
	}
	for _, r := range policyStore.List() {
		if r.ID == added.ID {
			t.Fatal("rule still present after id-addressed delete")
		}
	}
}

func assertCanonicalUniqueRuleIDs(t *testing.T, rules []PolicyRule) {
	t.Helper()
	seen := make(map[string]struct{}, len(rules))
	for i := range rules {
		rule := &rules[i]
		if !validRuleID(rule.ID) {
			t.Fatalf("rule %q has malformed ID %q", rule.Name, rule.ID)
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			t.Fatalf("rules contain duplicate ID %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
}

func TestPolicyStoreAddEnforcesCanonicalUniqueIdentity(t *testing.T) {
	ps := &PolicyStore{}
	importedID := newRuleID()
	first := ps.Add(PolicyRule{ID: importedID, Name: "imported", Action: ActionAllow})
	duplicate := ps.Add(PolicyRule{ID: importedID, Name: "duplicate", Action: ActionAllow})
	malformed := ps.Add(PolicyRule{ID: "not-a-ulid", Name: "malformed", Action: ActionAllow})
	if first.ID != importedID {
		t.Fatalf("Add changed canonical unique import ID %q to %q", importedID, first.ID)
	}
	assertCanonicalUniqueRuleIDs(t, []PolicyRule{first, duplicate, malformed})
}

func TestPolicyStoreReplaceAllNormalizesMalformedAndDuplicateIDs(t *testing.T) {
	ps := &PolicyStore{}
	preserved := newRuleID()
	ps.ReplaceAll([]PolicyRule{
		{ID: preserved, Priority: 1, Name: "preserved", Action: ActionAllow},
		{ID: preserved, Priority: 2, Name: "duplicate", Action: ActionAllow},
		{ID: "not-a-ulid", Priority: 3, Name: "malformed", Action: ActionAllow},
	})
	got := ps.List()
	assertCanonicalUniqueRuleIDs(t, got)
	if got[0].ID != preserved {
		t.Fatalf("first canonical unique ID changed from %q to %q", preserved, got[0].ID)
	}
}

func TestPolicyStoreLoadMigratesMalformedAndDuplicateIDs(t *testing.T) {
	preserved := newRuleID()
	rules := []PolicyRule{
		{ID: preserved, Priority: 1, Name: "preserved", Action: ActionAllow},
		{ID: preserved, Priority: 2, Name: "duplicate", Action: ActionAllow},
		{ID: "not-a-ulid", Priority: 3, Name: "malformed", Action: ActionAllow},
		{Priority: 4, Name: "missing", Action: ActionAllow},
	}
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}
	if err := ps.Load(path); err != nil {
		t.Fatal(err)
	}
	assertCanonicalUniqueRuleIDs(t, ps.List())
}
