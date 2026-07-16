package main

// policy_import_upsert_test.go — merge-mode config import UPSERTS policy rules
// by identity (stable ULID, then a one-time name fallback) instead of blindly
// appending, so an idempotent re-import no longer accumulates duplicates
// (POLICY-ARCHITECTURE-FUTURE §1, the P0 "kills the duplicate-accumulation
// problem" item). Covers the store helpers (matchForImport / countImportUpserts)
// and the handler (apiConfigImport merge branch).

import (
	"net/http/httptest"
	"testing"
)

func countRulesNamed(t *testing.T, name string) int {
	t.Helper()
	n := 0
	rules := policyStore.List()
	for i := range rules {
		if rules[i].Name == name {
			n++
		}
	}
	return n
}

// importMergeRules POSTs a merge-mode import of the given rules and asserts 200.
func importMergeRules(t *testing.T, rules []map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import", map[string]any{
		"version":     1,
		"exportedAt":  "2026-07-13T00:00:00Z",
		"policyRules": rules,
	}))
	assertStatus(t, w, 200)
}

// TestImport_IdempotentByID: importing the SAME rule (same ULID) twice in merge
// mode updates in place — one rule, not two. This is the core duplicate-
// accumulation fix.
func TestImport_IdempotentByID(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll(nil)

	id := newRuleID()
	rule := map[string]any{"name": "dedupe-me", "action": "Allow", "id": id}
	importMergeRules(t, []map[string]any{rule})
	if got := countRulesNamed(t, "dedupe-me"); got != 1 {
		t.Fatalf("after first import: %d rules named dedupe-me, want 1", got)
	}

	// Re-import the same rule with changed content — must UPDATE, not duplicate.
	rule["action"] = "Block_Page"
	importMergeRules(t, []map[string]any{rule})
	if got := countRulesNamed(t, "dedupe-me"); got != 1 {
		t.Fatalf("after re-import: %d rules named dedupe-me, want 1 (duplicate accumulated)", got)
	}
	if g := policyStore.findByIDCopy(id); g == nil || g.Action != ActionBlockPage {
		t.Errorf("re-import did not update content: %+v", g)
	}
}

// TestImport_NameFallbackAdoptsID: a legacy backup rule with a matching NAME but
// no id upserts the existing rule and adopts its ULID (the one-time migration
// bridge), rather than creating a second rule with the same name.
func TestImport_NameFallbackAdoptsID(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll(nil)

	added := policyStore.Add(PolicyRule{Name: "by-name", Action: ActionAllow})
	if added.ID == "" {
		t.Fatal("seeded rule has no ID")
	}

	// Incoming rule: same name, NO id, different content.
	importMergeRules(t, []map[string]any{{"name": "by-name", "action": "Drop"}})
	if got := countRulesNamed(t, "by-name"); got != 1 {
		t.Fatalf("name-fallback produced %d rules named by-name, want 1", got)
	}
	g := policyStore.findByIDCopy(added.ID)
	if g == nil {
		t.Fatalf("name-fallback did not upsert onto the existing ID %s", added.ID)
	}
	if g.Action != ActionDrop {
		t.Errorf("name-fallback did not apply content: action=%q want drop", g.Action)
	}
}

// TestImport_NewRuleAdded: a genuinely new rule (no id match, no name match) is
// added — upsert must not swallow new content.
func TestImport_NewRuleAdded(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll([]PolicyRule{{Name: "keep", Action: ActionAllow}})

	importMergeRules(t, []map[string]any{{"name": "brand-new", "action": "Allow"}})
	if countRulesNamed(t, "keep") != 1 || countRulesNamed(t, "brand-new") != 1 {
		t.Errorf("expected both keep and brand-new to be present; got keep=%d new=%d",
			countRulesNamed(t, "keep"), countRulesNamed(t, "brand-new"))
	}
}

// TestImport_UpsertPreservesPosition: an upsert keeps the live rule's priority
// (position) even when the payload carries a different priority — UpdateByID
// semantics, not a fresh Add that would append at the end.
func TestImport_UpsertPreservesPosition(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "first", Action: ActionAllow},
		{Name: "target", Action: ActionAllow},
		{Name: "third", Action: ActionAllow},
	})
	target := findRuleByName(t, "target")
	origPriority := target.Priority

	// Re-import "target" by id with a different priority in the payload — the
	// upsert must IGNORE the payload priority and keep the live position.
	importMergeRules(t, []map[string]any{
		{"name": "target", "action": "Drop", "id": target.ID, "priority": 999},
	})
	g := policyStore.findByIDCopy(target.ID)
	if g == nil {
		t.Fatal("target vanished after upsert")
	}
	if g.Priority != origPriority {
		t.Errorf("upsert changed priority to %d; want preserved %d", g.Priority, origPriority)
	}
	if g.Action != ActionDrop {
		t.Errorf("upsert did not apply content: action=%q want drop", g.Action)
	}
	// No duplicate slot created.
	if countRulesNamed(t, "target") != 1 {
		t.Errorf("upsert created a duplicate target rule")
	}
}

// TestImport_UpsertSurvivesPriorityCollision guards the reorder-idempotency
// fix (adversarial Finding 1 / Codex P1): a matched upsert must succeed even
// when the BACKUP's priority now collides with a different live rule, because
// UpdateByID discards the payload priority and keeps the live position. Before
// the fix the import validated the payload priority against the live set and
// spuriously skipped the content update.
func TestImport_UpsertSurvivesPriorityCollision(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "a", Priority: 1, Action: ActionAllow},
		{Name: "b", Priority: 2, Action: ActionAllow},
	})
	a := findRuleByName(t, "a")
	b := findRuleByName(t, "b")
	if a.Priority == b.Priority {
		t.Fatal("seed priorities collided; test needs distinct slots")
	}

	// Re-import rule "a" (matched by id) but with b's priority in the payload —
	// a collision with a DIFFERENT live rule. The upsert must still apply.
	importMergeRules(t, []map[string]any{
		{"name": "a", "id": a.ID, "priority": b.Priority, "action": "Drop"},
	})

	g := policyStore.findByIDCopy(a.ID)
	if g == nil || g.Action != ActionDrop {
		t.Fatalf("upsert was skipped on payload-priority collision: %+v", g)
	}
	if g.Priority != a.Priority {
		t.Errorf("upsert changed priority to %d; want live %d", g.Priority, a.Priority)
	}
	// b untouched, no duplicates.
	if countRulesNamed(t, "a") != 1 || countRulesNamed(t, "b") != 1 {
		t.Errorf("rule count drifted: a=%d b=%d", countRulesNamed(t, "a"), countRulesNamed(t, "b"))
	}
}

// TestCountImportUpserts: the preview split helper reports updates vs adds.
func TestCountImportUpserts(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	existing := policyStore
	existing.ReplaceAll(nil)
	r := existing.Add(PolicyRule{Name: "known", Action: ActionAllow})

	incoming := []PolicyRule{
		{Name: "known", ID: r.ID, Action: ActionDrop}, // id match → update
		{Name: "known", Action: ActionAllow},          // name match → update
		{Name: "fresh", Action: ActionAllow},          // no match → add
	}
	updates, adds := existing.countImportUpserts(incoming)
	if updates != 2 || adds != 1 {
		t.Errorf("countImportUpserts = %d update / %d add; want 2/1", updates, adds)
	}
}
