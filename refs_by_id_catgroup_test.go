package main

// refs_by_id_catgroup_test.go — rule→category-group references-by-id + rename
// (S2, OBJECT-REFERENCES-BY-ID.md): ID-authoritative match with name fallback,
// write-path stamp, rename cascade (hit-preserving, running + draft), ID-first
// delete-block, and the handler rename flow (atomic ordering + collision 409).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// catGroupMatches is the single-shot form of categoryGroupMatchesHostScratch:
// the production caller is a rule SCAN that shares one host scratch across every
// rule, so a test asking about one rule builds a throwaway scratch — the same
// shape matchDest uses.
func catGroupMatches(rule *PolicyRule, host string) bool {
	sc := newHostCatScratch(host)
	return categoryGroupMatchesHostScratch(rule, &sc)
}

// seedHostCategory points a host at a category via the admin catStore, so
// the category-group matcher's host→category fusion resolves it.
func seedHostCategory(t *testing.T, category, host string) {
	t.Helper()
	if err := catStore.Set(category, []string{host}, false); err != nil {
		t.Fatalf("seed catStore %q: %v", category, err)
	}
}

func TestCategoryGroupMatchesHostRule_IDFirstWithFallback(t *testing.T) {
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	seedHostCategory(t, "news", "example.com")
	g, err := globalCategoryGroups.Add("grp", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}

	// Rule links by ID but its denormalized name is STALE — the ID resolves, so
	// the group's real membership is used (matches), NOT the stale name.
	rule := &PolicyRule{DestCategoryGroup: "STALE", DestCategoryGroupID: g.ID}
	if !catGroupMatches(rule, "example.com") {
		t.Error("ID-first match failed: stale name should be ignored when the ID resolves")
	}
	// A rule whose ID points at a group that does NOT contain the host's category
	// must NOT match — even if its stale name happens to name a matching group.
	// (Authoritative-ID: a resolved group's result is final.)
	g2, _ := globalCategoryGroups.Add("other", []string{"gambling"})
	rule2 := &PolicyRule{DestCategoryGroup: "grp", DestCategoryGroupID: g2.ID}
	if catGroupMatches(rule2, "example.com") {
		t.Error("authoritative ID violated: a resolved non-member group must not fall back to the name")
	}
	// Un-migrated rule (no ID) falls back to the name.
	rule3 := &PolicyRule{DestCategoryGroup: "grp"}
	if !catGroupMatches(rule3, "example.com") {
		t.Error("name-fallback match failed for an un-migrated rule")
	}
	// Dangling ID (no such group) falls back to the name.
	rule4 := &PolicyRule{DestCategoryGroup: "grp", DestCategoryGroupID: "deadbeef0000"}
	if !catGroupMatches(rule4, "example.com") {
		t.Error("dangling ID must fall back to the denormalized name")
	}
}

func TestStampObjectRefIDs_CategoryGroup(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("grp", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	// A client-supplied ID is discarded and re-derived server-side from the name.
	rule := &PolicyRule{DestCategoryGroup: "grp", DestCategoryGroupID: "client-lies"}
	stampObjectRefIDs(rule)
	if rule.DestCategoryGroupID != g.ID {
		t.Errorf("stamp did not re-derive the ID from the name: got %q, want %q", rule.DestCategoryGroupID, g.ID)
	}
	// Unknown name leaves the ID empty (fail-safe: match falls back to name).
	rule2 := &PolicyRule{DestCategoryGroup: "ghost", DestCategoryGroupID: "x"}
	stampObjectRefIDs(rule2)
	if rule2.DestCategoryGroupID != "" {
		t.Errorf("unknown name must leave ID empty, got %q", rule2.DestCategoryGroupID)
	}
}

func TestCascadeDestCategoryGroupRename(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, _ := globalCategoryGroups.Add("old", []string{"news"})
	// One migrated rule (by ID, stale name) + one un-migrated (by old name).
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "byID", DestCategoryGroup: "STALE", DestCategoryGroupID: g.ID, Action: ActionAllow},
		{Name: "byName", DestCategoryGroup: "old", Action: ActionAllow},
		{Name: "unrelated", DestCategoryGroup: "keep", Action: ActionAllow},
	})
	n := policyStore.CascadeDestCategoryGroupRename(g.ID, "old", "new")
	if n != 2 {
		t.Fatalf("cascade touched %d rules, want 2", n)
	}
	rules := policyStore.List()
	byName := map[string]PolicyRule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	if byName["byID"].DestCategoryGroup != "new" {
		t.Errorf("byID rule name = %q, want new", byName["byID"].DestCategoryGroup)
	}
	// The un-migrated rule got both the new name AND the stamped ID (migrated).
	if byName["byName"].DestCategoryGroup != "new" || byName["byName"].DestCategoryGroupID != g.ID {
		t.Errorf("byName rule not migrated: %+v", byName["byName"])
	}
	if byName["unrelated"].DestCategoryGroup != "keep" {
		t.Error("unrelated rule must not be touched")
	}
}

func TestObjectReferences_CategoryGroupIDFirst(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("grp", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	// Rule links by ID with a STALE denormalized name (partial-cascade case).
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "r1", DestCategoryGroup: "STALE", DestCategoryGroupID: g.ID, Action: ActionAllow},
	})
	found, refs := objectReferences("category-group", "grp")
	if !found || len(refs) != 1 || refs[0].Name != "r1" {
		t.Fatalf("ID-first delete-block did not find the stale-named referencing rule: %+v", refs)
	}
}

// TestObjectReferences_CategoryGroupStaleNameNoFalsePositive pins the Codex P2
// fix: an ID-bearing rule whose STALE denormalized name equals a DIFFERENT
// group's current name must NOT be reported as referencing that other group
// (the ID is authoritative), so deleting the other group is not wrongly blocked.
func TestObjectReferences_CategoryGroupStaleNameNoFalsePositive(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	gA, err := globalCategoryGroups.Add("A", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	gB, err := globalCategoryGroups.Add("B", []string{"ads"})
	if err != nil {
		t.Fatal(err)
	}
	// Rule references group A by ID, but its cached name is stale and equals B's
	// current name (e.g. A was once named "B" before a swap). Evaluation follows A.
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "followsA", DestCategoryGroup: "B", DestCategoryGroupID: gA.ID, Action: ActionAllow},
	})
	// Querying references to B must find NONE — the rule follows A by ID.
	found, refs := objectReferences("category-group", "B")
	if !found {
		t.Fatal("objectReferences(B) not found")
	}
	if len(refs) != 0 {
		t.Errorf("stale name must not false-positive as a reference to B: %+v", refs)
	}
	// Querying references to A must find the rule (by ID).
	_, refsA := objectReferences("category-group", "A")
	if len(refsA) != 1 || refsA[0].Name != "followsA" {
		t.Errorf("ID-authoritative walk did not attribute the rule to A: %+v", refsA)
	}
	_ = gB
}

// TestObjectReferences_CategoryGroupDanglingIDFallsBackToName pins the
// walk↔match parity fix: a rule with a DANGLING DestCategoryGroupID (no live
// group) whose denormalized name resolves to a live group is ENFORCING that
// group at eval time (the matcher falls back to the name), so
// the delete-block walk must attribute it too — else the group is deletable
// while in use.
func TestObjectReferences_CategoryGroupDanglingIDFallsBackToName(t *testing.T) {
	snapshotPolicyStoreForTest(t)
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("live", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	// Dangling ID (no group has it) + a name that matches the live group.
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "dangler", DestCategoryGroup: "live", DestCategoryGroupID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Action: ActionAllow},
	})
	_, refs := objectReferences("category-group", "live")
	if len(refs) != 1 || refs[0].Name != "dangler" {
		t.Errorf("dangling-ID rule enforcing by name must block the group's delete: %+v", refs)
	}
	_ = g
}

func TestApiCategoryGroup_RenameCascades(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("old", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	policyStore.ReplaceAll([]PolicyRule{
		{Name: "r1", DestCategoryGroup: "old", DestCategoryGroupID: g.ID, Action: ActionAllow},
	})

	body := `{"name":"new","categories":["news","saas"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/category-groups?id="+g.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCategoryGroups(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("rename PUT = %d (%s)", w.Code, w.Body.String())
	}
	if globalCategoryGroups.GetByName("new") == nil {
		t.Error("group was not renamed to 'new'")
	}
	if globalCategoryGroups.GetByName("old") != nil {
		t.Error("old group name still resolves")
	}
	// Categories were updated in the SAME request.
	if got := globalCategoryGroups.GetByID(g.ID); got == nil || len(got.Categories) != 2 {
		t.Errorf("categories not updated alongside rename: %+v", got)
	}
	// The referencing rule's denormalized name followed the rename.
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].DestCategoryGroup != "new" {
		t.Errorf("referencing rule's name not cascaded: %+v", rules)
	}
}

// TestApiCategoryGroup_RenameCascadesDraft pins the draft-cascade (mirrors the
// S1 Finding-2 fix): a group rename during an ACTIVE draft must refresh the
// candidate's denormalized names too.
func TestApiCategoryGroup_RenameCascadesDraft(t *testing.T) {
	draftTestSetup(t)
	snapshotGlobalCategoryGroups(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("old", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	setRequireCommit(true)
	cand := policyDraft.stageTarget("admin@test")
	cand.Add(PolicyRule{Name: "cr", DestCategoryGroup: "old", DestCategoryGroupID: g.ID, Action: ActionAllow})

	body := `{"name":"new","categories":["news"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/category-groups?id="+g.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCategoryGroups(w, adminCtx(req))
	if w.Code != http.StatusOK {
		t.Fatalf("rename PUT = %d (%s)", w.Code, w.Body.String())
	}
	crules := policyDraft.candidateList()
	if len(crules) != 1 || crules[0].DestCategoryGroup != "new" {
		t.Errorf("draft candidate's denormalized name not cascaded: %+v", crules)
	}
}

// TestApiCategoryGroup_RenameCollision409 pins the atomic-rename pre-check: a
// rename onto a name owned by a DIFFERENT group is rejected with 409 and mutates
// nothing (neither categories nor name).
func TestApiCategoryGroup_RenameCollision409(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	snapshotPolicyStoreForTest(t)
	snapshotConfigVersionsDir(t)
	globalCategoryGroups.ReplaceAll(nil)
	g, err := globalCategoryGroups.Add("a", []string{"news"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := globalCategoryGroups.Add("b", []string{"ads"}); err != nil {
		t.Fatal(err)
	}
	// Try to rename "a" → "b" while ALSO changing categories.
	body := `{"name":"b","categories":["news","saas"]}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut,
		"/api/category-groups?id="+g.ID, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiCategoryGroups(w, adminCtx(req))
	if w.Code != http.StatusConflict {
		t.Fatalf("collision rename = %d (%s), want 409", w.Code, w.Body.String())
	}
	// Nothing changed: "a" keeps its name AND its original single category.
	if got := globalCategoryGroups.GetByID(g.ID); got == nil || got.Name != "a" || len(got.Categories) != 1 {
		t.Errorf("collision must not mutate the group: %+v", got)
	}
}
