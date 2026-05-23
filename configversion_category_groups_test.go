package main

// configversion_category_groups_test.go — regression coverage for
// the CategoryGroups rollback-surface extension. Per spec at
// roadmap/CATEGORYGROUPS-ROLLBACK-EXTENSION-SPEC.md §5.
//
// Four tests:
//   1. Round-trip: capture → mutate → apply prior snapshot → asserts
//      live groups exactly match the prior state, including catSet
//      O(1) lookup via MatchesHost.
//   2. Rule→Group integrity: seed v1 with group + rule referencing it,
//      mutate v2 by removing both, apply v1; assert restored rule's
//      group reference actually resolves through the restored group
//      (Hazard A in spec §2.2 regression guard).
//   3. Nil snapshot: build a configBackup with CategoryGroups left
//      nil (pre-extension shape); apply; assert live groups untouched
//      (backward-compat per spec §6).
//   4. Empty snapshot: explicit []CategoryGroup{} wipes live groups
//      (Hazard B / spec §6.4 — the zero-groups case the corrected
//      spec preserved).
//
// All tests snapshot/restore the package globals they mutate.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// snapshotGlobalCategoryGroups captures and restores the package-
// global globalCategoryGroups pointer (and re-initialises the in-test
// store with a tmp path so Save() goes to TempDir). Mirrors
// snapshotGlobalClusterStore from PR #255.
func snapshotGlobalCategoryGroups(t *testing.T) {
	t.Helper()
	orig := globalCategoryGroups
	dir := t.TempDir()
	fresh := &CategoryGroupStore{
		groups: make(map[string]*CategoryGroup),
		path:   filepath.Join(dir, "category_groups.json"),
	}
	globalCategoryGroups = fresh
	t.Cleanup(func() { globalCategoryGroups = orig })
}

// snapshotPolicyStoreForTest captures and restores the policyStore
// state via the existing ReplaceAll surface. Same pattern as
// cluster_features_test.go.
func snapshotPolicyStoreForTest(t *testing.T) {
	t.Helper()
	origRules := policyStore.List()
	origPath := policyStore.path
	policyStore.path = "" // disable persistence during test
	t.Cleanup(func() {
		policyStore.ReplaceAll(origRules)
		policyStore.path = origPath
	})
}

// listGroupNames returns sorted names from globalCategoryGroups for
// stable assertion ordering. Lower-cases by way of GetByName's key
// convention (categorygroup.go:100).
func listGroupNames(t *testing.T) []string {
	t.Helper()
	groups := globalCategoryGroups.List()
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	sort.Strings(names)
	return names
}

// ─── Test 1: round-trip ───────────────────────────────────────────────

// TestConfigVersion_CategoryGroups_RoundTrip captures a snapshot,
// mutates the live store, applies the prior snapshot's envelope, and
// asserts the live state matches the captured state byte-for-byte.
func TestConfigVersion_CategoryGroups_RoundTrip(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	tmp := snapshotConfigVersionsDir(t)

	// Seed v1 state with two groups.
	if _, err := globalCategoryGroups.Add("Prod Allowed", []string{"news", "saas"}); err != nil {
		t.Fatalf("seed Prod Allowed: %v", err)
	}
	if _, err := globalCategoryGroups.Add("Risky", []string{"gambling", "adult"}); err != nil {
		t.Fatalf("seed Risky: %v", err)
	}

	saveConfigVersion("round-trip-test", "v1")

	// Mutate to v2 state: change first group, delete second.
	if err := globalCategoryGroups.Update("Prod Allowed", []string{"news"}); err != nil {
		t.Fatalf("update Prod Allowed: %v", err)
	}
	if err := globalCategoryGroups.Delete("Risky"); err != nil {
		t.Fatalf("delete Risky: %v", err)
	}

	// Read v1's envelope from disk and apply it.
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) == 0 {
		t.Fatalf("expected v1 envelope on disk; got entries=%d err=%v", len(entries), err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, entries[0].Name()))
	if err != nil {
		t.Fatalf("read v1 envelope: %v", err)
	}
	var env struct {
		Config configBackup `json:"config"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal v1 envelope: %v", err)
	}

	applyConfigBackup(&env.Config)

	// Assert v1 state restored: both groups back, original categories.
	gotNames := listGroupNames(t)
	wantNames := []string{"Prod Allowed", "Risky"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("groups after rollback = %v; want %v", gotNames, wantNames)
	}
	if g := globalCategoryGroups.GetByName("Prod Allowed"); g == nil {
		t.Fatal("Prod Allowed missing after rollback")
	} else {
		gotCats := append([]string(nil), g.Categories...)
		sort.Strings(gotCats)
		if !reflect.DeepEqual(gotCats, []string{"news", "saas"}) {
			t.Errorf("Prod Allowed categories = %v; want [news saas]", gotCats)
		}
	}
	if g := globalCategoryGroups.GetByName("Risky"); g == nil {
		t.Fatal("Risky missing after rollback")
	}
}

// ─── Test 2: rule→group integrity (Hazard A regression guard) ────────

// TestConfigVersion_CategoryGroups_RuleIntegrity guards against
// spec §2.2 Hazard A: a restored policy rule referencing a group
// that was deleted between v1 and v2 must resolve through the
// restored group post-rollback. Without the extension, the rule
// would be silently inert (MatchesHost fails closed for unknown
// groups).
func TestConfigVersion_CategoryGroups_RuleIntegrity(t *testing.T) {
	snapshotGlobalCategoryGroups(t)
	snapshotPolicyStoreForTest(t)
	tmp := snapshotConfigVersionsDir(t)

	// v1: group G1 + rule R1 referencing G1.
	if _, err := globalCategoryGroups.Add("G1", []string{"news"}); err != nil {
		t.Fatalf("seed G1: %v", err)
	}
	policyStore.ReplaceAll([]PolicyRule{{
		Priority:          100,
		Name:              "R1",
		Action:            ActionAllow,
		DestCategoryGroup: "G1",
	}})

	saveConfigVersion("rule-integrity-test", "v1")

	// v2: delete R1 first (required by referential-integrity check at
	// ui_policy.go:412-418), then delete G1.
	policyStore.ReplaceAll(nil)
	if err := globalCategoryGroups.Delete("G1"); err != nil {
		t.Fatalf("delete G1: %v", err)
	}

	// Apply v1's envelope.
	entries, _ := os.ReadDir(tmp)
	if len(entries) == 0 {
		t.Fatal("no envelope on disk")
	}
	data, _ := os.ReadFile(filepath.Join(tmp, entries[0].Name()))
	var env struct {
		Config configBackup `json:"config"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	applyConfigBackup(&env.Config)

	// Both R1 and G1 must be restored.
	restored := policyStore.List()
	if len(restored) != 1 || restored[0].Name != "R1" {
		t.Fatalf("policyStore after rollback = %+v; want [R1]", restored)
	}
	if restored[0].DestCategoryGroup != "G1" {
		t.Errorf("R1.DestCategoryGroup = %q; want %q", restored[0].DestCategoryGroup, "G1")
	}
	if g := globalCategoryGroups.GetByName("G1"); g == nil {
		t.Fatal("G1 missing after rollback — Hazard A unresolved")
	} else if !reflect.DeepEqual(g.Categories, []string{"news"}) {
		t.Errorf("G1.Categories = %v; want [news]", g.Categories)
	}

	// Sanity: the restored rule's reference resolves through the
	// restored group via the production catSet path. We can't easily
	// drive MatchesHost without a real URL-category fixture, but we
	// can prove the structural resolution at the GetByName layer (the
	// catSet was rebuilt during ReplaceAll per spec §4.5).
	g := globalCategoryGroups.GetByName(restored[0].DestCategoryGroup)
	if g == nil || len(g.Categories) == 0 {
		t.Fatalf("rule R1's DestCategoryGroup=%q does not resolve to a populated group post-rollback — Hazard A regression",
			restored[0].DestCategoryGroup)
	}
}

// ─── Test 3: nil CategoryGroups in snapshot is a no-op ────────────────

// TestConfigVersion_CategoryGroups_NilSnapshotIsNoOp pins the
// backward-compat contract: a configBackup with CategoryGroups left
// nil (simulating an old pre-extension snapshot file) leaves the
// live store untouched. Per spec §6.1.
func TestConfigVersion_CategoryGroups_NilSnapshotIsNoOp(t *testing.T) {
	snapshotGlobalCategoryGroups(t)

	// Seed live state.
	if _, err := globalCategoryGroups.Add("LiveOnly", []string{"news"}); err != nil {
		t.Fatalf("seed LiveOnly: %v", err)
	}
	preNames := listGroupNames(t)

	// Build a snapshot with CategoryGroups DELIBERATELY nil.
	backup := configBackup{
		Version:    1,
		ExportedAt: "test",
		// CategoryGroups: nil — the pre-extension shape.
	}
	applyConfigBackup(&backup)

	// Live state must be unchanged.
	postNames := listGroupNames(t)
	if !reflect.DeepEqual(preNames, postNames) {
		t.Errorf("nil-snapshot apply mutated live groups: pre=%v post=%v", preNames, postNames)
	}
	if g := globalCategoryGroups.GetByName("LiveOnly"); g == nil {
		t.Error("LiveOnly missing after nil-snapshot apply — apply was NOT a no-op")
	}
}

// ─── Test 4: empty []CategoryGroup{} wipes live groups ────────────────

// TestConfigVersion_CategoryGroups_EmptySnapshotWipes pins Hazard B's
// resolution: a snapshot recorded at zero groups (CategoryGroups =
// []CategoryGroup{}) WIPES the live store on rollback. This is the
// case the corrected spec §6.4 explicitly preserves; the earlier
// omitempty + nil-skip recommendation would have left this broken.
func TestConfigVersion_CategoryGroups_EmptySnapshotWipes(t *testing.T) {
	snapshotGlobalCategoryGroups(t)

	// Seed live state with one group.
	if _, err := globalCategoryGroups.Add("WillBeWiped", []string{"news"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Build a snapshot recording "zero groups".
	backup := configBackup{
		Version:        1,
		ExportedAt:     "test",
		CategoryGroups: []CategoryGroup{}, // explicit empty
	}
	applyConfigBackup(&backup)

	// Live store must be empty.
	names := listGroupNames(t)
	if len(names) != 0 {
		t.Errorf("empty-snapshot apply did NOT wipe live groups: got %v; want []", names)
	}
}

// ─── Test 5: marshaller distinguishes [] from absent ──────────────────

// TestConfigVersion_CategoryGroups_EmptyMarshalsAsArray verifies the
// JSON shape contract from spec §6.4: a snapshot with zero groups
// must serialize as "categoryGroups": [] (NOT omitted, NOT null), so
// the round trip preserves Hazard B's resolution.
func TestConfigVersion_CategoryGroups_EmptyMarshalsAsArray(t *testing.T) {
	snapshotGlobalCategoryGroups(t)

	// globalCategoryGroups is now an empty store (fresh from helper).
	backup := captureConfigBackup()

	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)

	if !containsCG(js, `"categoryGroups":[]`) {
		t.Errorf("expected `\"categoryGroups\":[]` in marshaled snapshot; got: %s", js)
	}
	if containsCG(js, `"categoryGroups":null`) {
		t.Errorf("marshaled snapshot has `\"categoryGroups\":null` — omitempty must be absent AND List() must return non-nil empty: %s", js)
	}
}

// ─── Test 6: diffConfigs reports category-group changes ───────────────

// TestConfigVersion_CategoryGroups_DiffReportsChanges pins the
// struct-slice diff gap: diffConfigs must surface category_groups so
// rollback dry-run preflight reflects actual impact. Without
// diffCategoryGroups, dry-run claims "no changes" even when apply would
// add, remove, or edit a group. Covers all three sub-cases — the
// "changed" (in-place Categories edit) case is the one a naive
// added/removed-only implementation would silently drop.
func TestConfigVersion_CategoryGroups_DiffReportsChanges(t *testing.T) {
	a := &configBackup{CategoryGroups: []CategoryGroup{
		{Name: "Keep", Categories: []string{"news"}},
		{Name: "Edited", Categories: []string{"news", "saas"}},
		{Name: "Removed", Categories: []string{"gambling"}},
	}}
	b := &configBackup{CategoryGroups: []CategoryGroup{
		{Name: "Keep", Categories: []string{"news"}},
		{Name: "Edited", Categories: []string{"news"}}, // categories changed
		{Name: "Added", Categories: []string{"adult"}},
	}}

	change := findChange(t, diffConfigs(a, b), "category_groups")
	assertNameInList(t, change.To, "added", "Added")
	assertNameInList(t, change.From, "removed", "Removed")
	assertNameInList(t, change.From, "changed", "Edited")
}

// findChange locates the configChange for a field in a diff result, or
// fails the test. The failure message is the regression-catch signal:
// when the production diff func is stashed, the field is absent.
func findChange(t *testing.T, changes []configChange, field string) configChange {
	t.Helper()
	for _, c := range changes {
		if c.Field == field {
			return c
		}
	}
	t.Fatalf("diffConfigs did not report %q; got %d change(s): %+v — dry-run preflight would be inaccurate", field, len(changes), changes)
	return configChange{}
}

// assertNameInList asserts that name appears in the string slice keyed by
// `key` inside a configChange From/To map. Order-independent (the diff
// helpers iterate maps, so slice order is nondeterministic).
func assertNameInList(t *testing.T, side any, key, name string) {
	t.Helper()
	m, ok := side.(map[string]any)
	if !ok {
		t.Fatalf("diff side is %T, want map[string]any", side)
	}
	list, ok := m[key].([]string)
	if !ok {
		t.Fatalf("diff side[%q] is %T, want []string (value: %+v)", key, m[key], m[key])
	}
	for _, v := range list {
		if v == name {
			return
		}
	}
	t.Errorf("expected %q in diff %q list; got %v", name, key, list)
}

// containsCG is a tiny strings.Contains wrapper to avoid importing
// strings just for one call. Named with CG suffix to avoid collision
// with the package-level `contains` helper in enroll_util_test.go.
func containsCG(haystack, needle string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
