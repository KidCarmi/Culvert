package main

// configversion_url_categories_test.go — regression coverage for the
// URL Categories rollback-surface extension. Per spec at
// roadmap/URL-CATEGORIES-ROLLBACK-EXTENSION-SPEC.md §4.9.
//
// Six structural tests + five handler tests:
//   1-6: round-trip, Hazard URL-A, nil snapshot, empty wipes, empty
//        marshals as array, BuiltIn preserved.
//   7-11: each of the 5 apiURLCat* handlers produces an envelope
//        with the expected Meta.Action.
//
// Helpers shared with PR #267 reused: snapshotConfigVersionsDir,
// snapshotPolicyStoreForTest, snapshotGlobalCategoryGroups,
// assertNoConfigVersionWithAction.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// snapshotCatStore captures and restores the package-global catStore
// pointer (and re-initialises the in-test store with a tmp path so
// Save() goes to TempDir). Mirrors snapshotGlobalCategoryGroups from
// PR #267.
func snapshotCatStore(t *testing.T) {
	t.Helper()
	orig := catStore
	dir := t.TempDir()
	fresh := newCategoryStore(nil)
	fresh.SetPathForTest(filepath.Join(dir, "categories.json"))
	catStore = fresh
	t.Cleanup(func() { catStore = orig })
}

// listCategoryNames returns sorted lowercase names for stable
// assertions.
func listCategoryNames(t *testing.T) []string {
	t.Helper()
	all := catStore.All()
	names := make([]string, 0, len(all))
	for _, e := range all {
		names = append(names, strings.ToLower(e.Name))
	}
	sort.Strings(names)
	return names
}

// ─── Test 1: round-trip ───────────────────────────────────────────────

// TestConfigVersion_URLCategories_RoundTrip captures a snapshot,
// mutates the live store, applies the prior snapshot's envelope, and
// asserts the live state matches.
func TestConfigVersion_URLCategories_RoundTrip(t *testing.T) {
	snapshotCatStore(t)
	tmp := snapshotConfigVersionsDir(t)

	// Seed v1 with two categories.
	if err := catStore.Set("News", []string{"cnn.com", "bbc.com"}, true); err != nil {
		t.Fatalf("seed News: %v", err)
	}
	if err := catStore.Set("CustomCat", []string{"foo.example", "bar.example"}, false); err != nil {
		t.Fatalf("seed CustomCat: %v", err)
	}

	saveConfigVersion("urlcat-round-trip", "v1")

	// Mutate v2: change News hosts, delete CustomCat.
	if err := catStore.Set("News", []string{"cnn.com"}, true); err != nil {
		t.Fatalf("update News: %v", err)
	}
	if err := catStore.Delete("CustomCat"); err != nil {
		t.Fatalf("delete CustomCat: %v", err)
	}

	loadAndApplyV1Envelope(t, tmp)

	gotNames := listCategoryNames(t)
	wantNames := []string{"customcat", "news"}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("categories after rollback = %v; want %v", gotNames, wantNames)
	}
	assertCatStoreHasEntry(t, "News", []string{"cnn.com", "bbc.com"})
	assertCatStoreHasEntry(t, "CustomCat", []string{"foo.example", "bar.example"})
}

// ─── Test 2: Hazard URL-A regression ──────────────────────────────────

// loadAndApplyV1Envelope reads the (single) config-version envelope
// in tmp and applies it via applyConfigBackup. Used by the round-trip
// and HazardURLA tests to keep their inline branch count low (cyclop
// budget at 15 per function).
func loadAndApplyV1Envelope(t *testing.T, tmp string) {
	t.Helper()
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no envelope on disk")
	}
	data, err := os.ReadFile(filepath.Join(tmp, entries[0].Name()))
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	var env struct {
		Config configBackup `json:"config"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	applyConfigBackup(&env.Config)
}

// assertCatStoreHasEntry fails the test if catStore lacks an entry
// matching name (case-insensitive) or if its Hosts differ from
// wantHosts (order-insensitive).
func assertCatStoreHasEntry(t *testing.T, name string, wantHosts []string) {
	t.Helper()
	for _, e := range catStore.All() {
		if !strings.EqualFold(e.Name, name) {
			continue
		}
		gotHosts := append([]string(nil), e.Hosts...)
		sort.Strings(gotHosts)
		sortedWant := append([]string(nil), wantHosts...)
		sort.Strings(sortedWant)
		if !reflect.DeepEqual(gotHosts, sortedWant) {
			t.Errorf("catStore[%q].Hosts = %v; want %v", name, gotHosts, sortedWant)
		}
		return
	}
	t.Fatalf("catStore missing entry %q", name)
}

// TestConfigVersion_URLCategories_HazardURLA pins the URL-A
// regression: a custom category (Layer 1 only) referenced by a
// CategoryGroup, restored from a snapshot, must resolve at the
// Layer 1 lookup. Without URLCategories in the rollback surface, the
// custom category stays gone post-rollback and the group's reference
// fails closed.
func TestConfigVersion_URLCategories_HazardURLA(t *testing.T) {
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	snapshotPolicyStoreForTest(t)
	tmp := snapshotConfigVersionsDir(t)

	// v1: custom category CustomA + group G1 → CustomA + rule R1 → G1.
	if err := catStore.Set("CustomA", []string{"abc.example"}, false); err != nil {
		t.Fatalf("seed CustomA: %v", err)
	}
	if _, err := globalCategoryGroups.Add("G1", []string{"CustomA"}); err != nil {
		t.Fatalf("seed G1: %v", err)
	}
	policyStore.ReplaceAll([]PolicyRule{{
		Priority:          100,
		Name:              "R1",
		Action:            ActionAllow,
		DestCategoryGroup: "G1",
	}})

	saveConfigVersion("urlcat-hazard-a", "v1")

	// v2: delete R1 → delete G1 → delete CustomA (referential checks).
	policyStore.ReplaceAll(nil)
	if err := globalCategoryGroups.Delete("G1"); err != nil {
		t.Fatalf("delete G1: %v", err)
	}
	if err := catStore.Delete("CustomA"); err != nil {
		t.Fatalf("delete CustomA: %v", err)
	}

	loadAndApplyV1Envelope(t, tmp)

	// All three layers must be restored.
	if globalCategoryGroups.GetByName("G1") == nil {
		t.Fatal("G1 missing after rollback")
	}
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "R1" {
		t.Fatalf("policyStore = %+v; want [R1]", rules)
	}
	// The crucial new assertion: CustomA exists in catStore after
	// rollback (was missing pre-extension). Hazard URL-A regression.
	assertCatStoreHasEntry(t, "CustomA", []string{"abc.example"})

	// Layer-1 lookup must now find abc.example → CustomA (the proxy
	// hot path used by MatchesHost via lookupHostCategory).
	cat, tier, _ := lookupHostCategory("abc.example")
	if cat != "CustomA" {
		t.Errorf("lookupHostCategory(abc.example) = %q; want %q (Hazard URL-A regression)", cat, "CustomA")
	}
	if tier != "admin" {
		t.Errorf("lookupHostCategory(abc.example) tier = %q; want %q", tier, "admin")
	}
}

// ─── Test 3: nil snapshot is no-op ────────────────────────────────────

func TestConfigVersion_URLCategories_NilSnapshotIsNoOp(t *testing.T) {
	snapshotCatStore(t)

	if err := catStore.Set("LiveOnly", []string{"live.example"}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	preNames := listCategoryNames(t)

	backup := configBackup{
		Version:    1,
		ExportedAt: "test",
		// URLCategories: nil — the pre-extension shape.
	}
	applyConfigBackup(&backup)

	postNames := listCategoryNames(t)
	if !reflect.DeepEqual(preNames, postNames) {
		t.Errorf("nil-snapshot apply mutated catStore: pre=%v post=%v", preNames, postNames)
	}
}

// ─── Test 4: empty snapshot wipes ─────────────────────────────────────

func TestConfigVersion_URLCategories_EmptySnapshotWipes(t *testing.T) {
	snapshotCatStore(t)

	if err := catStore.Set("WillBeWiped", []string{"x.example"}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	backup := configBackup{
		Version:       1,
		ExportedAt:    "test",
		URLCategories: []CategoryEntry{}, // explicit empty
	}
	applyConfigBackup(&backup)

	names := listCategoryNames(t)
	if len(names) != 0 {
		t.Errorf("empty-snapshot apply did NOT wipe catStore: got %v", names)
	}
}

// ─── Test 5: empty marshals as [] not null ────────────────────────────

func TestConfigVersion_URLCategories_EmptyMarshalsAsArray(t *testing.T) {
	snapshotCatStore(t)

	backup := captureConfigBackup()
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"urlCategories":[]`) {
		t.Errorf("expected `\"urlCategories\":[]` in marshaled snapshot; got: %s", js)
	}
	if strings.Contains(js, `"urlCategories":null`) {
		t.Errorf("marshaled snapshot has `\"urlCategories\":null` — omitempty must be absent AND All() must return non-nil empty: %s", js)
	}
}

// ─── Test 6: BuiltIn flag preserved ───────────────────────────────────

func TestConfigVersion_URLCategories_BuiltInPreserved(t *testing.T) {
	snapshotCatStore(t)
	tmp := snapshotConfigVersionsDir(t)

	// Mixed entries: one built-in, one custom.
	if err := catStore.Set("BuiltinCat", []string{"a.example"}, true); err != nil {
		t.Fatalf("seed BuiltinCat: %v", err)
	}
	if err := catStore.Set("CustomCat", []string{"b.example"}, false); err != nil {
		t.Fatalf("seed CustomCat: %v", err)
	}

	saveConfigVersion("urlcat-builtin", "v1")

	// Flip BuiltIn on both via direct Set (BuiltIn arg controls it).
	if err := catStore.Set("BuiltinCat", []string{"a.example"}, false); err != nil {
		t.Fatalf("flip BuiltinCat: %v", err)
	}
	if err := catStore.Set("CustomCat", []string{"b.example"}, true); err != nil {
		t.Fatalf("flip CustomCat: %v", err)
	}

	loadAndApplyV1Envelope(t, tmp)

	// BuiltIn flags must be restored to v1 values.
	all := catStore.All()
	got := map[string]bool{}
	for _, e := range all {
		got[e.Name] = e.BuiltIn
	}
	if !got["BuiltinCat"] {
		t.Error("BuiltinCat.BuiltIn = false after rollback; want true")
	}
	if got["CustomCat"] {
		t.Error("CustomCat.BuiltIn = true after rollback; want false")
	}
}

// ─── Handler tests 7-11: each apiURLCat* mutation creates an envelope ──

// runHandlerVersionTest is a small driver for the five handler tests
// below. Each test seeds whatever prerequisites the handler needs,
// calls the handler with admin context, and asserts a config-version
// envelope with the right Meta.Action exists on disk.
func runHandlerVersionTest(t *testing.T, action string, prepare func(t *testing.T),
	method, target string, body []byte) {
	t.Helper()
	snapshotCatStore(t)
	tmp := snapshotConfigVersionsDir(t)
	if prepare != nil {
		prepare(t)
	}

	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	var r *http.Request
	if bodyReader != nil {
		r = httptest.NewRequestWithContext(ctx, method, target, bodyReader)
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequestWithContext(ctx, method, target, nil)
	}

	// Dispatch to the appropriate handler based on path.
	switch {
	case strings.HasPrefix(target, "/api/urlcat/host"):
		apiURLCatHost(w, r)
	default:
		apiURLCat(w, r)
	}

	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("handler status = %d; want 200 or 204 (body: %s)", w.Code, w.Body.String())
	}

	// Find an envelope with the right Action.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("read tmp: %v", err)
	}
	type envelope struct {
		Meta struct {
			Action string `json:"action"`
		} `json:"meta"`
	}
	var found bool
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(tmp, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal %s: %v", e.Name(), err)
		}
		if env.Meta.Action == action {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no envelope with Meta.Action=%q found — handler %s %s did not call saveConfigVersion",
			action, method, target)
	}
}

func TestAPIURLCat_Create_CreatesConfigVersion(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"name": "urlcat-test-create", "hosts": []string{"create.example"}})
	runHandlerVersionTest(t, "urlcat.create", nil, http.MethodPost, "/api/urlcat", body)
}

func TestAPIURLCat_Update_CreatesConfigVersion(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"hosts": []string{"updated.example"}})
	runHandlerVersionTest(t, "urlcat.update",
		func(t *testing.T) {
			if err := catStore.Set("urlcat-test-update", []string{"orig.example"}, false); err != nil {
				t.Fatalf("seed: %v", err)
			}
		},
		http.MethodPut, "/api/urlcat?name=urlcat-test-update", body)
}

func TestAPIURLCat_Delete_CreatesConfigVersion(t *testing.T) {
	runHandlerVersionTest(t, "urlcat.delete",
		func(t *testing.T) {
			if err := catStore.Set("urlcat-test-delete", []string{"del.example"}, false); err != nil {
				t.Fatalf("seed: %v", err)
			}
		},
		http.MethodDelete, "/api/urlcat?name=urlcat-test-delete", nil)
}

func TestAPIURLCat_HostAdd_CreatesConfigVersion(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"category": "urlcat-test-hostadd", "host": "host.example"})
	runHandlerVersionTest(t, "urlcat.host.add",
		func(t *testing.T) {
			if err := catStore.Set("urlcat-test-hostadd", []string{}, false); err != nil {
				t.Fatalf("seed: %v", err)
			}
		},
		http.MethodPost, "/api/urlcat/host", body)
}

func TestAPIURLCat_HostRemove_CreatesConfigVersion(t *testing.T) {
	runHandlerVersionTest(t, "urlcat.host.remove",
		func(t *testing.T) {
			if err := catStore.Set("urlcat-test-hostremove", []string{"host.example"}, false); err != nil {
				t.Fatalf("seed: %v", err)
			}
		},
		http.MethodDelete, "/api/urlcat/host?category=urlcat-test-hostremove&host=host.example", nil)
}

// ─── diffConfigs reports url-category changes ─────────────────────────

// TestConfigVersion_URLCategories_DiffReportsChanges pins the
// struct-slice diff gap for catStore: diffConfigs must surface
// url_categories so rollback dry-run preflight reflects actual impact.
// Without diffURLCategories, dry-run claims "no changes" even when apply
// would add, remove, or edit a category's host list. The "changed"
// (in-place Hosts edit) case is the one a naive added/removed-only
// implementation would silently drop. findChange/assertNameInList are
// defined in configversion_category_groups_test.go (same package).
func TestConfigVersion_URLCategories_DiffReportsChanges(t *testing.T) {
	a := &configBackup{URLCategories: []CategoryEntry{
		{Name: "Keep", Hosts: []string{"keep.example"}},
		{Name: "Edited", Hosts: []string{"a.example", "b.example"}},
		{Name: "Removed", Hosts: []string{"gone.example"}},
	}}
	b := &configBackup{URLCategories: []CategoryEntry{
		{Name: "Keep", Hosts: []string{"keep.example"}},
		{Name: "Edited", Hosts: []string{"a.example"}}, // hosts changed
		{Name: "Added", Hosts: []string{"new.example"}},
	}}

	change := findChange(t, diffConfigs(a, b), "url_categories")
	assertNameInList(t, change.To, "added", "Added")
	assertNameInList(t, change.From, "removed", "Removed")
	assertNameInList(t, change.From, "changed", "Edited")
}

// TestConfigVersion_URLCategories_DiffNilSkipsField pins the apply-mirror
// contract for catStore: applyConfigBackup skips a nil URLCategories
// (old/absent snapshot → no-op), so the dry-run/preflight diff must skip
// it too. Without the guard, rolling back to a pre-extension snapshot
// would report every live category as "removed" while apply leaves them
// untouched. assertNoChange is defined in
// configversion_category_groups_test.go (same package).
func TestConfigVersion_URLCategories_DiffNilSkipsField(t *testing.T) {
	a := &configBackup{URLCategories: []CategoryEntry{
		{Name: "Live", Hosts: []string{"live.example"}},
	}}
	b := &configBackup{ /* URLCategories nil — pre-extension snapshot */ }

	assertNoChange(t, diffConfigs(a, b), "url_categories")
}

// TestConfigVersion_URLCategories_DiffEmptyReportsWipe pins the wipe half:
// a non-nil empty []CategoryEntry{} is an explicit wipe (ReplaceAll([])),
// so the diff MUST report live categories as removed. Guards against a
// len()==0 skip that would swallow the wipe.
func TestConfigVersion_URLCategories_DiffEmptyReportsWipe(t *testing.T) {
	a := &configBackup{URLCategories: []CategoryEntry{
		{Name: "Wiped", Hosts: []string{"x.example"}},
	}}
	b := &configBackup{URLCategories: []CategoryEntry{}} // explicit wipe

	change := findChange(t, diffConfigs(a, b), "url_categories")
	assertNameInList(t, change.From, "removed", "Wiped")
}
