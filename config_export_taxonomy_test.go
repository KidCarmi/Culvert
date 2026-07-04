package main

// config_export_taxonomy_test.go — export/import coverage for the category
// taxonomy (URLCategories, CategoryGroups) and DPI bypass hosts. These three
// were rollback-only until the config-surface registry documented the gap: a
// "full" config export silently dropped the category policy that
// category-group rules reference, so a restored backup enforced different
// policy than the one exported.
//
// Contract pinned here:
//   - export "all" includes all three fields;
//   - import applies them BEFORE policy rules (categories → groups → rules,
//     the same leaf-first order as applyConfigBackup);
//   - replace mode replaces, merge mode upserts by name (incoming wins,
//     existing order preserved);
//   - an absent/empty field NEVER wipes live state (old backups stay safe);
//   - export → import round-trips.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// csrTaxIsolate isolates the three stores the taxonomy surface touches plus
// the config-version dir (import calls saveConfigVersion). Reuses the
// existing per-suite helpers.
func csrTaxIsolate(t *testing.T) {
	t.Helper()
	snapshotCatStore(t)
	snapshotGlobalCategoryGroups(t)
	snapshotDPIScanner(t)
	snapshotConfigVersionsDir(t)
}

func csrTaxSeed() {
	catStore.ReplaceAll([]CategoryEntry{{Name: "tax-cat", Hosts: []string{"tax.example.com"}}})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{{Name: "tax-group", Categories: []string{"tax-cat"}}})
	dpiScanner.SetBypassHosts([]string{"tax-bypass.example.com"})
}

func csrTaxExport(t *testing.T) *configBackup {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigExport(w, getReq("/api/config/export"))
	assertStatus(t, w, 200)
	var b configBackup
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	return &b
}

func TestConfigExport_IncludesCategoryTaxonomy(t *testing.T) {
	csrTaxIsolate(t)
	csrTaxSeed()

	b := csrTaxExport(t)
	if len(b.URLCategories) != 1 || b.URLCategories[0].Name != "tax-cat" {
		t.Errorf("export urlCategories = %+v; want the seeded tax-cat entry", b.URLCategories)
	}
	if len(b.CategoryGroups) != 1 || b.CategoryGroups[0].Name != "tax-group" {
		t.Errorf("export categoryGroups = %+v; want the seeded tax-group entry", b.CategoryGroups)
	}
	if len(b.ContentScanBypassHosts) != 1 || b.ContentScanBypassHosts[0] != "tax-bypass.example.com" {
		t.Errorf("export contentScanBypassHosts = %v; want the seeded bypass host", b.ContentScanBypassHosts)
	}
}

func csrTaxImport(t *testing.T, path string, backup map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", path, backup))
	assertStatus(t, w, 200)
}

func TestConfigImport_Taxonomy_ReplaceMode(t *testing.T) {
	csrTaxIsolate(t)
	csrTaxSeed()

	csrTaxImport(t, "/api/config/import?mode=replace", map[string]any{
		"version":    1,
		"exportedAt": "2026-01-01T00:00:00Z",
		"urlCategories": []map[string]any{
			{"name": "imported-cat", "hosts": []string{"imp.example.com"}},
		},
		"categoryGroups": []map[string]any{
			{"name": "imported-group", "categories": []string{"imported-cat"}},
		},
		"contentScanBypassHosts": []string{"imp-bypass.example.com"},
	})

	if got := listCategoryNames(t); len(got) != 1 || got[0] != "imported-cat" {
		t.Errorf("replace-mode import: categories = %v; want [imported-cat]", got)
	}
	if got := listGroupNames(t); len(got) != 1 || got[0] != "imported-group" {
		t.Errorf("replace-mode import: groups = %v; want [imported-group]", got)
	}
	if got := dpiScanner.BypassHosts(); len(got) != 1 || got[0] != "imp-bypass.example.com" {
		t.Errorf("replace-mode import: bypass hosts = %v; want [imp-bypass.example.com]", got)
	}
}

func TestConfigImport_Taxonomy_MergeUpserts(t *testing.T) {
	csrTaxIsolate(t)
	csrTaxSeed()

	// tax-cat is upserted (new hosts win), new-cat is appended; the group and
	// bypass lists gain entries without losing the seeded ones.
	csrTaxImport(t, "/api/config/import", map[string]any{
		"version":    1,
		"exportedAt": "2026-01-01T00:00:00Z",
		"urlCategories": []map[string]any{
			{"name": "tax-cat", "hosts": []string{"updated.example.com"}},
			{"name": "new-cat", "hosts": []string{"new.example.com"}},
		},
		"categoryGroups": []map[string]any{
			{"name": "new-group", "categories": []string{"new-cat"}},
		},
		"contentScanBypassHosts": []string{"new-bypass.example.com"},
	})

	if got := listCategoryNames(t); len(got) != 2 {
		t.Fatalf("merge import: categories = %v; want tax-cat + new-cat", got)
	}
	for _, e := range catStore.All() {
		if e.Name == "tax-cat" && (len(e.Hosts) != 1 || e.Hosts[0] != "updated.example.com") {
			t.Errorf("merge import did not upsert tax-cat hosts: %v", e.Hosts)
		}
	}
	if got := listGroupNames(t); len(got) != 2 {
		t.Errorf("merge import: groups = %v; want tax-group + new-group", got)
	}
	if got := dpiScanner.BypassHosts(); len(got) != 2 {
		t.Errorf("merge import: bypass hosts = %v; want seeded + new", got)
	}
}

func TestConfigImport_TaxonomyAbsent_IsNoOp(t *testing.T) {
	csrTaxIsolate(t)
	csrTaxSeed()

	// A pre-extension backup (fields absent) must not touch live taxonomy —
	// in EITHER mode. Import never wipes.
	for _, path := range []string{"/api/config/import", "/api/config/import?mode=replace"} {
		csrTaxImport(t, path, map[string]any{
			"version":    1,
			"exportedAt": "2026-01-01T00:00:00Z",
		})
		if got := listCategoryNames(t); len(got) != 1 || got[0] != "tax-cat" {
			t.Errorf("%s: absent taxonomy mutated categories: %v", path, got)
		}
		if got := listGroupNames(t); len(got) != 1 || got[0] != "tax-group" {
			t.Errorf("%s: absent taxonomy mutated groups: %v", path, got)
		}
		if got := dpiScanner.BypassHosts(); len(got) != 1 || got[0] != "tax-bypass.example.com" {
			t.Errorf("%s: absent taxonomy mutated bypass hosts: %v", path, got)
		}
	}
}

func TestConfigImport_BypassSkippedOnBadPatterns(t *testing.T) {
	csrTaxIsolate(t)
	csrTaxSeed()

	// A replace-mode import whose contentScanPatterns carry an invalid regex
	// must NOT apply the bypass hosts from the same backup: patterns and
	// bypass share the content_scan.json envelope, and applying one half
	// would persist a state matching neither the backup nor the prior state
	// (mirrors applyConfigBackup's guard; PR #557 Codex review).
	csrTaxImport(t, "/api/config/import?mode=replace", map[string]any{
		"version":                1,
		"exportedAt":             "2026-01-01T00:00:00Z",
		"contentScanPatterns":    []string{"("}, // invalid regex — Set must reject
		"contentScanBypassHosts": []string{"mixed-envelope.example.com"},
	})

	if got := dpiScanner.List(); len(got) != 0 {
		t.Errorf("invalid patterns were applied: %v", got)
	}
	if got := dpiScanner.BypassHosts(); len(got) != 1 || got[0] != "tax-bypass.example.com" {
		t.Errorf("bypass hosts = %v; want the seeded host untouched (mixed-envelope guard)", got)
	}
}

func TestConfigExportImport_Taxonomy_RoundTrip(t *testing.T) {
	csrTaxIsolate(t)
	csrTaxSeed()

	exported := csrTaxExport(t)

	// Wipe the live taxonomy, then restore from the exported backup.
	catStore.ReplaceAll([]CategoryEntry{})
	globalCategoryGroups.ReplaceAll([]CategoryGroup{})
	dpiScanner.SetBypassHosts([]string{})

	body, err := json.Marshal(exported)
	if err != nil {
		t.Fatalf("re-marshal export: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal export for import: %v", err)
	}
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", "/api/config/import?mode=replace", payload))
	assertStatus(t, w, 200)

	if got := listCategoryNames(t); len(got) != 1 || got[0] != "tax-cat" {
		t.Errorf("round-trip lost categories: %v", got)
	}
	if got := listGroupNames(t); len(got) != 1 || got[0] != "tax-group" {
		t.Errorf("round-trip lost groups: %v", got)
	}
	if got := dpiScanner.BypassHosts(); len(got) != 1 || got[0] != "tax-bypass.example.com" {
		t.Errorf("round-trip lost bypass hosts: %v", got)
	}
}
