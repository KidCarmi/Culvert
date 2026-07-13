//go:build uie2e

package main

// ui_category_group_id_e2e_test.go — live-browser proof that the category-group
// editor addresses saves by stable ULID (?id=), not by mutable name, so a
// concurrent rename can't misdirect the edit (P3 object-identity seam).

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_CategoryGroupEdit_AddressesByID(t *testing.T) {
	const adminUser, pass = "admin-cgid-e2e", "Cgid-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	snapshotGlobalCategoryGroups(t)
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	globalCategoryGroups.ReplaceAll(nil)
	// Seed a base category so the editor has something to keep selected.
	g, err := globalCategoryGroups.Add("cgid-group", []string{"ai"})
	if err != nil {
		t.Fatal(err)
	}
	if g.ID == "" {
		t.Fatal("seeded group has no ID")
	}

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-cgid-e2e", pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="catgroups"]`).First().Click(); err != nil {
		t.Fatalf("open catgroups: %v", err)
	}
	if err := assert.Locator(page.Locator("#catgroup-list")).ToContainText("cgid-group"); err != nil {
		t.Fatalf("seeded group should render: %v", err)
	}

	// Spy on the next PUT to /api/category-groups.
	if _, err := page.Evaluate(`() => {
		window.__lastCgPutURL = null;
		const orig = window.fetch;
		window.fetch = function(url, opts) {
			try {
				const u = typeof url === 'string' ? url : (url && url.url);
				if (opts && opts.method === 'PUT' && u && u.indexOf('/api/category-groups') !== -1) {
					window.__lastCgPutURL = u;
				}
			} catch (e) {}
			return orig.apply(this, arguments);
		};
	}`); err != nil {
		t.Fatalf("install fetch spy: %v", err)
	}

	// Open the editor for the group and save (categories are pre-selected from
	// the loaded group, so the save is a valid category update).
	if _, err := page.Evaluate(`(name) => editCatGroup(name)`, "cgid-group"); err != nil {
		t.Fatalf("editCatGroup: %v", err)
	}
	if err := page.Locator(`[data-click="saveCatGroup"]`).First().Click(); err != nil {
		t.Fatalf("save: %v", err)
	}

	var putURL string
	for i := 0; i < 40; i++ {
		v, err := page.Evaluate(`() => window.__lastCgPutURL`)
		if err == nil && v != nil {
			if s, ok := v.(string); ok && s != "" {
				putURL = s
				break
			}
		}
		page.WaitForTimeout(100)
	}
	if putURL == "" {
		t.Fatal("no PUT to /api/category-groups was observed")
	}
	if !strings.Contains(putURL, "id="+g.ID) {
		t.Errorf("category-group PUT addressed %q; want id=%s (rename-safe)", putURL, g.ID)
	}
}
