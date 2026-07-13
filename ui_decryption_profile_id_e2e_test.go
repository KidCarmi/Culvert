//go:build uie2e

package main

// ui_decryption_profile_id_e2e_test.go — live-browser proof that the decryption-
// profile editor addresses saves by stable ULID (?id=), not by mutable name
// (P3 object-identity seam, mirroring the category-group e2e).

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_DecryptionProfileEdit_AddressesByID(t *testing.T) {
	const adminUser, pass = "admin-dpid-e2e", "Dpid-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	orig := globalDecryptionProfiles.List()
	t.Cleanup(func() { globalDecryptionProfiles.ReplaceAll(orig) })
	globalDecryptionProfiles.ReplaceAll(nil)
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	p, err := globalDecryptionProfiles.Add(DecryptionProfile{Name: "dpid-profile", CertVerification: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == "" {
		t.Fatal("seeded profile has no ID")
	}

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-dpid-e2e", pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="decprofiles"]`).First().Click(); err != nil {
		t.Fatalf("open decprofiles: %v", err)
	}
	if err := assert.Locator(page.Locator("#view-decprofiles")).ToContainText("dpid-profile"); err != nil {
		t.Fatalf("seeded profile should render: %v", err)
	}

	if _, err := page.Evaluate(`() => {
		window.__lastDpPutURL = null;
		const orig = window.fetch;
		window.fetch = function(url, opts) {
			try {
				const u = typeof url === 'string' ? url : (url && url.url);
				if (opts && opts.method === 'PUT' && u && u.indexOf('/api/decryption-profiles') !== -1) {
					window.__lastDpPutURL = u;
				}
			} catch (e) {}
			return orig.apply(this, arguments);
		};
	}`); err != nil {
		t.Fatalf("install fetch spy: %v", err)
	}

	if _, err := page.Evaluate(`(name) => editDecProf(name)`, "dpid-profile"); err != nil {
		t.Fatalf("editDecProf: %v", err)
	}
	if err := page.Locator(`[data-click="saveDecProf"]`).First().Click(); err != nil {
		t.Fatalf("save: %v", err)
	}

	var putURL string
	for i := 0; i < 40; i++ {
		v, err := page.Evaluate(`() => window.__lastDpPutURL`)
		if err == nil && v != nil {
			if s, ok := v.(string); ok && s != "" {
				putURL = s
				break
			}
		}
		page.WaitForTimeout(100)
	}
	if putURL == "" {
		t.Fatal("no PUT to /api/decryption-profiles was observed")
	}
	if !strings.Contains(putURL, "id="+p.ID) {
		t.Errorf("decryption-profile PUT addressed %q; want id=%s (rename-safe)", putURL, p.ID)
	}
}
