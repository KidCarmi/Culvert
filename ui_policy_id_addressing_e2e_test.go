//go:build uie2e

package main

// ui_policy_id_addressing_e2e_test.go — live-browser proof that the policy rule
// editor addresses saves by stable ULID (?id=) rather than mutable priority
// (§1 identity seam). Verified in real Chromium by intercepting the PUT the
// editor fires: its URL must carry id=<the loaded rule's ULID>.

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_PolicyEdit_AddressesByID(t *testing.T) {
	const adminUser, pass = "admin-idaddr-e2e", "Idaddr-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	// Isolate the policy store; seed one rule with a known ULID.
	snapshotPolicyForIDTest(t)
	added := policyStore.Add(PolicyRule{Priority: 1, Name: "id-addr-rule", Action: ActionAllow, DestFQDN: "example.com"})
	if added.ID == "" {
		t.Fatal("seeded rule has no ID")
	}

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-idaddr-e2e", pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="policy"]`).First().Click(); err != nil {
		t.Fatalf("open policy panel: %v", err)
	}
	// The rule row must render before we can edit it.
	if err := assert.Locator(page.Locator("#pol-table")).ToContainText("id-addr-rule"); err != nil {
		t.Fatalf("seeded rule should appear in the table: %v", err)
	}

	// Capture the URL of the next PUT to /api/policy that the editor fires.
	if _, err := page.Evaluate(`() => {
		window.__lastPolicyPutURL = null;
		const orig = window.fetch;
		window.fetch = function(url, opts) {
			try {
				const u = typeof url === 'string' ? url : (url && url.url);
				if (opts && opts.method === 'PUT' && u && u.indexOf('/api/policy') !== -1) {
					window.__lastPolicyPutURL = u;
				}
			} catch (e) {}
			return orig.apply(this, arguments);
		};
	}`); err != nil {
		t.Fatalf("install fetch spy: %v", err)
	}

	// Load the rule into the editor (by its current priority) then save.
	if _, err := page.Evaluate(`(pri) => editPolicy(pri)`, added.Priority); err != nil {
		t.Fatalf("editPolicy: %v", err)
	}
	// Tweak the name so the save is a real mutation.
	if err := page.Locator("#pol-name").Fill("id-addr-rule-edited"); err != nil {
		t.Fatalf("edit name: %v", err)
	}
	if err := page.Locator("#policy-submit-btn").Click(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Poll for the intercepted PUT URL and assert it addresses by id, not priority.
	var putURL string
	for i := 0; i < 40; i++ {
		v, err := page.Evaluate(`() => window.__lastPolicyPutURL`)
		if err == nil && v != nil {
			if s, ok := v.(string); ok && s != "" {
				putURL = s
				break
			}
		}
		page.WaitForTimeout(100)
	}
	if putURL == "" {
		t.Fatal("no PUT to /api/policy was observed")
	}
	if !strings.Contains(putURL, "id="+added.ID) {
		t.Errorf("editor PUT addressed %q; want it to carry id=%s (reorder-safe addressing)", putURL, added.ID)
	}
	if strings.Contains(putURL, "priority=") {
		t.Errorf("editor PUT should address by id, not priority: %q", putURL)
	}
}
