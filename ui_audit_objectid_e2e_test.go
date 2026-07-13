//go:build uie2e

package main

// ui_audit_objectid_e2e_test.go — live-browser proof that a policy mutation's
// audit entry carries the rule's stable ULID all the way to the audit UI, where
// it is both shown (tooltip + link marker) and FILTERABLE. Filtering the audit
// log by a rule's ULID is the rename-safe correlation the §1 seam enables.

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_AuditLog_FilterableByRuleID(t *testing.T) {
	const adminUser, pass = "admin-auditid-e2e", "Auditid-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	snapshotPolicyForIDTest(t)
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-auditid-e2e", pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// Create a rule through the policy form → emits a policy.add audit carrying
	// the rule's ULID in ObjectID.
	if err := page.Locator(`.nav-item[data-view="policy"]`).First().Click(); err != nil {
		t.Fatalf("open policy: %v", err)
	}
	const ruleName = "auditid-rule"
	if err := page.Locator("#pol-name").Fill(ruleName); err != nil {
		t.Fatalf("fill name: %v", err)
	}
	if err := page.Locator("#pol-dest-fqdn").Fill("audit.example.com"); err != nil {
		t.Fatalf("fill dest: %v", err)
	}
	if _, err := page.Locator("#pol-action").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice(string(ActionAllow)),
	}); err != nil {
		t.Fatalf("select action: %v", err)
	}
	if err := page.Locator("#policy-submit-btn").Click(); err != nil {
		t.Fatalf("submit rule: %v", err)
	}

	// Resolve the created rule's ULID + priority from the backend.
	var ruleID string
	var rulePriority int
	for i := 0; i < 40; i++ {
		for _, r := range policyStore.List() {
			if r.Name == ruleName {
				ruleID, rulePriority = r.ID, r.Priority
			}
		}
		if ruleID != "" {
			break
		}
		page.WaitForTimeout(100)
	}
	if ruleID == "" {
		t.Fatal("created rule never appeared in the store")
	}

	// Open the audit view (loads /api/audit) and confirm the add row shows the
	// id tooltip.
	if err := page.Locator(`.nav-item[data-view="audit"]`).First().Click(); err != nil {
		t.Fatalf("open audit: %v", err)
	}
	// Force a fresh fetch so the assertion never races the view's one-shot load
	// (the create's audit entry is written synchronously before its response,
	// so a re-fetch here is guaranteed to see it).
	if _, err := page.Evaluate(`() => loadAuditLog()`); err != nil {
		t.Fatalf("reload audit log: %v", err)
	}
	if err := assert.Locator(page.Locator("#audit-table")).ToContainText("policy.add"); err != nil {
		t.Fatalf("audit log should show the policy.add entry: %v", err)
	}
	// Assert the object cell carries the ULID in its title tooltip. Use
	// ToBeAttached (DOM presence), not ToBeVisible: the intent is that the id was
	// rendered into the title attribute — its CSS visibility depends on which
	// view is active, a timing-flaky signal irrelevant to this check.
	titled := page.Locator(`#audit-table td[title="id: ` + ruleID + `"]`)
	if err := assert.Locator(titled).ToBeAttached(); err != nil {
		t.Fatalf("the policy.add row's object cell should carry the rule ULID as a tooltip: %v", err)
	}

	// Filter the audit log by the ULID — the entry must survive (rename-safe
	// correlation), and window._auditEntries (the filtered set) must include it.
	if err := page.Locator("#audit-filter").Fill(ruleID); err != nil {
		t.Fatalf("type filter: %v", err)
	}
	matched, err := page.Evaluate(`(id) => (window._auditEntries || []).some(e => e.action === 'policy.add' && e.objectId === id)`, ruleID)
	if err != nil {
		t.Fatalf("read filtered entries: %v", err)
	}
	if matched != true {
		t.Errorf("filtering the audit log by the rule ULID should keep the policy.add entry; got %v", matched)
	}
	// And the filtered table must not be empty.
	if err := assert.Locator(page.Locator("#audit-table")).Not().ToContainText("No audit entries"); err != nil {
		t.Fatalf("id-filtered audit table should still show the matching entry: %v", err)
	}

	// The per-rule History action must preload the filter with the ULID (not the
	// mutable name), so the trail stays correlatable after a rename.
	if _, err := page.Evaluate(`(pri) => polHistory(pri)`, rulePriority); err != nil {
		t.Fatalf("invoke polHistory: %v", err)
	}
	filterVal, err := page.Evaluate(`() => document.getElementById('audit-filter').value`)
	if err != nil {
		t.Fatalf("read audit filter: %v", err)
	}
	if filterVal != ruleID {
		t.Errorf("polHistory preloaded audit filter with %q, want the rule ULID %q", filterVal, ruleID)
	}
}
