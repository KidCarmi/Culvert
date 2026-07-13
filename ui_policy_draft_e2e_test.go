//go:build uie2e

package main

// ui_policy_draft_e2e_test.go — live-browser proof of the policy-draft GUI (S2):
// with commit-mode ON and a staged change, the Policy view shows the pending-
// changes bar; clicking "Review & commit" and entering the required comment
// activates the candidate and clears the bar (P3 policy-draft / G2).

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_PolicyDraft_CommitBar(t *testing.T) {
	const adminUser, pass = "admin-draft-e2e", "Draft-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	draftTestSetup(t) // isolates policyStore, config versions, the draft coordinator, and the flag
	// A committed (running) rule as the base, plus a staged candidate edit.
	policyStore.Add(PolicyRule{Name: "base-rule", Action: ActionAllow})
	setRequireCommit(true)
	policyDraft.stageTarget(adminUser).Add(PolicyRule{Name: "staged-rule", Action: ActionAllow})
	if !policyDraft.active() {
		t.Fatal("precondition: draft not active after staging")
	}

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-draft-e2e", pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="policy"]`).First().Click(); err != nil {
		t.Fatalf("open policy view: %v", err)
	}

	// The pending-changes bar surfaces the staged change; the commit-mode toggle reads "on".
	if err := assert.Locator(page.Locator("#pol-draft-bar")).ToBeVisible(); err != nil {
		t.Fatalf("pending-changes bar should be visible: %v", err)
	}
	if err := assert.Locator(page.Locator("#pol-draft-count")).ToContainText("1 change"); err != nil {
		t.Fatalf("draft count should read '1 change': %v", err)
	}
	if err := assert.Locator(page.Locator("#pol-commit-mode-state")).ToHaveText("on"); err != nil {
		t.Fatalf("commit-mode toggle should read 'on': %v", err)
	}

	// Review & commit → the required-comment dialog → commit.
	if err := page.Locator(`#pol-draft-bar [data-click="polCommitDraft"]`).Click(); err != nil {
		t.Fatalf("click Review & commit: %v", err)
	}
	if err := assert.Locator(page.Locator("#confirm-dialog-input")).ToBeVisible(); err != nil {
		t.Fatalf("commit comment input should appear: %v", err)
	}
	if err := page.Locator("#confirm-dialog-input").Fill("ship the staged rule"); err != nil {
		t.Fatalf("fill commit comment: %v", err)
	}
	if err := page.Locator("#confirm-dialog-ok").Click(); err != nil {
		t.Fatalf("confirm commit: %v", err)
	}

	// After commit the bar hides; server-side, running now carries the staged rule
	// and the draft is cleared.
	if err := assert.Locator(page.Locator("#pol-draft-bar")).ToBeHidden(); err != nil {
		t.Fatalf("pending-changes bar should hide after commit: %v", err)
	}
	found := false
	for _, r := range policyStore.List() {
		if r.Name == "staged-rule" {
			found = true
		}
	}
	if !found {
		t.Error("commit did not activate the staged rule into the running rulebase")
	}
	if policyDraft.active() {
		t.Error("draft still active after commit")
	}
}
