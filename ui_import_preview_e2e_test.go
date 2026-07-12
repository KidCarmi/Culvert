//go:build uie2e

package main

// ui_import_preview_e2e_test.go — live-browser coverage for the config-import
// dry-run/preview flow (P2 import-preview). Verifies the two-step UX in a real
// Chromium: uploading a backup shows a preview of what WOULD change, and the
// import applies nothing until the admin confirms — cancelling leaves live
// state untouched.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_ImportPreview_CancelLeavesStateUntouched(t *testing.T) {
	const adminUser, pass = "admin-imp-e2e", "Imp-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	// Isolate policy + config-version stores; restore on cleanup.
	snapshotPolicyStoreForTest(t)
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	policyStore.ReplaceAll([]PolicyRule{{Name: "keep-e2e", Action: ActionAllow}})

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, "viewer-imp-e2e", pass)

	// A replace-mode backup that WOULD wipe the seeded rule and install a new one.
	backupPath := filepath.Join(t.TempDir(), "backup.json")
	backup := `{"version":1,"exportedAt":"2026-02-02T00:00:00Z",` +
		`"defaultAction":"deny",` +
		`"policyRules":[{"name":"imported-e2e","action":"deny"}]}`
	if err := os.WriteFile(backupPath, []byte(backup), 0o600); err != nil {
		t.Fatalf("write backup fixture: %v", err)
	}

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="settings"]`).First().Click(); err != nil {
		t.Fatalf("open settings panel: %v", err)
	}

	// Turn on replace mode, then upload the backup — this fires importConfig,
	// which dry-runs first and renders #import-preview.
	if err := page.Locator("#import-replace-mode").Check(); err != nil {
		t.Fatalf("check replace mode: %v", err)
	}
	fileInput := page.Locator(`input[type="file"][data-change="importConfig"]`)
	if err := fileInput.SetInputFiles(backupPath); err != nil {
		t.Fatalf("upload backup: %v", err)
	}

	// Preview must show, flag REPLACE mode, and describe the destructive effect
	// on the seeded rule before anything is applied.
	previewEl := page.Locator("#import-preview")
	if err := assert.Locator(previewEl).ToBeVisible(); err != nil {
		t.Fatalf("import preview should render after upload: %v", err)
	}
	if err := assert.Locator(previewEl).ToContainText("REPLACE"); err != nil {
		t.Fatalf("preview should flag REPLACE mode: %v", err)
	}
	if err := assert.Locator(previewEl).ToContainText("replace 1 existing with 1 incoming"); err != nil {
		t.Fatalf("preview should describe the replace effect on Policy Rules: %v", err)
	}

	// The confirm modal gates the apply — CANCEL it.
	if err := assert.Locator(page.Locator("#confirm-dialog-cancel")).ToBeVisible(); err != nil {
		t.Fatalf("apply confirm modal should appear: %v", err)
	}
	if err := page.Locator("#confirm-dialog-cancel").Click(); err != nil {
		t.Fatalf("cancel apply: %v", err)
	}

	// Nothing was applied: the seeded rule survives, the imported rule is absent.
	rules := policyStore.List()
	if len(rules) != 1 || rules[0].Name != "keep-e2e" {
		t.Fatalf("cancel should leave policy untouched; got %+v", rules)
	}

	// Now upload again and CONFIRM — the import applies.
	if err := fileInput.SetInputFiles(backupPath); err != nil {
		t.Fatalf("re-upload backup: %v", err)
	}
	if err := assert.Locator(page.Locator("#confirm-dialog-ok")).ToBeVisible(); err != nil {
		t.Fatalf("apply confirm modal should reappear: %v", err)
	}
	if err := page.Locator("#confirm-dialog-ok").Click(); err != nil {
		t.Fatalf("confirm apply: %v", err)
	}

	// Poll for the replace to land (the apply POST is async).
	applied := false
	for i := 0; i < 40; i++ {
		rules := policyStore.List()
		if len(rules) == 1 && rules[0].Name == "imported-e2e" {
			applied = true
			break
		}
		page.WaitForTimeout(100)
	}
	if !applied {
		t.Fatalf("confirmed import should replace the rulebase; got %+v", policyStore.List())
	}
}
