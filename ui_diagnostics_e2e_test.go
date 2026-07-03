//go:build uie2e

package main

// Diagnostics panel E2E — advisory tier.
//
// The diagnostics panel runs the built-in self-checks (via /api/diagnostics) and
// renders an overall verdict plus a per-check list. This proves the panel is
// wired to the diagnostics engine end-to-end: opening it produces a verdict and
// at least one rendered check.
//
// Hermetic + in-process.

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_DiagnosticsPanelRuns(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Diag-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="diagnostics"]`).First().Click(); err != nil {
		t.Fatalf("open diagnostics panel: %v", err)
	}

	// The verdict badge is populated from /api/diagnostics once the checks run.
	if _, err := page.WaitForFunction(
		`() => { const b = document.getElementById('diag-verdict-badge'); return b && b.textContent.trim().length > 0; }`,
		nil,
		playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(10000)},
	); err != nil {
		t.Errorf("diagnostics verdict badge never populated (panel not wired to /api/diagnostics?): %v", err)
	}

	// The per-check list must render at least one check row.
	if _, err := page.WaitForFunction(
		`() => { const l = document.getElementById('diag-checks-list'); return l && l.textContent.trim().length > 0; }`,
		nil,
		playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(10000)},
	); err != nil {
		got, _ := page.Locator("#diag-checks-list").TextContent()
		t.Errorf("diagnostics check list did not render any checks; got %q: %v", got, err)
	}
}
