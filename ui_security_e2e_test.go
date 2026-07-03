//go:build uie2e

package main

// Security-config panel E2E — advisory tier.
//
// The security panel surfaces the proxy's protective configuration from
// /api/security: the per-IP rate-limit state and the source-IP filter (allow/
// block list). This proves the panel is wired to that endpoint and renders the
// live security posture.
//
// Hermetic + in-process.

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_SecurityPanelRendersConfig(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Sec-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="security"]`).First().Click(); err != nil {
		t.Fatalf("open security panel: %v", err)
	}

	// Rate-limit state is rendered as Enabled/Disabled from /api/security.
	if _, err := page.WaitForFunction(
		`() => { const e = document.getElementById('sec-rl-status'); return e && /Enabled|Disabled/.test(e.textContent); }`,
		nil,
		playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(10000)},
	); err != nil {
		got, _ := page.Locator("#sec-rl-status").TextContent()
		t.Errorf("security panel should render the rate-limit state (Enabled/Disabled); got %q: %v", got, err)
	}

	// The source-IP filter management UI (add field + list) is present.
	if v, _ := page.Locator("#sec-ip-input").IsVisible(); !v {
		t.Error("security panel should expose the source-IP filter add field (#sec-ip-input)")
	}
}
