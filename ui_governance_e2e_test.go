//go:build uie2e

package main

// Governance / control-plane panel E2E — advisory tier.
//
// The governance panel (C3) is the admin-only observability surface for the
// admin-API control plane: route inventory, C2 metadata-enforcement mode + its
// six counters, per-role breakdown, and derived health. This proves the panel
// is wired to /api/governance/control-plane end-to-end and renders the live
// route inventory + C2 telemetry — the browser view of the C2/RBAC machinery
// that the rest of the suite exercises at the enforcement layer.
//
// Hermetic + in-process.

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_GovernancePanelSurfacesControlPlane(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Gov-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// Governance is admin-only nav; opening it triggers loadGovernance().
	if err := page.Locator(`.nav-item[data-view="governance"]`).First().Click(); err != nil {
		t.Fatalf("open governance panel: %v", err)
	}

	// Route inventory rendered from the C3 endpoint.
	if err := assert.Locator(page.Locator("#gov-route-summary")).ToContainText("routes total"); err != nil {
		got, _ := page.Locator("#gov-route-summary").TextContent()
		t.Errorf("governance panel should render the route inventory; got %q: %v", got, err)
	}
	// C2 metadata-enforcement state (mode + kill switch) rendered.
	if err := assert.Locator(page.Locator("#gov-c2-state")).ToContainText("Mode:"); err != nil {
		got, _ := page.Locator("#gov-c2-state").TextContent()
		t.Errorf("governance panel should render the C2 mode; got %q: %v", got, err)
	}
	// The six C2 counters rendered (would_deny is the always-present first one).
	if err := assert.Locator(page.Locator("#gov-counters")).ToContainText("would_deny"); err != nil {
		got, _ := page.Locator("#gov-counters").TextContent()
		t.Errorf("governance panel should render the C2 counters; got %q: %v", got, err)
	}

	// Backstop: the underlying endpoint is admin-only — a viewer is denied even
	// though the panel is hidden from their nav (the server is the boundary).
	vctx, _ := newAuthedUIPage(t, browser, uiSrv.URL, viewerUser, RoleViewer)
	resp, err := vctx.Request().Get(uiSrv.URL + "/api/governance/control-plane")
	if err != nil {
		t.Fatalf("viewer GET governance: %v", err)
	}
	if resp.Status() == 200 {
		t.Errorf("viewer read the admin-only governance endpoint (status 200) — must be denied")
	}
}
