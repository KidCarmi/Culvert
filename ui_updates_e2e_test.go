//go:build uie2e

package main

// Self-update panel E2E — advisory tier.
//
// The updates panel reports the running version and update availability from
// /api/update/status. This smoke-tests that the panel is reachable and its
// status endpoint responds through the admin's browser session.
//
// Hermetic + in-process.

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestUIE2E_UpdatesPanelStatus(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Upd-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	ctx, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="updates"]`).First().Click(); err != nil {
		t.Fatalf("open updates panel: %v", err)
	}

	// The status endpoint the panel consumes responds through the admin session.
	resp, err := ctx.Request().Get(uiSrv.URL + "/api/update/status")
	if err != nil {
		t.Fatalf("GET /api/update/status: %v", err)
	}
	if resp.Status() != 200 {
		t.Fatalf("/api/update/status status %d, want 200", resp.Status())
	}
	body, _ := resp.Body()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode /api/update/status %q: %v", string(body), err)
	}
	if len(m) == 0 {
		t.Errorf("/api/update/status returned an empty object: %q", string(body))
	}
}
