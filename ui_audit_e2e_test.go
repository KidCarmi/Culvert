//go:build uie2e

package main

// Audit-trail surfacing E2E (advisory tier), slice 5.
//
// Compliance guarantee: an administrative state change is recorded in the audit
// trail AND shown in the admin UI. An admin performs a mutating action in their
// authenticated session; the audit panel must then render an entry for it. This
// exercises the auditEvent → in-memory ring → /api/audit → renderAuditLog chain
// against the REAL admin-UI handler.
//
// Hermetic + in-process; no proxy or external services needed. The action uses a
// unique host string as the discriminator (per the repo's audit-ring test
// guidance: assert on entry CONTENT, never on len() deltas — the ring is bounded
// at 500 and saturates under the shuffled determinism gate).

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_AuditTrailSurfaced(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Audit-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	// startTestProxy resets the global cfg; seed AFTER it so the admin session is valid.
	_ = startTestProxy(t)
	seedUIRoster(t, adminUser, viewerUser, pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)

	ctx, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// ── Admin performs an audited mutation in their session ─────────────────
	// A unique host makes the resulting audit entry unambiguous in the panel.
	const probeHost = "audit-probe-e2e.example"
	resp, err := ctx.Request().Post(uiSrv.URL+"/api/blocklist", playwright.APIRequestContextPostOptions{
		Data: map[string]any{"host": probeHost},
	})
	if err != nil {
		t.Fatalf("admin POST /api/blocklist: %v", err)
	}
	if resp.Status() != http.StatusOK {
		t.Fatalf("blocklist add returned %d, want 200 (admin should be authorized)", resp.Status())
	}

	// ── Open the audit panel → it must render an entry for that action ──────
	if err := page.Locator(`.nav-item[data-view="audit"]`).First().Click(); err != nil {
		t.Fatalf("open audit panel: %v", err)
	}
	audit := page.Locator("#audit-table")
	// The action verb is rendered in the action column…
	if err := assert.Locator(audit).ToContainText("blocklist.add"); err != nil {
		t.Errorf("audit panel should show the blocklist.add action: %v", err)
	}
	// …and the unique host in the detail column — the unambiguous proof that THIS
	// admin action reached the audit trail and the UI surfaced it.
	if err := assert.Locator(audit).ToContainText(probeHost); err != nil {
		t.Errorf("audit panel should show the audited object %q in the detail column: %v", probeHost, err)
	}
}
