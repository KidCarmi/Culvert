//go:build uie2e

package main

// UI RBAC gating — real-browser E2E (advisory tier).
//
// The browser complement to the C2 metadata-enforcement invariants: it proves
// the admin SPA gates its own navigation by the authenticated role AND that the
// server backs that gating (a viewer that forces an admin-only mutation is 403'd
// regardless of what the UI shows). Together: "identity enables, policy grants —
// and the handler is the real backstop, never the front-end."
//
// Flow (hermetic, in-process):
//   1. Mount the REAL admin-UI handler chain via httptest.NewServer.
//   2. Seed an admin + viewer UI user; mark the instance configured.
//   3. For each role: a fresh browser context with an injected ps_ui_session
//      cookie, navigate the SPA, let applySession() run, assert nav visibility.
//   4. Backstop: the viewer's own context POSTs to an admin-only endpoint and
//      must get 403 — the server enforces even when the UI is bypassed.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_RBACNavGating(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Rbac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)

	// openAs returns a page in a fresh context authenticated as the given role.
	// Delegates to newAuthedUIPage so it gets the same hardening as the rest of
	// the suite: the Chart.js stub (so the on-load init reaches applySession
	// instead of throwing) and a `load` wait (the persistent SSE connection means
	// `networkidle` never fires — the original inline path deadlocked on it in CI
	// where the Chart.js CDN is reachable and the full init runs).
	openAs := func(user string, role UIRole) playwright.Page {
		t.Helper()
		_, page := newAuthedUIPage(t, browser, srv.URL, user, role)
		return page
	}

	// waitState asserts a locator reaches the expected visibility (the SPA gates
	// asynchronously after fetching /api/auth/status, so we poll via WaitFor).
	waitState := func(page playwright.Page, selector string, state *playwright.WaitForSelectorState, desc string) {
		t.Helper()
		if err := page.Locator(selector).WaitFor(playwright.LocatorWaitForOptions{
			State:   state,
			Timeout: playwright.Float(8000),
		}); err != nil {
			t.Errorf("%s: selector %q never became %v: %v", desc, selector, *state, err)
		}
	}

	// ── Admin: admin-only nav is VISIBLE ────────────────────────────────────
	admin := openAs(adminUser, RoleAdmin)
	waitState(admin, "#nav-users", playwright.WaitForSelectorStateVisible, "admin sees users panel")
	waitState(admin, "[data-view=governance]", playwright.WaitForSelectorStateVisible, "admin sees governance panel")
	waitState(admin, "[data-view=dashboard]", playwright.WaitForSelectorStateVisible, "admin sees dashboard")

	// ── Viewer: admin/operator nav is HIDDEN, read-only nav remains ─────────
	viewer := openAs(viewerUser, RoleViewer)
	waitState(viewer, "#nav-users", playwright.WaitForSelectorStateHidden, "viewer cannot see users panel (admin-only)")
	waitState(viewer, "[data-view=governance]", playwright.WaitForSelectorStateHidden, "viewer cannot see governance panel (admin-only)")
	waitState(viewer, "[data-view=policy]", playwright.WaitForSelectorStateHidden, "viewer cannot see policy panel (operator-only)")
	waitState(viewer, "[data-view=dashboard]", playwright.WaitForSelectorStateVisible, "viewer still sees the read-only dashboard")

	// ── Backstop: the server denies a viewer's admin-only mutation ──────────
	// Uses the viewer context's own request store (same cookie), so this is the
	// UI being bypassed — the handler/C2 gate must still 403. This is the whole
	// point: gating the nav is UX; the server is the security boundary.
	viewerCtx := viewer.Context()
	resp, err := viewerCtx.Request().Post(srv.URL+"/api/auth/users", playwright.APIRequestContextPostOptions{
		Data: map[string]any{"username": "mallory", "password": "Should-not-work-1!", "role": "admin"},
	})
	if err != nil {
		t.Fatalf("viewer POST /api/auth/users: %v", err)
	}
	if resp.Status() != http.StatusForbidden {
		t.Errorf("BYPASS: viewer POST /api/auth/users returned %d, want 403 — the server must deny admin-only mutations regardless of the UI", resp.Status())
	}
	// And the user must not have been created.
	if cfg.UIUserExists("mallory") {
		t.Error("BYPASS: viewer-created admin user 'mallory' exists — server-side RBAC failed")
	}
}
