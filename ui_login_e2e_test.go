//go:build uie2e

package main

// UI login / auth flows — real-browser E2E (advisory tier), slice 2.
//
// Where slice 1 injected a session cookie, this drives the actual login overlay:
// wrong credentials are rejected (error shown, still gated), correct credentials
// authenticate (overlay clears, role gating applies, identity shown), logout
// returns to the gated state and clears the session, and repeated failures trip
// the brute-force lockout (429). All through the REAL admin-UI handler chain
// mounted in-process — the same login endpoint, session cookie, and lockout the
// product uses.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_LoginFlow(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Login-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)
	// Isolate the process-global login limiter so failed-attempt counters from
	// (or into) other tests cannot make the lockout assertion flaky.
	t.Cleanup(loginLimiter.SnapshotAndClear())

	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)

	// expect turns a (non-fatal) assertion error into a t.Errorf, keeping the
	// linear flow below flat (one branch per check would blow the cyclop budget).
	expect := func(err error, msg string) {
		t.Helper()
		if err != nil {
			t.Errorf("%s: %v", msg, err)
		}
	}

	ctx, page := newUIPage(t, browser, srv.URL)

	overlay := page.Locator("#login-overlay")
	errEl := page.Locator("#li-err")

	// submit fills the form and clicks Sign In; Click auto-waits for the button
	// to be re-enabled, so consecutive submits serialize on the in-flight request.
	submit := func(user, pw string) {
		t.Helper()
		if err := page.Locator("#li-user").Fill(user); err != nil {
			t.Fatalf("fill user: %v", err)
		}
		if err := page.Locator("#li-pass").Fill(pw); err != nil {
			t.Fatalf("fill pass: %v", err)
		}
		if err := page.Locator("#li-btn").Click(); err != nil {
			t.Fatalf("click sign-in: %v", err)
		}
	}

	// ── Gate: unauthenticated + configured → login overlay is shown ─────────
	if err := assert.Locator(overlay).ToBeVisible(); err != nil {
		t.Fatalf("login overlay should be visible before auth: %v", err)
	}

	// ── Wrong password → error surfaced, still gated ────────────────────────
	submit(adminUser, "definitely-wrong")
	expect(assert.Locator(errEl).ToBeVisible(), "invalid credentials should surface an error")
	expect(assert.Locator(overlay).ToBeVisible(), "after a failed login the overlay must remain (still gated)")

	// ── Correct password → authenticated: overlay clears, role gating applies ─
	submit(adminUser, pass)
	if err := assert.Locator(overlay).ToBeHidden(); err != nil {
		t.Fatalf("valid login should dismiss the overlay: %v", err)
	}
	expect(assert.Locator(page.Locator("#nav-users")).ToBeVisible(), "admin should see the admin-only users panel after login")
	expect(assert.Locator(page.Locator("#topbar-username")).ToHaveText(adminUser), "topbar should show the logged-in identity")

	// ── Logout → gated again, and the server session is cleared ─────────────
	if err := page.Locator("#logout-btn").Click(); err != nil {
		t.Fatalf("click logout: %v", err)
	}
	expect(assert.Locator(overlay).ToBeVisible(), "logout must return to the gated (overlay) state")
	if authStatusLoggedIn(t, ctx, srv.URL) {
		t.Error("after logout /api/auth/status still reports loggedIn=true — session not cleared")
	}

	// ── Brute-force lockout: repeated failures trip the 429 lockout ─────────
	// A dedicated username (never a real user) so this cannot lock out the
	// seeded admin/viewer accounts. MaxAttempts=5 → the 5th failure locks.
	for i := 0; i < 5; i++ {
		submit("ghost-e2e", "nope")
		expect(assert.Locator(errEl).ToBeVisible(), "failed attempt should surface an error")
	}
	if err := assert.Locator(errEl).ToContainText("locked"); err != nil {
		txt, _ := errEl.TextContent()
		t.Errorf("after 5 failed attempts the account should be locked (429); error was %q: %v", strings.TrimSpace(txt), err)
	}
}

// authStatusLoggedIn queries /api/auth/status through the context's cookie store
// (so it reflects the browser's current session) and returns the loggedIn flag.
func authStatusLoggedIn(t *testing.T, ctx playwright.BrowserContext, base string) bool {
	t.Helper()
	resp, err := ctx.Request().Get(base + "/api/auth/status")
	if err != nil {
		t.Fatalf("GET /api/auth/status: %v", err)
	}
	body, err := resp.Body()
	if err != nil {
		t.Fatalf("read status body: %v", err)
	}
	var s struct {
		LoggedIn bool `json:"loggedIn"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("decode status %q: %v", string(body), err)
	}
	return s.LoggedIn
}
