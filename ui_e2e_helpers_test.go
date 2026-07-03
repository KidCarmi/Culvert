//go:build uie2e

package main

// Shared harness for the admin-UI browser E2E suite (advisory tier).
//
// Build/run only under `-tags uie2e` so playwright-go and a real browser are
// NEVER pulled into the default `go test ./...` (the required qa-gate) or the
// shipped single binary. Everything here is hermetic: the REAL admin-UI handler
// chain is mounted in-process via httptest.NewServer (buildUIHandler), users are
// seeded into a temp store, and sessions are minted directly — no public
// internet, no external services.
//
// Browser provisioning is environment-driven so the same test runs in two
// places without code changes:
//   - CI: the workflow pre-installs the pinned playwright-go driver + chromium
//     into the default cache; the test calls playwright.Install (no-op) then
//     Launch finds the browser.
//   - Local/sandbox: set CULVERT_PW_DRIVER_DIR to a driver dir and
//     CULVERT_PW_CHROMIUM to a chromium binary; the test uses them as-is.
// If a browser cannot be obtained, the test SKIPS (advisory — never a hard
// failure in an unprovisioned environment).

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// uiE2EBrowser starts playwright and launches headless Chromium, or SKIPS the
// test if neither a driver nor a browser can be obtained. Cleanup is registered
// on t.
func uiE2EBrowser(t *testing.T) playwright.Browser {
	t.Helper()

	runOpts := &playwright.RunOptions{SkipInstallBrowsers: true}
	if dir := os.Getenv("CULVERT_PW_DRIVER_DIR"); dir != "" {
		runOpts.DriverDirectory = dir
	} else if err := playwright.Install(runOpts); err != nil {
		t.Skipf("playwright driver unavailable (advisory tier, skipping): %v", err)
	}

	pw, err := playwright.Run(runOpts)
	if err != nil {
		t.Skipf("playwright driver unavailable (advisory tier, skipping): %v", err)
	}

	launch := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     []string{"--no-sandbox"}, // required in the CI/sandbox container
	}
	if exe := chromiumExecutable(); exe != "" {
		launch.ExecutablePath = playwright.String(exe)
	}
	browser, err := pw.Chromium.Launch(launch)
	if err != nil {
		_ = pw.Stop()
		t.Skipf("chromium launch failed (advisory tier, skipping): %v", err)
	}
	t.Cleanup(func() {
		_ = browser.Close()
		_ = pw.Stop()
	})
	return browser
}

// chromiumExecutable resolves the Chromium binary: explicit override first, then
// the first chrome under PLAYWRIGHT_BROWSERS_PATH, else "" (let playwright pick
// the browser it installed).
func chromiumExecutable() string {
	if exe := os.Getenv("CULVERT_PW_CHROMIUM"); exe != "" {
		return exe
	}
	root := os.Getenv("PLAYWRIGHT_BROWSERS_PATH")
	if root == "" {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(root, "chromium-*", "chrome-linux", "chrome"))
	if len(matches) > 0 {
		return matches[0]
	}
	return ""
}

// seedUIRoster marks the instance "configured" (so the auth middleware enforces
// per-session roles instead of falling back to RoleAdmin for everyone) and
// creates an admin + viewer UI user in an isolated temp store. Everything is
// restored on cleanup.
func seedUIRoster(t *testing.T, adminUser, viewerUser, pass string) {
	t.Helper()

	// Isolate the UI-user store to a temp file so we don't touch real state.
	tmp := filepath.Join(t.TempDir(), "ui_users.json")
	cfg.SetUIUsersFile(tmp)

	// A credential backend must exist for cfg.IsConfigured() to be true; without
	// it the middleware treats setup as incomplete and grants RoleAdmin to all,
	// which would defeat the viewer half of the RBAC test.
	if err := cfg.SetAuth("bootstrap-admin", "Bootstrap-admin-1!"); err != nil {
		t.Fatalf("SetAuth (mark configured): %v", err)
	}
	if !cfg.IsConfigured() {
		t.Fatal("cfg.IsConfigured() is false after SetAuth — RBAC gating would be disabled")
	}
	if err := cfg.SetUIUser(adminUser, pass, RoleAdmin); err != nil {
		t.Fatalf("SetUIUser admin: %v", err)
	}
	if err := cfg.SetUIUser(viewerUser, pass, RoleViewer); err != nil {
		t.Fatalf("SetUIUser viewer: %v", err)
	}
	if len(sessionSecret) == 0 {
		initSessionSecret() // encodeSession needs the HMAC key
	}
	t.Cleanup(func() {
		_ = cfg.DeleteUIUser(viewerUser)
		_ = cfg.DeleteUIUser(adminUser)
		_ = cfg.SetAuth("", "")
	})
}

// newUIPage opens a fresh browser context + page and navigates to base, waiting
// for network idle so the SPA's on-load /api/auth/status fetch has completed.
// The context is closed on cleanup.
func newUIPage(t *testing.T, browser playwright.Browser, base string) (playwright.BrowserContext, playwright.Page) {
	t.Helper()
	ctx, err := browser.NewContext()
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	if _, err := page.Goto(base+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateNetworkidle}); err != nil {
		t.Fatalf("goto %s: %v", base, err)
	}
	return ctx, page
}

// mintUISessionValue produces a signed ps_ui_session cookie value for user/role,
// identical to what setUISessionCookie writes — so the browser is authenticated
// deterministically without driving the login overlay (that fidelity is slice 2).
func mintUISessionValue(t *testing.T, user string, role UIRole) string {
	t.Helper()
	value, err := encodeSession(&Session{
		Sub:      user,
		Provider: "local",
		Role:     string(role),
		Exp:      time.Now().Add(getSessionTTL()).Unix(),
		Jti:      newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	return value
}
