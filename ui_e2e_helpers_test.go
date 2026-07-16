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
	"strings"
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
		// --no-sandbox: required in the CI/sandbox container.
		// --no-proxy-server: the environment may set HTTP(S)_PROXY, which Chromium
		// otherwise honors — tunneling even loopback requests through an agent
		// proxy that cannot reach the in-process httptest server (the long-lived
		// SSE stream fails with ERR_TUNNEL_CONNECTION_FAILED). Force direct.
		Args: []string{"--no-sandbox", "--no-proxy-server"},
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
	cfg.mu.RLock()
	previousUIUsersFile := cfg.uiUsersFile
	cfg.mu.RUnlock()
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
	if !sessionSecretSet() {
		initSessionSecret() // encodeSession needs the HMAC key
	}
	t.Cleanup(func() {
		_ = cfg.DeleteUIUser(viewerUser)
		_ = cfg.DeleteUIUser(adminUser)
		_ = cfg.SetAuth("", "")
		cfg.SetUIUsersFile(previousUIUsersFile)
	})
}

// chartStubScript defines a no-op Chart.js so the SPA's on-load init does not
// abort at initChart(). The real dashboard loads Chart.js from a CDN that is
// unreachable in the hermetic test; without this stub initChart() throws
// "Chart is not defined", aborting the synchronous init block BEFORE
// connectSSE()/startTick() run — which the live-SSE test depends on. Charts
// themselves are out of scope for these tests.
const chartStubScript = `
window.Chart = function(){
  this.data = {labels: [], datasets: [{data: []},{data: []},{data: []}]};
  this.options = {}; this.config = {};
  this.update = function(){}; this.destroy = function(){}; this.resize = function(){};
};
window.Chart.register = function(){};
window.Chart.defaults = {plugins:{}, scales:{}};
`

// injectChartStub installs the Chart stub before any page script runs.
func injectChartStub(t *testing.T, ctx playwright.BrowserContext) {
	t.Helper()
	if err := ctx.AddInitScript(playwright.Script{Content: playwright.String(chartStubScript)}); err != nil {
		t.Fatalf("add chart stub init script: %v", err)
	}
}

// blockExternalRequests aborts every request that does not target the loopback
// test server (or a data:/blob: URL). This keeps the suite HERMETIC and, just as
// importantly, deterministic across environments: the SPA references an external
// Chart.js CDN, which is unreachable in the sandbox but REACHABLE from CI — a
// difference that made the full on-load init (and thus the page-load timing) vary
// between local and CI. Aborting external requests makes the CDN "fail" fast
// everywhere, so `load` fires promptly and the Chart stub is what initChart sees.
func blockExternalRequests(t *testing.T, ctx playwright.BrowserContext) {
	t.Helper()
	err := ctx.Route("**/*", func(route playwright.Route) {
		u := route.Request().URL()
		if strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost") ||
			strings.HasPrefix(u, "data:") || strings.HasPrefix(u, "blob:") {
			_ = route.Continue()
			return
		}
		_ = route.Abort()
	})
	if err != nil {
		t.Fatalf("route external block: %v", err)
	}
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
	injectChartStub(t, ctx)
	blockExternalRequests(t, ctx)
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	if _, err := page.Goto(base+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto %s: %v", base, err)
	}
	return ctx, page
}

// newAuthedUIPage opens a page already authenticated as user/role by injecting a
// signed ps_ui_session cookie BEFORE the first navigation (so the SPA's on-load
// auth/status fetch sees the session and applies role gating).
func newAuthedUIPage(t *testing.T, browser playwright.Browser, base, user string, role UIRole) (playwright.BrowserContext, playwright.Page) {
	t.Helper()
	ctx, err := browser.NewContext()
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	blockExternalRequests(t, ctx)
	if err := ctx.AddCookies([]playwright.OptionalCookie{{
		Name:  uiSessionCookieName,
		Value: mintUISessionValue(t, user, role),
		URL:   playwright.String(base),
	}}); err != nil {
		t.Fatalf("add cookie: %v", err)
	}
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	if _, err := page.Goto(base+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
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
