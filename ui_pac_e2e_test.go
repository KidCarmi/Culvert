//go:build uie2e

package main

// PAC (proxy auto-config) E2E — advisory tier.
//
// Culvert serves a dynamically generated PAC file at /proxy.pac for browser
// auto-configuration, and the admin UI's PAC panel previews/manages it. This
// proves both halves are wired: the served /proxy.pac is a valid PAC document,
// and the PAC panel renders the same generated config.
//
// Hermetic + in-process. /proxy.pac is intentionally UNAUTHENTICATED (PAC
// clients cannot present a session), so it is fetched without credentials.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_PACServedAndPreviewed(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Pac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// ── The served /proxy.pac is a valid PAC document (unauthenticated) ─────
	// Fetch with a plain, cookie-less client — NOT the browser context, which
	// carries the admin session. PAC clients cannot present a session, so this is
	// the actual contract: /proxy.pac must be served without auth. Going through
	// the browser context would still get 200 even if the route regressed to
	// require a session, silently dropping the coverage this test exists for.
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get(uiSrv.URL + "/proxy.pac")
	if err != nil {
		t.Fatalf("GET /proxy.pac: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/proxy.pac status %d, want 200 (it must be reachable without auth)", resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /proxy.pac body: %v", err)
	}
	body := string(bodyBytes)
	if !strings.Contains(body, "FindProxyForURL") {
		t.Errorf("/proxy.pac is not a valid PAC document (no FindProxyForURL):\n%.300s", body)
	}
	if !strings.Contains(body, "PROXY") {
		t.Errorf("/proxy.pac has no PROXY directive:\n%.300s", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "proxy-autoconfig") {
		t.Errorf("/proxy.pac content-type = %q, want x-ns-proxy-autoconfig", ct)
	}

	// ── The PAC panel renders the generated PAC preview ─────────────────────
	if err := page.Locator(`.nav-item[data-view="pac"]`).First().Click(); err != nil {
		t.Fatalf("open PAC panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#pac-preview")).ToContainText("FindProxyForURL"); err != nil {
		got, _ := page.Locator("#pac-preview").TextContent()
		t.Errorf("PAC panel preview should render the generated PAC; got:\n%.300s\n(%v)", got, err)
	}
}

// TestUIE2E_PACProfileEndpointsServed pins the PR-2 profile surface: the
// /pac/default.pac alias is served unauthenticated and byte-equal to
// /proxy.pac, and the PAC panel renders the Steering Profiles section.
func TestUIE2E_PACProfileEndpointsServed(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-pacprof", "viewer-pacprof", "Pac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	client := &http.Client{Timeout: 5 * time.Second} // deliberately cookie-less
	fetch := func(path string) string {
		t.Helper()
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s status %d, want 200 (unauthenticated PAC contract)", path, resp.StatusCode)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(b)
	}
	legacy := fetch("/proxy.pac")
	alias := fetch("/pac/default.pac")
	if legacy != alias {
		t.Errorf("/pac/default.pac must be byte-identical to /proxy.pac")
	}

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)
	assert := playwright.NewPlaywrightAssertions(8000)
	if err := page.Locator(`.nav-item[data-view="pac"]`).First().Click(); err != nil {
		t.Fatalf("open PAC panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#pac-profiles-list")).ToContainText("default"); err != nil {
		t.Errorf("Steering Profiles list should render the default profile: %v", err)
	}
}

// TestUIE2E_PACInventoryAndChangePreview pins the PEI posture surface in the
// PAC panel: the DIRECT Bypass Inventory renders its config-evidence summary,
// and the P3 change-preview (expand → Preview DIRECT changes) returns a diff.
func TestUIE2E_PACInventoryAndChangePreview(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-pacinv", "viewer-pacinv", "Pac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)
	assert := playwright.NewPlaywrightAssertions(8000)
	if err := page.Locator(`.nav-item[data-view="pac"]`).First().Click(); err != nil {
		t.Fatalf("open PAC panel: %v", err)
	}

	// Inventory summary renders with the config-evidence label (Observable).
	if err := assert.Locator(page.Locator("#pac-posture-summary")).ToContainText("evidence: config"); err != nil {
		got, _ := page.Locator("#pac-posture-summary").TextContent()
		t.Errorf("DIRECT Bypass Inventory summary should render; got %q (%v)", got, err)
	}

	// Change preview: expand, then run the diff (pre-filled with current config,
	// so an unchanged candidate reports no DIRECT-surface change).
	if err := page.Locator("#pac-diff-summary").Click(); err != nil {
		t.Fatalf("expand change preview: %v", err)
	}
	if err := assert.Locator(page.Locator("#pac-diff-input")).Not().ToBeEmpty(); err != nil {
		t.Errorf("change-preview editor should pre-fill with the current config: %v", err)
	}
	if err := page.Locator(`[data-click="runPacDiff"]`).Click(); err != nil {
		t.Fatalf("run change preview: %v", err)
	}
	if err := assert.Locator(page.Locator("#pac-diff-result")).ToContainText("bypass"); err != nil {
		got, _ := page.Locator("#pac-diff-result").TextContent()
		t.Errorf("change preview should render a DIRECT-surface diff; got %q (%v)", got, err)
	}
}

// TestUIE2E_PACSaveConfigRefreshesPreview proves the Save Configuration button
// persists and the Live PAC Preview reflects the saved proxy host.
func TestUIE2E_PACSaveConfigRefreshesPreview(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-pacsave", "viewer-pacsave", "Pac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)
	assert := playwright.NewPlaywrightAssertions(8000)
	if err := page.Locator(`.nav-item[data-view="pac"]`).First().Click(); err != nil {
		t.Fatalf("open PAC panel: %v", err)
	}
	const host = "proxy.polish.example"
	if err := page.Locator("#pac-host").Fill(host); err != nil {
		t.Fatalf("fill pac host: %v", err)
	}
	if err := page.Locator(`[data-click="savePACConfig"]`).Click(); err != nil {
		t.Fatalf("click Save Configuration: %v", err)
	}
	// On success savePACConfig refreshes the preview, which must now route
	// through the saved host.
	if err := assert.Locator(page.Locator("#pac-preview")).ToContainText(host); err != nil {
		got, _ := page.Locator("#pac-preview").TextContent()
		t.Errorf("preview should reflect the saved proxy host %q; got:\n%.300s\n(%v)", host, got, err)
	}
}

// TestUIE2E_PACEditorsOpen proves the "+ New Profile" and "+ New Pool" buttons
// reveal their inline editors (the create flow entry points work).
func TestUIE2E_PACEditorsOpen(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-paced", "viewer-paced", "Pac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)
	assert := playwright.NewPlaywrightAssertions(8000)
	if err := page.Locator(`.nav-item[data-view="pac"]`).First().Click(); err != nil {
		t.Fatalf("open PAC panel: %v", err)
	}
	if err := page.Locator(`[data-click="newPACProfile"]`).Click(); err != nil {
		t.Fatalf("click New Profile: %v", err)
	}
	if err := assert.Locator(page.Locator("#pac-profile-editor")).ToBeVisible(); err != nil {
		t.Errorf("New Profile should open the profile editor: %v", err)
	}
	if err := page.Locator(`[data-click="newPACPool"]`).Click(); err != nil {
		t.Fatalf("click New Pool: %v", err)
	}
	if err := assert.Locator(page.Locator("#pac-pool-editor")).ToBeVisible(); err != nil {
		t.Errorf("New Pool should open the pool editor: %v", err)
	}
}

// TestUIE2E_PACSimulator pins the PR-3 simulator panel: it renders and a
// simulate call returns an explained directive for the default profile.
func TestUIE2E_PACSimulator(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-pacsim", "viewer-pacsim", "Pac-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)
	assert := playwright.NewPlaywrightAssertions(8000)
	if err := page.Locator(`.nav-item[data-view="pac"]`).First().Click(); err != nil {
		t.Fatalf("open PAC panel: %v", err)
	}
	if err := page.Locator("#pacsim-host").Fill("intranet.corp.example"); err != nil {
		t.Fatalf("fill sim host: %v", err)
	}
	if err := page.Locator(`[data-click="runPACSimulate"]`).Click(); err != nil {
		t.Fatalf("run simulate: %v", err)
	}
	if err := assert.Locator(page.Locator("#pacsim-result")).ToContainText("Directive"); err != nil {
		t.Errorf("simulator should render a directive result: %v", err)
	}
}
