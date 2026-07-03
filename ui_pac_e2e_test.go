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
