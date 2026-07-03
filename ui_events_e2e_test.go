//go:build uie2e

package main

// Live SSE dashboard E2E (advisory tier), slice 4.
//
// Proves the real-time telemetry path end-to-end: the dashboard opens an
// EventSource to /api/events, and when live proxy traffic moves a global
// counter, the SPA's stat tile updates from an SSE data frame — no reload, no
// polling. This exercises the broadcaster → sseHub → EventSource → DOM chain
// against the REAL admin-UI handler and a REAL proxy listener in one process.
//
// Flow (hermetic, in-process):
//   1. Boot the admin UI (httptest) + a real proxy + counting backend, and start
//      the 1s SSE broadcaster (cancelled on cleanup).
//   2. Block-all policy so each proxied request increments statBlocked.
//   3. Open the dashboard as admin (EventSource connects → hub has a client).
//   4. Snapshot the rendered "blocked" tile, send N blocked requests, and assert
//      the tile climbs by >= N via a live SSE push.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_LiveSSEDashboard(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Events-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	proxyURL := startTestProxy(t)
	backend, _ := startCountingBackend(t)

	// seedUIRoster after startTestProxy (setupProxyTest replaces cfg). Open the
	// proxy's Stage-1 default so requests reach POLICY (a block increments
	// statBlocked) instead of 407'ing on proxy auth.
	seedUIRoster(t, adminUser, viewerUser, pass)
	prevOutcome := cfg.DefaultAuthOutcome()
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(prevOutcome) })

	// Block-all policy so each proxied request bumps statBlocked deterministically.
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll([]PolicyRule{{Priority: 1, Name: "block-all", DestFQDN: "*", Action: ActionBlockPage}})

	// Start the live broadcaster (production ticks at 1s). tick() only emits when
	// an SSE client is connected, so this is a no-op until the dashboard opens.
	sseCtx, sseCancel := context.WithCancel(context.Background())
	startSSEBroadcaster(sseCtx)
	t.Cleanup(sseCancel)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)

	// Dashboard is the default view on load.
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)
	if err := assert.Locator(page.Locator("#d-blocked")).ToBeVisible(); err != nil {
		t.Fatalf("dashboard blocked tile should be visible: %v", err)
	}

	before := statTileValue(t, page, "#d-blocked")

	// Generate N blocked requests through the proxy → statBlocked += N.
	const n = 6
	for i := 0; i < n; i++ {
		if status := proxyGETStatus(t, proxyURL, backend.URL); status != http.StatusForbidden {
			t.Fatalf("request %d: proxy returned %d, want 403 (block-all)", i+1, status)
		}
	}

	// The blocked tile must climb by >= N via a live SSE data frame (not a reload).
	want := before + n
	if _, err := page.WaitForFunction(
		fmt.Sprintf(`() => { const t = (document.getElementById('d-blocked').textContent||'').replace(/[^0-9]/g,''); return parseInt(t||'0', 10) >= %d; }`, want),
		nil,
		playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(10000)},
	); err != nil {
		got := statTileValue(t, page, "#d-blocked")
		t.Errorf("blocked tile did not reach >= %d via live SSE (before=%d, sent=%d, got=%d): %v", want, before, n, got, err)
	}
}

// statTileValue reads a dashboard stat tile's text and parses its integer value
// (stripping thousands separators / non-digits).
func statTileValue(t *testing.T, page playwright.Page, selector string) int {
	t.Helper()
	txt, err := page.Locator(selector).TextContent()
	if err != nil {
		t.Fatalf("read %s: %v", selector, err)
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, txt)
	if digits == "" {
		return 0
	}
	v, err := strconv.Atoi(digits)
	if err != nil {
		t.Fatalf("parse %s value %q: %v", selector, txt, err)
	}
	return v
}
