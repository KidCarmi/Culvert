//go:build uie2e

package main

// Header-rewrite cross-plane E2E — advisory tier.
//
// A request-header rewrite rule the admin adds through the UI is applied on the
// LIVE proxy: the admin UI and the proxy share the same process-global rewriter,
// and the proxy calls rewriter.ApplyRequest before forwarding upstream. This
// proves the rewrite control plane reaches the data plane — the upstream
// actually receives the injected header.
//
// Hermetic + in-process: a header-capturing loopback backend records what the
// proxy forwards.

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_HeaderRewriteCrossPlane(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Rw-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	const hdrName, hdrValue = "X-E2E-Rewrite", "applied-by-ui"

	// Header-capturing upstream: records the value of hdrName on each request.
	var lastHdr atomic.Value // string
	lastHdr.Store("")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastHdr.Store(r.Header.Get(hdrName))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	// Restore the global rewriter after the test (registered before startTestProxy
	// so this runs AFTER the proxy is torn down — no racing the hot path).
	oldRewriter := rewriter
	t.Cleanup(func() { rewriter = oldRewriter })

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	proxyURL := startTestProxy(t) // default-allow so the request forwards upstream
	host := mustHostname(t, backend.URL)

	seedUIRoster(t, adminUser, viewerUser, pass)
	prevOutcome := cfg.DefaultAuthOutcome()
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(prevOutcome) })

	// ── Baseline: no rewrite rule → upstream sees no injected header ─────────
	if s := proxyGETStatus(t, proxyURL, backend.URL); s != http.StatusOK {
		t.Fatalf("baseline: proxy returned %d, want 200", s)
	}
	if got := lastHdr.Load().(string); got != "" {
		t.Fatalf("baseline: upstream already saw %s=%q, want empty", hdrName, got)
	}

	// ── Admin adds a request-header "set" rule through the UI ────────────────
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="rewrite"]`).First().Click(); err != nil {
		t.Fatalf("open rewrite panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#rw-host")).ToBeVisible(); err != nil {
		t.Fatalf("rewrite form should be visible: %v", err)
	}
	if err := page.Locator("#rw-host").Fill(host); err != nil {
		t.Fatalf("fill host: %v", err)
	}
	if _, err := page.Locator("#rw-req-action").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice("set"),
	}); err != nil {
		t.Fatalf("select req action: %v", err)
	}
	if err := page.Locator("#rw-req-name").Fill(hdrName); err != nil {
		t.Fatalf("fill header name: %v", err)
	}
	if err := page.Locator("#rw-req-value").Fill(hdrValue); err != nil {
		t.Fatalf("fill header value: %v", err)
	}
	if err := page.Locator(`[data-click="addRewriteRule"]`).First().Click(); err != nil {
		t.Fatalf("add rewrite rule: %v", err)
	}

	// ── Cross-plane: the upstream now receives the injected header ───────────
	// The click's POST is async; poll a fresh request until the rule propagates.
	got := ""
	for i := 0; i < 20; i++ {
		if s := proxyGETStatus(t, proxyURL, backend.URL); s != http.StatusOK {
			t.Fatalf("proxy returned %d, want 200", s)
		}
		if got = lastHdr.Load().(string); got == hdrValue {
			break
		}
	}
	if got != hdrValue {
		t.Errorf("upstream saw %s=%q after UI added a set-rule, want %q — rewrite did not reach the data plane", hdrName, got, hdrValue)
	}
}
