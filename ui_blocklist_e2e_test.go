//go:build uie2e

package main

// Blocklist cross-plane E2E — advisory tier.
//
// A host the admin adds to the blocklist through the UI is blocked on the LIVE
// proxy: the admin UI and the proxy share the same process-global blocklist, and
// the proxy consults it (bl.IsBlocked) in its pre-policy content gate. Distinct
// from the policy-editor slice — this exercises the legacy blocklist path, which
// blocks BEFORE the policy engine.
//
// Flow (hermetic, in-process): boot the admin UI + a real proxy + counting
// backend; confirm the backend is reachable; add its host to the blocklist via
// the UI; confirm the same request is now blocked and never reaches the backend.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_BlocklistCrossPlane(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Blk-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	proxyURL := startTestProxy(t) // default-allow, empty rules + blocklist; restores on cleanup
	backend, cb := startCountingBackend(t)

	// Seed AFTER startTestProxy (it replaces cfg + resets bl). Open the proxy's
	// Stage-1 default so an unauthenticated probe reaches the content gate.
	seedUIRoster(t, adminUser, viewerUser, pass)
	prevOutcome := cfg.DefaultAuthOutcome()
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(prevOutcome) })

	host := mustHostname(t, backend.URL)

	// ── Baseline: not blocklisted → the request reaches the backend ─────────
	before := cb.hitCount()
	if s := proxyGETStatus(t, proxyURL, backend.URL); s != http.StatusOK {
		t.Fatalf("baseline: proxy returned %d, want 200 (host not blocklisted yet)", s)
	}
	if cb.hitCount() <= before {
		t.Fatal("baseline: backend was not reached")
	}

	// ── Admin adds the host to the blocklist through the UI ─────────────────
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="blocklist"]`).First().Click(); err != nil {
		t.Fatalf("open blocklist panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#new-host")).ToBeVisible(); err != nil {
		t.Fatalf("blocklist add field should be visible: %v", err)
	}
	if err := page.Locator("#new-host").Fill(host); err != nil {
		t.Fatalf("fill host: %v", err)
	}
	if err := page.Locator(`[data-click="addHost"]`).First().Click(); err != nil {
		t.Fatalf("click add host: %v", err)
	}

	// ── Cross-plane: the same request is now blocked ────────────────────────
	// The click's POST is async, so poll until the shared blocklist has
	// propagated (the very first request may still race the in-flight add).
	var last int
	blocked := false
	for i := 0; i < 20; i++ {
		last = proxyGETStatus(t, proxyURL, backend.URL)
		if last == http.StatusForbidden {
			blocked = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !blocked {
		t.Fatalf("after UI blocklisted %q, proxy never returned 403 (last=%d) — blocklist gate did not fire", host, last)
	}

	// Steady state: once blocked, a fresh request is denied AND never reaches the
	// backend (the blocklist gate runs before the request is forwarded).
	hitsBefore := cb.hitCount()
	if s := proxyGETStatus(t, proxyURL, backend.URL); s != http.StatusForbidden {
		t.Errorf("blocklisted host: proxy returned %d, want 403", s)
	}
	if cb.hitCount() != hitsBefore {
		t.Errorf("a blocklisted request reached the backend — the gate must block before forwarding")
	}
}

// mustHostname returns the hostname (no port) of a URL, failing the test on error.
func mustHostname(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}
