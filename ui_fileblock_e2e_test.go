//go:build uie2e

package main

// File-extension blocking cross-plane E2E — advisory tier.
//
// A file extension the admin blocks through the UI is enforced on the LIVE
// proxy: the admin UI and the proxy share the same process-global file blocker,
// and the proxy calls fileBlocker.CheckPath on the request path in its pre-policy
// content gate. A request for a path with that extension is then blocked before
// it reaches the upstream.
//
// Hermetic + in-process. Uses a deliberately unusual extension so the added rule
// cannot collide with any other test's traffic.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_FileBlockCrossPlane(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Fb-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	const ext = "e2eblk"                                                            // unusual → no collision with real traffic
	probePath := "/download.probe." + ext

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	proxyURL := startTestProxy(t) // default-allow so a non-blocked request forwards
	backend, cb := startCountingBackend(t)

	seedUIRoster(t, adminUser, viewerUser, pass)
	prevOutcome := cfg.DefaultAuthOutcome()
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(prevOutcome) })

	// ── Baseline: extension not blocked → the request reaches the backend ───
	before := cb.hitCount()
	if s := proxyGETStatus(t, proxyURL, backend.URL+probePath); s != http.StatusOK {
		t.Fatalf("baseline: proxy returned %d for %q, want 200", s, probePath)
	}
	if cb.hitCount() <= before {
		t.Fatal("baseline: backend was not reached")
	}

	// ── Admin blocks the extension through the UI ───────────────────────────
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="fileblock"]`).First().Click(); err != nil {
		t.Fatalf("open fileblock panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#fb-ext-input")).ToBeVisible(); err != nil {
		t.Fatalf("fileblock add field should be visible: %v", err)
	}
	if err := page.Locator("#fb-ext-input").Fill(ext); err != nil {
		t.Fatalf("fill extension: %v", err)
	}
	if err := page.Locator(`[data-click="addFileExt"]`).First().Click(); err != nil {
		t.Fatalf("click add extension: %v", err)
	}

	// ── Cross-plane: a request for that extension is now blocked ─────────────
	var last int
	blocked := false
	for i := 0; i < 20; i++ {
		last = proxyGETStatus(t, proxyURL, backend.URL+probePath)
		if last == http.StatusForbidden {
			blocked = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !blocked {
		t.Fatalf("after UI blocked .%s, proxy never returned 403 for %q (last=%d)", ext, probePath, last)
	}

	// Steady state: the block holds and the backend is not reached.
	hitsBefore := cb.hitCount()
	if s := proxyGETStatus(t, proxyURL, backend.URL+probePath); s != http.StatusForbidden {
		t.Errorf("blocked extension: proxy returned %d, want 403", s)
	}
	if cb.hitCount() != hitsBefore {
		t.Errorf("a file-blocked request reached the backend — the gate must block before forwarding")
	}
}
