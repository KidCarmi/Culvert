//go:build uie2e

package main

// UI policy-editor cross-plane E2E (advisory tier), slice 3.
//
// The strongest UI assertion in the suite: a policy rule created through the
// admin SPA takes effect on the LIVE traffic plane. The admin UI and the proxy
// share the same process-global policyStore, so a rule saved via the policy
// panel is immediately authoritative for real requests through the proxy
// listener. This proves the control plane (UI) and data plane (proxy) are wired
// end-to-end, not just that the API accepted a write.
//
// Flow (hermetic, in-process):
//   1. Boot the admin UI (httptest) AND a real proxy listener + counting backend.
//   2. Baseline default-deny → a request through the proxy is 403 (no rule).
//   3. In the SPA policy panel, create an "allow *" rule and Save.
//   4. Assert the rule appears in the UI table AND the same request now reaches
//      the backend (200) — deny→allow, driven entirely from the browser.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_PolicyEditorCrossPlane(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Policy-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	proxyURL := startTestProxy(t) // sets default-allow + clears rules; restores both on cleanup
	backend, cb := startCountingBackend(t)

	// seedUIRoster MUST run AFTER startTestProxy: setupProxyTest (inside it)
	// replaces the global cfg with a fresh, unconfigured one, which would leave
	// the SPA showing the first-run setup wizard (occluding the nav). Seeding
	// after re-establishes the admin credential backend + UI users.
	seedUIRoster(t, adminUser, viewerUser, pass)

	// seedUIRoster's SetAuth enables proxy authentication, which would 407 our
	// unauthenticated probe before policy runs. Open the proxy's Stage-1 default
	// (Exempt) so the request reaches policy evaluation — this test is about the
	// POLICY gate, not proxy auth. The UI stays configured + gated (IsConfigured
	// is still true, sessions still carry roles).
	prevOutcome := cfg.DefaultAuthOutcome()
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(prevOutcome) })

	// Establish a default-deny + empty-rules baseline AFTER startTestProxy (which
	// installs default-allow). startTestProxy's own cleanup restores prior state.
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll(nil)

	// ── Baseline: default-deny, no rules → proxy denies the request ─────────
	if status := proxyGETStatus(t, proxyURL, backend.URL); status != http.StatusForbidden {
		t.Fatalf("baseline (default-deny, no rules): proxy returned %d, want 403", status)
	}

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)

	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// Switch to the policy panel (admin has the operator-gated nav item). Use
	// First() so a duplicate nav entry (e.g. a responsive/mobile copy) can't turn
	// the click into a strict-mode wait.
	if err := page.Locator(`.nav-item[data-view="policy"]`).First().Click(); err != nil {
		t.Fatalf("open policy panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#pol-name")).ToBeVisible(); err != nil {
		t.Fatalf("policy form should be visible in the policy panel: %v", err)
	}
	// Wait for the panel's initial fetchPolicy() to settle (empty-state shown)
	// BEFORE submitting. Otherwise the panel-open fetch and the submit's fetch
	// race, and if the (stale, 0-rule) panel-open fetch resolves last it leaves
	// the table empty with nothing to re-render it.
	if err := assert.Locator(page.Locator("#pol-table")).ToContainText("No policy rules"); err != nil {
		t.Fatalf("policy table should show its empty state before we add a rule: %v", err)
	}

	// ── Create an "allow *" rule through the form ───────────────────────────
	const ruleName = "e2e-allow-all"
	if err := page.Locator("#pol-name").Fill(ruleName); err != nil {
		t.Fatalf("fill name: %v", err)
	}
	if err := page.Locator("#pol-dest-fqdn").Fill("*"); err != nil {
		t.Fatalf("fill dest: %v", err)
	}
	if _, err := page.Locator("#pol-action").SelectOption(playwright.SelectOptionValues{
		Values: playwright.StringSlice(string(ActionAllow)),
	}); err != nil {
		t.Fatalf("select action: %v", err)
	}
	if err := page.Locator("#policy-submit-btn").Click(); err != nil {
		t.Fatalf("submit rule: %v", err)
	}
	// Confirm the server accepted the write before checking the rendered table.
	if err := assert.Locator(page.Locator("#pol-name")).ToBeEmpty(); err != nil {
		t.Logf("note: form did not clear after submit: %v", err)
	}

	// ── UI round-trip: the new rule appears in the policy table ─────────────
	// Re-open the panel (dashboard → policy) so a single clean fetchPolicy()
	// renders the row. A direct post-submit assert is racy: the panel-open fetch
	// and the submit's fetch both run, and if the stale panel-open fetch resolves
	// last the table is left empty with nothing to re-render it.
	if err := page.Locator(`.nav-item[data-view="dashboard"]`).First().Click(); err != nil {
		t.Fatalf("nav to dashboard: %v", err)
	}
	if err := page.Locator(`.nav-item[data-view="policy"]`).First().Click(); err != nil {
		t.Fatalf("re-open policy panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#pol-table")).ToContainText(ruleName); err != nil {
		t.Errorf("created rule should appear in the policy table after re-opening the panel: %v", err)
	}

	// ── Cross-plane: the SAME request now reaches the backend (deny→allow) ───
	before := cb.hitCount()
	if status := proxyGETStatus(t, proxyURL, backend.URL); status != http.StatusOK {
		t.Errorf("after UI created an allow rule, proxy returned %d, want 200 (cross-plane effect)", status)
	}
	if cb.hitCount() <= before {
		t.Error("after UI created an allow rule, the backend was not reached — control-plane change did not affect the data plane")
	}
}

// proxyGETStatus issues a GET to target through the proxy and returns the status
// code (or fails the test on a transport error).
func proxyGETStatus(t *testing.T, proxyURL *url.URL, target string) int {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := ctxGet(client, target)
	if err != nil {
		t.Fatalf("proxied GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
