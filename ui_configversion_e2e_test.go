//go:build uie2e

package main

// Config-versioning rollback cross-plane E2E — advisory tier.
//
// The strongest governance assertion in the suite: rolling back a config
// version through the admin SPA reverts the LIVE traffic plane. Config
// snapshots are auto-created on every mutating change (saveConfigVersion), the
// Settings panel surfaces them, and the Rollback button re-applies a snapshot
// via applyConfigBackup — which bulk-replaces the process-global policyStore the
// proxy consults on every request. So a rollback driven entirely from the
// browser is authoritative for real traffic, not just an accepted API write.
//
// Flow (hermetic, in-process):
//   1. Redirect configVersionsDir to a temp dir; boot UI + real proxy + backend.
//   2. Establish a default-deny, no-rules baseline and snapshot it (v = baseline).
//   3. Baseline: a proxied request is 403 (default-deny).
//   4. In the SPA policy panel, create an "allow *" rule → auto-snapshot
//      (policy.add); the same request now reaches the backend (200).
//   5. In Settings, the Config Versions list surfaces the policy.add snapshot.
//   6. Click Rollback → confirm → the baseline snapshot is re-applied, and the
//      same request is 403 again (deny→allow→deny, the last step a UI rollback).

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_ConfigVersionRollbackCrossPlane(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Cfgver-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	// Snapshots must land in a scratch dir, never touch /data — the store
	// exposes SetDirForTest precisely for this.
	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	proxyURL := startTestProxy(t) // default-allow, empty rules; restores on cleanup
	backend, _ := startCountingBackend(t)

	// Seed AFTER startTestProxy (it replaces cfg). Open the proxy's Stage-1
	// default so an unauthenticated probe reaches the policy engine.
	seedUIRoster(t, adminUser, viewerUser, pass)
	prevOutcome := cfg.DefaultAuthOutcome()
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(prevOutcome) })

	// Default-deny + empty rules baseline, then snapshot it. This snapshot is the
	// rollback target: applying it restores deny + no rules.
	setDefaultPolicyAction("deny")
	policyStore.ReplaceAll(nil)
	saveConfigVersion("e2e-baseline", "test.baseline")

	// The version counter is a process-global (shared across the suite), so read
	// the baseline's number rather than assuming v1.
	baselineVer := configVersions.Seq()

	// ── Baseline: default-deny, no rules → proxy denies ─────────────────────
	if s := proxyGETStatus(t, proxyURL, backend.URL); s != http.StatusForbidden {
		t.Fatalf("baseline (default-deny): proxy returned %d, want 403", s)
	}

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// ── Create an "allow *" rule through the policy form (auto-snapshots) ────
	if err := page.Locator(`.nav-item[data-view="policy"]`).First().Click(); err != nil {
		t.Fatalf("open policy panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#pol-table")).ToContainText("No policy rules"); err != nil {
		t.Fatalf("policy table should show its empty state before we add a rule: %v", err)
	}
	const ruleName = "e2e-cfgver-allow-all"
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

	// The add is authoritative for live traffic (forward cross-plane), and the
	// POST auto-created a "policy.add" snapshot. Poll: the submit is async.
	if !pollProxyStatus(t, proxyURL, backend.URL, http.StatusOK, 20) {
		t.Fatalf("after UI created an allow rule, proxy never returned 200 — control-plane change did not reach the data plane")
	}

	// Deterministically confirm the policy.add snapshot PERSISTED before asserting
	// on the SPA list. The settings panel fetches the versions once on navigation
	// and the DOM-level ToContainText assertion never re-fetches — so if we navigate
	// before the async snapshot write lands, the list stays stale for the whole
	// timeout and flakes. Polling the store (no browser dependency) closes that race;
	// navigating only AFTER it lands guarantees the nav-time fetch includes it. If
	// the snapshot genuinely never persists, this fails with a precise message.
	if !pollConfigVersionAction(t, "policy.add", 40) {
		t.Fatalf("policy.add config-version snapshot never persisted after the UI added a rule")
	}

	// ── Settings surfaces the Config Versions list, incl. the policy.add snap ─
	if err := page.Locator(`.nav-item[data-view="settings"]`).First().Click(); err != nil {
		t.Fatalf("open settings panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#config-versions-list")).ToContainText("policy.add"); err != nil {
		t.Fatalf("Config Versions list should surface the auto-created policy.add snapshot: %v", err)
	}

	// ── Roll back to the baseline snapshot via the UI (button + confirm modal) ─
	rollbackBtn := page.Locator(`[data-click="rollbackConfigVersion"][data-arg="` + strconv.Itoa(baselineVer) + `"]`)
	if err := assert.Locator(rollbackBtn).ToBeVisible(); err != nil {
		t.Fatalf("baseline version (v%d) should offer a Rollback button: %v", baselineVer, err)
	}
	if err := rollbackBtn.Click(); err != nil {
		t.Fatalf("click rollback: %v", err)
	}
	// rollbackConfigVersion() gates on a custom confirm modal, not a native
	// dialog — approve it.
	if err := assert.Locator(page.Locator("#confirm-dialog-ok")).ToBeVisible(); err != nil {
		t.Fatalf("rollback confirm modal should appear: %v", err)
	}
	if err := page.Locator("#confirm-dialog-ok").Click(); err != nil {
		t.Fatalf("confirm rollback: %v", err)
	}

	// ── Cross-plane rollback: the same request is 403 again ─────────────────
	// The rollback POST is async; applyConfigBackup restores deny + no rules.
	if !pollProxyStatus(t, proxyURL, backend.URL, http.StatusForbidden, 20) {
		t.Fatalf("after UI rolled back to the deny baseline, proxy never returned 403 — rollback did not revert the data plane")
	}
}

// pollConfigVersionAction polls the process-global config-version store until a
// snapshot with the given action appears (up to attempts, 100ms apart). Reads the
// store directly (no browser/API round-trip), so it is a deterministic barrier
// against the async snapshot write — decoupling the UI-list assertion from write
// timing.
func pollConfigVersionAction(t *testing.T, action string, attempts int) bool {
	t.Helper()
	for i := 0; i < attempts; i++ {
		for _, m := range configVersions.ListMeta() {
			if m.Action == action {
				return true
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// pollProxyStatus issues proxied GETs to target until it observes want (up to
// attempts, 100ms apart), returning true on a match. Used where a UI-driven
// mutation reaches the shared proxy plane asynchronously.
func pollProxyStatus(t *testing.T, proxyURL *url.URL, target string, want, attempts int) bool {
	t.Helper()
	for i := 0; i < attempts; i++ {
		if proxyGETStatus(t, proxyURL, target) == want {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
