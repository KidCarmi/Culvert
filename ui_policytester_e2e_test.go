//go:build uie2e

package main

// Policy-tester (simulator) E2E — advisory tier.
//
// The policy-tester panel dry-runs the REAL policy engine against operator-
// supplied request attributes WITHOUT generating traffic — a safety tool for
// verifying a rule set before it goes live. This proves the panel is wired to
// the engine end-to-end: a block rule the admin just defined is reported as a
// block (with the matching rule identified), and an allow rule as an allow.
//
// Hermetic + in-process; no proxy needed (the tester is a pure simulation of
// policyStore).

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_PolicyTesterSimulatesDecision(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Ptest-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	// A block rule for a specific host + a catch-all allow, so the tester has an
	// unambiguous decision for each probe. Restore the store on cleanup.
	saved := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(saved) })
	const blockRule = "pt-block-e2e"
	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: blockRule, DestFQDN: "blocked.pt.example", Action: ActionBlockPage},
		{Priority: 2, Name: "pt-allow-e2e", DestFQDN: "*", Action: ActionAllow},
	})

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	if err := page.Locator(`.nav-item[data-view="policy-tester"]`).First().Click(); err != nil {
		t.Fatalf("open policy-tester panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#pt-host")).ToBeVisible(); err != nil {
		t.Fatalf("policy-tester form should be visible: %v", err)
	}

	// runTest fills the tester and runs it against the given host.
	runTest := func(host string) {
		t.Helper()
		if err := page.Locator("#pt-ip").Fill("203.0.113.10"); err != nil {
			t.Fatalf("fill ip: %v", err)
		}
		if err := page.Locator("#pt-host").Fill(host); err != nil {
			t.Fatalf("fill host: %v", err)
		}
		if err := page.Locator(`[data-click="runPolicyTest"]`).First().Click(); err != nil {
			t.Fatalf("run policy test: %v", err)
		}
	}

	// ── Blocked host → the tester identifies the block rule ─────────────────
	runTest("blocked.pt.example")
	body := page.Locator("#pt-result-body")
	if err := assert.Locator(body).ToContainText(blockRule); err != nil {
		got, _ := body.TextContent()
		t.Errorf("tester should report the matching block rule %q; result was:\n%s\n(%v)", blockRule, got, err)
	}

	// ── Allowed host → the tester identifies the allow rule ─────────────────
	runTest("anything-else.pt.example")
	if err := assert.Locator(body).ToContainText("pt-allow-e2e"); err != nil {
		got, _ := body.TextContent()
		t.Errorf("tester should report the matching allow rule; result was:\n%s\n(%v)", got, err)
	}
}
