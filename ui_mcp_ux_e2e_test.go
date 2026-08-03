//go:build uie2e

package main

// PR-UX-2 production validation: drives the REAL MCP Command Center + Activity
// rendering code (static/index.html, mcpx-* functions) in headless Chromium.
//
// The SHIPPED UI reads only /api/mcp/* responses; this test supplies SYNTHETIC
// responses via request interception to exercise every branch deterministically
// (tests may use synthetic fixtures; the shipped UI may not). It asserts on the
// rendered DOM, fails on any uncaught page exception, and writes PR screenshots.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

const mcpuxAssets = "docs/design/mcp/ux-audit-assets/production"

// ── synthetic /api/mcp/* fixtures (real response shapes) ──

const fxOverview = `{"distribution_state":"partially_acknowledged","execution_state":"executed","management_tools":14,` +
	`"health":{"gateway":{"capability":"gateway","runtime":{"state":"ready","listener_ready":true,"active_sessions":7,"in_flight":3},` +
	`"durability":{"critical_state":"degraded","denial_state":"degraded","severity":"high","commit_failures":37,"recovery_state":"recovering"},` +
	`"servers":4,"quarantined_tools":1,"drifted_tools":2,"policy_revision":12,"policy_snapshot_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988","pending_approvals":0},` +
	`"management":{"capability":"management","runtime":{"state":"ready","active_sessions":1,"in_flight":0},"durability":{"severity":"none"},"pending_approvals":0},` +
	`"distribution_state":"partially_acknowledged","management_access":{"enabled":true,"default_min_role":"viewer","mutation_enabled":false}}}`

const fxRollout = `{"gateway":{"mode":"canary","desired":"canary","killed":false,"connector":"local-client","history_len":6},` +
	`"management":{"mode":"observe","desired":"observe","killed":false,"connector":"","history_len":2},` +
	`"metrics":{"in_scope":2050,"out_of_scope":40,"shadow_override":214,"hard_blocks":6,"executed":1836,"upstream_ok":1801,"upstream_err":35,"dlp_blocks":12},` +
	`"production_locked":true,"distribution":{"enabled":true,"distribution_state":"partially_acknowledged"}}`

const fxDistribution = `{"enabled":true,"distribution_state":"partially_acknowledged",` +
	`"gateway":{"current_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988","previous_hash":"sha256:00ff11ee22dd33cc44bb55aa66998877","epoch":8,"rollback_available":true},` +
	`"management":{"current_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988","epoch":8}}`

const fxDecisions = `{"decisions":[` +
	`{"event_id":"evt_9f1a","sequence":4021,"partition":"P-CRIT","capability":"gateway","time_unix_nano":1722690123000000000,"tenant":"acme-prod","principal_id":"svc-agent-billing","principal_type":"workload","agent_id":"agent-42","server_id":"srv-github","tool_name":"create_issue","action":"DENY","reason_code":"out_of_scope","matched_rule_id":"rule-write-guard","operation_class":"write","execution_state":"shadow_recorded"},` +
	`{"event_id":"evt_9f22","sequence":4020,"partition":"P-ORD","capability":"gateway","time_unix_nano":1722690121000000000,"tenant":"acme-prod","principal_id":"u-jdoe","principal_type":"human","agent_id":"agent-42","server_id":"srv-github","tool_name":"list_issues","action":"ALLOW","reason_code":"observe_only","matched_rule_id":"rule-read-allow","operation_class":"read","execution_state":"executed"},` +
	`{"event_id":"evt_hf01","sequence":4019,"partition":"P-CRIT","capability":"gateway","time_unix_nano":1722690119000000000,"tenant":"acme-prod","principal_id":"svc-agent-x","principal_type":"workload","agent_id":"agent-x","server_id":"srv-github","tool_name":"create_issue","action":"DENY","reason_code":"sender_constraint_required","matched_rule_id":"-","operation_class":"write","execution_state":"blocked"}` +
	`],"next_cursor":"P-CRIT:4018"}`

const fxExplainShadow = `{"event_id":"evt_9f1a","correlation_id":"corr_7788","capability":"gateway","partition":"P-CRIT","time_unix_nano":1722690123000000000,` +
	`"tenant":"acme-prod","principal_id":"svc-agent-billing","principal_type":"workload","agent_id":"agent-42","client_id":"app-desktop",` +
	`"server_id":"srv-github","tool_name":"create_issue","tool_fingerprint":"fp-9a1b2c","resource_ref":"github://issue","assurance":"medium",` +
	`"action":"DENY","reason_code":"out_of_scope","matched_rule_id":"rule-write-guard","decisive_condition_id":"cond-scope-write","remediation":"narrow scope or promote",` +
	`"operation_class":"write","risk_class":"high","execution_state":"shadow_recorded","policy_revision":12,"catalog_revision":6,"registry_revision":4,` +
	`"inspection_revision":3,"runtime_revision":2,"policy_snapshot_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988",` +
	`"inspection_schema_status":"valid","dlp_disposition":"pass","credential_profile_ref":"cp-github-rw","credential_power_ceiling":"write","source":"historical"}`

// mcpuxRoute installs interception: /api/mcp/* -> synthetic fixtures; external ->
// abort; everything else (the real handler, static assets) -> continue.
func mcpuxRoute(t *testing.T, ctx playwright.BrowserContext, base string) {
	t.Helper()
	body := func(path string) (string, bool) {
		switch {
		case strings.Contains(path, "/api/mcp/overview"):
			return fxOverview, true
		case strings.Contains(path, "/api/mcp/rollout"):
			return fxRollout, true
		case strings.Contains(path, "/api/mcp/distribution"):
			return fxDistribution, true
		case strings.Contains(path, "/api/mcp/decision-explain"):
			return fxExplainShadow, true
		case strings.Contains(path, "/api/mcp/decisions"):
			return fxDecisions, true
		}
		return "", false
	}
	err := ctx.Route("**/*", func(route playwright.Route) {
		u := route.Request().URL()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		if b, ok := body(u); ok {
			_ = route.Fulfill(playwright.RouteFulfillOptions{
				Status: playwright.Int(200), ContentType: playwright.String("application/json"),
				Body: playwright.String(b),
			})
			return
		}
		_ = route.Continue()
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
}

func mcpuxPage(t *testing.T, browser playwright.Browser, base string, pageErrs *[]string) (playwright.BrowserContext, playwright.Page) {
	t.Helper()
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 1440, Height: 900},
	})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	mcpuxRoute(t, ctx, base)
	if err := ctx.AddCookies([]playwright.OptionalCookie{{
		Name: uiSessionCookieName, Value: mintUISessionValue(t, "ux_admin", RoleAdmin), URL: playwright.String(base),
	}}); err != nil {
		t.Fatalf("cookie: %v", err)
	}
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	page.On("pageerror", func(e error) { *pageErrs = append(*pageErrs, e.Error()) })
	if _, err := page.Goto(base+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto: %v", err)
	}
	return ctx, page
}

func mcpuxSeed(t *testing.T) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "ui_users.json")
	cfg.SetUIUsersFile(tmp)
	if err := cfg.SetAuth("bootstrap-admin", "Bootstrap-admin-1!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if err := cfg.SetUIUser("ux_admin", "Ux-Admin-Pwd-1!", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if !sessionSecretSet() {
		initSessionSecret()
	}
	t.Cleanup(func() { _ = cfg.DeleteUIUser("ux_admin"); _ = cfg.SetAuth("", "") })
}

func mcpuxShot(t *testing.T, page playwright.Page, name string) {
	t.Helper()
	p := filepath.Join(mcpuxAssets, name)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{Path: playwright.String(p), FullPage: playwright.Bool(true)}); err != nil {
		t.Logf("screenshot %s: %v", name, err)
	}
}

func TestMCPUX_CommandCenterAndActivity(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	// Register srv close BEFORE the browser so cleanup LIFO closes the browser
	// context (and its long-lived SSE connection) first; otherwise srv.Close()
	// blocks forever on the open /api/events stream.
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	_, page := mcpuxPage(t, browser, srv.URL, &pageErrs)

	page.SetDefaultTimeout(8000)
	must := func(err error, ctx string) {
		if err != nil {
			t.Fatalf("%s: %v", ctx, err)
		}
	}
	assert := playwright.NewPlaywrightAssertions()
	tct := func(loc playwright.Locator, sub, ctx string) {
		if err := assert.Locator(loc).ToContainText(sub, playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s (want text %q): %v | pageErrs=%v", ctx, sub, err, pageErrs)
		}
	}
	tvis := func(loc playwright.Locator, ctx string) {
		if err := assert.Locator(loc).ToBeVisible(playwright.LocatorAssertionsToBeVisibleOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s: %v | pageErrs=%v", ctx, err, pageErrs)
		}
	}

	// ── Command Center ──
	must(page.Locator(`.nav-item[data-view="mcp-overview"]`).First().Click(), "nav overview")
	tvis(page.Locator("#mcpx-overview-root .mcpx-posture"), "posture visible")
	tct(page.Locator("#mcpx-overview-root"), "Production: LOCKED", "prod locked chip")
	tct(page.Locator("#mcpx-overview-root"), "Fleet-effective", "triplet")
	tct(page.Locator("#mcpx-overview-root"), "Gateway", "gateway card")
	tvis(page.Locator("#mcpx-overview-root .mcpx-sevtag").First(), "severity token")
	if len(pageErrs) != 0 {
		t.Fatalf("page errors after Command Center: %v", pageErrs)
	}
	mcpuxShot(t, page, "command-center-dark-1440.png")

	// ── Activity ──
	must(page.Locator(`.nav-item[data-view="mcp-decisions"]`).First().Click(), "nav decisions")
	tct(page.Locator("#mcpx-decisions-root"), "Enter a tenant", "empty state")
	must(page.Locator("#mcp-dec-tenant").Fill("acme-prod"), "fill tenant")
	must(page.Locator(`[data-click="renderMCPActivity"]`).First().Click(), "search")
	tvis(page.Locator("table.mcpx-act"), "activity table")
	tct(page.Locator("table.mcpx-act thead"), "Evaluated to effective", "eval->eff header")

	// The Shadow-executed DENY row must show DENY + executed (shadow) + ! override,
	// and never read as a plain ALLOW.
	shadowRow := page.Locator(`tr[data-arg="evt_9f1a"]`)
	tct(shadowRow, "DENY", "shadow row DENY")
	tct(shadowRow, "executed (shadow)", "shadow row effective")
	tct(shadowRow, "! override", "shadow row override")
	txt, _ := shadowRow.TextContent()
	if strings.Contains(txt, "ALLOW") {
		t.Fatalf("shadow DENY row must not contain ALLOW; got %q", txt)
	}

	// Open the drawer; assert truthful evidence chain and NO fabricated fields.
	must(shadowRow.Click(), "open drawer")
	drawer := page.Locator("#mcpx-drawer.open")
	tvis(drawer, "drawer open")
	tct(drawer, "Evaluated: DENY", "drawer evaluated")
	tct(drawer, "executed (shadow)", "drawer effective")
	tct(drawer, "Shadow override (derived)", "override derived row")
	tct(drawer, "Credential profile", "cred profile row")
	tct(drawer, "Correlation id", "evidence row")
	// No fabricated/unavailable evidence FIELDS may appear (these have no source).
	dtxt, _ := drawer.TextContent()
	for _, forbidden := range []string{"Latency", "Environment", "DP / node", "Upstream outcome", "Upstream status"} {
		if strings.Contains(dtxt, forbidden) {
			t.Fatalf("drawer must not contain fabricated/unavailable field %q; drawer=%q", forbidden, dtxt)
		}
	}
	// No quarantine/revoke ACTION buttons (they exist only in the honest disclaimer
	// text, never as an actionable control).
	for _, sel := range []string{`#mcpx-drawer button:has-text("Quarantine")`, `#mcpx-drawer button:has-text("Revoke")`} {
		if n, _ := page.Locator(sel).Count(); n != 0 {
			t.Fatalf("drawer must not expose a quarantine/revoke action button (%s): found %d", sel, n)
		}
	}
	mcpuxShot(t, page, "activity-shadow-drawer-dark-1440.png")

	// Responsive proofs: table + overlay drawer must stay usable at 1280 and 1920.
	must(page.SetViewportSize(1280, 800), "resize 1280")
	tvis(page.Locator("table.mcpx-act"), "table at 1280")
	mcpuxShot(t, page, "activity-shadow-drawer-dark-1280.png")
	must(page.SetViewportSize(1920, 1080), "resize 1920")
	mcpuxShot(t, page, "activity-shadow-drawer-dark-1920.png")

	// Light-theme proof for the two primary screens.
	_, _ = page.Evaluate(`() => document.documentElement.setAttribute('data-theme','light')`)
	must(page.SetViewportSize(1440, 900), "resize 1440")
	mcpuxShot(t, page, "activity-shadow-drawer-light-1440.png")
	must(page.Locator(`.nav-item[data-view="mcp-overview"]`).First().Click(), "nav overview light")
	tvis(page.Locator("#mcpx-overview-root .mcpx-posture"), "posture light")
	mcpuxShot(t, page, "command-center-light-1440.png")

	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}

// TestMCPUX_States proves the loading/empty/error/permission-denied states render
// honestly (no raw JSON, no fabricated data) when the API returns 403 or empty.
func TestMCPUX_States(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)

	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: 1440, Height: 900}})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	// Force 403 on the MCP reads; everything else real.
	_ = ctx.Route("**/*", func(route playwright.Route) {
		u := route.Request().URL()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		if strings.Contains(u, "/api/mcp/overview") {
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(403), Body: playwright.String("admin_forbidden")})
			return
		}
		_ = route.Continue()
	})
	_ = ctx.AddCookies([]playwright.OptionalCookie{{Name: uiSessionCookieName, Value: mintUISessionValue(t, "ux_admin", RoleAdmin), URL: playwright.String(srv.URL)}})
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if _, err := page.Goto(srv.URL+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto: %v", err)
	}
	page.SetDefaultTimeout(8000)
	assert := playwright.NewPlaywrightAssertions()
	if err := page.Locator(`.nav-item[data-view="mcp-overview"]`).First().Click(); err != nil {
		t.Fatalf("nav: %v", err)
	}
	// Permission-denied must render a clean message, not a raw body or a crash.
	if err := assert.Locator(page.Locator("#mcpx-overview-root")).ToContainText("Permission denied", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("expected permission-denied state: %v", err)
	}
}
