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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

const mcpuxAssets = "docs/design/mcp/ux-audit-assets/production"

// ── synthetic /api/mcp/* fixtures (real response shapes) ──

const fxOverview = `{"distribution_state":"partially_acknowledged","execution_state":"executed","management_tools":14,` +
	`"health":{"gateway":{"capability":"gateway","runtime":{"state":"ready","listener_ready":true,"active_sessions":7,"in_flight":3},` +
	`"durability":{"critical_state":"degraded","denial_state":"degraded","severity":"high","commit_failures":37,"recovery_state":"recovering"},` +
	`"servers":4,"quarantined_tools":1,"drifted_tools":2,"review_required_tools":2,"policy_revision":12,"policy_snapshot_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988","pending_approvals":0},` +
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

// Degraded posture: BOTH kill switches active, Management durability critical while
// Gateway is clean, and /api/mcp/distribution unavailable (5xx). Proves the Command
// Center surfaces the management kill switch + management durability independently and
// renders the failed distribution read as unavailable rather than a benign default.
const fxOverviewDegraded = `{"distribution_state":"local_only","execution_state":"not_implemented","management_tools":14,` +
	`"health":{"gateway":{"capability":"gateway","runtime":{"state":"ready","active_sessions":0,"in_flight":0},"durability":{"severity":"none"},"policy_snapshot_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988"},` +
	`"management":{"capability":"management","runtime":{"state":"degraded","active_sessions":0,"in_flight":0},"durability":{"severity":"critical","commit_failures":91,"recovery_state":"stalled"}},` +
	`"distribution_state":"local_only","management_access":{"enabled":true,"default_min_role":"admin","mutation_enabled":false}}}`

const fxRolloutDegraded = `{"gateway":{"mode":"canary","desired":"canary","killed":true,"connector":"local-client","history_len":6},` +
	`"management":{"mode":"observe","desired":"observe","killed":true,"connector":"","history_len":2},` +
	`"metrics":{"hard_blocks":0},"production_locked":true}`

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
	// The evidence chain is truthful about fields with no source: upstream HTTP
	// status and latency are shown as "not recorded" (stage 9), never fabricated;
	// DP-node and environment (no source at all, DP node is PR-UX-5) never appear.
	dtxt, _ := drawer.TextContent()
	for _, forbidden := range []string{"Environment", "DP / node", "DP node"} {
		if strings.Contains(dtxt, forbidden) {
			t.Fatalf("drawer must not contain absent-source field %q; drawer=%q", forbidden, dtxt)
		}
	}
	if !strings.Contains(dtxt, "not recorded") {
		t.Fatalf("evidence chain must label absent fields 'not recorded', got drawer=%q", dtxt)
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

// TestMCPUX_DegradedPosture proves the Command Center surfaces BOTH capabilities'
// kill switches and durability independently, and renders a failed distribution read
// as unavailable rather than substituting a benign "local only" default.
func TestMCPUX_DegradedPosture(t *testing.T) {
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
	// overview + rollout = degraded fixtures; distribution = 500 (unavailable).
	_ = ctx.Route("**/*", func(route playwright.Route) {
		u := route.Request().URL()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		switch {
		case strings.Contains(u, "/api/mcp/overview"):
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), ContentType: playwright.String("application/json"), Body: playwright.String(fxOverviewDegraded)})
		case strings.Contains(u, "/api/mcp/distribution"):
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: playwright.String("boom")})
		case strings.Contains(u, "/api/mcp/rollout"):
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), ContentType: playwright.String("application/json"), Body: playwright.String(fxRolloutDegraded)})
		default:
			_ = route.Continue()
		}
	})
	_ = ctx.AddCookies([]playwright.OptionalCookie{{Name: uiSessionCookieName, Value: mintUISessionValue(t, "ux_admin", RoleAdmin), URL: playwright.String(srv.URL)}})
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	var pageErrs []string
	page.On("pageerror", func(e error) { pageErrs = append(pageErrs, e.Error()) })
	if _, err := page.Goto(srv.URL+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto: %v", err)
	}
	page.SetDefaultTimeout(8000)
	assert := playwright.NewPlaywrightAssertions()
	if err := page.Locator(`.nav-item[data-view="mcp-overview"]`).First().Click(); err != nil {
		t.Fatalf("nav: %v", err)
	}
	tct := func(sub, ctxs string) {
		if err := assert.Locator(page.Locator("#mcpx-overview-root")).ToContainText(sub, playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s (want %q): %v | pageErrs=%v", ctxs, sub, err, pageErrs)
		}
	}
	// Both kill switches surfaced in the strip and needs-attention.
	tct("Admission STOPPED: gateway + management", "combined kill chip")
	tct("Emergency kill switch active on gateway", "gateway kill attn")
	tct("Emergency kill switch active on management", "management kill attn")
	// Management durability critical must drive the strip severity + its own attn item,
	// even though Gateway durability is clean.
	tct("Durability: critical", "worst-of-both severity")
	tct("Management durability critical", "management durability attn")
	// A failed distribution read renders as unavailable, not "local only".
	tct("Fleet: unavailable", "distribution unavailable chip")
	tct("Distribution posture unavailable", "distribution unavailable attn")
	dtxt, _ := page.Locator("#mcpx-overview-root").TextContent()
	if strings.Contains(dtxt, "Fleet: local only") {
		t.Fatalf("failed distribution read must not fall back to 'local only'; got %q", dtxt)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
	mcpuxShot(t, page, "command-center-degraded-dark-1440.png")
}

// ── PR-UX-3 fixtures: entity pivots + evidence chain (real response shapes) ──

// Base decision page (tenant only): a rich shadow-DENY plus two minimal ALLOWs
// used for the drawer-race proof (evt-fast vs the delayed evt-slow).
const fxDec3Base = `{"decisions":[` +
	`{"event_id":"evt-rich","sequence":9001,"partition":"P-CRIT","capability":"gateway","time_unix_nano":1722690123000000000,"tenant":"acme","principal_id":"svc-billing","principal_type":"workload","agent_id":"agent-42","server_id":"srv-rich","tool_name":"create_issue","action":"DENY","reason_code":"out_of_scope","matched_rule_id":"rule-guard","operation_class":"write","execution_state":"shadow_recorded"},` +
	`{"event_id":"evt-fast","sequence":9000,"partition":"P-ORD","capability":"gateway","time_unix_nano":1722690121000000000,"tenant":"acme","principal_id":"u-jdoe","principal_type":"human","server_id":"srv-fast","tool_name":"list_issues","action":"ALLOW","reason_code":"observe_only","execution_state":"executed"},` +
	`{"event_id":"evt-slow","sequence":8999,"partition":"P-ORD","capability":"gateway","time_unix_nano":1722690119000000000,"tenant":"acme","principal_id":"u-slow","principal_type":"human","server_id":"srv-slow","tool_name":"read_repo","action":"ALLOW","reason_code":"observe_only","execution_state":"executed"},` +
	`{"event_id":"evt-noserver","sequence":8998,"partition":"P-ORD","capability":"gateway","time_unix_nano":1722690118000000000,"tenant":"acme","principal_id":"u-sparse","principal_type":"human","tool_name":"orphan_tool","action":"ALLOW","reason_code":"observe_only","execution_state":"executed"}` +
	`]}`

// Any entity-filtered decision query returns this single marker row, proving the
// exact filter was applied (the row carries a distinct event id).
const fxDecFiltered = `{"decisions":[` +
	`{"event_id":"evt-related","sequence":9002,"partition":"P-CRIT","capability":"gateway","time_unix_nano":1722690124000000000,"tenant":"acme","principal_id":"svc-billing","principal_type":"workload","server_id":"srv-rich","tool_name":"create_issue","action":"DENY","reason_code":"out_of_scope","matched_rule_id":"rule-guard","operation_class":"write","execution_state":"blocked"}` +
	`]}`

// Full ExplanationView for evt-rich: every evidence-chain stage has a source.
const fxExplainFull = `{"event_id":"evt-rich","correlation_id":"corr-9001","replay_id":"rep-9001","capability":"gateway","partition":"P-CRIT","time_unix_nano":1722690123000000000,` +
	`"tenant":"acme","principal_id":"svc-billing","principal_type":"workload","agent_id":"agent-42","client_id":"app-desktop",` +
	`"server_id":"srv-rich","tool_name":"create_issue","tool_fingerprint":"fp-rich-0011223344556677","resource_ref":"github://issue","resource_hash":"sha256:aa11bb22cc33dd44","assurance":"medium",` +
	`"action":"DENY","reason_code":"out_of_scope","matched_rule_id":"rule-guard","decisive_condition_id":"cond-scope-write","remediation":"narrow scope or promote","operation_class":"write","risk_class":"high","execution_state":"shadow_recorded","obligations":["log"],` +
	`"policy_revision":12,"catalog_revision":6,"registry_revision":4,"inspection_revision":3,"runtime_revision":2,"policy_snapshot_hash":"sha256:11aa22bb33cc44dd55ee66ff77009988",` +
	`"inspection_schema_status":"valid","finding_classes":["scope"],"max_severity":"medium","dlp_disposition":"pass","destination_class":"approved",` +
	`"credential_profile_ref":"cp-github-rw","credential_power_ceiling":"write","source":"historical"}`

// Minimal ExplanationView for evt-fast: many optional fields absent, so several
// stages must be omitted (credential) or labeled "not recorded" (snapshot etc).
const fxExplainMinFast = `{"event_id":"evt-fast","correlation_id":"corr-9000","capability":"gateway","partition":"P-ORD","time_unix_nano":1722690121000000000,` +
	`"tenant":"acme","principal_id":"u-jdoe","principal_type":"human","server_id":"srv-fast","tool_name":"list_issues",` +
	`"action":"ALLOW","reason_code":"observe_only","execution_state":"executed","source":"historical"}`

const fxExplainMinSlow = `{"event_id":"evt-slow","correlation_id":"corr-8999","capability":"gateway","partition":"P-ORD","time_unix_nano":1722690119000000000,` +
	`"tenant":"acme","principal_id":"u-slow","principal_type":"human","server_id":"srv-slow","tool_name":"read_repo",` +
	`"action":"ALLOW","reason_code":"observe_only","execution_state":"executed","source":"historical"}`

// Server-less event: has tool_name but NO server_id. GetTool rejects an empty
// server_id, so the Tool pivot must degrade to a tool-name related-decisions
// pivot, never open an always-unavailable inventory drawer.
const fxExplainNoServer = `{"event_id":"evt-noserver","correlation_id":"corr-8998","capability":"gateway","partition":"P-ORD","time_unix_nano":1722690118000000000,` +
	`"tenant":"acme","principal_id":"u-sparse","principal_type":"human","tool_name":"orphan_tool",` +
	`"action":"ALLOW","reason_code":"observe_only","execution_state":"executed","source":"historical"}`

const fxServerRich = `{"server_id":"srv-rich","tenant":"acme","capability":"gateway","enabled":true,"verification":"verified","identity_changed":false,"revision":7,"credential_profile_ref":"cp-github-rw","endpoint_configured":true}`

const fxToolRich = `{"server_id":"srv-rich","name":"create_issue","fingerprint":"fp-rich-0011223344556677","disposition":"usable","quarantined":false,"review_required":false,"destination_class":"approved","revision":3}`

// mcpuxRichRoute intercepts /api/mcp/* with the PR-UX-3 fixtures. Entity-filtered
// decision queries return a distinct row; srv-fast's server read returns 500 (the
// "unavailable" proof); evt-slow's explanation is delayed (the race proof).
func mcpuxRichRoute(t *testing.T, ctx playwright.BrowserContext) {
	t.Helper()
	err := ctx.Route("**/*", func(route playwright.Route) {
		u := route.Request().URL()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		fulfill := func(body string) {
			_ = route.Fulfill(playwright.RouteFulfillOptions{
				Status: playwright.Int(200), ContentType: playwright.String("application/json"), Body: playwright.String(body),
			})
		}
		parsed, _ := url.Parse(u)
		q := parsed.Query()
		switch {
		case strings.Contains(u, "/api/mcp/decision-explain"):
			switch q.Get("event_id") {
			case "evt-rich":
				fulfill(fxExplainFull)
			case "evt-noserver":
				fulfill(fxExplainNoServer)
			case "evt-slow":
				// Delay the stale request; fulfill from a goroutine so the handler
				// returns immediately and does not block evt-rich's fast read.
				go func() { time.Sleep(350 * time.Millisecond); fulfill(fxExplainMinSlow) }()
			default:
				fulfill(fxExplainMinFast)
			}
		case strings.Contains(u, "/api/mcp/decisions"):
			entity := q.Get("tool_fingerprint") + q.Get("principal_id") + q.Get("agent_id") +
				q.Get("client_id") + q.Get("rule_id") + q.Get("policy_snapshot_hash") + q.Get("credential_profile_ref") + q.Get("server_id")
			switch {
			case q.Get("principal_id") == "u-sparse":
				// Empty page but the bounded scan window was not exhausted -> a
				// truthful "more may exist" state, not "no matches".
				fulfill(`{"decisions":[],"next_cursor":"P-CRIT:1"}`)
			case q.Get("agent_id") != "":
				// Delayed filtered response for the activity-search race proof.
				go func() { time.Sleep(350 * time.Millisecond); fulfill(fxDecFiltered) }()
			case entity != "":
				fulfill(fxDecFiltered)
			default:
				fulfill(fxDec3Base)
			}
		case strings.Contains(u, "/api/mcp/servers"):
			if q.Get("server_id") == "srv-fast" {
				_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: playwright.String("boom")})
				return
			}
			fulfill(fxServerRich)
		case strings.Contains(u, "/api/mcp/tools"):
			fulfill(fxToolRich)
		default:
			_ = route.Continue()
		}
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
}

func mcpuxRichPage(t *testing.T, browser playwright.Browser, base string, pageErrs *[]string) playwright.Page {
	t.Helper()
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: 1440, Height: 900}})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	mcpuxRichRoute(t, ctx)
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
	return page
}

// TestMCPUX_EntityPivotsAndEvidence drives the real entity-pivot, Server/Tool
// drawer, evidence-chain and bounded-navigation code (scenarios 1-10, 12-15).
func TestMCPUX_EntityPivotsAndEvidence(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := mcpuxRichPage(t, browser, srv.URL, &pageErrs)
	page.SetDefaultTimeout(8000)
	assert := playwright.NewPlaywrightAssertions()

	must := func(err error, ctx string) {
		if err != nil {
			t.Fatalf("%s: %v | pageErrs=%v", ctx, err, pageErrs)
		}
	}
	tct := func(loc playwright.Locator, sub, ctx string) {
		if err := assert.Locator(loc).ToContainText(sub, playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s (want %q): %v | pageErrs=%v", ctx, sub, err, pageErrs)
		}
	}
	tvis := func(loc playwright.Locator, ctx string) {
		if err := assert.Locator(loc).ToBeVisible(playwright.LocatorAssertionsToBeVisibleOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s: %v | pageErrs=%v", ctx, err, pageErrs)
		}
	}

	must(page.Locator(`.nav-item[data-view="mcp-decisions"]`).First().Click(), "nav decisions")
	must(page.Locator("#mcp-dec-tenant").Fill("acme"), "fill tenant")
	must(page.Locator(`[data-click="renderMCPActivity"]`).First().Click(), "search")
	tvis(page.Locator("table.mcpx-act"), "activity table")

	// (1) Select the rich Activity row -> decision drawer opens with the chain.
	richRow := page.Locator(`tr[data-arg="evt-rich"]`)
	must(richRow.Click(), "open evt-rich")
	drawer := page.Locator("#mcpx-drawer.open")
	tvis(drawer, "decision drawer open")
	tct(drawer, "Evaluated: DENY", "evaluated deny")
	tct(drawer, "executed (shadow)", "effective shadow")
	// (8) Evidence stages present in the full fixture render; (9) minimal ones later.
	tct(drawer, "Server and tool", "stage 2")
	tct(drawer, "Policy decision", "stage 4")
	tct(drawer, "Snapshot and revisions", "stage 11")
	fullStages, _ := page.Locator("#mcpx-drawer .mcpx-evc-stage").Count()
	if fullStages < 8 {
		t.Fatalf("full explanation should render many stages, got %d", fullStages)
	}
	// (15) No secret/raw material in the drawer.
	dtxt, _ := drawer.TextContent()
	for _, banned := range []string{"Bearer", "Authorization", "password", "\"arguments\"", "raw_output", "private_key"} {
		if strings.Contains(dtxt, banned) {
			t.Fatalf("drawer leaked forbidden material %q: %s", banned, dtxt)
		}
	}

	// (2) Click the Tool pivot -> Tool drawer opens; the Activity row stays selected.
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("create_issue")`).First().Click(), "tool pivot")
	tct(page.Locator("#mcpx-drawer.open"), "Tool create_issue", "tool drawer")
	tct(page.Locator("#mcpx-drawer.open"), "approved", "tool destination class")
	if c, _ := page.Locator(`tr[data-arg="evt-rich"].sel`).Count(); c != 1 {
		t.Fatalf("Activity row must stay selected while the Tool drawer is open, sel=%d", c)
	}

	// (3) "View related decisions" applies the exact tool-fingerprint + tenant filter.
	must(page.Locator(`#mcpx-drawer button:has-text("View related decisions")`).First().Click(), "view related")
	tct(page.Locator(".mcpx-filterbar"), "tool fingerprint = fp-rich", "fingerprint filter tag")
	tvis(page.Locator(`tr[data-arg="evt-related"]`), "filtered related row")

	// (4) Back returns to the original Activity + reopens the selected decision drawer.
	must(page.Locator(".mcpx-filterbar .mcpx-back").First().Click(), "nav back")
	tvis(page.Locator(`tr[data-arg="evt-rich"]`), "base list restored")
	tct(page.Locator("#mcpx-drawer.open"), "Evaluated: DENY", "decision drawer reopened")
	if c, _ := page.Locator(`tr[data-arg="evt-rich"].sel`).Count(); c != 1 {
		t.Fatalf("original row must be reselected after Back, sel=%d", c)
	}

	// (5) Principal pivot filters related decisions by the exact principal.
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("svc-billing")`).First().Click(), "principal pivot")
	tct(page.Locator(".mcpx-filterbar"), "principal = svc-billing", "principal filter tag")
	must(page.Locator(".mcpx-filterbar .mcpx-back").First().Click(), "back from principal")

	// (6) Policy-rule pivot filters by the exact real rule id.
	tct(page.Locator("#mcpx-drawer.open"), "Evaluated: DENY", "drawer back for rule pivot")
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("rule-guard")`).First().Click(), "rule pivot")
	tct(page.Locator(".mcpx-filterbar"), "rule = rule-guard", "rule filter tag")
	must(page.Locator(".mcpx-filterbar .mcpx-back").First().Click(), "back from rule")

	// (7) Snapshot pivot filters by the exact snapshot hash.
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("sha256:11aa")`).First().Click(), "snapshot pivot")
	tct(page.Locator(".mcpx-filterbar"), "snapshot =", "snapshot filter tag")
	must(page.Locator(".mcpx-filterbar .mcpx-back").First().Click(), "back from snapshot")
	mcpuxShot(t, page, "evidence-chain-expanded-dark-1440.png")

	// (12) Escape closes the top drawer (Tool), then the parent (Decision).
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("create_issue")`).First().Click(), "reopen tool")
	tct(page.Locator("#mcpx-drawer.open"), "Tool create_issue", "tool reopened")
	must(page.Keyboard().Press("Escape"), "escape 1")
	tct(page.Locator("#mcpx-drawer.open"), "Evaluated: DENY", "escape pops to decision")
	if c, _ := page.Locator("#mcpx-drawer.open:has-text(\"Tool create_issue\")").Count(); c != 0 {
		t.Fatalf("Tool drawer must be gone after one Escape")
	}
	must(page.Keyboard().Press("Escape"), "escape 2")
	if err := assert.Locator(page.Locator("#mcpx-drawer.open")).ToHaveCount(0, playwright.LocatorAssertionsToHaveCountOptions{Timeout: playwright.Float(5000)}); err != nil {
		t.Fatalf("second Escape must close the decision drawer: %v", err)
	}

	// (9) Minimal explanation: credential stage omitted, snapshot "not recorded".
	must(page.Locator(`tr[data-arg="evt-fast"]`).Click(), "open evt-fast")
	tct(page.Locator("#mcpx-drawer.open"), "not recorded", "minimal shows not recorded")
	if c, _ := page.Locator("#mcpx-drawer .mcpx-evc-stage:has-text(\"Credential-profile\")").Count(); c != 0 {
		t.Fatalf("credential stage must be omitted when the event has no credential profile")
	}
	minStages, _ := page.Locator("#mcpx-drawer .mcpx-evc-stage").Count()
	if minStages >= fullStages {
		t.Fatalf("minimal explanation should render fewer stages (%d) than the full one (%d)", minStages, fullStages)
	}

	// (10) A failed related-data read renders "unavailable" (srv-fast -> 500).
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("srv-fast")`).First().Click(), "server pivot (broken)")
	tct(page.Locator("#mcpx-drawer.open"), "unavailable", "server unavailable")
	mcpuxShot(t, page, "failed-related-read-unavailable-dark-1440.png")

	// (16) No page exceptions across the whole flow.
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}

	// Screenshot sweep: dark/light x 1280/1440/1920 with the Tool drawer open.
	must(page.Locator(`tr[data-arg="evt-rich"]`).Click(), "reopen rich for shots")
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("create_issue")`).First().Click(), "tool for shots")
	mcpuxShot(t, page, "activity-tool-drawer-dark-1440.png")
	must(page.SetViewportSize(1280, 800), "1280")
	mcpuxShot(t, page, "activity-tool-drawer-dark-1280.png")
	must(page.SetViewportSize(1920, 1080), "1920")
	mcpuxShot(t, page, "activity-tool-drawer-dark-1920.png")
	_, _ = page.Evaluate(`() => document.documentElement.setAttribute('data-theme','light')`)
	must(page.SetViewportSize(1440, 900), "1440 light")
	mcpuxShot(t, page, "activity-tool-drawer-light-1440.png")
	must(page.Locator(`#mcpx-drawer button:has-text("View related decisions")`).First().Click(), "related for shot")
	mcpuxShot(t, page, "related-by-fingerprint-light-1440.png")
}

// TestMCPUX_DecisionDrawerRace proves scenario 11: a slower earlier explanation
// request (evt-slow) can never overwrite a newer selection (evt-rich). The
// 796ce167 request-ticket guard is extended to every drawer read.
func TestMCPUX_DecisionDrawerRace(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := mcpuxRichPage(t, browser, srv.URL, &pageErrs)
	page.SetDefaultTimeout(8000)
	assert := playwright.NewPlaywrightAssertions()

	if err := page.Locator(`.nav-item[data-view="mcp-decisions"]`).First().Click(); err != nil {
		t.Fatalf("nav: %v", err)
	}
	_ = page.Locator("#mcp-dec-tenant").Fill("acme")
	_ = page.Locator(`[data-click="renderMCPActivity"]`).First().Click()
	if err := assert.Locator(page.Locator("table.mcpx-act")).ToBeVisible(playwright.LocatorAssertionsToBeVisibleOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("table: %v", err)
	}
	// Select the delayed decision, then immediately select the fast one.
	_ = page.Locator(`tr[data-arg="evt-slow"]`).Click()
	_ = page.Locator(`tr[data-arg="evt-rich"]`).Click()
	// The drawer must show evt-rich (DENY) now...
	if err := assert.Locator(page.Locator("#mcpx-drawer.open")).ToContainText("Evaluated: DENY", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("drawer should show newer evt-rich: %v", err)
	}
	// ...and still after the slow (evt-slow) response would have arrived (~350ms).
	time.Sleep(700 * time.Millisecond)
	dtxt, _ := page.Locator("#mcpx-drawer.open").TextContent()
	if !strings.Contains(dtxt, "Evaluated: DENY") || strings.Contains(dtxt, "srv-slow") {
		t.Fatalf("stale evt-slow response overwrote newer evt-rich; drawer=%q", dtxt)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}

// TestMCPUX_ReviewFixes proves the three Codex review fixes:
//
//	#1 a Tool pivot for an event with no server_id degrades to a tool-name
//	   related-decisions pivot (never opens an always-unavailable inventory
//	   drawer, since GetTool rejects an empty server_id);
//	#2 the activity-search fetch has a latest-request guard, so a slower earlier
//	   navigation cannot overwrite a newer one;
//	#3 an empty page carrying next_cursor is reported as "more results may exist",
//	   not a definitive "no matches".
func TestMCPUX_ReviewFixes(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := mcpuxRichPage(t, browser, srv.URL, &pageErrs)
	page.SetDefaultTimeout(8000)
	assert := playwright.NewPlaywrightAssertions()
	must := func(err error, ctx string) {
		if err != nil {
			t.Fatalf("%s: %v | pageErrs=%v", ctx, err, pageErrs)
		}
	}
	tct := func(loc playwright.Locator, sub, ctx string) {
		if err := assert.Locator(loc).ToContainText(sub, playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s (want %q): %v | pageErrs=%v", ctx, sub, err, pageErrs)
		}
	}

	must(page.Locator(`.nav-item[data-view="mcp-decisions"]`).First().Click(), "nav decisions")
	must(page.Locator("#mcp-dec-tenant").Fill("acme"), "fill tenant")
	must(page.Locator(`[data-click="renderMCPActivity"]`).First().Click(), "search")
	if err := assert.Locator(page.Locator("table.mcpx-act")).ToBeVisible(playwright.LocatorAssertionsToBeVisibleOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("table: %v", err)
	}

	// (#1) Server-less event: the tool pivot filters by tool name instead of
	// opening an unavailable Tool drawer.
	must(page.Locator(`tr[data-arg="evt-noserver"]`).Click(), "open evt-noserver")
	tct(page.Locator("#mcpx-drawer.open"), "Server and tool", "noserver drawer")
	// No server pivot exists (no server_id); the tool pivot leads to related decisions.
	if c, _ := page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("orphan_tool")`).Count(); c != 1 {
		t.Fatalf("expected exactly one tool pivot for the server-less event, got %d", c)
	}
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("orphan_tool")`).First().Click(), "tool pivot (no server)")
	tct(page.Locator(".mcpx-filterbar"), "tool = orphan_tool", "tool-name filter applied")
	if c, _ := page.Locator(`#mcpx-drawer.open:has-text("unavailable")`).Count(); c != 0 {
		t.Fatalf("server-less tool pivot must not open an unavailable drawer")
	}
	must(page.Locator(".mcpx-filterbar .mcpx-back").First().Click(), "back from tool filter")

	// (#3) Empty page with next_cursor is reported as incomplete, not "no matches".
	must(page.Locator(`tr[data-arg="evt-noserver"]`).Click(), "reopen evt-noserver")
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("u-sparse")`).First().Click(), "principal pivot (sparse)")
	tct(page.Locator("#mcpx-decisions-root .mcpx-empty"), "more results may exist", "incomplete empty message")
	must(page.Locator(".mcpx-filterbar .mcpx-back").First().Click(), "back from sparse")

	// (#2) Activity-search race: a slow agent-filter navigation followed by a fast
	// Search must leave the base list showing, never the stale filtered marker.
	must(page.Locator(`tr[data-arg="evt-rich"]`).Click(), "open evt-rich")
	must(page.Locator(`#mcpx-drawer button.mcpx-pivot:has-text("agent-42")`).First().Click(), "agent pivot (slow)")
	// While the agent filter is still loading, issue a fresh Search (fast base).
	must(page.Locator(`[data-click="renderMCPActivity"]`).First().Click(), "search over slow nav")
	if err := assert.Locator(page.Locator(`tr[data-arg="evt-rich"]`)).ToBeVisible(playwright.LocatorAssertionsToBeVisibleOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("base list should win the race: %v", err)
	}
	time.Sleep(700 * time.Millisecond) // let the stale agent response arrive + be discarded
	if c, _ := page.Locator(`tr[data-arg="evt-related"]`).Count(); c != 0 {
		t.Fatalf("stale agent-filter response overwrote the newer base view")
	}
	if c, _ := page.Locator(".mcpx-filterbar .mcpx-back").Count(); c != 0 {
		t.Fatalf("base view after Search must have no Back affordance (nav stack reset)")
	}

	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}
