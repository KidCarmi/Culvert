//go:build uie2e

package main

// PR-UX-4 production validation: drives the REAL shared MCP dangerous-action
// dialog (static/index.html, mcpxDangerDialog + mcpxOpen* + classifiers) in
// headless Chromium against the REAL admin handler, RBAC and CSRF middleware.
//
// The shipped UI reads/writes only /api/mcp/* ; this test supplies SYNTHETIC
// responses via request interception to exercise every branch deterministically
// (tests may use synthetic fixtures; the shipped UI may not). It asserts on the
// rendered DOM, fails on any uncaught page exception, and writes PR screenshots.
// Nothing here asserts a fabricated success - only what the backend returned.

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// ── synthetic fixtures (real response shapes) ──

// Rollout status used by the dialog pre-fetch (current mode + kill switch).
const fxUX4Rollout = `{"gateway":{"mode":"observe","desired":"observe","killed":false,"connector":"local-client","history_len":1},` +
	`"management":{"mode":"disabled","desired":"disabled","killed":false,"connector":"","history_len":0},` +
	`"metrics":{"hard_blocks":0},"production_locked":true,"distribution":{"enabled":false,"distribution_state":"local_only"}}`

// Distribution with NO retained rollback target (the real disabled-default shape).
const fxUX4DistNoTarget = `{"enabled":false,"distribution_state":"local_only",` +
	`"gateway":{"current_hash":"","previous_hash":"","epoch":0,"rollback_available":false},` +
	`"management":{"current_hash":"","previous_hash":"","epoch":0,"rollback_available":false}}`

// Distribution WITH a retained gateway rollback target (simulated configured node).
const fxUX4DistWithTarget = `{"enabled":true,"distribution_state":"partially_acknowledged",` +
	`"gateway":{"current_hash":"sha256:current11223344","previous_hash":"sha256:retained99887766","epoch":8,"rollback_available":true},` +
	`"management":{"current_hash":"","previous_hash":"","epoch":0,"rollback_available":false}}`

// ux4Log records the mutation requests the page actually issued.
type ux4Log struct {
	mu   sync.Mutex
	reqs []ux4Req
}
type ux4Req struct{ method, url, body string }

func (l *ux4Log) add(m, u, b string) {
	l.mu.Lock()
	l.reqs = append(l.reqs, ux4Req{m, u, b})
	l.mu.Unlock()
}
func (l *ux4Log) count(method, urlSub string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, r := range l.reqs {
		if r.method == method && strings.Contains(r.url, urlSub) {
			n++
		}
	}
	return n
}
func (l *ux4Log) last(method, urlSub string) (ux4Req, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.reqs) - 1; i >= 0; i-- {
		if l.reqs[i].method == method && strings.Contains(l.reqs[i].url, urlSub) {
			return l.reqs[i], true
		}
	}
	return ux4Req{}, false
}

// ux4Cfg controls the synthetic backend for one test.
type ux4Cfg struct {
	rolloutStatus int    // GET /api/mcp/rollout (default 200)
	distStatus    int    // GET /api/mcp/distribution (default 200)
	distBody      string // default fxUX4DistNoTarget
	emgStatus     int    // POST emergency override (0 ⇒ echo 200 based on action)
	delayDisable  bool   // delay the disable POST (race proof)
	passthrough   bool   // do NOT intercept /api/mcp/* - hit the REAL handler (RBAC proof)
	// stateful: the emergency POST APPLIES a per-capability kill state and the
	// rollout GET reflects it, so a reconcile reads the true server state. Used to
	// prove a late/cancelled disable converges the card to the real kill state.
	stateful bool
	mu       sync.Mutex
	killedGW bool
	killedMG bool
	log      *ux4Log
}

func ux4Bool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ux4RolloutBody renders the /api/mcp/rollout GET body reflecting the current
// per-capability kill state (stateful mode).
func ux4RolloutBody(killedGW, killedMG bool) string {
	return `{"gateway":{"mode":"observe","desired":"observe","killed":` + ux4Bool(killedGW) + `,"connector":"local-client","history_len":1},` +
		`"management":{"mode":"disabled","desired":"disabled","killed":` + ux4Bool(killedMG) + `,"connector":"","history_len":0},` +
		`"metrics":{"hard_blocks":0},"production_locked":true,"distribution":{"enabled":false,"distribution_state":"local_only"}}`
}

func ux4Install(t *testing.T, ctx playwright.BrowserContext, cfg *ux4Cfg) {
	t.Helper()
	if cfg.rolloutStatus == 0 {
		cfg.rolloutStatus = 200
	}
	if cfg.distStatus == 0 {
		cfg.distStatus = 200
	}
	if cfg.distBody == "" {
		cfg.distBody = fxUX4DistNoTarget
	}
	err := ctx.Route("**/*", func(route playwright.Route) {
		req := route.Request()
		u := req.URL()
		method := req.Method()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		// Passthrough mode: everything loopback goes to the REAL handler chain
		// (real RBAC + CSRF). Used to prove server-side enforcement.
		if cfg.passthrough {
			if b, _ := req.PostData(); method == "POST" && cfg.log != nil {
				cfg.log.add(method, u, b)
			}
			_ = route.Continue()
			return
		}
		json := func(status int, body string) {
			_ = route.Fulfill(playwright.RouteFulfillOptions{
				Status: playwright.Int(status), ContentType: playwright.String("application/json"), Body: playwright.String(body),
			})
		}
		plain := func(status int, body string) {
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(status), Body: playwright.String(body)})
		}
		body, _ := req.PostData()
		if method == "POST" && cfg.log != nil {
			cfg.log.add(method, u, body)
		}
		switch {
		case strings.Contains(u, "/api/mcp/rollout/emergency"):
			if cfg.emgStatus != 0 {
				plain(cfg.emgStatus, "boom")
				return
			}
			isMgmt := strings.Contains(body, "management")
			isClear := strings.Contains(body, `"clear"`)
			respond := func() {
				capName := "gateway"
				if isMgmt {
					capName = "management"
				}
				killed := !isClear
				if cfg.stateful { // apply the kill state so a later rollout GET reflects it
					cfg.mu.Lock()
					if isMgmt {
						cfg.killedMG = killed
					} else {
						cfg.killedGW = killed
					}
					cfg.mu.Unlock()
				}
				json(200, `{"capability":"`+capName+`","killed":`+ux4Bool(killed)+`}`)
			}
			if cfg.delayDisable && !isClear {
				go func() { time.Sleep(600 * time.Millisecond); respond() }()
				return
			}
			respond()
		case strings.Contains(u, "/api/mcp/rollout/transition"):
			if strings.Contains(body, "production") {
				plain(403, "rollout_production_locked")
				return
			}
			plain(409, "distribution_not_configured")
		case strings.Contains(u, "/api/mcp/rollout/rehearse-rollback"):
			json(200, `{"capability":"gateway","rollback_rehearsed":true}`)
		case strings.Contains(u, "/api/mcp/rollback"):
			plain(409, "distribution_not_configured")
		case strings.Contains(u, "/api/mcp/rollout") && method == "GET":
			if cfg.rolloutStatus != 200 {
				plain(cfg.rolloutStatus, "boom")
				return
			}
			if cfg.stateful {
				cfg.mu.Lock()
				gw, mg := cfg.killedGW, cfg.killedMG
				cfg.mu.Unlock()
				json(200, ux4RolloutBody(gw, mg))
				return
			}
			json(200, fxUX4Rollout)
		case strings.Contains(u, "/api/mcp/distribution"):
			if cfg.distStatus != 200 {
				plain(cfg.distStatus, "boom")
				return
			}
			json(200, cfg.distBody)
		default:
			_ = route.Continue()
		}
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
}

// ux4Sel selects an <option> by value and fails the test on error (SelectOption
// returns ([]string, error), so it cannot be passed to the single-error must()).
func ux4Sel(t *testing.T, page playwright.Page, id, val string) {
	t.Helper()
	if _, err := page.Locator(id).SelectOption(playwright.SelectOptionValues{Values: &[]string{val}}); err != nil {
		t.Fatalf("select %s=%s: %v", id, val, err)
	}
}

func ux4Page(t *testing.T, browser playwright.Browser, base string, role UIRole, cfg *ux4Cfg, pageErrs *[]string) playwright.Page {
	t.Helper()
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: 1440, Height: 900}})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	ux4Install(t, ctx, cfg)
	if err := ctx.AddCookies([]playwright.OptionalCookie{{
		Name: uiSessionCookieName, Value: mintUISessionValue(t, "ux_admin", role), URL: playwright.String(base),
	}}); err != nil {
		t.Fatalf("cookie: %v", err)
	}
	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	if pageErrs != nil {
		page.On("pageerror", func(e error) { *pageErrs = append(*pageErrs, e.Error()) })
	}
	if _, err := page.Goto(base+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto: %v", err)
	}
	page.SetDefaultTimeout(8000)
	return page
}

// TestMCPUX4_EmergencyDialog covers scenarios 1-7, 13, 16, 19, 20, 22, 24 on the
// emergency + rehearsal controls.
func TestMCPUX4_EmergencyDialog(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	log := &ux4Log{}
	page := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log}, &pageErrs)
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
	dlg := page.Locator("#mcpx-danger-dialog")
	confirm := page.Locator("#mcpx-dlg-confirm")
	typed := page.Locator("#mcpx-dlg-typed")

	must(page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout")

	// (1) Emergency disable opens the STANDARD dialog with capability chip + facts.
	must(page.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).First().Click(), "open disable")
	tvis(dlg, "dialog visible")
	tct(dlg, "Emergency disable admission", "title")
	tct(dlg, "capability: gateway", "capability chip")
	tct(dlg, "Stops new gateway admission", "local effect")
	tct(dlg, "No - node-local kill switch.", "no round trip")
	mcpuxShot(t, page, "safe-action-gateway-disable-dark-1440.png")

	// (2) Wrong typed phrase cannot submit - Confirm stays disabled, no POST fires.
	must(typed.Fill("disable gateway"), "wrong phrase") // case mismatch
	if err := assert.Locator(confirm).ToBeDisabled(playwright.LocatorAssertionsToBeDisabledOptions{Timeout: playwright.Float(4000)}); err != nil {
		t.Fatalf("confirm must be disabled on wrong phrase: %v", err)
	}
	must(confirm.Click(playwright.LocatorClickOptions{Force: playwright.Bool(true)}), "force click wrong")
	if n := log.count("POST", "/api/mcp/rollout/emergency"); n != 0 {
		t.Fatalf("wrong phrase must not POST; got %d", n)
	}

	// (3)+(5) Correct Gateway phrase submits gateway disable only; result shows the
	// REAL returned killed state.
	must(typed.Fill("DISABLE GATEWAY"), "correct phrase")
	if err := assert.Locator(confirm).ToBeEnabled(playwright.LocatorAssertionsToBeEnabledOptions{Timeout: playwright.Float(4000)}); err != nil {
		t.Fatalf("confirm must enable on exact phrase: %v", err)
	}
	must(confirm.Click(), "confirm disable")
	tct(page.Locator("#mcpx-dlg-result"), "Admission stopped on gateway", "success title")
	tct(page.Locator("#mcpx-dlg-result"), "killed = true", "real killed state")
	req, ok := log.last("POST", "/api/mcp/rollout/emergency")
	if !ok || !strings.Contains(req.body, `"capability":"gateway"`) || !strings.Contains(req.body, `"action":"disable"`) {
		t.Fatalf("gateway disable POST body wrong: %q", req.body)
	}
	if strings.Contains(req.body, "management") {
		t.Fatalf("gateway disable must not name management: %q", req.body)
	}
	// (20) The aria-live result region is NOT hidden with display:none while it
	// carries a result.
	disp, _ := page.Locator("#mcpx-dlg-result").Evaluate(`el => getComputedStyle(el).display`, nil)
	if disp == "none" {
		t.Fatalf("live result region must not be display:none while showing a result")
	}
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close after disable") // now labelled Close

	// (4) Management disable posts management only.
	must(page.Locator(`[data-click="mcpxRfSelectCap"][data-arg="management"]`).Click(), "select mgmt capability tab")
	must(page.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).First().Click(), "open mgmt disable")
	tct(dlg, "capability: management", "mgmt chip")
	must(typed.Fill("DISABLE MANAGEMENT"), "mgmt phrase")
	must(confirm.Click(), "confirm mgmt disable")
	tct(page.Locator("#mcpx-dlg-result"), "Admission stopped on management", "mgmt success")
	req, _ = log.last("POST", "/api/mcp/rollout/emergency")
	if !strings.Contains(req.body, `"capability":"management"`) {
		t.Fatalf("management disable POST body wrong: %q", req.body)
	}
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close mgmt")
	must(page.Locator(`[data-click="mcpxRfSelectCap"][data-arg="gateway"]`).Click(), "reset gateway capability tab")

	// (6)+(7) Emergency clear WARNS admission is restored and requires its own phrase.
	must(page.Locator(`[data-click="mcpxOpenEmergencyClear"]`).First().Click(), "open clear")
	tct(dlg, "Restores new gateway admission", "clear warning")
	tct(dlg, "may increase exposure", "clear not harmless")
	must(typed.Fill("CLEAR GATEWAY"), "clear phrase")
	must(confirm.Click(), "confirm clear")
	tct(page.Locator("#mcpx-dlg-result"), "Admission restored on gateway", "clear success")
	tct(page.Locator("#mcpx-dlg-result"), "killed = false", "clear real state")
	mcpuxShot(t, page, "safe-action-clear-warning-dark-1440.png")
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close clear")

	// (13) Rehearsal (level 1, no phrase) says evidence recorded + no rollback occurred.
	must(page.Locator(`[data-click="mcpxOpenRehearse"]`).First().Click(), "open rehearse")
	tct(dlg, "Record rollback rehearsal", "rehearse title")
	tct(dlg, "does NOT roll back traffic", "rehearse honest explain")
	if c, _ := typed.Count(); c > 0 {
		if vis, _ := page.Locator("#mcpx-dlg-typedwrap").IsVisible(); vis {
			t.Fatalf("level-1 rehearsal must not show a typed-confirm field")
		}
	}
	must(confirm.Click(), "confirm rehearse")
	tct(page.Locator("#mcpx-dlg-result"), "Rollback rehearsal recorded", "rehearse success")
	tct(page.Locator("#mcpx-dlg-result"), "No rollback was performed", "rehearse distinction")
	mcpuxShot(t, page, "safe-action-rehearsal-dark-1440.png")
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close rehearse")

	// (19) Escape closes the dialog and restores focus to the triggering control.
	must(page.Locator(`[data-click="mcpxOpenRehearse"]`).First().Click(), "reopen rehearse")
	tvis(dlg, "reopened")
	must(page.Keyboard().Press("Escape"), "escape")
	if err := assert.Locator(dlg).ToBeHidden(playwright.LocatorAssertionsToBeHiddenOptions{Timeout: playwright.Float(4000)}); err != nil {
		t.Fatalf("Escape must close the dialog: %v", err)
	}
	focused, _ := page.Evaluate(`() => document.activeElement && document.activeElement.getAttribute('data-click')`)
	if focused != "mcpxOpenRehearse" {
		t.Fatalf("focus must restore to the triggering control, got %v", focused)
	}

	// (16) Double click causes exactly one request (delayed POST keeps commit open).
	log2 := &ux4Log{}
	page2 := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log2, delayDisable: true}, &pageErrs)
	must(page2.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout p2")
	must(page2.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).First().Click(), "open disable p2")
	must(page2.Locator("#mcpx-dlg-typed").Fill("DISABLE GATEWAY"), "phrase p2")
	c2 := page2.Locator("#mcpx-dlg-confirm")
	must(c2.Click(), "click 1")
	_ = c2.Click(playwright.LocatorClickOptions{Force: playwright.Bool(true), Timeout: playwright.Float(1000)}) // 2nd click during commit
	time.Sleep(900 * time.Millisecond)
	if n := log2.count("POST", "/api/mcp/rollout/emergency"); n != 1 {
		t.Fatalf("double click must cause exactly one request, got %d", n)
	}

	// (22)+(24) No forbidden raw material anywhere in the dialog; no page exceptions.
	dtxt, _ := dlg.TextContent()
	for _, banned := range []string{"Bearer", "Authorization", "password", "private_key", "\"arguments\""} {
		if strings.Contains(dtxt, banned) {
			t.Fatalf("dialog leaked forbidden material %q", banned)
		}
	}
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}

// TestMCPUX4_TransitionAndRollback covers scenarios 8, 9, 10, 11, 12, 21, 22.
func TestMCPUX4_TransitionAndRollback(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	log := &ux4Log{}
	// Start with NO retained rollback target (scenario 10).
	page := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log}, &pageErrs)
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
	dlg := page.Locator("#mcpx-danger-dialog")
	confirm := page.Locator("#mcpx-dlg-confirm")
	typed := page.Locator("#mcpx-dlg-typed")

	must(page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout")

	// (8) Transition to Production surfaces the lock and handles 403 truthfully.
	ux4Sel(t, page, "#mcpx-rf-tomode", "production")
	must(page.Locator(`[data-click="mcpxOpenTransition"]`).First().Click(), "open transition prod")
	tct(dlg, "Production is qualification-locked", "prod lock fact")
	tct(dlg, "expected to be rejected", "prod honest explain")
	must(typed.Fill("PROMOTE GATEWAY"), "promote phrase")
	must(confirm.Click(), "confirm prod")
	tct(page.Locator("#mcpx-dlg-result"), "Production is qualification-locked", "403 truthful")
	rtxt, _ := page.Locator("#mcpx-dlg-result").TextContent()
	if strings.Contains(rtxt, "pending") || strings.Contains(rtxt, "accepted") {
		t.Fatalf("production 403 must not read as pending/accepted: %q", rtxt)
	}
	mcpuxShot(t, page, "safe-action-production-locked-dark-1440.png")
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close prod")

	// (9) Transition returning distribution_not_configured shows failure, not pending.
	ux4Sel(t, page, "#mcpx-rf-tomode", "canary")
	must(page.Locator(`[data-click="mcpxOpenTransition"]`).First().Click(), "open transition canary")
	must(typed.Fill("PROMOTE GATEWAY"), "promote phrase canary")
	must(confirm.Click(), "confirm canary")
	tct(page.Locator("#mcpx-dlg-result"), "Not fleet-effective", "409 not pending")
	rtxt, _ = page.Locator("#mcpx-dlg-result").TextContent()
	if strings.Contains(rtxt, "accepted") && !strings.Contains(rtxt, "NOT") {
		t.Fatalf("409 must not read as accepted: %q", rtxt)
	}
	mcpuxShot(t, page, "safe-action-distribution-not-configured-dark-1440.png")
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close canary")

	// (10) Rollback with NO real target: Confirm disabled, truthful note, no typed
	// field. PR-UX-8 removed the legacy health Distribution diagnostics panel; the
	// rollback control now lives in the structured Rollout & Fleet actions card.
	must(page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout")
	must(page.Locator(`[data-click="mcpxOpenRollback"]`).First().Click(), "open rollback no-target")
	tct(dlg, "No retained rollback target", "no target note")
	if err := assert.Locator(confirm).ToBeDisabled(playwright.LocatorAssertionsToBeDisabledOptions{Timeout: playwright.Float(4000)}); err != nil {
		t.Fatalf("rollback confirm must be disabled with no target: %v", err)
	}
	must(confirm.Click(playwright.LocatorClickOptions{Force: playwright.Bool(true)}), "force click disabled")
	if n := log.count("POST", "/api/mcp/rollback"); n != 0 {
		t.Fatalf("rollback with no target must not POST; got %d", n)
	}
	mcpuxShot(t, page, "safe-action-rollback-unavailable-dark-1440.png")
	must(page.Locator("#mcpx-dlg-cancel").Click(), "close rollback no-target")

	// (11)+(12) Rollback WITH a retained target binds the exact hash; 409 is not "started".
	log2 := &ux4Log{}
	page2 := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log2, distBody: fxUX4DistWithTarget}, &pageErrs)
	must(page2.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout p2")
	must(page2.Locator(`[data-click="mcpxOpenRollback"]`).First().Click(), "open rollback target")
	dlg2 := page2.Locator("#mcpx-danger-dialog")
	tct(dlg2, "Rollback target", "target label")
	tct(dlg2, "sha256:ret", "exact hash bound") // truncated display of sha256:retained99887766
	must(page2.Locator("#mcpx-dlg-typed").Fill("ROLLBACK GATEWAY"), "rollback phrase")
	must(page2.Locator("#mcpx-dlg-confirm").Click(), "confirm rollback")
	tct(page2.Locator("#mcpx-dlg-result"), "Rollback not started", "409 not started")
	req, ok := log2.last("POST", "/api/mcp/rollback")
	if !ok || !strings.Contains(req.body, `"target_hash":"sha256:retained99887766"`) {
		t.Fatalf("rollback must submit the exact retained target, got %q", req.body)
	}
	// A 409 must render as a failure (crit), never a success - and the confirm
	// button must not remain a committed success (it becomes Retry or hides).
	rcls, _ := page2.Locator("#mcpx-dlg-result").GetAttribute("class")
	if strings.Contains(rcls, "ok") || !strings.Contains(rcls, "crit") {
		t.Fatalf("409 rollback result must be crit (failure), not success; class=%q", rcls)
	}
	rtitle, _ := page2.Locator("#mcpx-dlg-result .mcpx-dlg-rtitle").TextContent()
	if strings.Contains(rtitle, "initiated") || strings.Contains(rtitle, "started successfully") {
		t.Fatalf("409 rollback title must not read as initiated: %q", rtitle)
	}

	// (21) No unsupported quarantine/revoke controls exist anywhere in the MCP views.
	for _, sel := range []string{`button:has-text("Quarantine")`, `button:has-text("Revoke")`, `button:has-text("Terminate execution")`, `button:has-text("Force convergence")`} {
		if n, _ := page.Locator(sel).Count(); n != 0 {
			t.Fatalf("unsupported control present (%s): %d", sel, n)
		}
	}
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}

// TestMCPUX4_RBACAndRaces covers scenarios 14, 15, 17, 18, 23, 24.
func TestMCPUX4_RBACAndRaces(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions()

	// (14) A viewer sees NO admin mutation controls (data-min-role gating). Uses
	// the REAL handler chain (passthrough) so the forced-POST below hits real RBAC.
	viewerErrs := []string{}
	vpage := ux4Page(t, browser, srv.URL, RoleViewer, &ux4Cfg{passthrough: true}, &viewerErrs)
	if err := vpage.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(); err != nil {
		t.Fatalf("viewer nav: %v", err)
	}
	// The emergency-disable button lives in a data-min-role="admin" panel - hidden for a viewer.
	if err := assert.Locator(vpage.Locator(`[data-click="mcpxOpenEmergencyDisable"]`)).ToBeHidden(playwright.LocatorAssertionsToBeHiddenOptions{Timeout: playwright.Float(5000)}); err != nil {
		t.Fatalf("viewer must not see the emergency disable control: %v", err)
	}

	// (15) A FORCED viewer POST is denied server-side (client hiding is not authz).
	// Uses the real handler (not intercepted) via a same-origin fetch.
	forced, err := vpage.Evaluate(`async () => {
		const r = await fetch('/api/mcp/rollout/emergency', {method:'POST', credentials:'same-origin',
			headers:{'Content-Type':'application/json','X-CSRF-Token':(window.csrfToken||'')},
			body: JSON.stringify({capability:'gateway', action:'disable'})});
		return r.status;
	}`)
	if err != nil {
		t.Fatalf("forced fetch eval: %v", err)
	}
	// playwright-go returns a JS number as int/int64/float64 depending on value;
	// compare the string form so the RBAC assertion is representation-agnostic.
	if got := fmt.Sprint(forced); got != "403" {
		t.Fatalf("forced viewer POST must be 403 server-side, got %v", got)
	}

	// (17) A late/cancelled in-flight response must never leave the card asserting a
	// state the server no longer holds. The backend is STATEFUL here: a slow disable
	// is cancelled mid-commit, then a fast clear completes (card reconciles to
	// "clear"); when the delayed disable finally lands (applied LAST → kill switch
	// engaged), the card must RECONCILE to "engaged", not stay on the clear result.
	log := &ux4Log{}
	var pageErrs []string
	page := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log, delayDisable: true, stateful: true}, &pageErrs)
	if err := page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(); err != nil {
		t.Fatalf("nav: %v", err)
	}
	must := func(e error, c string) {
		if e != nil {
			t.Fatalf("%s: %v | pageErrs=%v", c, e, pageErrs)
		}
	}
	must(page.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).First().Click(), "open disable race")
	must(page.Locator("#mcpx-dlg-typed").Fill("DISABLE GATEWAY"), "disable phrase race")
	must(page.Locator("#mcpx-dlg-confirm").Click(), "confirm disable race")
	// Explicit cancel while the disable is still in flight (safe cancellation).
	must(page.Locator("#mcpx-dlg-cancel").Click(), "cancel during commit")
	// A fast Clear completes; the card reconciles to the authoritative state.
	must(page.Locator(`[data-click="mcpxOpenEmergencyClear"]`).First().Click(), "open clear race")
	must(page.Locator("#mcpx-dlg-typed").Fill("CLEAR GATEWAY"), "clear phrase race")
	must(page.Locator("#mcpx-dlg-confirm").Click(), "confirm clear race")
	if err := assert.Locator(page.Locator("#mcp-emergency-out")).ToContainText("gateway: clear", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("card must reconcile to the authoritative clear state: %v", err)
	}
	// The delayed disable now lands (applied last ⇒ kill switch engaged). The card
	// MUST converge to the true engaged state, not silently drop the late response.
	if err := assert.Locator(page.Locator("#mcp-emergency-out")).ToContainText("gateway: engaged", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("card must reconcile to engaged after the late disable lands: %v", err)
	}
	// The card is authoritative kill-state, never a stale action title.
	ctext, _ := page.Locator("#mcp-emergency-out").TextContent()
	if strings.Contains(ctext, "Admission") {
		t.Fatalf("card must show authoritative kill state, not a stale action title: %q", ctext)
	}

	// (18) Failed POST followed by failed refresh renders state as unavailable,
	// never a benign default. Emergency POST 500 + rollout GET 500.
	log3 := &ux4Log{}
	page3 := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log3, emgStatus: 500, rolloutStatus: 500}, &pageErrs)
	if err := page3.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(); err != nil {
		t.Fatalf("nav p3: %v", err)
	}
	must(page3.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).First().Click(), "open disable fail")
	// Pre-fetch failed ⇒ current state is shown as unavailable, not fabricated.
	if err := assert.Locator(page3.Locator("#mcpx-danger-dialog")).ToContainText("unavailable", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("failed pre-read must show unavailable: %v", err)
	}
	must(page3.Locator("#mcpx-dlg-typed").Fill("DISABLE GATEWAY"), "phrase fail")
	must(page3.Locator("#mcpx-dlg-confirm").Click(), "confirm fail")
	if err := assert.Locator(page3.Locator("#mcpx-dlg-result")).ToContainText("Action failed", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("failed POST must render a failure: %v", err)
	}
	// Retry is offered (safe - the action is idempotent / unconfirmed).
	if err := assert.Locator(page3.Locator("#mcpx-dlg-confirm")).ToContainText("Retry", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(4000)}); err != nil {
		t.Fatalf("failed POST must offer Retry: %v", err)
	}
	// PR-UX-8: the raw rollout JSON dump was removed. The forced refresh also failed,
	// so the persistent kill-switch status line must show an unavailable read (never a
	// benign killed=false default). This is the truthful structured surface that
	// replaced the raw #mcp-rollout-out pre.
	if err := assert.Locator(page3.Locator("#mcp-emergency-out")).ToContainText("unavailable", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		estat, _ := page3.Locator("#mcp-emergency-out").TextContent()
		t.Fatalf("failed refresh must show kill-switch unavailable, not a benign default: emergency=%q err=%v", estat, err)
	}

	if len(pageErrs) != 0 || len(viewerErrs) != 0 {
		t.Fatalf("uncaught page errors: admin=%v viewer=%v", pageErrs, viewerErrs)
	}

	// Screenshot sweep: light + responsive proofs of the disable dialog.
	log4 := &ux4Log{}
	pageS := ux4Page(t, browser, srv.URL, RoleAdmin, &ux4Cfg{log: log4}, &pageErrs)
	_ = pageS.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click()
	_ = pageS.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).First().Click()
	_, _ = pageS.Evaluate(`() => document.documentElement.setAttribute('data-theme','light')`)
	mcpuxShot(t, pageS, "safe-action-gateway-disable-light-1440.png")
	_ = pageS.SetViewportSize(1280, 800)
	mcpuxShot(t, pageS, "safe-action-gateway-disable-light-1280.png")
	_ = pageS.SetViewportSize(1920, 1080)
	mcpuxShot(t, pageS, "safe-action-gateway-disable-light-1920.png")
}
