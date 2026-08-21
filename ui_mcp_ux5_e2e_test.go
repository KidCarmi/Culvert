//go:build uie2e

package main

// PR-UX-5 production validation: drives the REAL truthful Rollout & Fleet screen
// (static/index.html, mcpxRenderRolloutFleet + card builders) in headless Chromium
// against the REAL admin handler. Synthetic /api/mcp/* fixtures exercise every
// branch deterministically (tests may use synthetic fixtures; the shipped UI may
// not). Nothing asserts a fabricated state - only what the backend returned.

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// ── PR-UX-5 fixtures (real response shapes) ──

const fxRfRollout = `{"gateway":{"mode":"canary","desired":"canary","killed":false,"connector":"local-client","history_len":3},` +
	`"management":{"mode":"observe","desired":"observe","killed":false,"connector":"","history_len":1},` +
	`"metrics":{},"production_locked":true,"distribution":{"enabled":true,"distribution_state":"partially_acknowledged"}}`

const fxRfScopeGW = `{"capability":"gateway","mode":"canary","kind":"enumerated","enumerable":true,"matches_nothing":false,` +
	`"high_risk":false,"exclusion_based":false,"percent":0,"operations":["read"],"selector_counts":{"servers":2,"tenants":1},` +
	`"exclusion_counts":{},"scope_hash":"sha256:gwscope1234","scope_revision":4,"connector_mode":"local-client",` +
	`"spec":{"capability":1,"servers":["srv-a","srv-b"],"tenants":["acme"]}}`

const fxRfScopeMG = `{"capability":"management","mode":"observe","kind":"percentage","enumerable":false,"matches_nothing":false,` +
	`"high_risk":true,"exclusion_based":false,"percent":25,"operations":["write"],"selector_counts":{},"exclusion_counts":{},` +
	`"scope_hash":"sha256:mgscope9999","scope_revision":2,"connector_mode":"","spec":{"capability":2,"percent":25,"high_risk":true}}`

const fxRfDist = `{"enabled":true,"distribution_state":"partially_acknowledged",` +
	`"gateway":{"current_hash":"sha256:gwcur1111","previous_hash":"sha256:gwprev2222","epoch":8,"rollback_available":true},` +
	`"management":{"current_hash":"","previous_hash":"","epoch":0,"rollback_available":false}}`

const fxRfAcksGW = `{"capability":"gateway","configured":true,"content_hash":"sha256:gwcur1111","distribution_state":"partially_acknowledged",` +
	`"as_of_unix_nano":1722690000000000000,"intended":3,"counts":{"intended":3,"applied":1,"rolled_back":0,"rejected":1,"incompatible":1,"unavailable":1},` +
	`"rows":[{"node_id":"dp-1","state":"applied","active_hash":"sha256:gwcur1111","dp_version":2,"health":"healthy"},` +
	`{"node_id":"dp-2","state":"rejected","reject_reason":"snapshot_min_version_unmet","incompatible":true,"dp_version":1,"health":"degraded"},` +
	`{"node_id":"dp-3","state":"unavailable"}]}`

const fxRfAcksMG = `{"capability":"management","configured":false,"content_hash":"","distribution_state":"local_only",` +
	`"as_of_unix_nano":1722690000000000000,"intended":0,"counts":null,"rows":[]}`

type ux5Cfg struct {
	delayGWScope bool // delay the gateway scope GET (stale-response proof)
	acksGW500    bool // gateway acks read fails (unavailable proof)
	mu           sync.Mutex
}

func ux5Install(t *testing.T, ctx playwright.BrowserContext, cfg *ux5Cfg) {
	t.Helper()
	err := ctx.Route("**/*", func(route playwright.Route) {
		req := route.Request()
		u := req.URL()
		method := req.Method()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		json := func(body string) {
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), ContentType: playwright.String("application/json"), Body: playwright.String(body)})
		}
		isMgmt := strings.Contains(u, "capability=management")
		switch {
		case method == "POST" && strings.Contains(u, "/api/mcp/rollout/scope/validate"):
			_ = route.Continue() // exercise the REAL validation handler end-to-end
		case method == "GET" && strings.Contains(u, "/api/mcp/rollout/scope"):
			if isMgmt {
				json(fxRfScopeMG)
			} else if cfg.delayGWScope {
				go func() { time.Sleep(500 * time.Millisecond); json(fxRfScopeGW) }()
			} else {
				json(fxRfScopeGW)
			}
		case method == "GET" && strings.Contains(u, "/api/mcp/distribution/acks"):
			if isMgmt {
				json(fxRfAcksMG)
			} else if cfg.acksGW500 {
				_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: playwright.String("boom")})
			} else {
				json(fxRfAcksGW)
			}
		case method == "GET" && strings.Contains(u, "/api/mcp/distribution"):
			json(fxRfDist)
		case method == "GET" && strings.Contains(u, "/api/mcp/rollout"):
			json(fxRfRollout)
		default:
			_ = route.Continue()
		}
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
}

func ux5Page(t *testing.T, browser playwright.Browser, base string, cfg *ux5Cfg, pageErrs *[]string) playwright.Page {
	t.Helper()
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: 1440, Height: 900}})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	ux5Install(t, ctx, cfg)
	if err := ctx.AddCookies([]playwright.OptionalCookie{{Name: uiSessionCookieName, Value: mintUISessionValue(t, "ux_admin", RoleAdmin), URL: playwright.String(base)}}); err != nil {
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

// TestMCPUX5_RolloutFleet drives the structured screen: mode triad, scope kind,
// real DP acknowledgement counts + rows, rollback target, and the candidate-scope
// validation preview (against the REAL validator).
func TestMCPUX5_RolloutFleet(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux5Page(t, browser, srv.URL, &ux5Cfg{}, &pageErrs)
	assert := playwright.NewPlaywrightAssertions()
	root := page.Locator("#mcpx-rf-root")
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

	must(page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout")

	// Mode triad (gateway): desired / locally-active / fleet-effective. Fleet is
	// "pending" (partially_acknowledged), NOT asserted as effective.
	tct(root, "Rollout mode - gateway", "mode card title")
	tct(root, "Desired", "triad desired")
	tct(root, "Locally active", "triad local")
	tct(root, "Fleet-effective", "triad fleet")
	tct(root, "Production: LOCKED", "prod lock chip")
	// Scope card: enumerated kind + selector counts + hash.
	tct(root, "kind: enumerated", "scope kind")
	tct(root, "enumerable", "scope enumerable chip")
	tct(root, "sha256:gws", "scope hash truncated")
	// Fleet card: real counts + per-DP rows.
	tct(root, "Fleet distribution - gateway", "fleet card title")
	tct(root, "applied", "counts applied label")
	tct(root, "incompatible", "counts incompatible label")
	tct(page.Locator("table.mcpx-rf-acks"), "dp-1", "ack row dp-1")
	tct(page.Locator("table.mcpx-rf-acks"), "dp-3", "ack row dp-3 (unavailable)")
	tct(page.Locator("table.mcpx-rf-acks"), "unavailable", "dp-3 state unavailable")
	// Rollback target is the exact retained previous_hash.
	tct(root, "Retained rollback target", "rollback target label")
	tct(root, "sha256:gwp", "rollback target hash")
	mcpuxShot(t, page, "rollout-fleet-gateway-dark-1440.png")

	// Candidate-scope validation preview (REAL validator): valid candidate ⇒ diff.
	must(page.Locator("#mcpx-rf-cand").Fill(`{"servers":["srv-x","srv-y"]}`), "fill candidate")
	must(page.Locator(`[data-click="mcpxRfValidateScope"]`).First().Click(), "validate candidate")
	tct(page.Locator("#mcpx-rf-cand-out"), "valid candidate", "candidate valid")
	// Invalid candidate ⇒ invalid + classified code, never applied.
	must(page.Locator("#mcpx-rf-cand").Fill(`{"operations":[2]}`), "fill invalid candidate")
	must(page.Locator(`[data-click="mcpxRfValidateScope"]`).First().Click(), "validate invalid")
	tct(page.Locator("#mcpx-rf-cand-out"), "invalid candidate", "candidate invalid")
	mcpuxShot(t, page, "rollout-fleet-candidate-preview-dark-1440.png")

	// No forbidden material anywhere; no page exceptions.
	rtxt, _ := root.TextContent()
	for _, banned := range []string{"Bearer", "Authorization", "password", "private_key", "\"signature\""} {
		if strings.Contains(rtxt, banned) {
			t.Fatalf("rollout/fleet leaked forbidden material %q", banned)
		}
	}
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}

	// Light + responsive proofs.
	_, _ = page.Evaluate(`() => document.documentElement.setAttribute('data-theme','light')`)
	mcpuxShot(t, page, "rollout-fleet-gateway-light-1440.png")
	must(page.SetViewportSize(1280, 800), "1280")
	mcpuxShot(t, page, "rollout-fleet-gateway-light-1280.png")
	must(page.SetViewportSize(1920, 1080), "1920")
	mcpuxShot(t, page, "rollout-fleet-gateway-light-1920.png")
}

// TestMCPUX5_NotConfiguredAndUnavailable proves the truthful negative states:
// management fleet is not-configured (no fabricated counts) and a failed gateway
// ack read renders "unavailable", never a benign zero-as-healthy.
func TestMCPUX5_NotConfiguredAndUnavailable(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux5Page(t, browser, srv.URL, &ux5Cfg{acksGW500: true}, &pageErrs)
	assert := playwright.NewPlaywrightAssertions()
	root := page.Locator("#mcpx-rf-root")
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

	must(page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout")
	// Gateway ack read failed (500) ⇒ fleet acknowledgements unavailable, NOT a
	// benign "0 DPs / fully acknowledged" default.
	tct(root, "Fleet acknowledgements unavailable", "gw acks unavailable")
	rtxt, _ := root.TextContent()
	if strings.Contains(rtxt, "fully_acknowledged") || strings.Contains(rtxt, "0 DPs") {
		t.Fatalf("failed ack read must not fabricate a healthy default: %q", rtxt)
	}
	// No ack table rendered when unavailable.
	if n, _ := page.Locator("table.mcpx-rf-acks").Count(); n != 0 {
		t.Fatalf("no ack table may render when acks are unavailable, got %d", n)
	}
	mcpuxShot(t, page, "rollout-fleet-unavailable-dark-1440.png")

	// Switch to Management: not-configured fleet ⇒ explicit "not configured", no counts.
	must(page.Locator(`[data-click="mcpxRfSelectCap"][data-arg="management"]`).Click(), "select management")
	tct(root, "Fleet distribution - management", "mgmt fleet card")
	tct(root, "not configured", "mgmt not configured")
	tct(root, "kind: percentage", "mgmt scope kind percentage")
	mtxt, _ := root.TextContent()
	if strings.Contains(mtxt, "applied") && strings.Contains(mtxt, "intended") {
		t.Fatalf("management (not configured) must not render fabricated counts: %q", mtxt)
	}
	mcpuxShot(t, page, "rollout-fleet-management-notconfigured-dark-1440.png")
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}

// TestMCPUX5_CapabilityIsolationAndStale proves capability binding: management's
// scope never shows gateway's, and a delayed gateway response cannot overwrite a
// newer management selection (request-ticket guard).
func TestMCPUX5_CapabilityIsolationAndStale(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux5Page(t, browser, srv.URL, &ux5Cfg{delayGWScope: true}, &pageErrs)
	assert := playwright.NewPlaywrightAssertions()
	root := page.Locator("#mcpx-rf-root")
	must := func(err error, ctx string) {
		if err != nil {
			t.Fatalf("%s: %v | pageErrs=%v", ctx, err, pageErrs)
		}
	}

	// Gateway render starts (its scope GET is delayed 500ms); immediately switch to
	// Management. The stale gateway scope must NOT overwrite the management view.
	must(page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout (gateway, delayed)")
	must(page.Locator(`[data-click="mcpxRfSelectCap"][data-arg="management"]`).Click(), "switch to management before gw resolves")
	// Management scope must render (percentage kind, mgmt hash).
	if err := assert.Locator(root).ToContainText("kind: percentage", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("management scope must render: %v | pageErrs=%v", err, pageErrs)
	}
	// Wait past the delayed gateway scope; it must NOT overwrite management.
	page.WaitForTimeout(800)
	rtxt, _ := root.TextContent()
	if strings.Contains(rtxt, "kind: enumerated") || strings.Contains(rtxt, "sha256:gwscope") {
		t.Fatalf("stale gateway scope overwrote management view: %q", rtxt)
	}
	if !strings.Contains(rtxt, "Scope - management") {
		t.Fatalf("management scope card must be present: %q", rtxt)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("uncaught page errors: %v", pageErrs)
	}
}
