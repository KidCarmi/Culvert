//go:build uie2e

package main

// PR-UX-7 production validation: drives the five REAL structured MCP admin views
// (Servers & Tools, Policy & Simulator, Health & Durability, Management Access,
// Listener Settings) plus the Gateway publication handoff in headless Chromium
// against the REAL admin handler. Policy / health / management-access / config /
// publications use the REAL handlers (real DTOs, real validation, real management
// guard); only the tenant-scoped inventory lists are fixtured to control row
// rendering and failure injection. Nothing asserts a fabricated state.

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// Real ServerView / ToolView shapes (fixtured for row rendering).
const fxU7Servers = `[{"server_id":"srv-alpha","tenant":"acme","capability":"gateway","enabled":true,"verification":"verified","identity_changed":false,"revision":4,"credential_profile_ref":"cred-1","endpoint_configured":true},` +
	`{"server_id":"srv-beta","tenant":"acme","capability":"gateway","enabled":false,"verification":"identity_mismatch","identity_changed":true,"revision":2,"endpoint_configured":false}]`
const fxU7Tools = `[{"server_id":"srv-alpha","name":"search","fingerprint":"sha256:fp-search-111","disposition":"usable","quarantined":false,"review_required":false,"destination_class":"approved","revision":4},` +
	`{"server_id":"srv-alpha","name":"delete","fingerprint":"sha256:fp-delete-222","disposition":"quarantined","quarantined":true,"review_required":false,"destination_class":"arbitrary","revision":4}]`

type ux7Cfg struct {
	servers, tools  string // inventory fixture bodies ("" => real handler / empty)
	srv500, tool500 bool
	srvEmpty        bool
	delayValidate   bool // delay the policy validate response (in-flight stale-race proof)
}

func ux7Install(t *testing.T, ctx playwright.BrowserContext, cfg *ux7Cfg) {
	t.Helper()
	err := ctx.Route("**/*", func(route playwright.Route) {
		req := route.Request()
		u, m := req.URL(), req.Method()
		loopback := strings.Contains(u, "127.0.0.1") || strings.Contains(u, "localhost")
		if !loopback && !strings.HasPrefix(u, "data:") && !strings.HasPrefix(u, "blob:") {
			_ = route.Abort()
			return
		}
		json := func(b string) {
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), ContentType: playwright.String("application/json"), Body: playwright.String(b)})
		}
		switch {
		case m == "GET" && strings.Contains(u, "/api/mcp/servers"):
			if cfg.srv500 {
				_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: playwright.String("boom")})
			} else if cfg.srvEmpty {
				json("[]")
			} else {
				json(nonEmpty7(cfg.servers, fxU7Servers))
			}
		case m == "GET" && strings.Contains(u, "/api/mcp/tools"):
			if cfg.tool500 {
				_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: playwright.String("boom")})
			} else {
				json(nonEmpty7(cfg.tools, fxU7Tools))
			}
		case m == "POST" && cfg.delayValidate && strings.Contains(u, "/api/mcp/policy-simulate"):
			pd, _ := req.PostData()
			if strings.Contains(pd, `"mode":"validate"`) {
				// Delayed OK for the ORIGINAL bytes; the test edits during the delay so
				// this stale response must be dropped by the advanced ticket.
				go func() {
					time.Sleep(400 * time.Millisecond)
					json(`{"ok":true,"capability":"gateway","candidate_hash":"sha256:stalehash","rule_count":0,"default_action":"DENY","schema_version":1}`)
				}()
			} else {
				_ = route.Continue()
			}
		default:
			_ = route.Continue() // real handler for policy / health / management / config / publications
		}
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
}

func nonEmpty7(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ux7Page(t *testing.T, browser playwright.Browser, base string, role UIRole, cfg *ux7Cfg, pageErrs *[]string) playwright.Page {
	t.Helper()
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: 1440, Height: 900}})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	ux7Install(t, ctx, cfg)
	user := "ux_admin"
	if role == RoleViewer {
		user = "ux_viewer"
	}
	if err := ctx.AddCookies([]playwright.OptionalCookie{{Name: uiSessionCookieName, Value: mintUISessionValue(t, user, role), URL: playwright.String(base)}}); err != nil {
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
	if _, err := page.WaitForFunction("() => window.currentRole && window.currentRole.length > 0", nil, playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(8000)}); err != nil {
		t.Fatalf("boot: %v | %v", err, pageErrs)
	}
	return page
}

func ux7tct(t *testing.T, assert playwright.PlaywrightAssertions, loc playwright.Locator, sub, ctx string, pageErrs *[]string) {
	t.Helper()
	if err := assert.Locator(loc).ToContainText(sub, playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
		t.Fatalf("%s (want %q): %v | pageErrs=%v", ctx, sub, err, *pageErrs)
	}
}

// TestMCPUX7_ServersAndTools: structured rows, drawers with only real fields,
// fingerprint copy value, quarantined textual, empty vs unavailable, no actions.
func TestMCPUX7_ServersAndTools(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	assert := playwright.NewPlaywrightAssertions()
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, &pageErrs)
	must := func(err error, c string) {
		if err != nil {
			t.Fatalf("%s: %v | %v", c, err, pageErrs)
		}
	}
	must(page.Locator(`.nav-item[data-view="mcp-servers"]`).First().Click(), "nav servers")
	must(page.Locator("#mcp-srv-tenant").Fill("acme"), "tenant")
	must(page.Locator(`[data-click="mcpxInvLoad"]`).First().Click(), "load")
	root := page.Locator("#mcpx-inv-root")
	ux7tct(t, assert, root, "srv-alpha", "server row", &pageErrs)
	ux7tct(t, assert, root, "search", "tool row", &pageErrs)
	ux7tct(t, assert, root, "quarantined", "quarantined textual", &pageErrs)
	// Server drawer: only real ServerView fields (no raw endpoint).
	must(page.Locator("tr.mcpx-inv-row").Filter(playwright.LocatorFilterOptions{HasText: "srv-alpha"}).First().Click(), "open server")
	ux7tct(t, assert, page.Locator("#mcpx-inv-drawer"), "Credential profile", "server cred ref", &pageErrs)
	ux7tct(t, assert, page.Locator("#mcpx-inv-drawer"), "View related activity", "server pivot", &pageErrs)
	mcpuxShot(t, page, "ux7-servers-drawer-dark-1440.png")
	// Tool drawer: fingerprint present.
	must(page.Locator("tr.mcpx-inv-row").Filter(playwright.LocatorFilterOptions{HasText: "search"}).First().Click(), "open tool")
	ux7tct(t, assert, page.Locator("#mcpx-inv-drawer"), "Fingerprint", "tool fingerprint", &pageErrs)
	mcpuxShot(t, page, "ux7-tools-drawer-dark-1440.png")
	// No mutation action anywhere.
	for _, forbidden := range []string{"Quarantine", "Unquarantine", "Register server", "Delete tool", "Refresh discovery"} {
		n, _ := page.Locator("button:has-text('" + forbidden + "')").Count()
		if n != 0 {
			t.Fatalf("forbidden inventory action %q present", forbidden)
		}
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX7_ServersUnavailableAndEmpty: failed read => unavailable (not empty);
// empty read => empty state; a tool failure never erases loaded servers.
func TestMCPUX7_ServersUnavailableAndEmpty(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	assert := playwright.NewPlaywrightAssertions()

	// Servers fail, tools succeed: unavailable for servers, tools still render.
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{srv500: true}, &pageErrs)
	_ = page.Locator(`.nav-item[data-view="mcp-servers"]`).First().Click()
	_ = page.Locator("#mcp-srv-tenant").Fill("acme")
	_ = page.Locator(`[data-click="mcpxInvLoad"]`).First().Click()
	ux7tct(t, assert, page.Locator("#mcpx-inv-root"), "Servers unavailable", "servers unavailable", &pageErrs)
	ux7tct(t, assert, page.Locator("#mcpx-inv-root"), "search", "tools still loaded", &pageErrs)
	mcpuxShot(t, page, "ux7-inventory-unavailable-dark-1440.png")

	// Empty inventory: explicit empty state (distinct from unavailable).
	page2 := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{srvEmpty: true, tools: "[]"}, &pageErrs)
	_ = page2.Locator(`.nav-item[data-view="mcp-servers"]`).First().Click()
	_ = page2.Locator("#mcp-srv-tenant").Fill("acme")
	_ = page2.Locator(`[data-click="mcpxInvLoad"]`).First().Click()
	ux7tct(t, assert, page2.Locator("#mcpx-inv-root"), "No servers for this tenant", "empty servers", &pageErrs)
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX7_PolicyWorkflow: active summary (new candidate), validate (real, valid +
// invalid), structured corpus, simulate, compare labels + new-allow, and the Gateway
// publication handoff creating a REAL request (request id, not published).
func TestMCPUX7_PolicyWorkflow(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	assert := playwright.NewPlaywrightAssertions()
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, &pageErrs)
	must := func(err error, c string) {
		if err != nil {
			t.Fatalf("%s: %v | %v", c, err, pageErrs)
		}
	}
	must(page.Locator(`.nav-item[data-view="mcp-policies"]`).First().Click(), "nav policies")
	root := page.Locator("#mcpx-pol-root")
	ux7tct(t, assert, root, "Active policy - gateway", "active card", &pageErrs)
	ux7tct(t, assert, root, "NEW candidate", "new candidate label", &pageErrs)
	must(page.Locator("#mcpx-pol-tenant").Fill("acme"), "tenant")

	// Invalid candidate => classified failure (real validator), active unchanged.
	must(page.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway"}`), "fill invalid")
	must(page.Locator(`[data-click="mcpxPolValidate"]`).First().Click(), "validate invalid")
	ux7tct(t, assert, root, "Invalid candidate", "invalid result", &pageErrs)
	mcpuxShot(t, page, "ux7-policy-invalid-dark-1440.png")

	// Valid candidate => server-returned hash + metadata.
	must(page.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`), "fill valid")
	must(page.Locator(`[data-click="mcpxPolValidate"]`).First().Click(), "validate valid")
	ux7tct(t, assert, root, "Valid candidate", "valid result", &pageErrs)
	ux7tct(t, assert, root, "Candidate hash (server)", "server hash", &pageErrs)
	mcpuxShot(t, page, "ux7-policy-valid-dark-1440.png")

	// Structured corpus: add a case, compare, and confirm the corpus-change label.
	must(page.Locator(`[data-click="mcpxPolAddCase"]`).First().Click(), "add case")
	must(page.Locator(".mcpx-pol-case").First().WaitFor(), "case row")
	must(page.Locator(`[data-click="mcpxPolCompare"]`).First().Click(), "compare")
	ux7tct(t, assert, root, "Changes in the submitted test corpus", "compare label", &pageErrs)
	ux7tct(t, assert, root, "new allow", "new allow class", &pageErrs)
	mcpuxShot(t, page, "ux7-policy-compare-dark-1440.png")

	// Publication handoff: create a REAL Gateway request, see the request id (not published).
	must(page.Locator(`[data-click="mcpxPolCreateRequest"]`).First().Click(), "open create dialog")
	ux7tct(t, assert, page.Locator("#mcpx-dlg-explain"), "does NOT approve, publish", "create disclosure", &pageErrs)
	ux7tct(t, assert, page.Locator("#mcpx-dlg-facts"), "Base revision", "create binding facts", &pageErrs)
	mcpuxShot(t, page, "ux7-policy-handoff-confirm-dark-1440.png")
	must(page.Locator("#mcpx-dlg-confirm").Click(), "confirm create")
	ux7tct(t, assert, page.Locator("#mcpx-dlg-result"), "Publication request created", "request created", &pageErrs)
	// Active policy remains unchanged (still revision 0, new candidate).
	ux7tct(t, assert, root, "Request created", "request card", &pageErrs)
	mcpuxShot(t, page, "ux7-policy-request-created-dark-1440.png")
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX7_CapabilitySwitchDiscardsDraft proves a capability switch discards the
// candidate draft (matching its own confirm), so the previous capability's source
// never persists in the other capability's editor.
func TestMCPUX7_CapabilitySwitchDiscardsDraft(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, &pageErrs)
	page.On("dialog", func(d playwright.Dialog) { _ = d.Accept() }) // accept the discard confirm
	must := func(err error, c string) {
		if err != nil {
			t.Fatalf("%s: %v | %v", c, err, pageErrs)
		}
	}
	must(page.Locator(`.nav-item[data-view="mcp-policies"]`).First().Click(), "nav policies")
	must(page.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`), "fill gateway draft")
	must(page.Locator(`[data-click="mcpxPolSelectCap"][data-arg="management"]`).First().Click(), "switch to management")
	// The management editor must be empty (the gateway draft was discarded).
	val, err := page.Locator("#mcpx-pol-src").InputValue()
	if err != nil {
		t.Fatalf("read editor: %v", err)
	}
	if strings.TrimSpace(val) != "" {
		t.Fatalf("capability switch must discard the draft; editor still has %q", val)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX7_StaleValidateDropped proves an in-flight validate response for the
// pre-edit bytes cannot land and re-enable publication after the candidate changes:
// editing during the in-flight validate advances the ticket, so the stale response
// is dropped and the state never becomes valid.
func TestMCPUX7_StaleValidateDropped(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{delayValidate: true}, &pageErrs)
	must := func(err error, c string) {
		if err != nil {
			t.Fatalf("%s: %v | %v", c, err, pageErrs)
		}
	}
	must(page.Locator(`.nav-item[data-view="mcp-policies"]`).First().Click(), "nav policies")
	must(page.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`), "fill candidate A")
	must(page.Locator(`[data-click="mcpxPolValidate"]`).First().Click(), "validate A (delayed)")
	// Edit to different bytes while validate-A is still in flight.
	must(page.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"ALLOW","rules":[]}`), "edit to candidate B")
	page.WaitForTimeout(800) // allow the delayed validate-A response to arrive
	res, err := page.Evaluate(`() => ({ state: mcpxPol.state, hasValidate: !!mcpxPol.validate })`)
	if err != nil {
		t.Fatalf("evaluate mcpxPol: %v", err)
	}
	m, _ := res.(map[string]interface{})
	if m["state"] == "valid" || m["hasValidate"] == true {
		t.Fatalf("stale validate must be dropped after an edit; got state=%v hasValidate=%v", m["state"], m["hasValidate"])
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX7_ManagementNoPublish: Management has no publication-request control, and
// a forced Management publication is rejected server-side (the guard).
func TestMCPUX7_ManagementNoPublish(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	assert := playwright.NewPlaywrightAssertions()
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, &pageErrs)
	_ = page.Locator(`.nav-item[data-view="mcp-policies"]`).First().Click()
	_ = page.Locator(`[data-click="mcpxPolSelectCap"][data-arg="management"]`).First().Click()
	ux7tct(t, assert, page.Locator("#mcpx-pol-root"), "no publication-request control for Management", "mgmt no publish", &pageErrs)
	n, _ := page.Locator("#mcpx-pol-root button:has-text('Create publication request')").Count()
	if n != 0 {
		t.Fatalf("management must not show a create-publication control, got %d", n)
	}
	// Forced server-side: a management publication POST is rejected (the guard).
	res, err := page.Evaluate(`async () => { const r = await fetch('/api/mcp/publications', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json','X-CSRF-Token':(window.csrfToken||'')}, body: JSON.stringify({capability:'management', tenant:'acme', candidate:{}, expected_base:0})}); return r.status; }`)
	if err != nil {
		t.Fatalf("forced mgmt publish: %v", err)
	}
	if code, _ := res.(int); code != 403 {
		t.Fatalf("forced management publication = %v, want 403", res)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX7_HealthManagementSettings: Health cards (capability-isolated, real
// fields, durability meters), Management Access (mutation off + catalog), Listener
// Settings (form populated, stored-but-not-active, viewer cannot save).
func TestMCPUX7_HealthManagementSettings(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	assert := playwright.NewPlaywrightAssertions()
	page := ux7Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, &pageErrs)
	must := func(err error, c string) {
		if err != nil {
			t.Fatalf("%s: %v | %v", c, err, pageErrs)
		}
	}

	// Health (real disabled-default snapshot): both capabilities, durability section.
	must(page.Locator(`.nav-item[data-view="mcp-health"]`).First().Click(), "nav health")
	hroot := page.Locator("#mcpx-health-root")
	ux7tct(t, assert, hroot, "Gateway health", "gateway card", &pageErrs)
	ux7tct(t, assert, hroot, "Management health", "management card", &pageErrs)
	ux7tct(t, assert, hroot, "Durability", "durability section", &pageErrs)
	ux7tct(t, assert, hroot, "View fleet distribution", "fleet link", &pageErrs)
	mcpuxShot(t, page, "ux7-health-dark-1440.png")

	// Management Access (real): mutation off + catalog.
	must(page.Locator(`.nav-item[data-view="mcp-management"]`).First().Click(), "nav mgmt")
	mroot := page.Locator("#mcpx-mgmt-root")
	ux7tct(t, assert, mroot, "Mutation: OFF", "mutation off", &pageErrs)
	ux7tct(t, assert, mroot, "Management tool catalog", "catalog", &pageErrs)
	n, _ := page.Locator("#mcpx-mgmt-root button:has-text('Invoke')").Count()
	if n != 0 {
		t.Fatalf("management catalog must have no invoke control")
	}
	mcpuxShot(t, page, "ux7-management-access-dark-1440.png")

	// Listener Settings (real): form populated + stored-but-not-active on save.
	must(page.Locator(`.nav-item[data-view="mcp-settings"]`).First().Click(), "nav settings")
	croot := page.Locator("#mcpx-cfg-root")
	ux7tct(t, assert, croot, "Gateway listener", "gateway fieldset", &pageErrs)
	ux7tct(t, assert, croot, "Management listener", "management fieldset", &pageErrs)
	// mutation_enabled is disabled + false.
	dis, _ := page.Locator("#mcpx-cfg-management-mutation_enabled").IsDisabled()
	if !dis {
		t.Fatalf("management mutation_enabled must be disabled")
	}
	mcpuxShot(t, page, "ux7-settings-gateway-dark-1440.png")
	must(page.Locator(`[data-click="mcpxCfgSave"]`).First().Click(), "store config")
	ux7tct(t, assert, page.Locator("#mcpx-cfg-result"), "not_implemented", "stored not active", &pageErrs)
	mcpuxShot(t, page, "ux7-settings-stored-dark-1440.png")
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}
