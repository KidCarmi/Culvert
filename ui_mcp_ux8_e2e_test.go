//go:build uie2e

package main

// PR-UX-8 production validation: drives the REAL MCP navigation-state model
// (deep links + browser history), the accessibility pass, the raw-JSON removal,
// and the sensitive-state-in-URL guards against the REAL admin handler. Inventory
// lists are fixtured (ux7Cfg) to control entity rows; nothing asserts a fabricated
// state. All restoration is READ-ONLY; no test drives a mutation from a URL.

import (
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// ux8Page loads the page at a specific initial hash so the DOMContentLoaded
// deep-link apply runs against a fresh document (a hash-only change would not
// reload). Reuses the ux7 route fixtures for inventory rows.
func ux8Page(t *testing.T, browser playwright.Browser, base string, role UIRole, cfg *ux7Cfg, hash string, pageErrs *[]string) playwright.Page {
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
	if _, err := page.Goto(base+hash, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto %s: %v", hash, err)
	}
	return page
}

func ux8Must(t *testing.T, err error, ctx string, pageErrs *[]string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v | pageErrs=%v", ctx, err, *pageErrs)
	}
}

// TestMCPUX8_DeepLinks: direct routes restore the view + safe state; a selected
// entity is re-read from the real endpoint; a missing entity is truthful; and
// malformed / oversized / unknown route state fails to a safe view without throwing.
func TestMCPUX8_DeepLinks(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions()

	// (1) Direct Command Center route restores the MCP view.
	var e1 []string
	p1 := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/overview", &e1)
	if err := assert.Locator(p1.Locator(`.nav-item[data-view="mcp-overview"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("overview deep link must activate the view: %v", err)
	}

	// (5) Servers route restores tenant + opens the exact server drawer (re-read).
	var e2 []string
	p2 := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/servers?tenant=acme&drawer=server&server=srv-alpha", &e2)
	if v, _ := p2.Locator("#mcp-srv-tenant").InputValue(); v != "acme" {
		t.Fatalf("servers deep link must restore tenant, got %q", v)
	}
	if err := assert.Locator(p2.Locator("#mcpx-inv-drawer")).ToContainText("srv-alpha", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("server drawer must re-open from the route: %v | %v", err, e2)
	}

	// (5b) A tool deep link resolves by (server, name): two servers in one tenant may
	// expose the same tool name, so the route's server must disambiguate and never
	// open the wrong server's fingerprint.
	sameName := `[{"server_id":"srv-alpha","name":"shared","fingerprint":"sha256:fp-alpha-aaa","disposition":"usable","revision":1},` +
		`{"server_id":"srv-beta","name":"shared","fingerprint":"sha256:fp-beta-bbb","disposition":"usable","revision":1}]`
	var e2b []string
	p2b := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{tools: sameName}, "/#mcp/servers?tenant=acme&drawer=tool&server=srv-beta&tool=shared", &e2b)
	// The drawer shows the full server id + the truncated fingerprint (…-bbb); the
	// route resolved the srv-beta tool, never srv-alpha's same-named tool.
	if err := assert.Locator(p2b.Locator("#mcpx-inv-drawer")).ToContainText("srv-beta", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("tool deep link must open the server-scoped tool: %v | %v", err, e2b)
	}
	if txt, _ := p2b.Locator("#mcpx-inv-drawer").TextContent(); strings.Contains(txt, "srv-alpha") || strings.Contains(txt, "-aaa") {
		t.Fatalf("tool deep link must not open the other server's same-named tool: %q", txt)
	}

	// (3) A selected entity that no longer exists is truthful, and no other entity
	// is silently selected.
	var e3 []string
	p3 := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/servers?tenant=acme&drawer=server&server=srv-ghost", &e3)
	if err := assert.Locator(p3.Locator("#mcpx-inv-src")).ToContainText("no longer", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(6000)}); err != nil {
		t.Fatalf("missing server must be truthful, not silently reselected: %v | %v", err, e3)
	}
	if c, _ := p3.Locator("#mcpx-inv-drawer .mcpx-drawer-body").Count(); c != 0 {
		t.Fatalf("no drawer body should open for a missing entity; got %d", c)
	}

	// (7) Fleet route restores capability.
	var e4 []string
	p4 := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/rollout?capability=management", &e4)
	if v, _ := p4.Locator("#mcpx-rf-cap").InputValue(); v != "management" {
		t.Fatalf("rollout deep link must restore capability, got %q", v)
	}

	// (14) Malformed / (15) oversized / (16) unknown-key route state fails safe:
	// no page exception; unknown slug leaves the default view; unknown key + oversized
	// value are dropped while the valid part still restores.
	over := "/#mcp/servers?tenant=acme&server=" + strings.Repeat("x", 400) + "&evilkey=1"
	var e5 []string
	p5 := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, over, &e5)
	if v, _ := p5.Locator("#mcp-srv-tenant").InputValue(); v != "acme" {
		t.Fatalf("oversized/unknown keys must drop but keep the valid tenant, got %q", v)
	}
	if c, _ := p5.Locator("#mcpx-inv-drawer .mcpx-drawer-body").Count(); c != 0 {
		t.Fatalf("oversized entity id must be dropped, not opened; got %d drawer bodies", c)
	}
	var e6 []string
	p6 := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/not-a-real-view?x=1", &e6)
	if err := assert.Locator(p6.Locator(`.nav-item[data-view="dashboard"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("unknown slug must fall back to the default view without throwing: %v", err)
	}

	for i, e := range [][]string{e1, e2, e2b, e3, e4, e5, e6} {
		if len(e) != 0 {
			t.Fatalf("page %d threw exceptions: %v", i+1, e)
		}
	}
}

// TestMCPUX8_History: browser Back/Forward restore MCP context READ-ONLY; Back
// never replays a POST; reload never recreates a policy candidate draft.
func TestMCPUX8_History(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions()

	var pageErrs []string
	var posts int64
	p := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/servers?tenant=acme", &pageErrs)
	p.On("request", func(req playwright.Request) {
		if req.Method() == "POST" && strings.Contains(req.URL(), "/api/mcp/") {
			atomic.AddInt64(&posts, 1)
		}
	})
	// Intra-MCP navigation pushes a history entry.
	ux8Must(t, p.Locator(`.nav-item[data-view="mcp-approvals"]`).First().Click(), "nav approvals", &pageErrs)
	if err := assert.Locator(p.Locator(`.nav-item[data-view="mcp-approvals"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("approvals nav must activate: %v", err)
	}
	// (9) Back restores the originating servers context (tenant preserved).
	if _, err := p.GoBack(); err != nil {
		t.Fatalf("GoBack: %v", err)
	}
	if err := assert.Locator(p.Locator(`.nav-item[data-view="mcp-servers"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("Back must restore the servers view: %v", err)
	}
	if v, _ := p.Locator("#mcp-srv-tenant").InputValue(); v != "acme" {
		t.Fatalf("Back must restore the servers tenant, got %q", v)
	}
	// (10) Forward restores the approvals view.
	if _, err := p.GoForward(); err != nil {
		t.Fatalf("GoForward: %v", err)
	}
	if err := assert.Locator(p.Locator(`.nav-item[data-view="mcp-approvals"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("Forward must restore the approvals view: %v", err)
	}
	// (11) No POST was replayed by history navigation.
	if n := atomic.LoadInt64(&posts); n != 0 {
		t.Fatalf("history navigation must not replay any MCP POST; got %d", n)
	}

	// Leaving MCP for a non-MCP view drops the stale #mcp/ fragment, so a reload
	// shows the non-MCP view instead of resurrecting the MCP route.
	ux8Must(t, p.Locator(`.nav-item[data-view="dashboard"]`).First().Click(), "nav dashboard", &pageErrs)
	if err := assert.Locator(p.Locator(`.nav-item[data-view="dashboard"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("dashboard nav must activate: %v", err)
	}
	if h := p.URL(); strings.Contains(h, "#mcp/") {
		t.Fatalf("leaving MCP must drop the #mcp/ fragment; url still %q", h)
	}

	// (13) Reload never restores a policy candidate draft (candidate bytes are never
	// serialized to URL/history/storage).
	ux8Must(t, p.Locator(`.nav-item[data-view="mcp-policies"]`).First().Click(), "nav policies", &pageErrs)
	ux8Must(t, p.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`), "type candidate", &pageErrs)
	// A real document reload (not a same-URL goto) must not resurrect the draft.
	if _, err := p.Reload(playwright.PageReloadOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if v, _ := p.Locator("#mcpx-pol-src").InputValue(); strings.TrimSpace(v) != "" {
		t.Fatalf("reload must not recreate a candidate draft; got %q", v)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX8_Accessibility: the consolidated live region is present and not
// display:none; the corpus fields are labelled; the capability tablist is
// arrow-key operable.
func TestMCPUX8_Accessibility(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions()

	var pageErrs []string
	p := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/policy", &pageErrs)

	// (33) Live regions are not display:none. The shared MCP live region exists and
	// is a status region rendered off-screen (not display:none, which mutes AT).
	disp, err := p.Locator("#mcpx-live").Evaluate("el => getComputedStyle(el).display", nil)
	if err != nil {
		t.Fatalf("read #mcpx-live display: %v", err)
	}
	if d, _ := disp.(string); d == "none" {
		t.Fatalf("shared live region must not be display:none")
	}

	// (35) Every corpus field has a programmatic label (for/id association).
	ux8Must(t, p.Locator(`[data-click="mcpxPolAddCase"]`).First().Click(), "add corpus case", &pageErrs)
	unlabeled, err := p.Locator("#view-mcp-policies .mcpx-pol-case-f").EvaluateAll(
		`els => els.filter(el => { const f=el.querySelector('input,select'); const l=el.querySelector('label'); return !(f && l && l.getAttribute('for') && f.id && l.getAttribute('for')===f.id); }).length`)
	if err != nil {
		t.Fatalf("evaluate corpus labels: %v", err)
	}
	if n, _ := unlabeled.(float64); n != 0 {
		t.Fatalf("all corpus fields must associate label/for with input/id; %v unlabeled", unlabeled)
	}

	// (28) Capability tablist is arrow-key operable (activation follows focus).
	tab := p.Locator(`#view-mcp-policies .mcpx-rf-captab[data-arg="gateway"]`).First()
	ux8Must(t, tab.Focus(), "focus gateway tab", &pageErrs)
	ux8Must(t, p.Keyboard().Press("ArrowRight"), "arrow right", &pageErrs)
	if err := assert.Locator(p.Locator(`#view-mcp-policies .mcpx-rf-captab[data-arg="management"]`)).ToHaveAttribute("aria-selected", "true", playwright.LocatorAssertionsToHaveAttributeOptions{Timeout: playwright.Float(4000)}); err != nil {
		t.Fatalf("ArrowRight must move+activate to the management tab: %v", err)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX8_LegacyRemovedAndSecurity: no MCP view renders a whole-response raw
// JSON dump; no sensitive state reaches the URL; a viewer deep link stays read-only.
func TestMCPUX8_LegacyRemovedAndSecurity(t *testing.T) {
	mcpuxSeed(t)
	// A viewer identity for the RBAC deep-link check.
	if err := cfg.SetUIUser("ux_viewer", "Ux-Viewer-Pwd-1!", RoleViewer); err != nil {
		t.Fatalf("SetUIUser viewer: %v", err)
	}
	t.Cleanup(func() { _ = cfg.DeleteUIUser("ux_viewer") })
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions()

	// (50/51) No obsolete raw-output container survives in any MCP view.
	var pageErrs []string
	p := ux8Page(t, browser, srv.URL, RoleAdmin, &ux7Cfg{}, "/#mcp/overview", &pageErrs)
	for _, sel := range []string{".mcpx-legacy", "#mcp-overview-out", "#mcp-rollout-out", "#mcp-cfg-json", "#mcp-pol-candidate", "#mcp-approvals-list"} {
		if c, _ := p.Locator(sel).Count(); c != 0 {
			t.Fatalf("legacy raw surface %q must be removed; found %d", sel, c)
		}
	}

	// (64) Navigating the policy workflow and typing a candidate never puts the
	// candidate source (or any raw policy) into the URL or storage.
	ux8Must(t, p.Locator(`.nav-item[data-view="mcp-policies"]`).First().Click(), "nav policies", &pageErrs)
	ux8Must(t, p.Locator("#mcpx-pol-src").Fill(`{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`), "type candidate", &pageErrs)
	url := p.URL()
	if strings.Contains(url, "default_action") || strings.Contains(url, "policy_revision") || strings.Contains(url, "schema_version") {
		t.Fatalf("candidate source must never enter the URL: %q", url)
	}
	stor, err := p.Evaluate(`() => JSON.stringify({l:Object.entries(localStorage), s:Object.entries(sessionStorage)})`)
	if err != nil {
		t.Fatalf("read storage: %v", err)
	}
	if s, _ := stor.(string); strings.Contains(s, "default_action") || strings.Contains(s, "policy_revision") {
		t.Fatalf("candidate source must never enter storage: %s", s)
	}

	// (18) A viewer deep link to an admin context restores the view read-only: the
	// admin-only rollout actions card is not rendered for a viewer, so a URL cannot
	// widen access.
	var vErrs []string
	pv := ux8Page(t, browser, srv.URL, RoleViewer, &ux7Cfg{}, "/#mcp/rollout?capability=gateway", &vErrs)
	if err := assert.Locator(pv.Locator(`.nav-item[data-view="mcp-rollout"].active`)).ToBeVisible(); err != nil {
		t.Fatalf("viewer deep link must still restore the view: %v", err)
	}
	if c, _ := pv.Locator(`[data-click="mcpxOpenEmergencyDisable"]`).Count(); c != 0 {
		t.Fatalf("viewer must not see the admin-only emergency control via a deep link; found %d", c)
	}
	if len(pageErrs) != 0 || len(vErrs) != 0 {
		t.Fatalf("page exceptions: admin=%v viewer=%v", pageErrs, vErrs)
	}
}
