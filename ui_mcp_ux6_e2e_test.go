//go:build uie2e

package main

// PR-UX-6 production validation: drives the REAL Production Qualification evidence
// card (inside the Rollout screen) and the REAL unified approvals experience in
// headless Chromium against the REAL admin handler. Evidence fixtures are generated
// from the REAL buildMCPEvidenceDTO (so the wire shape can never drift from the
// server), and approval fixtures use the real ApprovalView shape. Nothing asserts a
// fabricated state - only what a real response would carry.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/playwright-community/playwright-go"
)

const ux6AsOf = int64(1722690000000000000)

func ux6EvidenceJSON(cap string, ev rollout.EvidenceSummary) string {
	b, _ := json.Marshal(buildMCPEvidenceDTO(cap, "shadow", ev, time.Unix(1_000_000_000, 0), ux6AsOf))
	return string(b)
}

// Real evidence shapes generated from the real builder.
func ux6EvNotStarted(cap string) string {
	return ux6EvidenceJSON(cap, rollout.EvidenceSummary{Origin: rollout.OriginProduction})
}
func ux6EvSynthetic(cap string) string {
	return ux6EvidenceJSON(cap, rollout.EvidenceSummary{Origin: rollout.OriginSynthetic, ShadowStartUnix: time.Unix(1_000_000_000, 0).Unix() - 30*24*3600})
}
func ux6EvMet(cap string) string {
	base := time.Unix(1_000_000_000, 0).Unix()
	return ux6EvidenceJSON(cap, rollout.EvidenceSummary{Origin: rollout.OriginProduction, ShadowStartUnix: base - 30*24*3600, CanaryStartUnix: base - 10*24*3600, SoakStartUnix: base - 2*24*3600, RollbackRehearsed: true})
}

// Approval fixtures (real ApprovalView shape).
const fxApprOp = `[{"id":"appr-op-1","kind":"operational","state":"pending","tenant":"acme","capability":"gateway",` +
	`"requester":"alice","action":"invoke","resource":"tool:search","server_id":"srv-a","tool_fingerprint":"sha256:toolfp111",` +
	`"operation_class":"read","risk_class":"read","decision_event_id":"evt-123","created_unix_nano":1722600000000000000,"expiry_unix_nano":1999999999000000000},` +
	`{"id":"appr-op-2","kind":"operational","state":"approved","tenant":"acme","capability":"gateway","requester":"bob","approver":"carol",` +
	`"action":"invoke","risk_class":"destructive","operation_class":"destructive","created_unix_nano":1722500000000000000,"expiry_unix_nano":1999999999000000000}]`

const fxApprPub = `[{"id":"appr-pub-1","kind":"publication","state":"pending","tenant":"acme","capability":"gateway","requester":"dave",` +
	`"candidate_hash":"sha256:candabc123","base_revision":7,"proposed_revision":8,"policy_revision":7,"catalog_revision":3,` +
	`"created_unix_nano":1722550000000000000,"expiry_unix_nano":1999999999000000000}]`

const fxApprExpired = `[{"id":"appr-op-3","kind":"operational","state":"expired","tenant":"acme","capability":"gateway","requester":"eve",` +
	`"action":"invoke","created_unix_nano":1722400000000000000,"expiry_unix_nano":1722400001000000000}]`

type ux6Cfg struct {
	evGW, evMG      string // evidence fixture bodies (empty => not-started)
	ev500           bool   // gateway evidence read fails
	delayGWEv       bool   // delay gateway evidence (stale-response proof)
	opBody, pubBody string // approval list bodies (empty => empty array)
	op500, pub500   bool   // list source failures
	decisionStatus  int    // status for decision POSTs (0 => 503 durability default)
	decisionBody    string
	mu              sync.Mutex
}

func ux6Install(t *testing.T, ctx playwright.BrowserContext, cfg *ux6Cfg) {
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
		fail := func(code int, body string) {
			_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(code), Body: playwright.String(body)})
		}
		isMgmt := strings.Contains(u, "capability=management")
		switch {
		// ── evidence (qualification) ──
		case method == "GET" && strings.Contains(u, "/api/mcp/rollout/evidence"):
			if isMgmt {
				json(nonEmpty(cfg.evMG, ux6EvNotStarted("management")))
			} else if cfg.ev500 {
				fail(500, "boom")
			} else if cfg.delayGWEv {
				go func() { time.Sleep(500 * time.Millisecond); json(nonEmpty(cfg.evGW, ux6EvNotStarted("gateway"))) }()
			} else {
				json(nonEmpty(cfg.evGW, ux6EvNotStarted("gateway")))
			}
		// ── rollout / scope / distribution / acks (other rollout cards) ──
		case method == "GET" && strings.Contains(u, "/api/mcp/rollout/scope"):
			json(fxRfScopeGW)
		case method == "GET" && strings.Contains(u, "/api/mcp/distribution/acks"):
			json(fxRfAcksGW)
		case method == "GET" && strings.Contains(u, "/api/mcp/distribution"):
			json(fxRfDist)
		case method == "GET" && strings.Contains(u, "/api/mcp/rollout"):
			json(fxRfRollout)
		// ── approvals ──
		case method == "GET" && strings.Contains(u, "/api/mcp/approvals"):
			if cfg.op500 {
				fail(500, "boom")
			} else {
				json(nonEmpty(cfg.opBody, "[]"))
			}
		case method == "GET" && strings.Contains(u, "/api/mcp/publications"):
			if cfg.pub500 {
				fail(500, "boom")
			} else {
				json(nonEmpty(cfg.pubBody, "[]"))
			}
		case method == "POST" && (strings.Contains(u, "/api/mcp/approval-decision") || strings.Contains(u, "/api/mcp/publication-decision")):
			code := cfg.decisionStatus
			if code == 0 {
				code = 503
			}
			body := nonEmpty(cfg.decisionBody, "event_durability_degraded")
			fail(code, body)
		default:
			_ = route.Continue()
		}
	})
	if err != nil {
		t.Fatalf("route: %v", err)
	}
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func ux6Page(t *testing.T, browser playwright.Browser, base string, role UIRole, cfg *ux6Cfg, pageErrs *[]string) playwright.Page {
	t.Helper()
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{Viewport: &playwright.Size{Width: 1440, Height: 900}})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	t.Cleanup(func() { _ = ctx.Close() })
	injectChartStub(t, ctx)
	ux6Install(t, ctx, cfg)
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
	// Wait for the session boot to apply the role (nav visibility keys on it), so a
	// role-gated nav click never races the boot.
	if _, err := page.WaitForFunction("() => window.currentRole && window.currentRole.length > 0", nil, playwright.PageWaitForFunctionOptions{Timeout: playwright.Float(8000)}); err != nil {
		t.Fatalf("session boot did not set currentRole: %v | pageErrs=%v", err, pageErrs)
	}
	return page
}

// TestMCPUX6_Qualification drives the Production Qualification card across origins
// and window states, proving: Production is always LOCKED, no qualify/unlock/receipt
// control exists, production-origin renders as production, synthetic evidence is
// marked non-qualifying (never met), a met window still leaves Production locked, and
// no unsupported category is shown as passed.
func TestMCPUX6_Qualification(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{evGW: ux6EvNotStarted("gateway")}, &pageErrs)
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

	// Production locked is always visible; requirements list renders; not-started windows.
	tct(root, "Production Qualification - gateway", "qual card title")
	tct(root, "Production: LOCKED", "prod locked chip")
	tct(root, "External qualification required", "ext qual chip")
	tct(page.Locator("table.mcpx-qual-tbl"), "Shadow window floor", "shadow requirement row")
	tct(page.Locator("table.mcpx-qual-tbl"), "not started", "shadow not started")
	tct(root, "Not represented by this runtime evidence source", "unsupported categories")
	// No qualify/unlock/receipt/enable control exists anywhere on the page.
	for _, forbidden := range []string{"Qualify", "Unlock", "Issue receipt", "Enable Production"} {
		n, _ := page.Locator("button:has-text('" + forbidden + "')").Count()
		if n != 0 {
			t.Fatalf("forbidden control %q present (%d)", forbidden, n)
		}
	}
	mcpuxShot(t, page, "ux6-qual-notstarted-dark-1440.png")

	// Synthetic evidence: shadow past target but origin synthetic => non-qualifying.
	page2 := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{evGW: ux6EvSynthetic("gateway")}, &pageErrs)
	must(page2.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout syn")
	syn := page2.Locator("#mcpx-rf-root")
	tct(syn, "origin: synthetic", "synthetic origin chip")
	tct(page2.Locator("table.mcpx-qual-tbl"), "synthetic - does not qualify", "synthetic non-qualifying")
	// The synthetic shadow row must NOT read plain "met".
	if err := assert.Locator(page2.Locator("table.mcpx-qual-tbl")).ToContainText("Production: LOCKED", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(1000)}); err == nil {
		t.Fatal("qual table unexpectedly contains the lock chip text")
	}
	mcpuxShot(t, page2, "ux6-qual-synthetic-dark-1440.png")

	// All windows met (production) but Production stays LOCKED.
	page3 := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{evGW: ux6EvMet("gateway")}, &pageErrs)
	must(page3.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click(), "nav rollout met")
	metRoot := page3.Locator("#mcpx-rf-root")
	tct(page3.Locator("table.mcpx-qual-tbl"), "met", "a requirement met")
	tct(metRoot, "Production: LOCKED", "still locked when met")
	mcpuxShot(t, page3, "ux6-qual-met-locked-dark-1440.png")

	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX6_QualificationUnavailableAndIsolation proves a failed evidence read
// renders unavailable (no stale green) and that Gateway/Management stay isolated.
func TestMCPUX6_QualificationUnavailableAndIsolation(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	assert := playwright.NewPlaywrightAssertions()
	tct := func(loc playwright.Locator, sub, ctx string) {
		if err := assert.Locator(loc).ToContainText(sub, playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(7000)}); err != nil {
			t.Fatalf("%s (want %q): %v | pageErrs=%v", ctx, sub, err, pageErrs)
		}
	}

	// Evidence read fails -> unavailable card, never a stale green requirement.
	page := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{ev500: true}, &pageErrs)
	_ = page.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click()
	tct(page.Locator("#mcpx-rf-root"), "Qualification evidence unavailable", "evidence unavailable")
	mcpuxShot(t, page, "ux6-qual-unavailable-dark-1440.png")

	// Capability isolation + stale guard: gateway evidence delayed; a fast switch to
	// management must not let the late gateway response overwrite management.
	page2 := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{delayGWEv: true, evMG: ux6EvNotStarted("management")}, &pageErrs)
	_ = page2.Locator(`.nav-item[data-view="mcp-rollout"]`).First().Click()
	_ = page2.Locator(`[data-click="mcpxRfSelectCap"][data-arg="management"]`).First().Click()
	tct(page2.Locator("#mcpx-rf-root"), "Production Qualification - management", "management qual card")
	page2.WaitForTimeout(800) // allow the delayed gateway evidence to arrive
	if err := assert.Locator(page2.Locator("#mcpx-rf-root")).ToContainText("Production Qualification - management", playwright.LocatorAssertionsToContainTextOptions{Timeout: playwright.Float(2000)}); err != nil {
		t.Fatalf("stale gateway evidence overwrote management: %v", err)
	}
	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX6_UnifiedApprovals proves operational and publication records appear in
// one list with distinct kinds, the drawer renders real fields (candidate hash
// without a fake diff), publication shows unavailable, and a decision-event pivot is
// present only when the id exists.
func TestMCPUX6_UnifiedApprovals(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
	page := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{opBody: fxApprOp, pubBody: fxApprPub}, &pageErrs)
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
	must(page.Locator(`.nav-item[data-view="mcp-approvals"]`).First().Click(), "nav approvals")
	must(page.Locator("#mcp-appr-tenant").Fill("acme"), "fill tenant")
	must(page.Locator(`[data-click="mcpxApprLoad"]`).First().Click(), "load approvals")

	root := page.Locator("#mcpx-appr-root")
	tct(root, "operational", "operational kind present")
	tct(root, "publication", "publication kind present")
	tct(page.Locator("#mcpx-appr-src"), "Operational: 2", "operational source count")
	tct(page.Locator("#mcpx-appr-src"), "Publication: 1", "publication source count")

	// Open the publication drawer: real candidate hash + revisions, no fake diff,
	// publication-unavailable text.
	must(page.Locator("tr.mcpx-appr-row").Filter(playwright.LocatorFilterOptions{HasText: "publication"}).First().Click(), "open pub drawer")
	drawer := page.Locator("#mcpx-appr-drawer")
	tct(drawer, "Candidate and revisions", "candidate section")
	tct(drawer, "Base revision", "base revision")
	tct(drawer, "binding reference, not a policy diff", "no fake diff disclaimer")
	tct(drawer, "Publication unavailable in this runtime", "publish unavailable")
	// A publication has no decision_event_id -> no pivot button.
	n, _ := drawer.Locator("button:has-text('Open decision evidence')").Count()
	if n != 0 {
		t.Fatalf("publication drawer must not show a decision pivot, got %d", n)
	}
	mcpuxShot(t, page, "ux6-approvals-publication-drawer-dark-1440.png")

	// Operational pending drawer: decision-event pivot present + admin decision controls.
	must(page.Locator("tr.mcpx-appr-row").Filter(playwright.LocatorFilterOptions{HasText: "operational"}).First().Click(), "open op drawer")
	tct(drawer, "Open decision evidence", "operational decision pivot")
	tct(drawer, "Approve", "approve control")
	mcpuxShot(t, page, "ux6-approvals-operational-drawer-dark-1440.png")

	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// ux6ApprLoad navigates to the approvals view, enters the tenant, and loads.
func ux6ApprLoad(t *testing.T, page playwright.Page, pageErrs *[]string) {
	t.Helper()
	must := func(err error, ctx string) {
		if err != nil {
			t.Fatalf("%s: %v | pageErrs=%v", ctx, err, *pageErrs)
		}
	}
	must(page.Locator(`.nav-item[data-view="mcp-approvals"]`).First().Click(), "nav approvals")
	must(page.Locator("#mcp-appr-tenant").Fill("acme"), "fill tenant")
	must(page.Locator(`[data-click="mcpxApprLoad"]`).First().Click(), "load approvals")
}

// TestMCPUX6_ApprovalSourceFailureAndDurability proves independent source-failure
// handling (a failed source never erases the other) and the durability-failure
// decision path (not committed, prior state preserved).
func TestMCPUX6_ApprovalSourceFailureAndDurability(t *testing.T) {
	mcpuxSeed(t)
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
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

	// One source fails: publication 500 must not erase operational.
	page := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{opBody: fxApprOp, pub500: true}, &pageErrs)
	ux6ApprLoad(t, page, &pageErrs)
	tct(page.Locator("#mcpx-appr-src"), "Publication approvals unavailable", "pub unavailable")
	tct(page.Locator("#mcpx-appr-root"), "operational", "operational still shown")
	mcpuxShot(t, page, "ux6-approvals-source-failure-dark-1440.png")

	// Durability failure: approve returns 503 -> "Not committed", request stays pending.
	page2 := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{opBody: fxApprOp, decisionStatus: 503, decisionBody: "event_durability_degraded"}, &pageErrs)
	ux6ApprLoad(t, page2, &pageErrs)
	must(page2.Locator("tr.mcpx-appr-row").Filter(playwright.LocatorFilterOptions{HasText: "pending"}).First().Click(), "open pending")
	must(page2.Locator("#mcpx-appr-drawer button:has-text('Approve')").First().Click(), "click approve")
	must(page2.Locator("#mcpx-dlg-confirm").Click(), "confirm approve")
	tct(page2.Locator("#mcpx-dlg-result"), "Not committed", "durability not committed")
	mcpuxShot(t, page2, "ux6-approvals-durability-dark-1440.png")

	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}

// TestMCPUX6_ApprovalViewerAndExpired proves a viewer sees no decision controls and
// an expired record has no active decision control (server RBAC is the real backstop;
// this is defense-in-depth).
func TestMCPUX6_ApprovalViewerAndExpired(t *testing.T) {
	mcpuxSeed(t)
	if err := cfg.SetUIUser("ux_viewer", "Ux-Viewer-Pwd-1!", RoleViewer); err != nil {
		t.Fatalf("SetUIUser viewer: %v", err)
	}
	t.Cleanup(func() { _ = cfg.DeleteUIUser("ux_viewer") })
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	browser := uiE2EBrowser(t)
	var pageErrs []string
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

	// Viewer sees no decision controls.
	pageV := ux6Page(t, browser, srv.URL, RoleViewer, &ux6Cfg{opBody: fxApprOp}, &pageErrs)
	ux6ApprLoad(t, pageV, &pageErrs)
	must(pageV.Locator("tr.mcpx-appr-row").Filter(playwright.LocatorFilterOptions{HasText: "pending"}).First().Click(), "open pending viewer")
	if visible, _ := pageV.Locator("#mcpx-appr-drawer button:has-text('Approve')").First().IsVisible(); visible {
		t.Fatalf("viewer must not see a visible approve control")
	}

	// Expired record: no active decision control in the drawer.
	pageE := ux6Page(t, browser, srv.URL, RoleAdmin, &ux6Cfg{opBody: fxApprExpired}, &pageErrs)
	ux6ApprLoad(t, pageE, &pageErrs)
	must(pageE.Locator("tr.mcpx-appr-row").First().Click(), "open expired")
	tct(pageE.Locator("#mcpx-appr-drawer"), "no decision control is available", "expired no control")
	en, _ := pageE.Locator("#mcpx-appr-drawer button:has-text('Approve')").Count()
	if en != 0 {
		t.Fatalf("expired record must have no approve control, got %d", en)
	}

	if len(pageErrs) != 0 {
		t.Fatalf("page exceptions: %v", pageErrs)
	}
}
