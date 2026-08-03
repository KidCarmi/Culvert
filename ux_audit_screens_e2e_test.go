//go:build uie2e

package main

// UX-AUDIT screenshot harness (advisory, test-only — NEVER a merge gate).
//
// Production-Qualification UX reconnaissance of the MCP admin surface. This
// mounts the REAL admin-UI handler chain (newAdminUIHandler → the full
// uiIPGuard→security→auth→metadata middleware stack) in-process, mints signed
// role sessions exactly like the shipped cookie codec, drives headless Chromium
// via the existing playwright-go harness, and captures screenshots of every MCP
// view across roles / themes / resolutions / synthetic postures.
//
// SAFETY: no production code path is modified. Posture scenarios are produced by
// intercepting /api/mcp/** responses with SYNTHETIC fixtures (fixtures live in
// ux_audit_fixtures_e2e_test.go) — never real tenant data, never raw tokens or
// secrets. Permission-denied captures use the REAL viewer session so the server
// returns real 401/403s. Empty/error captures use the REAL unseeded server.
//
// Run:
//   CULVERT_PW_DRIVER_DIR=/tmp/pwdriver \
//   CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
//   PLAYWRIGHT_NODEJS_PATH=/opt/node22/bin/node \
//   go test -tags uie2e -run TestUXAudit -timeout 30m .
//
// Output: docs/design/mcp/ux-audit-assets/current/<role>-<theme>/<view>[-<scenario>].png
//         plus responsive/<width>/… and a browser-console/API-failure ledger JSON.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
)

// ── asset roots ────────────────────────────────────────────────────────────

const uxAuditRoot = "docs/design/mcp/ux-audit-assets/current"

// pageObservation is the console/error/failed-request ledger for one capture.
type pageObservation struct {
	Shot            string   `json:"shot"`
	Role            string   `json:"role"`
	Theme           string   `json:"theme"`
	Width           int      `json:"width"`
	View            string   `json:"view"`
	Scenario        string   `json:"scenario"`
	ConsoleErrors   []string `json:"console_errors,omitempty"`
	PageErrors      []string `json:"page_errors,omitempty"`
	RequestFailures []string `json:"request_failures,omitempty"`
	HTTP4xx5xx      []string `json:"http_4xx_5xx,omitempty"`
}

// ledger accumulates observations across the whole run (thread-safe).
type ledger struct {
	mu   sync.Mutex
	rows []pageObservation
}

func (l *ledger) add(o pageObservation) {
	l.mu.Lock()
	l.rows = append(l.rows, o)
	l.mu.Unlock()
}

func (l *ledger) flush(t *testing.T, path string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sort.Slice(l.rows, func(i, j int) bool { return l.rows[i].Shot < l.rows[j].Shot })
	b, _ := json.MarshalIndent(struct {
		Generated string            `json:"generated_note"`
		Count     int               `json:"observation_count"`
		Rows      []pageObservation `json:"observations"`
	}{
		Generated: "UX-audit browser console + API failure ledger (advisory).",
		Count:     len(l.rows),
		Rows:      l.rows,
	}, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write ledger: %v", err)
	}
	t.Logf("ledger written: %s (%d observations)", path, len(l.rows))
}

// ── roster seeding (admin + operator + viewer) ─────────────────────────────

const (
	uxAdminUser = "ux_admin"
	uxOpUser    = "ux_operator"
	uxViewUser  = "ux_viewer"
	uxPass      = "Ux-Audit-Pwd-1!"
)

// seedUXRoster marks the instance configured and seeds all three RBAC roles in
// an isolated temp store. Restored on cleanup.
func seedUXRoster(t *testing.T) {
	t.Helper()
	tmp := filepath.Join(t.TempDir(), "ui_users.json")
	cfg.SetUIUsersFile(tmp)
	if err := cfg.SetAuth("bootstrap-admin", "Bootstrap-admin-1!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if !cfg.IsConfigured() {
		t.Fatal("cfg.IsConfigured() false after SetAuth")
	}
	if err := cfg.SetUIUser(uxAdminUser, uxPass, RoleAdmin); err != nil {
		t.Fatalf("SetUIUser admin: %v", err)
	}
	if err := cfg.SetUIUser(uxOpUser, uxPass, RoleOperator); err != nil {
		t.Fatalf("SetUIUser operator: %v", err)
	}
	if err := cfg.SetUIUser(uxViewUser, uxPass, RoleViewer); err != nil {
		t.Fatalf("SetUIUser viewer: %v", err)
	}
	if !sessionSecretSet() {
		initSessionSecret()
	}
	t.Cleanup(func() {
		_ = cfg.DeleteUIUser(uxViewUser)
		_ = cfg.DeleteUIUser(uxOpUser)
		_ = cfg.DeleteUIUser(uxAdminUser)
		_ = cfg.SetAuth("", "")
	})
}

// ── capture matrix types ───────────────────────────────────────────────────

type roleSpec struct {
	name string
	user string
	role UIRole
}

var uxRoles = []roleSpec{
	{"admin", uxAdminUser, RoleAdmin},
	{"operator", uxOpUser, RoleOperator},
	{"viewer", uxViewUser, RoleViewer},
}

// mcpViews are the nine MCP data-views plus the two existing activity surfaces
// (dashboard, livefeed) that the audit contrasts against.
var mcpViews = []string{
	"mcp-overview", "mcp-servers", "mcp-decisions", "mcp-policies",
	"mcp-approvals", "mcp-health", "mcp-rollout", "mcp-management", "mcp-settings",
}
var activityViews = []string{"dashboard", "livefeed", "audit"}

// capture opens an authenticated, themed, sized page (optionally with an MCP API
// fixture installed), navigates to view, waits for the panel, screenshots it, and
// records the console/API ledger. It NEVER sleeps — it waits on DOM state.
func capture(t *testing.T, browser playwright.Browser, base string, r roleSpec, theme string, width, height int, view, scenario string, fixture *mcpFixture, lg *ledger) {
	t.Helper()

	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: width, Height: height},
	})
	if err != nil {
		t.Fatalf("new context: %v", err)
	}
	defer ctx.Close()

	obs := pageObservation{Role: r.name, Theme: theme, Width: width, View: view, Scenario: scenario}

	// Deterministic theme: seed localStorage before any page script runs.
	if theme == "light" {
		_ = ctx.AddInitScript(playwright.Script{Content: playwright.String(
			`try{localStorage.setItem('culvert-theme','light')}catch(e){}`)})
	} else {
		_ = ctx.AddInitScript(playwright.Script{Content: playwright.String(
			`try{localStorage.setItem('culvert-theme','dark')}catch(e){}`)})
	}
	injectChartStub(t, ctx)

	// Route: block external, install MCP fixture if present, else pass loopback.
	installRoutes(t, ctx, base, fixture, &obs)

	// Authenticated cookie (skip for the "anon/denied" scenario).
	if scenario != "anon" {
		if err := ctx.AddCookies([]playwright.OptionalCookie{{
			Name:  uiSessionCookieName,
			Value: mintUISessionValue(t, r.user, r.role),
			URL:   playwright.String(base),
		}}); err != nil {
			t.Fatalf("add cookie: %v", err)
		}
	}

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("new page: %v", err)
	}
	wireObservers(page, &obs)

	if _, err := page.Goto(base+"/", playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto: %v", err)
	}

	// Navigate to the view (nav-item may be role-hidden — tolerate + record).
	navigated := gotoView(t, page, view)
	obs.Shot = shotName(r.name, theme, width, view, scenario)

	// Several MCP panels are not auto-loaded (mcp-rollout) or need a tenant
	// filter + explicit load click (servers/decisions/approvals). Prime them so
	// the fixture (or the real empty/error state) actually renders.
	if navigated {
		primeView(page, view, scenario)
	}

	// Give the panel's async load a deterministic settle: wait for the view
	// container to be attached, then for network to go idle (all /api/* fetches
	// resolved), then a short raf tick for paint. No arbitrary sleeps.
	if navigated {
		_ = page.Locator(fmt.Sprintf("[data-view=%s]", cssIdent(view))).First().WaitFor(
			playwright.LocatorWaitForOptions{State: playwright.WaitForSelectorStateAttached, Timeout: playwright.Float(4000)})
	}
	_ = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateNetworkidle, Timeout: playwright.Float(8000)})
	settlePaint(page)

	// The SPA scrolls inside #main (height:100vh; overflow-y:auto), so a plain
	// FullPage screenshot only captures the viewport. Neutralise the inner scroll
	// so the document grows and FullPage captures the whole panel.
	_, _ = page.Evaluate(`() => {
		document.documentElement.style.overflow='visible';
		document.body.style.overflow='visible';
		const m=document.getElementById('main');
		if(m){ m.style.height='auto'; m.style.minHeight='100vh'; m.style.overflowY='visible'; }
	}`)
	settlePaint(page)

	shotPath := screenshotPath(r.name, theme, width, view, scenario)
	if err := os.MkdirAll(filepath.Dir(shotPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path: playwright.String(shotPath), FullPage: playwright.Bool(true),
	}); err != nil {
		// A failed screenshot must still leave a ledger row (task requirement:
		// capture on failure too).
		obs.PageErrors = append(obs.PageErrors, "screenshot failed: "+err.Error())
	}
	lg.add(obs)
}

// gotoView clicks the nav-item for view; returns false if it is not present
// (role-hidden) so the caller still captures the resulting UI state.
func gotoView(t *testing.T, page playwright.Page, view string) bool {
	t.Helper()
	nav := page.Locator(fmt.Sprintf(`.nav-item[data-view="%s"]`, view)).First()
	n, _ := nav.Count()
	if n == 0 {
		return false
	}
	vis, _ := nav.IsVisible()
	if !vis {
		return false
	}
	if err := nav.Click(playwright.LocatorClickOptions{Timeout: playwright.Float(4000)}); err != nil {
		return false
	}
	return true
}

// primeView fills tenant filters and clicks the panel load buttons that the SPA
// does not auto-fire, so the (fixture or real) data actually renders. Best-effort
// and silent — a missing/hidden control is simply skipped (role-gated captures).
func primeView(page playwright.Page, view, scenario string) {
	fill := func(sel, val string) {
		loc := page.Locator(sel).First()
		if n, _ := loc.Count(); n == 0 {
			return
		}
		if vis, _ := loc.IsVisible(); !vis {
			return
		}
		_ = loc.Fill(val)
	}
	click := func(sel string) {
		loc := page.Locator(sel).First()
		if n, _ := loc.Count(); n == 0 {
			return
		}
		if vis, _ := loc.IsVisible(); !vis {
			return
		}
		_ = loc.Click(playwright.LocatorClickOptions{Timeout: playwright.Float(3000)})
	}
	const tenant = "acme-prod"
	switch view {
	case "mcp-servers":
		fill("#mcp-srv-tenant", tenant)
		click(`[data-click="loadMCPServers"]`)
		click(`[data-click="loadMCPTools"]`)
	case "mcp-decisions":
		fill("#mcp-dec-tenant", tenant)
		click(`[data-click="loadMCPDecisions"]`)
		// If this scenario ships an explain fixture, drive the explain panel too.
		switch scenario {
		case "hardfail":
			fill("#mcp-dec-event", "evt_hf01")
			click(`[data-click="loadMCPExplain"]`)
		case "dlpblock":
			fill("#mcp-dec-event", "evt_dlp1")
			click(`[data-click="loadMCPExplain"]`)
		case "dlpredact":
			fill("#mcp-dec-event", "evt_rd1")
			click(`[data-click="loadMCPExplain"]`)
		}
	case "mcp-approvals":
		fill("#mcp-appr-tenant", tenant)
		click(`[data-click="loadMCPApprovals"]`)
	case "mcp-rollout":
		click(`[data-click="loadMCPRollout"]`)
		click(`[data-click="loadMCPExecutions"]`)
		click(`[data-click="loadMCPUpstreamHealth"]`)
		click(`[data-click="loadMCPRolloutEvidence"]`)
	case "mcp-health":
		click(`[data-click="loadMCPDistribution"]`)
	}
}

// settlePaint waits two animation frames so CSS transitions finish before shot.
func settlePaint(page playwright.Page) {
	_, _ = page.Evaluate(`() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))`)
}

// wireObservers records console errors, uncaught exceptions, failed requests and
// 4xx/5xx responses for the ledger.
func wireObservers(page playwright.Page, obs *pageObservation) {
	page.On("console", func(msg playwright.ConsoleMessage) {
		if msg.Type() == "error" {
			obs.ConsoleErrors = append(obs.ConsoleErrors, uxTruncate(msg.Text(), 300))
		}
	})
	page.On("pageerror", func(err error) {
		obs.PageErrors = append(obs.PageErrors, uxTruncate(err.Error(), 300))
	})
	page.On("requestfailed", func(req playwright.Request) {
		obs.RequestFailures = append(obs.RequestFailures, uxTruncate(req.URL(), 200))
	})
	page.On("response", func(resp playwright.Response) {
		if resp.Status() >= 400 {
			obs.HTTP4xx5xx = append(obs.HTTP4xx5xx,
				fmt.Sprintf("%d %s", resp.Status(), uxTruncate(resp.URL(), 200)))
		}
	})
}

// ── path + name helpers ────────────────────────────────────────────────────

func shotName(role, theme string, width int, view, scenario string) string {
	base := view
	if scenario != "" && scenario != "current" {
		base = view + "-" + scenario
	}
	return fmt.Sprintf("%s-%s/%dpx/%s.png", role, theme, width, base)
}

func screenshotPath(role, theme string, width int, view, scenario string) string {
	base := view
	if scenario != "" && scenario != "current" {
		base = view + "-" + scenario
	}
	// Primary 1920 set lives directly under <role>-<theme>/; other widths under a
	// responsive subfolder to match the task's naming example while keeping the
	// widescreen contact sheet flat.
	if width == 1920 {
		return filepath.Join(uxAuditRoot, role+"-"+theme, base+".png")
	}
	return filepath.Join(uxAuditRoot, role+"-"+theme, "responsive", fmt.Sprintf("%dpx", width), base+".png")
}

func cssIdent(s string) string { return s } // data-view names are already valid idents

func uxTruncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// waitForBrowser resolves the shared browser once; skips the whole suite if the
// environment cannot provide one (advisory tier).
var _ = time.Second
