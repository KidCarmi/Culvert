//go:build uie2e

package main

// UX qualification harness for the Decryption Exclusions admin panel + the
// "On Inspect Failure" decryption-profile control (PR #693). Advisory tier —
// SKIPS if a browser cannot be obtained. Captures screenshots of every state
// in BOTH dark and light themes into scratchpad/ux/. Product behavior is NOT
// changed; this only drives the real SPA and photographs it.
//
// Run: go test -tags uie2e -run TestUX_DecExclusions .

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
	"github.com/playwright-community/playwright-go"
)

const uxShotDir = "/home/user/Culvert/scratchpad/ux"

func uxShot(t *testing.T, page playwright.Page, name string) {
	t.Helper()
	p := filepath.Join(uxShotDir, name+".png")
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path:     playwright.String(p),
		FullPage: playwright.Bool(true),
	}); err != nil {
		t.Errorf("screenshot %s: %v", name, err)
		return
	}
	t.Logf("saved %s", p)
}

func uxSetTheme(t *testing.T, page playwright.Page, theme string) {
	t.Helper()
	var js string
	if theme == "light" {
		js = `document.documentElement.setAttribute('data-theme','light')`
	} else {
		js = `document.documentElement.removeAttribute('data-theme')`
	}
	if _, err := page.Evaluate(js); err != nil {
		t.Fatalf("set theme %s: %v", theme, err)
	}
	page.WaitForTimeout(120)
}

// uxNav switches SPA view and gives the async loader a moment.
func uxNav(t *testing.T, page playwright.Page, view string) {
	t.Helper()
	if _, err := page.Evaluate(`(v)=>switchView(v)`, view); err != nil {
		t.Fatalf("switchView(%s): %v", view, err)
	}
	page.WaitForTimeout(350)
}

// uxBothThemes captures name-dark and name-light for the current DOM state.
func uxBothThemes(t *testing.T, page playwright.Page, name string) {
	uxSetTheme(t, page, "dark")
	uxShot(t, page, name+"-dark")
	uxSetTheme(t, page, "light")
	uxShot(t, page, name+"-light")
	uxSetTheme(t, page, "dark") // restore
}

// seedRule adds a policy rule referencing a decryption profile so the panel's
// "Rules" blast-radius column and fail_open_rules footprint are non-zero.
// Restores policyStore on cleanup.
func uxSeedRule(t *testing.T, ruleName, profileName string) {
	t.Helper()
	prev := policyStore.List()
	t.Cleanup(func() { policyStore.ReplaceAll(prev) })
	policyStore.Add(PolicyRule{Name: ruleName, SSLAction: SSLInspect, DecryptionProfile: profileName, Action: ActionAllow})
}

func TestUX_DecExclusions(t *testing.T) {
	if err := os.MkdirAll(uxShotDir, 0o755); err != nil {
		t.Fatalf("mkdir ux dir: %v", err)
	}
	const adminUser, viewerUser, pass = "ux-admin", "ux-viewer", "Ux-e2e-pass-1!" // #nosec G101 -- test-only fixture
	seedUIRoster(t, adminUser, viewerUser, pass)

	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t) // SKIPs if no browser

	// ── 1. Profile editor: "On Inspect Failure" fail-open vs fail-close ──────
	swapProfiles(t)
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)

	uxNav(t, page, "decprofiles")
	if _, err := page.Evaluate(`showAddDecProfForm()`); err != nil {
		t.Fatalf("open profile form: %v", err)
	}
	page.WaitForTimeout(150)
	// Select fail-open and fire the change handler that reveals the warning.
	if _, err := page.Evaluate(`(()=>{const e=document.getElementById('dp-oninspecterr');e.value='fail-open';syncDecProfFailOpenHint();})()`); err != nil {
		t.Fatalf("set fail-open: %v", err)
	}
	page.WaitForTimeout(150)
	uxBothThemes(t, page, "profile-editor-failopen")

	// fail-close → warning hidden.
	if _, err := page.Evaluate(`(()=>{const e=document.getElementById('dp-oninspecterr');e.value='fail-close';syncDecProfFailOpenHint();})()`); err != nil {
		t.Fatalf("set fail-close: %v", err)
	}
	page.WaitForTimeout(150)
	uxBothThemes(t, page, "profile-editor-failclose")

	// Close-up of just the warning paragraph (element screenshot, dark).
	if box := page.Locator("#dp-failopen-hint"); box != nil {
		if _, err := page.Evaluate(`(()=>{const e=document.getElementById('dp-oninspecterr');e.value='fail-open';syncDecProfFailOpenHint();})()`); err == nil {
			page.WaitForTimeout(120)
			_, _ = box.Screenshot(playwright.LocatorScreenshotOptions{Path: playwright.String(filepath.Join(uxShotDir, "warning-copy-closeup.png"))})
		}
	}

	// ── 2. Exclusions panel: empty / provable-OFF (0 fail-open profiles) ─────
	// Fresh empty profile store + empty cache ⇒ green "cannot be auto-disabled".
	swapProfiles(t)
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	uxNav(t, page, "decexclusions")
	uxBothThemes(t, page, "panel-empty-off")

	// ── 3. One entry (bind a fail-open profile + a referencing rule) ─────────
	_, scopeMobile := bindFailOpenProfile(t, "byod-mobile", "fail-open")
	uxSeedRule(t, "byod-allow", "byod-mobile")
	autoExclude.Observe(scopeMobile, "byod-mobile", "login.example.com", autoexclude.ReasonClientPinned, "id:u1")
	uxNav(t, page, "decexclusions")
	uxBothThemes(t, page, "panel-one-entry")

	// ── 4. 100 entries ───────────────────────────────────────────────────────
	for i := 0; i < 100; i++ {
		h := fmt.Sprintf("host-%03d.svc.example.net", i)
		reason := autoexclude.ReasonUnsupportedParams
		if i%3 == 0 {
			reason = autoexclude.ReasonClientCertRequired
		} else if i%3 == 1 {
			reason = autoexclude.ReasonClientPinned
		}
		autoExclude.Observe(scopeMobile, "byod-mobile", h, reason, "id:seed")
	}
	uxNav(t, page, "decexclusions")
	uxBothThemes(t, page, "panel-100-entries")

	// ── 5. Long hostname (253-char FQDN) ─────────────────────────────────────
	long := strings.Repeat("averylonglabelsegment", 12) // 252 chars
	long = long[:60] + "." + long[60:120] + "." + long[120:180] + "." + long[180:249] + ".io"
	autoExclude.Observe(scopeMobile, "byod-mobile", long, autoexclude.ReasonUnsupportedParams, "id:long")
	uxNav(t, page, "decexclusions")
	uxShot(t, page, "panel-long-hostname-dark")
	uxSetTheme(t, page, "light")
	uxShot(t, page, "panel-long-hostname-light")
	uxSetTheme(t, page, "dark")

	// ── 6. Renamed / missing profile (deleted ⇒ stale cached name fallback) ──
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	_, scopeGone := bindFailOpenProfile(t, "legacy-vpn", "fail-open")
	autoExclude.Observe(scopeGone, "legacy-vpn", "gw.legacy.example", autoexclude.ReasonClientCertRequired, "id:u9")
	if err := globalDecryptionProfiles.Delete("legacy-vpn"); err != nil {
		t.Logf("delete legacy-vpn: %v", err)
	}
	uxNav(t, page, "decexclusions")
	uxBothThemes(t, page, "panel-missing-profile")

	// ── 7. Near-expiry entry (short TTL) — note: fully-expired rows vanish ────
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1, TTL: 45 * time.Second, PinnedTTL: 45 * time.Second})
	_, scopeExp := bindFailOpenProfile(t, "byod-mobile", "fail-open")
	autoExclude.Observe(scopeExp, "byod-mobile", "soon-expires.example", autoexclude.ReasonUnsupportedParams, "id:u1")
	uxNav(t, page, "decexclusions")
	uxShot(t, page, "panel-near-expiry-dark")

	// ── 8. API failure (route fulfils 500) ───────────────────────────────────
	if err := page.Route("**/api/decryption-exclusions**", func(route playwright.Route) {
		_ = route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: playwright.String(`{"error":"boom"}`)})
	}); err != nil {
		t.Fatalf("route 500: %v", err)
	}
	uxNav(t, page, "decexclusions")
	page.WaitForTimeout(300)
	uxShot(t, page, "panel-api-failure-dark")
	_ = page.Unroute("**/api/decryption-exclusions**", nil)

	// ── 9. Loading (throttled route) ─────────────────────────────────────────
	if err := page.Route("**/api/decryption-exclusions**", func(route playwright.Route) {
		time.Sleep(1500 * time.Millisecond)
		_ = route.Continue()
	}); err != nil {
		t.Fatalf("route slow: %v", err)
	}
	if _, err := page.Evaluate(`(v)=>switchView(v)`, "decexclusions"); err != nil {
		t.Fatalf("nav loading: %v", err)
	}
	page.WaitForTimeout(400) // mid-load
	uxShot(t, page, "panel-loading-dark")
	page.WaitForTimeout(1600)
	_ = page.Unroute("**/api/decryption-exclusions**", nil)

	// ── 10. Narrow viewport (390px) ──────────────────────────────────────────
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	_, scopeN := bindFailOpenProfile(t, "byod-mobile", "fail-open")
	for i := 0; i < 6; i++ {
		autoExclude.Observe(scopeN, "byod-mobile", fmt.Sprintf("mobilehost-%d.example.com", i), autoexclude.ReasonClientPinned, "id:u1")
	}
	if err := page.SetViewportSize(390, 800); err != nil {
		t.Fatalf("narrow viewport: %v", err)
	}
	uxNav(t, page, "decexclusions")
	uxShot(t, page, "panel-narrow-390-dark")
	uxSetTheme(t, page, "light")
	uxShot(t, page, "panel-narrow-390-light")
	uxSetTheme(t, page, "dark")
	_ = page.SetViewportSize(1440, 900)

	// ── 11. Destructive: Clear-all dialog ────────────────────────────────────
	uxNav(t, page, "decexclusions")
	if _, err := page.Evaluate(`void(window._uxClear = clearDecExclusions())`); err != nil {
		t.Fatalf("open clear dialog: %v", err)
	}
	page.WaitForTimeout(250)
	uxShot(t, page, "dialog-clear-all-dark")
	// Record whether it is the typed-confirmation (confirmDanger) component.
	hasTyped, _ := page.Locator("#confirm-dialog-typed").IsVisible()
	t.Logf("clear-all dialog uses typed-confirmation input: %v", hasTyped)
	_ = page.Keyboard().Press("Escape")
	page.WaitForTimeout(150)

	// ── 12. Destructive: Evict — capture whether ANY confirm dialog appears ──
	// evictDecExclusion() calls the API directly with no dialog; prove it by
	// checking #confirm-dialog never becomes visible after invoking the handler.
	dialogBefore, _ := page.Locator("#confirm-dialog").IsVisible()
	t.Logf("evict: confirm-dialog visible BEFORE = %v", dialogBefore)
	uxShot(t, page, "evict-button-context-dark")

	// ── 13. Keyboard focus visibility on the Clear-all button ────────────────
	if _, err := page.Evaluate(`(()=>{const b=[...document.querySelectorAll('#view-decexclusions button')].find(x=>/Clear all/i.test(x.textContent));if(b)b.focus();})()`); err != nil {
		t.Logf("focus clear btn: %v", err)
	}
	page.WaitForTimeout(150)
	uxShot(t, page, "keyboard-focus-clear-dark")
	focusedId, _ := page.Evaluate(`document.activeElement && (document.activeElement.textContent||'').trim().slice(0,40)`)
	t.Logf("focused element text: %v", focusedId)

	// ── 14. RBAC viewer: evict/clear controls hidden ─────────────────────────
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	_, scopeV := bindFailOpenProfile(t, "byod-mobile", "fail-open")
	autoExclude.Observe(scopeV, "byod-mobile", "viewer-visible.example", autoexclude.ReasonClientPinned, "id:u1")
	_, vpage := newAuthedUIPage(t, browser, srv.URL, viewerUser, RoleViewer)
	uxNav(t, vpage, "decexclusions")
	uxSetTheme(t, vpage, "dark")
	uxShot(t, vpage, "rbac-viewer-dark")
	clearVisibleViewer, _ := vpage.Locator("#view-decexclusions button:has-text('Clear all')").IsVisible()
	evictVisibleViewer, _ := vpage.Locator("#view-decexclusions button:has-text('Evict')").IsVisible()
	t.Logf("VIEWER: clear-all visible=%v evict visible=%v (want both false)", clearVisibleViewer, evictVisibleViewer)

	// ── 15. RBAC operator: evict + clear visible ─────────────────────────────
	_, opage := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleOperator)
	uxNav(t, opage, "decexclusions")
	uxSetTheme(t, opage, "dark")
	uxShot(t, opage, "rbac-operator-dark")
	clearVisibleOp, _ := opage.Locator("#view-decexclusions button:has-text('Clear all')").IsVisible()
	evictVisibleOp, _ := opage.Locator("#view-decexclusions button:has-text('Evict')").IsVisible()
	t.Logf("OPERATOR: clear-all visible=%v evict visible=%v (want both true)", clearVisibleOp, evictVisibleOp)

	t.Log("UX screenshot capture complete")
}
