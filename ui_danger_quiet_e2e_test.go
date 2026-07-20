//go:build uie2e

package main

// Browser E2E for the quiet destructive-button hierarchy (advisory tier).
//
// Drives a real Chromium against the in-process admin UI and asserts the
// COMPUTED styling of a repeated row-level Remove button (Blocklist host row):
//
//   - dark-theme idle is NOT solid red (transparent fill, red border);
//   - dark-theme hover fills solid destructive red;
//   - light-theme idle is NOT solid red; light-theme hover fills solid red;
//   - keyboard focus (:focus-visible) is visibly ringed;
//   - the button does not change size between idle and hover (no layout shift);
//   - clicking still opens the existing confirmation flow, and cancelling issues
//     no DELETE request.
//
// Hermetic and env-gated exactly like the rest of the uie2e suite: SKIPS when no
// browser is available.

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/playwright-community/playwright-go"
)

// computedStyle returns getComputedStyle(sel)[prop] for the first match.
func computedStyle(t *testing.T, page playwright.Page, sel, prop string) string {
	t.Helper()
	v, err := page.Evaluate(
		`([sel, prop]) => { const el = document.querySelector(sel); if(!el) return ""; return getComputedStyle(el).getPropertyValue(prop); }`,
		[]string{sel, prop},
	)
	if err != nil {
		t.Fatalf("computedStyle(%q,%q): %v", sel, prop, err)
	}
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// hoverAndReadBg hovers btn and returns its background-color once the 150ms
// hover transition has settled. It re-hovers and polls (the pointer can drift
// off if layout nudges, and a mid-transition read would report an interpolated
// color), returning the first solid-red reading or the last value seen.
func hoverAndReadBg(t *testing.T, page playwright.Page, btn playwright.Locator, sel string) string {
	t.Helper()
	var last string
	for i := 0; i < 10; i++ {
		if err := btn.Hover(); err != nil {
			t.Fatalf("hover: %v", err)
		}
		page.WaitForTimeout(200) // > the 150ms background transition
		last = computedStyle(t, page, sel, "background-color")
		if isSolidRed(last) {
			return last
		}
	}
	return last
}

// setTheme forces dark (attribute removed) or light (data-theme="light").
func setTheme(t *testing.T, page playwright.Page, light bool) {
	t.Helper()
	_, err := page.Evaluate(`(light) => { if (light) document.documentElement.setAttribute('data-theme','light'); else document.documentElement.removeAttribute('data-theme'); }`, light)
	if err != nil {
		t.Fatalf("setTheme(light=%v): %v", light, err)
	}
}

// setThemeSettled switches theme and waits past the 150ms token transition so a
// following computed-style read reflects the new theme, not a mid-interpolation.
func setThemeSettled(t *testing.T, page playwright.Page, light bool) {
	t.Helper()
	setTheme(t, page, light)
	page.WaitForTimeout(200)
}

// moveAway parks the pointer at the top-left corner (off the row button) and
// waits past the hover transition, so a following idle read sees no :hover.
func moveAway(t *testing.T, page playwright.Page) {
	t.Helper()
	if err := page.Mouse().Move(2, 2); err != nil {
		t.Fatalf("mouse move away: %v", err)
	}
	page.WaitForTimeout(200)
}

func TestUIE2E_DangerQuietRowButton(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-dq", "viewer-dq", "Dq-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, viewerUser, pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	ctx, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// Record DELETE requests so we can prove Cancel issues none.
	var mu sync.Mutex
	var deletes []string
	page.OnRequest(func(req playwright.Request) {
		if req.Method() == "DELETE" {
			mu.Lock()
			deletes = append(deletes, req.URL())
			mu.Unlock()
		}
	})

	// Open Blocklist and add a host so a real row (with the Remove button) renders.
	if err := page.Locator(`.nav-item[data-view="blocklist"]`).First().Click(); err != nil {
		t.Fatalf("open blocklist panel: %v", err)
	}
	if err := assert.Locator(page.Locator("#new-host")).ToBeVisible(); err != nil {
		t.Fatalf("blocklist add field should be visible: %v", err)
	}
	if err := page.Locator("#new-host").Fill("danger-quiet-fixture.example"); err != nil {
		t.Fatalf("fill host: %v", err)
	}
	if err := page.Locator(`[data-click="addHost"]`).First().Click(); err != nil {
		t.Fatalf("click add host: %v", err)
	}

	btn := page.Locator(`#bl-table .btn.danger-quiet`).First()
	if err := assert.Locator(btn).ToBeVisible(); err != nil {
		t.Fatalf("row Remove button should render: %v", err)
	}
	const sel = `#bl-table .btn.danger-quiet`

	// Freeze the SPA's 3s polling tick: it re-renders #bl-table, replacing the
	// hovered <button> node with a fresh one that is NOT under the pointer, so a
	// tick landing between Hover() and the style read would report the idle
	// (transparent) background. Clearing all timers keeps the node stable for the
	// duration of the style assertions.
	if _, err := page.Evaluate(`() => { for (let i = 1; i < 100000; i++) window.clearInterval(i); }`); err != nil {
		t.Fatalf("freeze polling timers: %v", err)
	}

	// ── Idle colors FIRST, before any hover ────────────────────────────────
	// Measure both themes' idle backgrounds while the button has never been
	// hovered, so a residual :hover can never contaminate the "quiet at rest"
	// assertion. moveAway keeps the pointer off the button; setThemeSettled lets
	// the 150ms transition finish before the read.
	moveAway(t, page)

	setThemeSettled(t, page, false)
	if bg := computedStyle(t, page, sel, "background-color"); !isTransparent(bg) {
		t.Errorf("dark idle background = %q; want transparent (quiet, not a wall of red)", bg)
	}
	if border := computedStyle(t, page, sel, "border-top-color"); !isRedish(border) {
		t.Errorf("dark idle border-color = %q; want a destructive red", border)
	}

	setThemeSettled(t, page, true)
	if bg := computedStyle(t, page, sel, "background-color"); !isTransparent(bg) {
		t.Errorf("light idle background = %q; want transparent (not solid red)", bg)
	}

	// ── Hover fills solid destructive red, in both themes ───────────────────
	setThemeSettled(t, page, false)
	boxIdle, err := btn.BoundingBox()
	if err != nil {
		t.Fatalf("bounding box (idle): %v", err)
	}
	if bg := hoverAndReadBg(t, page, btn, sel); !isSolidRed(bg) {
		t.Errorf("dark hover background = %q; want a solid destructive red fill", bg)
	}
	boxHover, err := btn.BoundingBox()
	if err != nil {
		t.Fatalf("bounding box (hover): %v", err)
	}
	if boxIdle.Width != boxHover.Width || boxIdle.Height != boxHover.Height {
		t.Errorf("button changed size on hover: idle %gx%g vs hover %gx%g (layout shift / density regression)",
			boxIdle.Width, boxIdle.Height, boxHover.Width, boxHover.Height)
	}
	moveAway(t, page)

	setThemeSettled(t, page, true)
	if bg := hoverAndReadBg(t, page, btn, sel); !isSolidRed(bg) {
		t.Errorf("light hover background = %q; want a solid destructive red fill", bg)
	}
	moveAway(t, page)

	// ── Keyboard focus (:focus-visible) must be visibly ringed ──────────────
	fv, err := page.Evaluate(`(sel) => { const el = document.querySelector(sel); el.focus({focusVisible:true}); return { visible: el.matches(':focus-visible'), shadow: getComputedStyle(el).boxShadow }; }`, sel)
	if err != nil {
		t.Fatalf("focus eval: %v", err)
	}
	fvMap, _ := fv.(map[string]interface{})
	if shadow, _ := fvMap["shadow"].(string); shadow == "" || shadow == "none" {
		t.Errorf("focus-visible box-shadow = %q; want a visible focus ring", shadow)
	}

	// ── Confirmation flow: click opens the dialog; Cancel issues no DELETE ───
	if err := btn.Click(); err != nil {
		t.Fatalf("click Remove: %v", err)
	}
	if err := assert.Locator(page.Locator("#confirm-dialog")).ToBeVisible(); err != nil {
		t.Fatalf("confirmation dialog should open on row Remove: %v", err)
	}
	if err := page.Locator("#confirm-dialog-cancel").Click(); err != nil {
		t.Fatalf("click Cancel: %v", err)
	}
	if err := assert.Locator(page.Locator("#confirm-dialog")).ToBeHidden(); err != nil {
		t.Fatalf("confirmation dialog should close on Cancel: %v", err)
	}
	mu.Lock()
	nDeletes := len(deletes)
	mu.Unlock()
	if nDeletes != 0 {
		t.Errorf("Cancel issued %d DELETE request(s); want 0: %v", nDeletes, deletes)
	}

	_ = ctx
}

// Color helpers — computed background-color comes back as rgb()/rgba().

func isTransparent(c string) bool {
	c = strings.ReplaceAll(c, " ", "")
	return c == "rgba(0,0,0,0)" || c == "transparent"
}

// isSolidRed matches the two --crit fills: dark rgb(239,68,68), light rgb(220,38,38).
func isSolidRed(c string) bool {
	c = strings.ReplaceAll(c, " ", "")
	return strings.HasPrefix(c, "rgb(239,68,68") || strings.HasPrefix(c, "rgb(220,38,38")
}

// isRedish accepts either --crit value with any alpha (border color).
func isRedish(c string) bool {
	c = strings.ReplaceAll(c, " ", "")
	return strings.Contains(c, "239,68,68") || strings.Contains(c, "220,38,38")
}
