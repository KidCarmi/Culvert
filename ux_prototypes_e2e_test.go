//go:build uie2e

package main

// Renders the MCP TARGET PROTOTYPES (static HTML mockups) to PNGs at 1440×900.
// These are DESIGN PROTOTYPES — they never touch production static/index.html,
// never call a real API, and use synthetic fixture data only. Advisory tier
// (SKIP without a browser); NEVER a merge gate.
//
// Run:
//   CULVERT_PW_DRIVER_DIR=/tmp/pwdriver \
//   CULVERT_PW_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
//   PLAYWRIGHT_NODEJS_PATH=/opt/node22/bin/node \
//   go test -tags uie2e -run TestUXPrototypes -timeout 15m .

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/playwright-community/playwright-go"
)

const protoRoot = "docs/design/mcp/ux-audit-assets/target-prototypes"

type protoSpec struct {
	file  string // html filename under protoRoot
	query string // query string (state/modal/dialog)
	theme string // dark|light
	out   string // output png name
	dir   string // output subdir under protoRoot (default "renders")
}

func renderProto(t *testing.T, browser playwright.Browser, s protoSpec) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join(protoRoot, s.file))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Logf("SKIP %s (not present yet)", s.file)
		return
	}
	ctx, err := browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 1440, Height: 900},
	})
	if err != nil {
		t.Fatalf("context: %v", err)
	}
	defer ctx.Close()
	theme := s.theme
	if theme == "" {
		theme = "dark"
	}
	_ = ctx.AddInitScript(playwright.Script{Content: playwright.String(
		fmt.Sprintf(`try{document.documentElement.setAttribute('data-theme','%s')}catch(e){}`, theme))})

	page, err := ctx.NewPage()
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	url := "file://" + abs
	if s.query != "" {
		url += "?" + s.query
	}
	if _, err := page.Goto(url, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad}); err != nil {
		t.Fatalf("goto %s: %v", url, err)
	}
	// Wait for the prototype to signal it finished rendering.
	if _, err := page.WaitForSelector(`body[data-ready="1"]`, playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(5000),
	}); err != nil {
		t.Logf("warn: %s never set data-ready (%v)", s.file, err)
	}
	// Apply the theme AFTER navigation (an init-script attribute set on the
	// pre-navigation document does not survive into the loaded file:// document).
	if theme == "light" {
		_, _ = page.Evaluate(`() => document.documentElement.setAttribute('data-theme','light')`)
	} else {
		_, _ = page.Evaluate(`() => document.documentElement.removeAttribute('data-theme')`)
	}
	_, _ = page.Evaluate(`() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))`)

	dir := s.dir
	if dir == "" {
		dir = "renders"
	}
	outPath := filepath.Join(protoRoot, dir, s.out)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{
		Path: playwright.String(outPath), FullPage: playwright.Bool(true),
	}); err != nil {
		t.Fatalf("shot: %v", err)
	}
	t.Logf("rendered %s", s.out)
}

func protoSpecs() []protoSpec {
	return []protoSpec{
		// 1. Command Center — six states (dark) + one light.
		{"command-center.html", "state=healthy", "dark", "command-center-healthy.png", ""},
		{"command-center.html", "state=needs-attention", "dark", "command-center-needs-attention.png", ""},
		{"command-center.html", "state=killswitch", "dark", "command-center-killswitch.png", ""},
		{"command-center.html", "state=durability", "dark", "command-center-durability.png", ""},
		{"command-center.html", "state=dpincompat", "dark", "command-center-dpincompat.png", ""},
		{"command-center.html", "state=prodlocked", "dark", "command-center-prodlocked.png", ""},
		{"command-center.html", "state=needs-attention", "light", "command-center-needs-attention-light.png", ""},
		// 2. Activity / execution — table + drawers (dark) + one light.
		{"activity.html", "state=table", "dark", "activity-table.png", ""},
		{"activity.html", "state=shadow", "dark", "activity-shadow-drawer.png", ""},
		{"activity.html", "state=hardfail", "dark", "activity-hardfail-drawer.png", ""},
		{"activity.html", "state=dlp", "dark", "activity-dlp-drawer.png", ""},
		{"activity.html", "state=shadow", "light", "activity-shadow-drawer-light.png", ""},
		// 3. Rollout & Exposure — main + blast-radius modal.
		{"rollout.html", "state=main", "dark", "rollout-main.png", ""},
		{"rollout.html", "state=main&modal=blast", "dark", "rollout-blast-radius.png", ""},
		// 4. Production Qualification.
		{"qualification.html", "", "dark", "qualification-locked.png", ""},
		// 5. Emergency response — hierarchy + typed-confirm dialog.
		{"emergency.html", "state=hierarchy", "dark", "emergency-hierarchy.png", ""},
		{"emergency.html", "state=hierarchy&dialog=stop", "dark", "emergency-typed-confirm.png", ""},
		// Health & Distribution (used by the comparison sheet).
		{"health.html", "", "dark", "health-distribution.png", ""},
		// Current-vs-proposed comparison sheets (rendered AFTER the prototypes
		// above exist, since they embed those PNGs).
		{"compare-overview.html", "", "dark", "compare-overview.png", "comparisons"},
		{"compare-decisions.html", "", "dark", "compare-decisions.png", "comparisons"},
		{"compare-rollout.html", "", "dark", "compare-rollout.png", "comparisons"},
		{"compare-health.html", "", "dark", "compare-health.png", "comparisons"},
		{"compare-qualification.html", "", "dark", "compare-qualification.png", "comparisons"},
	}
}

func TestUXPrototypes(t *testing.T) {
	browser := uiE2EBrowser(t)
	for _, s := range protoSpecs() {
		renderProto(t, browser, s)
	}
}
