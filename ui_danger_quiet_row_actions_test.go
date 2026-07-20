package main

// Regression wall for the quiet destructive-row-action button tier
// (docs/design/UX-PRINCIPLES.md §3 danger tiers; docs/design/DESIGN-SYSTEM.md §1).
//
// The redesign split repeated row-level destructive actions (Remove/Delete in
// table & list rows) OFF the solid `.btn.danger` tier and onto a lower-visual
// `.btn.danger-quiet` tier, so a many-row screen (Blocklist) no longer renders a
// wall of solid-red buttons. Solid `.btn.danger` MUST remain the tier for
// high-blast-radius actions: the confirmation dialog's final button, bulk
// delete, and clear-all. These tests pin the semantic distinction so a later
// change cannot silently collapse the two tiers back together (in either
// direction) or re-introduce a native handler on the migrated controls.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// buttonClassFor returns the class attribute of the button element that carries
// the given `data-click="handler"`, by scanning backwards from the handler to
// the nearest preceding `class="..."`. This is robust to class-token ordering
// (`btn danger-quiet sm` vs `btn sm danger-quiet`) and to attribute layout.
func buttonClassFor(t *testing.T, s, handler string) string {
	t.Helper()
	needle := `data-click="` + handler + `"`
	idx := strings.Index(s, needle)
	if idx < 0 {
		t.Fatalf("row-action handler %q not found in static/index.html", handler)
	}
	// The class attribute lives just before the handler in the same element;
	// other attributes (id/style/title) may sit between them, so take the LAST
	// btn class= before the handler.
	window := s[max0(idx-260):idx]
	all := regexp.MustCompile(`class="([^"]*\bbtn\b[^"]*)"`).FindAllStringSubmatch(window, -1)
	if len(all) == 0 {
		t.Fatalf("no btn class= attribute precedes data-click=%q", handler)
	}
	return all[len(all)-1][1]
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func classHasToken(class, token string) bool {
	for _, f := range strings.Fields(class) {
		if f == token {
			return true
		}
	}
	return false
}

// ── 1. The quiet variant exists and is a distinct, correctly-behaving tier ──

func TestDangerQuiet_VariantExistsAndUsesTokens(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)

	// The idle rule exists with a transparent fill + thin --crit border + text.
	if !strings.Contains(s, ".btn.danger-quiet {") {
		t.Fatal("`.btn.danger-quiet` idle rule is missing — the quiet destructive tier is not defined")
	}
	idle := cssBlock(t, s, ".btn.danger-quiet {")
	for _, want := range []string{"background: transparent", "border: 1px solid var(--crit)", "color: var(--text)"} {
		if !strings.Contains(idle, want) {
			t.Errorf("`.btn.danger-quiet` idle rule missing %q — got:\n%s", want, idle)
		}
	}
	// Idle must NOT be a solid crit fill (that would defeat the whole purpose).
	if strings.Contains(idle, "background: var(--crit)") {
		t.Error("`.btn.danger-quiet` idle fills with var(--crit) — it must be transparent at rest")
	}

	// Hover fills with --crit (becomes clearly destructive).
	hover := cssBlock(t, s, ".btn.danger-quiet:hover {")
	if !strings.Contains(hover, "background: var(--crit)") {
		t.Errorf("`.btn.danger-quiet:hover` must fill with var(--crit) — got: %s", hover)
	}

	// Keyboard focus is visible via the --crit-tint ring and does NOT depend on
	// hover alone.
	focus := cssBlock(t, s, ".btn.danger-quiet:focus-visible {")
	if !strings.Contains(focus, "var(--crit-tint)") {
		t.Errorf("`.btn.danger-quiet:focus-visible` must use the var(--crit-tint) focus ring — got: %s", focus)
	}

	// The active (pressed) state stays filled + restrained; no transform/margin
	// that would shift layout.
	active := cssBlock(t, s, ".btn.danger-quiet:active {")
	if !strings.Contains(active, "background: var(--crit)") {
		t.Errorf("`.btn.danger-quiet:active` must stay filled with var(--crit) — got: %s", active)
	}
	if strings.Contains(active, "transform") || strings.Contains(active, "translate") || strings.Contains(active, "margin") {
		t.Errorf("`.btn.danger-quiet:active` must not move/shift the button — got: %s", active)
	}

	// No raw hex/rgba leaked into the variant's rules (design-system §1: raw
	// values live only in the token block; `white` is a named color, allowed).
	for _, block := range []string{idle, hover, focus, active} {
		if m := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|rgba?\(`).FindString(block); m != "" {
			t.Errorf("`.btn.danger-quiet` rule contains a raw color %q outside the token block:\n%s", m, block)
		}
	}
}

// ── 1b. The 1px border is compensated by padding (no size regression) ───────

func TestDangerQuiet_BorderCompensatedByPadding(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	// Base .btn has border:none; these auto-width inline-flex buttons have no
	// explicit width/height, so box-sizing:border-box does NOT absorb the added
	// 1px border. The quiet variant must trim exactly 1px per edge so its OUTER
	// box is identical to the border-less solid button it replaces — otherwise
	// every row action grows 2px and table density regresses. Base .btn padding
	// is 8px 16px → 7px 15px; .btn.sm is 5px 10px → 4px 9px. (Verified in-browser:
	// solid .sm and quiet .sm both measure 66.69×24.)
	idle := cssBlock(t, s, ".btn.danger-quiet {")
	if !strings.Contains(idle, "padding: 7px 15px") {
		t.Errorf("`.btn.danger-quiet` must trim base padding to 7px 15px to offset its 1px border; got:\n%s", idle)
	}
	if !strings.Contains(s, ".btn.danger-quiet.sm { padding: 4px 9px; }") {
		t.Error("`.btn.danger-quiet.sm` must trim .sm padding to 4px 9px to offset its 1px border (row-density guard)")
	}
}

// ── 2. Solid `.btn.danger` is NOT weakened or replaced ──────────────────────

func TestDangerQuiet_SolidDangerIntact(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, ".btn.danger  { background: var(--crit); }") {
		t.Error("solid `.btn.danger` no longer fills with var(--crit) — the high-prominence tier was weakened")
	}
}

// ── 3. Repeated row-level destructive actions use the quiet variant ─────────

func TestDangerQuiet_RowActionsAreQuiet(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)

	// Handler → why it is a repeated row-level destructive action.
	rowLevel := map[string]string{
		"removeHost":           "Blocklist host row removal",
		"removeException":      "Blocklist exception row removal",
		"secRemoveIP":          "Security IP-filter row removal",
		"removeSSLBypass":      "SSL-bypass row removal",
		"removeRewriteRule":    "Rewrite-rule row removal",
		"deleteWebhook":        "Webhook row deletion",
		"deleteIdP":            "Identity Provider row deletion",
		"apDeleteRule":         "Authentication Policy rule deletion",
		"removeUpstreamProxy":  "Upstream-proxy row removal",
		"deleteURLCategory":    "URL-category card deletion",
		"cdrDeletePolicy":      "CDR policy row deletion",
		"cdrRevokeInstanceRPC": "CDR instance revoke row action",
	}
	for handler, why := range rowLevel {
		class := buttonClassFor(t, s, handler)
		if !classHasToken(class, "danger-quiet") {
			t.Errorf("%s (data-click=%q) must use the quiet destructive tier; class=%q", why, handler, class)
		}
		if classHasToken(class, "danger") {
			t.Errorf("%s (data-click=%q) still carries the solid `danger` token; class=%q", why, handler, class)
		}
		// The presentation change must not have touched the CSP-safe delegation
		// contract — every migrated control keeps data-click (no inline handler).
		if !strings.Contains(class, "btn") {
			t.Errorf("%s lost its .btn class; class=%q", why, class)
		}
	}
}

// ── 4. High-blast-radius / confirmation actions STAY solid danger ───────────

func TestDangerQuiet_HighProminenceStaysSolid(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)

	// The confirmation dialog's final destructive button.
	if !strings.Contains(s, `<button class="btn danger" id="confirm-dialog-ok"`) {
		t.Error("confirmation dialog OK button is no longer solid `.btn.danger` — the final destructive action must stay high-prominence")
	}
	// Its default JS-set style (confirmAction) is solid danger, not quiet.
	if !strings.Contains(s, `'btn ' + (opts.okStyle || 'danger')`) {
		t.Error("confirmAction default okStyle is no longer solid 'danger'")
	}

	// Bulk delete stays visually stronger than a single row removal.
	blk := buttonClassFor(t, s, "bulkDeleteBL")
	if !classHasToken(blk, "danger") || classHasToken(blk, "danger-quiet") {
		t.Errorf("Blocklist bulk delete must stay solid `.btn.danger`; class=%q", blk)
	}

	// Clear-all operations stay solid.
	for _, handler := range []string{"clearAllExts", "clearDecExclusions"} {
		class := buttonClassFor(t, s, handler)
		if !classHasToken(class, "danger") || classHasToken(class, "danger-quiet") {
			t.Errorf("clear-all action %q must stay solid `.btn.danger`; class=%q", handler, class)
		}
	}
}

// ── 5. No native handlers/dialogs introduced on the migrated controls ───────

func TestDangerQuiet_NoNativeHandlersIntroduced(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	// Any inline on*= on a danger-quiet button would be dead UI (CSP-blocked)
	// and a delegation-contract regression.
	if m := regexp.MustCompile(`danger-quiet[^>]*\bon[a-z]+="`).FindString(s); m != "" {
		t.Errorf("a `.btn.danger-quiet` control carries an inline event handler (CSP-blocked): %q", m)
	}
	// The webhook abbreviation was normalised from "Del" to "Delete" during the
	// migration; the terse label must not creep back in.
	if strings.Contains(s, `data-click="deleteWebhook" data-arg="${h.id}">Del</button>`) {
		t.Error("webhook delete reverted to the abbreviated `Del` label")
	}
}

// cssBlock returns the text from the start marker up to and including the next
// `}` — i.e. the single CSS rule body that begins at marker.
func cssBlock(t *testing.T, s, marker string) string {
	t.Helper()
	start := strings.Index(s, marker)
	if start < 0 {
		t.Fatalf("CSS rule %q not found in static/index.html", marker)
	}
	end := strings.Index(s[start:], "}")
	if end < 0 {
		t.Fatalf("CSS rule %q has no closing brace", marker)
	}
	return s[start : start+end+1]
}
