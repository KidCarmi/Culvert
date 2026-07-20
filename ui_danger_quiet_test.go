package main

// Semantic wall for the quiet destructive-button hierarchy.
//
// Repeated row-level destructive actions (Remove/Delete inside table or list
// rows) use the low-prominence `.btn.danger-quiet` variant so a table's right
// edge does not become a wall of solid red. Solid `.btn.danger` stays reserved
// for high-prominence destructive actions: the confirmation-dialog final
// button, bulk delete, clear-all, and other high-blast-radius controls.
//
// These tests pin the DISTINCTION (which action tier uses which variant) and
// the token-only, CSS-pseudo-class implementation, so a later edit cannot
// silently collapse the two tiers back into one. See
// docs/design/UX-PRINCIPLES.md §3 and docs/design/DESIGN-SYSTEM.md.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// classForDataClick returns the class attribute of the FIRST <button> (or
// element) whose data-click equals handler, or "" if not found.
func classForDataClick(t *testing.T, html, handler string) string {
	t.Helper()
	// Match an element tag containing data-click="handler" and capture its class.
	// The class attribute may appear before or after data-click on the tag, so
	// isolate the single tag first, then pull class out of it.
	tagRe := regexp.MustCompile(`<[a-zA-Z]+[^>]*\bdata-click="` + regexp.QuoteMeta(handler) + `"[^>]*>`)
	tag := tagRe.FindString(html)
	if tag == "" {
		return ""
	}
	clsRe := regexp.MustCompile(`\bclass="([^"]*)"`)
	m := clsRe.FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return m[1]
}

// classForID returns the class attribute of the first element carrying id, or
// "" if the element (or its class attribute) is absent.
func classForID(t *testing.T, html, id string) string {
	t.Helper()
	tag := regexp.MustCompile(`<[a-zA-Z]+[^>]*\bid="` + regexp.QuoteMeta(id) + `"[^>]*>`).FindString(html)
	if tag == "" {
		return ""
	}
	m := regexp.MustCompile(`\bclass="([^"]*)"`).FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return m[1]
}

// assertSolidDanger fails unless cls is the SOLID .btn.danger tier (has danger,
// not danger-quiet). label names the control for the failure message.
func assertSolidDanger(t *testing.T, label, cls string) {
	t.Helper()
	if cls == "" {
		t.Errorf("%s: not found (or missing class)", label)
		return
	}
	if hasClass(cls, "danger-quiet") {
		t.Errorf("%s must stay SOLID danger, not quiet: %q", label, cls)
	}
	if !hasClass(cls, "danger") {
		t.Errorf("%s must carry .danger: %q", label, cls)
	}
}

func hasClass(classAttr, want string) bool {
	for _, c := range strings.Fields(classAttr) {
		if c == want {
			return true
		}
	}
	return false
}

func loadIndexHTML(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	return string(data)
}

//  1. The quiet destructive variant exists, is token-only, and defines its
//     hover/focus/active state via CSS pseudo-classes (no JS-driven hover).
func TestDangerQuiet_VariantDefinedWithTokensOnly(t *testing.T) {
	s := loadIndexHTML(t)

	for _, sel := range []string{
		`.btn.danger-quiet {`,
		`.btn.danger-quiet:hover`,
		`.btn.danger-quiet:focus-visible`,
		`.btn.danger-quiet:active`,
	} {
		if !strings.Contains(s, sel) {
			t.Errorf("static/index.html missing CSS rule %q — quiet destructive tier not defined", sel)
		}
	}

	// Semantic foreground token for a filled --crit surface, defined in BOTH
	// themes (raw color stays in the token layer, never in the component).
	if n := strings.Count(s, `--on-crit: #ffffff;`); n != 2 {
		t.Errorf("--on-crit token defined %d times; want 2 (dark + light theme blocks)", n)
	}

	// Isolate the variant's CSS block and assert it references only tokens,
	// never a raw hex/rgb literal (design-system rule: no raw color outside the
	// token block).
	start := strings.Index(s, ".btn.danger-quiet {")
	if start < 0 {
		t.Fatal(".btn.danger-quiet rule not found")
	}
	// The block ends at the next selector that is NOT a .btn.danger-quiet state.
	end := strings.Index(s[start:], ".btn.ghost")
	if end < 0 {
		t.Fatal("could not bound the danger-quiet CSS block")
	}
	block := s[start : start+end]
	if regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`).FindString(block) != "" {
		t.Errorf("danger-quiet CSS block contains a raw hex color; use tokens only:\n%s", block)
	}
	if regexp.MustCompile(`\brgba?\(`).FindString(block) != "" {
		t.Errorf("danger-quiet CSS block contains a raw rgb()/rgba() literal; use tokens only:\n%s", block)
	}
	// The border must be present (thin destructive outline) and the hover state
	// must fill with --crit — the destructive intent on interaction.
	if !strings.Contains(block, "border: 1px solid var(--crit)") {
		t.Error("danger-quiet idle state must carry a 1px solid var(--crit) border")
	}
	if !strings.Contains(block, "background: var(--crit)") {
		t.Error("danger-quiet hover/active must fill with var(--crit)")
	}
}

// 2+3. Repeated row-level destructive actions — including the two required
//
//	Blocklist ones — use the quiet variant.
func TestDangerQuiet_RowLevelActionsUseQuietVariant(t *testing.T) {
	s := loadIndexHTML(t)

	rowLevel := []string{
		"removeHost",          // Blocklist host rows (required)
		"removeException",     // Blocklist exception rows (required)
		"secRemoveIP",         // Security IP filter rows
		"removeSSLBypass",     // SSL bypass rows
		"removeRewriteRule",   // Header-rewrite rows
		"deleteWebhook",       // Alert webhook rows
		"deleteIdP",           // Identity provider rows
		"apDeleteRule",        // Authentication policy rule rows
		"removeUpstreamProxy", // Upstream proxy rows
		"deleteURLCategory",   // URL category rows
		"cdrDeletePolicy",     // CDR policy rows
	}
	for _, h := range rowLevel {
		cls := classForDataClick(t, s, h)
		if cls == "" {
			t.Errorf("no element found for data-click=%q", h)
			continue
		}
		if !hasClass(cls, "danger-quiet") {
			t.Errorf("row-level destructive action %q has class %q; want the quiet variant (danger-quiet)", h, cls)
		}
		// The quiet variant is a .btn modifier — the base class must remain.
		if !hasClass(cls, "btn") {
			t.Errorf("row-level destructive action %q lost the base .btn class: %q", h, cls)
		}
	}
}

// 4. The confirmation dialog's final destructive button stays SOLID .btn.danger.
func TestDangerQuiet_ConfirmDialogStaysSolidDanger(t *testing.T) {
	assertSolidDanger(t, "confirmation-dialog final button", classForID(t, loadIndexHTML(t), "confirm-dialog-ok"))
}

//  5. Bulk delete remains visually stronger (solid) than a single row-level
//     removal (quiet) — the two tiers must not collapse.
func TestDangerQuiet_HighProminenceActionsStaySolid(t *testing.T) {
	s := loadIndexHTML(t)

	// Bulk delete is a static-markup button with a stable id.
	assertSolidDanger(t, "bulk delete (bl-bulk-del)", classForID(t, s, "bl-bulk-del"))

	// Clear-all, CA rotation, and the high-blast CDR revoke stay solid.
	for _, h := range []string{
		"clearAllExts",         // clear all file extensions
		"clearDecExclusions",   // clear all decryption exclusions
		"forceRotateCA",        // CA rotation (high blast radius)
		"cdrRevokeInstanceRPC", // server-side cert revoke (high blast radius)
	} {
		assertSolidDanger(t, "high-prominence action "+h, classForDataClick(t, s, h))
	}
}

//  6. The change introduced no native event handler or dialog and no JS-driven
//     hover: the migrated buttons keep data-click delegation, and the quiet
//     hover/focus behavior is pure CSS. (Broad bans live in
//     ui_redesign_foundation_test.go; this narrows the guarantee to the migrated
//     controls.)
func TestDangerQuiet_NoNativeHandlersOnMigratedButtons(t *testing.T) {
	s := loadIndexHTML(t)

	// No inline on*="" handler may appear on any danger-quiet button. Grab each
	// danger-quiet tag and scan it.
	tagRe := regexp.MustCompile(`<button[^>]*\bdanger-quiet\b[^>]*>`)
	inlineRe := regexp.MustCompile(`\bon(?:click|mouseover|mouseout|mousedown|mouseup|focus|blur|change)="`)
	for _, tag := range tagRe.FindAllString(s, -1) {
		if m := inlineRe.FindString(tag); m != "" {
			t.Errorf("danger-quiet button carries an inline handler %q (CSP-blocked, use data-*): %s", m, tag)
		}
		if !strings.Contains(tag, "data-click=") {
			t.Errorf("danger-quiet button lost its data-click delegation: %s", tag)
		}
	}
}
