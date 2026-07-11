package main

// Wall tests for the M1+M2 GUI-redesign foundation
// (docs/design/M2-IMPLEMENTATION-REPORT.md). These pin the properties the
// redesign introduced so later slices cannot silently regress them:
//
//   1. the admin console is fully air-gapped (no external origins in the CSP
//      or in the shell markup — Chart.js is embedded, not CDN-loaded);
//   2. the shared component layer exists (danger-tier dialogs, prompt dialog,
//      modal focus mechanics, table helpers);
//   3. native browser dialogs (confirm/prompt) stay banned;
//   4. cache policy: the nonce-bearing shell is never cached, the embedded
//      chart bundle is.

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// ── 1. Air gap ───────────────────────────────────────────────────────────────

func TestFoundation_CSPHasNoExternalOrigins(t *testing.T) {
	fx := newE2EFixture(t)
	resp := mustGet(t, fx.anonClient(), fx.srv.URL+"/")
	defer resp.Body.Close()
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("shell response has no Content-Security-Policy header")
	}
	for _, ext := range []string{"http://", "https://"} {
		if strings.Contains(csp, ext) {
			t.Fatalf("CSP references an external origin (air-gap regression): %s", csp)
		}
	}
}

func TestFoundation_ShellMarkupIsAirGapped(t *testing.T) {
	html, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	// No src/href may point off-origin — the UI must work with zero outbound
	// network access (air-gapped deployments).
	if m := regexp.MustCompile(`(?:src|href)="https?://`).Find(html); m != nil {
		t.Fatalf("static/index.html references an external URL: %q", m)
	}
	if !strings.Contains(string(html), `src="chart.umd.js"`) {
		t.Fatal("static/index.html no longer loads the embedded chart.umd.js")
	}
}

func TestFoundation_ChartAssetEmbeddedAndCached(t *testing.T) {
	fx := newE2EFixture(t)

	resp := mustGet(t, fx.anonClient(), fx.srv.URL+"/chart.umd.js")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /chart.umd.js = %d; want 200", resp.StatusCode)
	}
	if len(body) < 100_000 {
		t.Fatalf("embedded chart.umd.js suspiciously small (%d bytes) — truncated embed?", len(body))
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Fatalf("chart.umd.js Cache-Control = %q; want a max-age policy (embed FS has no validators)", cc)
	}

	// The shell embeds a per-request CSP nonce — caching it would serve stale
	// nonces and block every script.
	shell := mustGet(t, fx.anonClient(), fx.srv.URL+"/")
	shell.Body.Close()
	if cc := shell.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("shell Cache-Control = %q; want no-store (per-request nonce)", cc)
	}
}

// ── 2/3. Shared component layer + native-dialog ban ─────────────────────────

func TestFoundation_SharedComponentLayerPresent(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	for _, marker := range []string{
		`function confirmDanger`,          // Tier-3 typed confirmation
		`function promptAction`,           // input dialog (replaces prompt)
		`function modalActivate`,          // shared focus mechanics
		`function tableRows`,              // shared table renderer
		`id="confirm-dialog-typed"`,       // typed-word gate input
		`id="confirm-dialog-impact"`,      // impact statement region
		`id="confirm-dialog-rollback"`,    // rollback statement region
		`aria-live="polite"`,              // toast announcement region
		`aria-current`,                    // nav current-page marker
	} {
		if !strings.Contains(s, marker) {
			t.Errorf("static/index.html missing foundation marker %q", marker)
		}
	}
}

func TestFoundation_NoNativeBrowserDialogs(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	// Bare prompt(/confirm( calls (not confirmAction/confirmDanger/
	// confirmDialogResolve, whose names keep matching letters after "confirm").
	re := regexp.MustCompile(`[^a-zA-Z_.](?:prompt|confirm)\(`)
	if m := re.Find(data); m != nil {
		t.Fatalf("native browser dialog call found (use confirmAction/confirmDanger/promptAction): %q", m)
	}
}

// ── 4. Danger-tier coverage stays wired ──────────────────────────────────────

func TestFoundation_TypedConfirmationsCoverLockoutClassActions(t *testing.T) {
	data, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	// One confirmWord per Tier-3 action (see M2-IMPLEMENTATION-REPORT.md §6).
	for word, context := range map[string]string{
		`confirmWord: toOpen ? 'OPEN' : 'REQUIRE'`:                    "default auth outcome",
		`confirmWord: newMode === 'allow' ? 'ALLOWLIST' : 'BLOCKLIST'`: "blocklist mode",
		`confirmWord: 'ROTATE'`:  "session signing key",
		`confirmWord: 'PROMOTE'`: "HA promote",
		`confirmWord: 'IMPORT'`:  "cluster CA import",
	} {
		if !strings.Contains(s, word) {
			t.Errorf("Tier-3 typed confirmation for %s no longer present (marker %q)", context, word)
		}
	}
	// Both cluster-forming actions use ENABLE.
	if strings.Count(s, `confirmWord: 'ENABLE'`) < 2 {
		t.Error("expected typed ENABLE confirmations on both control-plane and HA enable")
	}
}
