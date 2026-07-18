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
	"reflect"
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
	html, err := os.ReadFile(staticIndexHTMLPath())
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
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	for _, marker := range []string{
		`function confirmDanger`,       // Tier-3 typed confirmation
		`function promptAction`,        // input dialog (replaces prompt)
		`function modalActivate`,       // shared focus mechanics
		`function tableRows`,           // shared table renderer
		`id="confirm-dialog-typed"`,    // typed-word gate input
		`id="confirm-dialog-impact"`,   // impact statement region
		`id="confirm-dialog-rollback"`, // rollback statement region
		`aria-live="polite"`,           // toast announcement region
		`aria-current`,                 // nav current-page marker
		// M3 S3 — policy editor assist layer
		`function polReadForm`,       // single form reader shared by submit/summary/validation
		`function polValidateClient`, // pre-submit checks mirroring validatePolicyRule
		`function polRenderSummary`,  // live human-readable rule summary (G10)
		`function polHistory`,        // per-rule History → filtered audit view (G7)
		`function polMarkEdited`,     // dirty-tracking entry point for chip/picker gestures
		`function polValidSourceIP`,  // strict IPv4/IPv6 CIDR pre-validation
		`id="pol-summary"`,           // summary region
		`id="pol-form-err"`,          // inline validation errors
		`data-mousedown=`,            // CSP-safe replacement for picker onmousedown
		// M3 S4 — decision-trace integration
		`function renderPolicyTrace`,   // shared trace rows consuming the walkPolicyTestRules payload
		`function gotoAnchoredRow`,     // generic view+row anchor (any tbody with data-priority)
		`function polTestRule`,         // tester prefill from a rule's conditions (G6)
		`data-click="trafficGotoRule"`, // Traffic rule chip → resolve + anchored rulebase row
		// M3 S5 — staged reorder + advisory shadow hints
		`function polApplyOrder`,  // the ONLY /api/policy/reorder call site (G3)
		`function polRevertOrder`, // discard the staged order
		`function polShadowHints`, // exactly-decidable advisory shadow detection (G4)
		`id="pol-reorder-bar"`,    // sticky Apply/Revert commit bar
		// P1 Where-Used — generic object-reference presentation (policy-refs)
		`function whereUsedList`,     // generic consumer-entry renderer (switches on nothing)
		`function handleDeleteError`, // blocked-delete 409 → navigable referent list
		`function openWhereUsed`,     // on-demand references fetch for a shared object row
		`id="where-used-dialog"`,     // Where-Used modal
		`data-click="whereUsedGoto"`, // referent → consumer navigation
		`data-click="openWhereUsed"`, // on-demand Where-Used affordance on object rows
		// policy-metadata P1 — Tier-A rule metadata (comment + provenance)
		`function polRenderProvenance`, // read-only createdAt/modifiedAt/modifiedBy line
		`id="pol-comment"`,             // admin-authored rule comment field
		`id="pol-provenance"`,          // server-stamped provenance display
		// policy-metadata P1 — persisted hit counters + lastHit
		`function polHitsTitle`, // Hits-cell hover: total matches + last-match time
		// policy-metadata P1 — unused-rules filter
		`function polRuleIsUnused`,     // "not matched within N days (incl. never)" predicate
		`function togglePolUnused`,     // unused-only filter toggle
		`id="pol-unused-btn"`,          // the Unused filter button
		`data-click="togglePolUnused"`, // its dispatch wiring
		// P2 — optimistic concurrency (rule-set generation counter)
		`function polV`,                 // appends ?ifVersion= to policy mutations
		`function polVForEdit`,          // binds a form submit to its loaded version (not the live poll)
		`function polIsVersionConflict`, // 409 rule-set-conflict → warn + reload
	} {
		if !strings.Contains(s, marker) {
			t.Errorf("static/index.html missing foundation marker %q", marker)
		}
	}
}

// ── M3 S4: the decision-trace payload is a frozen contract ──────────────────

func TestFoundation_PolicyTraceContractFrozen(t *testing.T) {
	// renderPolicyTrace (static/index.html) consumes the walkPolicyTestRules
	// payload verbatim; renaming or adding fields silently breaks (or silently
	// bypasses) the admin UI's trace viewer. Field changes must update the
	// trace component in the same commit. Contract owner:
	// docs/design/M3-POLICY-ARCH-REVIEW.md §4 (S4).
	want := map[string]string{
		"Priority":   "priority",
		"Name":       "name",
		"SkipReason": "skipReason,omitempty",
	}
	typ := reflect.TypeOf(policyTestTrace{})
	if typ.NumField() != len(want) {
		t.Fatalf("policyTestTrace has %d fields; want %d — update renderPolicyTrace and this contract together", typ.NumField(), len(want))
	}
	for name, tag := range want {
		f, ok := typ.FieldByName(name)
		if !ok {
			t.Errorf("policyTestTrace lost field %s (frozen trace contract)", name)
			continue
		}
		if got := f.Tag.Get("json"); got != tag {
			t.Errorf("policyTestTrace.%s json tag = %q; want %q (frozen trace contract)", name, got, tag)
		}
	}
}

// ── M3 S5: drag must never POST — the commit bar owns the reorder ───────────

func TestFoundation_DragReorderIsStaged(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	// Exactly one CALL site may hit /api/policy/reorder (comments may name it).
	// The URL is wrapped in polV() for the P2 optimistic-concurrency version param.
	call := `polV('/api/policy/reorder')`
	if n := strings.Count(s, call); n != 1 {
		t.Fatalf("%s appears %d times in static/index.html; want exactly 1 (inside polApplyOrder) — drag must stage, never POST", call, n)
	}
	// …and it must live inside polApplyOrder, not the drag handlers.
	start := strings.Index(s, "async function polApplyOrder")
	if start < 0 {
		t.Fatal("polApplyOrder not found")
	}
	end := strings.Index(s[start:], "\nfunction ")
	if end < 0 {
		end = len(s) - start
	}
	if !strings.Contains(s[start:start+end], call) {
		t.Error("the /api/policy/reorder call is not inside polApplyOrder — the staged-reorder contract (G3) is broken")
	}
}

func TestFoundation_NoInlineEventHandlers(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	// The CSP is script-src 'self' 'nonce-…' — inline on*="" handlers are
	// BLOCKED by the browser, so any such attribute (in static markup or in
	// JS-generated template strings) is silently dead UI. Everything must go
	// through the data-* delegation layer.
	re := regexp.MustCompile(`\bon(?:click|dblclick|mousedown|mouseup|mouseover|mouseout|change|input|blur|focus|keydown|keyup|keypress|submit|load|error)="`)
	for i, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue // delegation-layer comments name the attributes they replace
		}
		if m := re.FindString(line); m != "" {
			t.Errorf("static/index.html:%d inline event handler %q is blocked by the CSP — use the data-* delegation layer", i+1, m)
		}
	}
}

func TestFoundation_NoNativeBrowserDialogs(t *testing.T) {
	data, err := os.ReadFile(staticIndexHTMLPath())
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
	data, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read static/index.html: %v", err)
	}
	s := string(data)
	// One confirmWord per Tier-3 action (see M2-IMPLEMENTATION-REPORT.md §6).
	for word, context := range map[string]string{
		`confirmWord: toOpen ? 'OPEN' : 'REQUIRE'`:                     "default auth outcome",
		`confirmWord: newMode === 'allow' ? 'ALLOWLIST' : 'BLOCKLIST'`: "blocklist mode",
		`confirmWord: 'ROTATE'`:                                        "session signing key",
		`confirmWord: 'PROMOTE'`:                                       "HA promote",
		`confirmWord: 'IMPORT'`:                                        "cluster CA import",
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
