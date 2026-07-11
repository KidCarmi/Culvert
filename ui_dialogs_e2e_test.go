//go:build uie2e

package main

// Danger-tier dialog + modal-stack browser E2E (advisory tier).
//
// Browser complement to ui_redesign_foundation_test.go, closing self-review
// findings H1/H2 (docs/design/M1-M2-SELF-REVIEW.md): the static wall tests
// pin that the components EXIST; these prove they BEHAVE — the typed-word
// gate only arms on the exact confirmation word, Esc cancels (resolving the
// pending promise false, even from a focused input), the modal STACK restores
// focus layer-by-layer when a dialog opens on top of another modal, and the
// background is aria-hidden while any stack-managed modal is open.
//
// Hermetic like the rest of the suite: real handler chain via httptest, a
// minted admin session, and dialogs driven through the REAL shared components
// (confirmDanger / confirmAction / openUserModal). Every dialog is cancelled —
// no mutation is ever submitted.

import (
	"net/http/httptest"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_TypedConfirmationGate(t *testing.T) {
	const adminUser, viewerUser, pass = "dlg-admin-e2e", "dlg-viewer-e2e", "Dlg-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)

	// Open a Tier-3 dialog through the real component; park the promise on
	// window so its settled value can be read back after cancellation.
	// NOTE: `void (...)` so the expression's value is undefined — evaluating
	// the assignment itself would hand Playwright the PENDING dialog promise,
	// which it auto-awaits (deadlock until the dialog closes).
	if _, err := page.Evaluate(`void (window._e2eConfirm = confirmDanger({
		title: 'E2E typed gate', msg: 'browser regression fixture',
		impact: 'none — cancelled by the test', rollback: 'n/a',
		confirmWord: 'ROTATE', okLabel: 'Apply'}))`); err != nil {
		t.Fatalf("open confirmDanger: %v", err)
	}
	mustBeVisible(t, page, "#confirm-dialog", "Tier-3 dialog opens")

	ok := page.Locator("#confirm-dialog-ok")
	assertDisabled(t, ok, true, "OK disarmed before any input")

	if err := page.Locator("#confirm-dialog-typed").Fill("WRONG"); err != nil {
		t.Fatalf("fill wrong word: %v", err)
	}
	assertDisabled(t, ok, true, "OK stays disarmed on a wrong word")

	if err := page.Locator("#confirm-dialog-typed").Fill("ROTATE"); err != nil {
		t.Fatalf("fill confirmation word: %v", err)
	}
	assertDisabled(t, ok, false, "OK arms on the exact confirmation word")

	// Background is aria-hidden while the dialog is open (finding M1).
	if v, _ := page.Locator("#main").GetAttribute("aria-hidden"); v != "true" {
		t.Errorf("#main aria-hidden = %q while dialog open; want \"true\"", v)
	}

	// Esc from the FOCUSED INPUT cancels and resolves the promise false.
	if err := page.Locator("#confirm-dialog-typed").Press("Escape"); err != nil {
		t.Fatalf("press Escape: %v", err)
	}
	mustBeHidden(t, page, "#confirm-dialog", "Esc closes the dialog")
	if res, err := page.Evaluate(`window._e2eConfirm`); err != nil || res != false {
		t.Errorf("cancelled confirmDanger resolved %v (err %v); want false", res, err)
	}
	if v, _ := page.Locator("#main").GetAttribute("aria-hidden"); v == "true" {
		t.Error("#main still aria-hidden after the last modal closed")
	}
}

func TestUIE2E_ModalStackNesting(t *testing.T) {
	const adminUser, viewerUser, pass = "stack-admin-e2e", "stack-viewer-e2e", "Stack-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	seedUIRoster(t, adminUser, viewerUser, pass)

	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)

	browser := uiE2EBrowser(t)
	_, page := newAuthedUIPage(t, browser, srv.URL, adminUser, RoleAdmin)

	// Layer 1: the real user modal (class-toggle visibility mechanism).
	if _, err := page.Evaluate(`openUserModal()`); err != nil {
		t.Fatalf("openUserModal: %v", err)
	}
	mustBeVisible(t, page, "#user-modal", "user modal opens")
	if id, _ := page.Evaluate(`document.activeElement && document.activeElement.id`); id != "um-username" {
		t.Errorf("user-modal initial focus = %v; want um-username", id)
	}

	// Layer 2: a confirm dialog on top (display-toggle mechanism).
	// void(...) — see TestUIE2E_TypedConfirmationGate: never hand Playwright
	// the pending promise.
	if _, err := page.Evaluate(`void (window._e2eNested = confirmAction('E2E nested', 'on top of the user modal', 'OK'))`); err != nil {
		t.Fatalf("open nested confirmAction: %v", err)
	}
	mustBeVisible(t, page, "#confirm-dialog", "nested dialog opens")
	if n, err := page.Evaluate(`_modalStack.length`); err != nil || n != 2 {
		t.Errorf("_modalStack length = %v (err %v); want 2", n, err)
	}

	// First Esc closes ONLY the top layer and returns focus into the modal
	// underneath (the single-slot bug this stack replaced restored it to the
	// page background instead).
	if err := page.Keyboard().Press("Escape"); err != nil {
		t.Fatalf("press Escape (1): %v", err)
	}
	mustBeHidden(t, page, "#confirm-dialog", "Esc closes the top layer only")
	mustBeVisible(t, page, "#user-modal", "user modal survives the nested close")
	if res, err := page.Evaluate(`window._e2eNested`); err != nil || res != false {
		t.Errorf("nested confirmAction resolved %v (err %v); want false", res, err)
	}
	if inModal, err := page.Evaluate(`!!(document.activeElement && document.activeElement.closest('#user-modal'))`); err != nil || inModal != true {
		t.Errorf("focus not restored into the underlying modal (got %v, err %v)", inModal, err)
	}
	if v, _ := page.Locator("#main").GetAttribute("aria-hidden"); v != "true" {
		t.Errorf("#main aria-hidden = %q with one modal still open; want \"true\"", v)
	}

	// Second Esc closes the remaining layer; stack drains, background restored.
	if err := page.Keyboard().Press("Escape"); err != nil {
		t.Fatalf("press Escape (2): %v", err)
	}
	mustBeHidden(t, page, "#user-modal", "Esc closes the remaining layer")
	if n, err := page.Evaluate(`_modalStack.length`); err != nil || n != 0 {
		t.Errorf("_modalStack length = %v (err %v) after closing all; want 0", n, err)
	}
	if v, _ := page.Locator("#main").GetAttribute("aria-hidden"); v == "true" {
		t.Error("#main still aria-hidden after the stack drained")
	}
}

// ── small assertion helpers (suite-local) ────────────────────────────────────

func mustBeVisible(t *testing.T, page playwright.Page, selector, desc string) {
	t.Helper()
	if err := page.Locator(selector).WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(8000),
	}); err != nil {
		t.Fatalf("%s: %q never became visible: %v", desc, selector, err)
	}
}

func mustBeHidden(t *testing.T, page playwright.Page, selector, desc string) {
	t.Helper()
	if err := page.Locator(selector).WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateHidden,
		Timeout: playwright.Float(8000),
	}); err != nil {
		t.Fatalf("%s: %q never became hidden: %v", desc, selector, err)
	}
}

func assertDisabled(t *testing.T, loc playwright.Locator, want bool, desc string) {
	t.Helper()
	got, err := loc.IsDisabled()
	if err != nil {
		t.Fatalf("%s: IsDisabled: %v", desc, err)
	}
	if got != want {
		t.Errorf("%s: disabled = %v; want %v", desc, got, want)
	}
}
