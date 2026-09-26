package main

// ui_change_password_uicontract_test.go — pins the self-service "Change
// Password" wiring added to static/index.html.
//
// apiAuthChangePassword (ui_auth.go, POST /api/auth/change-password) has
// existed since before this test with full RBAC (any authenticated role,
// RoleViewer floor), current-password verification, complexity validation
// and audit logging — but it was never reachable from the GUI. The only
// password-affordance in the SPA was the admin-only "Edit User" modal in
// User Management (fetchUsers gates the whole table on uiRole === 'admin'),
// which resets ANY user's password without the old one — a privileged
// admin action, not self-service. An operator or viewer therefore had no
// way inside the product to rotate their own password.
//
// This test uses the same string-scan approach as the PAC governance /
// change-diff UI contract tests: it does not exercise a browser, but it
// pins the stable identifiers, handler names, dispatch wiring and endpoint
// call the SPA's self-service password panel depends on, so a future edit
// cannot silently drop the affordance again. Full interaction is covered by
// the Playwright e2e lane.
import (
	"os"
	"strings"
	"testing"
)

func TestUIContract_ChangePasswordSurfacePresent(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)

	mustContain := []string{
		// Topbar affordance — visible to any authenticated role, alongside
		// Sign Out (applySession toggles both from the same condition).
		`id="change-pw-btn"`,
		`data-click="openChangePasswordModal"`,

		// The modal + its fields.
		`id="change-password-modal"`,
		`id="cp-current"`,
		`id="cp-new"`,
		`id="cp-confirm"`,
		`id="cp-err"`,
		`id="cp-save-btn"`,

		// Handlers.
		`function openChangePasswordModal`,
		`function closeChangePasswordModal`,
		`function submitChangePassword`,

		// It must call the self-service endpoint, not the admin-only
		// /api/auth/users bulk endpoint.
		`/api/auth/change-password`,
		`current_password`,
		`new_password`,

		// CSP-safe dispatch (no eval): every handler must be routed.
		`case 'openChangePasswordModal':`,
		`case 'closeChangePasswordModal':`,
		`case 'submitChangePassword':`,
		`data-click="submitChangePassword"`,
		`data-click="closeChangePasswordModal"`,
	}
	for _, sub := range mustContain {
		if !strings.Contains(s, sub) {
			t.Errorf("static/index.html change-password UI missing %q", sub)
		}
	}
}

// TestUIContract_ChangePasswordButtonSharesLogoutVisibility pins that the
// new button is toggled by the SAME (user || role) condition as the
// pre-existing logout button in applySession — i.e. visible for every
// authenticated role, not gated to admin the way the User Management table
// is (fetchUsers: `if (uiRole !== 'admin') return;`).
func TestUIContract_ChangePasswordButtonSharesLogoutVisibility(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)

	const marker = "function applySession("
	i := strings.Index(s, marker)
	if i < 0 {
		t.Fatal("applySession() not found in static/index.html")
	}
	// applySession is a short, self-contained function; a generous window
	// comfortably covers its body without needing a brace-matching parser.
	end := i + 1600
	if end > len(s) {
		end = len(s)
	}
	body := s[i:end]

	if !strings.Contains(body, `document.getElementById('logout-btn').style.display = (user || role) ? '' : 'none';`) {
		t.Fatal("applySession no longer toggles logout-btn the expected way — update this test's expectation alongside it")
	}
	if !strings.Contains(body, `document.getElementById('change-pw-btn').style.display = (user || role) ? '' : 'none';`) {
		t.Error("change-pw-btn is not toggled by applySession using the same (user || role) condition as logout-btn — a role-gated regression would strand operator/viewer self-service password rotation")
	}
}

// TestUIContract_ChangePasswordInputsHaveAccessibleNames pins that each
// password field is programmatically labelled: without a `for`/`id` pair a
// screen reader or voice-control user gets three indistinguishable generic
// password fields (Codex review).
func TestUIContract_ChangePasswordInputsHaveAccessibleNames(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	for _, id := range []string{"cp-current", "cp-new", "cp-confirm"} {
		if !strings.Contains(s, `id="`+id+`"`) {
			t.Errorf("input %q missing", id)
		}
		if !strings.Contains(s, `<label class="form-label" for="`+id+`">`) {
			t.Errorf("input %q has no associated <label for=%q> — it has no accessible name", id, id)
		}
	}
}

// TestUIContract_ChangePasswordModalIsAnAnnouncedDialog pins the dialog
// semantics: the overlay is a modal dialog named by its heading, and the error
// container is an alert live region so validation and server errors are
// announced to screen-reader users rather than silently made visible.
func TestUIContract_ChangePasswordModalIsAnAnnouncedDialog(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	for _, want := range []string{
		`<div id="change-password-modal" role="dialog" aria-modal="true" aria-labelledby="cp-title"`,
		`<h2 id="cp-title"`,
		`id="cp-err" role="alert" aria-live="assertive"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("change-password modal is missing %q", want)
		}
	}
}

// A 401 during submit means api() has already raised the login overlay; the
// dialog must be cleared and closed rather than left (with the typed
// passwords) behind the overlay for whoever signs in next.
func TestUIContract_ChangePasswordClearedOnReauth(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	i := strings.Index(s, "async function submitChangePassword")
	if i < 0 {
		t.Fatal("submitChangePassword not found")
	}
	body := s[i:]
	if j := strings.Index(body, "\n}\n"); j > 0 {
		body = body[:j]
	}
	for _, want := range []string{`err.message === 'Unauthorized'`, `clearChangePasswordFields()`, `closeChangePasswordModal()`} {
		if !strings.Contains(body, want) {
			t.Errorf("submitChangePassword must handle reauthentication: missing %q", want)
		}
	}
}

// The topbar action row gained a button; on narrow viewports it must wrap
// rather than overflow (body hides overflow, so Sign Out could be clipped).
func TestUIContract_TopbarActionsWrapOnNarrowViewports(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, `class="topbar-actions"`) {
		t.Fatal("topbar action row must carry class topbar-actions")
	}
	i := strings.Index(s, "@media(max-width:860px) {\n  #sidebar {")
	if i < 0 {
		t.Fatal("narrow-viewport media block not found")
	}
	block := s[i:]
	end := strings.Index(block, "\n}\n")
	if end < 0 {
		t.Fatal("narrow-viewport media block is not terminated")
	}
	block = block[:end]
	for _, want := range []string{".topbar { flex-wrap: wrap;", ".topbar-actions { flex-wrap: wrap;"} {
		if !strings.Contains(block, want) {
			t.Errorf("narrow-viewport block must contain %q", want)
		}
	}
}

// Session loss can be observed by ANY api() call (the 3 s dashboard tick),
// not only the password submit, so the dialog must be dismissed in the one
// place every session-loss path converges: showLoginOverlay.
func TestUIContract_ChangePasswordDismissedOnAnySessionLoss(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	i := strings.Index(s, "function showLoginOverlay() {")
	if i < 0 {
		t.Fatal("showLoginOverlay not found")
	}
	body := s[i:]
	end := strings.Index(body, "\n}\n")
	if end < 0 {
		t.Fatal("showLoginOverlay body is not terminated")
	}
	if !strings.Contains(body[:end], "dismissChangePasswordModal()") {
		t.Error("showLoginOverlay must dismiss (clear + close) the password dialog")
	}
	j := strings.Index(s, "function dismissChangePasswordModal() {")
	if j < 0 {
		t.Fatal("dismissChangePasswordModal not found")
	}
	d := s[j:]
	if k := strings.Index(d, "\n}\n"); k >= 0 {
		d = d[:k]
	}
	for _, want := range []string{"clearChangePasswordFields()", "closeChangePasswordModal()"} {
		if !strings.Contains(d, want) {
			t.Errorf("dismissChangePasswordModal must call %s", want)
		}
	}
}

// The topbar wraps on narrow viewports, so the sticky policy bars must offset
// by its measured height rather than a fixed single-row 52px.
func TestUIContract_StickyBarsTrackTopbarHeight(t *testing.T) {
	html, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	s := string(html)
	if !strings.Contains(s, ".reorder-bar { position:sticky;top:var(--topbar-h, 52px);") {
		t.Error(".reorder-bar must offset by var(--topbar-h), not a fixed 52px")
	}
	for _, want := range []string{"function syncTopbarHeight()", "setProperty('--topbar-h'", "new ResizeObserver(syncTopbarHeight)"} {
		if !strings.Contains(s, want) {
			t.Errorf("index.html must keep --topbar-h in sync with the topbar: missing %q", want)
		}
	}
}
