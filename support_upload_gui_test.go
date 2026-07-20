package main

// support_upload_gui_test.go — M6 PR-6: the Secure Upload GUI. Proves the SPA
// renders the upload config (incl. credential), the read-only TAC-trust list, the
// upload-queue view, and the per-bundle "Upload to TAC" consent action wired to
// their endpoints, and that the consent POST is admin-gated through the FULL
// middleware chain. Mirrors decexcl_tunables_gui_test.go / release_gui_test.go.

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestUploadGUI_PanelAndWiringRender(t *testing.T) {
	fx := newE2EFixture(t)
	resp := mustGet(t, fx.anonClient(), fx.srv.URL+"/") // SPA shell is public
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(body)

	for _, marker := range []string{
		`id="support-upload-status"`,       // config posture slot
		`id="upload-credential"`,           // credential input (PR-5)
		`id="upload-clear-cred"`,           // explicit credential clear
		`id="support-tac-trust"`,           // TAC trust key list
		`id="support-uploads"`,             // upload queue view
		`data-click="saveUploadConfig"`,    // wired config save
		`data-click="supportUploadBundle"`, // wired per-bundle consent action
		`function loadTacTrust`,            // trust loader
		`function loadUploads`,             // queue loader
		`function renderUploads`,           // queue renderer
		`function supportUploadBundle`,     // consent handler
		`/api/support/tac-trust`,           // endpoints the JS calls
		`/api/support/uploads`,
		`/api/support/bundles/`, // consent POST path prefix
	} {
		if !strings.Contains(html, marker) {
			t.Errorf("rendered SPA missing secure-upload marker %q", marker)
		}
	}

	// The config form must be admin-gated in markup (server PUT is the real
	// backstop, asserted separately). The credential input lives in the same
	// admin-gated row.
	if i := strings.Index(html, `id="upload-origin"`); i >= 0 {
		// Walk back to the enclosing row's data-min-role.
		start := strings.LastIndex(html[:i], "<div")
		if start < 0 || !strings.Contains(html[start:i], `data-min-role="admin"`) {
			t.Error("upload config row must carry data-min-role=\"admin\"")
		}
	}
}

func TestUploadGUI_ConsentRequiresAdmin(t *testing.T) {
	fx := newE2EFixture(t)
	id := "csb_" + strings.Repeat("a", 26) // valid bundle-id shape
	url := fx.srv.URL + "/api/support/bundles/" + id + "/upload"
	payload := map[string]any{"confirm": true, "case_id": "CASE-1"}

	viewer := fx.loginAs(e2eViewUser, e2eViewPass)
	if code, _ := postJSON(t, viewer, url, payload); code != http.StatusForbidden {
		t.Fatalf("viewer upload-consent = %d; want 403", code)
	}
	op := fx.loginAs(e2eOpUser, e2eOpPass)
	if code, _ := postJSON(t, op, url, payload); code != http.StatusForbidden {
		t.Fatalf("operator upload-consent = %d; want 403 (admin-only)", code)
	}
	// Admin passes the role gate; with no upload configured the handler fails closed
	// with 409 (not 403), proving the gate admitted the admin.
	admin := fx.loginAs(e2eAdminUser, e2eAdminPass)
	if code, _ := postJSON(t, admin, url, payload); code == http.StatusForbidden {
		t.Fatalf("admin upload-consent = 403; the admin must pass the role gate")
	}
}
