//go:build uie2e

package main

// CA-management panel E2E — advisory tier.
//
// The CA panel surfaces the SSL-inspection root CA: its issuer, validity, and
// SHA-256 fingerprint (from /api/ca-cert), and offers the PEM for browser import
// (/api/ca/download). This drives those endpoints through the admin's browser
// session (the real auth middleware) and confirms the panel is reachable —
// proving the CA-management surface is wired to the live CertManager, the same
// root that signs MITM leaf certs.
//
// Hermetic + in-process. A CA is installed via setupInspectCA (shared with the
// MITM suite) so there is a real root to surface.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_CAPanelShowsRoot(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Ca-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials
	setupInspectCA(t)                                                               // install a real root CA into the global certMgr
	seedUIRoster(t, adminUser, viewerUser, pass)

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)

	browser := uiE2EBrowser(t)
	ctx, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// The admin can reach the CA panel (its info container is present in the DOM).
	if err := page.Locator(`.nav-item[data-view="ca-mgmt"]`).First().Click(); err != nil {
		t.Fatalf("open CA panel: %v", err)
	}
	if n, _ := page.Locator("#ca-info").Count(); n == 0 {
		t.Error("CA panel is missing its info container (#ca-info)")
	}

	// /api/ca-cert (what the panel renders) returns the live root's metadata.
	resp, err := ctx.Request().Get(uiSrv.URL+"/api/ca-cert", playwright.APIRequestContextGetOptions{
		Headers: map[string]string{"Accept": "application/json"},
	})
	if err != nil {
		t.Fatalf("GET /api/ca-cert: %v", err)
	}
	if resp.Status() != 200 {
		t.Fatalf("/api/ca-cert status %d, want 200", resp.Status())
	}
	var ca struct {
		Issuer      string `json:"issuer"`
		Fingerprint string `json:"fingerprint"`
		NotAfter    string `json:"notAfter"`
	}
	body, _ := resp.Body()
	if err := json.Unmarshal(body, &ca); err != nil {
		t.Fatalf("decode /api/ca-cert %q: %v", string(body), err)
	}
	if ca.Fingerprint == "" || ca.NotAfter == "" {
		t.Errorf("/api/ca-cert missing root metadata: %+v", ca)
	}

	// The root CA is downloadable as PEM for browser import (admin).
	dl, err := ctx.Request().Get(uiSrv.URL + "/api/ca/download")
	if err != nil {
		t.Fatalf("GET /api/ca/download: %v", err)
	}
	if dl.Status() != 200 {
		t.Fatalf("/api/ca/download status %d, want 200", dl.Status())
	}
	pem, _ := dl.Body()
	if !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Errorf("/api/ca/download did not return a PEM certificate:\n%.200s", pem)
	}
}
