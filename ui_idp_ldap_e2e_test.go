//go:build uie2e

package main

// LDAP / Active Directory IdP GUI E2E (ADR-0027, Slice 4) — advisory tier.
//
// Drives real Chromium against the in-process admin UI and covers the mission
// contract for the Identity Providers screen:
//
//   - Create: Add provider → Microsoft Active Directory → smart defaults
//     appear → enter server/Base DN/service account → save disabled → the
//     provider renders with the LDAP badge, server, Base DN, and state.
//   - Secret UX: the bind credential is never prefilled on edit; the
//     "Configured" affordance is shown; editing an unrelated field preserves
//     the stored credential and the browser never receives it.
//   - Unsafe transport: Plain LDAP and skip-verify surface visible warnings.
//   - LDAP is a directory (credential) provider: the SP/callback info panel
//     for browser SSO is not shown.
//   - RBAC: the Identity Providers nav item is admin-gated (hidden for
//     viewer role).
//
// Hermetic: no directory is contacted — the provider is saved DISABLED, so no
// network preflight runs (the staged connection test itself is covered by the
// OpenLDAP interop suite and Slice 3 API tests).

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestUIE2E_LDAPProviderCreateEditSecretAndWarnings(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Ldap-e2e-pass-1!" // #nosec G101 -- test-only fixture credentials

	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, viewerUser, pass)

	// Isolated in-memory registry for this test.
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() { idpRegistry = origReg })

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, adminUser, RoleAdmin)

	// ── Open Identity Providers and start the AD create flow ────────────────
	if err := page.Locator(`.nav-item[data-view="idproviders"]`).First().Click(); err != nil {
		t.Fatalf("open Identity Providers: %v", err)
	}
	if err := page.Locator(`[data-click="openIdPModal"]`).First().Click(); err != nil {
		t.Fatalf("open add-provider modal: %v", err)
	}
	if err := page.Locator(`.idp-provider-card[data-tpl="ad-ldap"]`).Click(); err != nil {
		t.Fatalf("select Active Directory preset: %v", err)
	}

	// Smart defaults from the preset.
	if v, _ := page.Locator("#idp-ldap-filter").InputValue(); v != "(sAMAccountName=%s)" {
		t.Errorf("AD preset user filter = %q, want (sAMAccountName=%%s)", v)
	}
	if v, _ := page.Locator("#idp-ldap-group-attr").InputValue(); v != "memberOf" {
		t.Errorf("AD preset group attribute = %q, want memberOf", v)
	}
	// LDAPS is the recommended default and drives the port placeholder.
	if checked, _ := page.Locator("#idp-ldap-sec-ldaps").IsChecked(); !checked {
		t.Error("LDAPS must be the default connection security")
	}
	// A directory provider has no browser callback — the SP info panel stays hidden.
	if visible, _ := page.Locator("#idp-sp-info").IsVisible(); visible {
		t.Error("SP/callback info panel must not be shown for a directory provider")
	}

	// ── Fill the essentials and save DISABLED ──────────────────────────────
	fill := func(sel, val string) {
		t.Helper()
		if err := page.Locator(sel).Fill(val); err != nil {
			t.Fatalf("fill %s: %v", sel, err)
		}
	}
	fill("#idp-ldap-server", "dc01.corp.example")
	fill("#idp-ldap-basedn", "DC=corp,DC=example")
	fill("#idp-ldap-binddn", "CN=svc-proxy,OU=Service,DC=corp,DC=example")
	fill("#idp-ldap-bindpw", "e2e-bind-secret")
	if err := page.Locator("#idp-enabled").Uncheck(); err != nil {
		t.Fatalf("uncheck enable: %v", err)
	}
	if err := page.Locator(`[data-click="saveIdP"]`).Click(); err != nil {
		t.Fatalf("save provider: %v", err)
	}

	// List renders the provider with the LDAP badge and connection facts.
	row := page.Locator("#idp-list")
	if err := assert.Locator(row).ToContainText("Active Directory"); err != nil {
		t.Fatalf("provider row missing: %v", err)
	}
	if err := assert.Locator(row).ToContainText("LDAP"); err != nil {
		t.Fatalf("LDAP badge missing: %v", err)
	}
	if err := assert.Locator(row).ToContainText("DC=corp,DC=example"); err != nil {
		t.Fatalf("Base DN missing from row: %v", err)
	}
	if err := assert.Locator(row).ToContainText("LDAPS"); err != nil {
		t.Fatalf("connection-security label missing from row: %v", err)
	}

	// Server-side truth: stored with the credential, disabled.
	var created *IdPProfile
	for _, p := range idpRegistry.All() {
		if p.Type == IdPTypeLDAP {
			created = p
		}
	}
	if created == nil {
		t.Fatal("LDAP profile not stored")
	}
	if created.Enabled {
		t.Error("provider must be saved disabled")
	}
	if created.LDAP.BindPassword != "e2e-bind-secret" {
		t.Error("bind credential not stored")
	}
	if created.LDAP.URL != "ldaps://dc01.corp.example:636" {
		t.Errorf("canonical URL = %q", created.LDAP.URL)
	}

	// ── Edit: secret never prefilled; unrelated edit preserves it ───────────
	if err := page.Locator(`#idp-list [data-click="editIdP"]`).First().Click(); err != nil {
		t.Fatalf("open edit: %v", err)
	}
	if v, _ := page.Locator("#idp-ldap-bindpw").InputValue(); v != "" {
		t.Fatalf("bind credential PREFILLED in the browser: %q", v)
	}
	if err := assert.Locator(page.Locator("#idp-ldap-bindpw-state")).ToBeVisible(); err != nil {
		t.Fatalf("'Configured' affordance missing on edit: %v", err)
	}
	// The browser must never have received the secret in any response.
	content, err := page.Content()
	if err != nil {
		t.Fatalf("page content: %v", err)
	}
	if strings.Contains(content, "e2e-bind-secret") {
		t.Fatal("bind credential leaked into the DOM")
	}
	fill("#idp-name", "Renamed Corporate AD")
	if err := page.Locator(`[data-click="saveIdP"]`).Click(); err != nil {
		t.Fatalf("save rename: %v", err)
	}
	if err := assert.Locator(page.Locator("#idp-list")).ToContainText("Renamed Corporate AD"); err != nil {
		t.Fatalf("rename not applied: %v", err)
	}
	got := idpRegistry.Get(created.ID)
	if got == nil || got.LDAP.BindPassword != "e2e-bind-secret" {
		t.Fatal("unrelated edit wiped the stored bind credential")
	}

	// ── Unsafe transport warnings ───────────────────────────────────────────
	if err := page.Locator(`#idp-list [data-click="editIdP"]`).First().Click(); err != nil {
		t.Fatalf("re-open edit: %v", err)
	}
	if err := page.Locator("#idp-ldap-sec-plain").Check(); err != nil {
		t.Fatalf("select plain LDAP: %v", err)
	}
	if err := assert.Locator(page.Locator("#idp-ldap-plain-warning")).ToBeVisible(); err != nil {
		t.Fatalf("plain-LDAP warning not visible: %v", err)
	}
	if _, err := page.Evaluate(`() => { document.getElementById('idp-ldap-advanced').open = true; }`); err != nil {
		t.Fatalf("open advanced: %v", err)
	}
	if err := page.Locator("#idp-ldap-skipverify").Check(); err != nil {
		t.Fatalf("check skip-verify: %v", err)
	}
	if err := assert.Locator(page.Locator("#idp-ldap-skipverify-warning")).ToBeVisible(); err != nil {
		t.Fatalf("skip-verify warning not visible: %v", err)
	}

	// ── Accessibility spot checks ───────────────────────────────────────────
	for _, id := range []string{"idp-ldap-server", "idp-ldap-basedn", "idp-ldap-bindpw"} {
		count, err := page.Locator(`label[for="` + id + `"]`).Count()
		if err != nil || count == 0 {
			t.Errorf("input #%s has no associated label (err=%v)", id, err)
		}
	}
	if count, _ := page.Locator(`[role="radiogroup"][aria-label="Connection security"]`).Count(); count == 0 {
		t.Error("connection-security radios lack a labelled radiogroup")
	}
}

func TestUIE2E_LDAPProviderViewerCannotSeePanel(t *testing.T) {
	const adminUser, viewerUser, pass = "admin-e2e", "viewer-e2e", "Ldap-e2e-pass-2!" // #nosec G101 -- test-only fixture credentials
	uiSrv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(uiSrv.Close)
	seedUIRoster(t, adminUser, viewerUser, pass)

	browser := uiE2EBrowser(t)
	assert := playwright.NewPlaywrightAssertions(8000)
	_, page := newAuthedUIPage(t, browser, uiSrv.URL, viewerUser, RoleViewer)
	// Role gating applies once the SPA's auth/status fetch resolves — the
	// assertion polls rather than sampling instantly.
	if err := assert.Locator(page.Locator(`.nav-item[data-view="idproviders"]`).First()).ToBeHidden(); err != nil {
		t.Errorf("Identity Providers nav item must be hidden for viewer role (admin-gated): %v", err)
	}
}
