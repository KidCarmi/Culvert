package main

// ui_auth_ldap_api_test.go — Slice 3 wall (ADR-0025): the LDAP admin-API
// surface. Directory-free: live-directory behavior is covered by the
// OpenLDAP interop suite; here we pin request validation, RBAC, staged-report
// shape on unreachable targets, stored-secret reuse, audit hygiene, the
// legacy summary/import endpoints, and the safe-activation preflight
// transaction (a broken candidate never replaces a working provider).

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// unreachableLDAPBody returns a test-request body whose directory can never
// answer (TEST-NET-1 address, port 1) so dial fails fast and deterministically.
func unreachableLDAPTestBody(extra map[string]any) map[string]any {
	ldap := map[string]any{
		"url":    "ldap://192.0.2.1:1",
		"baseDn": "DC=corp,DC=example",
	}
	for k, v := range extra {
		ldap[k] = v
	}
	return map[string]any{
		"profile": map[string]any{
			"name": "Test AD",
			"type": "ldap",
			"ldap": ldap,
		},
	}
}

func TestAPIIdPTest_RequiresPOSTAndAdmin(t *testing.T) {
	w := httptest.NewRecorder()
	apiIdPTest(w, getReq("/api/idp/test"))
	assertStatus(t, w, http.StatusMethodNotAllowed)

	// Viewer must be rejected by handler-level RBAC (defense-in-depth).
	w = httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/idp/test", unreachableLDAPTestBody(nil))
	r = viewerCtx(r)
	apiIdPTest(w, r)
	assertStatus(t, w, http.StatusForbidden)
}

func TestAPIIdPTest_RejectsNonLDAPAndInvalidConfig(t *testing.T) {
	w := httptest.NewRecorder()
	apiIdPTest(w, jsonReq(http.MethodPost, "/api/idp/test", map[string]any{
		"profile": map[string]any{"name": "X", "type": "oidc", "oidc": map[string]any{"issuer": "https://idp.example"}},
	}))
	assertStatus(t, w, http.StatusBadRequest)

	w = httptest.NewRecorder()
	apiIdPTest(w, jsonReq(http.MethodPost, "/api/idp/test", map[string]any{
		"profile": map[string]any{"name": "X", "type": "ldap", "ldap": map[string]any{
			"url": "https://not-ldap.example", "baseDn": "DC=x",
		}},
	}))
	assertStatus(t, w, http.StatusBadRequest)

	// Unknown top-level fields are rejected (strict decoding).
	w = httptest.NewRecorder()
	body := unreachableLDAPTestBody(nil)
	body["unexpected"] = true
	apiIdPTest(w, jsonReq(http.MethodPost, "/api/idp/test", body))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIIdPTest_UnreachableDirectoryReportsStagedFailure(t *testing.T) {
	w := httptest.NewRecorder()
	start := time.Now()
	apiIdPTest(w, jsonReq(http.MethodPost, "/api/idp/test", unreachableLDAPTestBody(nil)))
	assertStatus(t, w, http.StatusOK) // the HTTP call succeeded; the report carries the failure
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("test endpoint not bounded: took %v", elapsed)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"ok":false`) || !strings.Contains(body, `"name":"reachable"`) {
		t.Fatalf("staged report missing: %s", body)
	}
	if !strings.Contains(body, "Directory unreachable") && !strings.Contains(body, "Timeout") {
		t.Fatalf("report lacks an actionable hint: %s", body)
	}
}

func TestAPIIdPTest_AuditsCategoryNeverCredentials(t *testing.T) {
	baseline := time.Now().UnixMilli()
	w := httptest.NewRecorder()
	body := unreachableLDAPTestBody(map[string]any{"bindPassword": "svc-audit-secret"})
	body["testUsername"] = "alice"
	body["testPassword"] = "user-audit-secret"
	apiIdPTest(w, jsonReq(http.MethodPost, "/api/idp/test", body))
	assertStatus(t, w, http.StatusOK)

	found := false
	for _, e := range auditGet() {
		if e.Action != "idp.test" || e.TS < baseline {
			continue
		}
		found = true
		if strings.Contains(e.Detail, "svc-audit-secret") || strings.Contains(e.Detail, "user-audit-secret") {
			t.Fatalf("audit entry leaked a credential: %+v", e)
		}
		if !strings.HasPrefix(e.Detail, "failed") {
			t.Errorf("audit detail should carry the failure category, got %q", e.Detail)
		}
	}
	if !found {
		t.Fatal("idp.test produced no audit entry")
	}
}

func TestAPIIdPTest_ReusesStoredBindCredentialForExistingProfile(t *testing.T) {
	withTestIdPRegistry(t)
	seedLDAPProfile(t, "ldap-test-reuse")

	p := &IdPProfile{ID: "ldap-test-reuse", Type: IdPTypeLDAP, LDAP: &LDAPProfileConfig{URL: "ldap://192.0.2.1:1", BaseDN: "DC=x"}}
	resolveTestBindCredential(p)
	if p.LDAP.BindPassword != "svc-secret" {
		t.Fatalf("stored credential not reused: %q", p.LDAP.BindPassword)
	}
	// A candidate with its own credential keeps it.
	p2 := &IdPProfile{ID: "ldap-test-reuse", Type: IdPTypeLDAP, LDAP: &LDAPProfileConfig{URL: "ldap://x:1", BaseDN: "DC=x", BindPassword: "own"}}
	resolveTestBindCredential(p2)
	if p2.LDAP.BindPassword != "own" {
		t.Fatal("candidate credential was overwritten by the stored one")
	}
}

// ── Safe-activation preflight ────────────────────────────────────────────────

func TestAPIIdPItem_PreflightFailureNeverReplacesWorkingProvider(t *testing.T) {
	withTestIdPRegistry(t)
	if err := idpRegistry.Upsert(ldapTestProfile("ldap-live", "Working AD")); err != nil {
		t.Fatal(err)
	}

	// Edit to an unreachable server WITH the connection preflight: must fail
	// 422 and leave the stored profile byte-identical.
	body := ldapProfileBodyForPut("Working AD", map[string]any{"bindPassword": "svc-secret"})
	body["enabled"] = true
	if m, ok := body["ldap"].(map[string]any); ok {
		m["url"] = "ldap://192.0.2.1:1"
	}
	r := jsonReq(http.MethodPut, "/api/idp/ldap-live?preflight=connection", body)
	w := httptest.NewRecorder()
	apiIdPItem(w, r, "ldap-live")
	assertStatus(t, w, http.StatusUnprocessableEntity)
	if !strings.Contains(w.Body.String(), "remains active and unchanged") {
		t.Errorf("preflight failure must state the working config is untouched: %s", w.Body.String())
	}

	got := idpRegistry.Get("ldap-live")
	if got.LDAP.URL != "ldaps://dc01.corp.example:636" {
		t.Fatalf("broken candidate replaced the working provider: url=%q", got.LDAP.URL)
	}
	if prov, ok := idpRegistry.LiveProvider("ldap-live"); !ok || prov.Name() != "ldap:ldap-live" {
		t.Fatal("live provider lost after failed preflight")
	}
}

func TestAPIIdPItem_PutWithoutPreflightKeepsExistingSemantics(t *testing.T) {
	withTestIdPRegistry(t)
	seedLDAPProfile(t, "ldap-nopreflight")
	// No preflight param: a validation-clean edit persists without any dial.
	start := time.Now()
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/ldap-nopreflight", ldapProfileBodyForPut("Renamed", nil)), "ldap-nopreflight")
	assertStatus(t, w, http.StatusOK)
	if time.Since(start) > 2*time.Second {
		t.Fatal("PUT without preflight performed network I/O")
	}
}

func TestLDAPActivationPreflight_IgnoresNonLDAPAndAbsentParam(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/api/idp/x", nil)
	if rep := ldapActivationPreflight(r, ldapTestProfile("x", "X")); rep != nil {
		t.Fatal("preflight ran without the query param")
	}
	r = httptest.NewRequest(http.MethodPut, "/api/idp/x?preflight=connection", nil)
	oidc := &IdPProfile{Type: IdPTypeOIDC}
	if rep := ldapActivationPreflight(r, oidc); rep != nil {
		t.Fatal("preflight must be a no-op for non-LDAP types")
	}
}

// ── Legacy summary + import ──────────────────────────────────────────────────

func withLegacyLDAPYAML(t *testing.T, c *LDAPConfig) {
	t.Helper()
	legacyLDAPYAMLState.mu.Lock()
	prev := legacyLDAPYAMLState.cfg
	legacyLDAPYAMLState.cfg = c
	legacyLDAPYAMLState.mu.Unlock()
	t.Cleanup(func() {
		legacyLDAPYAMLState.mu.Lock()
		legacyLDAPYAMLState.cfg = prev
		legacyLDAPYAMLState.mu.Unlock()
	})
}

func TestAPIIdPLegacyLDAP_SummaryNeverLeaksCredential(t *testing.T) {
	withLegacyLDAPYAML(t, &LDAPConfig{
		URL: "ldaps://legacy.corp.example:636", BaseDN: "DC=legacy", BindDN: "CN=svc",
		BindPassword: "legacy-secret", StartTLS: false,
	})
	w := httptest.NewRecorder()
	apiIdPLegacyLDAP(w, getReq("/api/idp/legacy-ldap"))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if strings.Contains(body, "legacy-secret") {
		t.Fatalf("legacy summary leaked the bind credential: %s", body)
	}
	for _, want := range []string{`"present":true`, `"bindCredentialConfigured":true`, `"baseDn":"DC=legacy"`} {
		if !strings.Contains(body, want) {
			t.Errorf("summary missing %s: %s", want, body)
		}
	}
}

func TestAPIIdPLegacyLDAP_AbsentYAML(t *testing.T) {
	withLegacyLDAPYAML(t, nil)
	w := httptest.NewRecorder()
	apiIdPLegacyLDAP(w, getReq("/api/idp/legacy-ldap"))
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), `"present":false`) {
		t.Fatalf("want present:false, got %s", w.Body.String())
	}

	w = httptest.NewRecorder()
	apiIdPLegacyLDAPImport(w, jsonReq(http.MethodPost, "/api/idp/legacy-ldap/import", nil))
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIIdPLegacyLDAPImport_CreatesDisabledProfilePreservingSecurityFields(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPYAML(t, &LDAPConfig{
		URL: "ldaps://legacy.corp.example:636", BaseDN: "DC=legacy,DC=example",
		BindDN: "CN=svc,DC=legacy,DC=example", BindPassword: "legacy-secret",
		UserFilter: "(uid=%s)", RequiredGroup: "CN=Proxy,DC=legacy,DC=example",
		StartTLS:      true, // contradictory with ldaps:// in the profile schema — must normalize, not fail
		TLSSkipVerify: true, CacheTTL: 10 * time.Minute,
	})

	w := httptest.NewRecorder()
	apiIdPLegacyLDAPImport(w, jsonReq(http.MethodPost, "/api/idp/legacy-ldap/import", nil))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if strings.Contains(body, "legacy-secret") {
		t.Fatalf("import response leaked the bind credential: %s", body)
	}

	var imported *IdPProfile
	for _, p := range idpRegistry.All() {
		if p.Type == IdPTypeLDAP && p.Name == "Imported legacy LDAP" {
			imported = p
			break
		}
	}
	if imported == nil {
		t.Fatal("imported profile not found in registry")
	}
	if imported.Enabled {
		t.Fatal("imported profile must be DISABLED (test-then-enable)")
	}
	l := imported.LDAP
	if l.URL != "ldaps://legacy.corp.example:636" || l.BaseDN != "DC=legacy,DC=example" ||
		l.BindDN != "CN=svc,DC=legacy,DC=example" || l.BindPassword != "legacy-secret" ||
		l.UserFilter != "(uid=%s)" || l.RequiredGroup != "CN=Proxy,DC=legacy,DC=example" ||
		!l.TLSSkipVerify || l.CacheTTLSeconds != 600 {
		t.Fatalf("security-effective fields not preserved: %+v", l)
	}
	if l.StartTLS {
		t.Fatal("ldaps+StartTLS contradiction must be normalized off on import")
	}
}

func TestAPIIdPLegacyLDAPImport_RequiresAdmin(t *testing.T) {
	withLegacyLDAPYAML(t, &LDAPConfig{URL: "ldap://x:389", BaseDN: "DC=x"})
	w := httptest.NewRecorder()
	apiIdPLegacyLDAPImport(w, viewerCtx(jsonReq(http.MethodPost, "/api/idp/legacy-ldap/import", nil)))
	assertStatus(t, w, http.StatusForbidden)
}
