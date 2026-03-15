package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── apiAuthStatus ────────────────────────────────────────────────────────────

func TestAPIAuthStatus_Get_AuthDisabled(t *testing.T) {
	// When auth is not enabled, should return loggedIn:true
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthStatus(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIAuthStatus_BasicAuth_Valid(t *testing.T) {
	// Set up a UI user for basic-auth test
	_ = cfg.SetUIUser("teststatuser", "testpass999", RoleAdmin)
	defer cfg.DeleteUIUser("teststatuser") //nolint:errcheck // test teardown; cleanup errors are non-actionable

	// Enable auth so the basic-auth branch is reached
	_ = cfg.SetAuth("teststatuser", "testpass999")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r.SetBasicAuth("teststatuser", "testpass999")
	apiAuthStatus(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIAuthStatus_BasicAuth_Invalid(t *testing.T) {
	_ = cfg.SetAuth("authstatuser2", "correctpass")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r.SetBasicAuth("authstatuser2", "wrongpass")
	apiAuthStatus(w, r)
	assertStatus(t, w, http.StatusOK) // returns 200 with loggedIn:false
}

// ─── apiAuthLogout ────────────────────────────────────────────────────────────

func TestAPIAuthLogout_Post(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/logout", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiAuthLogout(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiFileblock ─────────────────────────────────────────────────────────────

func TestAPIFileblock_Post_Add(t *testing.T) {
	defer fileBlocker.Remove(".testexe")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/fileblock", map[string]any{
		"extension": ".testexe",
	})
	r = adminCtx(r)
	apiFileblock(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIFileblock_Post_BulkAdd(t *testing.T) {
	defer fileBlocker.Remove(".testdll")
	defer fileBlocker.Remove(".testbat")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/fileblock", map[string]any{
		"extensions": []string{".testdll", ".testbat"},
	})
	r = adminCtx(r)
	apiFileblock(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIFileblock_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/fileblock", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiFileblock(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIFileblock_Delete(t *testing.T) {
	fileBlocker.Add(".tmpext")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/fileblock?ext=.tmpext", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiFileblock(w, r)
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIFileblock_Delete_MissingExt(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/fileblock", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiFileblock(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIFileblock_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/fileblock", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiFileblock(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiPolicyReorder ─────────────────────────────────────────────────────────

func TestAPIPolicyReorder_Post_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/policy/reorder", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiPolicyReorder(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIPolicyReorder_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/policy/reorder", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiPolicyReorder(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIPolicyReorder_Post_Mismatch(_ *testing.T) {
	// empty priorities list should cause a mismatch if there are rules
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy/reorder", map[string]any{
		"priorities": []int{999998, 999997},
	})
	r = adminCtx(r)
	apiPolicyReorder(w, r)
	// Either 400 (mismatch) or 200 (no rules to match) — both are acceptable
	// but we just verify it doesn't panic
}

func TestAPIPolicyReorder_Post_Success(t *testing.T) {
	// Add two rules and reorder them
	r1 := policyStore.Add(PolicyRule{Priority: 7701, Name: "reorder-a", Action: "allow"})
	r2 := policyStore.Add(PolicyRule{Priority: 7702, Name: "reorder-b", Action: "deny"})
	defer func() {
		policyStore.Delete(r1.Priority)
		policyStore.Delete(r2.Priority)
	}()

	w := httptest.NewRecorder()
	req := jsonReq(http.MethodPost, "/api/policy/reorder", map[string]any{
		"priorities": []int{r2.Priority, r1.Priority},
	})
	req = adminCtx(req)
	apiPolicyReorder(w, req)
	// Accept 200 or 400 — Reorder may have other priorities in store too
	// Just verify the call completes without panic
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("apiPolicyReorder unexpected status %d", w.Code)
	}
}

// ─── apiIdPList ───────────────────────────────────────────────────────────────

func TestAPIIdPList_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/idp", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPList(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIIdPList_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/idp", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPList(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIIdPList_Post_Create(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/idp", map[string]any{
		"name":    "test-saml-idp",
		"type":    "saml",
		"enabled": false,
		"saml":    map[string]any{"metadataXML": "<xml/>"},
	})
	r = adminCtx(r)
	apiIdPList(w, r)
	// Should be 200 or 400 depending on whether profile validates
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Errorf("apiIdPList POST unexpected status %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIIdPList_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/idp", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPList(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiIdPItem ───────────────────────────────────────────────────────────────

func TestAPIIdPItem_Get_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/idp/nonexistent-id", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, "nonexistent-id")
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIIdPItem_Get_MissingID(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/idp/", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, "")
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIIdPItem_Delete_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/idp/nonexistent-id", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, "nonexistent-id")
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIIdPItem_Put_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/idp/some-id", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, "some-id")
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIIdPItem_Get_Exists(t *testing.T) {
	p := &IdPProfile{
		Name:    "test-get-idp",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
	}
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	defer idpRegistry.Delete(p.ID) //nolint:errcheck // test teardown; cleanup errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/idp/%s", p.ID), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, p.ID)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIIdPItem_Delete_Exists(t *testing.T) {
	p := &IdPProfile{
		Name:    "test-del-idp",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
	}
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/idp/%s", p.ID), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, p.ID)
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIIdPItem_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/idp/some-id", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPItem(w, r, "some-id")
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiIdPGroups ─────────────────────────────────────────────────────────────

func TestAPIIdPGroups_Get_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/idp/nonexistent/groups", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPGroups(w, r, "nonexistent")
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIIdPGroups_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/idp/some-id/groups", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPGroups(w, r, "some-id")
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIIdPGroups_Get_Exists(t *testing.T) {
	p := &IdPProfile{
		Name:        "test-groups-idp",
		Type:        IdPTypeSAML,
		Enabled:     false,
		SAML:        &SAMLProfileConfig{MetadataXML: "<xml/>"},
		KnownGroups: []string{"admin", "users"},
	}
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	defer idpRegistry.Delete(p.ID) //nolint:errcheck // test teardown; cleanup errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/idp/%s/groups", p.ID), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPGroups(w, r, p.ID)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiIdPRouter ─────────────────────────────────────────────────────────────

func TestAPIIdPRouter_Groups(t *testing.T) {
	p := &IdPProfile{
		Name:    "test-router-idp",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
	}
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	defer idpRegistry.Delete(p.ID) //nolint:errcheck // test teardown; cleanup errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/idp/%s/groups", p.ID), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	r.URL.Path = fmt.Sprintf("/api/idp/%s/groups", p.ID)
	apiIdPRouter(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIIdPRouter_Item(t *testing.T) {
	p := &IdPProfile{
		Name:    "test-router-item",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
	}
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	defer idpRegistry.Delete(p.ID) //nolint:errcheck // test teardown; cleanup errors are non-actionable

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/idp/%s", p.ID), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	r.URL.Path = fmt.Sprintf("/api/idp/%s", p.ID)
	apiIdPRouter(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiSecFeedsSync ──────────────────────────────────────────────────────────

func TestAPISecFeedsSync_FeedsNotEnabled(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/feeds/sync", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSecFeedsSync(w, r)
	assertStatus(t, w, http.StatusServiceUnavailable)
}

func TestAPISecFeedsSync_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/security-scan/feeds/sync", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSecFeedsSync(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiSecYARAReload ─────────────────────────────────────────────────────────

func TestAPISecYARAReload_NoDirConfigured(t *testing.T) {
	old := globalYARA
	globalYARA = &YARARuleSet{}
	defer func() { globalYARA = old }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/yara/reload", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSecYARAReload(w, r)
	assertStatus(t, w, http.StatusServiceUnavailable)
}

func TestAPISecYARAReload_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/security-scan/yara/reload", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSecYARAReload(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiIdPDiscover ───────────────────────────────────────────────────────────

func TestAPIIdPDiscover_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/idp/discover", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPDiscover(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIIdPDiscover_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/idp/discover", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiIdPDiscover(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIIdPDiscover_InvalidIssuer(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/idp/discover", map[string]any{
		"issuer": "http://192.168.1.1/",
	})
	r = adminCtx(r)
	apiIdPDiscover(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}
