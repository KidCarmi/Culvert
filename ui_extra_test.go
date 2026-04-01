package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Helper: inject RoleAdmin into request context (same as ui_test.go adminCtx)
// Note: adminCtx is already defined in ui_test.go - use it directly from there
// (same package, so it's available).

// ─── /api/security POST ───────────────────────────────────────────────────────

func TestAPISecurity_Post_IPAdd(t *testing.T) {
	defer func() {
		ipf.Remove("203.0.113.1")
		ipf.SetMode("")
	}()
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/security", map[string]any{
		"ipFilterMode": "block",
		"ipAdd":        "203.0.113.1",
	})
	r = adminCtx(r)
	apiSecurity(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPISecurity_Post_RateLimit(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/security", map[string]any{
		"rateLimitRPM": 100,
	})
	r = adminCtx(r)
	apiSecurity(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPISecurity_Post_InvalidIP(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/security", map[string]any{
		"ipAdd": "not-an-ip",
	})
	r = adminCtx(r)
	apiSecurity(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPISecurity_Post_IPRemove(t *testing.T) {
	_ = ipf.Add("203.0.113.2")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/security", map[string]any{
		"ipRemove": "203.0.113.2",
	})
	r = adminCtx(r)
	apiSecurity(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/settings POST ───────────────────────────────────────────────────────

func TestAPISettings_Post(t *testing.T) {
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/settings", map[string]string{
		"user": "admin",
		"pass": "strongpassword123",
	})
	r = adminCtx(r)
	apiSettings(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPISettings_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/settings", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	apiSettings(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── /api/rewrite DELETE ──────────────────────────────────────────────────────

func TestAPIRewrite_Delete(t *testing.T) {
	rule := rewriter.Add(RewriteRule{Host: "delete-me.com"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/rewrite?id=%d", rule.ID), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiRewrite(w, r)
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIRewrite_Delete_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/rewrite?id=99999", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiRewrite(w, r)
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIRewrite_Delete_BadID(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/rewrite?id=abc", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiRewrite(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── /api/policy PUT and DELETE ──────────────────────────────────────────────

func TestAPIPolicy_Delete(t *testing.T) {
	rule := policyStore.Add(PolicyRule{Priority: 9901, Name: "del-test", Action: "allow"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/policy?priority=%d", rule.Priority), http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIPolicy_Delete_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/policy?priority=999999", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIPolicy_Put_NotFound(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/policy?priority=999999", map[string]any{
		"name":   "updated",
		"action": "Drop",
	})
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusNotFound)
}

func TestAPIPolicy_Add_MissingName(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"action": "allow",
	})
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIPolicy_Add_MissingAction(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/policy", map[string]any{
		"name": "test-rule",
	})
	r = adminCtx(r)
	apiPolicy(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── /api/auth/users DELETE ───────────────────────────────────────────────────

func TestAPIAuthUsers_Delete_Success(t *testing.T) {
	// Add two admins so we can delete one
	_ = cfg.SetUIUser("admin-to-delete", "password123", RoleAdmin)
	_ = cfg.SetUIUser("admin-keeper", "password456", RoleAdmin)
	defer func() {
		cfg.DeleteUIUser("admin-to-delete") //nolint:errcheck // test teardown; cleanup errors are non-actionable
		cfg.DeleteUIUser("admin-keeper")    //nolint:errcheck // test teardown; cleanup errors are non-actionable
	}()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/users?username=admin-to-delete", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiAuthUsers(w, r)
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIAuthUsers_Delete_MissingUsername(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/users", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiAuthUsers(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── misc UI helpers ──────────────────────────────────────────────────────────

func TestOIDCMustRandHex(t *testing.T) {
	h := mustRandHex(16)
	if h == "" {
		t.Error("mustRandHex should return non-empty string")
	}
	h2 := mustRandHex(16)
	if h == h2 {
		t.Error("mustRandHex should be random (two calls should differ)")
	}
}

func TestExtractStringSliceClaim(t *testing.T) {
	claims := map[string]interface{}{
		"groups": []interface{}{"admin", "users"},
		"role":   "operator",
		"empty":  "",
		"other":  123,
	}

	got := extractStringSliceClaim(claims, "groups")
	if len(got) != 2 || got[0] != "admin" {
		t.Errorf("groups claim = %v, want [admin users]", got)
	}

	got = extractStringSliceClaim(claims, "role")
	if len(got) != 1 || got[0] != "operator" {
		t.Errorf("single-string claim = %v, want [operator]", got)
	}

	got = extractStringSliceClaim(claims, "empty")
	if got != nil {
		t.Error("empty string claim should return nil")
	}

	got = extractStringSliceClaim(claims, "missing")
	if got != nil {
		t.Error("missing key should return nil")
	}

	got = extractStringSliceClaim(claims, "other")
	if got != nil {
		t.Error("non-string claim type should return nil")
	}
}

func TestProxyBaseURL(t *testing.T) {
	old := proxyExternalBaseURL
	defer func() { proxyExternalBaseURL = old }()

	// No base URL configured — should return default
	proxyExternalBaseURL = ""
	url := proxyBaseURL()
	if url == "" {
		t.Error("proxyBaseURL should return non-empty default")
	}

	// With base URL configured
	SetProxyBaseURL("https://proxy.corp.com")
	url = proxyBaseURL()
	if url != "https://proxy.corp.com" {
		t.Errorf("proxyBaseURL() = %q, want 'https://proxy.corp.com'", url)
	}
}
