package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── apiConfigImport ──────────────────────────────────────────────────────────

func TestAPIConfigImport_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/config/import", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiConfigImport(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIConfigImport_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/config/import", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiConfigImport(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIConfigImport_WrongVersion(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/config/import", map[string]any{
		"version": 2,
	})
	r = adminCtx(r)
	apiConfigImport(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIConfigImport_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/config/import", map[string]any{
		"version":        1,
		"exportedAt":     "2026-01-01T00:00:00Z",
		"blocklistMode":  "block",
		"blocklist":      []string{},
		"policyRules":    []any{},
		"defaultAction":  "allow",
		"rewriteRules":   []any{},
		"sslBypass":      []string{},
		"contentScanPatterns": []string{},
		"fileBlockExtensions": []string{},
		"ipFilterMode":   "",
		"ipList":         []string{},
		"rateLimitRPM":   0,
	})
	r = adminCtx(r)
	apiConfigImport(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiExport ────────────────────────────────────────────────────────────────

func TestAPIExport_JSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/export", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiExport(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIExport_CSV(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/export?format=csv", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiExport(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiCACert ────────────────────────────────────────────────────────────────

func TestAPICACert_Get_NotInitialized(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/ca-cert", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	// certMgr may or may not be initialized - either 200 or 503 is acceptable
	apiCACert(w, r)
	if w.Code != http.StatusOK && w.Code != http.StatusServiceUnavailable {
		t.Errorf("apiCACert unexpected status %d", w.Code)
	}
}

func TestAPICACert_Get_JSON(t *testing.T) {
	// Init CA first
	if err := certMgr.InitCA(); err != nil {
		t.Skipf("InitCA failed: %v", err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/ca-cert", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("Accept", "application/json")
	r = adminCtx(r)
	apiCACert(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPICACert_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/ca-cert", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiCACert(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiCertsUpload ───────────────────────────────────────────────────────────

func TestAPICertsUpload_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/certs/upload", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiCertsUpload(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPICertsUpload_BadForm(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/certs/upload", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiCertsUpload(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── authLogout ───────────────────────────────────────────────────────────────

func TestAuthLogout(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	authLogout(w, r)
	if w.Code != http.StatusFound {
		t.Errorf("authLogout status = %d, want 302", w.Code)
	}
}

// ─── authSelectProvider ───────────────────────────────────────────────────────

func TestAuthSelectProvider_NoProviders(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/select", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	authSelectProvider(w, r)
	// Should return some status (200 or redirect) without panic
	if w.Code == 0 {
		t.Error("authSelectProvider should write a response")
	}
}

// ─── authOIDCCallback ─────────────────────────────────────────────────────────

func TestAuthOIDCCallback_MissingParams(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	authOIDCCallback(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAuthOIDCCallback_InvalidState(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=testcode&state=invalidstate", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	authOIDCCallback(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── authSAMLCallback ─────────────────────────────────────────────────────────

func TestAuthSAMLCallback_MissingRelayState(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/saml/callback", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	authSAMLCallback(w, r)
	// Should return an error status
	if w.Code == http.StatusOK {
		t.Error("authSAMLCallback with no relay state should not return 200")
	}
}
