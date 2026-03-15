package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── apiContentScan ───────────────────────────────────────────────────────────

func TestAPIContentScan_Post_Add(t *testing.T) {
	defer dpiScanner.Remove("test-pattern-\\d+")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/content-scan", map[string]any{
		"pattern": "test-pattern-\\d+",
	})
	r = adminCtx(r)
	apiContentScan(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIContentScan_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/content-scan", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiContentScan(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIContentScan_Post_InvalidPattern(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/content-scan", map[string]any{
		"pattern": "[invalid regex(",
	})
	r = adminCtx(r)
	apiContentScan(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIContentScan_Delete(t *testing.T) {
	_ = dpiScanner.Add("delete-this-pattern")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/content-scan?pattern=delete-this-pattern", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiContentScan(w, r)
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIContentScan_Delete_MissingPattern(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/content-scan", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiContentScan(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiSecScanStatus ─────────────────────────────────────────────────────────

func TestAPISecScanStatus_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/security-scan/status", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSecScanStatus(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPISecScanStatus_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/status", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSecScanStatus(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiBlocklistMode ─────────────────────────────────────────────────────────

func TestAPIBlocklistMode_Post_Block(t *testing.T) {
	defer bl.SetMode("block")
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/blocklist/mode", map[string]any{
		"mode": "allow",
	})
	r = adminCtx(r)
	apiBlocklistMode(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIBlocklistMode_Post_Invalid(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/blocklist/mode", map[string]any{
		"mode": "invalid",
	})
	r = adminCtx(r)
	apiBlocklistMode(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIBlocklistMode_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/blocklist/mode", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiBlocklistMode(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIBlocklistMode_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/blocklist/mode", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiBlocklistMode(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── apiTimeseries ────────────────────────────────────────────────────────────

func TestAPITimeseries_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/timeseries", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiTimeseries(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiSessionTimeout ────────────────────────────────────────────────────────

func TestAPISessionTimeout_Post_Valid(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/session-timeout", map[string]any{
		"hours": 4,
	})
	r = adminCtx(r)
	apiSessionTimeout(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPISessionTimeout_Post_OutOfRange(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/session-timeout", map[string]any{
		"hours": 999,
	})
	r = adminCtx(r)
	apiSessionTimeout(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPISessionTimeout_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/session-timeout", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSessionTimeout(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiLogs ──────────────────────────────────────────────────────────────────

func TestAPILogs_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/logs", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiLogs(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPILogs_WithFilters(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/logs?filter=example.com&status=OK&level=INFO&method=GET", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiLogs(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiConfigExport ──────────────────────────────────────────────────────────

func TestAPIConfigExport_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/config/export", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiConfigExport(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiSyslogConfig POST ─────────────────────────────────────────────────────

func TestAPISyslogConfig_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/syslog", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiSyslogConfig(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiDefaultAction extra paths ─────────────────────────────────────────────

func TestAPIDefaultAction_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/default-action", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiDefaultAction(w, r)
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIDefaultAction_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/default-action", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiDefaultAction(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIDefaultAction_Post_InvalidAction(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/default-action", map[string]any{
		"action": "maybe",
	})
	r = adminCtx(r)
	apiDefaultAction(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiAuthUsers extra paths ─────────────────────────────────────────────────

func TestAPIAuthUsers_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiAuthUsers(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIAuthUsers_Post_Create(t *testing.T) {
	defer cfg.DeleteUIUser("newuser-test") //nolint:errcheck // test teardown; cleanup errors are non-actionable
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "newuser-test",
		"password": "strongpassword123",
		"role":     "viewer",
	})
	r = adminCtx(r)
	apiAuthUsers(w, r)
	assertStatus(t, w, http.StatusOK)
}

func TestAPIAuthUsers_Post_ShortPassword(t *testing.T) {
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "testuser",
		"password": "short",
		"role":     "viewer",
	})
	r = adminCtx(r)
	apiAuthUsers(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthUsers_Post_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/users", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiAuthUsers(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}
