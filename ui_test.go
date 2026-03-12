package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// adminCtx returns a request with RoleAdmin injected so requireRole() passes.
func adminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
	return r.WithContext(ctx)
}

// jsonReq builds a request with a JSON body.
func jsonReq(method, path string, body any) *http.Request {
	var buf io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, buf)
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	return adminCtx(r)
}

// getReq builds a plain GET request with admin context.
func getReq(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "127.0.0.1:9999"
	return adminCtx(r)
}

// assertStatus checks the response status code.
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Errorf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
	}
}

// assertJSON checks that the response is valid JSON and optionally checks a field.
func assertJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Errorf("response is not valid JSON: %v; body: %s", err, w.Body.String())
	}
	return m
}

// ─── Middleware helpers ───────────────────────────────────────────────────────

func TestAddUIAllowedCIDR(t *testing.T) {
	// Reset state after test.
	defer func() {
		uiAllowedNetsMu.Lock()
		uiAllowedNets = nil
		uiAllowedNetsMu.Unlock()
	}()

	if err := AddUIAllowedCIDR("10.0.0.0/8"); err != nil {
		t.Fatalf("AddUIAllowedCIDR: %v", err)
	}
	if err := AddUIAllowedCIDR("192.168.1.5"); err != nil {
		t.Fatalf("AddUIAllowedCIDR bare IP: %v", err)
	}
	if err := AddUIAllowedCIDR("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP/CIDR")
	}
	list := ListUIAllowedCIDRs()
	if len(list) != 2 {
		t.Errorf("expected 2 CIDRs, got %v", list)
	}
}

func TestSetUIAllowedCIDRs(t *testing.T) {
	defer func() {
		uiAllowedNetsMu.Lock()
		uiAllowedNets = nil
		uiAllowedNetsMu.Unlock()
	}()

	if err := SetUIAllowedCIDRs([]string{"10.0.0.0/8", "", "192.168.0.0/16"}); err != nil {
		t.Fatalf("SetUIAllowedCIDRs: %v", err)
	}
	if len(ListUIAllowedCIDRs()) != 2 {
		t.Errorf("expected 2 (blank ignored), got %v", ListUIAllowedCIDRs())
	}
	if err := SetUIAllowedCIDRs([]string{"bad-ip"}); err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestUIIPGuardMiddleware_NoList(t *testing.T) {
	// Empty allowlist → all IPs allowed.
	uiAllowedNetsMu.Lock()
	uiAllowedNets = nil
	uiAllowedNetsMu.Unlock()

	reached := false
	handler := uiIPGuardMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"
	handler.ServeHTTP(w, r)
	if !reached {
		t.Error("request should be allowed when allowlist is empty")
	}
}

func TestUIIPGuardMiddleware_Blocked(t *testing.T) {
	defer func() {
		uiAllowedNetsMu.Lock()
		uiAllowedNets = nil
		uiAllowedNetsMu.Unlock()
	}()
	_ = SetUIAllowedCIDRs([]string{"10.0.0.0/8"})

	handler := uiIPGuardMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.1:1234"
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestIsSameOrigin(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "localhost:9090"

	if !isSameOrigin(r, "https://localhost:9090") {
		t.Error("same host:port should be same origin")
	}
	if isSameOrigin(r, "https://evil.com") {
		t.Error("different host should not be same origin")
	}
	if !isSameOrigin(r, "") {
		t.Error("empty origin should return true")
	}
}

func TestSecurityMiddleware_Headers(t *testing.T) {
	handler := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("X-Frame-Options should be DENY")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options should be nosniff")
	}
}

func TestSecurityMiddleware_OPTIONS(t *testing.T) {
	handler := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/", nil))
	if w.Code != http.StatusNoContent {
		t.Errorf("OPTIONS should return 204, got %d", w.Code)
	}
}

// ─── /api/setup ───────────────────────────────────────────────────────────────

func TestAPISetupStatus_NeedsSetup(t *testing.T) {
	// Reset auth so needsSetup = true.
	origUser := cfg.GetUser()
	_ = cfg.SetAuth("", "")
	defer func() { _ = cfg.SetAuth(origUser, "") }()

	w := httptest.NewRecorder()
	apiSetupStatus(w, getReq("/api/setup/status"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if m["needsSetup"] != true {
		t.Errorf("needsSetup = %v, want true", m["needsSetup"])
	}
}

func TestAPISetupStatus_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiSetupStatus(w, jsonReq(http.MethodPost, "/api/setup/status", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPISetupComplete_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiSetupComplete(w, getReq("/api/setup/complete"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPISetupComplete_AlreadyDone(t *testing.T) {
	// Configure auth so "already complete" path is taken.
	_ = cfg.SetAuth("admin", "testpassword123")
	defer func() { _ = cfg.SetAuth("", "") }()

	w := httptest.NewRecorder()
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "newuser", "pass": "newpassword",
	}))
	assertStatus(t, w, http.StatusForbidden)
}

func TestAPISetupComplete_ShortPassword(t *testing.T) {
	_ = cfg.SetAuth("", "") // ensure no auth configured
	w := httptest.NewRecorder()
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "admin", "pass": "short",
	}))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPISetupComplete_UnauthMode(t *testing.T) {
	_ = cfg.SetAuth("", "")
	defer func() { cfg.SetUnauthMode(false) }()

	w := httptest.NewRecorder()
	initSecret(t)
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"unauth": true,
	}))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/auth ────────────────────────────────────────────────────────────────

func TestAPIAuthStatus_NoAuth(t *testing.T) {
	_ = cfg.SetAuth("", "")
	w := httptest.NewRecorder()
	apiAuthStatus(w, getReq("/api/auth/status"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if m["loggedIn"] != true {
		t.Errorf("loggedIn = %v, want true (no auth configured)", m["loggedIn"])
	}
}

func TestAPIAuthStatus_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthStatus(w, jsonReq(http.MethodPost, "/api/auth/status", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIAuthLogin_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthLogin(w, getReq("/api/auth/login"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIAuthLogin_NoAuth(t *testing.T) {
	_ = cfg.SetAuth("", "")
	initSecret(t)

	w := httptest.NewRecorder()
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", map[string]string{
		"user": "anyone", "pass": "anything",
	}))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if m["ok"] != true {
		t.Errorf("expected ok=true when auth disabled, got %v", m)
	}
}

func TestAPIAuthLogin_InvalidCredentials(t *testing.T) {
	_ = cfg.SetAuth("admin", "correct-password-123")
	defer func() { _ = cfg.SetAuth("", "") }()
	initSecret(t)

	// Reset lockout counter for this user to avoid test pollution.
	loginLimiter.RecordSuccess("admin")

	w := httptest.NewRecorder()
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", map[string]string{
		"user": "admin", "pass": "wrong",
	}))
	assertStatus(t, w, http.StatusUnauthorized)
}

func TestAPIAuthLogin_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader("not json"))
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthLogin(w, r)
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthLogout_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthLogout(w, getReq("/api/auth/logout"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIAuthLogout_OK(t *testing.T) {
	initSecret(t)
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/logout", nil)
	apiAuthLogout(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/auth/users ─────────────────────────────────────────────────────────

func TestAPIAuthUsers_List(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthUsers(w, getReq("/api/auth/users"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["users"]; !ok {
		t.Error("response should contain 'users' field")
	}
}

func TestAPIAuthUsers_Create(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]string{
		"username": "testoperator",
		"password": "operatorpass123",
		"role":     "operator",
	}))
	assertStatus(t, w, http.StatusOK)
	// Cleanup
	_ = cfg.DeleteUIUser("testoperator")
}

func TestAPIAuthUsers_Create_BadRole(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]string{
		"username": "u", "password": "longpass123", "role": "superuser",
	}))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthUsers_Create_ShortPassword(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]string{
		"username": "u", "password": "short", "role": "admin",
	}))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthUsers_Delete_Missing(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/users", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthUsers(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthUsers_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/auth/users", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthUsers(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/stats ───────────────────────────────────────────────────────────────

func TestAPIStats(t *testing.T) {
	w := httptest.NewRecorder()
	apiStats(w, getReq("/api/stats"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["total"]; !ok {
		t.Error("stats response missing 'total' field")
	}
}

// apiStats accepts any HTTP method — no method restriction.

// ─── /api/timeseries ─────────────────────────────────────────────────────────

func TestAPITimeseries(t *testing.T) {
	w := httptest.NewRecorder()
	apiTimeseries(w, getReq("/api/timeseries"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/logs ────────────────────────────────────────────────────────────────

func TestAPILogs(t *testing.T) {
	w := httptest.NewRecorder()
	apiLogs(w, getReq("/api/logs"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/top-hosts ───────────────────────────────────────────────────────────

func TestAPITopHosts(t *testing.T) {
	w := httptest.NewRecorder()
	apiTopHosts(w, getReq("/api/top-hosts"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/audit ───────────────────────────────────────────────────────────────

func TestAPIAudit_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiAudit(w, getReq("/api/audit"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIAudit_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiAudit(w, jsonReq(http.MethodPost, "/api/audit", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/blocklist ───────────────────────────────────────────────────────────

func TestAPIBlocklist_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiBlocklist(w, getReq("/api/blocklist"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIBlocklist_Add(t *testing.T) {
	w := httptest.NewRecorder()
	apiBlocklist(w, jsonReq(http.MethodPost, "/api/blocklist", map[string]string{
		"host": "testblock.example.com",
	}))
	assertStatus(t, w, http.StatusOK)
	// Cleanup
	bl.Remove("testblock.example.com")
}

func TestAPIBlocklist_AddBadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/blocklist", strings.NewReader("bad"))
	r.RemoteAddr = "127.0.0.1:9999"
	apiBlocklist(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIBlocklist_Delete(t *testing.T) {
	bl.Add("todelete.example.com")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/blocklist?host=todelete.example.com", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiBlocklist(w, adminCtx(r))
	// DELETE returns 204 No Content on success
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIBlocklist_DeleteMissing(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/blocklist", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiBlocklist(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── /api/blocklist/mode ─────────────────────────────────────────────────────

func TestAPIBlocklistMode_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiBlocklistMode(w, getReq("/api/blocklist/mode"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["mode"]; !ok {
		t.Error("response missing 'mode' field")
	}
}

func TestAPIBlocklistMode_Set(t *testing.T) {
	w := httptest.NewRecorder()
	apiBlocklistMode(w, jsonReq(http.MethodPost, "/api/blocklist/mode", map[string]string{
		"mode": "allow", // valid values: "block" or "allow"
	}))
	assertStatus(t, w, http.StatusOK)
	// Reset
	bl.SetMode("block")
}

// ─── /api/policy ─────────────────────────────────────────────────────────────

func TestAPIPolicy_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiPolicy(w, getReq("/api/policy"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIPolicy_Add(t *testing.T) {
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq(http.MethodPost, "/api/policy", PolicyRule{
		Priority: 999, Name: "test-rule", Action: ActionAllow,
	}))
	assertStatus(t, w, http.StatusOK)
	// Cleanup
	policyStore.Delete(999)
}

func TestAPIPolicy_BadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/policy", strings.NewReader("bad"))
	r.RemoteAddr = "127.0.0.1:9999"
	apiPolicy(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIPolicy_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/policy", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiPolicy(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/ssl-bypass ─────────────────────────────────────────────────────────

func TestAPISSLBypass_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiSSLBypass(w, getReq("/api/ssl-bypass"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPISSLBypass_Add(t *testing.T) {
	w := httptest.NewRecorder()
	apiSSLBypass(w, jsonReq(http.MethodPost, "/api/ssl-bypass", map[string]string{
		"pattern": "bypass-test.example.com",
	}))
	assertStatus(t, w, http.StatusOK)
	// Cleanup
	sslBypass.Remove("bypass-test.example.com")
}

func TestAPISSLBypass_Delete(t *testing.T) {
	_ = sslBypass.Add("delete-me.example.com")
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/ssl-bypass?pattern=delete-me.example.com", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSSLBypass(w, adminCtx(r))
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPISSLBypass_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/ssl-bypass", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSSLBypass(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/content-scan ───────────────────────────────────────────────────────

func TestAPIContentScan_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiContentScan(w, getReq("/api/content-scan"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIContentScan_Add(t *testing.T) {
	w := httptest.NewRecorder()
	apiContentScan(w, jsonReq(http.MethodPost, "/api/content-scan", map[string]any{
		"patterns": []string{"sensitive-pattern"},
	}))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIContentScan_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/content-scan", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiContentScan(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/rewrite ────────────────────────────────────────────────────────────

func TestAPIRewrite_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiRewrite(w, getReq("/api/rewrite"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIRewrite_Add(t *testing.T) {
	w := httptest.NewRecorder()
	apiRewrite(w, jsonReq(http.MethodPost, "/api/rewrite", RewriteRule{
		Host:   "test.example.com",
		ReqSet: map[string]string{"X-Test": "1"},
	}))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/pac-config ─────────────────────────────────────────────────────────

func TestAPIPACConfig_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiPACConfig(w, getReq("/api/pac-config"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["proxyPort"]; !ok {
		t.Error("response missing 'proxyPort'")
	}
}

func TestAPIPACConfig_Set(t *testing.T) {
	w := httptest.NewRecorder()
	apiPACConfig(w, jsonReq(http.MethodPost, "/api/pac-config", PACConfig{
		ProxyHost: "proxy.corp.com",
		ProxyPort: 3128,
	}))
	assertStatus(t, w, http.StatusOK)
	// Reset
	_ = pacStore.Set(PACConfig{})
}

func TestAPIPACConfig_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/pac-config", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiPACConfig(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/default-action ─────────────────────────────────────────────────────

func TestAPIDefaultAction_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiDefaultAction(w, getReq("/api/default-action"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIDefaultAction_Set(t *testing.T) {
	w := httptest.NewRecorder()
	apiDefaultAction(w, jsonReq(http.MethodPost, "/api/default-action", map[string]string{
		"action": "allow",
	}))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/security ───────────────────────────────────────────────────────────

func TestAPISecurity_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiSecurity(w, getReq("/api/security"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["rateLimitRPM"]; !ok {
		t.Error("security response missing 'rateLimitRPM'")
	}
}

func TestAPISecurity_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/security", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSecurity(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/security-scan/status ───────────────────────────────────────────────

func TestAPISecScanStatus(t *testing.T) {
	w := httptest.NewRecorder()
	apiSecScanStatus(w, getReq("/api/security-scan/status"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/session-timeout ────────────────────────────────────────────────────

func TestAPISessionTimeout_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiSessionTimeout(w, getReq("/api/session-timeout"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["hours"]; !ok {
		t.Error("response missing 'hours'")
	}
}

func TestAPISessionTimeout_Set(t *testing.T) {
	origTTL := getSessionTTL()
	defer SetSessionTTL(origTTL)

	w := httptest.NewRecorder()
	apiSessionTimeout(w, jsonReq(http.MethodPost, "/api/session-timeout", map[string]any{
		"hours": 4,
	}))
	assertStatus(t, w, http.StatusOK)
}

func TestAPISessionTimeout_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/session-timeout", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSessionTimeout(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/ui-allow-ips ───────────────────────────────────────────────────────

func TestAPIUIAllowIPs_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiUIAllowIPs(w, getReq("/api/ui-allow-ips"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIUIAllowIPs_Set(t *testing.T) {
	defer func() {
		uiAllowedNetsMu.Lock()
		uiAllowedNets = nil
		uiAllowedNetsMu.Unlock()
	}()
	w := httptest.NewRecorder()
	apiUIAllowIPs(w, jsonReq(http.MethodPost, "/api/ui-allow-ips", map[string]any{
		"ips": []string{"10.0.0.0/8"},
	}))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/syslog ─────────────────────────────────────────────────────────────

func TestAPISyslogConfig_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiSyslogConfig(w, getReq("/api/syslog"))
	assertStatus(t, w, http.StatusOK)
}

func TestAPISyslogConfig_Disable(t *testing.T) {
	w := httptest.NewRecorder()
	apiSyslogConfig(w, jsonReq(http.MethodPost, "/api/syslog", map[string]string{
		"addr": "",
	}))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/country-traffic ────────────────────────────────────────────────────

func TestAPICountryTraffic(t *testing.T) {
	w := httptest.NewRecorder()
	apiCountryTraffic(w, getReq("/api/country-traffic"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/fileblock ──────────────────────────────────────────────────────────

func TestAPIFileblock_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiFileblock(w, getReq("/api/fileblock"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/settings ───────────────────────────────────────────────────────────

func TestAPISettings_Get(t *testing.T) {
	w := httptest.NewRecorder()
	apiSettings(w, getReq("/api/settings"))
	assertStatus(t, w, http.StatusOK)
}

// ─── /api/config/export ──────────────────────────────────────────────────────

func TestAPIConfigExport(t *testing.T) {
	w := httptest.NewRecorder()
	apiConfigExport(w, getReq("/api/config/export"))
	assertStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Error("config export should be a download (Content-Disposition: attachment)")
	}
}

func TestAPIConfigExport_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiConfigExport(w, jsonReq(http.MethodPost, "/api/config/export", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/policy/test ────────────────────────────────────────────────────────

func TestAPIPolicyTest(t *testing.T) {
	w := httptest.NewRecorder()
	apiPolicyTest(w, jsonReq(http.MethodPost, "/api/policy/test", map[string]any{
		"sourceIP":   "10.0.0.1",
		"host":       "example.com",
		"identity":   "",
		"authSource": "",
		"groups":     []string{},
	}))
	assertStatus(t, w, http.StatusOK)
}

func TestAPIPolicyTest_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiPolicyTest(w, getReq("/api/policy/test"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/policy/reorder ─────────────────────────────────────────────────────

func TestAPIPolicyReorder_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiPolicyReorder(w, getReq("/api/policy/reorder"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── requireRole / uiRole helpers ────────────────────────────────────────────

func TestRequireRole_Pass(t *testing.T) {
	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequest(http.MethodGet, "/", nil))
	if !requireRole(w, r, RoleAdmin) {
		t.Error("requireRole should pass for admin")
	}
}

func TestRequireRole_Fail(t *testing.T) {
	w := httptest.NewRecorder()
	// No role in context → defaults to RoleViewer.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	if requireRole(w, r, RoleAdmin) {
		t.Error("requireRole should fail for viewer trying admin route")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestUIRole_NoContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	role := uiRole(r)
	if role != RoleViewer {
		t.Errorf("uiRole with no context = %q, want %q", role, RoleViewer)
	}
}
