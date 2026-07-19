package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ─── Test helpers ─────────────────────────────────────────────────────────────

// adminCtx returns a request with RoleAdmin injected so requireRole() passes.
func adminCtx(r *http.Request) *http.Request {
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
	return r.WithContext(ctx)
}

// resetSetupLockout clears the per-IP lockout state apiSetupComplete uses
// when validation fails. Without this, the lockout counter LEAKS ACROSS
// tests (every TestAPISetupComplete_* test that hits a 4xx path triggers
// loginLimiter.RecordFailure on the same ("127.0.0.1", "setup") pair), so
// after ~5 attempts in a single suite run the next test gets a 429 instead
// of the expected 4xx — a flake that surfaces under -count>1 / -shuffle=on.
// Tests calling apiSetupComplete should defer or invoke this helper.
func resetSetupLockout() {
	loginLimiter.ResetUser("setup")
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
	r := httptest.NewRequest(http.MethodGet, path, http.NoBody)
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
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
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
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "192.168.1.1:1234"
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestIsSameOrigin(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
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
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

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
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodOptions, "/", http.NoBody))
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
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	w := httptest.NewRecorder()
	apiSetupComplete(w, getReq("/api/setup/complete"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPISetupComplete_AlreadyDone(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
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
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	_ = cfg.SetAuth("", "") // ensure no auth configured
	w := httptest.NewRecorder()
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "admin", "pass": "short",
	}))
	assertStatus(t, w, http.StatusBadRequest)
}

// TestAPISetupComplete_PasswordTooLong proves the first-time setup wizard
// rejects an over-long password with a clean 400, not a bcrypt internals leak.
// bcrypt.GenerateFromPassword errors on any password over 72 bytes
// (golang.org/x/crypto's documented limit), but validatePasswordComplexity
// only enforces a minimum length — so an admin pasting a long password-manager
// password (a very plausible first-run action) previously hit SetAuth's
// bcrypt error and got a raw 500 "internal error: bcrypt: password length
// exceeds 72 bytes" instead of the same 400 validation response every other
// weak-password case gets.
func TestAPISetupComplete_PasswordTooLong(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	_ = cfg.SetAuth("", "") // ensure no auth configured
	defer func() { _ = cfg.SetAuth("", "") }()

	longPass := "Aa1" + strings.Repeat("x", 70) // 73 bytes, otherwise valid
	w := httptest.NewRecorder()
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "admin", "pass": longPass,
	}))
	assertStatus(t, w, http.StatusBadRequest)
	if cfg.IsConfigured() {
		t.Error("setup must not be marked complete when the password is rejected")
	}
}

func TestAPISetupComplete_UnauthMode(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	_ = cfg.SetAuth("", "")
	defer func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) }()

	w := httptest.NewRecorder()
	initSecret(t)
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"unauth": true,
	}))
	assertStatus(t, w, http.StatusOK)
}

// TestAPISetupComplete_ConcurrentRequests_OnlyOneWins proves apiSetupComplete's
// "callable once" contract holds under concurrency. The handler reads
// cfg.IsConfigured() and only later calls cfg.SetAuth — a classic
// check-then-act TOCTOU gap. On the real first-boot setup wizard, the
// endpoint is reachable by anyone on the network before an admin account
// exists, so a second requester racing the legitimate admin's first POST
// must not also be able to provision a credential set.
func TestAPISetupComplete_ConcurrentRequests_OnlyOneWins(t *testing.T) {
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	_ = cfg.SetAuth("", "")
	defer func() { _ = cfg.SetAuth("", "") }()
	initSecret(t)

	const n = 20
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			body := map[string]any{
				"user": fmt.Sprintf("admin%d", i),
				"pass": "Password123",
			}
			apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", body))
			codes[i] = w.Code
		}(i)
	}
	wg.Wait()

	successes := 0
	for _, c := range codes {
		if c == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 of %d concurrent /api/setup/complete requests to succeed, got %d successes; codes=%v", n, successes, codes)
	}
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
	loginLimiter.ResetUser("admin")

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
		"password": "Operator1pass",
		"role":     "operator",
	}))
	assertStatus(t, w, http.StatusOK)
	// Cleanup
	_ = cfg.DeleteUIUser("testoperator")
}

func TestAPIAuthUsers_Create_BadRole(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]string{
		"username": "u", "password": "LongPass1", "role": "superuser",
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
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/users", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthUsers(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthUsers_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/auth/users", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthUsers(w, adminCtx(r))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// ─── /api/auth/lockouts ────────────────────────────────────────────────────

func TestAPIAuthLockouts_List_Empty(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthLockouts(w, getReq("/api/auth/lockouts"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["lockouts"]; !ok {
		t.Error("response should contain 'lockouts' field")
	}
}

func TestAPIAuthLockouts_List_RejectsViewer(t *testing.T) {
	// The listing includes usernames and pair-lock source IPs — the same
	// authentication-telemetry sensitivity as GET /api/auth/users, which
	// is also admin-only. A viewer must not be able to enumerate it.
	r := httptest.NewRequest(http.MethodGet, "/api/auth/lockouts", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiAuthLockouts(w, withRoleCtx(r, RoleViewer))
	assertStatus(t, w, http.StatusForbidden)
}

func TestAPIAuthLockouts_List_ReportsActiveLockout(t *testing.T) {
	defer loginLimiter.ResetUser("lockoutlisttest")
	for range lockoutMaxAttempts {
		loginLimiter.RecordFailure("198.51.100.50", "lockoutlisttest")
	}

	w := httptest.NewRecorder()
	apiAuthLockouts(w, getReq("/api/auth/lockouts"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	entries, _ := m["lockouts"].([]any)
	found := false
	for _, e := range entries {
		entry, _ := e.(map[string]any)
		if entry["username"] == "lockoutlisttest" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a lockout entry for lockoutlisttest, got: %v", entries)
	}
}

func TestAPIAuthLockouts_Unlock_ClearsLockout(t *testing.T) {
	for range lockoutMaxAttempts {
		loginLimiter.RecordFailure("198.51.100.51", "lockoutunlocktest")
	}
	if locked, _ := loginLimiter.Check("198.51.100.51", "lockoutunlocktest"); !locked {
		t.Fatal("precondition: account should be locked")
	}

	w := httptest.NewRecorder()
	apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts", map[string]string{"username": "lockoutunlocktest"}))
	assertStatus(t, w, http.StatusOK)

	if locked, _ := loginLimiter.Check("198.51.100.51", "lockoutunlocktest"); locked {
		t.Error("account should no longer be locked after unlock")
	}
}

func TestAPIAuthLockouts_Unlock_MissingUsername(t *testing.T) {
	w := httptest.NewRecorder()
	apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts", map[string]string{"username": "  "}))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestAPIAuthLockouts_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/auth/lockouts", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiAuthLockouts(w, adminCtx(r))
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

// TestAPIStats_LogPersistenceFields proves the operator-blind-spot fix:
// GET /api/stats must distinguish "log persistence never configured" from
// "configured but silently fell back to in-memory storage" — a state that
// previously showed up only in a startup log line (observability_startup.go).
func TestAPIStats_LogPersistenceFields(t *testing.T) {
	restoreAudit := audit.ResetForTest()
	restoreReqlog := reqlog.SwapPersistenceForTest()
	oldAuditPath, oldReqPath := auditLogConfiguredPath, requestLogConfiguredPath
	t.Cleanup(func() {
		restoreAudit()
		restoreReqlog()
		auditLogConfiguredPath, requestLogConfiguredPath = oldAuditPath, oldReqPath
	})

	// Neither log configured: both "Configured" flags false, and the
	// dashboard must not report a degraded state for a setup that was never
	// asked to persist anything.
	auditLogConfiguredPath, requestLogConfiguredPath = "", ""
	w := httptest.NewRecorder()
	apiStats(w, getReq("/api/stats"))
	m := assertJSON(t, w)
	if m["auditLogConfigured"] != false || m["requestLogConfigured"] != false {
		t.Errorf("expected both *LogConfigured false with no path set, got %v / %v", m["auditLogConfigured"], m["requestLogConfigured"])
	}
	if m["auditLogPersisted"] != false || m["requestLogPersisted"] != false {
		t.Errorf("expected both *LogPersisted false with no engine wired, got %v / %v", m["auditLogPersisted"], m["requestLogPersisted"])
	}

	// A path was configured but Init never succeeded (simulates the silent
	// fallback in loadObservability): Configured=true, Persisted=false —
	// the exact combination the GUI now needs to warn on.
	auditLogConfiguredPath = "/var/log/culvert/audit.jsonl"
	requestLogConfiguredPath = "/var/log/culvert/request.jsonl"
	w = httptest.NewRecorder()
	apiStats(w, getReq("/api/stats"))
	m = assertJSON(t, w)
	if m["auditLogConfigured"] != true || m["auditLogPersisted"] != false {
		t.Errorf("expected audit log Configured=true/Persisted=false (fallback), got Configured=%v Persisted=%v", m["auditLogConfigured"], m["auditLogPersisted"])
	}
	if m["requestLogConfigured"] != true || m["requestLogPersisted"] != false {
		t.Errorf("expected request log Configured=true/Persisted=false (fallback), got Configured=%v Persisted=%v", m["requestLogConfigured"], m["requestLogPersisted"])
	}
	if m["auditLogPath"] != auditLogConfiguredPath {
		t.Errorf("auditLogPath = %v; want %v", m["auditLogPath"], auditLogConfiguredPath)
	}
	if m["requestLogPath"] != requestLogConfiguredPath {
		t.Errorf("requestLogPath = %v; want %v", m["requestLogPath"], requestLogConfiguredPath)
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
	r := httptest.NewRequest(http.MethodDelete, "/api/blocklist?host=todelete.example.com", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiBlocklist(w, adminCtx(r))
	// DELETE returns 204 No Content on success
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPIBlocklist_DeleteMissing(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodDelete, "/api/blocklist", http.NoBody)
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
	r := httptest.NewRequest(http.MethodPatch, "/api/policy", http.NoBody)
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
	r := httptest.NewRequest(http.MethodDelete, "/api/ssl-bypass?pattern=delete-me.example.com", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	apiSSLBypass(w, adminCtx(r))
	assertStatus(t, w, http.StatusNoContent)
}

func TestAPISSLBypass_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPatch, "/api/ssl-bypass", http.NoBody)
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
	r := httptest.NewRequest(http.MethodPatch, "/api/content-scan", http.NoBody)
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
	r := httptest.NewRequest(http.MethodDelete, "/api/pac-config", http.NoBody)
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
	r := httptest.NewRequest(http.MethodDelete, "/api/security", http.NoBody)
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
	r := httptest.NewRequest(http.MethodDelete, "/api/session-timeout", http.NoBody)
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
	r := adminCtx(httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	if !requireRole(w, r, RoleAdmin) {
		t.Error("requireRole should pass for admin")
	}
}

func TestRequireRole_Fail(t *testing.T) {
	w := httptest.NewRecorder()
	// No role in context → defaults to RoleViewer.
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	if requireRole(w, r, RoleAdmin) {
		t.Error("requireRole should fail for viewer trying admin route")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestUIRole_NoContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	role := uiRole(r)
	if role != RoleViewer {
		t.Errorf("uiRole with no context = %q, want %q", role, RoleViewer)
	}
}
