package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── Phase C5a — HTTP/API end-to-end smoke tests ──────────────────────────
//
// C5a validates the critical admin/control-plane flows through real
// HTTP/API requests, the same way a real operator (or a curl script)
// would use them. The fixture spins up an httptest.Server over the
// FULL middleware chain (uiIPGuardMiddleware → securityMiddleware →
// uiAuthMiddleware → uiMetadataEnforcement → mux), wires three test
// users (admin/operator/viewer), and lets each test drive the API
// with real cookie-based session state.
//
// SCOPE — strict invariants:
//   • Test-only. No production code is modified.
//   • In-process httptest.Server — no os/exec, no Playwright, no new CI
//     job. Runs inside the existing `go test ./...` invocation.
//   • Per-test fixture. Globals (cfg.user, cfg.passHash, cfg.uiUsers,
//     cfg.unauthMode, dataDir) are snapshotted at fixture start and
//     restored in t.Cleanup. Tests are deterministic under
//     -count=2 -shuffle=on.
//   • Audit assertions are content-based (Action + host substring +
//     baseline TS). No len(auditGet()) deltas — the C3.2 ring-
//     saturation pitfall is documented in CLAUDE.md and we follow the
//     canonical pattern.
//   • C2 counter assertions are diff-based (before/after snapshots).

// ── Fixture ──────────────────────────────────────────────────────────────

const (
	e2eAdminUser = "e2e_admin"
	e2eAdminPass = "E2E-Admin-Pwd-1!"
	e2eOpUser    = "e2e_operator"
	e2eOpPass    = "E2E-Operator-Pwd-1!"
	e2eViewUser  = "e2e_viewer"
	e2eViewPass  = "E2E-Viewer-Pwd-1!"
)

// e2eFixture holds the per-test HTTP test server and exposes helpers
// for login, GET, and POST with cookie management.
type e2eFixture struct {
	t   *testing.T
	srv *httptest.Server
}

// newE2EFixture builds a per-test fixture: snapshots global state,
// wires three e2e_* users (admin/operator/viewer), starts an
// httptest.Server over the full middleware chain, and registers a
// t.Cleanup that restores everything to its pre-test state.
//
// Whitebox access to cfg internals is required because DeleteUIUser
// refuses to remove the last admin (correct production guard) — the
// snapshot+restore pattern bypasses that for test cleanup without
// changing production code.
func newE2EFixture(t *testing.T) *e2eFixture {
	t.Helper()

	// 1. Snapshot the cfg fields we are about to mutate.
	cfg.mu.Lock()
	prevUser := cfg.user
	prevPassHash := cfg.passHash
	prevUnauth := cfg.unauthMode
	prevUsers := make(map[string]*uiAdminUser, len(cfg.uiUsers))
	for k, v := range cfg.uiUsers {
		prevUsers[k] = v
	}
	cfg.mu.Unlock()

	// Snapshot the global revocation list. JWT cookies are time-
	// deterministic (Sub + Role + Exp-in-seconds → same b64 payload), so
	// two logins for the same user in the same second produce IDENTICAL
	// JWTs. If a prior test logged out and revoked a JWT for "e2e_viewer"
	// at second T, a fresh login here at the same second T would
	// regenerate the revoked JWT and immediately trip decodeSession's
	// "session: revoked" guard. Snapshot+restore isolates each fixture
	// from any other test's revocations.
	sessionRevoked.mu.Lock()
	prevRevokedTokens := make(map[string]time.Time, len(sessionRevoked.tokens))
	for k, v := range sessionRevoked.tokens {
		prevRevokedTokens[k] = v
	}
	prevRevokedUsers := make(map[string]time.Time, len(sessionRevoked.users))
	for k, v := range sessionRevoked.users {
		prevRevokedUsers[k] = v
	}
	// Reset to empty for this fixture's lifetime so my own logout
	// revocations cannot collide with my own re-logins.
	sessionRevoked.tokens = map[string]time.Time{}
	sessionRevoked.users = map[string]time.Time{}
	sessionRevoked.mu.Unlock()

	prevDataDir := dataDir
	dataDir = t.TempDir()

	// 2. Bootstrap: admin (also enables auth via SetAuth) plus operator and viewer.
	if err := cfg.SetAuth(e2eAdminUser, e2eAdminPass); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if err := cfg.SetUIUser(e2eOpUser, e2eOpPass, RoleOperator); err != nil {
		t.Fatalf("SetUIUser operator: %v", err)
	}
	if err := cfg.SetUIUser(e2eViewUser, e2eViewPass, RoleViewer); err != nil {
		t.Fatalf("SetUIUser viewer: %v", err)
	}

	// 3. Build the full middleware chain — byte-for-byte what startUI assembles.
	handler := uiIPGuardMiddleware(
		securityMiddleware(
			uiAuthMiddleware(
				uiMetadataEnforcement(d0WireMux(t)))))
	srv := httptest.NewServer(handler)

	fx := &e2eFixture{t: t, srv: srv}

	// 4. Cleanup — restore everything.
	t.Cleanup(func() {
		srv.Close()
		cfg.mu.Lock()
		cfg.user = prevUser
		cfg.passHash = prevPassHash
		cfg.unauthMode = prevUnauth
		cfg.uiUsers = prevUsers
		cfg.mu.Unlock()
		cfg.cache.clear()
		sessionRevoked.mu.Lock()
		sessionRevoked.tokens = prevRevokedTokens
		sessionRevoked.users = prevRevokedUsers
		sessionRevoked.mu.Unlock()
		dataDir = prevDataDir
	})

	return fx
}

// loginAs returns an *http.Client with a fresh cookie jar that holds
// the session cookie for the given user. Each call gives an
// independent jar so role-specific bodies don't share session state.
func (fx *e2eFixture) loginAs(user, pass string) *http.Client {
	fx.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		fx.t.Fatalf("cookiejar: %v", err)
	}
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	body := bytes.NewBufferString(`{"user":"` + user + `","pass":"` + pass + `"}`)
	req, _ := http.NewRequest(http.MethodPost, fx.srv.URL+"/api/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		fx.t.Fatalf("login %s: %v", user, err)
	}
	// Drain + close so the underlying connection is returned to the
	// pool cleanly. Without draining, a subsequent request on the same
	// client can race against the server's connection state and the
	// Set-Cookie may not be applied to the next outbound request in
	// time. This is the standard net/http best practice for short-
	// lived test traffic.
	// Drain + close so the underlying connection is returned to the
	// pool cleanly. Without draining, a subsequent request on the same
	// client can race against the server's connection state.
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fx.t.Fatalf("login %s: status=%d body=%s", user, resp.StatusCode, string(respBody))
	}
	return client
}

// anonClient returns a no-cookies client for unauthenticated requests.
func (fx *e2eFixture) anonClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// ── Tests ────────────────────────────────────────────────────────────────

// TestE2E_AuthLifecycle covers the full session lifecycle for each
// role: status before login (anon), login, status after login,
// logout, status after logout.
func TestE2E_AuthLifecycle(t *testing.T) {
	fx := newE2EFixture(t)
	cases := []struct {
		name string
		user string
		pass string
		role UIRole
	}{
		{"admin", e2eAdminUser, e2eAdminPass, RoleAdmin},
		{"operator", e2eOpUser, e2eOpPass, RoleOperator},
		{"viewer", e2eViewUser, e2eViewPass, RoleViewer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Status before login — anon.
			anon := fx.anonClient()
			doc := decodeJSONMap(t, mustGet(t, anon, fx.srv.URL+"/api/auth/status"))
			if v, _ := doc["loggedIn"].(bool); v {
				t.Errorf("anon status loggedIn = true; want false")
			}

			// Login.
			cli := fx.loginAs(tc.user, tc.pass)

			// Status after login — must report user + role.
			doc2 := decodeJSONMap(t, mustGet(t, cli, fx.srv.URL+"/api/auth/status"))
			if v, _ := doc2["loggedIn"].(bool); !v {
				t.Errorf("post-login loggedIn = false; want true")
			}
			if got, _ := doc2["user"].(string); got != tc.user {
				t.Errorf("post-login user = %q; want %q", got, tc.user)
			}
			if got, _ := doc2["role"].(string); got != string(tc.role) {
				t.Errorf("post-login role = %q; want %q", got, tc.role)
			}

			// Logout.
			logoutReq, _ := http.NewRequest(http.MethodPost, fx.srv.URL+"/api/auth/logout", http.NoBody)
			resp, err := cli.Do(logoutReq)
			if err != nil {
				t.Fatalf("logout: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("logout status = %d; want 200", resp.StatusCode)
			}

			// Status after logout — back to anon (the cookie was revoked,
			// so even though the jar still carries it, readUISessionCookie
			// returns no session).
			doc3 := decodeJSONMap(t, mustGet(t, cli, fx.srv.URL+"/api/auth/status"))
			if v, _ := doc3["loggedIn"].(bool); v {
				t.Errorf("post-logout loggedIn = true; want false")
			}
		})
	}
}

// TestE2E_GovernanceRBAC covers RBAC on the C3 governance endpoint:
// anon → 401 (auth middleware), viewer/operator → 403 (handler-level
// requireRole(admin)), admin → 200 with valid JSON.
func TestE2E_GovernanceRBAC(t *testing.T) {
	fx := newE2EFixture(t)
	govURL := fx.srv.URL + "/api/governance/control-plane"

	// Anon → 401 from uiAuthMiddleware (no session cookie, no Basic Auth).
	if got := mustGetCode(t, fx.anonClient(), govURL); got != http.StatusUnauthorized {
		t.Errorf("anon: got %d, want 401", got)
	}

	// Viewer → 403 from handler-level requireRole(admin).
	if got := mustGetCode(t, fx.loginAs(e2eViewUser, e2eViewPass), govURL); got != http.StatusForbidden {
		t.Errorf("viewer: got %d, want 403", got)
	}

	// Operator → 403, same backstop.
	if got := mustGetCode(t, fx.loginAs(e2eOpUser, e2eOpPass), govURL); got != http.StatusForbidden {
		t.Errorf("operator: got %d, want 403", got)
	}

	// Admin → 200 + structurally-valid JSON.
	resp := mustGet(t, fx.loginAs(e2eAdminUser, e2eAdminPass), govURL)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin: got %d, want 200", resp.StatusCode)
	}
	doc := decodeJSONMap(t, resp)
	for _, k := range []string{"schema_version", "routes", "counters", "governance_health", "test_layers"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("admin response missing key %q", k)
		}
	}
}

// TestE2E_AdminMutationAndAudit covers a safe round-trip mutation:
// admin POSTs a deterministic blocklist host, the matching audit
// entry is found by content (not ring length), and DELETE removes
// the host (also recorded). Audit assertion uses the
// content-based scan documented in CLAUDE.md so it stays clean
// under -count=2 -shuffle=on.
func TestE2E_AdminMutationAndAudit(t *testing.T) {
	fx := newE2EFixture(t)
	cli := fx.loginAs(e2eAdminUser, e2eAdminPass)

	const host = "e2e-blocklist-test.example"
	// Belt-and-braces — even if the test fails between POST and DELETE,
	// scrub the global blocklist on the way out.
	t.Cleanup(func() { bl.Remove(host) })

	baseline := time.Now().UnixMilli()

	// POST /api/blocklist {"hosts":["..."]} — admin (operator+ allowed).
	addReq, _ := http.NewRequest(http.MethodPost, fx.srv.URL+"/api/blocklist",
		bytes.NewBufferString(`{"hosts":["`+host+`"]}`))
	addReq.Header.Set("Content-Type", "application/json")
	addResp, err := cli.Do(addReq)
	if err != nil {
		t.Fatalf("POST /api/blocklist: %v", err)
	}
	addResp.Body.Close()
	if addResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/blocklist status = %d; want 200", addResp.StatusCode)
	}

	// Audit entry — content-based scan, NOT len() delta. The Detail
	// field carries the host name (apiBlocklist POST joins body.Hosts
	// into Detail); Object carries the count summary.
	if !findBlocklistAuditEntry(auditGet(), "blocklist.add", host, baseline) {
		t.Errorf("no audit entry found for blocklist.add of %q since TS=%d", host, baseline)
	}

	// DELETE /api/blocklist?host=... — round-trip + cleanup.
	delReq, _ := http.NewRequest(http.MethodDelete,
		fx.srv.URL+"/api/blocklist?host="+host, http.NoBody)
	delResp, err := cli.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE /api/blocklist: %v", err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /api/blocklist status = %d; want 204", delResp.StatusCode)
	}

	// blocklist.remove sets Object=host (single-host path).
	if !findBlocklistAuditEntry(auditGet(), "blocklist.remove", host, baseline) {
		t.Errorf("no audit entry found for blocklist.remove of %q since TS=%d", host, baseline)
	}
}

// TestE2E_CounterCleanlinessOnNavigation walks the same set of admin
// routes a real operator would touch in normal use and asserts that
// none of the C2/C2c/C4 counters move. Catches regressions where a
// route somehow ends up missing from metadata, drops a method
// policy, fails to emit an expected audit, or triggers a role
// divergence on the happy path.
func TestE2E_CounterCleanlinessOnNavigation(t *testing.T) {
	fx := newE2EFixture(t)
	cli := fx.loginAs(e2eAdminUser, e2eAdminPass)

	paths := []string{
		"/api/auth/users",
		"/api/policy",
		"/api/blocklist",
		"/api/audit",
		"/api/diagnostics",
		"/api/cluster/status",
		"/api/idp",
		"/api/governance/control-plane",
	}

	before := c2CounterSnapshot()
	for _, p := range paths {
		resp, err := cli.Get(fx.srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		// Status code is intentionally not asserted — some routes may
		// legitimately 4xx under the test config (e.g. cluster not
		// enrolled). What we pin is C2 counter cleanliness.
	}
	after := c2CounterSnapshot()

	// Per-axis deltas. Admin happy-path navigation must not move ANY
	// C2/C2c/C4 counter — admin meets every per-method MinRole, so
	// even would_deny / enforce_denied should stay at zero. Any
	// movement here indicates a real regression: would_deny means a
	// route declares a MinRole stricter than admin (which doesn't
	// exist), missing_meta means metadata drift, no_policy means a
	// method has no per-method or MethodAny entry, role_divergence
	// means the handler enforces a role stricter than metadata even
	// for an admin session, and audit_missing means a navigated GET
	// silently dropped its expected audit.
	if d := after.WouldDeny - before.WouldDeny; d != 0 {
		t.Errorf("would_deny delta = %d; want 0 (admin should clear every per-method MinRole)", d)
	}
	if d := after.EnforceDenied - before.EnforceDenied; d != 0 {
		t.Errorf("enforce_denied delta = %d; want 0 (admin should never receive a 403 from C2)", d)
	}
	if d := after.MissingMeta - before.MissingMeta; d != 0 {
		t.Errorf("missing_meta delta = %d; want 0 (drift between mux and uiRoutes)", d)
	}
	if d := after.NoPolicy - before.NoPolicy; d != 0 {
		t.Errorf("no_policy delta = %d; want 0 (a navigated route has no method policy?)", d)
	}
	if d := after.RoleDivergence - before.RoleDivergence; d != 0 {
		t.Errorf("role_divergence delta = %d; want 0 (admin should not provoke divergence on read paths)", d)
	}
	if d := after.AuditMissing - before.AuditMissing; d != 0 {
		t.Errorf("audit_missing delta = %d; want 0 (a navigated GET silently dropped its expected audit?)", d)
	}
}

// TestE2E_LogoutInvalidatesSession proves that a session cookie
// presented after logout is rejected. Confirms the
// revokeSessionCookie path actually invalidates the JWT — without
// this guarantee, an attacker who replayed a captured cookie could
// continue acting as the logged-out user.
func TestE2E_LogoutInvalidatesSession(t *testing.T) {
	fx := newE2EFixture(t)
	url := fx.srv.URL + "/api/governance/control-plane"

	cli := fx.loginAs(e2eAdminUser, e2eAdminPass)

	// Sanity: admin can hit governance pre-logout.
	if got := mustGetCode(t, cli, url); got != http.StatusOK {
		t.Fatalf("pre-logout GET = %d; want 200", got)
	}

	// Logout.
	logoutReq, _ := http.NewRequest(http.MethodPost, fx.srv.URL+"/api/auth/logout", http.NoBody)
	if r, err := cli.Do(logoutReq); err != nil {
		t.Fatalf("logout: %v", err)
	} else {
		r.Body.Close()
	}

	// Same client, same (revoked) cookie → must NOT be 200. Pin denial
	// without binding to a specific 4xx code so a future cookie-
	// revocation refactor doesn't break this test unnecessarily.
	if got := mustGetCode(t, cli, url); got == http.StatusOK {
		t.Errorf("post-logout GET = 200; expected denial (auth middleware should reject the revoked session)")
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

func mustGet(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func mustGetCode(t *testing.T, c *http.Client, url string) int {
	t.Helper()
	resp := mustGet(t, c, url)
	resp.Body.Close()
	return resp.StatusCode
}

func decodeJSONMap(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("invalid JSON: %v; body=%s", err, string(body))
	}
	return m
}

// findBlocklistAuditEntry scans newest-first for an audit entry whose
// Action matches and whose Object or Detail mentions the host, with
// TS at or after baseline. Saturation-tolerant by design — see
// security_feedsync_audit_test.go and CLAUDE.md for the canonical
// pattern this mirrors. Used for both blocklist.add (host appears in
// Detail) and blocklist.remove (host appears in Object).
func findBlocklistAuditEntry(snap []AuditEntry, action, host string, sinceTS int64) bool {
	for i := range snap {
		e := snap[i]
		if e.TS < sinceTS {
			continue
		}
		if e.Action != action {
			continue
		}
		if strings.Contains(e.Object, host) || strings.Contains(e.Detail, host) {
			return true
		}
	}
	return false
}
