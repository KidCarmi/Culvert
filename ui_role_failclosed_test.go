package main

// ui_role_failclosed_test.go — SEC-RBAC-ROLE-1.
//
// Gates for the three layers that together let a role string no build enrolls
// become ADMIN:
//
//	(1) HasRole treated an unenrolled REQUIREMENT as priority 0, i.e. as a
//	    requirement every authenticated role satisfied;
//	(2) LoadUIUsersFile admitted any role string from disk verbatim, while the
//	    admin API rejected the same value;
//	(3) uiAuthMiddleware / apiAuthStatus promoted every role below viewer —
//	    which includes every unenrolled string, not just the pre-RBAC empty
//	    value the branch was written for — to RoleAdmin.
//
// Each DEFECT gate below was verified failing against the pre-fix tree. The
// CONTROL gates exist because the cheapest way to pass the defect gates is to
// refuse more than the defect required: refusing the EMPTY session role locks
// pre-RBAC single-admin deployments out of their own appliance, and dropping a
// clamped roster record deletes an account off a file the operator can repair.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// ─── Layer 1: the comparison primitive ───────────────────────────────────────

// DEFECT GATE. An unenrolled requirement must be unsatisfiable. Pre-fix,
// rolePriority[min] read 0 for every one of these and all three roles passed.
func TestRoleFailClosed_UnenrolledRequirementIsUnsatisfiable(t *testing.T) {
	// Boundary + malformed-input set: the sentinel, case variants of real
	// roles, whitespace-padded reals, a plausible future role, and empty.
	unenrolled := []UIRole{
		RolePublic, "", " ", "Admin", "ADMIN", "admin ", " viewer", "Viewer",
		"superuser", "root", "auditor", "read-only", "operator\n", "0", "3",
	}
	for _, min := range unenrolled {
		for _, have := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
			if have.HasRole(min) {
				t.Errorf("HasRole: role %q satisfied unenrolled requirement %q — "+
					"an unenrolled requirement must be unsatisfiable", have, min)
			}
		}
	}
}

// CONTROL. The fix must not make the ordinary role lattice stricter: refusing
// everything would pass the defect gate above while disabling the admin UI.
func TestRoleFailClosed_EnrolledLatticeUnchanged(t *testing.T) {
	type c struct {
		have, min UIRole
		want      bool
	}
	for _, tc := range []c{
		{RoleViewer, RoleViewer, true}, {RoleViewer, RoleOperator, false}, {RoleViewer, RoleAdmin, false},
		{RoleOperator, RoleViewer, true}, {RoleOperator, RoleOperator, true}, {RoleOperator, RoleAdmin, false},
		{RoleAdmin, RoleViewer, true}, {RoleAdmin, RoleOperator, true}, {RoleAdmin, RoleAdmin, true},
	} {
		if got := tc.have.HasRole(tc.min); got != tc.want {
			t.Errorf("HasRole(%q, %q) = %v, want %v", tc.have, tc.min, got, tc.want)
		}
	}
	// The receiver half must keep failing closed too — POST /api/auth/users
	// uses exactly this shape as its role validator.
	for _, bogus := range []UIRole{"", RolePublic, "superuser", "Admin"} {
		if bogus.HasRole(RoleViewer) {
			t.Errorf("role validator: %q accepted as >= viewer", bogus)
		}
	}
}

func TestRoleFailClosed_RoleEnrolledInventory(t *testing.T) {
	for _, r := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
		if !roleEnrolled(r) {
			t.Errorf("roleEnrolled(%q) = false, want true", r)
		}
	}
	for _, r := range []UIRole{"", RolePublic, "Admin", "superuser"} {
		if roleEnrolled(r) {
			t.Errorf("roleEnrolled(%q) = true, want false", r)
		}
	}
}

// Concurrency: HasRole is read from every gated request and from the C2
// middleware simultaneously. Nothing it touches may be mutated.
func TestRoleFailClosed_ConcurrentHasRoleIsStable(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				if UIRole("superuser").HasRole(RoleViewer) ||
					RoleViewer.HasRole(RolePublic) ||
					!RoleAdmin.HasRole(RoleViewer) {
					t.Error("HasRole answered inconsistently under concurrency")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// ─── Layer 1b: the route-metadata wall ───────────────────────────────────────

// WALL. Nothing pinned that a non-public route never carries an unenrolled
// MinRole. With the pre-fix HasRole such an entry silently admitted every
// authenticated session — including a viewer — to that method, leaving the
// handler's own requireRole as the only gate (and 12 routes document that they
// have none). The wall holds whether or not HasRole fails closed.
func TestRoleMetadata_MinRoleIsAlwaysEnrolled(t *testing.T) {
	checked, publicSeen := 0, 0
	for _, rt := range uiRoutes {
		for _, m := range rt.Methods {
			if m.MinRole == RolePublic {
				publicSeen++
				if !rt.Public {
					t.Errorf("route %s method %s: MinRole=RolePublic on a route that is NOT Public — "+
						"C2 evaluates it as a real requirement", rt.Path, m.Method)
				}
				continue
			}
			checked++
			if !roleEnrolled(m.MinRole) {
				t.Errorf("route %s method %s: MinRole %q is not an enrolled role",
					rt.Path, m.Method, m.MinRole)
			}
		}
	}
	// Not-vacuous: the selector must actually be reaching the table.
	if checked < 100 || publicSeen == 0 {
		t.Fatalf("wall selector degenerate: checked=%d publicSeen=%d", checked, publicSeen)
	}
}

// ─── Layer 2: the roster loader ──────────────────────────────────────────────

// seedRoster writes a ui_users.json whose single record carries role, and
// returns its path plus the plaintext password.
func seedRosterWithRole(t *testing.T, role string) (path, pass string) {
	t.Helper()
	dir := t.TempDir()
	pass = "Sup3rSecret!x"

	seeder := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := seeder.SetUIUser("bob", pass, RoleViewer); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	seedPath := filepath.Join(dir, "seed.json")
	seeder.SetUIUsersFile(seedPath)
	if err := seeder.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal seed: %v", err)
	}
	users, _ := env["users"].([]any)
	if len(users) != 1 {
		t.Fatalf("seed roster: got %d users, want 1", len(users))
	}
	rec := users[0].(map[string]any)
	if h, _ := rec["pass_hash"].(string); h == "" {
		t.Fatalf("seed roster carries no pass_hash: %v", rec)
	} else if _, err := hex.DecodeString(h); err != nil {
		t.Fatalf("seed pass_hash not hex: %v", err)
	}
	rec["role"] = role
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal roster: %v", err)
	}
	path = filepath.Join(dir, "ui_users.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	return path, pass
}

// DEFECT GATE. Pre-fix the loader returned "superuser" verbatim and the login
// path minted a session with it.
func TestRosterLoad_UnenrolledRoleIsClampedNotHonoured(t *testing.T) {
	for _, bogus := range []string{"superuser", "Admin", "ADMIN", "root", "public", "auditor", " viewer"} {
		t.Run(bogus, func(t *testing.T) {
			path, pass := seedRosterWithRole(t, bogus)
			c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
			c.SetUIUsersFile(path)
			before := RosterRoleClampCount()
			if err := c.LoadUIUsersFile(); err != nil {
				t.Fatalf("load: %v", err)
			}
			got, ok := c.VerifyUIUser("bob", pass)
			if !ok {
				t.Fatalf("clamped account must stay usable; VerifyUIUser refused it")
			}
			if got != RoleViewer {
				t.Fatalf("roster role %q resolved to %q, want %q (least privilege)", bogus, got, RoleViewer)
			}
			if RosterRoleClampCount() <= before {
				t.Errorf("clamp not counted: the operator's only signal that the roster names an unknown role")
			}
			// The whole point: it must not be admin, by any route.
			if got.HasRole(RoleAdmin) || got.HasRole(RoleOperator) {
				t.Errorf("clamped role %q still satisfies an elevated requirement", got)
			}
		})
	}
}

// CONTROL. Enrolled roles and the pre-RBAC empty value must survive the loader
// untouched — clamping them would silently demote real admins.
func TestRosterLoad_EnrolledAndLegacyRolesUnchanged(t *testing.T) {
	for _, role := range []string{string(RoleViewer), string(RoleOperator), string(RoleAdmin), ""} {
		name := role
		if name == "" {
			name = "legacy_empty"
		}
		t.Run(name, func(t *testing.T) {
			path, pass := seedRosterWithRole(t, role)
			c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
			c.SetUIUsersFile(path)
			before := RosterRoleClampCount()
			if err := c.LoadUIUsersFile(); err != nil {
				t.Fatalf("load: %v", err)
			}
			got, ok := c.VerifyUIUser("bob", pass)
			if !ok {
				t.Fatalf("VerifyUIUser refused a well-formed record")
			}
			if string(got) != role {
				t.Fatalf("role %q was rewritten to %q", role, got)
			}
			if RosterRoleClampCount() != before {
				t.Errorf("clamp counter moved on a well-formed role %q", role)
			}
		})
	}
}

func TestLoadedRosterRole_Table(t *testing.T) {
	for _, tc := range []struct{ in, want UIRole }{
		{RoleViewer, RoleViewer}, {RoleOperator, RoleOperator}, {RoleAdmin, RoleAdmin},
		{"", ""}, // pre-RBAC compat value, deliberately preserved
		{"superuser", RoleViewer}, {RolePublic, RoleViewer}, {"Admin", RoleViewer},
	} {
		if got := loadedRosterRole("bob", tc.in); got != tc.want {
			t.Errorf("loadedRosterRole(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ─── Layer 3: the session sink ───────────────────────────────────────────────

func withSessionKey(t *testing.T) {
	t.Helper()
	prev := session.SigningKey()
	session.SetSigningKey([]byte("sec-rbac-role-1-test-signing-key"))
	t.Cleanup(func() { session.SetSigningKey(prev) })
}

// configuredCfg installs a cfg for which IsConfigured() is true, so the
// pre-setup bootstrap bypass in uiAuthMiddleware is NOT the branch under test.
func configuredCfg(t *testing.T) {
	t.Helper()
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := cfg.SetAuth("root", "Sup3rSecret!x"); err != nil {
		t.Fatalf("seed auth: %v", err)
	}
	if err := cfg.SetUIUser("bob", "Sup3rSecret!x", RoleViewer); err != nil {
		t.Fatalf("seed roster: %v", err)
	}
	if !cfg.IsConfigured() {
		t.Fatalf("precondition: cfg must be configured")
	}
}

// driveMiddleware runs one /api request carrying a session with sessionRole and
// reports the status and the role the middleware injected (or "" if the inner
// handler was never reached).
func driveMiddleware(t *testing.T, sessionRole string) (int, UIRole, bool) {
	t.Helper()
	value, err := encodeSession(&Session{
		Sub: "bob", Provider: "local", Role: sessionRole,
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	var seen UIRole
	reached := false
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached, seen = true, uiRole(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen, reached
}

// DEFECT GATE. Pre-fix this returned 200 with the injected role "admin".
func TestSessionRole_UnenrolledSessionIsRefusedNotPromoted(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)
	for _, bogus := range []string{"superuser", "Admin", "ADMIN", "public", "read-only", " viewer", "root"} {
		t.Run(bogus, func(t *testing.T) {
			code, role, reached := driveMiddleware(t, bogus)
			if reached {
				t.Fatalf("handler reached with injected role %q for session role %q", role, bogus)
			}
			if code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 for unenrolled session role %q", code, bogus)
			}
			if role == RoleAdmin {
				t.Fatalf("session role %q was promoted to admin", bogus)
			}
		})
	}
}

// CONTROL. The pre-RBAC compatibility case must survive — refusing it would
// pass the defect gate while locking legacy single-admin deployments out.
func TestSessionRole_EmptyRoleStillResolvesToAdmin(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)
	code, role, reached := driveMiddleware(t, "")
	if !reached || code != http.StatusOK {
		t.Fatalf("legacy role-less session refused: status=%d reached=%v", code, reached)
	}
	if role != RoleAdmin {
		t.Fatalf("legacy role-less session resolved to %q, want %q", role, RoleAdmin)
	}
}

// CONTROL. Ordinary sessions are untouched, at their exact role.
func TestSessionRole_EnrolledRolesPassThroughUnchanged(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)
	for _, r := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
		code, got, reached := driveMiddleware(t, string(r))
		if !reached || code != http.StatusOK {
			t.Fatalf("session role %q refused: status=%d reached=%v", r, code, reached)
		}
		if got != r {
			t.Fatalf("session role %q injected as %q", r, got)
		}
	}
}

func TestSessionRoleOrReject_Table(t *testing.T) {
	if got, ok := sessionRoleOrReject(""); !ok || got != RoleAdmin {
		t.Errorf(`sessionRoleOrReject("") = (%q,%v), want (admin,true)`, got, ok)
	}
	for _, r := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
		if got, ok := sessionRoleOrReject(string(r)); !ok || got != r {
			t.Errorf("sessionRoleOrReject(%q) = (%q,%v), want (%q,true)", r, got, ok, r)
		}
	}
	for _, bogus := range []string{"superuser", "Admin", "public", " ", "viewer "} {
		if got, ok := sessionRoleOrReject(bogus); ok {
			t.Errorf("sessionRoleOrReject(%q) = (%q,true), want refused", bogus, got)
		}
	}
}

// DEFECT GATE. The public status endpoint reported the same promoted admin,
// so the console rendered the full admin surface for a principal every gated
// endpoint was about to refuse.
func TestAuthStatus_UnenrolledSessionIsNotReportedAsAdmin(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)
	value, err := encodeSession(&Session{
		Sub: "bob", Provider: "local", Role: "superuser",
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	apiAuthStatus(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status body %q: %v", rec.Body.String(), err)
	}
	if role, _ := body["role"].(string); role == string(RoleAdmin) {
		t.Fatalf("apiAuthStatus reported role=admin for an unenrolled session role: %v", body)
	}
	if li, _ := body["loggedIn"].(bool); li {
		t.Fatalf("apiAuthStatus reported loggedIn for a session no gated endpoint will honour: %v", body)
	}
}

// ─── End to end: the whole chain ─────────────────────────────────────────────

// DEFECT GATE. A roster restored with a role this build does not enroll must
// not yield an admin session. Pre-fix: disk "superuser" -> VerifyUIUser
// "superuser" -> signed session "superuser" -> middleware -> RoleAdmin.
func TestRosterToSession_UnenrolledDiskRoleNeverReachesAdmin(t *testing.T) {
	withSessionKey(t)
	path, pass := seedRosterWithRole(t, "superuser")

	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := cfg.SetAuth("root", "Sup3rSecret!x"); err != nil {
		t.Fatalf("seed auth: %v", err)
	}
	cfg.SetUIUsersFile(path)
	if err := cfg.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.IsConfigured() {
		t.Fatalf("precondition: cfg must be configured")
	}

	role, ok := cfg.VerifyUIUser("bob", pass)
	if !ok {
		t.Fatalf("login refused for a repairable roster record")
	}
	code, injected, reached := driveMiddleware(t, string(role))
	if !reached || code != http.StatusOK {
		t.Fatalf("clamped account could not use the admin UI at all: status=%d", code)
	}
	if injected == RoleAdmin || injected.HasRole(RoleOperator) {
		t.Fatalf("disk role %q reached %q through login+session", "superuser", injected)
	}
	if injected != RoleViewer {
		t.Fatalf("injected role = %q, want %q", injected, RoleViewer)
	}
	// Authorization: the elevated gate must actually refuse it.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/users", http.NoBody)
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, injected))
	rec := httptest.NewRecorder()
	if requireRole(rec, req, RoleAdmin) {
		t.Fatalf("requireRole(admin) admitted the clamped principal")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("requireRole wrote %d, want 403", rec.Code)
	}
}

// savedRole re-reads the roster file and returns bob's persisted role.
func savedRole(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	var env struct {
		Users []struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal roster: %v", err)
	}
	for _, u := range env.Users {
		if u.Username == "bob" {
			return u.Role
		}
	}
	t.Fatalf("bob missing from saved roster")
	return ""
}

// DEFECT GATE (Codex review). The clamp governs AUTHORIZATION only: an
// ordinary save on a downgraded build — including a password change, which
// re-writes the record with the unchanged effective role — must write the
// newer build's role back verbatim, or a temporary downgrade permanently
// destroys the assignment and upgrading again cannot restore it.
func TestRosterLoad_ClampIsNeverPersisted(t *testing.T) {
	path, pass := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got, ok := c.VerifyUIUser("bob", pass); !ok || got != RoleViewer {
		t.Fatalf("precondition: clamped role = %q ok=%v, want %q", got, ok, RoleViewer)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := savedRole(t, path); got != "auditor" {
		t.Fatalf("plain save persisted role %q, want the original %q — the clamp overwrote a newer build's assignment", got, "auditor")
	}
	// A self-service password change is not a role assignment, so the
	// persisted role survives.
	if err := c.ChangeUIUserPassword("bob", "N3wSecret!pass", RoleAdmin); err != nil {
		t.Fatalf("password change: %v", err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := savedRole(t, path); got != "auditor" {
		t.Fatalf("password change persisted role %q, want %q", got, "auditor")
	}
	if got, _ := c.VerifyUIUser("bob", "N3wSecret!pass"); got != RoleViewer {
		t.Fatalf("authorization role after password change = %q, want the clamp %q", got, RoleViewer)
	}
}

// CONTROL. An explicit reassignment by an admin must win over the preserved
// raw role, or the admin could never repair the account on this build.
func TestRosterLoad_ExplicitReassignmentReplacesPersistedRole(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.SetUIUser("bob", "", RoleOperator); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := savedRole(t, path); got != string(RoleOperator) {
		t.Fatalf("explicit reassignment persisted %q, want %q", got, RoleOperator)
	}
}

// TestRosterLoad_SameRoleReassignmentReplacesPersistedRole pins that a
// password-empty role update naming the SAME role the clamp produced (an admin
// confirming "viewer" in the edit UI) still replaces the preserved raw role,
// so the unknown role is not silently written back and restored on upgrade.
func TestRosterLoad_SameRoleReassignmentReplacesPersistedRole(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.SetUIUser("bob", "", RoleViewer); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := savedRole(t, path); got != string(RoleViewer) {
		t.Fatalf("confirming the clamped role persisted %q, want %q — the explicit assignment was ignored", got, RoleViewer)
	}
}

// TestRosterLoad_ActiveClampCountClearsAfterRepair pins that the current-health
// value behind /healthz and /api/stats reflects records PRESENTLY clamped, not
// the cumulative counter, so a repaired roster stops reporting degraded.
func TestRosterLoad_ActiveClampCountClearsAfterRepair(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := c.ActiveRosterRoleClamps(); got != 1 {
		t.Fatalf("active clamps after load = %d, want 1", got)
	}
	cumulative := RosterRoleClampCount()
	if err := c.SetUIUser("bob", "", RoleOperator); err != nil {
		t.Fatalf("reassign: %v", err)
	}
	if got := c.ActiveRosterRoleClamps(); got != 0 {
		t.Fatalf("active clamps after repair = %d, want 0 — health would stay degraded after the documented fix", got)
	}
	if RosterRoleClampCount() != cumulative {
		t.Fatal("the cumulative _total counter must not move on repair")
	}
}

// TestRosterLoad_PasswordChangeKeepsPersistedRoleAndTOTP pins that the
// SEC-TOTP-1 record constructor and the persisted-role carry compose: a
// password change on a clamped account keeps BOTH the raw role a newer build
// assigned and the account's TOTP enrolment (secret + replay counter).
func TestRosterLoad_PasswordChangeKeepsPersistedRoleAndTOTP(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	const secret = "JBSWY3DPEHPK3PXP" // #nosec G101 -- RFC 6238 example TOTP seed, test fixture
	if !c.SetTOTPSecret("bob", secret, []string{"code-one"}) {
		t.Fatal("precondition: enrol TOTP")
	}
	if !c.SetTOTPLastCounter("bob", 42) {
		t.Fatal("precondition: set counter")
	}
	if err := c.ChangeUIUserPassword("bob", "N3wSecret!pass", RoleAdmin); err != nil {
		t.Fatalf("password change: %v", err)
	}
	if got := c.GetTOTPSecret("bob"); got != secret {
		t.Fatalf("TOTP secret after password change = %q, want %q", got, secret)
	}
	if got := c.GetTOTPLastCounter("bob"); got != 42 {
		t.Fatalf("TOTP counter after password change = %d, want 42", got)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := savedRole(t, path); got != "auditor" {
		t.Fatalf("password change persisted role %q, want %q", got, "auditor")
	}
}

// DEFECT GATE (Codex review). The admin user editor sends password AND role
// in one POST /api/auth/users request; confirming the clamped "viewer" while
// also setting a password is an explicit assignment and must replace the
// preserved raw role, or the unknown role is written back and restored on
// upgrade although the UI reported the repair as done.
func TestRosterLoad_SameRoleReassignmentWithPasswordReplacesPersistedRole(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.SetUIUser("bob", "N3wSecret!pass", RoleViewer); err != nil {
		t.Fatalf("reassign with password: %v", err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := savedRole(t, path); got != string(RoleViewer) {
		t.Fatalf("admin edit (password + same role) persisted %q, want %q", got, RoleViewer)
	}
}
