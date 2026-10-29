package main

// setup_anchor_roster_test.go — SEC-SETUPANCHOR-1.
//
// The first-run bootstrap window grants unauthenticated RoleAdmin
// (uiAuthMiddleware). IsConfigured's `c.user` term is set by loadUIUsersFile
// ONLY from a record whose effective role is admin, so a roster holding
// accounts but no PRESENT admin left every term false and reopened that window
// on an appliance that had demonstrably been set up.
//
// Two routes reach that state without touching the admin API:
//
//   - loadedRosterRole's least-privilege clamp. Restoring a backup from a build
//     that enrolls a role this one does not clamps the only admin to RoleViewer
//     — a control written to fail CLOSED against role-based escalation handed
//     the admin plane to anonymous callers.
//   - a legacy pre-RBAC roster, whose empty role is never equal to RoleAdmin.
//
// The gates below are authorization gates, not predicate assertions: the
// anonymous ones drive a real request through uiAuthMiddleware and requireRole,
// because the predicate is only interesting through the door it opens. The
// negative controls pin the states that MUST keep the window open, since a fix
// that over-closes bricks a new install instead.

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// anonymousAdminReachable drives one credential-free request for an admin-only
// API path through the real middleware chain and reports whether it was granted
// RoleAdmin. It asks the question the finding is about rather than trusting a
// predicate: the grant is what an attacker gets.
func anonymousAdminReachable(t *testing.T) bool {
	t.Helper()
	granted := false
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		granted = true
		w.WriteHeader(http.StatusOK)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/users", http.NoBody))
	return granted
}

// loadRoster points the global cfg at a Config that has LOADED body, which is
// what a real boot does. withRosterOnDisk deliberately does not load.
func loadRoster(t *testing.T, body string) *Config {
	t.Helper()
	withRosterOnDisk(t, body)
	if err := cfg.LoadUIUsersFile(); err != nil {
		t.Fatalf("load roster: %v", err)
	}
	resetDurableSetupAnchorForTest()
	return cfg
}

// rosterWithRole rewrites the seeded envelope's single record to carry role,
// bypassing the API's own role validation the way raw persistence does (a
// restored backup, a hand edit). The bcrypt hash is kept real so the loader's
// hex admission test is satisfied honestly.
func rosterWithRole(t *testing.T, role UIRole) string {
	t.Helper()
	var env uiUsersFileEnvelope
	if err := json.Unmarshal([]byte(adminRoster(t, RoleAdmin)), &env); err != nil {
		t.Fatalf("decode seed envelope: %v", err)
	}
	if len(env.Users) != 1 {
		t.Fatalf("premise broken: seed envelope holds %d records, want 1", len(env.Users))
	}
	env.Users[0].Role = role
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal roster: %v", err)
	}
	return string(out)
}

// TestSetupAnchor_ClampedAdminDoesNotReopenTheWindow is the security gate. A
// roster whose only admin was clamped to RoleViewer by loadedRosterRole records
// a completed setup; anonymous callers must get nothing.
func TestSetupAnchor_ClampedAdminDoesNotReopenTheWindow(t *testing.T) {
	c := loadRoster(t, rosterWithRole(t, UIRole("superadmin")))

	// Premise: the clamp really did fire and really did remove the admin term.
	if roleEnrolled(UIRole("superadmin")) {
		t.Skip("this build enrolls 'superadmin'; the clamp cannot be provoked with it")
	}
	if got := c.uiUsers["alice"].role; got != RoleViewer {
		t.Fatalf("premise broken: want the clamp to leave RoleViewer, got %q", got)
	}
	if c.user != "" {
		t.Fatalf("premise broken: want the admin term empty after the clamp, got %q", c.user)
	}

	if !c.IsConfigured() {
		t.Error("a roster holding an account records a completed setup; IsConfigured must be true")
	}
	if bootstrapWindowOpen() {
		t.Error("the first-run window must stay CLOSED for a roster that records a setup")
	}
	if anonymousAdminReachable(t) {
		t.Fatal("SEC-SETUPANCHOR-1: an unauthenticated request was granted RoleAdmin on an admin-only route")
	}
}

// TestSetupAnchor_LegacyEmptyRoleDoesNotReopenTheWindow is the same bypass by
// its second route. A pre-RBAC roster's empty role is never RoleAdmin, and such
// an account signs in as admin via the middleware's compat branch — so the
// appliance is configured and anonymous callers must still get nothing.
func TestSetupAnchor_LegacyEmptyRoleDoesNotReopenTheWindow(t *testing.T) {
	c := loadRoster(t, rosterWithRole(t, ""))

	if c.user != "" {
		t.Fatalf("premise broken: an empty role must not set the admin term, got %q", c.user)
	}
	if len(c.uiUsers) != 1 {
		t.Fatalf("premise broken: want the record admitted to the roster, got %d", len(c.uiUsers))
	}
	if bootstrapWindowOpen() {
		t.Error("a legacy pre-RBAC roster records a completed setup; the window must stay closed")
	}
	if anonymousAdminReachable(t) {
		t.Fatal("SEC-SETUPANCHOR-1: an unauthenticated request was granted RoleAdmin via a legacy roster")
	}
}

// TestSetupAnchor_ViewerOnlyRosterClosesTheDurableWindow pins the durable side.
// A SECOND process on a shared /data never loads the file, so the fix has to
// hold through rosterBytesConfigure too or the backstop keeps granting
// authority exactly where CHAOS-103 removed it.
func TestSetupAnchor_ViewerOnlyRosterClosesTheDurableWindow(t *testing.T) {
	withRosterOnDisk(t, adminRoster(t, RoleViewer)) // on disk, deliberately NOT loaded

	if cfg.IsConfigured() {
		t.Fatal("premise broken: this Config must not have loaded the roster, or the test proves nothing")
	}
	if !rosterBytesConfigure([]byte(adminRoster(t, RoleViewer))) {
		t.Error("a roster file holding an account must anchor setup on the durable side")
	}
	if bootstrapWindowOpen() {
		t.Error("a durable roster with any account must close the bootstrap window")
	}
	if anonymousAdminReachable(t) {
		t.Fatal("SEC-SETUPANCHOR-1: unauthenticated RoleAdmin from a second process on a viewer-only roster")
	}
}

// TestSetupAnchor_NegativeControls holds the states that MUST keep the window
// open. Over-closing is the failure mode of this fix: it would make a genuine
// first run unconfigurable, so each case here is load-bearing.
func TestSetupAnchor_NegativeControls(t *testing.T) {
	nonHex := func(t *testing.T) string {
		t.Helper()
		body, err := json.Marshal(uiUsersFileEnvelope{
			Users: []uiUserRecord{{Username: "alice", PassHash: "not-hex!!", Role: RoleAdmin}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(body)
	}

	cases := []struct {
		name string
		body func(*testing.T) string
		why  string
	}{
		{"no roster file at all", func(*testing.T) string { return "" },
			"a genuine fresh install"},
		{"empty envelope", func(*testing.T) string { return `{"users":[]}` },
			"setup has created nothing yet"},
		{"empty legacy array", func(*testing.T) string { return `[]` },
			"a pre-RBAC install that has created nothing yet"},
		{"corrupt roster", func(*testing.T) string { return `{"users":[` },
			"CHAOS-05 quarantines and keeps going; the wizard stays open"},
		{"every record's hash is not hex", nonHex,
			"the loader admits none of them, so the roster records nothing"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body(t)
			withRosterOnDisk(t, body)
			_ = cfg.LoadUIUsersFile() // a corrupt roster errors AND quarantines; both are "not configured"
			resetDurableSetupAnchorForTest()

			if cfg.IsConfigured() {
				t.Errorf("IsConfigured must stay false — %s", tc.why)
			}
			if !bootstrapWindowOpen() {
				t.Errorf("the bootstrap window must stay OPEN — %s", tc.why)
			}
			if body != "" && rosterBytesConfigure([]byte(body)) {
				t.Errorf("the durable anchor must not claim a setup — %s", tc.why)
			}
		})
	}
}

// TestSetupAnchor_RollbackKeepsTheWizardRetryable pins the interaction with
// SetAuthDurably's rollback, whose recorded contract is that restoring the
// pre-setup state ("no accounts, empty legacy pair") reverts IsConfigured to
// false. The new term reads c.uiUsers, so a rollback that left an account
// behind would strand a half-configured appliance with no way back in.
func TestSetupAnchor_RollbackKeepsTheWizardRetryable(t *testing.T) {
	withRosterOnDisk(t, "")
	if !bootstrapWindowOpen() {
		t.Fatal("premise broken: a fresh install must start with the window open")
	}

	// The pre-setup snapshot mutateRosterDurably takes before running SetAuth.
	pre := cfg.snapshotRoster()

	if err := cfg.SetAuth("alice", "Sup3rSecret!x"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if bootstrapWindowOpen() {
		t.Fatal("premise broken: an admin account must close the window")
	}

	// The compensation a refused write runs: a wholesale restore of that
	// snapshot, which is the path DeleteUIUser's "last admin" guard does not
	// (and must not) stand in the way of.
	cfg.restoreRoster(pre)
	resetDurableSetupAnchorForTest()

	if cfg.IsConfigured() {
		t.Error("a rolled-back setup must revert IsConfigured to false")
	}
	if !bootstrapWindowOpen() {
		t.Error("a rolled-back setup must leave the wizard retryable")
	}
}

// TestSetupAnchor_ConcurrentReadersAgree runs the gate under -race against a
// roster being mutated, because bootstrapWindowOpen is evaluated per request on
// an unauthenticated public path (/api/setup/status) and reads cfg.uiUsers
// through the lock. It also pins the one-directional property: the window may
// only ever CLOSE as accounts appear, never reopen.
func TestSetupAnchor_ConcurrentReadersAgree(t *testing.T) {
	withRosterOnDisk(t, "")

	var wg sync.WaitGroup
	closed := make(chan bool, 64)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				closed <- !bootstrapWindowOpen()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := cfg.SetUIUser("alice", "Sup3rSecret!x", RoleViewer); err != nil {
			t.Errorf("concurrent roster write: %v", err)
		}
	}()
	wg.Wait()
	close(closed)

	// Every reader saw a defined verdict and none panicked; once the account
	// exists the verdict must be stable at CLOSED.
	for range closed { //nolint:revive // draining; the verdicts are time-dependent mid-race
	}
	if bootstrapWindowOpen() {
		t.Fatal("after an account exists the window must be closed for every reader")
	}
}

// TestSetupAnchor_HexBoundary pins the exact admission test the mirror shares
// with the loader. An EMPTY pass_hash decodes as hex (to zero bytes), so the
// loader admits the record and the roster anchors setup — the account cannot
// sign in (bcrypt rejects an empty hash), which is a lockout for
// --reset-password, not grounds to reopen an anonymous admin plane.
func TestSetupAnchor_HexBoundary(t *testing.T) {
	if _, err := hex.DecodeString(""); err != nil {
		t.Skipf("premise broken: this stdlib rejects an empty hex string (%v)", err)
	}
	body, err := json.Marshal(uiUsersFileEnvelope{
		Users: []uiUserRecord{{Username: "alice", PassHash: "", Role: RoleViewer}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	withRosterOnDisk(t, string(body))
	if err := cfg.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	resetDurableSetupAnchorForTest()

	if len(cfg.uiUsers) != 1 {
		t.Fatalf("premise broken: the loader must admit an empty-hash record, got %d", len(cfg.uiUsers))
	}
	if !rosterBytesConfigure(body) {
		t.Error("the durable anchor must agree with the loader's admission test")
	}
	if bootstrapWindowOpen() {
		t.Error("an admitted record anchors setup even when it cannot authenticate")
	}
	if anonymousAdminReachable(t) {
		t.Fatal("SEC-SETUPANCHOR-1: unauthenticated RoleAdmin on an unusable-but-present roster")
	}
}

// TestSetupAnchor_EmptyUsernameRecordAnchorsLikeTheLoader pins the divergence
// the fix deliberately removed. The loader keys c.uiUsers by whatever username
// a record carries, the empty string included, so requiring a non-empty one on
// the durable side would diverge in the direction that leaves the window OPEN.
func TestSetupAnchor_EmptyUsernameRecordAnchorsLikeTheLoader(t *testing.T) {
	body, err := json.Marshal(uiUsersFileEnvelope{
		Users: []uiUserRecord{{Username: "", PassHash: hex.EncodeToString([]byte("x")), Role: RoleViewer}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	probe := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	probe.SetUIUsersFile(path)
	if err := probe.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}

	loaded := probe.IsConfigured()
	anchor := rosterBytesConfigure(body)
	if anchor != loaded {
		t.Errorf("durable anchor and loader must agree on an empty-username record: anchor=%v loader=%v",
			anchor, loaded)
	}
	if !loaded {
		t.Error("the loader admits an empty-username record to the roster, so it anchors setup")
	}
}
