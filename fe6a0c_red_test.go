package main

// fe6a0c_red_test.go — FE-6A.0 CORRECTION RED matrix (external review of
// `e3c0d5d7`, Blockers 1–10), committed on exactly that head BEFORE any
// product change. Every row encodes the corrected contract and FAILS on the
// baseline it is committed on; the correction commits turn each row GREEN
// without editing the assertions. The accepted R1–R14 rows
// (fe6a0_red_test.go) stay untouched.
//
//   CR1  self-service password change: fenced on the caller's security
//        generation (428/409/404), revokes every prior session after the
//        durable commit, returns action-bound facts        (Blocker 1)
//   CR2  session invalidation is DURABLE: a pre-change cookie stays invalid
//        after a restart, a post-change login is honoured, a legacy cookie
//        without a generation fails closed                  (Blocker 2)
//   CR3  legacy single-user password change is one persist-before-publish
//        transaction: failure leaves the old credential usable and the new
//        one unusable, runtime untouched (RED); its happy-path sibling is
//        the CONTROL — it passes on the baseline and must keep passing
//                                                              (Blocker 3)
//   CR4  create fences: IdP create (registry document revision), user
//        create (roster revision), lockout reset (lockout generation);
//        428 absent / 409 stale / 404 vanished               (Blocker 4)
//   CR5  IdP delete serialises behind the shared reference-integrity gate
//        an SSORequired writer holds                          (Blocker 5)
//   CR6  a dependency failure (discovery/metadata/transport) never reaches
//        a response, an audit entry or the process log; the refusal is a
//        bounded code + reason class                          (Blocker 6)
//   CR7  administrative mutations on a non-persistable store are refused
//        BEFORE any runtime change (503 persistence_not_configured); reads
//        keep reporting the posture                           (Blocker 7)
//   CR8  a rejected fleet publication is a structured fact on the action
//        result, in the audit detail and on the read model; the empty-
//        registry publication follows the same contract     (Blocker 8)
//   CR9  the cutover is client-recoverable and at-most-once: a client
//        operationId is required for a cutover-bearing write, a duplicate
//        replays without a second profile or cutover, an authoritative
//        lookup answers pending/committed/aborted/outcome_unknown, and an
//        observed cutover whose sentinel save failed reports pending
//        reconciliation                                       (Blocker 9)
//   CR10 the test suite never writes into the operator's default /data
//        tree (every data-dir-rooted default is rebound for the process)
//                                                              (Blocker 10)

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// ─── shared helpers ──────────────────────────────────────────────────────────

// fe6acStatus reads GET /api/auth/status for a cookie-jar client.
func fe6acStatus(t *testing.T, ch *fe6aChain, client *http.Client) map[string]any {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ch.srv.URL+"/api/auth/status", http.NoBody)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("status decode: %v", err)
	}
	return m
}

// fe6acPost sends a JSON POST through a cookie-jar client and returns the
// status, decoded body and the response headers.
func fe6acPost(t *testing.T, ch *fe6aChain, client *http.Client, path string, body any) (status int, out map[string]any, hdr http.Header) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, ch.srv.URL+path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m, resp.Header
}

// fe6acDocRevision reads the registry document revision from GET /api/idp.
func fe6acDocRevision(t *testing.T) string {
	t.Helper()
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	rev, _ := fe6aJSON(t, w)["revision"].(string)
	return rev
}

// fe6acCreateFenced creates an IdP profile with the current document revision.
func fe6acCreateFenced(t *testing.T, body map[string]any, extra ...string) (status int, out map[string]any) {
	t.Helper()
	q := []string{"documentRevision=" + fe6acDocRevision(t)}
	q = append(q, extra...)
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp?"+strings.Join(q, "&"), body))
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

// fe6acAuditSnapshot captures the audit ring by entry identity so a
// follow-up assertion is exact even when two actions land in the same
// millisecond (a TS watermark cannot separate them).
func fe6acAuditSnapshot() map[string]int {
	seen := map[string]int{}
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		seen[fe6acAuditKey(e)]++
	}
	return seen
}

func fe6acAuditKey(e *audit.Entry) string {
	return strconv.FormatInt(e.TS, 10) + "|" + e.Action + "|" + e.Object + "|" + e.Detail
}

// fe6acAssertNoNewAudit fails when an entry with one of the actions appeared
// AFTER the snapshot was taken.
func fe6acAssertNoNewAudit(t *testing.T, before map[string]int, actions ...string) {
	t.Helper()
	after := auditGet()
	for i := range after {
		e := &after[i]
		if before[fe6acAuditKey(e)] > 0 {
			before[fe6acAuditKey(e)]--
			continue
		}
		for _, a := range actions {
			if e.Action == a {
				t.Fatalf("refusal/replay emitted a success audit entry: %+v", e)
			}
		}
	}
}

func fe6acUserGeneration(t *testing.T, user string) int64 {
	t.Helper()
	w := httptest.NewRecorder()
	apiAuthUsers(w, getReq("/api/auth/users"))
	users, _ := fe6aJSON(t, w)["users"].([]any)
	for _, u := range users {
		m, _ := u.(map[string]any)
		if m["username"] == user {
			g, _ := m["securityGeneration"].(float64)
			return int64(g)
		}
	}
	t.Fatalf("user %s not in the read model", user)
	return 0
}

// ─── CR1 — self-service password change: fenced, revoking, truthful ─────────

func TestFE6A0C_CR1_ChangePasswordIsFencedOnTheSecurityGeneration(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	ch := fe6aFullChain(t)
	bob := ch.login(t, "bob", "BobPass123")
	st := fe6acStatus(t, ch, bob)
	gen, ok := st["securityGeneration"].(float64)
	if !ok || gen <= 0 {
		t.Fatalf("auth status must expose the caller's positive securityGeneration; got %v", st)
	}
	// Missing fence → 428 carrying the current generation; nothing changes.
	code, m, _ := fe6acPost(t, ch, bob, "/api/auth/change-password", map[string]any{"current_password": "BobPass123", "new_password": "BobNew456"})
	if code != http.StatusPreconditionRequired || m["code"] != "precondition_required" {
		t.Fatalf("unfenced change-password = %d %v, want 428 precondition_required", code, m)
	}
	if cur, _ := m["current"].(map[string]any); cur["generation"] != gen {
		t.Fatalf("428 must carry current.generation=%v; got %v", gen, m["current"])
	}
	if _, ok := c.VerifyUIUser("bob", "BobPass123"); !ok {
		t.Fatal("refused change must keep the old credential")
	}
	// An administrator's competing update lands first (generation advances).
	rev := fe6aRosterRevision(t)
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "bob", "password": "AdminSet789"}))
	if w.Code != http.StatusOK {
		t.Fatalf("admin update = %d: %s", w.Code, w.Body.String())
	}
	// The self-service request still carries the generation it observed
	// with its verified credential → 409 stale, zero mutation.
	bob2 := ch.login(t, "bob", "AdminSet789")
	code, m, _ = fe6acPost(t, ch, bob2, "/api/auth/change-password?generation="+strconv.FormatInt(int64(gen), 10), map[string]any{"current_password": "AdminSet789", "new_password": "BobNew456"})
	if code != http.StatusConflict || m["code"] != "stale" {
		t.Fatalf("stale change-password = %d %v, want 409 stale", code, m)
	}
	if _, ok := c.VerifyUIUser("bob", "AdminSet789"); !ok {
		t.Fatal("stale self-service change overwrote the administrator's newer credential")
	}
	if _, ok := c.VerifyUIUser("bob", "BobNew456"); ok {
		t.Fatal("stale self-service change installed its credential")
	}
	// Deleted target → 404 (the roster fence sees the user gone).
	rev = fe6aRosterRevision(t)
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodDelete, "/api/auth/users?username=bob&revision="+strconv.FormatInt(rev, 10), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}
	r := jsonReq(http.MethodPost, "/api/auth/change-password?generation=999", map[string]string{"current_password": "AdminSet789", "new_password": "BobNew456"})
	r = withRoleCtx(r, RoleOperator)
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "bob"))
	w = httptest.NewRecorder()
	apiAuthChangePassword(w, r)
	fe6aAssertRefusal(t, w, http.StatusNotFound, "not_found")
}

func TestFE6A0C_CR1_ChangePasswordRevokesPriorSessionsAndReportsFacts(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	ch := fe6aFullChain(t)
	other := ch.login(t, "bob", "BobPass123") // a second device, logged in earlier
	bob := ch.login(t, "bob", "BobPass123")
	gen, _ := fe6acStatus(t, ch, bob)["securityGeneration"].(float64)
	code, m, hdr := fe6acPost(t, ch, bob, "/api/auth/change-password?generation="+strconv.FormatInt(int64(gen), 10), map[string]any{"current_password": "BobPass123", "new_password": "BobNew456"})
	if code != http.StatusOK {
		t.Fatalf("change-password = %d %v", code, m)
	}
	for _, k := range []string{"sessionsRevoked", "selfAffected", "persisted"} {
		if v, _ := m[k].(bool); !v {
			t.Fatalf("success must report %s:true; body=%v", k, m)
		}
	}
	if newGen, _ := m["securityGeneration"].(float64); newGen <= gen {
		t.Fatalf("securityGeneration must advance (%v → %v)", gen, newGen)
	}
	if _, ok := m["revision"].(float64); !ok {
		t.Fatalf("success must carry the roster revision; body=%v", m)
	}
	// The other device's session issued under the previous generation is
	// gone; the caller was re-issued a session at the new generation.
	if got := ch.get(t, other, "/api/auth/status"); got != http.StatusOK {
		t.Fatalf("status route = %d", got)
	}
	if st := fe6acStatus(t, ch, other); st["loggedIn"] != false {
		t.Fatalf("a session issued before the password change must be invalid; status=%v", st)
	}
	if !strings.Contains(strings.Join(hdr.Values("Set-Cookie"), ";"), uiSessionCookieName+"=") {
		t.Fatal("the caller must be re-issued a session at the new generation (Set-Cookie)")
	}
	if st := fe6acStatus(t, ch, bob); st["loggedIn"] != true {
		t.Fatalf("the caller's re-issued session must be valid; status=%v", st)
	}
	if _, ok := c.VerifyUIUser("bob", "BobNew456"); !ok {
		t.Fatal("new credential not accepted")
	}
}

// ─── CR2 — durable session invalidation across restart ──────────────────────

func TestFE6A0C_CR2_PreChangeSessionStaysInvalidAfterRestart(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	ch := fe6aFullChain(t)
	bob := ch.login(t, "bob", "BobPass123")
	if got := ch.get(t, bob, "/api/auth/users"); got != http.StatusOK {
		t.Fatalf("precondition: bob admin GET users = %d", got)
	}
	rev := fe6aRosterRevision(t)
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPut, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "bob", "role": "viewer"}))
	if w.Code != http.StatusOK {
		t.Fatalf("demote = %d: %s", w.Code, w.Body.String())
	}
	// RESTART: a fresh process loads the roster from disk and starts with an
	// EMPTY in-memory revocation list.
	fresh := newTestConfig()
	fresh.SetUIUsersFile(path)
	if err := fresh.LoadUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	cfg = fresh
	t.Cleanup(sessionRevoked.SwapForTest())
	ch2 := fe6aFullChain(t)
	// Re-point the old cookie jar at the new server (same host/port shape).
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ch2.srv.URL+"/api/auth/users", http.NoBody)
	for _, ck := range bob.Jar.Cookies(mustURL(t, ch.srv.URL)) {
		req.AddCookie(ck)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("pre-demotion admin cookie after restart = %d, want 401 (durable invalidation)", resp.StatusCode)
	}
	// A login AFTER the change is honoured (as a viewer).
	bob2 := ch2.login(t, "bob", "BobPass123")
	if got := ch2.get(t, bob2, "/api/auth/users"); got != http.StatusForbidden {
		t.Fatalf("fresh viewer session on an admin route = %d, want 403", got)
	}
	if got := ch2.get(t, bob2, "/api/auth/status"); got != http.StatusOK {
		t.Fatalf("fresh session must work on a viewer route (%d)", got)
	}
}

func TestFE6A0C_CR2_LegacyCookieWithoutGenerationFailsClosed(t *testing.T) {
	c, _ := fe6aSwapCfg(t, "")
	if err := c.SetUIUser("bob", "BobPass123", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	ch := fe6aFullChain(t)
	legacy := &Session{Sub: "bob", Provider: "local", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()}
	tok, err := encodeSession(legacy)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ch.srv.URL+"/api/auth/users", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: tok})
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("legacy cookie without a security generation = %d, want 401 (fail closed)", resp.StatusCode)
	}
}

func mustURL(t *testing.T, raw string) *urlT {
	t.Helper()
	u, err := parseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// ─── CR3 — legacy single-user password change is one transaction ────────────

func fe6acLegacyOnlyUser(t *testing.T, usersPath string) *Config {
	t.Helper()
	c, _ := fe6aSwapCfg(t, usersPath)
	// The authenticated identity lives ONLY in the legacy mirror: remove the
	// roster entry SetAuth mirrored (the RollbackFailedSetupAuth-era shape).
	c.mu.Lock()
	delete(c.uiUsers, "root")
	c.mu.Unlock()
	if c.UIUserExists("root") {
		t.Fatal("precondition: root must not be in the roster")
	}
	if _, ok := c.VerifyUIUser("root", "RootPass1"); !ok {
		t.Fatal("precondition: legacy fallback must authenticate root")
	}
	return c
}

func fe6acSelfChange(t *testing.T, user, cur, next string, gen int64) *httptest.ResponseRecorder {
	t.Helper()
	path := "/api/auth/change-password"
	if gen > 0 {
		path += "?generation=" + strconv.FormatInt(gen, 10)
	}
	r := jsonReq(http.MethodPost, path, map[string]string{"current_password": cur, "new_password": next})
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, user))
	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)
	return w
}

func TestFE6A0C_CR3_LegacySingleUserChangeFailsAtomically(t *testing.T) {
	c := fe6acLegacyOnlyUser(t, fe6aBrokenPath(t, "ui_users.json"))
	w := fe6acSelfChange(t, "root", "RootPass1", "RootNew234", 1)
	fe6aAssertRefusal(t, w, http.StatusInternalServerError, "persist_failed")
	if _, ok := c.VerifyUIUser("root", "RootPass1"); !ok {
		t.Fatal("failed legacy password change replaced the live credential")
	}
	if _, ok := c.VerifyUIUser("root", "RootNew234"); ok {
		t.Fatal("failed legacy password change left the new credential usable")
	}
	if c.UIUserExists("root") {
		t.Fatal("failed legacy password change created a roster entry")
	}
	if !c.AuthEnabled() {
		t.Fatal("failed change must leave the legacy mirror intact")
	}
}

func TestFE6A0C_CR3_LegacySingleUserChangeMigratesDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui_users.json")
	c := fe6acLegacyOnlyUser(t, path)
	w := fe6acSelfChange(t, "root", "RootPass1", "RootNew234", 1)
	if w.Code != http.StatusOK {
		t.Fatalf("legacy change = %d: %s", w.Code, w.Body.String())
	}
	if _, ok := c.VerifyUIUser("root", "RootNew234"); !ok {
		t.Fatal("new credential not live")
	}
	if _, ok := c.VerifyUIUser("root", "RootPass1"); ok {
		t.Fatal("old credential still live")
	}
	if got := fe6aRosterFromDisk(t, path)["root"]; got != RoleAdmin {
		t.Fatalf("legacy user must be migrated into the durable roster as admin; got %q", got)
	}
}

// ─── CR4 — create fences on both stores + lockout generation ────────────────

func TestFE6A0C_CR4_IdPCreateRequiresTheDocumentRevision(t *testing.T) {
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	probe := fe6aProbeIdP(t, reg, path)
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", ldapProfileBodyForPut("Unfenced create", nil)))
	m := fe6aAssertRefusal(t, w, http.StatusPreconditionRequired, "precondition_required")
	cur, _ := m["current"].(map[string]any)
	if rev, _ := cur["documentRevision"].(string); rev == "" || rev != fe6acDocRevision(t) {
		t.Fatalf("428 must carry the current documentRevision; got %v", cur)
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.create")

	code, first := fe6acCreateFenced(t, ldapProfileBodyForPut("First", nil))
	if code != http.StatusOK {
		t.Fatalf("fenced create = %d %v", code, first)
	}
	stale := fe6acDocRevision(t) // read AFTER: the second writer below uses an OLDER one
	_ = stale
	w = httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp?documentRevision="+probe.docRevisionAtProbe(t), ldapProfileBodyForPut("Second with the old revision", nil)))
	fe6aAssertRefusal(t, w, http.StatusConflict, "stale")
	if n := len(reg.All()); n != 1 {
		t.Fatalf("stale create landed (%d profiles)", n)
	}
}

func TestFE6A0C_CR4_UserCreateRequiresTheRosterRevision(t *testing.T) {
	c, path := fe6aSwapCfg(t, "")
	before := fe6aReadFile(t, path)
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{"username": "carol", "password": "CarolPass1", "role": "viewer"}))
	m := fe6aAssertRefusal(t, w, http.StatusPreconditionRequired, "precondition_required")
	if fe6aCurrentRevision(t, m) != c.RosterRevision() {
		t.Fatalf("428 must carry the current roster revision; got %v", m)
	}
	if c.UIUserExists("carol") {
		t.Fatal("unfenced create landed")
	}
	rev := c.RosterRevision()
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "carol", "password": "CarolPass1", "role": "viewer"}))
	if w.Code != http.StatusOK {
		t.Fatalf("fenced create = %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users?revision="+strconv.FormatInt(rev, 10), map[string]any{"username": "dave", "password": "DavePass123", "role": "viewer"}))
	fe6aAssertRefusal(t, w, http.StatusConflict, "stale")
	if c.UIUserExists("dave") {
		t.Fatal("stale create landed")
	}
	_ = before
}

func TestFE6A0C_CR4_LockoutResetIsFencedOnAGeneration(t *testing.T) {
	t.Cleanup(loginLimiter.SnapshotAndClear())
	for range lockoutMaxAttempts {
		loginLimiter.RecordFailure("198.51.100.77", "locked-user")
	}
	w := httptest.NewRecorder()
	apiAuthLockouts(w, getReq("/api/auth/lockouts"))
	m := fe6aJSON(t, w)
	gen, ok := m["generation"].(float64)
	if !ok || gen <= 0 {
		t.Fatalf("lockout listing must expose a positive server-owned generation; body=%s", w.Body.String())
	}
	if m["scope"] != "node-local" {
		t.Fatal("lockout listing must be labelled node-local")
	}
	w = httptest.NewRecorder()
	apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts", map[string]any{"username": "locked-user"}))
	r := fe6aAssertRefusal(t, w, http.StatusPreconditionRequired, "precondition_required")
	if cur, _ := r["current"].(map[string]any); cur["generation"] != gen {
		t.Fatalf("428 must carry current.generation; got %v", r)
	}
	if locked, _ := loginLimiter.Check("198.51.100.77", "locked-user"); !locked {
		t.Fatal("unfenced reset cleared the lock")
	}
	// The lock set changes (another failure) → the observed generation is stale.
	loginLimiter.RecordFailure("198.51.100.78", "someone-else")
	w = httptest.NewRecorder()
	apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts?generation="+strconv.FormatInt(int64(gen), 10), map[string]any{"username": "locked-user"}))
	fe6aAssertRefusal(t, w, http.StatusConflict, "stale")
	if locked, _ := loginLimiter.Check("198.51.100.77", "locked-user"); !locked {
		t.Fatal("stale reset cleared the lock")
	}
	w = httptest.NewRecorder()
	apiAuthLockouts(w, getReq("/api/auth/lockouts"))
	gen2, _ := fe6aJSON(t, w)["generation"].(float64)
	// Unknown target → 404 with zero mutation.
	w = httptest.NewRecorder()
	apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts?generation="+strconv.FormatInt(int64(gen2), 10), map[string]any{"username": "nobody-here"}))
	fe6aAssertRefusal(t, w, http.StatusNotFound, "not_found")
	w = httptest.NewRecorder()
	apiAuthLockouts(w, jsonReq(http.MethodPost, "/api/auth/lockouts?generation="+strconv.FormatInt(int64(gen2), 10), map[string]any{"username": "locked-user"}))
	if w.Code != http.StatusOK {
		t.Fatalf("fenced reset = %d: %s", w.Code, w.Body.String())
	}
	if locked, _ := loginLimiter.Check("198.51.100.77", "locked-user"); locked {
		t.Fatal("fenced reset did not clear the lock")
	}
	if g3, _ := fe6aJSON(t, w)["generation"].(float64); g3 <= gen2 {
		t.Fatalf("a successful reset must advance the generation (%v → %v)", gen2, g3)
	}
}

// ─── CR5 — IdP delete serialises behind the reference-integrity gate ────────

func TestFE6A0C_CR5_IdPDeleteWaitsForTheReferenceGate(t *testing.T) {
	reg, _ := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	withFreshPolicyStore(t)
	withConfigVersionsDir(t)
	if err := reg.Upsert(&IdPProfile{ID: "gated-saml", Name: "Gated", Type: IdPTypeSAML, SAML: &SAMLProfileConfig{MetadataXML: "<EntityDescriptor/>"}}); err != nil {
		t.Fatal(err)
	}
	rev := fe6aIdPRevision(t, "gated-saml")

	// An SSORequired writer is inside its validate→commit window: it holds
	// the SHARED side of objectReferenceMutationGate.
	refWriteLock()
	released := false
	defer func() {
		if !released {
			refWriteUnlock()
		}
	}()
	done := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/gated-saml?revision="+strconv.FormatInt(rev, 10), nil), "gated-saml")
		done <- w.Code
	}()
	select {
	case code := <-done:
		t.Fatalf("CR5: IdP delete completed (%d) while an SSORequired writer held the reference gate — no shared integrity boundary", code)
	case <-time.After(2 * time.Second):
		// Correct: the delete is waiting on the exclusive side.
	}
	refWriteUnlock()
	released = true
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("delete after the writer released = %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("delete never completed after the gate was released")
	}
	if reg.Get("gated-saml") != nil {
		t.Fatal("delete did not land after the gate was released")
	}
}

// ─── CR6 — dependency failures never cross the boundary ─────────────────────

func TestFE6A0C_CR6_DependencyErrorsAreBoundedOnEverySink(t *testing.T) {
	const canary = "CANARY-tls-7f3e91-internal-host.corp.example"
	reg, path := fe6aSwapRegistry(t, "")
	fe6aSwapConfigStore(t)
	orig := ssrfSafeDialContext
	ssrfSafeDialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 203.0.113.10:443: " + canary + ": x509: certificate signed by unknown authority")
	}
	t.Cleanup(func() { ssrfSafeDialContext = orig })
	since := fe6aSince()
	probe := fe6aProbeIdP(t, reg, path)
	var w *httptest.ResponseRecorder
	logs := captureLogger(t, func() {
		w = httptest.NewRecorder()
		apiIdPList(w, jsonReq(http.MethodPost, "/api/idp?documentRevision="+fe6acDocRevision(t), map[string]any{
			"name": "Broken OIDC", "type": "oidc", "enabled": true,
			"oidc": map[string]any{"issuer": "https://203.0.113.10", "clientId": "c", "clientSecret": "s"},
		}))
	})
	m := fe6aAssertRefusal(t, w, http.StatusBadGateway, "provider_compile_failed")
	if cur, _ := m["current"].(map[string]any); cur["reason"] != "oidc_discovery" {
		t.Fatalf("refusal must carry a bounded reason class; got %v", m)
	}
	if strings.Contains(w.Body.String(), canary) || strings.Contains(w.Body.String(), "203.0.113.10") || strings.Contains(w.Body.String(), "x509") {
		t.Fatalf("response leaked dependency detail: %s", w.Body.String())
	}
	if strings.Contains(logs, canary) {
		t.Fatalf("process log leaked the dependency detail: %s", logs)
	}
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS >= since && strings.Contains(e.Detail+e.Before+e.After+e.Object, canary) {
			t.Fatalf("audit leaked the dependency detail: %+v", e)
		}
	}
	probe.assertIdPUnchanged(t, reg, path, "idp.create")
}

// ─── CR7 — non-persistable stores refuse administrative mutations ───────────

func TestFE6A0C_CR7_InMemoryStoresRefuseAdminMutations(t *testing.T) {
	orig := idpRegistry
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)} // no path
	t.Cleanup(func() { idpRegistry = orig })
	fe6aSwapConfigStore(t)
	since := fe6aSince()
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp?documentRevision="+fe6acDocRevision(t), ldapProfileBodyForPut("Volatile", nil)))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	if n := len(idpRegistry.All()); n != 0 {
		t.Fatalf("refused create mutated the in-memory registry (%d)", n)
	}
	fe6aAssertNoAudit(t, since, "idp.create")
	w = httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	if p, _ := fe6aJSON(t, w)["persisted"].(bool); p {
		t.Fatal("read model must keep reporting persisted:false")
	}

	origCfg := cfg
	cfg = newTestConfig() // no users file
	t.Cleanup(func() { cfg = origCfg })
	if err := cfg.SetAuth("root", "RootPass1"); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users?revision="+strconv.FormatInt(cfg.RosterRevision(), 10), map[string]any{"username": "carol", "password": "CarolPass1", "role": "viewer"}))
	fe6aAssertRefusal(t, w, http.StatusServiceUnavailable, "persistence_not_configured")
	if cfg.UIUserExists("carol") {
		t.Fatal("refused create mutated the in-memory roster")
	}
	fe6aAssertNoAudit(t, since, "auth.users.create")
}

// ─── CR8 — fleet publication truth ──────────────────────────────────────────

func TestFE6A0C_CR8_RejectedPublicationIsAStructuredFact(t *testing.T) {
	_, _ = fe6aSwapRegistry(t, "")
	store := fe6aSwapConfigStore(t)
	withConfigVersionsDir(t)
	setRewriteIdentityDegraded("cr8-injected")
	t.Cleanup(clearRewriteIdentityDegraded)
	since := fe6aSince()
	code, m := fe6acCreateFenced(t, ldapProfileBodyForPut("Fleet", nil))
	if code != http.StatusOK {
		t.Fatalf("local commit must succeed: %d %v", code, m)
	}
	cluster, _ := m["cluster"].(map[string]any)
	if cluster["publication"] != "rejected" {
		t.Fatalf("action result must carry cluster.publication=rejected; got %v", m)
	}
	if reason, _ := cluster["reason"].(string); reason == "" || strings.Contains(reason, "cr8-injected") {
		t.Fatalf("cluster.reason must be a bounded class, got %q", reason)
	}
	e := fe6aFindAudit(since, "idp.create")
	if e == nil || !strings.Contains(e.Detail, "fleet=rejected") {
		t.Fatalf("audit must distinguish the fleet rejection from the local commit; got %+v", e)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	rm := fe6aJSON(t, w)
	rc, _ := rm["cluster"].(map[string]any)
	if rc["state"] != "pending" {
		t.Fatalf("read model must show the fleet state pending; got %v", rm["cluster"])
	}
	if store.Version() != 0 {
		t.Fatal("a rejected publication must not advance the store version")
	}
	// The empty-registry publication follows the same contract.
	id, _ := m["id"].(string)
	rev := fe6aIdPRevision(t, id)
	w = httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+id+"?revision="+strconv.FormatInt(rev, 10), nil), id)
	if w.Code != http.StatusOK {
		t.Fatalf("delete = %d", w.Code)
	}
	dm := fe6aJSON(t, w)
	if dc, _ := dm["cluster"].(map[string]any); dc["publication"] != "rejected" {
		t.Fatalf("delete of the last profile must report the rejected publication; got %v", dm)
	}
	// Recovery: once the fleet accepts, the read model is published again.
	clearRewriteIdentityDegraded()
	if err := publishCurrentConfigSnapshot(); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	rc, _ = fe6aJSON(t, w)["cluster"].(map[string]any)
	if rc["state"] != "published" {
		t.Fatalf("read model must show published after a successful publish; got %v", rc)
	}
}

// ─── CR9 — cutover: client operationId, replay, lookup, durability truth ────

func TestFE6A0C_CR9_CutoverWriteRequiresAndReplaysTheOperationId(t *testing.T) {
	settings := filepath.Join(t.TempDir(), "admin_settings.json")
	reg, _ := fe6aLegacyLDAPFixture(t, settings)
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = true
	// A cutover-bearing write without an operationId is refused before any write.
	code, m := fe6acCreateFenced(t, body)
	if code != http.StatusPreconditionRequired || m["code"] != "operation_id_required" {
		t.Fatalf("cutover write without operationId = %d %v, want 428 operation_id_required", code, m)
	}
	if n := len(reg.All()); n != 0 || legacyLDAPRetired() {
		t.Fatal("refused cutover write mutated state")
	}
	const opID = "3f0e0d3a-5b7f-4f2b-9a8f-1c2d3e4f5a6b"
	code, first := fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm=ldap://legacy.corp.example:389")
	if code != http.StatusOK {
		t.Fatalf("cutover create = %d %v", code, first)
	}
	if first["operationId"] != opID {
		t.Fatalf("success must echo the operationId; got %v", first)
	}
	before := fe6acAuditSnapshot()
	// The lost-response retry: same operationId, same candidate → REPLAY.
	code, again := fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm=ldap://legacy.corp.example:389")
	if code != http.StatusOK {
		t.Fatalf("replay = %d %v", code, again)
	}
	if rep, _ := again["replayed"].(bool); !rep || again["id"] != first["id"] {
		t.Fatalf("duplicate operationId must replay the recorded result (same profile), got %v", again)
	}
	if n := len(reg.All()); n != 1 {
		t.Fatalf("duplicate operationId created a second profile (%d)", n)
	}
	fe6acAssertNoNewAudit(t, before, "idp.create", "idp.legacy_ldap.retired")
	// Authoritative lookup.
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	if w.Code != http.StatusOK {
		t.Fatalf("operation lookup = %d: %s", w.Code, w.Body.String())
	}
	lk := fe6aJSON(t, w)
	if lk["state"] != "committed" || lk["profileId"] != first["id"] || lk["operationId"] != opID {
		t.Fatalf("lookup must report the committed operation bound to its profile; got %v", lk)
	}
	if _, ok := lk["registryRevision"].(string); !ok {
		t.Fatalf("lookup must carry the registry revision the operation was bound to; got %v", lk)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/00000000-0000-4000-8000-000000000000"))
	fe6aAssertRefusal(t, w, http.StatusNotFound, "not_found")
	// A different candidate under the same operationId is a mismatch, never a second write.
	body["name"] = "Different"
	code, mm := fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm=ldap://legacy.corp.example:389")
	if code != http.StatusConflict || mm["code"] != "operation_mismatch" {
		t.Fatalf("mismatched replay = %d %v, want 409 operation_mismatch", code, mm)
	}
}

func TestFE6A0C_CR9_AbortedCutoverIsLookedUpAsAborted(t *testing.T) {
	reg, _ := fe6aLegacyLDAPFixture(t, fe6aBrokenPath(t, "admin_settings.json"))
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = true
	const opID = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	code, m := fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm=ldap://legacy.corp.example:389")
	if code != http.StatusInternalServerError || m["code"] != "persist_failed" {
		t.Fatalf("cutover with a failing sentinel = %d %v", code, m)
	}
	if n := len(reg.All()); n != 0 {
		t.Fatal("aborted cutover published a profile")
	}
	mux := d0WireMux(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, getReq("/api/idp/operations/"+opID))
	if w.Code != http.StatusOK {
		t.Fatalf("lookup = %d: %s", w.Code, w.Body.String())
	}
	if st := fe6aJSON(t, w)["state"]; st != "aborted" {
		t.Fatalf("lookup state = %v, want aborted", st)
	}
	// A retry of the same operation replays the aborted verdict — never a second attempt.
	code, m = fe6acCreateFenced(t, body, "operationId="+opID, "cutoverConfirm=ldap://legacy.corp.example:389")
	if code != http.StatusConflict || m["code"] != "operation_aborted" {
		t.Fatalf("replay of an aborted operation = %d %v, want 409 operation_aborted", code, m)
	}
}

func TestFE6A0C_CR9_ObservedCutoverReportsDurabilityTruth(t *testing.T) {
	_, _ = fe6aLegacyLDAPFixture(t, fe6aBrokenPath(t, "admin_settings.json"))
	// The observed path (boot reconciliation / CP→DP sync): the runtime
	// cutover must stay active (safety first) but its durability must be
	// reported truthfully.
	markLegacyLDAPRetired("observed in test")
	if !legacyLDAPRetired() {
		t.Fatal("observed cutover must take effect at runtime")
	}
	w := httptest.NewRecorder()
	apiIdPLegacyLDAP(w, getReq("/api/idp/legacy-ldap"))
	m := fe6aJSON(t, w)
	cut, _ := m["cutover"].(map[string]any)
	if d, ok := cut["durable"].(bool); !ok || d {
		t.Fatalf("cutover.durable must be false after a failed sentinel save; got %v", m)
	}
	if m["cutoverDurability"] != "pending_reconciliation" {
		t.Fatalf("read model must report pending_reconciliation; got %v", m)
	}
}

// ─── CR10 — the suite never writes the operator's /data tree ────────────────

func TestFE6A0C_CR10_TestProcessNeverTouchesDefaultDataDir(t *testing.T) {
	if strings.HasPrefix(configVersions.Dir(), defaultDataDir+"/") || configVersions.Dir() == defaultDataDir+"/config_versions" {
		t.Fatalf("the config-version store still points at the operator's %s tree (%s) — bind every data-dir default to the test data dir", defaultDataDir, configVersions.Dir())
	}
	if !strings.HasPrefix(configVersions.Dir(), dataDir) {
		t.Fatalf("config-version store %q is not under the test data dir %q", configVersions.Dir(), dataDir)
	}
	if got := audit.Get(); got == nil {
		t.Log("audit ring readable")
	}
}

// keep the sync import honest for the helper set above
var _ sync.Locker = (*sync.Mutex)(nil)

type urlT = url.URL

func parseURL(raw string) (*url.URL, error) { return url.Parse(raw) }

// docRevisionAtProbe recomputes the registry document revision of the
// profile set captured by the probe (the revision an older reader held).
func (p fe6aStateProbe) docRevisionAtProbe(t *testing.T) string {
	t.Helper()
	var profiles []*IdPProfile
	if err := json.Unmarshal([]byte(p.registryJSON), &profiles); err != nil {
		t.Fatal(err)
	}
	return idpDocumentRevisionOf(profiles)
}
