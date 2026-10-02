package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 TOTP mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/totp"
)

// auth_totp_preservation_test.go — SEC-TOTP-1.
//
// TOTP enrollment (secret + backup codes + the replay counter) is the second
// authentication factor for the admin plane: apiAuthLogin refuses to issue a
// session for an enrolled user until verifyLoginTOTP accepts a code
// (ui_auth.go). Its whole purpose is to SURVIVE a password compromise, so the
// only thing that may remove it is an explicit, audited de-enrolment.
//
// These gates pin that invariant against every credential-write primitive that
// reaches the roster. The DEFECT they were written against: Config.SetUIUser
// and Config.SetAuth both REPLACED the whole *uiAdminUser record on a password
// write, so an ordinary password change silently destroyed the user's second
// factor — and reset totpLastCounter to 0, reopening the OTP replay window
// that SetTOTPLastCounter exists to close.

// enrolTOTPUser seeds a user with a password and a full TOTP enrolment.
func enrolTOTPUser(t *testing.T, c *Config, user, pass string, role UIRole) {
	t.Helper()
	if err := c.SetUIUser(user, pass, role); err != nil {
		t.Fatalf("seed SetUIUser(%q): %v", user, err)
	}
	if !c.SetTOTPSecret(user, "JBSWY3DPEHPK3PXP", []string{"bcrypt-code-1", "bcrypt-code-2"}) {
		t.Fatalf("seed SetTOTPSecret(%q) returned false", user)
	}
	if !c.SetTOTPLastCounter(user, 987654) {
		t.Fatalf("seed SetTOTPLastCounter(%q) returned false", user)
	}
}

// assertTOTPIntact fails when any part of the enrolment seeded by
// enrolTOTPUser is missing.
func assertTOTPIntact(t *testing.T, c *Config, user, where string) {
	t.Helper()
	if !c.UserHasTOTP(user) {
		t.Errorf("%s: TOTP enrolment was destroyed — the account silently dropped to single-factor", where)
	}
	if got := c.GetTOTPSecret(user); got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("%s: TOTP secret = %q, want the seeded secret", where, got)
	}
	if got := c.GetTOTPLastCounter(user); got != 987654 {
		t.Errorf("%s: totpLastCounter = %d, want 987654 — resetting it reopens the OTP replay window", where, got)
	}
	if !c.ConsumeBackupCode(user, "") && len(backupCodesOf(c, user)) != 2 {
		t.Errorf("%s: backup codes = %v, want the 2 seeded codes", where, backupCodesOf(c, user))
	}
}

// resetPasswordArg builds the documented `--reset-password username:newpassword`
// argument. Assembling it beats an inline "user:pass" literal: gosec G101 reads
// that shape as a hardcoded credential (and flags any variable whose name
// contains "cred"), and a test fixture should not train reviewers to scroll past
// that warning.
func resetPasswordArg(user, newPassword string) string { return user + ":" + newPassword }

// backupCodesOf reads the stored (hashed) backup codes for assertions.
func backupCodesOf(c *Config, user string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u, ok := c.uiUsers[user]; ok {
		return append([]string(nil), u.backupCodes...)
	}
	return nil
}

// TestSetUIUser_PasswordChangePreservesTOTP is the store-level gate: a password
// write against an EXISTING user must not disturb the second factor.
func TestSetUIUser_PasswordChangePreservesTOTP(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "alice", "Passw0rd1", RoleAdmin)

	if err := c.SetUIUser("alice", "Passw0rd2", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser (password change): %v", err)
	}
	assertTOTPIntact(t, c, "alice", "SetUIUser password change")

	// Positive control: the new password must actually be in force.
	if _, ok := c.VerifyUIUser("alice", "Passw0rd2"); !ok {
		t.Error("new password does not authenticate — the password write was lost")
	}
	if _, ok := c.VerifyUIUser("alice", "Passw0rd1"); ok {
		t.Error("old password still authenticates — the password write did not take effect")
	}
}

// TestSetUIUser_RoleChangePreservesTOTP covers the password-empty branch
// (role-only update), which already preserved the record — a control that the
// fix did not move it.
func TestSetUIUser_RoleChangePreservesTOTP(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "bob", "Passw0rd1", RoleAdmin)

	if err := c.SetUIUser("bob", "", RoleViewer); err != nil {
		t.Fatalf("SetUIUser (role change): %v", err)
	}
	assertTOTPIntact(t, c, "bob", "SetUIUser role-only change")
	if role, _ := c.VerifyUIUser("bob", "Passw0rd1"); role != RoleViewer {
		t.Errorf("role = %q, want viewer", role)
	}
}

// TestSetUIUser_NewUserHasNoTOTP is the control for the create branch: a brand
// new account must start unenrolled, never inherit anything.
func TestSetUIUser_NewUserHasNoTOTP(t *testing.T) {
	c := newTestConfig()
	if err := c.SetUIUser("carol", "Passw0rd1", RoleOperator); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if c.UserHasTOTP("carol") {
		t.Error("a freshly created user must not be enrolled in TOTP")
	}
	if got := c.GetTOTPLastCounter("carol"); got != 0 {
		t.Errorf("new user totpLastCounter = %d, want 0", got)
	}
}

// TestSetAuth_PreservesTOTPOfMirroredUser pins the second primitive: SetAuth
// mirrors the legacy -user/-pass credential into the RBAC roster and must not
// clobber an enrolment already held for that username. Reachable at runtime
// from POST /api/settings/auth (ui_config.go), not just at boot.
func TestSetAuth_PreservesTOTPOfMirroredUser(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "dave", "Passw0rd1", RoleAdmin)

	if err := c.SetAuth("dave", "Passw0rd2"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	assertTOTPIntact(t, c, "dave", "SetAuth credential update")
	if _, ok := c.VerifyUIUser("dave", "Passw0rd2"); !ok {
		t.Error("new password does not authenticate after SetAuth")
	}
}

// TestSetAuth_NewUserHasNoTOTP is the create-branch control for SetAuth.
func TestSetAuth_NewUserHasNoTOTP(t *testing.T) {
	c := newTestConfig()
	if err := c.SetAuth("erin", "Passw0rd1"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if c.UserHasTOTP("erin") {
		t.Error("a user created by SetAuth must not be enrolled in TOTP")
	}
}

// TestSetUIUser_RejectedPasswordLeavesTOTPIntact is the negative/boundary
// case: a password that fails complexity must change nothing at all.
func TestSetUIUser_RejectedPasswordLeavesTOTPIntact(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "frank", "Passw0rd1", RoleAdmin)

	if err := c.SetUIUser("frank", "short", RoleAdmin); err == nil {
		t.Fatal("SetUIUser accepted a password that fails complexity")
	}
	assertTOTPIntact(t, c, "frank", "rejected password write")
	if _, ok := c.VerifyUIUser("frank", "Passw0rd1"); !ok {
		t.Error("original password stopped working after a rejected write")
	}
}

// TestAPIChangePassword_PreservesTOTP drives the real self-service handler.
// This is the reachable path: ANY authenticated principal (viewer and above)
// can call it for its own account, so a stolen session plus the known current
// password used to convert into a PERMANENT second-factor removal.
func TestAPIChangePassword_PreservesTOTP(t *testing.T) {
	snapshotAuthGlobals(t)
	ensureAuthStartupTestLogger(t)

	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.uiUsersFile = ""
	cfg.mu.Unlock()
	cfg.cache.clear()

	enrolTOTPUser(t, cfg, "grace", "Passw0rd1", RoleAdmin)

	body, _ := json.Marshal(map[string]string{
		"current_password": "Passw0rd1",
		"new_password":     "Passw0rd2",
	})
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	ctx = context.WithValue(ctx, uiUserKey{}, "grace")
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/auth/change-password", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	apiAuthChangePassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("change-password returned %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	assertTOTPIntact(t, cfg, "grace", "POST /api/auth/change-password")
	if _, ok := cfg.VerifyUIUser("grace", "Passw0rd2"); !ok {
		t.Error("new password does not authenticate after change-password")
	}
}

// TestAPIAuthUsers_AdminPasswordSetPreservesTOTP drives the admin roster
// handler: an admin resetting another account's password must not silently
// de-enrol that account's second factor.
func TestAPIAuthUsers_AdminPasswordSetPreservesTOTP(t *testing.T) {
	snapshotAuthGlobals(t)
	ensureAuthStartupTestLogger(t)

	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.uiUsersFile = ""
	cfg.mu.Unlock()
	cfg.cache.clear()

	enrolTOTPUser(t, cfg, "heidi", "Passw0rd1", RoleOperator)

	body, _ := json.Marshal(map[string]string{
		"username": "heidi",
		"password": "Passw0rd2",
		"role":     string(RoleOperator),
	})
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/auth/users", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	apiAuthUsers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/users returned %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	assertTOTPIntact(t, cfg, "heidi", "POST /api/auth/users password set")
}

// TestSetUIUser_PreservationSurvivesPersistence proves the invariant is
// DURABLE, not just in-memory: the roster is written and read back through the
// real SaveUIUsersFile / LoadUIUsersFile pair after a password change.
// Persistence is what made the old wipe permanent, so it is what must be
// pinned.
func TestSetUIUser_PreservationSurvivesPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui_users.json")

	before := newTestConfig()
	before.SetUIUsersFile(path)
	enrolTOTPUser(t, before, "ivan", "Passw0rd1", RoleAdmin)
	if err := before.SetUIUser("ivan", "Passw0rd2", RoleAdmin); err != nil {
		t.Fatalf("password change: %v", err)
	}
	if err := before.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}

	after := newTestConfig()
	after.SetUIUsersFile(path)
	if err := after.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	assertTOTPIntact(t, after, "ivan", "roster round-trip after password change")
	if _, ok := after.VerifyUIUser("ivan", "Passw0rd2"); !ok {
		t.Error("new password does not authenticate after the roster round-trip")
	}
}

// TestSetUIUser_ConcurrentWithTOTPMutators is the concurrency gate. The fix
// carries fields from the stored record into a replacement one; that must not
// race the authentication hot path (VerifyUIUser reads passHash after
// releasing the read lock) or lose a counter update landing beside it. Run
// under -race.
func TestSetUIUser_ConcurrentWithTOTPMutators(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "judy", "Passw0rd1", RoleAdmin)

	const iterations = 60
	var wg sync.WaitGroup
	wg.Add(4)

	go func() { // credential writer
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := c.SetUIUser("judy", "Passw0rd1", RoleAdmin); err != nil {
				t.Errorf("concurrent SetUIUser: %v", err)
				return
			}
		}
	}()
	go func() { // counter advance (login-side replay guard)
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			c.SetTOTPLastCounter("judy", int64(1_000_000+i))
		}
	}()
	go func() { // enrolment reader
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = c.UserHasTOTP("judy")
			_ = c.GetTOTPSecret("judy")
			_ = c.GetTOTPLastCounter("judy")
		}
	}()
	go func() { // authentication hot path
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _ = c.VerifyUIUser("judy", "Passw0rd1")
		}
	}()
	wg.Wait()

	if !c.UserHasTOTP("judy") {
		t.Fatal("enrolment lost under concurrent credential writes")
	}
	// The counter is monotonic by SetTOTPLastCounter's own contract; a
	// credential write must never drag it backwards below the seed.
	if got := c.GetTOTPLastCounter("judy"); got < 987654 {
		t.Errorf("totpLastCounter regressed to %d under concurrency — replay window reopened", got)
	}
}

// TestRunResetPasswordCommand_ClearsTOTPExplicitlyAndSaysSo pins the ONE path
// that may still drop a second factor. --reset-password is the documented
// break-glass (host/container shell only); an operator who has lost the
// authenticator as well as the password depends on it, so the behaviour is
// unchanged — but it is now deliberate rather than a side effect, and the
// operator is told the account became single-factor.
func TestRunResetPasswordCommand_ClearsTOTPExplicitlyAndSaysSo(t *testing.T) {
	restoreGlobalRosterPath(t)
	snapshotAuthGlobals(t)
	ensureAuthStartupTestLogger(t)

	path := filepath.Join(t.TempDir(), "ui_users.json")
	seed := newTestConfig()
	seed.SetUIUsersFile(path)
	enrolTOTPUser(t, seed, "kate", "Passw0rd1", RoleAdmin)
	if err := seed.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.mu.Unlock()
	cfg.cache.clear()

	resetArg := resetPasswordArg("kate", "BrandNewPass1")
	uiUsersFile := path
	s := &startupState{resetPwUser: &resetArg, uiUsersFile: &uiUsersFile}

	stdout, runErr := captureStdout(t, func() error { return runResetPasswordCommand(s) })
	if runErr != nil {
		t.Fatalf("runResetPasswordCommand: %v", runErr)
	}

	if cfg.UserHasTOTP("kate") {
		t.Error("break-glass reset must clear TOTP — an operator who lost the authenticator has no other way in")
	}
	if !strings.Contains(stdout, "TOTP") || !strings.Contains(stdout, "single-factor") {
		t.Errorf("break-glass reset removed a second factor without saying so; stdout=%q", stdout)
	}

	// And it must be durable, not just in memory.
	reloaded := newTestConfig()
	reloaded.SetUIUsersFile(path)
	if err := reloaded.LoadUIUsersFile(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.UserHasTOTP("kate") {
		t.Error("TOTP enrolment survived the break-glass reset on disk")
	}
}

// TestRunResetPasswordCommand_SilentWhenNoTOTPEnrolled is the control: the
// warning must not fire for an account that never had a second factor.
func TestRunResetPasswordCommand_SilentWhenNoTOTPEnrolled(t *testing.T) {
	restoreGlobalRosterPath(t)
	snapshotAuthGlobals(t)
	ensureAuthStartupTestLogger(t)

	path := filepath.Join(t.TempDir(), "ui_users.json")
	seed := newTestConfig()
	seed.SetUIUsersFile(path)
	if err := seed.SetUIUser("leo", "Passw0rd1", RoleAdmin); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := seed.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.mu.Unlock()
	cfg.cache.clear()

	resetArg := resetPasswordArg("leo", "BrandNewPass1")
	uiUsersFile := path
	s := &startupState{resetPwUser: &resetArg, uiUsersFile: &uiUsersFile}
	stdout, runErr := captureStdout(t, func() error { return runResetPasswordCommand(s) })
	if runErr != nil {
		t.Fatalf("runResetPasswordCommand: %v", runErr)
	}
	if strings.Contains(stdout, "single-factor") {
		t.Errorf("warned about removing a second factor that was never enrolled; stdout=%q", stdout)
	}
}

// TestWall_CredentialWritesGoThroughTOTPPreservingConstructor is the
// structural wall. Behavioural gates cover the paths that exist today; this
// one covers the path someone adds tomorrow. Every &uiAdminUser{…} composite
// literal in store.go must either be the disk loader (which sets the TOTP
// fields itself) or live inside newUIAdminUserPreservingTOTP. A new credential
// writer that builds a bare record would silently re-introduce the wipe, and
// no behavioural test would name it.
func TestWall_CredentialWritesGoThroughTOTPPreservingConstructor(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "store.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse store.go: %v", err)
	}

	// Fields that carry the second factor. A literal that omits ANY of them is
	// only acceptable inside the preserving constructor.
	totpFields := []string{"totpSecret", "backupCodes", "totpLastCounter"}

	var checked int
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		for _, lit := range uiAdminUserLiterals(fn) {
			checked++
			if fn.Name.Name == "newUIAdminUserPreservingTOTP" {
				continue // the sanctioned constructor
			}
			set := compositeLitFieldNames(lit)
			for _, f := range totpFields {
				if set[f] {
					continue
				}
				t.Errorf("%s constructs a uiAdminUser without %s at %s — a credential write "+
					"that does not go through newUIAdminUserPreservingTOTP silently destroys the "+
					"account's second factor (SEC-TOTP-1)", fn.Name.Name, f, fset.Position(lit.Pos()))
				break
			}
		}
	}
	// Not-vacuous check: if the selector stops matching, the wall proves nothing.
	if checked < 2 {
		t.Fatalf("wall inspected only %d uiAdminUser literals — the selector no longer matches "+
			"the code it is meant to guard", checked)
	}
}

// uiAdminUserLiterals returns every `uiAdminUser{…}` composite literal in fn's
// body. Split out of the wall above so the wall stays a flat loop (gocognit).
func uiAdminUserLiterals(fn *ast.FuncDecl) []*ast.CompositeLit {
	var out []*ast.CompositeLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if ident, ok := lit.Type.(*ast.Ident); ok && ident.Name == "uiAdminUser" {
			out = append(out, lit)
		}
		return true
	})
	return out
}

// compositeLitFieldNames returns the set of field names a keyed composite
// literal assigns. Positional elements are ignored: uiAdminUser is only ever
// built with keys, and a positional literal would not compile against a struct
// whose field set this wall exists to police.
func compositeLitFieldNames(lit *ast.CompositeLit) map[string]bool {
	set := map[string]bool{}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok {
			set[k.Name] = true
		}
	}
	return set
}

// TestWall_TOTPPublicPrefixIsInert stood here and was REMOVED WITH THE ENTRY
// IT GUARDED (SEC-PUBLICPATH-1), which is what its own vacuity check
// instructed: "if the entry was removed deliberately, remove this test with
// it". It watched the inert `/api/auth/totp` PREFIX in isPublicUIAuthPath and
// failed if a route ever landed under it. The prefix is now gone, so there is
// nothing left to be inert — a future /api/auth/totp/enroll route is gated by
// default rather than public by default, which is the stronger answer to the
// same finding (SEC-TOTP-1) and needs no wall to stay true.
//
// The allowlist itself is now walled generally rather than per-prefix:
// TestPublicAllowlist_EveryEntryMatchesARegisteredRoute (ui_public_allowlist_test.go)
// fails for ANY allowlist entry that matches no registered route, so the next
// pre-authorised-but-nonexistent path is caught whatever its name.

// TestWall_PublicAllowlistRoutesAreDeclaredPublic pins the forward direction of
// allowlist/metadata agreement: anything uiAuthMiddleware serves without
// authentication must SAY so in uiRoutes. Metadata that claims a route is
// authenticated while the middleware lets it through unauthenticated is the
// shape a reviewer reads as safe and an attacker reads as open.
func TestWall_PublicAllowlistRoutesAreDeclaredPublic(t *testing.T) {
	var checked int
	for _, rt := range uiRoutes {
		if !isPublicUIAuthPath(rt.Path) {
			continue
		}
		checked++
		if !rt.Public {
			t.Errorf("route %q (%s) is on the uiAuthMiddleware public allowlist but its uiRoutes "+
				"entry says Public=false — the metadata and the middleware disagree about whether "+
				"an unauthenticated caller can reach it", rt.Path, rt.Handler)
		}
	}
	if checked == 0 {
		t.Fatal("wall inspected no routes — isPublicUIAuthPath no longer matches any registered path")
	}
}

// ── Replay counter lifecycle (Codex review, PR #1429) ─────────────────────
//
// The counter belongs to the SECRET. Preserving it across a credential write
// is the whole point of SEC-TOTP-1, but preserving it across DE-ENROLMENT is a
// lockout: VerifyTOTPReturnCounter skips every candidate with
// `candidate <= lastCounter`, so a counter left behind by the previous
// authenticator refuses the next one until wall-clock time passes it — and
// indefinitely after a clock rollback. These gates pin both halves.

// TestClearTOTP_ResetsReplayCounter is the store-level gate.
func TestClearTOTP_ResetsReplayCounter(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "mallory", "Passw0rd1", RoleAdmin)

	if !c.ClearTOTP("mallory") {
		t.Fatal("ClearTOTP returned false for an existing user")
	}
	if c.UserHasTOTP("mallory") {
		t.Error("secret survived ClearTOTP")
	}
	if got := c.GetTOTPLastCounter("mallory"); got != 0 {
		t.Errorf("totpLastCounter = %d after ClearTOTP, want 0 — a counter that outlives its "+
			"secret refuses the next authenticator enrolled for this account", got)
	}
}

// TestSetTOTPSecret_NewSecretResetsCounter covers re-enrolment: a different
// secret must start from a clean counter, or its first code is refused.
func TestSetTOTPSecret_NewSecretResetsCounter(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "niaj", "Passw0rd1", RoleAdmin)

	if !c.SetTOTPSecret("niaj", "KRSXG5CTMVRXEZLU", []string{"new-1"}) {
		t.Fatal("SetTOTPSecret returned false")
	}
	if got := c.GetTOTPLastCounter("niaj"); got != 0 {
		t.Errorf("totpLastCounter = %d after installing a DIFFERENT secret, want 0 — the new "+
			"device's codes would be refused until wall-clock time passed the old counter", got)
	}
}

// TestSetTOTPSecret_SameSecretKeepsCounter is the CONTROL, and it is the
// security half: re-issuing backup codes for the SAME secret must not zero the
// replay guard. The cheapest way to pass the gate above is to reset the
// counter unconditionally, which would reopen the replay window for a live
// secret — strictly worse than the lockout it fixes.
func TestSetTOTPSecret_SameSecretKeepsCounter(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "olivia", "Passw0rd1", RoleAdmin)

	if !c.SetTOTPSecret("olivia", "JBSWY3DPEHPK3PXP", []string{"regenerated-1", "regenerated-2"}) {
		t.Fatal("SetTOTPSecret returned false")
	}
	if got := c.GetTOTPLastCounter("olivia"); got != 987654 {
		t.Errorf("totpLastCounter = %d after re-issuing backup codes for the SAME secret, want "+
			"987654 — zeroing it here reopens the OTP replay window for a live secret", got)
	}
}

// TestRunResetPasswordCommand_LeavesNoStaleReplayCounter is the end-to-end
// gate on the break-glass path: the account must be ready to re-enrol, which
// is exactly what the warning the command prints tells the operator to do.
func TestRunResetPasswordCommand_LeavesNoStaleReplayCounter(t *testing.T) {
	restoreGlobalRosterPath(t)
	snapshotAuthGlobals(t)
	ensureAuthStartupTestLogger(t)

	path := filepath.Join(t.TempDir(), "ui_users.json")
	seed := newTestConfig()
	seed.SetUIUsersFile(path)
	enrolTOTPUser(t, seed, "peggy", "Passw0rd1", RoleAdmin)
	if err := seed.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}

	cfg.mu.Lock()
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.mu.Unlock()
	cfg.cache.clear()

	resetArg := resetPasswordArg("peggy", "BrandNewPass1")
	uiUsersFile := path
	s := &startupState{resetPwUser: &resetArg, uiUsersFile: &uiUsersFile}
	if _, err := captureStdout(t, func() error { return runResetPasswordCommand(s) }); err != nil {
		t.Fatalf("runResetPasswordCommand: %v", err)
	}

	if got := cfg.GetTOTPLastCounter("peggy"); got != 0 {
		t.Errorf("totpLastCounter = %d after the break-glass reset, want 0 — the account cannot "+
			"re-enrol an authenticator until wall-clock time passes a counter from the device the "+
			"operator no longer has", got)
	}
	// And durably: the stale counter must not come back from disk.
	reloaded := newTestConfig()
	reloaded.SetUIUsersFile(path)
	if err := reloaded.LoadUIUsersFile(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.GetTOTPLastCounter("peggy"); got != 0 {
		t.Errorf("persisted totpLastCounter = %d after the break-glass reset, want 0", got)
	}
}

// TestRunResetPasswordCommand_LeavesNoGlobalAuthPostureBehind is a
// test-hygiene gate, not a product gate, and it earned its place: CI's
// shuffled double run (Deep · determinism) failed on this PR because the
// break-glass gates above are the FIRST tests in the tree to drive
// runResetPasswordCommand to SUCCESS, and success reaches
// cfg.LoadUIUsersFile, which rewrites the process-global
// cfg.defaultAuthOutcome from the roster envelope. snapshotAuthGlobals did
// not capture that field, so the global authentication posture leaked into
// whichever test the shuffle ran next — a failure whose reported location has
// nothing to do with its cause.
//
// The fix is in snapshotAuthGlobals (it now restores the field, as its own
// "every cfg field the loadAuth slice touches" contract always required).
// This gate pins the property directly so the next person to add a test that
// loads a roster does not have to rediscover it from a shuffle seed.
func TestRunResetPasswordCommand_LeavesNoGlobalAuthPostureBehind(t *testing.T) {
	// Park the global on the value the default-Default load would overwrite,
	// so a regression is visible rather than accidentally matching.
	cfg.mu.Lock()
	cfg.defaultAuthOutcome = OutcomeExempt
	cfg.mu.Unlock()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.defaultAuthOutcome = OutcomeDefault
		cfg.mu.Unlock()
	})
	before := cfg.DefaultAuthOutcome()

	// A SUBTEST, not a closure: the helpers register their restoration with
	// t.Cleanup, which runs when the test they were given finishes. Asserting
	// inside the same test would read the globals BEFORE restoration and prove
	// nothing. The subtest boundary is also the real shape of the bug — one
	// test ends, its cleanups run, the next test observes what was left.
	t.Run("scoped break-glass reset", func(t *testing.T) {
		restoreGlobalRosterPath(t)
		snapshotAuthGlobals(t)
		ensureAuthStartupTestLogger(t)

		path := filepath.Join(t.TempDir(), "ui_users.json")
		seed := newTestConfig()
		seed.SetUIUsersFile(path)
		if err := seed.SetUIUser("quinn", "Passw0rd1", RoleAdmin); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := seed.SaveUIUsersFile(); err != nil {
			t.Fatalf("seed save: %v", err)
		}
		cfg.mu.Lock()
		cfg.uiUsers = map[string]*uiAdminUser{}
		cfg.mu.Unlock()
		cfg.cache.clear()

		resetArg := resetPasswordArg("quinn", "BrandNewPass1")
		uiUsersFile := path
		s := &startupState{resetPwUser: &resetArg, uiUsersFile: &uiUsersFile}
		if _, err := captureStdout(t, func() error { return runResetPasswordCommand(s) }); err != nil {
			t.Fatalf("runResetPasswordCommand: %v", err)
		}
		// Sanity: the reset really did run (otherwise the gate is vacuous).
		if !cfg.UIUserExists("quinn") {
			t.Fatal("reset did not populate the roster — the gate would be vacuous")
		}
	})

	if got := cfg.DefaultAuthOutcome(); got != before {
		t.Errorf("global defaultAuthOutcome = %q after a scoped break-glass reset, want %q — a test "+
			"that rewrites the process-wide authentication posture breaks whichever test the shuffle "+
			"runs next, and names the wrong one when it does", got, before)
	}
}

// ─── Codex review round 2: key identity, not string identity ────────────────
//
// The conditional reset above compared the STORED STRINGS. The verifier
// canonicalises case and surrounding whitespace before base32-decoding
// (internal/totp decodeSecret), so several spellings name ONE authenticator and
// generate identical codes. A raw string comparison therefore read a
// backup-code re-issue that spelled the same secret differently as a KEY
// CHANGE and zeroed the replay counter for a LIVE key — reopening the window
// TestSetTOTPSecret_SameSecretKeepsCounter exists to defend, reached through
// spelling rather than an identical literal, which is precisely why that
// control could not see it: it re-passes the same literal.

// TestSetTOTPSecret_SameKeyDifferentSpellingKeepsCounter is the defect gate.
func TestSetTOTPSecret_SameKeyDifferentSpellingKeepsCounter(t *testing.T) {
	// Every spelling of the secret enrolTOTPUser seeds. Each decodes to the
	// same HMAC key, so each generates the same codes as the seeded one.
	for _, tc := range []struct {
		name    string
		respelt string
	}{
		{"lowercase", "jbswy3dpehpk3pxp"},
		{"mixed case", "JbSwY3dPeHpK3pXp"},
		{"surrounding whitespace", "  JBSWY3DPEHPK3PXP  "},
		{"leading newline", "\nJBSWY3DPEHPK3PXP"},
		{"lowercase and whitespace", " jbswy3dpehpk3pxp\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestConfig()
			enrolTOTPUser(t, c, "peggy", "Passw0rd1", RoleAdmin)

			// Prove the premise rather than assuming it: the respelt secret
			// really is the same authenticator to the verifier.
			if !totpSameKeyForTest(t, "JBSWY3DPEHPK3PXP", tc.respelt) {
				t.Fatalf("fixture is wrong: %q is not the seeded key to the verifier", tc.respelt)
			}

			if !c.SetTOTPSecret("peggy", tc.respelt, []string{"regenerated-1"}) {
				t.Fatal("SetTOTPSecret returned false")
			}
			if got := c.GetTOTPLastCounter("peggy"); got != 987654 {
				t.Errorf("totpLastCounter = %d after re-issuing backup codes for the SAME key "+
					"spelled %q, want 987654 — the key is unchanged and live, so zeroing the "+
					"counter reopens the OTP replay window", got, tc.respelt)
			}
		})
	}
}

// TestSetTOTPSecret_UnusableSecretKeepsCounter: a secret that cannot decode to
// a key validates nothing, so it is no evidence that the key changed. Resetting
// on it would zero the guard protecting the key a caller may restore next.
func TestSetTOTPSecret_UnusableSecretKeepsCounter(t *testing.T) {
	for _, tc := range []struct {
		name     string
		unusable string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"not base32", "not-a-base32-secret!"},
		{"base32 alphabet violation", "JBSWY3DPEHPK3PX1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestConfig()
			enrolTOTPUser(t, c, "rupert", "Passw0rd1", RoleAdmin)

			if !c.SetTOTPSecret("rupert", tc.unusable, nil) {
				t.Fatal("SetTOTPSecret returned false")
			}
			if got := c.GetTOTPLastCounter("rupert"); got != 987654 {
				t.Errorf("totpLastCounter = %d after installing the unusable secret %q, want "+
					"987654 — an unusable secret authenticates nothing and so proves nothing "+
					"about the key the counter guards", got, tc.unusable)
			}
		})
	}
}

// TestSetTOTPSecret_FreshEnrolmentOverUnusableSecretResets is the other
// direction, and it is the availability half: when the account held no usable
// key, installing one is a genuinely new binding. A counter carried into it
// refuses the new device until wall-clock time passes the stale value, and
// indefinitely after a clock rollback — the lockout the previous correction
// round closed on ClearTOTP.
func TestSetTOTPSecret_FreshEnrolmentOverUnusableSecretResets(t *testing.T) {
	c := newTestConfig()
	enrolTOTPUser(t, c, "sybil", "Passw0rd1", RoleAdmin)

	// Reach the "no usable key, stale counter" shape the way a provisioned or
	// restored roster can: blank the secret without touching the counter.
	c.mu.Lock()
	c.uiUsers["sybil"].totpSecret = ""
	c.mu.Unlock()
	if got := c.GetTOTPLastCounter("sybil"); got != 987654 {
		t.Fatalf("fixture: counter = %d, want the seeded 987654", got)
	}

	if !c.SetTOTPSecret("sybil", "KRSXG5CTMVRXEZLU", []string{"fresh-1"}) {
		t.Fatal("SetTOTPSecret returned false")
	}
	if got := c.GetTOTPLastCounter("sybil"); got != 0 {
		t.Errorf("totpLastCounter = %d after enrolling a key over an unusable secret, want 0 — "+
			"the new authenticator would be refused until the clock passed the stale counter", got)
	}
}

// TestTOTPSameKey_AgreesWithTheVerifier is the ANTI-DRIFT wall, and it is the
// gate that actually matters: it never mentions ToUpper or TrimSpace, so it
// keeps holding if the verifier's canonicalisation changes. It asserts the
// agreement itself — SameKey says two spellings are one key IF AND ONLY IF the
// verifier accepts the same code under both. A future change that canonicalises
// in one layer and not the other fails here rather than silently reopening the
// replay window.
func TestTOTPSameKey_AgreesWithTheVerifier(t *testing.T) {
	const canonical = "JBSWY3DPEHPK3PXP"
	spellings := []string{
		canonical,
		"jbswy3dpehpk3pxp",
		"JbSwY3dPeHpK3pXp",
		"  JBSWY3DPEHPK3PXP  ",
		"\tJBSWY3DPEHPK3PXP\n",
		"KRSXG5CTMVRXEZLU", // a genuinely different key
		"krsxg5ctmvrxezlu", // …and its lowercase spelling
		"MZXW6",            // trailing-bit twins: canonically DIFFERENT strings
		"MZXW7",            // …that base32-decode to the SAME key
		"",
		"   ",
		"not-a-base32-secret!",
	}
	for _, a := range spellings {
		for _, b := range spellings {
			sameKey := totpSameKeyForTest(t, a, b)
			sameToVerifier := totpVerifiersAgree(t, a, b)
			if sameKey != sameToVerifier {
				t.Errorf("SameKey(%q, %q) = %v but the verifier treats them as the same "+
					"authenticator = %v — the key-identity comparison and the code generator "+
					"disagree, so a live key can be read as changed (or a changed key as live)",
					a, b, sameKey, sameToVerifier)
			}
		}
	}
}

// TestSetTOTPSecret_TrailingBitSpellingKeepsCounter pins that comparing
// CANONICALISED STRINGS is not sufficient — the comparison must compare the
// decoded KEYS.
//
// Go's base32 decoder ignores the non-canonical trailing bits of a secret whose
// length is not a multiple of 8 characters, so "MZXW6" and "MZXW7" differ in
// every case-folded, whitespace-trimmed spelling and still decode to the SAME
// HMAC key — one authenticator generating one stream of codes. A fix that only
// upper-cased and trimmed would pass every other gate in this file and still
// zero the replay counter for a live key, which is the whole defect.
func TestSetTOTPSecret_TrailingBitSpellingKeepsCounter(t *testing.T) {
	c := newTestConfig()
	if err := c.SetUIUser("trent", "Passw0rd1", RoleAdmin); err != nil {
		t.Fatalf("seed SetUIUser: %v", err)
	}
	if !c.SetTOTPSecret("trent", "MZXW6", []string{"code-1"}) {
		t.Fatal("seed SetTOTPSecret returned false")
	}
	if !c.SetTOTPLastCounter("trent", 987654) {
		t.Fatal("seed SetTOTPLastCounter returned false")
	}

	// Prove the premise: these really are one authenticator to the verifier.
	if !totpVerifiersAgree(t, "MZXW6", "MZXW7") {
		t.Fatal("fixture is wrong: MZXW6 and MZXW7 are not the same key to the verifier")
	}
	if strings.EqualFold(strings.TrimSpace("MZXW6"), strings.TrimSpace("MZXW7")) {
		t.Fatal("fixture is wrong: the two spellings must differ after case folding and trimming")
	}

	if !c.SetTOTPSecret("trent", "MZXW7", []string{"regenerated-1"}) {
		t.Fatal("SetTOTPSecret returned false")
	}
	if got := c.GetTOTPLastCounter("trent"); got != 987654 {
		t.Errorf("totpLastCounter = %d after re-issuing backup codes for a secret that decodes "+
			"to the SAME key, want 987654 — case folding alone does not establish key identity, "+
			"so the replay window reopened for a live key", got)
	}
}

// ─── Oracle for TestTOTPSameKey_AgreesWithTheVerifier ───────────────────────
//
// testTOTPCode is an INDEPENDENT RFC 6238 implementation written from the spec,
// not a call into internal/totp — the repo's differential-oracle idiom
// (legacySanitizeLog, legacySetupRequestTracing, oracleIsExempt). It mints a
// code from a raw key so the oracle can ask the PRODUCTION verifier whether a
// given spelling accepts it, which is what "the verifier treats these as one
// authenticator" actually means.
func testTOTPCode(key []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter)) // #nosec G115 -- fixed positive test time steps
	mac := hmac.New(sha1.New, key)                      // #nosec G401 G505 -- RFC 6238 mandates HMAC-SHA1
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (int32(sum[off]&0x7f) << 24) | (int32(sum[off+1]) << 16) |
		(int32(sum[off+2]) << 8) | int32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// testDecodeTOTPSecret decodes a stored secret the way RFC 4648 base32 and the
// documented storage format require. It exists only to obtain a key for the
// oracle above; the agreement being tested is between totp.SameKey and the
// production VERIFIER, never between production and this function.
func testDecodeTOTPSecret(secret string) ([]byte, bool) {
	s := strings.ToUpper(strings.TrimSpace(secret))
	if s == "" {
		return nil, false
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(key) == 0 {
		return nil, false
	}
	return key, true
}

func totpSameKeyForTest(t *testing.T, a, b string) bool {
	t.Helper()
	return totp.SameKey(a, b)
}

// totpVerifiersAgree reports whether the PRODUCTION verifier treats spellings a
// and b as the same authenticator: it mints codes from a's key and asks the
// verifier whether the b spelling accepts them.
//
// Several time steps are checked because two DIFFERENT keys can collide on one
// 6-digit code (~1e-6); agreeing across three independent steps makes a false
// "same" verdict ~1e-18 rather than relying on one sample.
func totpVerifiersAgree(t *testing.T, a, b string) bool {
	t.Helper()
	ka, aok := testDecodeTOTPSecret(a)
	_, bok := testDecodeTOTPSecret(b)
	if !aok || !bok {
		// A secret that decodes to no key authenticates nothing, so it is not
		// "the same authenticator" as anything — including another such secret.
		return false
	}
	for _, step := range []int64{56_666_666, 57_000_000, 57_123_456} {
		nowUnix := step * 30
		ok, _ := totp.VerifyTOTPReturnCounter(b, testTOTPCode(ka, step), nowUnix, 0)
		if !ok {
			return false
		}
	}
	return true
}
