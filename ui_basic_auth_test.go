package main

// ui_basic_auth_test.go — SEC-BASIC-1 regression suite.
//
// Every test whose name ends in _DefectProof was verified FAILING against the
// pre-fix tree (the three call sites calling cfg.VerifyUIUser directly) and
// passing after. The rest are the positive / boundary / authorization /
// concurrency / wall coverage that keeps the fix from being narrowed later.

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/lockout"
)

// secBasicEnv installs an isolated admin-auth environment: a private
// ui_users.json, a credential backend (so cfg.IsConfigured() is true and the
// middleware actually gates), and a snapshotted loginLimiter.
func secBasicEnv(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	snapshotLoginLimiter(t)
	cfg.SetUIUsersFile(filepath.Join(t.TempDir(), "ui_users.json"))
	t.Cleanup(func() { cfg.SetUIUsersFile("") })
	if err := cfg.SetAuth("setup-anchor", "Anchor-Password-1!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { _ = cfg.SetAuth("", "") })
	if !cfg.IsConfigured() {
		t.Fatal("precondition: setup must read as complete or the middleware never gates")
	}
}

// secBasicUser creates a UI user, optionally enrolling TOTP.
func secBasicUser(t *testing.T, user, pass string, role UIRole, totp bool) {
	t.Helper()
	if err := cfg.SetUIUser(user, pass, role); err != nil {
		t.Fatalf("SetUIUser(%q): %v", user, err)
	}
	if totp {
		cfg.SetTOTPSecret(user, "JBSWY3DPEHPK3PXP", []string{"backup-code-1"})
		if !cfg.UserHasTOTP(user) {
			t.Fatalf("precondition: TOTP enrolment did not take for %q", user)
		}
	}
	t.Cleanup(func() { loginLimiter.ResetUser(user) })
}

// secBasicRequest drives the REAL uiAuthMiddleware and reports the status plus
// the role injected into the request context.
func secBasicRequest(t *testing.T, user, pass string) (int, UIRole) {
	t.Helper()
	var got UIRole
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = uiRole(r)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", http.NoBody)
	req.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, got
}

// ── 1. The 2FA bypass ─────────────────────────────────────────────────────

// TestSECBASIC1_TOTPEnrolledAccountCannotUseBasic_DefectProof is the core
// finding: the Basic scheme carries one credential, so an enrolled second
// factor cannot be presented over it. Before the fix the correct password
// alone returned 200 with the account's FULL role — every admin mutation
// included — making TOTP decorative for anyone holding the password.
func TestSECBASIC1_TOTPEnrolledAccountCannotUseBasic_DefectProof(t *testing.T) {
	secBasicEnv(t)
	secBasicUser(t, "totp-admin", "Correct-Horse-Battery-1!", RoleAdmin, true)

	code, role := secBasicRequest(t, "totp-admin", "Correct-Horse-Battery-1!")
	if code == http.StatusOK || role != "" {
		t.Fatalf("2FA BYPASS: Basic granted status=%d role=%q on a TOTP-enrolled account with no second factor; want refusal",
			code, role)
	}
	if code != http.StatusUnauthorized {
		t.Errorf("refusal status = %d, want 401 (uniform with a wrong password, so the response is not an enrolment oracle)", code)
	}
}

// TestSECBASIC1_TOTPRefusalIsNotAnEnrolmentOracle pins the ORDER: the refusal
// must be indistinguishable from a wrong password, so an unauthenticated
// caller cannot use it to learn which accounts exist or which carry 2FA.
func TestSECBASIC1_TOTPRefusalIsNotAnEnrolmentOracle(t *testing.T) {
	secBasicEnv(t)
	secBasicUser(t, "totp-admin", "Correct-Horse-Battery-1!", RoleAdmin, true)

	enrolled, _ := secBasicRequest(t, "totp-admin", "Correct-Horse-Battery-1!")
	wrongPass, _ := secBasicRequest(t, "totp-admin", "definitely-wrong")
	unknown, _ := secBasicRequest(t, "no-such-account-at-all", "definitely-wrong")

	if enrolled != wrongPass || enrolled != unknown {
		t.Errorf("responses distinguishable — enrolled=%d wrongPassword=%d unknownUser=%d; all three must be identical",
			enrolled, wrongPass, unknown)
	}
}

// ── 2. The lockout bypass ─────────────────────────────────────────────────

// TestSECBASIC1_BasicFailuresFeedTheLockout_DefectProof pins that Basic
// guessing is now bounded by the same two-tier limiter as the login endpoint.
// Before the fix an attacker could move the guess from POST /api/auth/login to
// any GET and brute-force without limit: securityMiddleware's apiLimiter gates
// only MUTATING methods, so nothing at all bounded the rate.
func TestSECBASIC1_BasicFailuresFeedTheLockout_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "cli-user", "Correct-Horse-Battery-2!"
	secBasicUser(t, user, pass, RoleAdmin, false)

	// The correct password works before any failures — establishes the control.
	if code, role := secBasicRequest(t, user, pass); code != http.StatusOK || role != RoleAdmin {
		t.Fatalf("precondition: valid Basic credential rejected (status=%d role=%q)", code, role)
	}

	for i := 0; i < lockout.MaxAttempts; i++ {
		if code, _ := secBasicRequest(t, user, "wrong-guess"); code != http.StatusUnauthorized {
			t.Fatalf("wrong password attempt %d: status=%d, want 401", i+1, code)
		}
	}

	// The lock must now refuse even the CORRECT password. This is the
	// assertion that fails against the pre-fix tree, where no failure was ever
	// recorded and the correct password kept working indefinitely.
	code, role := secBasicRequest(t, user, pass)
	if code == http.StatusOK || role != "" {
		t.Fatalf("LOCKOUT BYPASS: after %d failed Basic attempts the correct password still authenticated (status=%d role=%q)",
			lockout.MaxAttempts, code, role)
	}
}

// TestSECBASIC1_LockoutBoundary pins that the lock trips at the threshold and
// not before — a gate that locked early would be its own availability defect.
func TestSECBASIC1_LockoutBoundary(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "boundary-user", "Correct-Horse-Battery-3!"
	secBasicUser(t, user, pass, RoleAdmin, false)

	for i := 0; i < lockout.MaxAttempts-1; i++ {
		secBasicRequest(t, user, "wrong-guess")
	}
	if code, role := secBasicRequest(t, user, pass); code != http.StatusOK || role != RoleAdmin {
		t.Fatalf("locked one attempt early: after %d failures the correct password gave status=%d role=%q, want 200/admin",
			lockout.MaxAttempts-1, code, role)
	}
	// A success must clear the counter, so the next failure run starts fresh.
	for i := 0; i < lockout.MaxAttempts-1; i++ {
		secBasicRequest(t, user, "wrong-guess")
	}
	if code, _ := secBasicRequest(t, user, pass); code != http.StatusOK {
		t.Errorf("a successful Basic auth did not reset the failure counter (status=%d)", code)
	}
}

// ── 3. Positive + authorization ───────────────────────────────────────────

// TestSECBASIC1_ValidBasicStillWorks is the CONTROL. The cheapest way to pass
// every test above is to refuse Basic Auth outright, which would break the
// documented CLI/API path for every operator. An account without a second
// factor must still authenticate.
func TestSECBASIC1_ValidBasicStillWorks(t *testing.T) {
	secBasicEnv(t)
	secBasicUser(t, "plain-admin", "Correct-Horse-Battery-4!", RoleAdmin, false)

	if code, role := secBasicRequest(t, "plain-admin", "Correct-Horse-Battery-4!"); code != http.StatusOK || role != RoleAdmin {
		t.Fatalf("valid Basic credential without TOTP was refused: status=%d role=%q", code, role)
	}
}

// TestSECBASIC1_BasicPreservesRoleNoEscalation pins that the new chokepoint
// returns the account's OWN role. A helper that returned a default role would
// silently promote every CLI caller to admin.
func TestSECBASIC1_BasicPreservesRoleNoEscalation(t *testing.T) {
	secBasicEnv(t)
	for _, tc := range []struct {
		user, pass string
		want       UIRole
	}{
		{"basic-viewer", "Correct-Horse-Battery-5!", RoleViewer},
		{"basic-operator", "Correct-Horse-Battery-6!", RoleOperator},
		{"basic-admin", "Correct-Horse-Battery-7!", RoleAdmin},
	} {
		secBasicUser(t, tc.user, tc.pass, tc.want, false)
		code, got := secBasicRequest(t, tc.user, tc.pass)
		if code != http.StatusOK {
			t.Errorf("%s: status=%d, want 200", tc.user, code)
			continue
		}
		if got != tc.want {
			t.Errorf("PRIVILEGE CONFUSION: %s authenticated as %q, want %q", tc.user, got, tc.want)
		}
	}
}

// ── 4. Malformed input ────────────────────────────────────────────────────

// TestSECBASIC1_OversizeUsernameIsBounded pins CHAOS-63's bound on this path
// too. Basic is reachable unauthenticated via /api/auth/status, so an
// unbounded name here is the same write amplifier into the lockout maps and
// the durable audit log that the login endpoint already closes.
func TestSECBASIC1_OversizeUsernameIsBounded(t *testing.T) {
	secBasicEnv(t)
	secBasicUser(t, "plain-admin", "Correct-Horse-Battery-8!", RoleAdmin, false)

	before := loginOversizeRejected.Load()
	huge := strings.Repeat("A", maxUsernameLen+1)
	if code, role := secBasicRequest(t, huge, "anything"); code == http.StatusOK || role != "" {
		t.Fatalf("oversize username authenticated (status=%d role=%q)", code, role)
	}
	if got := loginOversizeRejected.Load(); got <= before {
		t.Errorf("oversize rejection not counted: %d → %d (the operator's only signal)", before, got)
	}
	// A configured account is never refused for its length alone — mirrors
	// rejectOversizeLoginUser, and a divergence here is an admin lockout.
	long := strings.Repeat("b", maxUsernameLen+5)
	secBasicUser(t, long, "Correct-Horse-Battery-9!", RoleAdmin, false)
	if code, role := secBasicRequest(t, long, "Correct-Horse-Battery-9!"); code != http.StatusOK || role != RoleAdmin {
		t.Errorf("a CONFIGURED over-long account was refused for its length: status=%d role=%q", code, role)
	}
}

// ── 5. The public endpoint and the SSE path ───────────────────────────────

// TestSECBASIC1_AuthStatusIsNotAnUnlockedOracle_DefectProof covers
// /api/auth/status, which is on uiAuthMiddleware's PUBLIC allowlist: an
// unauthenticated caller reaches it directly, and it answered loggedIn
// true/false from a bare bcrypt with no lockout, no rate limit and no audit —
// a clean password oracle.
func TestSECBASIC1_AuthStatusIsNotAnUnlockedOracle_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "oracle-user", "Correct-Horse-Battery-10!"
	secBasicUser(t, user, pass, RoleAdmin, false)

	call := func(p string) bool {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/auth/status", http.NoBody)
		req.SetBasicAuth(user, p)
		w := httptest.NewRecorder()
		apiAuthStatus(w, req)
		return strings.Contains(w.Body.String(), `"loggedIn":true`)
	}

	if !call(pass) {
		t.Fatal("precondition: valid credential not reported as logged in")
	}
	for i := 0; i < lockout.MaxAttempts; i++ {
		if call("wrong-guess") {
			t.Fatalf("attempt %d: wrong password reported as logged in", i+1)
		}
	}
	if call(pass) {
		t.Fatal("ORACLE UNBOUNDED: /api/auth/status still confirmed the correct password after " +
			"MaxAttempts failures — the lockout does not reach this public endpoint")
	}
}

// TestSECBASIC1_SSEPathIsGated pins the third call site (events.go). It is a
// separate authorizer, so a fix applied to only the middleware would leave a
// live, lockout-free verifier behind.
func TestSECBASIC1_SSEPathIsGated(t *testing.T) {
	secBasicEnv(t)
	secBasicUser(t, "sse-totp", "Correct-Horse-Battery-11!", RoleAdmin, true)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/events", http.NoBody)
	req.SetBasicAuth("sse-totp", "Correct-Horse-Battery-11!")
	if sseAuthStillValid(req) {
		t.Fatal("SSE authorized a TOTP-enrolled account over Basic with no second factor")
	}
}

// ── 6. Concurrency ────────────────────────────────────────────────────────

// TestSECBASIC1_ConcurrentBasicAttempts exercises the chokepoint from many
// goroutines. Run under -race this covers the limiter and audit writes the new
// path performs on every request.
func TestSECBASIC1_ConcurrentBasicAttempts(t *testing.T) {
	secBasicEnv(t)
	secBasicUser(t, "race-user", "Correct-Horse-Battery-12!", RoleAdmin, false)

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pass := "Correct-Horse-Battery-12!"
			if i%2 == 0 {
				pass = fmt.Sprintf("wrong-%d", i)
			}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", http.NoBody)
			req.SetBasicAuth("race-user", pass)
			_, _ = verifyUIBasicAuth(req, "race-user", pass)
		}(i)
	}
	wg.Wait()
}

// ── 7. The wall ───────────────────────────────────────────────────────────

// TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller is the structural wall.
// The defect was three independent call sites drifting from the login
// handler's control set; behavioural tests can only cover the sites that exist
// today, so this fails the build when a FOURTH appears. verifyUIBasicAuth and
// apiAuthLogin are the only functions permitted to call cfg.VerifyUIUser —
// apiAuthLogin because it applies the full control set inline (lockout, TOTP,
// audit, anti-brute-force delay) and owns the interactive flow.
func TestSECBASIC1_VerifyUIUserHasNoOtherRequestPathCaller(t *testing.T) {
	allowed := map[string]string{
		"verifyUIBasicAuth": "THE admin-plane Basic chokepoint; applies lockout + TOTP refusal + audit",
		"apiAuthLogin":      "the interactive login handler; applies the same controls inline plus the TOTP challenge",
		// Re-authentication of an ALREADY-authenticated caller for a sensitive
		// action. The username comes from the session, never the request, so
		// there is no enumeration surface and no unauthenticated reach; it is a
		// POST, so securityMiddleware's mutating-method apiLimiter bounds the
		// bcrypt rate. RESIDUAL (recorded, not changed here): it consults no
		// lockout, so a caller who already holds the session can guess the
		// current password at the limiter's rate. Adding a lock would let a
		// session holder lock themselves out of the login flow, so the trade is
		// deliberate rather than an oversight.
		"apiAuthChangePassword": "re-auth of an already-authenticated session for its OWN account; session-derived username, mutating-method rate limit",
	}

	checked, offenders := secBasicVerifyUIUserCallers(t, allowed)

	// Not-vacuous guard: if the selector stops matching, every future caller
	// would pass silently.
	if checked < len(allowed) {
		t.Fatalf("wall found only %d cfg.VerifyUIUser call sites, expected at least %d — the selector has drifted and the wall proves nothing",
			checked, len(allowed))
	}
	if len(offenders) > 0 {
		t.Errorf("cfg.VerifyUIUser is called from %d function(s) outside the permitted set:\n%s\n\n"+
			"cfg.VerifyUIUser is a BARE bcrypt compare: it consults no lockout, no rate limit and no second factor, "+
			"and records nothing. Route admin-plane credentials through verifyUIBasicAuth (ui_basic_auth.go) instead.",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

// secBasicVerifyUIUserCallers walks every non-test source file in the package
// and returns how many cfg.VerifyUIUser call sites it saw, plus the ones
// outside the allowed functions.
func secBasicVerifyUIUserCallers(t *testing.T, allowed map[string]string) (checked int, offenders []string) {
	t.Helper()
	fset := token.NewFileSet()
	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if !secBasicIsCfgVerifyUIUser(n) {
					return true
				}
				checked++
				if _, allow := allowed[fn.Name.Name]; !allow {
					offenders = append(offenders, fmt.Sprintf("  %s:%d in %s",
						name, fset.Position(n.Pos()).Line, fn.Name.Name))
				}
				return true
			})
		}
	}
	return checked, offenders
}

// secBasicIsCfgVerifyUIUser reports whether n is a cfg.VerifyUIUser(...) call.
func secBasicIsCfgVerifyUIUser(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "VerifyUIUser" {
		return false
	}
	recv, ok := sel.X.(*ast.Ident)
	return ok && recv.Name == "cfg"
}

// ── 8. Per-IP failure budget (Codex review) ───────────────────────────────

// TestSECBASIC1_RotatingUsernamesHitAPerIPFailureBudget closes the gap the
// two-tier lockout cannot see: it is keyed by (IP, username), so a caller
// rotating a fresh username per GET never trips it, and apiLimiter gates only
// mutating methods. Before the per-IP budget every such attempt reached bcrypt,
// minted a lockout-map entry and wrote a durable audit line, without bound.
func TestSECBASIC1_RotatingUsernamesHitAPerIPFailureBudget(t *testing.T) {
	secBasicEnv(t)
	for i := 0; i < lockout.Burst; i++ {
		secBasicRequest(t, fmt.Sprintf("rotating-guess-%d", i), "wrong")
	}
	const fresh = "rotating-guess-after-budget"
	secBasicRequest(t, fresh, "wrong")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", http.NoBody)
	if left := loginLimiter.AttemptsLeft(realClientIP(req), fresh); left != lockout.MaxAttempts {
		t.Fatalf("attempt past the per-IP failure budget still reached the lockout (attempts_left=%d, want %d untouched) — "+
			"rotating usernames remain an unbounded bcrypt/state/audit amplifier", left, lockout.MaxAttempts)
	}
}

// TestSECBASIC1_SuccessesDoNotConsumeTheFailureBudget is the CONTROL: only
// failures are charged, so a correctly configured script making many
// requests must never be throttled by the budget.
func TestSECBASIC1_SuccessesDoNotConsumeTheFailureBudget(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "busy-script", "Correct-Horse-Battery-20!"
	secBasicUser(t, user, pass, RoleOperator, false)
	for i := 0; i < lockout.Burst+5; i++ {
		if code, role := secBasicRequest(t, user, pass); code != http.StatusOK || role != RoleOperator {
			t.Fatalf("valid request %d throttled (status=%d role=%q); successes must not charge the failure budget", i+1, code, role)
		}
	}
}

// ── 9. Atomic reservation + TOTP refusals (Codex review, round 2) ─────────

// TestSECBASIC1_ConcurrentWaveCannotExceedTheFailureBudget pins that the
// per-IP budget is RESERVED atomically before verification. A probe-then-
// charge pair let a concurrent wave all observe "not exhausted" before any
// bcrypt finished, so far more than Burst failures reached bcrypt, the
// lockout maps and the audit trail.
func TestSECBASIC1_ConcurrentWaveCannotExceedTheFailureBudget(t *testing.T) {
	secBasicEnv(t)
	const wave = lockout.Burst * 3
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < wave; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			secBasicRequest(t, fmt.Sprintf("wave-guess-%d", i), "wrong")
		}(i)
	}
	close(start)
	wg.Wait()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", http.NoBody)
	ip := realClientIP(req)
	reached := 0
	for i := 0; i < wave; i++ {
		if loginLimiter.AttemptsLeft(ip, fmt.Sprintf("wave-guess-%d", i)) != lockout.MaxAttempts {
			reached++
		}
	}
	if reached > lockout.Burst {
		t.Fatalf("%d concurrent failures reached verification, want <= %d — the per-IP budget is not an atomic reservation",
			reached, lockout.Burst)
	}
}

// TestSECBASIC1_TOTPRefusalsAreChargedToTheIPBudget pins that a correct
// password for a TOTP-enrolled account — the compromised-first-factor case —
// cannot be replayed without bound: each refusal costs a bcrypt and a durable
// audit line, so it consumes the per-IP budget (while still never locking the
// account, see TestSECBASIC1_TOTPRefusalIsNotAnEnrolmentOracle).
func TestSECBASIC1_TOTPRefusalsAreChargedToTheIPBudget(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "totp-replayed", "Correct-Horse-Battery-21!"
	secBasicUser(t, user, pass, RoleAdmin, true)
	// One refusal, then probe the remaining budget directly: looping Burst
	// bcrypts under -race can outlive the 1-minute window and reset it.
	secBasicRequest(t, user, pass)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", http.NoBody)
	ip := realClientIP(req)
	for i := 1; i < lockout.Burst; i++ {
		if _, ok := basicAuthFailLimiter.Reserve(ip); !ok {
			t.Fatalf("budget exhausted after %d units; want exactly Burst", i)
		}
	}
	if _, ok := basicAuthFailLimiter.Reserve(ip); ok {
		t.Fatalf("a TOTP refusal left the per-IP Basic budget unconsumed — a compromised first factor is an unbounded bcrypt/audit amplifier")
	}
	if left := loginLimiter.AttemptsLeft(realClientIP(req), user); left != lockout.MaxAttempts {
		t.Errorf("TOTP refusals charged the per-account lockout (attempts_left=%d, want %d)", left, lockout.MaxAttempts)
	}
}
