package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ui_basicauth_lockout_test.go — SEC-BASICAUTH-1 defect gates + controls.
//
// The finding: /api/auth/login is guarded by the two-tier lockout (RISK-012),
// but the THREE other admin-plane credential entry points — uiAuthMiddleware's
// HTTP Basic Auth fallback, apiAuthStatus (which is on the PUBLIC allowlist),
// and the SSE mid-stream revalidation — called cfg.VerifyUIUser directly with
// no lockout check, no failure record, no rate limit and no audit trail. Two of
// the three are reachable with no credentials at all, and none of them is a
// mutating request, so securityMiddleware's 60-POST/min limiter never sees
// them.
//
// Every DEFECT gate below was verified failing against the pre-fix tree.

// basicAuthTestCfg installs a Config with one local admin and returns a
// restore func. It also clears the process-global login limiter so the gates
// do not inherit each other's failure counters.
func basicAuthTestCfg(t *testing.T, user, pass string) {
	t.Helper()
	orig := cfg
	testCfg := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := testCfg.SetAuth(user, pass); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	cfg = testCfg
	t.Cleanup(func() { cfg = orig })
	t.Cleanup(loginLimiter.SnapshotAndClear())
	resetBasicAuthLockoutStateForTest()
}

// basicAuthProbe drives one Basic-Auth request through uiAuthMiddleware from
// the given client IP and reports the status the middleware produced.
func basicAuthProbe(t *testing.T, ip, user, pass string) int {
	t.Helper()
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.RemoteAddr = ip + ":51234"
	r.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// authStatusProbe drives one Basic-Auth request at the PUBLIC /api/auth/status
// endpoint and reports (status code, loggedIn).
func authStatusProbe(t *testing.T, ip, user, pass string) (int, bool) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	r.RemoteAddr = ip + ":51234"
	r.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	apiAuthStatus(w, r)
	var body struct {
		LoggedIn bool `json:"loggedIn"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	return w.Code, body.LoggedIn
}

// TestSecBasicAuth1_MiddlewareFallbackIsLockoutBounded is the primary DEFECT
// gate. Before the fix, every wrong-password Basic Auth request reached
// bcrypt and answered 401 forever: the lockout that guards the login form was
// simply not on this path, so an attacker could brute-force admin credentials
// at line rate against any /api/ route.
func TestSecBasicAuth1_MiddlewareFallbackIsLockoutBounded(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.10"
	for i := 0; i < lockoutMaxAttempts; i++ {
		if code := basicAuthProbe(t, ip, "admin", "guess"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	// The (ip, user) pair has now tripped tier 1. The next attempt must be
	// refused by the limiter, NOT verified.
	if code := basicAuthProbe(t, ip, "admin", "guess"); code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d after %d failures: got %d, want 429 (locked)",
			lockoutMaxAttempts+1, lockoutMaxAttempts, code)
	}
	if got := basicAuthLockoutRefused.Load(); got == 0 {
		t.Fatal("culvert_admin_basic_auth_lockout_refused_total did not move on a refused attempt")
	}
}

// TestSecBasicAuth1_LockedOutCredentialIsRefusedEvenWhenCorrect proves the
// refusal happens BEFORE credential verification: once the pair is locked, the
// RIGHT password is refused too. That is what makes the bound a CPU bound as
// well as a guessing bound — a locked attempt runs no bcrypt.
func TestSecBasicAuth1_LockedOutCredentialIsRefusedEvenWhenCorrect(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.11"
	for i := 0; i < lockoutMaxAttempts; i++ {
		_ = basicAuthProbe(t, ip, "admin", "guess")
	}
	if code := basicAuthProbe(t, ip, "admin", "correct-horse-battery"); code != http.StatusTooManyRequests {
		t.Fatalf("correct password while locked: got %d, want 429", code)
	}
}

// TestSecBasicAuth1_LockoutStateIsSharedWithTheLoginEndpoint proves an attacker
// cannot reset their budget by alternating endpoints. Failures recorded on the
// Basic Auth path must count toward the SAME tier-1 pair the login form uses.
func TestSecBasicAuth1_LockoutStateIsSharedWithTheLoginEndpoint(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.12"
	for i := 0; i < lockoutMaxAttempts; i++ {
		_ = basicAuthProbe(t, ip, "admin", "guess")
	}
	// The login endpoint must now see the same pair as locked.
	locked, secs := loginLimiter.Check(ip, "admin")
	if !locked || secs <= 0 {
		t.Fatalf("after %d Basic Auth failures the login endpoint sees locked=%v secs=%d, want locked with a positive remainder",
			lockoutMaxAttempts, locked, secs)
	}
}

// TestSecBasicAuth1_PublicAuthStatusIsNotAnUnboundedOracle is the second
// DEFECT gate, and the more serious half: /api/auth/status is on
// isPublicUIAuthPath, so uiAuthMiddleware lets it through unauthenticated, and
// it is a GET, so securityMiddleware's mutating-only rate limit never applies.
// Before the fix it verified caller-supplied Basic credentials with bcrypt on
// every request and reported the verdict in loggedIn — an unauthenticated,
// unthrottled, unaudited password oracle.
func TestSecBasicAuth1_PublicAuthStatusIsNotAnUnboundedOracle(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.13"
	for i := 0; i < lockoutMaxAttempts; i++ {
		code, loggedIn := authStatusProbe(t, ip, "admin", "guess")
		if code != http.StatusOK || loggedIn {
			t.Fatalf("attempt %d: got code=%d loggedIn=%v, want 200/false", i+1, code, loggedIn)
		}
	}
	code, loggedIn := authStatusProbe(t, ip, "admin", "guess")
	if code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d on the public oracle: got %d, want 429", lockoutMaxAttempts+1, code)
	}
	if loggedIn {
		t.Fatal("a refused attempt must never report loggedIn")
	}
}

// TestSecBasicAuth1_LockoutTripIsAudited proves the refusal leaves evidence.
// Before the fix a full brute-force run against the Basic Auth paths produced
// ZERO audit entries — the admin plane could be attacked with no record at all
// (CWE-778). The trip is audited once, not once per attempt, so the record
// cannot itself be flooded (the CHAOS-63 lesson).
func TestSecBasicAuth1_LockoutTripIsAudited(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.14"
	before := auditGet()
	var baseTS int64
	if len(before) > 0 {
		baseTS = before[len(before)-1].TS
	}

	for i := 0; i < lockoutMaxAttempts; i++ {
		_ = basicAuthProbe(t, ip, "admin", "guess")
	}

	// Scan by CONTENT, never by length delta: the audit ring is bounded at 500
	// and a shuffled -count=2 run saturates it (see CLAUDE.md test pitfalls).
	var found int
	for _, e := range auditGet() {
		if e.TS < baseTS {
			continue
		}
		if e.Action == "auth.lockout" && strings.Contains(e.Actor, ip) {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("auth.lockout entries naming %s: got %d, want exactly 1 (one per trip, never one per attempt)", ip, found)
	}
}

// --- CONTROLS --------------------------------------------------------------
//
// The cheapest way to pass every gate above is to stop accepting Basic Auth,
// or to lock an account on the first failure. Both would be far worse than the
// defect, so each is pinned as a control.

// TestSecBasicAuth1_Control_ValidCredentialsAreNeverThrottled proves a
// legitimate CLI/automation client with the right password is not rate-limited
// however many API calls it makes: each success clears its own pair counter.
func TestSecBasicAuth1_Control_ValidCredentialsAreNeverThrottled(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.15"
	for i := 0; i < lockoutMaxAttempts*4; i++ {
		if code := basicAuthProbe(t, ip, "admin", "correct-horse-battery"); code != http.StatusOK {
			t.Fatalf("valid Basic Auth call %d: got %d, want 200", i+1, code)
		}
	}
}

// TestSecBasicAuth1_Control_InterleavedSuccessResetsTheCounter proves the
// bound tracks CONSECUTIVE failures per pair, so an automation client that
// occasionally races a password rotation is not locked out of the API.
func TestSecBasicAuth1_Control_InterleavedSuccessResetsTheCounter(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.16"
	for round := 0; round < 3; round++ {
		for i := 0; i < lockoutMaxAttempts-1; i++ {
			_ = basicAuthProbe(t, ip, "admin", "guess")
		}
		if code := basicAuthProbe(t, ip, "admin", "correct-horse-battery"); code != http.StatusOK {
			t.Fatalf("round %d: valid credential after %d failures got %d, want 200",
				round, lockoutMaxAttempts-1, code)
		}
	}
}

// TestSecBasicAuth1_Control_AttackerCannotLockOutTheRealAdminsIP is the
// lockout-as-DoS control (RISK-012's own reason for being two-tier): a flood
// from the attacker's IP against the admin's username locks the ATTACKER's
// pair, never the admin's, so wiring this path into the limiter cannot be used
// to deny the operator their own admin plane.
func TestSecBasicAuth1_Control_AttackerCannotLockOutTheRealAdminsIP(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const attacker = "198.51.100.17"
	const operator = "203.0.113.9"
	for i := 0; i < lockoutMaxAttempts*2; i++ {
		_ = basicAuthProbe(t, attacker, "admin", "guess")
	}
	if code := basicAuthProbe(t, operator, "admin", "correct-horse-battery"); code != http.StatusOK {
		t.Fatalf("operator IP after an attacker flood: got %d, want 200", code)
	}
}

// TestSecBasicAuth1_Control_UnauthenticatedStatusStillAnswers proves the
// public /api/auth/status contract is untouched for the login overlay, which
// reads it with NO Authorization header at all: no header ⇒ no lockout key is
// ever consulted or created, so an anonymous poll can never trip anything.
func TestSecBasicAuth1_Control_UnauthenticatedStatusStillAnswers(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	for i := 0; i < lockoutMaxAttempts*3; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
		r.RemoteAddr = "198.51.100.18:4444"
		w := httptest.NewRecorder()
		apiAuthStatus(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("anonymous status poll %d: got %d, want 200", i+1, w.Code)
		}
	}
	if got := basicAuthLockoutRefused.Load(); got != 0 {
		t.Fatalf("anonymous polls charged %d lockout refusals, want 0", got)
	}
}

// --- SEC-BASICAUTH-2: the P1 this fix introduced -----------------------------
//
// Codex review of PR #1399 found that SEC-BASICAUTH-1's own fix opened a
// different unauthenticated hole on the SAME public endpoint. Wiring
// loginLimiter.RecordFailure into a path with no rate limit means every failed
// attempt CREATES two durable map entries (the tier-1 pair and the tier-2
// account), keyed by an attacker-chosen username, retained for at least
// lockout.Window (10 min) because Cleanup cannot sweep them sooner.
//
// The rationale recorded for leaving that unbounded was WRONG, and measuring it
// is what showed so: "entry creation is bcrypt-rate-bounded because
// RecordFailure runs only after a verification". cfg.VerifyUIUser bcrypts ONLY
// when the username names a configured account — an unknown one is a map miss
// that returns in ~106 ns against ~66.7 ms for a real account, 629,518x
// cheaper. So an attacker cycling unique usernames pays nothing per request,
// and /api/auth/status is a public GET, which securityMiddleware's
// mutating-only apiLimiter never sees.
//
// That is the CHAOS-63 memory/audit amplifier, reintroduced by the fix for a
// different unauthenticated-caller defect — on an endpoint that previously
// created NO state at all.

// TestSecBasicAuth2_UniqueUsernameFloodDoesNotGrowLimiterState is the DEFECT
// gate: a single IP cycling distinct usernames against the public endpoint must
// not be able to create limiter state without bound.
func TestSecBasicAuth2_UniqueUsernameFloodDoesNotGrowLimiterState(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.30"
	const flood = 400
	for i := 0; i < flood; i++ {
		// A distinct username every time: each one is its own tier-1 pair AND
		// its own tier-2 account entry, so nothing ever locks and nothing ever
		// stops the growth.
		authStatusProbe(t, ip, fmt.Sprintf("ghost-%d-%s", i, strings.Repeat("x", 200)), "guess")
	}

	// The limiter must have refused most of this. lockout.Burst is the per-IP
	// budget the login POST already lives under; allow one window's worth plus
	// slack, never the whole flood.
	if got := loginLimiterEntriesForTest(); got > apiRateBurst*2 {
		t.Fatalf("after %d unique-username probes from one IP the login limiter holds %d entries, want <= %d — "+
			"an unauthenticated caller can grow admin-plane state without bound",
			flood, got, apiRateBurst*2)
	}
	if basicAuthFailShed.Load() == 0 {
		t.Fatal("culvert_admin_basic_auth_fail_shed_total did not move — the flood was not bounded")
	}
}

// TestSecBasicAuth2_Control_OrdinaryFailuresStillLockOut is the CONTROL: the
// rate bound must not neuter SEC-BASICAUTH-1. An ordinary brute-force run
// against ONE username stays well inside the per-IP budget and must still lock.
func TestSecBasicAuth2_Control_OrdinaryFailuresStillLockOut(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.31"
	for i := 0; i < lockoutMaxAttempts; i++ {
		if code := basicAuthProbe(t, ip, "admin", "guess"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	if code := basicAuthProbe(t, ip, "admin", "guess"); code != http.StatusTooManyRequests {
		t.Fatalf("the lockout must still trip inside the rate budget: got %d, want 429", code)
	}
}

// TestSecBasicAuth2_Control_OverBudgetRefusalCarriesNoOracle is the control
// that caught a flaw in the FIRST version of this fix and is the reason the
// budget is consulted BEFORE verification.
//
// That version charged the budget on the failure and then simply did not
// RECORD it. The attempt was still verified and still answered, so the caller
// still learned "wrong" — while the account never accumulated failures and
// therefore never locked. An attacker could burn their budget on ghost
// usernames and then guess a real account's password indefinitely at the
// window rate, which is WEAKER than the 5-then-15-minutes the lockout gives.
// Shedding the RECORD of an answered attempt weakens the bound it is meant to
// protect; shedding the ATTEMPT does not.
//
// So an over-budget client is refused before cfg.VerifyUIUser runs, and the
// refusal must be identical whether the credentials are right or wrong — a
// correct password must not be the one input that gets through, or the refusal
// itself becomes the oracle.
func TestSecBasicAuth2_Control_OverBudgetRefusalCarriesNoOracle(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")
	swapBasicAuthFailLimiterForTest()

	const ip = "198.51.100.32"
	// Burn the budget with distinct UNKNOWN usernames: each is its own pair, so
	// nothing locks and only the failure budget can stop it.
	for i := 0; i < apiRateBurst+5; i++ {
		_, _ = authStatusProbe(t, ip, fmt.Sprintf("ghost-%d", i), "guess")
	}
	if basicAuthFailShed.Load() == 0 {
		t.Fatal("the per-client failure budget never engaged")
	}

	// A WRONG password from that client is refused...
	wrong := basicAuthProbe(t, ip, "admin", "guess")
	// ...and so is the RIGHT one. Same answer, so the refusal tells an attacker
	// nothing about the credential.
	right := basicAuthProbe(t, ip, "admin", "correct-horse-battery")

	if wrong != http.StatusTooManyRequests || right != http.StatusTooManyRequests {
		t.Fatalf("over-budget client: wrong-password got %d, correct-password got %d — both must be 429, "+
			"or the refusal distinguishes a valid credential from an invalid one", wrong, right)
	}
}

// TestSecBasicAuth2_Control_ValidClientIsNeverBudgeted proves the budget is
// charged by FAILURES only: a legitimate CLI or monitoring client making far
// more than the window budget of successful calls is never refused.
func TestSecBasicAuth2_Control_ValidClientIsNeverBudgeted(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")
	swapBasicAuthFailLimiterForTest()

	const ip = "198.51.100.34"
	for i := 0; i < apiRateBurst+20; i++ {
		if code := basicAuthProbe(t, ip, "admin", "correct-horse-battery"); code != http.StatusOK {
			t.Fatalf("valid call %d of %d: got %d, want 200 — the budget must be charged by failures only",
				i+1, apiRateBurst+20, code)
		}
	}
	if got := basicAuthFailShed.Load(); got != 0 {
		t.Fatalf("a client that never failed was charged %d shed failures", got)
	}
}
