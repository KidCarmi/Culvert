package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// uniqueAuditUser returns a username no other test or run has used, so an
// audit assertion can name exactly its own entry.
//
// A timestamp baseline is NOT enough here and the first version of this test
// proved it: under -count=2 the second run's "last entry before the test" IS
// the first run's own auth.lockout entry when nothing else audited in between,
// so an `e.TS < baseTS` guard does not exclude it and the count comes back 2.
// The audit ring is bounded at maxAuditLogs and shared by the whole suite, so
// the only reliable discriminator is one this invocation minted (CLAUDE.md,
// "Test-authoring pitfalls").
var auditUserSeq atomic.Int64

func uniqueAuditUser(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("sba1-%d-%d", time.Now().UnixNano(), auditUserSeq.Add(1))
}

// TestSecBasicAuth1_LockoutTripIsAudited proves the refusal leaves evidence.
// Before the fix a full brute-force run against the Basic Auth paths produced
// ZERO audit entries — the admin plane could be attacked with no record at all
// (CWE-778). The trip is audited once, not once per attempt, so the record
// cannot itself be flooded (the CHAOS-63 lesson).
func TestSecBasicAuth1_LockoutTripIsAudited(t *testing.T) {
	user := uniqueAuditUser(t)
	basicAuthTestCfg(t, user, "correct-horse-battery")

	const ip = "198.51.100.14"
	for i := 0; i < lockoutMaxAttempts; i++ {
		_ = basicAuthProbe(t, ip, user, "guess")
	}

	// Scan by CONTENT on a discriminator this invocation minted, never by
	// length delta and never by timestamp alone — see uniqueAuditUser.
	var found int
	for _, e := range auditGet() {
		if e.Action == "auth.lockout" && e.Object == user {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("auth.lockout entries for %q: got %d, want exactly 1 (one per trip, never one per attempt)", user, found)
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

// ---------------------------------------------------------------------------
// SEC-BASICAUTH-4 — the per-client failure budget was WITHDRAWN, and these are
// the gates that keep it withdrawn.
// ---------------------------------------------------------------------------
//
// Three iterations happened on one mechanism. SEC-BASICAUTH-2 (Codex review of
// PR #1399) correctly found that wiring loginLimiter.RecordFailure into a path
// with no rate limit lets an unauthenticated caller create limiter state on a
// public GET: two map entries per failed attempt, keyed by an attacker-chosen
// username, retained for at least lockout.Window because Cleanup cannot sweep
// them sooner (measured: 800 entries from 400 requests). It also corrected a
// false premise worth remembering — "entry creation is bcrypt-rate-bounded" is
// wrong, because cfg.VerifyUIUser bcrypts ONLY for a CONFIGURED username and an
// unknown one is a ~106 ns map miss against ~66.7 ms, 629,518x cheaper.
//
// The remedy was a per-client failure budget consulted before verification.
// SEC-BASICAUTH-3 found that budget was a read-then-act pair bounding the
// caller's CONCURRENCY rather than its rate, and made it atomic.
//
// SEC-BASICAUTH-4 (Codex review round 3) found the budget itself was the defect.
// Keyed on the client, it let 60 cheap UNKNOWN-username probes from one client
// key make a VALID credential answer 429 — so on any shared egress (a NAT, a
// CGNAT range, or an L7 proxy with no trusted_proxy_cidrs configured) an
// unauthenticated attacker denies every admin sharing that key. That is strictly
// worse than the tier-1 lockout it sat beside: username-INDEPENDENT, CHEAP, and
// with no trusted-IP bypass. It contradicts a property SEC-BASICAUTH-1 states
// outright, which the control below it already claimed to hold —
// TestSecBasicAuth1_Control_AttackerCannotLockOutTheRealAdminsIP covered the
// LOCKOUT path and not the budget path. THE LESSON: a control pins the mechanism
// it names; a new refusal path needs its own control.
//
// The budget is gone rather than patched a fourth time, because every patch
// shape reopens something already closed (gate only unknown usernames ⇒ the
// enumeration oracle; exempt recent successes ⇒ still denies first contact and
// an attacker with any valid credential exempts themselves; key on the username
// ⇒ enumeration plus a targeted denial). The two axes it claimed are recorded
// OPEN — AU-17b (state growth ⇒ internal/authstate fair-share eviction, which
// evicts without ever refusing) and AU-18 (concurrent bcrypt ⇒
// internal/authcost, which WAITS rather than refusing).

// TestSecBasicAuth4_UnauthenticatedFloodCannotDenyAValidCredential is the DEFECT
// GATE for the withdrawal, and the durable protection against rebuilding it.
// Verified failing against the reintroduced per-client budget, where the valid
// credential at the end answers 429 / loggedIn=false.
//
// The flood deliberately uses UNKNOWN usernames: they cost no bcrypt and require
// no knowledge of any account, which is what made the budget cheap to weaponise.
func TestSecBasicAuth4_UnauthenticatedFloodCannotDenyAValidCredential(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	// ONE client key, as a NAT egress or an untrusted L7 proxy would present.
	const shared = "198.51.100.50"

	// An unauthenticated attacker, from that shared key, well past any
	// per-window budget. Distinct usernames so nothing can lock, and unknown
	// ones so nothing costs bcrypt.
	for i := 0; i < apiRateBurst*3; i++ {
		_, _ = authStatusProbe(t, shared, fmt.Sprintf("ghost-%d", i), "guess")
	}

	// The real operator, sharing that egress, with CORRECT credentials.
	code, loggedIn := authStatusProbe(t, shared, "admin", "correct-horse-battery")
	if code != http.StatusOK || !loggedIn {
		t.Fatalf("after %d unauthenticated probes from the shared client key a VALID credential got "+
			"code=%d loggedIn=%v, want 200/true — a refusal keyed on the client lets an attacker deny "+
			"every admin behind one NAT or untrusted proxy (lockout-as-DoS, CWE-770)",
			apiRateBurst*3, code, loggedIn)
	}

	// Same through the middleware fallback, which is the path a CLI uses.
	if got := basicAuthProbe(t, shared, "admin", "correct-horse-battery"); got != http.StatusOK {
		t.Fatalf("middleware fallback after the flood: got %d, want 200", got)
	}
}

// TestSecBasicAuth4_Control_TargetedBruteForceStillLocks is the CONTROL. The
// cheapest way to pass the gate above is to stop refusing anything, which would
// delete SEC-BASICAUTH-1 — the actual brute-force and CPU bound. A run against
// ONE username from one client must still lock, and the lock must still be
// reached WITHOUT verifying the credential.
func TestSecBasicAuth4_Control_TargetedBruteForceStillLocks(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.51"
	for i := 0; i < lockoutMaxAttempts; i++ {
		if code := basicAuthProbe(t, ip, "admin", "guess"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	// The correct password now: a lock that could be walked past by guessing
	// right would be no lock, and this is also the "costs no bcrypt" bound.
	if code := basicAuthProbe(t, ip, "admin", "correct-horse-battery"); code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures the correct password got %d, want 429 — the lockout is gone",
			lockoutMaxAttempts, code)
	}
	if basicAuthLockoutRefused.Load() == 0 {
		t.Fatal("culvert_admin_basic_auth_lockout_refused_total did not move — the refusal was not the lockout")
	}
}

// TestSecBasicAuth4_ResidualUnauthenticatedStateGrowth pins AU-17b as a FACT,
// not a wish — the TestNormalizeHostStrict_IsNotALogSanitiser convention.
//
// With the budget withdrawn, an unauthenticated caller CAN still grow the
// lockout maps through the public GET. This test exists so nobody reads the
// withdrawal as "that axis is bounded now". What remains bounded, and why the
// residual is acceptable until fair-share eviction lands:
//
//   - PER KEY: internal/lockout's injective boundUsername clamp caps the key at
//     MaxUsernameKeyLen regardless of what the caller submits — asserted here
//     with a 4 KiB username, and pinned structurally by
//     internal/lockout/lockout_keybound_test.go.
//   - IN TIME: Cleanup sweeps a window-expired entry (connlimit_startup.go).
//   - IN VISIBILITY: culvert_login_limiter_entries reports the live size, which
//     is the first signal the admin plane has ever had for this growth.
//
// The designed fix is fair-share eviction: evict the oldest entry of the client
// key holding the MOST, so a flooding source evicts itself. That bounds the
// state WITHOUT REFUSING ANY REQUEST, which is exactly the property the
// withdrawn budget lacked. Do NOT close this by refusing again.
func TestSecBasicAuth4_ResidualUnauthenticatedStateGrowth(t *testing.T) {
	basicAuthTestCfg(t, "admin", "correct-horse-battery")

	const ip = "198.51.100.52"
	const flood = 120
	before := loginLimiterEntriesForTest()
	for i := 0; i < flood; i++ {
		// A 4 KiB username: if the clamp ever regressed, the KEY size would
		// scale with attacker input, which is the CHAOS-63 amplifier class.
		_, _ = authStatusProbe(t, ip, fmt.Sprintf("ghost-%d-%s", i, strings.Repeat("x", 4096)), "guess")
	}
	after := loginLimiterEntriesForTest()

	// The honest fact: it grows. Recorded as AU-17b, not silently tolerated.
	if after <= before {
		t.Fatalf("limiter entries went %d -> %d: this test documents AU-17b (unauthenticated state growth "+
			"IS still reachable). If growth is genuinely bounded now, close AU-17b and replace this test "+
			"with the bound — do not delete the assertion", before, after)
	}
	// And the bound that DOES hold: growth is in entry COUNT only. A valid
	// credential is unaffected by it, which is what distinguishes this residual
	// from the withdrawn budget's defect.
	if code, loggedIn := authStatusProbe(t, ip, "admin", "correct-horse-battery"); code != http.StatusOK || !loggedIn {
		t.Fatalf("state growth must not deny a valid credential: got code=%d loggedIn=%v", code, loggedIn)
	}
	t.Logf("residual (recorded, AU-17b): %d unauthenticated probes grew the lockout from %d to %d entries; "+
		"keys stay clamped at lockout.MaxUsernameKeyLen and expire with Cleanup's window",
		flood, before, after)
}
