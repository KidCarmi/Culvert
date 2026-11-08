package main

// auth_bootstrap_trust_grant_chaos112_test.go — the CHAOS-112 rider.
//
// A separate defect, in a separate domain, found by the same sweep.
//
// `POST /api/auth/login` is on uiAuthMiddleware's PUBLIC allowlist. Inside the
// first-run bootstrap window it forces its own authorization verdict —
// `role, ok = RoleAdmin, true`, with cfg.VerifyUIUser's answer discarded —
// and then, one line before the branch that deliberately refuses to issue a
// session for exactly this reason, it called
// `loginLimiter.RecordSuccess(clientIP, body.User)`.
//
// RecordSuccess mints a tier-2 TRUSTED-IP GRANT: isTrustedLocked makes that IP
// bypass the account-wide lock outright for TrustTTL (30 days). Tier 2 is the
// only backstop against distributed, IP-rotating brute force — tier 1 caps one
// (IP, username) pair and cannot see a flood across IPs — so a grant is an
// exemption from the one control that would stop one.
//
// Three properties made it worth fixing rather than recording:
//
//   - the caller is UNAUTHENTICATED and chooses both map keys (the username
//     from the POST body, the IP from the peer or, behind a configured trusted
//     proxy, from X-Forwarded-For);
//   - the grant OUTLIVES the window. Nothing in apiSetupComplete resets the
//     limiter, so grants minted before any roster existed still bypass tier 2
//     for the account the operator subsequently creates;
//   - it is invisible and non-revocable. Snapshot() reports active LOCKS, not
//     grants, so GET /api/auth/lockouts shows nothing; ResetUser — the explicit
//     unlock primitive behind POST /api/auth/lockouts — deliberately leaves the
//     trusted set alone ("trust is an allowance earned by a successful login,
//     not lock state"); Cleanup prunes a grant only past its 30-day TTL. The
//     only remedy was a restart, which lockout.go's own header designates as
//     break-glass rather than routine.
//
// The handler one function over already states the rule this broke —
// apiSetupComplete: "there is no RecordSuccess here to ever build a trust grant
// that would bypass it" — and ui_basic_auth.go already enforces it for its own
// non-submission re-checks (SEC-BASICAUTH-5, which guards both the failure
// record AND the success record behind `if submission`). The login handler's
// bootstrap branch was the remaining caller that recorded a success it had not
// verified.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/lockout"
)

// chaos112RiderIsolate gives the test a fresh limiter and config. The limiter
// is a package global and these tests assert on its trusted set, so it must be
// replaced rather than mutated in place.
func chaos112RiderIsolate(t *testing.T) {
	t.Helper()
	prevLimiter := loginLimiter
	prevCfg := cfg
	t.Cleanup(func() {
		loginLimiter = prevLimiter
		cfg = prevCfg
	})
	loginLimiter = lockout.NewLoginLimiter()
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
}

// chaos112RiderLogin posts a login with the given credentials and returns the
// recorder, driving the real handler.
func chaos112RiderLogin(t *testing.T, clientIP, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"user": user, "pass": pass})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/auth/login", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = clientIP + ":40000"
	w := httptest.NewRecorder()
	apiAuthLogin(w, r)
	return w
}

// chaos112RiderTier2Bypassed reports whether ip currently bypasses a tripped
// tier-2 account lock for username. It asks through the limiter's real
// decision function rather than reading internals: the grant only matters
// because of what Check does with it.
func chaos112RiderTier2Bypassed(t *testing.T, ip, username string) bool {
	t.Helper()
	// Trip tier 2 from addresses OTHER than ip, so only a trust grant can
	// explain ip getting through. AccountMaxAttempts failures across IPs trips
	// the account-wide lock.
	for i := 0; i < lockout.AccountMaxAttempts+2; i++ {
		loginLimiter.RecordFailure(chaos112RiderFloodIP(i), username)
	}
	locked, _ := loginLimiter.Check(ip, username)
	return !locked
}

// chaos112RiderFloodIP returns distinct source addresses for the tier-2 flood.
// Distinct is the only property that matters: tier 2 counts failures against one
// username ACROSS IPs, so the flood must not collapse onto one pair key.
func chaos112RiderFloodIP(i int) string {
	return fmt.Sprintf("198.18.%d.%d", (i/200)%200, i%200)
}

// ───────────────────────── DEFECT GATE ─────────────────────────

// TestCHAOS112Rider_BootstrapWindowLoginMintsNoTrustGrant is the primary gate.
// An unconfigured node is in the bootstrap window; a credential-free POST
// answers 200 by design (the window grants RoleAdmin to everything) and must
// leave behind no tier-2 exemption for the username and IP the caller chose.
func TestCHAOS112Rider_BootstrapWindowLoginMintsNoTrustGrant(t *testing.T) {
	chaos112RiderIsolate(t)

	if cfg.IsConfigured() {
		t.Fatal("fixture: an empty Config must not report itself configured")
	}
	if !bootstrapWindowOpen() {
		t.Skip("bootstrap window is not open on this fixture; the handler branch under test is unreachable")
	}

	const attackerIP = "203.0.113.200"
	const target = "admin"

	w := chaos112RiderLogin(t, attackerIP, target, "not-the-password")
	if w.Code != http.StatusOK {
		t.Fatalf("pre-setup login status = %d, want 200 — the bootstrap window's own "+
			"behaviour changed, so this gate is no longer measuring what it claims", w.Code)
	}

	if chaos112RiderTier2Bypassed(t, attackerIP, target) {
		t.Errorf("after one credential-free bootstrap-window POST, %s bypasses the tier-2 "+
			"account lock for %q — an unauthenticated caller minted a 30-day exemption from "+
			"the only control that sees distributed brute force, invisible to "+
			"GET /api/auth/lockouts and not cleared by ResetUser", attackerIP, target)
	}
}

// TestCHAOS112Rider_ControlAVerifiedLoginStillMintsItsGrant is the control
// that forbids the cheap fix. Deleting the RecordSuccess call outright would
// pass the gate above and remove tier 2's reason to be safe: RISK-012 gave
// trusted IPs the bypass precisely so an attacker flooding failures for
// "admin" cannot lock the real admin out. If a genuine login stops earning its
// grant, lockout-as-DoS is back.
func TestCHAOS112Rider_ControlAVerifiedLoginStillMintsItsGrant(t *testing.T) {
	chaos112RiderIsolate(t)

	const adminIP = "203.0.113.201"
	const user = "alice"
	const pass = "correct-horse-battery-staple"
	if err := cfg.SetAuth(user, pass); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	if !cfg.IsConfigured() {
		t.Fatal("fixture: SetAuth must leave the config configured, closing the bootstrap window")
	}
	if bootstrapWindowOpen() {
		t.Fatal("fixture: the bootstrap window must be closed for this control")
	}

	w := chaos112RiderLogin(t, adminIP, user, pass)
	if w.Code != http.StatusOK {
		t.Fatalf("verified login status = %d, want 200; body=%q", w.Code, w.Body.String())
	}

	if !chaos112RiderTier2Bypassed(t, adminIP, user) {
		t.Errorf("a VERIFIED login from %s no longer earns its tier-2 trusted-IP grant for "+
			"%q — the RISK-012 property that stops an attacker locking the real admin out "+
			"by flooding failures for their username is gone", adminIP, user)
	}
}

// TestCHAOS112Rider_ControlAWrongPasswordMintsNoGrant is the other side of the
// control: outside the window, a refused credential must earn nothing. It
// would fail against a "fix" that moved RecordSuccess somewhere reached on
// every request.
func TestCHAOS112Rider_ControlAWrongPasswordMintsNoGrant(t *testing.T) {
	chaos112RiderIsolate(t)

	const attackerIP = "203.0.113.202"
	const user = "bob"
	if err := cfg.SetAuth(user, "the-real-password"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}

	w := chaos112RiderLogin(t, attackerIP, user, "guess")
	if w.Code == http.StatusOK {
		t.Fatalf("a wrong password answered 200")
	}
	if chaos112RiderTier2Bypassed(t, attackerIP, user) {
		t.Errorf("a REFUSED login from %s earned a tier-2 bypass for %q", attackerIP, user)
	}
}

// TestCHAOS112Rider_BootstrapWindowStillClearsItsOwnPairCounter pins the half
// the window keeps. ClearFailures is not a no-op substitution: the bootstrap
// branch still clears the caller's own tier-1 counter, which is what stops a
// first-run operator who fat-fingers the wizard five times from locking
// themselves out of the window they are standing in.
func TestCHAOS112Rider_BootstrapWindowStillClearsItsOwnPairCounter(t *testing.T) {
	chaos112RiderIsolate(t)
	if !bootstrapWindowOpen() {
		t.Skip("bootstrap window is not open on this fixture")
	}

	const ip = "203.0.113.203"
	const user = "setup"
	for i := 0; i < lockout.MaxAttempts-1; i++ {
		loginLimiter.RecordFailure(ip, user)
	}
	if left := loginLimiter.AttemptsLeft(ip, user); left != 1 {
		t.Fatalf("fixture: AttemptsLeft = %d, want 1", left)
	}

	if w := chaos112RiderLogin(t, ip, user, "anything"); w.Code != http.StatusOK {
		t.Fatalf("pre-setup login status = %d, want 200", w.Code)
	}

	if left := loginLimiter.AttemptsLeft(ip, user); left != lockout.MaxAttempts {
		t.Errorf("AttemptsLeft = %d, want %d — the bootstrap branch no longer clears its own "+
			"tier-1 counter, so a first-run operator can lock themselves out of the setup "+
			"window", left, lockout.MaxAttempts)
	}
}
