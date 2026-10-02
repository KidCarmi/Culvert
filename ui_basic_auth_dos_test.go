package main

// ui_basic_auth_dos_test.go — SEC-BASICAUTH-4 and SEC-BASICAUTH-5.
//
// Both findings are about the SAME mistake made in two places: treating a
// request that is not a credential guess as though it were one, and letting
// that decision REFUSE or RECORD. SEC-BASIC-1 (#1420) built the right
// chokepoint; these gates pin what the chokepoint may do with each caller.
//
// Every _DefectProof here was verified FAILING against `main` at f13479b —
// the shipped implementation — not against a synthetic pre-fix shape.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/lockout"
)

// basicDoSRequest drives the REAL uiAuthMiddleware from a chosen client
// address. secBasicRequest cannot be reused: it leaves RemoteAddr at
// httptest's default, and every one of these gates is about what happens when
// several parties SHARE one client key.
func basicDoSRequest(t *testing.T, ip, user, pass string) int {
	t.Helper()
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", http.NoBody)
	req.RemoteAddr = ip + ":51234"
	req.SetBasicAuth(user, pass)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code
}

// basicDoSRevalidate drives one SSE mid-stream re-check from a chosen address.
func basicDoSRevalidate(t *testing.T, ip, user, pass string) bool {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/events", http.NoBody)
	r.RemoteAddr = ip + ":51234"
	r.SetBasicAuth(user, pass)
	return sseAuthStillValid(r)
}

// ── SEC-BASICAUTH-4 — a bound keyed on the client must not DENY ───────────

// TestSECBASIC4_SharedEgressFloodCannotDenyAValidCredential_DefectProof is the
// core finding. A per-IP failure budget reserved before verification is
// exhausted by UNKNOWN usernames, which are a map miss and cost no bcrypt — so
// an unauthenticated caller spends microseconds and every administrator
// sharing that address (a NAT, a CGNAT range, an L7 proxy with no
// trusted_proxy_cidrs) is refused while presenting a CORRECT password.
//
// Measured against main at f13479b: code=401 on a valid admin credential.
func TestSECBASIC4_SharedEgressFloodCannotDenyAValidCredential_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "opsadmin", "Correct-Horse-Battery-31!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	const shared = "198.51.100.77"

	// Well past any per-window budget. Distinct names so nothing can lock, and
	// unknown ones so nothing costs a bcrypt — the attacker's whole cost.
	for i := 0; i < lockout.Burst*2; i++ {
		basicDoSRequest(t, shared, fmt.Sprintf("ghost-%d", i), "guess")
	}

	if code := basicDoSRequest(t, shared, user, pass); code != http.StatusOK {
		t.Fatalf("after %d cheap unknown-username probes from the shared client key a VALID admin credential got %d, want 200 — "+
			"a refusal keyed on the client lets an unauthenticated attacker deny every administrator behind one NAT or "+
			"untrusted proxy (lockout-as-DoS, CWE-770)", lockout.Burst*2, code)
	}
}

// TestSECBASIC4_Control_TargetedBruteForceStillLocks is the CONTROL. The
// cheapest way to pass the gate above is to stop refusing anything, which
// would delete SEC-BASIC-1's brute-force and CPU bounds entirely.
func TestSECBASIC4_Control_TargetedBruteForceStillLocks(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "targetadmin", "Correct-Horse-Battery-32!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	const ip = "198.51.100.81"

	for i := 0; i < lockout.MaxAttempts; i++ {
		if code := basicDoSRequest(t, ip, user, "guess"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	if isLocked, _ := loginLimiter.Check(ip, user); !isLocked {
		t.Fatalf("after %d failures the (IP, username) pair is not locked — the two-tier lockout is gone", lockout.MaxAttempts)
	}
	// The CORRECT password now. A lock that can be walked past by guessing
	// right would be no lock — and this is also the "costs no bcrypt" bound,
	// since the refusal must precede verification.
	if code := basicDoSRequest(t, ip, user, pass); code == http.StatusOK {
		t.Fatalf("after %d failures the correct password was admitted — the lockout does not gate this path", lockout.MaxAttempts)
	}
}

// TestSECBASIC4_ResidualUnauthenticatedStateGrowth pins AU-17b as a FACT
// rather than a wish (the TestNormalizeHostStrict_IsNotALogSanitiser
// convention). With the budget withdrawn an unauthenticated caller CAN still
// grow the lockout maps, so this exists to stop anyone reading the removal as
// closure — while asserting the property that distinguishes this residual from
// the defect above: the growth cannot deny a valid credential.
func TestSECBASIC4_ResidualUnauthenticatedStateGrowth(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "residadmin", "Correct-Horse-Battery-33!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	const shared = "198.51.100.82"

	before := loginLimiter.EntryCount()
	// Ordinary-length distinct names: SEC-BASIC-1's CHAOS-63 bound refuses an
	// OVERSIZE name before it can reach the maps at all (asserted below), so
	// the reachable growth is from names within the limit.
	const flood = 40
	for i := 0; i < flood; i++ {
		basicDoSRequest(t, shared, fmt.Sprintf("resid-ghost-%d", i), "guess")
	}
	after := loginLimiter.EntryCount()
	if after <= before {
		t.Fatalf("expected the unauthenticated flood to STILL grow the lockout maps (before=%d after=%d); "+
			"if this is now bounded, AU-17b is closed and this test should be replaced by the gate that closed it", before, after)
	}
	if code := basicDoSRequest(t, shared, user, pass); code != http.StatusOK {
		t.Fatalf("the residual growth denied a VALID credential (got %d, want 200) — that is the SEC-BASICAUTH-4 defect, "+
			"not the recorded residual", code)
	}
	// The per-KEY half of what still bounds this: an OVERSIZE name is refused
	// before it can create an entry, so a regression in that bound fails here.
	oversize := loginLimiter.EntryCount()
	basicDoSRequest(t, shared, strings.Repeat("A", 4096), "guess")
	if loginLimiter.EntryCount() != oversize {
		t.Error("an oversize username created lockout state — SEC-BASIC-1's CHAOS-63 bound must refuse it before the maps")
	}
	t.Logf("residual (recorded, AU-17b): %d unauthenticated probes grew the lockout from %d to %d entries; "+
		"oversize names are refused outright and entries expire with Cleanup's window", flood, before, after)
}

// ── SEC-BASICAUTH-5 — a liveness re-check is not a login attempt ──────────

// TestSECBASIC5_StaleStreamsCannotLockOutTheRotatedPassword_DefectProof:
// rotating a password does not close the SSE streams already open, so each
// keeps replaying the OLD secret. Charging those re-checks as attempts trips
// tier 1 on the administrator's own address at the exact moment they performed
// the security action.
//
// Measured against main at f13479b: the rotated correct password got 401.
func TestSECBASIC5_StaleStreamsCannotLockOutTheRotatedPassword_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "rotadmin", "Rotated-New-Password-41!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	const ip = "198.51.100.83"

	// One more than the threshold, so a build that records them cannot squeak
	// under it.
	for i := 0; i <= lockout.MaxAttempts; i++ {
		if basicDoSRevalidate(t, ip, user, "Pre-Rotation-Password-41!") {
			t.Fatalf("stale stream %d survived revalidation with the OLD password — a re-check must still "+
				"terminate a stream whose credential is no longer valid", i+1)
		}
	}

	if code := basicDoSRequest(t, ip, user, pass); code != http.StatusOK {
		t.Fatalf("after %d stale-stream re-checks the ROTATED password got %d, want 200 — charging a re-check as a "+
			"login attempt locks an administrator out of their own appliance for rotating a password (CWE-645)",
			lockout.MaxAttempts+1, code)
	}
}

// TestSECBASIC5_LiveStreamCannotClearAnAttackersFailureCount_DefectProof is the
// more serious half, and it is a weakening of RISK-012 rather than an
// availability defect. RecordSuccess deletes the tier-1 pair entry and
// refreshes the tier-2 trusted-IP grant, so one legitimate stream held open
// from a shared egress resets a co-located attacker's count once per interval.
//
// Measured against main at f13479b: 8 failures, threshold 5, still unlocked.
func TestSECBASIC5_LiveStreamCannotClearAnAttackersFailureCount_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "shareadmin", "Correct-Horse-Battery-42!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	const shared = "198.51.100.84"

	burst := lockout.MaxAttempts - 1 // deliberately under the threshold
	for i := 0; i < burst; i++ {
		if code := basicDoSRequest(t, shared, user, "guess"); code != http.StatusUnauthorized {
			t.Fatalf("attacker attempt %d: got %d, want 401", i+1, code)
		}
	}

	if !basicDoSRevalidate(t, shared, user, pass) {
		t.Fatal("precondition: a live stream whose credential still verifies must survive revalidation")
	}

	// SEC-BASIC-1 never writes the response, so a locked client gets the same
	// plain 401 as a wrong password. The limiter itself is the observable.
	locked := false
	for i := 0; i < burst; i++ {
		basicDoSRequest(t, shared, user, "guess")
		if isLocked, _ := loginLimiter.Check(shared, user); isLocked {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatalf("after %d failures spanning one mid-stream re-check the pair is still unlocked (threshold %d) — "+
			"a re-check that records a success resets a co-located attacker's tier-1 counter once per interval and "+
			"re-arms the tier-2 bypass (CWE-307)", 2*burst, lockout.MaxAttempts)
	}
}

// TestSECBASIC5_Control_RevalidationStillCutsAnInvalidStream is the CONTROL for
// both SEC-BASICAUTH-5 gates: the cheapest way to pass them is to stop
// revalidating, which would delete the reason revalidation exists — an SSE
// connection outlives its connect-time check.
func TestSECBASIC5_Control_RevalidationStillCutsAnInvalidStream(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "ctrladmin", "Correct-Horse-Battery-43!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	secBasicUser(t, "totpadmin", "Correct-Horse-Battery-44!", RoleAdmin, true)
	const ip = "198.51.100.85"

	if basicDoSRevalidate(t, ip, user, "no-longer-the-password") {
		t.Error("control: a stream carrying a credential that no longer verifies must be terminated")
	}
	if basicDoSRevalidate(t, ip, "ghost-account", "anything") {
		t.Error("control: a stream naming an account that does not exist must be terminated")
	}
	// The TOTP posture is a REFUSAL, not a record, so it must apply on the
	// liveness intent too — otherwise an enrolled account keeps a live admin
	// stream that the submission path would refuse.
	if basicDoSRevalidate(t, ip, "totpadmin", "Correct-Horse-Battery-44!") {
		t.Error("control: a stream for a TOTP-enrolled account must be terminated — the liveness intent is exempt from RECORDING, never from a refusal")
	}
	if !basicDoSRevalidate(t, ip, user, pass) {
		t.Error("control: a stream whose credential still verifies must survive")
	}
}

// TestSECBASIC5_Control_RevalidationStillHonoursAnActiveLockout is what keeps
// "records nothing" from drifting into "checks nothing". The liveness intent is
// exempt from WRITING to the limiter, not from READING it.
func TestSECBASIC5_Control_RevalidationStillHonoursAnActiveLockout(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "lockadmin", "Correct-Horse-Battery-45!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	const ip = "198.51.100.86"

	for i := 0; i < lockout.MaxAttempts; i++ {
		if code := basicDoSRequest(t, ip, user, "guess"); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, code)
		}
	}
	// A CORRECT credential: if the lockout were consulted after verification
	// this would survive, which is the "costs no bcrypt" ordering inverted.
	if basicDoSRevalidate(t, ip, user, pass) {
		t.Fatal("control: a live stream on a LOCKED pair must be cut — the liveness intent is exempt from recording, never from the lockout Check")
	}
}
