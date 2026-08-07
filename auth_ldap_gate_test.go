package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// CHAOS-47 blast-radius tests for the LDAP leg.
//
// The CHAOS-47 gate is PROVIDER-WIDE: one recordUnavailable() denies every
// LDAP authentication for the whole cooldown without dialing the directory.
// That is the correct response to an unreachable directory and a denial-of-
// service primitive if anything an unauthenticated caller can provoke reaches
// it. The OIDC leg learned this first (errIntrospectClient, auth_oidc.go); these
// tests pin the same contract on the LDAP leg.
//
// The threat model in one line: an attacker who knows one username can put that
// ONE account into a state whose bind result code is not 49 — locked out (by
// their own brute force), disabled, expired, or simply not a bindable entry —
// and then re-arm the gate on demand.

// ldapErr builds the *ldap.Error value go-ldap returns when a server answers a
// bind with a non-success result code. Constructed exactly as the library does
// so the classifier is tested against the real shape, not a stand-in.
func ldapErr(code uint16) error {
	return &ldap.Error{ResultCode: code, Err: fmt.Errorf("%s", ldap.LDAPResultCodeMap[code])}
}

// ── Classifier: which errors may arm the provider-wide cooldown ───────────────

func TestLDAPUserBindIsUnreachable_Classification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
		why  string
	}{
		// Reachable: the directory answered about ONE account. None of these
		// may gate — each is provokable by whoever is attempting the bind.
		{"invalid credentials (49)", ldapErr(ldap.LDAPResultInvalidCredentials), false,
			"a wrong password is the ordinary case and is never an outage"},
		{"unwilling to perform (53)", ldapErr(ldap.LDAPResultUnwillingToPerform), false,
			"OpenLDAP/ppolicy and FreeIPA report a locked or disabled account this way"},
		{"constraint violation (19)", ldapErr(ldap.LDAPResultConstraintViolation), false,
			"ppolicy reports an expired password / lockout this way"},
		{"inappropriate authentication (48)", ldapErr(ldap.LDAPResultInappropriateAuthentication), false,
			"an entry with no bindable credential — reachable via a broad user_filter"},
		{"insufficient access rights (50)", ldapErr(ldap.LDAPResultInsufficientAccessRights), false,
			"the directory answered; an ACL decision is not a reachability failure"},
		{"referral (10)", ldapErr(ldap.LDAPResultReferral), false,
			"a cross-domain user object still proves the directory answered"},
		{"operations error (1)", ldapErr(ldap.LDAPResultOperationsError), false,
			"server-produced result code — the directory is up"},

		// Unreachable: nothing came back, or the server said it cannot serve.
		{"network error (200)", ldapErr(ldap.ErrorNetwork), true,
			"go-ldap's own transport failure — the directory never answered"},
		{"unexpected response (205)", ldapErr(ldap.ErrorUnexpectedResponse), true,
			"client-space fault: the connection did not behave like LDAP"},
		{"busy (51)", ldapErr(ldap.LDAPResultBusy), true,
			"server-wide back-off signal, not account state — the OIDC 429 analogue"},
		{"unavailable (52)", ldapErr(ldap.LDAPResultUnavailable), true,
			"server-wide back-off signal, not account state — the OIDC 408 analogue"},
		{"plain net error", &net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, true,
			"not an LDAP result at all: fail safe and treat it as the backend's fault"},
		{"context cancellation", context.Canceled, true,
			"unclassifiable fault ⇒ attributed to the backend, never silently ignored"},
		{"nil-ish opaque error", errors.New("something went wrong"), true,
			"an unrecognised error must default to the conservative branch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ldapUserBindIsUnreachable(tc.err); got != tc.want {
				t.Errorf("ldapUserBindIsUnreachable(%v) = %v, want %v — %s", tc.err, got, tc.want, tc.why)
			}
		})
	}
}

// TestLDAPUserBindIsUnreachable_ClientSpaceBoundaries pins the exact edges of
// the go-ldap client-error range. A server result code must never fall inside
// it, and a client-space code must never fall outside.
func TestLDAPUserBindIsUnreachable_ClientSpaceBoundaries(t *testing.T) {
	// One below the floor is the highest ordinary server code region; it must
	// read as reachable.
	if ldapUserBindIsUnreachable(ldapErr(ldapClientErrorFloor - 1)) {
		t.Errorf("code %d (just below the client-error floor) classified as unreachable", ldapClientErrorFloor-1)
	}
	for code := uint16(ldapClientErrorFloor); code <= ldapClientErrorCeil; code++ {
		if !ldapUserBindIsUnreachable(ldapErr(code)) {
			t.Errorf("client-space code %d classified as reachable", code)
		}
	}
	// LDAPResultSyncRefreshRequired (4096) is above the ceiling but is a real
	// server-sent result: it must stay on the reachable side.
	if ldapUserBindIsUnreachable(ldapErr(ldap.LDAPResultSyncRefreshRequired)) {
		t.Errorf("server code %d (above the client-error ceiling) classified as unreachable",
			ldap.LDAPResultSyncRefreshRequired)
	}
}

// TestLDAPUserBindIsUnreachable_ThroughWrapping proves the classifier survives
// the %w wrapping verify() applies, so the decision cannot be lost in transit.
func TestLDAPUserBindIsUnreachable_ThroughWrapping(t *testing.T) {
	wrapped := fmt.Errorf("user bind: %w", ldapErr(ldap.LDAPResultUnwillingToPerform))
	if ldapUserBindIsUnreachable(wrapped) {
		t.Error("wrapping an account rejection turned it into a reachability failure")
	}
	doubly := fmt.Errorf("outer: %w", fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultBusy)))
	if !ldapUserBindIsUnreachable(doubly) {
		t.Error("wrapping a busy-server error hid the reachability failure")
	}
}

// ── Wiring: the gate is only armed by a real reachability failure ─────────────

// TestLDAP_AccountRejectionDoesNotArmCooldown is the regression test for the
// finding. It fails on the pre-fix code, where EVERY verify() error — including
// a locked-account result code — called gate.recordUnavailable() and denied
// every other user for the cooldown.
func TestLDAP_AccountRejectionDoesNotArmCooldown(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}

	// The error shape verify() produces for a locked/disabled account.
	rejection := fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultUnwillingToPerform))

	// An attacker hammering one locked account must not accumulate ANY
	// provider-wide state, no matter how many times they try.
	for i := 0; i < 25; i++ {
		a.noteVerifyError(rejection)
	}

	if a.gate.gated() {
		t.Fatal("a directory-answered account rejection armed the provider-wide cooldown — " +
			"an attacker who can lock out one account can deny authentication to every user")
	}
	if !a.gate.allow() {
		t.Error("gate is refusing traffic after an account rejection")
	}
	snap := authBackendHealthStatus()
	if snap.Unavailable != 0 {
		t.Errorf("account rejection reported as %d backend outage(s) — it would page an operator "+
			"and make a brute-force attempt look like a directory failure", snap.Unavailable)
	}
	if snap.Degraded {
		t.Error("account rejection marked the identity backend degraded")
	}
	if snap.GatedDenials != 0 {
		t.Errorf("account rejection produced %d gated denial(s)", snap.GatedDenials)
	}
}

// TestLDAP_ReachabilityFailureStillArmsCooldown is the other half: the fix must
// not have disarmed the protection CHAOS-47 exists to provide.
func TestLDAP_ReachabilityFailureStillArmsCooldown(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"transport failure", fmt.Errorf("user bind: %w", ldapErr(ldap.ErrorNetwork))},
		{"server busy", fmt.Errorf("user bind: %w", ldapErr(ldap.LDAPResultBusy))},
		{"server unavailable", fmt.Errorf("user bind: %w", ldapErr(ldap.LDAPResultUnavailable))},
		{"dial refused", fmt.Errorf("dial: %w", errors.New("connection refused"))},
		{"service bind failure", fmt.Errorf("service bind: %w", ldapErr(ldap.LDAPResultInvalidCredentials))},
		{"search failure", fmt.Errorf("search: %w", ldapErr(ldap.LDAPResultBusy))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetAuthBackendHealthForTest()
			t.Cleanup(resetAuthBackendHealthForTest)

			a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
			if err != nil {
				t.Fatalf("NewLDAPAuth: %v", err)
			}
			a.noteVerifyError(tc.err)

			if !a.gate.gated() {
				t.Error("a genuine reachability failure did not arm the cooldown — " +
					"a hard-down directory would cost a full dial timeout on every request")
			}
			if snap := authBackendHealthStatus(); snap.Unavailable != 1 || !snap.Degraded || snap.Backend != "ldap" {
				t.Errorf("outage not visible to the operator: %+v", snap)
			}
		})
	}
}

// TestLDAP_AccountRejectionIsNotCached pins the second half of the contract: an
// account rejection is denied closed but never remembered, so an account the
// directory unlocks authenticates on its very next attempt rather than staying
// locked out for the whole cache TTL.
func TestLDAP_AccountRejectionIsNotCached(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	a.noteVerifyError(fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultConstraintViolation)))

	a.mu.Lock()
	cached := len(a.cache)
	a.mu.Unlock()
	if cached != 0 {
		t.Errorf("account rejection poisoned the auth cache with %d entr(ies)", cached)
	}
}

// TestLDAP_GateRecoversOnObservedReach pins that a real outage still clears on
// EVIDENCE — one observed reach releases every waiting caller — and that the
// account-rejection path leaves that machinery untouched.
func TestLDAP_GateRecoversOnObservedReach(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	a.noteVerifyError(fmt.Errorf("dial: %w", errors.New("connection refused")))
	if !a.gate.gated() {
		t.Fatal("outage did not arm the gate")
	}

	// A single observed reach — what the success path does — clears it.
	a.gate.recordReachable()
	noteAuthBackendReachable("ldap")
	if a.gate.gated() {
		t.Error("gate still armed after an observed reach")
	}
	if snap := authBackendHealthStatus(); snap.Degraded {
		t.Error("backend still reported degraded after an observed reach")
	}

	// And an account rejection afterwards must not push it back into a degraded
	// state (the interaction between the two paths, not just each alone).
	a.noteVerifyError(fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultUnwillingToPerform)))
	if a.gate.gated() {
		t.Error("account rejection re-armed the gate after recovery")
	}
}

// TestLDAP_AccountRejectionClearsAnArmedCooldown pins the second half of the
// blast-radius contract, found by Codex review on PR #1077.
//
// Not arming the gate is not enough. Once a GENUINE outage has armed it, the
// half-open probe that follows recovery may well be the attacker's — they are
// generating far more traffic than anyone else. If a directory-answered account
// rejection merely declined to arm the gate, it would consume that probe and
// leave `down` set, so the gate re-arms for another cooldown and every other
// user keeps being denied. Looping on one locked account would then hold a fully
// recovered directory in a permanent outage.
//
// The answer IS the evidence of reachability, so it must clear the gate.
func TestLDAP_AccountRejectionClearsAnArmedCooldown(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}

	// Drive the cooldown from an injected clock rather than sleeping.
	var nowNS atomic.Int64
	nowNS.Store(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC).UnixNano())
	a.gate.now = func() time.Time { return time.Unix(0, nowNS.Load()).UTC() }

	// 1. A real outage arms the gate.
	a.noteVerifyError(fmt.Errorf("dial: %w", errors.New("connection refused")))
	if !a.gate.gated() {
		t.Fatal("outage did not arm the gate")
	}

	// 2. The directory recovers and the cooldown elapses.
	nowNS.Add(int64(authBackendProbeCooldown + time.Second))

	// 3. The attacker wins the single half-open probe with their locked account.
	if !a.gate.allow() {
		t.Fatal("cooldown elapsed but no probe was granted")
	}
	a.noteVerifyError(fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultUnwillingToPerform)))

	// 4. Every other user must now get through. Without the clear, `down` is
	//    still set and `until` was just re-armed by step 3's grant, so this is
	//    false and the outage continues indefinitely.
	if a.gate.gated() {
		t.Fatal("a directory-answered account rejection consumed the recovery probe without clearing the gate — " +
			"an attacker looping on one locked account holds a healthy directory in a permanent outage")
	}
	if !a.gate.allow() {
		t.Error("legitimate authentication still gated after the directory demonstrably answered")
	}
	if snap := authBackendHealthStatus(); snap.Degraded {
		t.Error("backend still reported degraded after the directory answered")
	}
}

// TestLDAP_AttackerCannotHoldTheGateOpen is the same finding expressed as the
// attack: after one genuine outage, a client hammering a locked account across
// many cooldown windows must never keep other users gated.
func TestLDAP_AttackerCannotHoldTheGateOpen(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	var nowNS atomic.Int64
	nowNS.Store(time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC).UnixNano())
	a.gate.now = func() time.Time { return time.Unix(0, nowNS.Load()).UTC() }

	a.noteVerifyError(fmt.Errorf("dial: %w", errors.New("connection refused"))) // the one real blip
	rejection := fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultConstraintViolation))

	for round := 0; round < 10; round++ {
		nowNS.Add(int64(authBackendProbeCooldown + time.Second))
		a.gate.allow() // the attacker takes the probe
		a.noteVerifyError(rejection)
		if a.gate.gated() {
			t.Fatalf("round %d: gate still armed after the directory answered — "+
				"a three-second blip has become an indefinite outage", round)
		}
	}
}

// TestLDAP_ConcurrentAccountRejectionsNeverGate runs the attack shape under the
// race detector: many callers hammering locked accounts in parallel while
// legitimate callers check the gate. No interleaving may produce a gated state.
func TestLDAP_ConcurrentAccountRejectionsNeverGate(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	rejection := fmt.Errorf("%w: %w", errLDAPAccountRejected, ldapErr(ldap.LDAPResultUnwillingToPerform))

	const attackers, victims, rounds = 8, 8, 200
	var wg sync.WaitGroup
	var denied int64
	var mu sync.Mutex

	for i := 0; i < attackers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				a.noteVerifyError(rejection)
			}
		}()
	}
	for i := 0; i < victims; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				if !a.gate.allow() {
					mu.Lock()
					denied++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if denied != 0 {
		t.Errorf("%d legitimate authentication attempt(s) were denied without reaching the directory "+
			"while other clients were being rejected by the directory itself", denied)
	}
	if snap := authBackendHealthStatus(); snap.Unavailable != 0 || snap.GatedDenials != 0 {
		t.Errorf("concurrent account rejections leaked into backend health: %+v", snap)
	}
}

// TestLDAP_EmptyPasswordStillShortCircuits keeps the pre-existing authentication
// invariant pinned alongside the new branch: an empty password is rejected
// locally and never becomes an LDAP round trip, so a blank-password spray can
// reach neither the directory nor the health record.
func TestLDAP_EmptyPasswordStillShortCircuits(t *testing.T) {
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=com"})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	if a.Verify("alice", "") {
		t.Fatal("empty password must be denied")
	}
	if a.gate.gated() {
		t.Error("empty-password rejection armed the identity-backend cooldown")
	}
	if snap := authBackendHealthStatus(); snap.Unavailable != 0 || snap.GatedDenials != 0 {
		t.Errorf("empty-password rejection charged to backend health: %+v", snap)
	}
}
