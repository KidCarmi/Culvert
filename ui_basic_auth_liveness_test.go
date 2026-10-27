package main

// ui_basic_auth_liveness_test.go — SEC-BASICAUTH-5 (RISK-032).
//
// The SSE stream re-checks its HTTP Basic credentials every
// sseRevalidateEvery messages. Those headers were captured when the stream
// was ESTABLISHED and cannot change, so a re-check replays one already-admitted
// credential: it is not a login attempt. Routing it through the submission
// path (verifyUIBasicAuth) recorded it as one, which broke the limiter in both
// directions and spent the per-IP failure budget that bounds real guesses.
//
// Every _DefectProof test here fails on the pre-fix tree (sseAuthStillValid →
// verifyUIBasicAuth). The _Control tests pin what must NOT change: the cheapest
// way to pass the defect proofs is to stop revalidating, which would keep a
// rotated, deleted, TOTP-enrolled or locked credential streaming telemetry.
// The submission path's atomic Reserve/Refund budget (SEC-BASICAUTH-4) is
// pinned unchanged by the TestSECBASIC1_* suite in ui_basic_auth_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/lockout"
)

// secBasicStream builds the request an established Basic-auth SSE stream
// carries. It shares secBasicRequest's RemoteAddr, so both resolve to the same
// client IP and therefore the same lockout pair and per-IP budget.
func secBasicStream(user, pass string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/events", http.NoBody)
	req.SetBasicAuth(user, pass)
	return req
}

// secBasicUniqueUser returns a username no other test (or earlier run in the
// same process) can have written to the audit ring.
func secBasicUniqueUser(t *testing.T, label string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return "sec-basicauth-5-" + label + "-" + hex.EncodeToString(b[:])
}

// TestSECBASIC5_StaleStreamsCannotLockOutTheRotatedPassword_DefectProof: an
// administrator rotates their password while streams opened with the old one
// are still live. Each re-check carries the OLD password; recording those as
// failures tripped the tier-1 pair, refusing the NEW, correct password from
// that IP at the moment the operator performed the security action.
func TestSECBASIC5_StaleStreamsCannotLockOutTheRotatedPassword_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, oldPass, newPass = "rotating-admin", "Correct-Horse-Battery-30!", "Correct-Horse-Battery-31!"
	secBasicUser(t, user, oldPass, RoleAdmin, false)
	stream := secBasicStream(user, oldPass)
	if !sseAuthStillValid(stream) {
		t.Fatal("precondition: the stream's credential is valid before the rotation")
	}

	if err := cfg.SetUIUser(user, newPass, RoleAdmin); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for i := 0; i <= lockout.MaxAttempts; i++ {
		if sseAuthStillValid(stream) {
			t.Fatalf("re-check %d: a stream carrying the rotated-away password was kept alive", i+1)
		}
	}
	if left := loginLimiter.AttemptsLeft(realClientIP(stream), user); left != lockout.MaxAttempts {
		t.Errorf("stale re-checks were recorded as failed attempts (attempts_left=%d, want %d)", left, lockout.MaxAttempts)
	}
	if code, role := secBasicRequest(t, user, newPass); code != http.StatusOK || role != RoleAdmin {
		t.Fatalf("SELF-INFLICTED LOCKOUT: after %d stale stream re-checks the rotated, correct password got status=%d role=%q, want 200/admin",
			lockout.MaxAttempts+1, code, role)
	}
}

// TestSECBASIC5_LiveStreamCannotClearAnAttackersFailureCount_DefectProof is
// the serious half. RecordSuccess deletes the tier-1 pair entry, so one
// legitimate stream held open from a shared egress reset a co-located
// attacker's count once per interval — the attacker never reached the lock.
func TestSECBASIC5_LiveStreamCannotClearAnAttackersFailureCount_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "shared-egress-admin", "Correct-Horse-Battery-32!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	stream := secBasicStream(user, pass)
	ip := realClientIP(stream)

	for i := 0; i < lockout.MaxAttempts-1; i++ {
		secBasicRequest(t, user, "attacker-guess")
	}
	if !sseAuthStillValid(stream) {
		t.Fatal("precondition: the legitimate stream's credential is valid and the pair is not yet locked")
	}
	if left := loginLimiter.AttemptsLeft(ip, user); left != 1 {
		t.Fatalf("LOCKOUT RESET: a liveness re-check cleared the attacker's %d recorded failures (attempts_left=%d, want 1)",
			lockout.MaxAttempts-1, left)
	}
	secBasicRequest(t, user, "attacker-guess")
	if locked, _ := loginLimiter.Check(ip, user); !locked {
		t.Fatalf("the pair did not lock at %d failures with a live stream re-checking in between", lockout.MaxAttempts)
	}
}

// TestSECBASIC5_ReChecksDoNotDrawOnThePerIPBudget_DefectProof: the per-IP
// Basic failure budget bounds unauthenticated guesses. A failed re-check (a
// stream still carrying a rotated-away password) kept its reserved unit, so
// open streams spent the allowance real guesses are bounded by. The budget is
// probed directly: looping Burst bcrypts under -race can outlive the window.
func TestSECBASIC5_ReChecksDoNotDrawOnThePerIPBudget_DefectProof(t *testing.T) {
	secBasicEnv(t)
	const user, oldPass, newPass = "budget-stream-admin", "Correct-Horse-Battery-33!", "Correct-Horse-Battery-34!"
	secBasicUser(t, user, oldPass, RoleAdmin, false)
	live := secBasicStream(user, oldPass)
	for i := 0; i < 3; i++ {
		if !sseAuthStillValid(live) {
			t.Fatalf("precondition: valid re-check %d refused", i+1)
		}
	}
	if err := cfg.SetUIUser(user, newPass, RoleAdmin); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for i := 0; i < 3; i++ {
		if sseAuthStillValid(live) {
			t.Fatalf("stale re-check %d kept the stream alive", i+1)
		}
	}

	ip := realClientIP(live)
	for i := 0; i < lockout.Burst; i++ {
		if _, ok := basicAuthFailLimiter.Reserve(ip); !ok {
			t.Fatalf("BUDGET DRAWN: the per-IP Basic budget held only %d units after 6 liveness re-checks; want the full %d",
				i, lockout.Burst)
		}
	}
	if _, ok := basicAuthFailLimiter.Reserve(ip); ok {
		t.Fatal("control: the budget admitted more than Burst units — the probe above proves nothing")
	}
}

// TestSECBASIC5_Control_RevalidationStillCutsAnInvalidStream: a re-check
// records nothing, but it still VERIFIES. A rotated password, a deleted
// account and an account that enrolled TOTP after the stream opened all end it.
func TestSECBASIC5_Control_RevalidationStillCutsAnInvalidStream(t *testing.T) {
	secBasicEnv(t)

	const rotated, rotatedPass = "cut-rotated", "Correct-Horse-Battery-35!"
	secBasicUser(t, rotated, rotatedPass, RoleAdmin, false)
	if err := cfg.SetUIUser(rotated, "Correct-Horse-Battery-36!", RoleAdmin); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if sseAuthStillValid(secBasicStream(rotated, rotatedPass)) {
		t.Error("a stream carrying a rotated-away password survived its re-check")
	}

	const deleted, deletedPass = "cut-deleted", "Correct-Horse-Battery-37!"
	secBasicUser(t, deleted, deletedPass, RoleAdmin, false)
	if err := cfg.DeleteUIUser(deleted); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if sseAuthStillValid(secBasicStream(deleted, deletedPass)) {
		t.Error("a stream for a deleted account survived its re-check")
	}

	enrolled := secBasicUniqueUser(t, "enrolled")
	const enrolledPass = "Correct-Horse-Battery-38!"
	secBasicUser(t, enrolled, enrolledPass, RoleAdmin, false)
	stream := secBasicStream(enrolled, enrolledPass)
	if !sseAuthStillValid(stream) {
		t.Fatal("precondition: the stream is valid before TOTP enrolment")
	}
	cfg.SetTOTPSecret(enrolled, "JBSWY3DPEHPK3PXP", []string{"backup-code-1"})
	if sseAuthStillValid(stream) {
		t.Error("a Basic stream survived its account enrolling TOTP")
	}
	if _, ok := findAuditByActionObject(t, "auth.basic.refused", truncateForAudit(enrolled)); !ok {
		t.Error("the TOTP refusal on a re-check was not audited as auth.basic.refused")
	}
}

// TestSECBASIC5_Control_RevalidationStillHonoursAnActiveLockout: the lockout
// Check runs on BOTH intents, so a pair locked by real guesses has its live
// streams cut too — exempt from recording, never from being refused.
func TestSECBASIC5_Control_RevalidationStillHonoursAnActiveLockout(t *testing.T) {
	secBasicEnv(t)
	const user, pass = "locked-stream-admin", "Correct-Horse-Battery-39!"
	secBasicUser(t, user, pass, RoleAdmin, false)
	stream := secBasicStream(user, pass)
	if !sseAuthStillValid(stream) {
		t.Fatal("precondition: the stream is valid before the lock")
	}
	for i := 0; i < lockout.MaxAttempts; i++ {
		secBasicRequest(t, user, "attacker-guess")
	}
	if locked, _ := loginLimiter.Check(realClientIP(stream), user); !locked {
		t.Fatal("precondition: MaxAttempts submissions must lock the pair")
	}
	if sseAuthStillValid(stream) {
		t.Fatal("a live stream on a LOCKED (IP, username) pair survived its re-check")
	}
}

// TestSECBASIC5_Control_EveryFailedSubmissionIsStillAudited pins that removing
// the re-check's writes did not touch the SUBMISSION path's audit: every failed
// Basic submission still writes its own auth.basic.fail entry (asserted on
// unique content, never on ring length).
func TestSECBASIC5_Control_EveryFailedSubmissionIsStillAudited(t *testing.T) {
	secBasicEnv(t)
	user := secBasicUniqueUser(t, "audited")
	const attempts = 3
	for i := 0; i < attempts; i++ {
		if code, _ := secBasicRequest(t, user, "wrong-guess"); code != http.StatusUnauthorized {
			t.Fatalf("failed submission %d: status=%d, want 401", i+1, code)
		}
	}
	object := truncateForAudit(user)
	entries := auditGet()
	got := 0
	for i := range entries {
		if entries[i].Action == "auth.basic.fail" && entries[i].Object == object {
			got++
		}
	}
	if got != attempts {
		t.Fatalf("auth.basic.fail entries for %q = %d, want %d (one per failed submission)", user, got, attempts)
	}
}
