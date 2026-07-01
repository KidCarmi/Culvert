package main

// lockout_isolation_test.go — test-isolation helpers + regression
// guard for the package-global `loginLimiter`.
//
// The flake this addresses
// ========================
// Pre-fix, running `go test -count=N -run TestAPIAuthLogin_InvalidCreds
// ./...` with N >= 6 produced this failure pattern:
//
//   iter 1: 401 OK   (loginLimiter.entries["logintest"].attempts = 1)
//   iter 2: 401 OK   (.attempts = 2)
//   iter 3: 401 OK   (.attempts = 3)
//   iter 4: 401 OK   (.attempts = 4)
//   iter 5: 401 OK   (.attempts = 5; .lockedUntil set AFTER Check
//                     has already returned (false, 0))
//   iter 6+: 429 FAIL (Check sees lockedUntil > now → returns true →
//                      apiAuthLogin short-circuits with 429 before
//                      the credential check runs)
//
// Under `-count=N -shuffle=on` with N ≥ 6 this surfaced as a real
// CI flake (originally reported during PR #245 -count=5 validation;
// the exact threshold depends on suite shape but the determinism gate
// in CLAUDE.md targets `-count=2` — which doesn't trip the flake, but
// any higher count does).
//
// Root cause
// ==========
// `TestAPIAuthLogin_InvalidCreds` deliberately submits an invalid
// credential to exercise the 401 path. The submission necessarily
// records a failure in the package-global `loginLimiter` (ui_auth.go
// records the failure inside the apiAuthLogin handler after
// VerifyAuth returns false). The pre-fix test did not clean up that
// limiter state, so consecutive iterations of the same test (under
// `-count=N`) accumulated failures until the global hit the
// lockoutMaxAttempts threshold and subsequent iterations short-
// circuited at the lockout check.
//
// The fix
// =======
// Full-map snapshot+restore of the package-global limiter at test
// entry, mirroring the PR #241 / #245 idiom. Two key properties:
//
//   1. The snapshot is full — every existing entry is deep-copied
//      under the limiter's mutex. Restore on t.Cleanup is also under
//      the mutex.
//   2. The entries map is replaced with a fresh empty map for the
//      test's duration. The test's failed-login side effect is
//      therefore contained in this fresh map and discarded on
//      cleanup; the original entries are restored as they were.
//
// The snapshot/restore is owned by the limiter via the exported
// `loginLimiter.SnapshotAndClear()` API (internal/lockout, ADR-0002)
// rather than the production `RecordSuccess(user)` API because:
//
//   - RecordSuccess only deletes a SINGLE username key — it cannot
//     preserve state for OTHER tests' entries (qa_gate_test.go uses
//     a different username via the production RecordSuccess pattern;
//     that's still safe for ITS scope, but doesn't generalise).
//   - The isolation must capture and restore the WHOLE map so the
//     test's side effects are fully contained.
//
// No sleeps. No retries. No flaky annotations. No weakening of any
// CI gate.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// snapshotLoginLimiter captures and restores the package-global
// loginLimiter map for the duration of the test, delegating to the
// limiter's own SnapshotAndClear (which takes the snapshot and runs
// the restore under its mutex, so neither tears against a concurrent
// reader/writer).
//
// Tests that exercise the apiAuthLogin / lockout path MUST call
// this helper as their first step. The pattern is mandatory under
// -count=N -shuffle=on; without it the same test's own iterations
// would contaminate each other.
func snapshotLoginLimiter(t *testing.T) {
	t.Helper()
	t.Cleanup(loginLimiter.SnapshotAndClear())
}

// TestAPIAuthLogin_InvalidCreds_DeterministicUnderPollution is a
// regression guard for the snapshot/restore helper. It pre-pollutes
// loginLimiter with a fully-locked entry for "logintest" (simulating
// the worst case where a prior test left the user locked), then
// runs the same body as TestAPIAuthLogin_InvalidCreds. Without the
// snapshot/restore helper, this would fail with 429; with the
// helper, the pre-pollution is replaced by a fresh empty map at
// test entry and the test correctly returns 401.
func TestAPIAuthLogin_InvalidCreds_DeterministicUnderPollution(t *testing.T) {
	// Pollute the limiter BEFORE the snapshot helper runs by driving
	// "logintest" to a fully-locked state through the production
	// RecordFailure API (max consecutive failures ⇒ locked). This
	// simulates the worst case where a prior test left the user
	// locked. snapshotLoginLimiter inside the test scope will capture
	// this state, swap in a fresh empty map for the test, then restore
	// the polluted state on cleanup — so this test proves the helper
	// actually isolates iteration from external state.
	for i := 0; i < lockoutMaxAttempts; i++ {
		loginLimiter.RecordFailure("logintest")
	}
	// Manual restore for THIS test's pre-pollution (the snapshot
	// helper's restore will overwrite it back to the polluted state,
	// which we then clean here on a second t.Cleanup so we don't
	// leak the pollution into OTHER tests if this test is shuffled
	// to run before them).
	t.Cleanup(func() { loginLimiter.RecordSuccess("logintest") })

	// Now apply the snapshot helper — captures polluted state,
	// installs fresh empty map for the test body.
	snapshotLoginLimiter(t)

	// Same body as TestAPIAuthLogin_InvalidCreds.
	_ = cfg.SetAuth("logintest", "correctpass123")
	t.Cleanup(func() { _ = cfg.SetAuth("", "") })

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/login", map[string]any{
		"user": "logintest",
		"pass": "wrongpass",
	})
	apiAuthLogin(w, r)

	// Without the snapshot helper, the polluted entry would cause
	// Check() to return (true, ~900s) and the handler would emit
	// 429. With the helper, the test sees a fresh empty limiter
	// → Check returns (false, 0) → VerifyAuth fails → 401.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (snapshot helper failed to isolate the pre-polluted limiter; body: %s)",
			w.Code, http.StatusUnauthorized, w.Body.String())
	}
}
