package lockout

import (
	"strings"
	"testing"
	"time"
)

func newLimiter() *LoginLimiter {
	return &LoginLimiter{entries: map[string]*lockoutEntry{}}
}

// ─── Check ────────────────────────────────────────────────────────────────────

func TestLoginLimiter_CheckUnknown(t *testing.T) {
	l := newLimiter()
	locked, secs := l.Check("nobody")
	if locked || secs != 0 {
		t.Errorf("unknown user should not be locked, got locked=%v secs=%d", locked, secs)
	}
}

func TestLoginLimiter_CheckLockedAccount(t *testing.T) {
	l := newLimiter()
	const user = "alice"
	// Trigger lockout.
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(user)
	}
	locked, secs := l.Check(user)
	if !locked {
		t.Error("account should be locked after max attempts")
	}
	if secs <= 0 {
		t.Errorf("seconds remaining should be positive, got %d", secs)
	}
}

func TestLoginLimiter_CheckExpiredLock(t *testing.T) {
	l := newLimiter()
	const user = "bob"
	// Manually insert an expired lockout entry.
	l.mu.Lock()
	l.entries[user] = &lockoutEntry{
		attempts:    MaxAttempts,
		lockedUntil: time.Now().Add(-time.Second), // already expired
	}
	l.mu.Unlock()

	locked, secs := l.Check(user)
	if locked {
		t.Error("expired lockout should not be locked")
	}
	if secs != 0 {
		t.Errorf("expected 0 seconds for expired lock, got %d", secs)
	}
	// Entry should be cleaned up.
	l.mu.Lock()
	_, exists := l.entries[user]
	l.mu.Unlock()
	if exists {
		t.Error("expired lockout entry should be deleted after Check")
	}
}

// ─── RecordFailure ────────────────────────────────────────────────────────────

func TestLoginLimiter_RecordFailure_NotYetLocked(t *testing.T) {
	l := newLimiter()
	const user = "charlie"
	for i := 0; i < MaxAttempts-1; i++ {
		locked := l.RecordFailure(user)
		if locked {
			t.Errorf("attempt %d should not trigger lockout yet", i+1)
		}
	}
}

func TestLoginLimiter_RecordFailure_TriggersLockout(t *testing.T) {
	l := newLimiter()
	const user = "dave"
	var justLocked bool
	for i := 0; i < MaxAttempts; i++ {
		justLocked = l.RecordFailure(user)
	}
	if !justLocked {
		t.Error("RecordFailure should return true when account just becomes locked")
	}
	locked, _ := l.Check(user)
	if !locked {
		t.Error("account should be locked after max attempts")
	}
}

func TestLoginLimiter_RecordFailure_WindowReset(t *testing.T) {
	l := newLimiter()
	const user = "eve"
	// Manually insert a stale entry (failure outside the window).
	l.mu.Lock()
	l.entries[user] = &lockoutEntry{
		attempts:  MaxAttempts - 1,
		firstFail: time.Now().Add(-(Window + time.Second)), // outside window
	}
	l.mu.Unlock()

	// Next failure should reset the window and start fresh.
	justLocked := l.RecordFailure(user)
	if justLocked {
		t.Error("should not lock immediately after window reset")
	}
	left := l.AttemptsLeft(user)
	if left != MaxAttempts-1 {
		t.Errorf("after window reset, attempts left = %d, want %d", left, MaxAttempts-1)
	}
}

// ─── RecordSuccess ────────────────────────────────────────────────────────────

func TestLoginLimiter_RecordSuccess_ClearsFailures(t *testing.T) {
	l := newLimiter()
	const user = "frank"
	l.RecordFailure(user)
	l.RecordFailure(user)

	l.RecordSuccess(user)

	if l.AttemptsLeft(user) != MaxAttempts {
		t.Error("RecordSuccess should reset failure counter to max")
	}
}

// ─── AttemptsLeft ─────────────────────────────────────────────────────────────

func TestLoginLimiter_AttemptsLeft_Default(t *testing.T) {
	l := newLimiter()
	if got := l.AttemptsLeft("nobody"); got != MaxAttempts {
		t.Errorf("AttemptsLeft for unknown user = %d, want %d", got, MaxAttempts)
	}
}

func TestLoginLimiter_AttemptsLeft_AfterFailures(t *testing.T) {
	l := newLimiter()
	const user = "grace"
	l.RecordFailure(user)
	l.RecordFailure(user)

	if got := l.AttemptsLeft(user); got != MaxAttempts-2 {
		t.Errorf("AttemptsLeft = %d, want %d", got, MaxAttempts-2)
	}
}

func TestLoginLimiter_AttemptsLeft_ZeroWhenLocked(t *testing.T) {
	l := newLimiter()
	const user = "heidi"
	for i := 0; i < MaxAttempts; i++ {
		l.RecordFailure(user)
	}
	if got := l.AttemptsLeft(user); got != 0 {
		t.Errorf("AttemptsLeft when locked = %d, want 0", got)
	}
}

// ─── LockoutMsg ───────────────────────────────────────────────────────────────

func TestMsg(t *testing.T) {
	msg := Msg(300)
	if !strings.Contains(msg, "300") {
		t.Errorf("Msg should contain seconds, got %q", msg)
	}
	if !strings.Contains(msg, "locked") || !strings.Contains(msg, "300") {
		t.Errorf("Msg should mention lock, got %q", msg)
	}
}

// ─── API Rate Limiter ───────────────────────────────────────────────────────

func TestAPIRateLimiter_Allow(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	for i := 0; i < Burst; i++ {
		if !lim.Allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	// Next should be rejected.
	if lim.Allow("10.0.0.1") {
		t.Error("should be rate limited after burst")
	}
}

func TestAPIRateLimiter_DifferentIPs(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	for i := 0; i < Burst; i++ {
		lim.Allow("10.0.0.1")
	}
	// Different IP should still be allowed.
	if !lim.Allow("10.0.0.2") {
		t.Error("different IP should not be rate limited")
	}
}

func TestAPIRateLimiter_Cleanup(t *testing.T) {
	lim := &APIRateLimiter{entries: map[string]*apiRateEntry{}}
	lim.Allow("10.0.0.1")
	if len(lim.entries) != 1 {
		t.Fatal("expected 1 entry")
	}
	// Manually expire the entry.
	lim.entries["10.0.0.1"].windowStart = lim.entries["10.0.0.1"].windowStart.Add(-2 * RateWindow)
	lim.Cleanup()
	if len(lim.entries) != 0 {
		t.Error("expected cleanup to remove expired entry")
	}
}

// ─── LoginLimiter.Cleanup — bound the username-keyed map ─────────────────────

// TestLoginLimiter_Cleanup_RemovesStaleEntries is the regression guard for the
// unbounded-memory DoS: the key is the attacker-controlled login username, so
// without a sweep one failed attempt per random username leaks a permanent
// entry. Cleanup must evict entries whose lock has expired AND unlocked
// entries whose failure window has elapsed, while keeping still-relevant ones.
func TestLoginLimiter_Cleanup_RemovesStaleEntries(t *testing.T) {
	l := newLimiter()
	now := time.Now()

	l.mu.Lock()
	// (a) lock expired → removable.
	l.entries["expired-lock"] = &lockoutEntry{attempts: MaxAttempts, lockedUntil: now.Add(-time.Second)}
	// (b) unlocked, window elapsed → removable (a future RecordFailure resets it).
	l.entries["stale-window"] = &lockoutEntry{attempts: 2, firstFail: now.Add(-Window - time.Minute)}
	// (c) unlocked, window still open → KEEP (an in-progress attacker must stay
	//     rate-limited).
	l.entries["fresh-fail"] = &lockoutEntry{attempts: 2, firstFail: now.Add(-time.Second)}
	// (d) currently locked → KEEP (the lock must still apply).
	l.entries["active-lock"] = &lockoutEntry{attempts: MaxAttempts, lockedUntil: now.Add(Duration)}
	l.mu.Unlock()

	l.Cleanup()

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.entries["expired-lock"]; ok {
		t.Error("expired lock entry should be evicted")
	}
	if _, ok := l.entries["stale-window"]; ok {
		t.Error("elapsed-window entry should be evicted")
	}
	if _, ok := l.entries["fresh-fail"]; !ok {
		t.Error("in-window failure entry must be kept (attacker still rate-limited)")
	}
	if _, ok := l.entries["active-lock"]; !ok {
		t.Error("active lock entry must be kept (lock still applies)")
	}
}

// TestLoginLimiter_Cleanup_DoesNotAlterDecision proves eviction is behavior-
// preserving: a fresh attempt after a stale entry is swept sees exactly the
// same state it would have via the hot-path lazy reset.
func TestLoginLimiter_Cleanup_DoesNotAlterDecision(t *testing.T) {
	l := newLimiter()
	const user = "carol"

	l.mu.Lock()
	l.entries[user] = &lockoutEntry{attempts: 3, firstFail: time.Now().Add(-Window - time.Minute)}
	l.mu.Unlock()

	l.Cleanup() // removes the stale entry

	// A subsequent failure must start a fresh window (attempts=1), identical to
	// the lazy reset RecordFailure would have applied to the stale entry.
	l.RecordFailure(user)
	if left := l.AttemptsLeft(user); left != MaxAttempts-1 {
		t.Errorf("AttemptsLeft = %d after post-cleanup failure; want %d (fresh window)", left, MaxAttempts-1)
	}
}
