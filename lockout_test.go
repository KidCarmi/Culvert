package main

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
	for i := 0; i < lockoutMaxAttempts; i++ {
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
		attempts:    lockoutMaxAttempts,
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
	for i := 0; i < lockoutMaxAttempts-1; i++ {
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
	for i := 0; i < lockoutMaxAttempts; i++ {
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
		attempts:  lockoutMaxAttempts - 1,
		firstFail: time.Now().Add(-(lockoutWindow + time.Second)), // outside window
	}
	l.mu.Unlock()

	// Next failure should reset the window and start fresh.
	justLocked := l.RecordFailure(user)
	if justLocked {
		t.Error("should not lock immediately after window reset")
	}
	left := l.AttemptsLeft(user)
	if left != lockoutMaxAttempts-1 {
		t.Errorf("after window reset, attempts left = %d, want %d", left, lockoutMaxAttempts-1)
	}
}

// ─── RecordSuccess ────────────────────────────────────────────────────────────

func TestLoginLimiter_RecordSuccess_ClearsFailures(t *testing.T) {
	l := newLimiter()
	const user = "frank"
	l.RecordFailure(user)
	l.RecordFailure(user)

	l.RecordSuccess(user)

	if l.AttemptsLeft(user) != lockoutMaxAttempts {
		t.Error("RecordSuccess should reset failure counter to max")
	}
}

// ─── AttemptsLeft ─────────────────────────────────────────────────────────────

func TestLoginLimiter_AttemptsLeft_Default(t *testing.T) {
	l := newLimiter()
	if got := l.AttemptsLeft("nobody"); got != lockoutMaxAttempts {
		t.Errorf("AttemptsLeft for unknown user = %d, want %d", got, lockoutMaxAttempts)
	}
}

func TestLoginLimiter_AttemptsLeft_AfterFailures(t *testing.T) {
	l := newLimiter()
	const user = "grace"
	l.RecordFailure(user)
	l.RecordFailure(user)

	if got := l.AttemptsLeft(user); got != lockoutMaxAttempts-2 {
		t.Errorf("AttemptsLeft = %d, want %d", got, lockoutMaxAttempts-2)
	}
}

func TestLoginLimiter_AttemptsLeft_ZeroWhenLocked(t *testing.T) {
	l := newLimiter()
	const user = "heidi"
	for i := 0; i < lockoutMaxAttempts; i++ {
		l.RecordFailure(user)
	}
	if got := l.AttemptsLeft(user); got != 0 {
		t.Errorf("AttemptsLeft when locked = %d, want 0", got)
	}
}

// ─── LockoutMsg ───────────────────────────────────────────────────────────────

func TestLockoutMsg(t *testing.T) {
	msg := LockoutMsg(300)
	if !strings.Contains(msg, "300") {
		t.Errorf("LockoutMsg should contain seconds, got %q", msg)
	}
	if !strings.Contains(msg, "locked") || !strings.Contains(msg, "300") {
		t.Errorf("LockoutMsg should mention lock, got %q", msg)
	}
}
