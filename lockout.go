package main

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Login rate-limiter / account lockout
//
// After lockoutMaxAttempts consecutive failures within lockoutWindow the
// account is locked for lockoutDuration.  A successful login resets the
// counter.  Keys are usernames; the limiter is not persisted across restarts
// (intentional — a restart by an operator is a valid recovery path).
// ---------------------------------------------------------------------------

const (
	lockoutMaxAttempts = 5
	lockoutWindow      = 10 * time.Minute
	lockoutDuration    = 15 * time.Minute
)

type lockoutEntry struct {
	attempts    int
	firstFail   time.Time
	lockedUntil time.Time
}

// LoginLimiter tracks failed login attempts per username.
type LoginLimiter struct {
	mu      sync.Mutex
	entries map[string]*lockoutEntry
}

var loginLimiter = &LoginLimiter{entries: map[string]*lockoutEntry{}}

// Check returns (locked bool, secondsRemaining int).
// A locked account must not be verified further.
func (l *LoginLimiter) Check(username string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[username]
	if e == nil {
		return false, 0
	}
	if !e.lockedUntil.IsZero() {
		remaining := time.Until(e.lockedUntil)
		if remaining > 0 {
			return true, int(remaining.Seconds()) + 1
		}
		// Lock expired — clean up.
		delete(l.entries, username)
	}
	return false, 0
}

// RecordFailure registers one failed attempt. Returns true when the account
// just became locked (so the caller can log the lockout event).
func (l *LoginLimiter) RecordFailure(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[username]
	if e == nil {
		e = &lockoutEntry{}
		l.entries[username] = e
	}
	now := time.Now()
	// Reset window if too much time has passed since the first failure.
	if !e.firstFail.IsZero() && now.Sub(e.firstFail) > lockoutWindow {
		e.attempts = 0
		e.firstFail = time.Time{}
		e.lockedUntil = time.Time{}
	}
	if e.attempts == 0 {
		e.firstFail = now
	}
	e.attempts++
	if e.attempts >= lockoutMaxAttempts {
		e.lockedUntil = now.Add(lockoutDuration)
		return true
	}
	return false
}

// RecordSuccess clears the failure history for the username.
func (l *LoginLimiter) RecordSuccess(username string) {
	l.mu.Lock()
	delete(l.entries, username)
	l.mu.Unlock()
}

// AttemptsLeft returns how many more failures are allowed before lockout.
func (l *LoginLimiter) AttemptsLeft(username string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[username]
	if e == nil {
		return lockoutMaxAttempts
	}
	left := lockoutMaxAttempts - e.attempts
	if left < 0 {
		left = 0
	}
	return left
}

// LockoutMsg returns a human-readable lockout error.
func LockoutMsg(seconds int) string {
	return fmt.Sprintf("Account temporarily locked. Try again in %d seconds.", seconds)
}
