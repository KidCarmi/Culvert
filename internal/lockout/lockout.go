// Package lockout provides the login account-lockout limiter and the admin-API
// rate limiter. It is a self-contained leaf (stdlib only, no Culvert coupling)
// extracted from the flat package main per ADR-0002.
package lockout

import (
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Login rate-limiter / account lockout
//
// After MaxAttempts consecutive failures within Window the account is locked
// for Duration.  A successful login resets the counter.  Keys are usernames;
// the limiter is not persisted across restarts (intentional — a restart by an
// operator is a valid recovery path).
// ---------------------------------------------------------------------------

const (
	// MaxAttempts is the number of consecutive failures that triggers a lock.
	MaxAttempts = 5
	// Window is the span within which failures accumulate toward a lock.
	Window = 10 * time.Minute
	// Duration is how long an account stays locked once tripped.
	Duration = 15 * time.Minute
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

// NewLoginLimiter returns a ready-to-use LoginLimiter.
func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{entries: map[string]*lockoutEntry{}}
}

// Check returns (locked bool, secondsRemaining int).
// A locked account must not be verified further.
func (l *LoginLimiter) Check(username string) (locked bool, secondsRemaining int) {
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
	if !e.firstFail.IsZero() && now.Sub(e.firstFail) > Window {
		e.attempts = 0
		e.firstFail = time.Time{}
		e.lockedUntil = time.Time{}
	}
	if e.attempts == 0 {
		e.firstFail = now
	}
	e.attempts++
	if e.attempts >= MaxAttempts {
		e.lockedUntil = now.Add(Duration)
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

// Cleanup removes entries that can no longer affect a decision, bounding the
// map against an unbounded-memory DoS: the key is the attacker-controlled
// username from the unauthenticated login POST, so without a sweep one failed
// attempt per distinct random username leaks a permanent entry each. An entry
// is removable when its lock has expired (a future Check would delete it
// anyway) or when it is unlocked and its failure window has elapsed (a future
// RecordFailure would reset it to a fresh window). Called periodically by the
// shared cleanup janitor. Removing a stale entry is behaviorally identical to
// the lazy reset both hot paths already perform, so it changes no decision.
func (l *LoginLimiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for username, e := range l.entries {
		if !e.lockedUntil.IsZero() {
			if e.lockedUntil.Before(now) {
				delete(l.entries, username) // lock expired
			}
			continue
		}
		if !e.firstFail.IsZero() && now.Sub(e.firstFail) > Window {
			delete(l.entries, username) // accumulating-failures window elapsed
		}
	}
}

// AttemptsLeft returns how many more failures are allowed before lockout.
func (l *LoginLimiter) AttemptsLeft(username string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[username]
	if e == nil {
		return MaxAttempts
	}
	left := MaxAttempts - e.attempts
	if left < 0 {
		left = 0
	}
	return left
}

// SnapshotAndClear captures the current limiter state, replaces it with an
// empty map, and returns a closure that restores the captured state. It is the
// exported equivalent of the whitebox snapshot/restore idiom used for test
// isolation of the package-global limiter: the entries are deep-copied under
// the mutex and the restore runs under the mutex too, so neither tears against
// a concurrent reader/writer. Production code never calls this; it exists so
// package main's test isolation helper does not need access to the unexported
// entries map across the package boundary (ADR-0002 extraction).
func (l *LoginLimiter) SnapshotAndClear() func() {
	l.mu.Lock()
	saved := make(map[string]*lockoutEntry, len(l.entries))
	for k, v := range l.entries {
		cp := *v
		saved[k] = &cp
	}
	l.entries = map[string]*lockoutEntry{}
	l.mu.Unlock()
	return func() {
		l.mu.Lock()
		l.entries = saved
		l.mu.Unlock()
	}
}

// Msg returns a human-readable lockout error. Exposed in package main as
// LockoutMsg via the shim alias.
func Msg(seconds int) string {
	return fmt.Sprintf("Account temporarily locked. Try again in %d seconds.", seconds)
}

// ---------------------------------------------------------------------------
// Admin API rate limiter — protects mutation endpoints against abuse.
//
// A sliding window of Burst requests is allowed per IP per RateWindow.
// This runs *after* session auth, so it limits authenticated admin actions.
// ---------------------------------------------------------------------------

const (
	// Burst is the max API mutations allowed per window.
	Burst = 60
	// RateWindow is the sliding window width for the API rate limiter.
	RateWindow = 1 * time.Minute
)

type apiRateEntry struct {
	count       int
	windowStart time.Time
}

// APIRateLimiter limits mutating admin API calls per client IP.
type APIRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*apiRateEntry
}

// NewAPIRateLimiter returns a ready-to-use APIRateLimiter.
func NewAPIRateLimiter() *APIRateLimiter {
	return &APIRateLimiter{entries: map[string]*apiRateEntry{}}
}

// Allow returns true if the IP is within the rate limit for API mutations.
func (a *APIRateLimiter) Allow(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[ip]
	now := time.Now()
	if e == nil || now.Sub(e.windowStart) > RateWindow {
		a.entries[ip] = &apiRateEntry{count: 1, windowStart: now}
		return true
	}
	e.count++
	return e.count <= Burst
}

// Cleanup removes expired entries.
func (a *APIRateLimiter) Cleanup() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, e := range a.entries {
		if now.Sub(e.windowStart) > RateWindow {
			delete(a.entries, k)
		}
	}
}
