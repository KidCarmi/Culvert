package main

// Per-instance circuit breaker for the Sluice CDR pool.
//
// State machine:
//
//   closed ──(N consecutive failures)──> open
//   open   ──(reset timeout elapsed)───> half-open
//   half-open ─(probe success)────────> closed
//   half-open ─(probe failure)────────> open  (reset timer starts fresh)
//
// Thread-safe.  The hot path (Allow + OnSuccess/OnFailure) is atomic
// where possible so picking under load doesn't serialise on a mutex.
//
// What counts as a failure is the POLICY of the caller (cdr_pool.go /
// cdr_proxy.go), not the breaker.  Breaker only tracks Allow()/Result
// transitions — orthogonal to transport vs. app errors.

import (
	"sync"
	"sync/atomic"
	"time"
)

// Breaker state (atomic int32 — cheap read without mutex).
const (
	cbStateClosed   int32 = 0
	cbStateOpen     int32 = 1
	cbStateHalfOpen int32 = 2
)

// cdrBreakerConfig tunables.  Zero value gives sensible defaults.
//
// HalfOpenProbes is int32 because the runtime budget counter is int32
// and this avoids a (lossy in theory, safe in practice) int→int32 cast
// that gosec G115 flags as CWE-190.
type cdrBreakerConfig struct {
	FailureThreshold int           // consecutive failures to open (default 5)
	ResetTimeout     time.Duration // time in open before half-open (default 30s)
	HalfOpenProbes   int32         // probes allowed in half-open (default 1)
	// HalfOpenProbeTimeout bounds how long a reserved half-open probe may go
	// without reporting an outcome before the budget is re-armed. It is a
	// WEDGE ESCAPE, not a concurrency control: Allow() hands out a reservation
	// that only OnSuccess/OnFailure/Reset release, and half-open has no other
	// timer, so a single caller that takes a reservation and never records an
	// outcome used to strand the breaker in half-open for the whole process
	// lifetime — every later Allow() denied, CDR silently skipped on every
	// file, and (under the default fail-OPEN FailMode) every document
	// forwarded unsanitized. It must comfortably exceed a legitimate probe:
	// the per-file deadline is cdrDefaultTimeout (35s), so the default is
	// 2×ResetTimeout with a 90s floor.
	HalfOpenProbeTimeout time.Duration
}

func (c cdrBreakerConfig) withDefaults() cdrBreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.ResetTimeout <= 0 {
		c.ResetTimeout = 30 * time.Second
	}
	if c.HalfOpenProbes <= 0 {
		c.HalfOpenProbes = 1
	}
	if c.HalfOpenProbeTimeout <= 0 {
		c.HalfOpenProbeTimeout = 2 * c.ResetTimeout
		if c.HalfOpenProbeTimeout < cdrHalfOpenProbeTimeoutFloor {
			c.HalfOpenProbeTimeout = cdrHalfOpenProbeTimeoutFloor
		}
	}
	return c
}

// cdrHalfOpenProbeTimeoutFloor keeps the wedge escape above any legitimate
// probe duration even when ResetTimeout is tuned very low. cdrDefaultTimeout
// (the per-file Sluice deadline) is 35s.
const cdrHalfOpenProbeTimeoutFloor = 90 * time.Second

// cdrCircuitBreaker tracks one instance's health.  The pool owns one
// breaker per enrolled Sluice.
type cdrCircuitBreaker struct {
	cfg cdrBreakerConfig

	state         atomic.Int32
	openedAt      atomic.Int64 // UnixNano when state transitioned to open
	consecFails   atomic.Int64
	halfOpenTried atomic.Int32 // probes currently being served in half-open
	halfOpenAt    atomic.Int64 // UnixNano when the current half-open budget was armed
	// staleProbes counts half-open budgets re-armed because a reserved probe
	// never reported an outcome. Non-zero means some caller is taking a
	// reservation it cannot release — surfaced in Stats for exactly that.
	staleProbes atomic.Int64

	// totalOpens counts state transitions into open for observability.
	totalOpens atomic.Int64
	totalTrips atomic.Int64 // Allow() denials while open

	// nowFn is injectable for tests — defaults to time.Now().
	nowMu sync.RWMutex
	nowFn func() time.Time
}

// newCDRCircuitBreaker returns a breaker initialised in the closed state.
func newCDRCircuitBreaker(cfg cdrBreakerConfig) *cdrCircuitBreaker {
	b := &cdrCircuitBreaker{cfg: cfg.withDefaults()}
	b.state.Store(cbStateClosed)
	b.nowFn = time.Now
	return b
}

// now returns the injectable current time.
func (b *cdrCircuitBreaker) now() time.Time {
	b.nowMu.RLock()
	fn := b.nowFn
	b.nowMu.RUnlock()
	return fn()
}

// setNowFn swaps the clock (tests only).
func (b *cdrCircuitBreaker) setNowFn(fn func() time.Time) {
	b.nowMu.Lock()
	b.nowFn = fn
	b.nowMu.Unlock()
}

// State reports the current state.  Lock-free.
func (b *cdrCircuitBreaker) State() int32 {
	return b.state.Load()
}

// Allow reports whether the caller should proceed with a request.  Also
// advances the state machine when the open→half-open timer has elapsed,
// and enforces the half-open probe budget.
func (b *cdrCircuitBreaker) Allow() bool {
	switch b.state.Load() {
	case cbStateClosed:
		return true
	case cbStateOpen:
		// Check if the reset timeout has elapsed.
		elapsed := b.now().UnixNano() - b.openedAt.Load()
		if elapsed < int64(b.cfg.ResetTimeout) {
			b.totalTrips.Add(1)
			return false
		}
		// Try to transition to half-open (racy with other goroutines; CAS
		// makes exactly one succeed).
		if b.state.CompareAndSwap(cbStateOpen, cbStateHalfOpen) {
			b.halfOpenTried.Store(0)
			b.halfOpenAt.Store(b.now().UnixNano())
		}
		// Fall through to half-open handling below.
		fallthrough
	case cbStateHalfOpen:
		// Budget: only N concurrent probes.
		if b.halfOpenTried.Add(1) > b.cfg.HalfOpenProbes {
			b.halfOpenTried.Add(-1) // undo the reservation
			// Wedge escape. A reservation is released only by
			// OnSuccess/OnFailure/Reset, and half-open has no other timer, so a
			// caller that takes one and never records an outcome would otherwise
			// deny every later Allow() for the rest of the process lifetime. If
			// the budget has gone that long without an outcome, treat the
			// reservation as abandoned, re-arm, and admit one fresh probe so the
			// breaker can still find its way back to closed. HalfOpenProbeTimeout
			// is set well above a legitimate probe, so this cannot preempt one
			// that is merely slow.
			armed := b.halfOpenAt.Load()
			if armed != 0 && b.now().UnixNano()-armed >= int64(b.cfg.HalfOpenProbeTimeout) &&
				b.halfOpenAt.CompareAndSwap(armed, b.now().UnixNano()) {
				b.staleProbes.Add(1)
				b.halfOpenTried.Store(1)
				return true
			}
			b.totalTrips.Add(1)
			return false
		}
		return true
	default:
		return true
	}
}

// OnSuccess records a successful call.  In closed state, resets the
// failure counter.  In half-open state, transitions back to closed.
func (b *cdrCircuitBreaker) OnSuccess() {
	// Reset fail counter regardless of state.
	b.consecFails.Store(0)
	if b.state.Load() == cbStateHalfOpen {
		// Transition half-open → closed.  CAS to avoid racing with a
		// concurrent OnFailure.
		if b.state.CompareAndSwap(cbStateHalfOpen, cbStateClosed) {
			b.halfOpenTried.Store(0)
			b.halfOpenAt.Store(0)
		}
	}
}

// OnFailure records a failure.  In closed state, may trip the breaker.
// In half-open state, returns straight to open with a fresh timer.
func (b *cdrCircuitBreaker) OnFailure() {
	switch b.state.Load() {
	case cbStateClosed:
		fails := b.consecFails.Add(1)
		if fails >= int64(b.cfg.FailureThreshold) {
			if b.state.CompareAndSwap(cbStateClosed, cbStateOpen) {
				b.openedAt.Store(b.now().UnixNano())
				b.totalOpens.Add(1)
			}
		}
	case cbStateHalfOpen:
		// Single failure in half-open → back to open.
		if b.state.CompareAndSwap(cbStateHalfOpen, cbStateOpen) {
			b.openedAt.Store(b.now().UnixNano())
			b.totalOpens.Add(1)
			b.halfOpenTried.Store(0)
			b.halfOpenAt.Store(0)
		}
	case cbStateOpen:
		// Already open — nothing to do.
	}
}

// Reset forces the breaker back to closed (admin override).
func (b *cdrCircuitBreaker) Reset() {
	b.state.Store(cbStateClosed)
	b.consecFails.Store(0)
	b.halfOpenTried.Store(0)
	b.halfOpenAt.Store(0)
	b.openedAt.Store(0)
}

// Available reports whether Allow() would plausibly admit a request, WITHOUT
// consuming a half-open probe reservation.
//
// A liveness nil-check must use this, never Allow(): the hot path asked
// "is any instance up?" through Allow(), which spent the single half-open
// probe on a check that issues no RPC and so can never report an outcome. The
// real sanitize call that followed was then denied, and the breaker wedged.
// The reservation belongs to the caller that can actually record the result.
func (b *cdrCircuitBreaker) Available() bool {
	switch b.state.Load() {
	case cbStateClosed:
		return true
	case cbStateOpen:
		return b.now().UnixNano()-b.openedAt.Load() >= int64(b.cfg.ResetTimeout)
	case cbStateHalfOpen:
		if b.halfOpenTried.Load() < b.cfg.HalfOpenProbes {
			return true
		}
		armed := b.halfOpenAt.Load()
		return armed != 0 && b.now().UnixNano()-armed >= int64(b.cfg.HalfOpenProbeTimeout)
	default:
		return true
	}
}

// Stats returns a snapshot suitable for /api/cdr/instances exposure.
type cdrBreakerStats struct {
	State       string `json:"state"` // "closed" | "open" | "half_open"
	ConsecFails int64  `json:"consecFails"`
	TotalOpens  int64  `json:"totalOpens"` // total transitions into open
	TotalTrips  int64  `json:"totalTrips"` // Allow() denials while open
	OpenedAt    int64  `json:"openedAt"`   // UnixNano; 0 if never opened
	// StaleProbes counts half-open budgets re-armed after a reserved probe
	// never reported an outcome. Any non-zero value is a bug signal: some
	// caller is taking a reservation it cannot release.
	StaleProbes int64 `json:"staleProbes"`
}

// Stats returns a lock-free snapshot of current breaker state.
func (b *cdrCircuitBreaker) Stats() cdrBreakerStats {
	return cdrBreakerStats{
		State:       breakerStateName(b.state.Load()),
		ConsecFails: b.consecFails.Load(),
		TotalOpens:  b.totalOpens.Load(),
		TotalTrips:  b.totalTrips.Load(),
		OpenedAt:    b.openedAt.Load(),
		StaleProbes: b.staleProbes.Load(),
	}
}

func breakerStateName(s int32) string {
	switch s {
	case cbStateClosed:
		return "closed"
	case cbStateOpen:
		return "open"
	case cbStateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}
