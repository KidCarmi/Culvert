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
	return c
}

// cdrCircuitBreaker tracks one instance's health.  The pool owns one
// breaker per enrolled Sluice.
type cdrCircuitBreaker struct {
	cfg cdrBreakerConfig

	state         atomic.Int32
	openedAt      atomic.Int64 // UnixNano when state transitioned to open
	consecFails   atomic.Int64
	halfOpenTried atomic.Int32 // probes currently being served in half-open

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
	allowed, _, _ := b.allowReserve()
	return allowed
}

// allowReserve is Allow plus the bookkeeping a releasing caller needs:
// whether THIS call reserved a half-open slot, and the open-generation the
// reservation belongs to.
//
// Only a caller that actually reserved may release, and only while the
// breaker is still in the generation it reserved under.  A caller admitted
// in the CLOSED state reserves nothing, so releasing on its behalf would
// decrement a slot some other goroutine is holding -- handing out more
// concurrent probes than the configured budget, which is the opposite of
// the defect this budget exists to prevent.
func (b *cdrCircuitBreaker) allowReserve() (allowed, reserved bool, gen int64) {
	// The generation is captured BEFORE the state is read, and that order
	// is deliberate.  Capturing it AFTER the reservation would let a
	// breaker that re-opened in between hand back a generation NEWER than
	// the one the slot was taken in -- and since OnFailure zeroes the
	// counter on its way to open, the later release would then decrement
	// a slot belonging to a fresh cycle: an over-release, which is the
	// failure direction that matters.  Capturing it first can only err the
	// other way (a release declined for a slot we did hold), which costs
	// one slot for one cycle and is cleared by the next reported outcome.
	// Do not move this load below the switch.
	gen = b.totalOpens.Load()
	switch b.state.Load() {
	case cbStateClosed:
		return true, false, gen
	case cbStateOpen:
		// Check if the reset timeout has elapsed.
		elapsed := b.now().UnixNano() - b.openedAt.Load()
		if elapsed < int64(b.cfg.ResetTimeout) {
			b.totalTrips.Add(1)
			return false, false, gen
		}
		// Try to transition to half-open (racy with other goroutines; CAS
		// makes exactly one succeed).
		if b.state.CompareAndSwap(cbStateOpen, cbStateHalfOpen) {
			b.halfOpenTried.Store(0)
		}
		// Fall through to half-open handling below.
		fallthrough
	case cbStateHalfOpen:
		// Budget: only N concurrent probes.
		if b.halfOpenTried.Add(1) > b.cfg.HalfOpenProbes {
			b.halfOpenTried.Add(-1) // undo the reservation
			b.totalTrips.Add(1)
			return false, false, gen
		}
		return true, true, gen
	default:
		return true, false, gen
	}
}

// Permits reports whether Allow() would currently permit a call, WITHOUT
// reserving a half-open probe slot, WITHOUT advancing the open->half-open
// timer, and WITHOUT charging totalTrips.
//
// This is the accessor every OBSERVER must use: the admin-UI status reads,
// the diagnostics row, and the proxy's cheap "is CDR live at all?"
// short-circuit.  Allow()'s half-open budget is a RESERVATION that only a
// reported outcome gives back, so an observer that called Allow() would
// consume the single probe the breaker uses to discover that the backend
// recovered and then throw it away -- leaving the breaker wedged in
// half-open forever (CHAOS-66).  Observing a control must never change it.
func (b *cdrCircuitBreaker) Permits() bool {
	switch b.state.Load() {
	case cbStateClosed:
		return true
	case cbStateOpen:
		return b.now().UnixNano()-b.openedAt.Load() >= int64(b.cfg.ResetTimeout)
	case cbStateHalfOpen:
		return b.halfOpenTried.Load() < b.cfg.HalfOpenProbes
	default:
		return true
	}
}

// ReleaseProbe returns an unused half-open reservation taken by Allow().
//
// Allow() reserves a slot; only OnSuccess/OnFailure (which Store(0)) or
// this call give it back.  Any caller that receives true from Allow() and
// then does NOT report an outcome -- a cache hit, an oversize skip, a
// file_too_large error that is deliberately not charged to the breaker, a
// recovered panic -- MUST release, or the reservation leaks and the
// breaker can never issue another probe.
//
// Never drives the counter below zero: a release racing an OnSuccess that
// already zeroed it is a no-op, not an over-release that would hand out
// more concurrent probes than the configured budget.
func (b *cdrCircuitBreaker) releaseProbeForGeneration(gen int64) {
	// A newer open cycle owns the budget now: OnFailure bumps totalOpens on
	// every transition into open, so an unchanged generation means the slot
	// still in the counter is the one we took.  OnSuccess/OnFailure both
	// Store(0), so a settled breaker leaves nothing to release.
	if b.totalOpens.Load() != gen {
		return
	}
	b.ReleaseProbe()
}

func (b *cdrCircuitBreaker) ReleaseProbe() {
	for {
		cur := b.halfOpenTried.Load()
		if cur <= 0 {
			return
		}
		if b.halfOpenTried.CompareAndSwap(cur, cur-1) {
			return
		}
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
	b.openedAt.Store(0)
}

// Stats returns a snapshot suitable for /api/cdr/instances exposure.
type cdrBreakerStats struct {
	State       string `json:"state"` // "closed" | "open" | "half_open"
	ConsecFails int64  `json:"consecFails"`
	TotalOpens  int64  `json:"totalOpens"` // total transitions into open
	TotalTrips  int64  `json:"totalTrips"` // Allow() denials while open
	OpenedAt    int64  `json:"openedAt"`   // UnixNano; 0 if never opened
}

// Stats returns a lock-free snapshot of current breaker state.
func (b *cdrCircuitBreaker) Stats() cdrBreakerStats {
	return cdrBreakerStats{
		State:       breakerStateName(b.state.Load()),
		ConsecFails: b.consecFails.Load(),
		TotalOpens:  b.totalOpens.Load(),
		TotalTrips:  b.totalTrips.Load(),
		OpenedAt:    b.openedAt.Load(),
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
