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
	// PerFileDeadline is the effective per-file Sluice deadline this
	// breaker's probes run under (cdr.timeout_sec, else cdrDefaultTimeout).
	// It only feeds HalfOpenProbeTimeout. Zero resolves from the active config.
	PerFileDeadline time.Duration
	// HalfOpenProbeTimeout bounds how long a reserved half-open probe may go
	// without reporting an outcome before the budget is re-armed. It is a
	// WEDGE ESCAPE, not a concurrency control: Allow() hands out a reservation
	// that only OnSuccess/OnFailure/Reset release, and half-open has no other
	// timer, so a single caller that takes a reservation and never records an
	// outcome used to strand the breaker in half-open for the whole process
	// lifetime — every later Allow() denied, CDR silently skipped on every
	// file, and (under the default fail-OPEN FailMode) every document
	// forwarded unsanitized.
	//
	// It MUST exceed any legitimate probe, or it preempts a live one: the
	// preempted call's late OnFailure can reopen the breaker after the
	// replacement probe already succeeded, reintroducing a fail-open bypass
	// window. cdr.timeout_sec is bounded below at 30s but NOT above
	// (validCDRTimeoutSec), so this cannot derive from ResetTimeout alone.
	// See cdrHalfOpenProbeTimeout.
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
	if c.PerFileDeadline <= 0 {
		c.PerFileDeadline = cdrEffectivePerFileDeadline()
	}
	if c.HalfOpenProbeTimeout <= 0 {
		c.HalfOpenProbeTimeout = cdrHalfOpenProbeTimeout(c.ResetTimeout, c.PerFileDeadline)
	}
	return c
}

const (
	// cdrHalfOpenProbeTimeoutFloor keeps the wedge escape above any legitimate
	// probe even when ResetTimeout is tuned very low.
	cdrHalfOpenProbeTimeoutFloor = 90 * time.Second
	// cdrHalfOpenProbeGrace is the margin over the per-file deadline, so a probe
	// that runs right up to its deadline (plus dial, queueing and the outcome
	// write) is never mistaken for abandoned.
	cdrHalfOpenProbeGrace = 30 * time.Second
)

// cdrHalfOpenProbeTimeout derives the wedge-escape timeout. A probe can
// legitimately run for the whole per-file Sluice deadline, and cdr.timeout_sec
// may be set arbitrarily high (validCDRTimeoutSec bounds it below at 30s, not
// above), so the deadline — not ResetTimeout alone — sets the floor. Pure, so
// the relationship is testable across the whole configurable range.
func cdrHalfOpenProbeTimeout(reset, perFile time.Duration) time.Duration {
	d := 2 * reset
	if overDeadline := perFile + cdrHalfOpenProbeGrace; overDeadline > d {
		d = overDeadline
	}
	if d < cdrHalfOpenProbeTimeoutFloor {
		d = cdrHalfOpenProbeTimeoutFloor
	}
	return d
}

// cdrConfigPerFileDeadline resolves the per-file Sluice deadline a given
// CDRConfig implies, mirroring newCDRClient's own resolution
// (0 ⇒ cdrDefaultTimeout) and the clientCfg.Timeout assignment in
// dialEnrolledInstance.
//
// Every breaker built during a config apply MUST be seeded from the config
// being applied, via this function — never from cdrEffectivePerFileDeadline
// below. initCDRClient builds the pool (and therefore the breakers) BEFORE it
// publishes cdrActiveCfg, so a breaker that resolved the deadline from the
// active config at construction time would read the PREVIOUS config — the zero
// value on first boot — and derive a 90s probe timeout no matter what
// cdr.timeout_sec says. That silently reinstated the preemption bug this
// derivation exists to prevent.
func cdrConfigPerFileDeadline(cfg CDRConfig) time.Duration {
	if cfg.TimeoutSec > 0 {
		return time.Duration(cfg.TimeoutSec) * time.Second
	}
	return cdrDefaultTimeout
}

// cdrEffectivePerFileDeadline reports the deadline implied by the currently
// PUBLISHED config. It is the fallback for a breaker built outside a config
// apply (a test, or a zero-value cdrBreakerConfig); see the ordering warning on
// cdrConfigPerFileDeadline before using it anywhere else.
func cdrEffectivePerFileDeadline() time.Duration {
	return cdrConfigPerFileDeadline(cdrActiveConfig())
}

// cdrCircuitBreaker tracks one instance's health.  The pool owns one
// breaker per enrolled Sluice.
type cdrCircuitBreaker struct {
	cfg cdrBreakerConfig

	state         atomic.Int32
	openedAt      atomic.Int64 // UnixNano when state transitioned to open
	consecFails   atomic.Int64
	halfOpenTried atomic.Int32 // probes currently being served in half-open
	halfOpenAt    atomic.Int64 // UnixNano when the current half-open budget was armed; doubles as its generation
	// halfOpenLastAt is UnixNano of the most recent reservation taken from the
	// current budget (or of the arm, before any). The wedge escape measures
	// staleness from HERE, not from halfOpenAt: once Release can hand a slot
	// back, one budget can host several sequential reservations, and measuring
	// from the arm time would reclaim a probe taken moments ago.
	halfOpenLastAt atomic.Int64
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

// cdrProbeReservation identifies a half-open probe slot handed out by
// Reserve, so Release can return exactly that slot. gen is the halfOpenAt
// value of the budget the slot came from; zero means "no half-open slot was
// taken" (closed state), and Release of it is a no-op.
type cdrProbeReservation struct {
	gen int64
}

// Allow reports whether the caller should proceed with a request.  Also
// advances the state machine when the open→half-open timer has elapsed,
// and enforces the half-open probe budget.
//
// A caller that may return WITHOUT recording an outcome must use Reserve and
// Release instead, or it strands the half-open slot it was given.
func (b *cdrCircuitBreaker) Allow() bool {
	ok, _ := b.Reserve()
	return ok
}

// Reserve is Allow plus the identity of the half-open slot it handed out, so
// a caller that ends up NOT issuing the RPC (an oversize file, a cache hit, a
// client-side refusal, a panic) can give the slot back with Release instead of
// abandoning it. Only a slot that is released or reported on lets the breaker
// leave half-open on the next real call.
func (b *cdrCircuitBreaker) Reserve() (bool, cdrProbeReservation) {
	switch b.state.Load() {
	case cbStateClosed:
		return true, cdrProbeReservation{}
	case cbStateOpen:
		// Check if the reset timeout has elapsed.
		elapsed := b.now().UnixNano() - b.openedAt.Load()
		if elapsed < int64(b.cfg.ResetTimeout) {
			b.totalTrips.Add(1)
			return false, cdrProbeReservation{}
		}
		// Try to transition to half-open (racy with other goroutines; CAS
		// makes exactly one succeed).
		if b.state.CompareAndSwap(cbStateOpen, cbStateHalfOpen) {
			now := b.now().UnixNano()
			b.halfOpenTried.Store(0)
			b.halfOpenLastAt.Store(now)
			b.halfOpenAt.Store(now)
		}
		// Fall through to half-open handling below.
		fallthrough
	case cbStateHalfOpen:
		return b.reserveHalfOpen()
	default:
		return true, cdrProbeReservation{}
	}
}

// reserveHalfOpen takes one slot of the half-open budget, or re-arms an
// abandoned budget (the wedge escape). Split from Reserve to keep both under
// the cyclomatic threshold.
func (b *cdrCircuitBreaker) reserveHalfOpen() (bool, cdrProbeReservation) {
	// Budget: only N concurrent probes. Acquired with a CAS loop, NOT by
	// optimistically incrementing and undoing on denial: a denied caller's
	// Add(-1) could land after the wedge-escape re-arm below reset the
	// counter, driving it to 0 (or, under a burst, negative) while a
	// replacement probe was in flight. That silently defeated the budget
	// and let a recovering Sluice be flooded. A denied caller must leave
	// the counter untouched.
	for {
		gen := b.halfOpenAt.Load()
		if gen == 0 {
			// Not half-open any more (an outcome or Reset landed), or the
			// open->half-open arm is mid-publish. Never hand out a slot
			// under generation 0: Release could not return it.
			if b.state.Load() != cbStateHalfOpen {
				return b.Reserve()
			}
			continue
		}
		tried := b.halfOpenTried.Load()
		if tried < b.cfg.HalfOpenProbes {
			if b.halfOpenTried.CompareAndSwap(tried, tried+1) {
				b.halfOpenLastAt.Store(b.now().UnixNano())
				return true, cdrProbeReservation{gen: gen}
			}
			continue // lost the race; re-read the budget
		}
		// Wedge escape. A reservation is released only by
		// OnSuccess/OnFailure/Reset, and half-open has no other timer, so a
		// caller that takes one and never records an outcome would otherwise
		// deny every later Allow() for the rest of the process lifetime. If
		// the budget has gone that long without an outcome, treat the
		// reservation as abandoned, re-arm, and admit one fresh probe so the
		// breaker can still find its way back to closed. Staleness is
		// measured from the NEWEST reservation (halfOpenLastAt), so every
		// outstanding one is at least HalfOpenProbeTimeout old. The CAS on
		// halfOpenAt elects exactly one re-armer and starts a new
		// generation, so a late Release from the reclaimed budget is a
		// no-op; HalfOpenProbeTimeout is derived to exceed any legitimate
		// probe, so this cannot preempt one that is merely slow.
		armed := b.halfOpenAt.Load()
		now := b.now().UnixNano()
		if armed != 0 && now-b.halfOpenLastAt.Load() >= int64(b.cfg.HalfOpenProbeTimeout) &&
			b.halfOpenAt.CompareAndSwap(armed, now) {
			b.staleProbes.Add(1)
			b.halfOpenLastAt.Store(now)
			// Reclaim the abandoned reservation(s): exactly this probe is
			// outstanding. Safe as a Store only because denied callers never
			// touch the counter.
			b.halfOpenTried.Store(1)
			return true, cdrProbeReservation{gen: now}
		}
		b.totalTrips.Add(1)
		return false, cdrProbeReservation{}
	}
}

// Release returns a half-open slot taken by Reserve WITHOUT counting a
// success or a failure. Call it on every path that took a reservation and
// then did not issue the RPC; a deferred call is safe on the RPC paths too,
// because OnSuccess/OnFailure leave half-open (halfOpenAt reset to 0), which
// makes a later Release of that reservation a no-op.
//
// It is a no-op for a closed-state reservation (gen 0), after the breaker has
// left half-open, and after the budget was re-armed by the wedge escape (new
// generation) — in each case the slot is already gone. The one window it does
// not close is a re-arm landing between the generation check and the
// decrement; that requires the releasing holder to be older than
// HalfOpenProbeTimeout, i.e. already reclaimable, and the worst case is one
// extra concurrent probe.
func (b *cdrCircuitBreaker) Release(r cdrProbeReservation) {
	if r.gen == 0 || b.state.Load() != cbStateHalfOpen || b.halfOpenAt.Load() != r.gen {
		return
	}
	for {
		tried := b.halfOpenTried.Load()
		if tried <= 0 {
			return
		}
		if b.halfOpenTried.CompareAndSwap(tried, tried-1) {
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
		return armed != 0 && b.now().UnixNano()-b.halfOpenLastAt.Load() >= int64(b.cfg.HalfOpenProbeTimeout)
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
