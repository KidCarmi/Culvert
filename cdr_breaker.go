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
// Every outcome carries the reservation it was earned under, so a probe the
// wedge escape reclaimed (or a request admitted before the breaker opened)
// cannot decide a half-open episode it is not the probe of.  All timers run on
// a monotonic clock.
//
// Thread-safe.  Every state transition runs under one per-breaker mutex
// (see the concurrency contract on cdrCircuitBreaker); the critical sections
// are a few loads and stores and never span the RPC.
//
// What counts as a failure is the POLICY of the caller (cdr_pool.go /
// cdr_proxy.go), not the breaker.  Breaker only tracks Allow()/Result
// transitions — orthogonal to transport vs. app errors.

import (
	"math"
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
	// WEDGE ESCAPE, not a concurrency control: Reserve() hands out a reservation
	// that only OnSuccess/OnFailure/Release/Reset return, and half-open has no other
	// timer, so a single caller that takes a reservation and never records an
	// outcome used to strand the breaker in half-open for the whole process
	// lifetime — every later Reserve() denied, CDR silently skipped on every
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
//
// The arithmetic saturates (cdrSaturatingAdd): a plain perFile+grace wrapped
// negative for a deadline near the Duration maximum, and the result then fell
// to the 90s floor — centuries short of the deadline it must exceed.
func cdrHalfOpenProbeTimeout(reset, perFile time.Duration) time.Duration {
	d := cdrSaturatingAdd(reset, reset)
	if overDeadline := cdrSaturatingAdd(perFile, cdrHalfOpenProbeGrace); overDeadline > d {
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
		return cdrTimeoutSecDuration(cfg.TimeoutSec)
	}
	return cdrDefaultTimeout
}

// cdrMaxDuration is the largest representable time.Duration (~292 years).
const cdrMaxDuration = time.Duration(math.MaxInt64)

// cdrTimeoutSecDuration converts a positive cdr.timeout_sec to a Duration,
// saturating at cdrMaxDuration. validCDRTimeoutSec bounds the setting below
// (30s) but not above, and time.Duration(secs)*time.Second wraps for
// secs > 9223372036 — to a negative or arbitrary value, which would expire the
// RPC deadline immediately and collapse the probe timeout to its floor. Every
// conversion of the setting (client deadline, call context, breaker seed)
// goes through here so they agree.
func cdrTimeoutSecDuration(secs int) time.Duration {
	if int64(secs) > int64(cdrMaxDuration/time.Second) {
		return cdrMaxDuration
	}
	return time.Duration(secs) * time.Second
}

// cdrSaturatingAdd returns a+b clamped to cdrMaxDuration instead of wrapping.
// Both operands are non-negative at every call site.
func cdrSaturatingAdd(a, b time.Duration) time.Duration {
	if b > 0 && a > cdrMaxDuration-b {
		return cdrMaxDuration
	}
	return a + b
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
//
// ── Concurrency contract: ONE mutex owns every state transition ─────────────
//
// state, openedAt, the half-open generation, the newest-reservation stamp and
// the probe budget are COUPLED: a transition must publish them together, and a
// reader deciding on one must see the others as of the same instant. An
// earlier revision published them as independent atomics and every fix opened
// another interleaving (PR #1611 review): a failed probe's cleanup zeroing the
// generation of a half-open episode a concurrent caller had just armed (state
// half-open with no generation, so every later reserver spun), two re-armers
// both admitted because the generation was published before the stamp and the
// budget, and a denied caller's decrement clobbering a re-arm.
//
// So mu guards ALL of it, and every method that reads or writes more than one
// of those fields holds it for its whole decision. The critical sections are a
// handful of loads and stores and never span I/O — in particular, mu is never
// held across the Sanitize RPC: Reserve returns before the call, and the
// outcome is recorded after it. The cost is irrelevant at this call rate (one
// Reserve and one outcome per inspected document, against a sanitize RPC
// measured in milliseconds), and in exchange each transition is one atomic
// step that can be reasoned about sequentially.
//
// The fields stay atomic types so Stats, State and the tests can read a single
// value without the lock; they are only ever WRITTEN under mu.
type cdrCircuitBreaker struct {
	cfg cdrBreakerConfig

	mu sync.Mutex

	state atomic.Int32
	// openedAt is the WALL-clock UnixNano of the last transition to open. It
	// is for display (Stats, /api/cdr/instances) only and must never feed a
	// timer decision: see openedMono.
	openedAt atomic.Int64
	// openedMono is the same instant on the breaker's MONOTONIC clock
	// (monoNow); the ResetTimeout comparison reads only this.
	openedMono    atomic.Int64
	consecFails   atomic.Int64
	halfOpenTried atomic.Int32 // probes currently being served in half-open
	// halfOpenGen identifies the current half-open budget. It is bumped on
	// every arm (open -> half-open), every stale re-arm, and every exit from
	// half-open, so a reservation from an earlier budget can never be released
	// into a later one. It is never 0 while state is half-open.
	halfOpenGen atomic.Int64
	// halfOpenLastAt is the monotonic stamp (monoNow) of the newest
	// reservation taken from the current budget (or of the arm, before any).
	// The wedge escape measures staleness from HERE, not from the arm: once
	// Release can hand a slot back, one budget hosts several sequential
	// reservations, and measuring from the arm time would reclaim a probe
	// taken moments ago.
	halfOpenLastAt atomic.Int64
	// staleProbes counts half-open budgets re-armed because a reserved probe
	// never reported an outcome. Non-zero means some caller is taking a
	// reservation it cannot release — surfaced in Stats for exactly that.
	staleProbes atomic.Int64
	// staleOutcomes counts outcomes dropped because their reservation was
	// superseded (see outcomeIsCurrentLocked) — typically the late report of
	// a probe the wedge escape reclaimed.
	staleOutcomes atomic.Int64
	// episode identifies the breaker's current state episode. It advances on
	// EVERY state transition (closed->open, open->half-open, half-open->closed
	// or open, Reset), only through setStateLocked, and starts at 1, so it is
	// never 0. Every reservation records the episode it was admitted under,
	// and an outcome counts only for that same episode: a closed-state RPC
	// still in flight when the breaker tripped and then recovered cannot feed
	// its failure into the NEW closed episode's threshold.
	episode atomic.Int64

	// totalOpens counts state transitions into open for observability.
	totalOpens atomic.Int64
	totalTrips atomic.Int64 // Reserve denials while open / budget exhausted

	// Two injectable clocks (tests only swap them):
	//
	//   nowFn  — the WALL clock; it only stamps openedAt for display.
	//   monoFn — MONOTONIC elapsed time; every timer decision (ResetTimeout,
	//            HalfOpenProbeTimeout) reads only this.
	//
	// They are separate because a probe's own deadline runs on Go's monotonic
	// clock (context.WithTimeout). Measuring probe age as a difference of
	// UnixNano wall readings let a forward wall-clock step (NTP correction,
	// VM resume) of HalfOpenProbeTimeout declare a still-live probe stale and
	// admit a replacement (PR #1611 review); a backward step could equally
	// hold an open breaker open, or a wedged budget wedged, for the size of
	// the step.
	nowMu  sync.RWMutex
	nowFn  func() time.Time
	monoFn func() time.Duration
}

// newCDRCircuitBreaker returns a breaker initialised in the closed state.
func newCDRCircuitBreaker(cfg cdrBreakerConfig) *cdrCircuitBreaker {
	b := &cdrCircuitBreaker{cfg: cfg.withDefaults()}
	b.state.Store(cbStateClosed)
	b.episode.Store(1)
	b.nowFn = time.Now
	epoch := time.Now() // carries a monotonic reading
	b.monoFn = func() time.Duration { return time.Since(epoch) }
	return b
}

// now returns the injectable wall-clock time (display stamps only).
func (b *cdrCircuitBreaker) now() time.Time {
	b.nowMu.RLock()
	fn := b.nowFn
	b.nowMu.RUnlock()
	return fn()
}

// monoNow returns the breaker's monotonic clock reading in nanoseconds. Only
// differences of two monoNow readings are meaningful.
func (b *cdrCircuitBreaker) monoNow() int64 {
	b.nowMu.RLock()
	fn := b.monoFn
	b.nowMu.RUnlock()
	return int64(fn())
}

// cdrBreakerTestClockRef anchors setNowFn's derived monotonic clock. Any fixed
// instant works, since only differences are compared.
var cdrBreakerTestClockRef = time.Unix(0, 0)

// setNowFn swaps in ONE test clock that drives both the wall and the
// monotonic clock, so advancing it simulates real elapsed time (tests only).
// To step the wall clock independently of elapsed time, use setClocks.
func (b *cdrCircuitBreaker) setNowFn(fn func() time.Time) {
	b.setClocks(fn, func() time.Duration { return fn().Sub(cdrBreakerTestClockRef) })
}

// setClocks swaps the wall and monotonic clocks independently (tests only).
func (b *cdrCircuitBreaker) setClocks(wall func() time.Time, mono func() time.Duration) {
	b.nowMu.Lock()
	b.nowFn = wall
	b.monoFn = mono
	b.nowMu.Unlock()
}

// State reports the current state.  Lock-free single read.
func (b *cdrCircuitBreaker) State() int32 {
	return b.state.Load()
}

// cdrProbeReservation identifies a half-open probe slot handed out by
// Reserve, so Release can return exactly that slot and an outcome can be
// attributed to exactly the episode it was taken in. ep is the state episode
// it was admitted under (never 0 for a real reservation, so the zero value
// matches no episode). gen is the half-open budget the slot came from; zero
// means "no half-open slot was taken" (closed state), and Release of it is a
// no-op.
type cdrProbeReservation struct {
	ep  int64
	gen int64
}

// Allow is Reserve without the reservation handle.
//
// It CONSUMES a half-open probe and drops the means to return it, so it is for
// the breaker's own unit tests only. Production code reserves through
// cdrPickPooledReserved (the sanitize RPC path, which releases or records every
// reservation) and asks "is it up?" through Available. Pinned by
// TestCDRBreaker_ReservingCallsOnlyOnTheSanitizePath.
func (b *cdrCircuitBreaker) Allow() bool {
	ok, _ := b.Reserve()
	return ok
}

// Reserve reports whether the caller may issue an RPC to this instance and,
// in half-open, hands out one slot of the probe budget. The caller OWNS the
// returned reservation: it must either record an outcome (OnSuccess /
// OnFailure) or hand it back with Release. Only the sanitize RPC path may call
// it (see Allow).
func (b *cdrCircuitBreaker) Reserve() (bool, cdrProbeReservation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.monoNow()
	switch b.state.Load() {
	case cbStateClosed:
		return true, cdrProbeReservation{ep: b.episode.Load()}
	case cbStateOpen:
		if now-b.openedMono.Load() < int64(b.cfg.ResetTimeout) {
			b.totalTrips.Add(1)
			return false, cdrProbeReservation{}
		}
		b.armHalfOpenLocked(now)
		return b.reserveHalfOpenLocked(now)
	case cbStateHalfOpen:
		return b.reserveHalfOpenLocked(now)
	default:
		return true, cdrProbeReservation{ep: b.episode.Load()}
	}
}

// armHalfOpenLocked starts a fresh half-open budget. Caller holds mu.
func (b *cdrCircuitBreaker) armHalfOpenLocked(now int64) {
	b.halfOpenTried.Store(0)
	b.halfOpenGen.Add(1)
	b.halfOpenLastAt.Store(now)
	b.setStateLocked(cbStateHalfOpen)
}

// setStateLocked publishes a state transition and starts a new episode, which
// retires every reservation admitted under the previous one. It is the ONLY
// writer of state after construction. Caller holds mu.
func (b *cdrCircuitBreaker) setStateLocked(s int32) {
	b.episode.Add(1)
	b.state.Store(s)
}

// reserveHalfOpenLocked takes one slot of the current budget, or re-arms an
// abandoned one (the wedge escape). Caller holds mu.
//
// Wedge escape: a reservation is released only by an outcome or Release, and
// half-open has no other timer, so a caller that takes one and never reports
// would otherwise deny every later Reserve for the rest of the process
// lifetime. If the NEWEST reservation is older than HalfOpenProbeTimeout,
// every outstanding one is, and HalfOpenProbeTimeout is derived to exceed any
// legitimate probe — so they are abandoned: start a new generation (a late
// Release from the old one is then a no-op) and admit exactly one probe.
func (b *cdrCircuitBreaker) reserveHalfOpenLocked(now int64) (bool, cdrProbeReservation) {
	if b.halfOpenTried.Load() < b.cfg.HalfOpenProbes {
		b.halfOpenTried.Add(1)
		b.halfOpenLastAt.Store(now)
		return true, cdrProbeReservation{ep: b.episode.Load(), gen: b.halfOpenGen.Load()}
	}
	if now-b.halfOpenLastAt.Load() >= int64(b.cfg.HalfOpenProbeTimeout) {
		b.staleProbes.Add(1)
		b.halfOpenGen.Add(1)
		b.halfOpenTried.Store(1)
		b.halfOpenLastAt.Store(now)
		return true, cdrProbeReservation{ep: b.episode.Load(), gen: b.halfOpenGen.Load()}
	}
	b.totalTrips.Add(1)
	return false, cdrProbeReservation{}
}

// Release returns a half-open slot taken by Reserve WITHOUT counting a
// success or a failure. Call it on every path that took a reservation and
// then did not issue the RPC. A deferred Release is also safe on the paths
// that did record an outcome: an outcome leaves half-open and bumps the
// generation, so the later Release no longer matches and does nothing.
//
// It is a no-op for a closed-state reservation (gen 0), after the breaker has
// left half-open, and after the budget was re-armed by the wedge escape — in
// each case the slot is already gone. Because the generation check and the
// decrement happen under mu, a release can never free a slot of a budget
// other than the one it was taken from.
func (b *cdrCircuitBreaker) Release(r cdrProbeReservation) {
	if r.gen == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Load() != cbStateHalfOpen || b.halfOpenGen.Load() != r.gen {
		return
	}
	if b.halfOpenTried.Load() > 0 {
		b.halfOpenTried.Add(-1)
	}
}

// outcomeIsCurrentLocked reports whether an outcome recorded against r still
// belongs to the breaker's current episode. Caller holds mu.
//
//   - The reservation must have been admitted under the CURRENT episode.
//     Every state transition starts a new one, so a report from any earlier
//     episode is superseded: a closed-state RPC still in flight when the
//     breaker tripped, recovered and closed again used to count its late
//     failure toward the NEW closed episode's threshold (FailureThreshold of
//     them reopened a just-recovered breaker — fail-open by default), and a
//     pre-open request's late report used to decide a half-open episode it
//     was not the probe of.
//   - In half-open, the reservation must also come from the CURRENT probe
//     budget. The wedge escape re-arms the budget without a state change; a
//     reclaimed probe's late failure used to reopen the breaker under its
//     replacement, and its late success closed it past the probe budget.
//
// Dropped outcomes are counted in staleOutcomes and change no counter.
func (b *cdrCircuitBreaker) outcomeIsCurrentLocked(r cdrProbeReservation) bool {
	current := r.ep == b.episode.Load()
	if current && b.state.Load() == cbStateHalfOpen {
		current = r.gen != 0 && r.gen == b.halfOpenGen.Load()
	}
	if !current {
		b.staleOutcomes.Add(1)
	}
	return current
}

// OnSuccess records a successful call made under reservation r.  In closed
// state, resets the failure counter.  In half-open state, transitions back to
// closed.  A superseded reservation's outcome is dropped
// (outcomeIsCurrentLocked).
func (b *cdrCircuitBreaker) OnSuccess(r cdrProbeReservation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.outcomeIsCurrentLocked(r) {
		return
	}
	b.consecFails.Store(0)
	if b.state.Load() == cbStateHalfOpen {
		b.leaveHalfOpenLocked()
		b.setStateLocked(cbStateClosed)
	}
}

// OnFailure records a failure of a call made under reservation r.  In closed
// state, may trip the breaker.  In half-open state, returns straight to open
// with a fresh timer.  A superseded reservation's outcome is dropped
// (outcomeIsCurrentLocked).
func (b *cdrCircuitBreaker) OnFailure(r cdrProbeReservation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.outcomeIsCurrentLocked(r) {
		return
	}
	switch b.state.Load() {
	case cbStateClosed:
		if b.consecFails.Add(1) >= int64(b.cfg.FailureThreshold) {
			b.openLocked()
		}
	case cbStateHalfOpen:
		// Single failure in half-open → back to open.
		b.leaveHalfOpenLocked()
		b.openLocked()
	case cbStateOpen:
		// Already open — nothing to do.
	}
}

// leaveHalfOpenLocked retires the current half-open budget. The generation
// bump is what turns every still-outstanding reservation's Release into a
// no-op. Caller holds mu and then publishes the new state.
func (b *cdrCircuitBreaker) leaveHalfOpenLocked() {
	b.halfOpenTried.Store(0)
	b.halfOpenGen.Add(1)
	b.halfOpenLastAt.Store(0)
}

// openLocked publishes the open state with a fresh reset timer. The stamps are
// written before the state so a lock-free State() reader that sees open also
// has its timer (Reserve itself reads both under mu). Caller holds mu.
func (b *cdrCircuitBreaker) openLocked() {
	b.openedMono.Store(b.monoNow())
	b.openedAt.Store(b.now().UnixNano())
	b.totalOpens.Add(1)
	b.setStateLocked(cbStateOpen)
}

// Reset forces the breaker back to closed (admin override).
func (b *cdrCircuitBreaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Load() == cbStateHalfOpen {
		b.leaveHalfOpenLocked()
	}
	b.setStateLocked(cbStateClosed)
	b.consecFails.Store(0)
	b.halfOpenTried.Store(0)
	b.openedAt.Store(0)
	b.openedMono.Store(0)
}

// Available reports whether Reserve would currently admit a request, WITHOUT
// consuming a half-open probe reservation or advancing the state machine.
//
// Every liveness, status, UI and diagnostic caller must use this, never
// Reserve/Allow: a reservation taken by a caller that issues no sanitize RPC
// can never be reported on, and the probe it held is exactly the one the next
// real document needed — under the default fail-OPEN FailMode, that document
// is then forwarded unsanitized.
func (b *cdrCircuitBreaker) Available() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.monoNow()
	switch b.state.Load() {
	case cbStateClosed:
		return true
	case cbStateOpen:
		return now-b.openedMono.Load() >= int64(b.cfg.ResetTimeout)
	case cbStateHalfOpen:
		if b.halfOpenTried.Load() < b.cfg.HalfOpenProbes {
			return true
		}
		return now-b.halfOpenLastAt.Load() >= int64(b.cfg.HalfOpenProbeTimeout)
	default:
		return true
	}
}

// Stats returns a snapshot suitable for /api/cdr/instances exposure.
type cdrBreakerStats struct {
	State       string `json:"state"` // "closed" | "open" | "half_open"
	ConsecFails int64  `json:"consecFails"`
	TotalOpens  int64  `json:"totalOpens"` // total transitions into open
	TotalTrips  int64  `json:"totalTrips"` // Reserve denials (open, or half-open budget exhausted)
	OpenedAt    int64  `json:"openedAt"`   // UnixNano; 0 if never opened
	// StaleProbes counts half-open budgets re-armed after a reserved probe
	// never reported an outcome. Any non-zero value is a bug signal: some
	// caller is taking a reservation it cannot release.
	StaleProbes int64 `json:"staleProbes"`
	// StaleOutcomes counts outcomes dropped because their reservation was
	// superseded — the late report of a reclaimed probe, or of a request
	// admitted before the breaker opened.
	StaleOutcomes int64 `json:"staleOutcomes"`
}

// Stats returns a snapshot of current breaker state. Each field is a single
// lock-free read, so the snapshot as a whole is advisory (observability only).
func (b *cdrCircuitBreaker) Stats() cdrBreakerStats {
	return cdrBreakerStats{
		State:         breakerStateName(b.state.Load()),
		ConsecFails:   b.consecFails.Load(),
		TotalOpens:    b.totalOpens.Load(),
		TotalTrips:    b.totalTrips.Load(),
		OpenedAt:      b.openedAt.Load(),
		StaleProbes:   b.staleProbes.Load(),
		StaleOutcomes: b.staleOutcomes.Load(),
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
