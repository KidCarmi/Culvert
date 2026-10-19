package main

// cdr_breaker_wedge_chaos_test.go — CHAOS-72 gates: chaos coverage for the CDR circuit
// breaker's recovery path (cdr_breaker.go) and the hot-path liveness gate
// (cdr_proxy.go runCDRStage / cdr_pool.go).
//
// The failure mode pinned here is a PERMANENT half-open wedge that silently
// disables content sanitization. Allow() hands out a half-open probe
// reservation that is released only by OnSuccess, OnFailure or Reset, and the
// half-open branch had no timer of its own — the ResetTimeout re-check lives
// only under cbStateOpen. So one caller that took a reservation and never
// recorded an outcome denied every later Allow() for the whole process
// lifetime. Reset() has no production caller, and cdrClientPool.replace
// deliberately carries breaker state across pool rebuilds, so nothing cleared
// it short of a restart.
//
// runCDRStage guaranteed exactly that unpaired Allow() on the first inspected
// upload after ResetTimeout elapsed: its liveness gate went through
// cdrActiveClient() -> Pick() -> Allow(), which issues no RPC and so can never
// report an outcome, and safeCDRSanitize's own Pick() was then denied and took
// the "skip CDR" branch. With FailMode defaulting to fail-OPEN
// (config.go cdrFailOpen), the result was every document forwarded
// UNSANITIZED, indefinitely, signalled only by a breaker_state gauge.
//
// Two independent guarantees are tested: the breaker self-heals from an
// abandoned reservation (HalfOpenProbeTimeout), and the hot path no longer
// creates one (Available / cdrAnyInstanceAvailable).

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// wedgeBreaker returns a breaker driven by a caller-advanced clock, plus the
// function that advances it.
func wedgeBreaker(t *testing.T, cfg cdrBreakerConfig) (breaker *cdrCircuitBreaker, advance func(time.Duration)) {
	t.Helper()
	b := newCDRCircuitBreaker(cfg)
	now := time.Now()
	b.setNowFn(func() time.Time { return now })
	return b, func(d time.Duration) { now = now.Add(d) }
}

// tripOpen drives the breaker closed→open.
func tripOpen(t *testing.T, b *cdrCircuitBreaker) {
	t.Helper()
	for i := 0; i < b.cfg.FailureThreshold; i++ {
		b.OnFailure(cdrReserveForTest(b))
	}
	if b.State() != cbStateOpen {
		t.Fatalf("breaker state = %s after %d failures, want open",
			breakerStateName(b.State()), b.cfg.FailureThreshold)
	}
}

// TestCDRBreaker_AbandonedProbeDoesNotWedgeHalfOpenForever is the core
// regression. A reservation taken and never released must not deny every
// later request for the process lifetime.
func TestCDRBreaker_AbandonedProbeDoesNotWedgeHalfOpenForever(t *testing.T) {
	b, advance := wedgeBreaker(t, cdrBreakerConfig{})
	tripOpen(t, b)

	advance(b.cfg.ResetTimeout + time.Second)
	// An unpaired Allow(): takes the probe, records no outcome. This is what
	// the hot path's liveness nil-check used to do.
	if !b.Allow() {
		t.Fatal("first Allow() past ResetTimeout must admit the recovery probe")
	}
	if b.State() != cbStateHalfOpen {
		t.Fatalf("state = %s, want half_open", breakerStateName(b.State()))
	}
	// While a probe could still legitimately be in flight, the budget holds.
	if b.Allow() {
		t.Fatal("a second concurrent probe must be denied while the budget is live")
	}

	// Once the reservation is older than HalfOpenProbeTimeout it is abandoned,
	// and the breaker must admit a fresh probe instead of denying forever.
	advance(b.cfg.HalfOpenProbeTimeout + time.Second)
	if !b.Allow() {
		t.Fatal("breaker is wedged: an abandoned half-open reservation still " +
			"denies every request, so CDR can never recover without a restart")
	}
	if got := b.Stats().StaleProbes; got != 1 {
		t.Fatalf("Stats().StaleProbes = %d, want 1 — an abandoned reservation "+
			"must be visible to an operator", got)
	}

	// And it must keep recovering, not heal exactly once.
	var probe cdrProbeReservation
	for i := 0; i < 3; i++ {
		advance(b.cfg.HalfOpenProbeTimeout + time.Second)
		var ok bool
		if ok, probe = b.Reserve(); !ok {
			t.Fatalf("round %d: breaker stopped re-arming abandoned probes", i)
		}
	}
	// A real outcome from the current probe still closes it.
	b.OnSuccess(probe)
	if b.State() != cbStateClosed {
		t.Fatalf("state = %s after OnSuccess, want closed", breakerStateName(b.State()))
	}
	if !b.Allow() {
		t.Fatal("a closed breaker must admit requests")
	}
}

// TestCDRBreaker_ProbeTimeoutExceedsPerFileDeadline guards the one way the
// wedge escape can do harm: preempting a probe that is merely slow. The
// preempted call's late OnFailure can reopen the breaker after the replacement
// probe already succeeded, which is another fail-open bypass window.
//
// The deadline is operator-controlled and effectively unbounded above:
// validCDRTimeoutSec rejects cdr.timeout_sec below 30s but imposes NO upper
// bound, so a deployment may legitimately run 5- or 10-minute per-file
// deadlines. Deriving the escape from ResetTimeout alone (a flat 90s floor)
// preempted a live probe on every such deployment.
func TestCDRBreaker_ProbeTimeoutExceedsPerFileDeadline(t *testing.T) {
	resets := []time.Duration{0, time.Second, 5 * time.Second, 30 * time.Second, 10 * time.Minute}
	// Includes values validCDRTimeoutSec accepts well above the 90s floor.
	deadlines := []time.Duration{
		0, 30 * time.Second, cdrDefaultTimeout, 90 * time.Second,
		2 * time.Minute, 5 * time.Minute, time.Hour,
	}
	for _, reset := range resets {
		for _, deadline := range deadlines {
			cfg := cdrBreakerConfig{ResetTimeout: reset, PerFileDeadline: deadline}.withDefaults()
			if cfg.HalfOpenProbeTimeout <= cfg.PerFileDeadline {
				t.Errorf("ResetTimeout=%s deadline=%s -> HalfOpenProbeTimeout=%s, must exceed "+
					"the effective per-file deadline %s or it preempts a live probe",
					reset, deadline, cfg.HalfOpenProbeTimeout, cfg.PerFileDeadline)
			}
			if cfg.HalfOpenProbeTimeout < cdrHalfOpenProbeTimeoutFloor {
				t.Errorf("ResetTimeout=%s deadline=%s -> HalfOpenProbeTimeout=%s, below the %s floor",
					reset, deadline, cfg.HalfOpenProbeTimeout, cdrHalfOpenProbeTimeoutFloor)
			}
		}
	}

	// A probe running right up to a long configured deadline must NOT be
	// preempted. With a 10-minute deadline the old flat 90s escape fired first.
	const longDeadline = 10 * time.Minute
	b, advance := wedgeBreaker(t, cdrBreakerConfig{PerFileDeadline: longDeadline})
	tripOpen(t, b)
	advance(b.cfg.ResetTimeout + time.Second)
	if !b.Allow() {
		t.Fatal("recovery probe denied")
	}
	advance(longDeadline) // the slowest legitimate per-file call
	if b.Allow() {
		t.Fatalf("the budget was re-armed after %s while a probe under a %s deadline "+
			"could still be in flight", longDeadline, longDeadline)
	}
	// Past the deadline plus its grace, it is genuinely abandoned.
	advance(cdrHalfOpenProbeGrace + time.Second)
	if !b.Allow() {
		t.Fatal("a probe abandoned past deadline+grace must still be reclaimed")
	}
}

// TestCDRBreaker_DeadlineSeededFromAppliedConfigNotActiveConfig pins the
// construction ORDERING that makes the deadline-derived probe timeout actually
// work. initCDRClient builds the pool — and therefore every breaker — BEFORE it
// publishes cdrActiveCfg:
//
//	newPool, err := buildCDRPoolFromRegistry(cfg, oldPool)   // breakers built here
//	cdrPool.replace(newPool)
//	cdrActiveCfg = cfg                                       // published only now
//
// So a breaker that resolved the deadline from the ACTIVE config at
// construction time would read the previous config — the zero value on first
// boot — and derive the 90s floor no matter what cdr.timeout_sec says, silently
// reinstating the preemption bug. Breakers must be seeded from the config being
// applied, via cdrConfigPerFileDeadline.
func TestCDRBreaker_DeadlineSeededFromAppliedConfigNotActiveConfig(t *testing.T) {
	// Simulate the init ordering: the published config is still empty (first
	// boot) while a config with a long deadline is being applied.
	cdrClientMu.Lock()
	prev := cdrActiveCfg
	cdrActiveCfg = CDRConfig{}
	cdrClientMu.Unlock()
	t.Cleanup(func() {
		cdrClientMu.Lock()
		cdrActiveCfg = prev
		cdrClientMu.Unlock()
	})

	applied := CDRConfig{Enabled: true, TimeoutSec: 600} // 10 minutes, valid config

	// The active-config fallback cannot see it — this is the trap.
	if got := cdrEffectivePerFileDeadline(); got != cdrDefaultTimeout {
		t.Fatalf("cdrEffectivePerFileDeadline() = %s during the init window, want the "+
			"%s default; the premise of this test no longer holds", got, cdrDefaultTimeout)
	}
	// The applied config must be resolved from cfg.
	wantDeadline := 600 * time.Second
	if got := cdrConfigPerFileDeadline(applied); got != wantDeadline {
		t.Fatalf("cdrConfigPerFileDeadline(TimeoutSec=600) = %s, want %s", got, wantDeadline)
	}

	// A breaker built the way the pool builds it must outlast that deadline.
	b := newCDRCircuitBreaker(cdrBreakerConfig{
		PerFileDeadline: cdrConfigPerFileDeadline(applied),
	})
	if b.cfg.HalfOpenProbeTimeout <= wantDeadline {
		t.Errorf("breaker seeded from the applied config has HalfOpenProbeTimeout=%s, "+
			"must exceed the configured %s deadline", b.cfg.HalfOpenProbeTimeout, wantDeadline)
	}

	// And the zero-value construction the pool USED to do must be shown to be
	// insufficient, so a regression back to it fails here.
	stale := newCDRCircuitBreaker(cdrBreakerConfig{})
	if stale.cfg.HalfOpenProbeTimeout > wantDeadline {
		t.Errorf("a zero-value breaker resolved %s during the init window, which would "+
			"make this test vacuous", stale.cfg.HalfOpenProbeTimeout)
	}
}

// TestCDRBreaker_BudgetSurvivesConcurrentDenials pins the half-open budget
// under a burst. The budget used to be acquired by optimistically incrementing
// and undoing on denial, so a denied caller's decrement could land AFTER the
// wedge escape re-armed the counter — driving it to 0, or negative under a
// burst, while a replacement probe was in flight. The budget then admitted
// everything and flooded a recovering Sluice. A denied caller must leave the
// counter untouched.
func TestCDRBreaker_BudgetSurvivesConcurrentDenials(t *testing.T) {
	for _, budget := range []int32{1, 2, 4} {
		b := newCDRCircuitBreaker(cdrBreakerConfig{HalfOpenProbes: budget})
		var clockMu sync.Mutex
		now := time.Now()
		b.setNowFn(func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		})
		for i := 0; i < b.cfg.FailureThreshold; i++ {
			b.OnFailure(cdrReserveForTest(b))
		}
		clockMu.Lock()
		now = now.Add(b.cfg.ResetTimeout + time.Second)
		clockMu.Unlock()

		// A burst far larger than the budget, all contending at once.
		const contenders = 64
		var wg sync.WaitGroup
		var admitted atomic.Int64
		start := make(chan struct{})
		for i := 0; i < contenders; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if b.Allow() {
					admitted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if got := admitted.Load(); got > int64(budget) {
			t.Errorf("budget %d: %d of %d contenders admitted concurrently — the "+
				"half-open limit does not hold", budget, got, contenders)
		}
		if got := b.halfOpenTried.Load(); got < 0 {
			t.Errorf("budget %d: halfOpenTried = %d, must never go negative — a "+
				"negative count admits every later request", budget, got)
		}
		if got := b.halfOpenTried.Load(); got > budget {
			t.Errorf("budget %d: halfOpenTried = %d, must never exceed the budget", budget, got)
		}
	}
}

// TestCDRBreaker_AvailableDoesNotConsumeProbe pins the non-consuming contract
// the hot-path gate depends on: a liveness check must not mutate the budget.
func TestCDRBreaker_AvailableDoesNotConsumeProbe(t *testing.T) {
	b, advance := wedgeBreaker(t, cdrBreakerConfig{})

	if !b.Available() {
		t.Fatal("a closed breaker must report available")
	}
	tripOpen(t, b)
	if b.Available() {
		t.Fatal("an open breaker inside ResetTimeout must not report available")
	}

	advance(b.cfg.ResetTimeout + time.Second)
	// Many liveness checks in a row must leave the probe budget untouched...
	for i := 0; i < 50; i++ {
		if !b.Available() {
			t.Fatalf("check %d: must report available past ResetTimeout", i)
		}
	}
	if st := b.State(); st != cbStateOpen {
		t.Fatalf("Available() advanced the state machine to %s; it must be a pure read",
			breakerStateName(st))
	}
	if n := b.halfOpenTried.Load(); n != 0 {
		t.Fatalf("Available() consumed %d probe reservations, want 0", n)
	}
	// ...so the real call still gets the probe.
	if !b.Allow() {
		t.Fatal("the recovery probe was consumed by liveness checks")
	}
}

// TestCDRHotPath_LivenessGateLeavesProbeForTheRealCall is the end-to-end
// regression on the pool gate runCDRStage uses. The old gate
// (cdrActiveClient() != nil) spent the probe; the sanitize call that followed
// was denied and silently skipped CDR.
func TestCDRHotPath_LivenessGateLeavesProbeForTheRealCall(t *testing.T) {
	cdrPoolInstallSingleForTest(&CDRClient{})
	t.Cleanup(cdrPool.shutdown)

	pc := cdrPool.Pick()
	if pc == nil {
		t.Fatal("test pool install did not yield a pooled client")
	}
	b := pc.Breaker
	now := time.Now()
	b.setNowFn(func() time.Time { return now })
	b.OnSuccess(cdrReserveForTest(b)) // closed: resets nothing; Pick() reserves nothing

	tripOpen(t, b)
	now = now.Add(b.cfg.ResetTimeout + time.Second)

	// The hot path's gate: must report CDR usable without taking the probe.
	if !cdrAnyInstanceAvailable() {
		t.Fatal("liveness gate reports CDR unusable past ResetTimeout, so the " +
			"recovery probe is never attempted")
	}
	if n := b.halfOpenTried.Load(); n != 0 {
		t.Fatalf("the liveness gate consumed %d probe reservations, want 0 — "+
			"the probe must be left for the call that can record an outcome", n)
	}
	// The real selector now gets it, and can report the outcome.
	got, probe := cdrPickPooledReserved()
	if got == nil {
		t.Fatal("cdrPickPooledReserved() == nil right after the gate said CDR was usable: " +
			"the recovery probe was consumed by the gate, so every file would " +
			"silently skip sanitization")
	}
	b.OnSuccess(probe)
	if b.State() != cbStateClosed {
		t.Fatalf("state = %s after a successful probe, want closed", breakerStateName(b.State()))
	}
}
