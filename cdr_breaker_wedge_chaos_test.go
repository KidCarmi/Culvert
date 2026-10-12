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
		b.OnFailure()
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
	for i := 0; i < 3; i++ {
		advance(b.cfg.HalfOpenProbeTimeout + time.Second)
		if !b.Allow() {
			t.Fatalf("round %d: breaker stopped re-arming abandoned probes", i)
		}
	}
	// A real outcome still closes it.
	b.OnSuccess()
	if b.State() != cbStateClosed {
		t.Fatalf("state = %s after OnSuccess, want closed", breakerStateName(b.State()))
	}
	if !b.Allow() {
		t.Fatal("a closed breaker must admit requests")
	}
}

// TestCDRBreaker_ProbeTimeoutExceedsPerFileDeadline guards the one way the
// wedge escape could do harm: preempting a legitimate probe that is merely
// slow. The per-file Sluice deadline is cdrDefaultTimeout, so the escape must
// be comfortably longer — including when ResetTimeout is tuned very low.
func TestCDRBreaker_ProbeTimeoutExceedsPerFileDeadline(t *testing.T) {
	for _, reset := range []time.Duration{0, time.Second, 5 * time.Second, 30 * time.Second, 10 * time.Minute} {
		cfg := cdrBreakerConfig{ResetTimeout: reset}.withDefaults()
		if cfg.HalfOpenProbeTimeout <= cdrDefaultTimeout {
			t.Errorf("ResetTimeout=%s → HalfOpenProbeTimeout=%s, must exceed the "+
				"%s per-file deadline or it can preempt a live probe",
				reset, cfg.HalfOpenProbeTimeout, cdrDefaultTimeout)
		}
	}
	// A slow-but-live probe must NOT be preempted.
	b, advance := wedgeBreaker(t, cdrBreakerConfig{})
	tripOpen(t, b)
	advance(b.cfg.ResetTimeout + time.Second)
	if !b.Allow() {
		t.Fatal("recovery probe denied")
	}
	advance(cdrDefaultTimeout) // the slowest legitimate per-file call
	if b.Allow() {
		t.Fatal("the budget was re-armed while a legitimate probe could still " +
			"be in flight — HalfOpenProbeTimeout is too short")
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
	b.OnSuccess() // release the reservation Pick() just took

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
	if got := cdrPickPooled(); got == nil {
		t.Fatal("cdrPickPooled() == nil right after the gate said CDR was usable: " +
			"the recovery probe was consumed by the gate, so every file would " +
			"silently skip sanitization")
	}
	b.OnSuccess()
	if b.State() != cbStateClosed {
		t.Fatalf("state = %s after a successful probe, want closed", breakerStateName(b.State()))
	}
}
