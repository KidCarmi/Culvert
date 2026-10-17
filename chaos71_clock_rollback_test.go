package main

// chaos71_clock_rollback_test.go — CHAOS-71: every bound that measures an
// interval from a PERSISTED or ATOMIC wall-clock stamp must survive the wall
// clock stepping BACKWARDS.
//
// A backward step is ordinary infrastructure: an NTP correction after the RTC
// came up wrong, a hypervisor resuming a snapshot, a VM migrated to a host with
// a skewed clock, an operator fixing the date. Go's monotonic reading makes
// `time.Since(t)` immune to it ONLY while t still carries that reading;
// `time.Unix(...)` and `time.UnixMilli(...)` do not, so every stamp that
// round-trips through an int64 is compared on the wall clock.
//
// The failure is always the same shape and it is never an error: the measured
// interval goes NEGATIVE, every `elapsed >= limit` test is false, and a bound
// that exists to END a degraded state never fires again until the wall clock
// catches back up — which, after a step of hours, means hours.
//
// THE WHOLE CLASS, enumerated at this revision. Seventeen interval comparisons
// in the tree are derived from an int64 stamp:
//
//	ALREADY GUARDED (8) — the controls for the class, re-checked here:
//	  internal/scanner/scanner.go     budgetRemaining      elapsed < 0 -> full budget
//	  internal/admission/engine.go    snapshot maxAge      age < 0 || age >= maxAge
//	  internal/mcp/canary/...         windowOpenLocked x2  elapsed >= 0 && ...
//	  internal/mcp/rollout/evidence.go elapsed             d < 0 -> 0
//	  store.go                        advanceLocked        diff <= 0 -> return
//	  proxy_host_bounds.go            oversize log window  d >= 0 && ...
//	  request_tracing_bounds.go       bounds log window    d >= 0 && ...
//
//	UNGUARDED, CLOSED BY THIS SWEEP (7) — every one a recovery bound or the
//	only operator signal for a degraded state:
//	  proxy_tunnel.go                 tunnel idle reaper        CK-1
//	  internal/upstream/upstream.go   parent-proxy breaker      CK-2
//	  cdr_breaker.go                  Sluice/CDR breaker        CK-3
//	  readyz_dp_health.go             DP readiness grace        CK-4
//	  roster_persist_durability.go x2 durability log gates      CK-5
//	  internal/ocsp/ocsp.go           responder-cap log gate    CK-5
//
//	UNGUARDED, DELIBERATELY LEFT (2) — CK-8, recorded with its fix shape in
//	docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-10-17.md §7:
//	  internal/mcp/canary/budget_enforce.go rate window (Reserve + the read)
//	  — fail-CLOSED under a step, and inside a reviewed budget boundary.
//
// A new bound added on an int64 stamp is not structurally stopped from
// repeating this; CK-7 records the lint/AST option and why it is not trivial.
//
// FAULT INJECTION. A backward step of Δ is observationally identical to a stamp
// Δ in the FUTURE, because the stamp was written before the step and is read
// after it. Every gate injects exactly that, so the fault is deterministic and
// needs neither a sleep nor control of the host clock.

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// clockStepBack is how far the wall clock moves backwards in these gates. One
// hour is both realistic (a DST/RTC/NTP correction) and larger than every
// window under test, which is what makes the measured interval negative.
const clockStepBack = time.Hour

// ─── CK-1: the raw-tunnel idle reaper ────────────────────────────────────────

// TestChaos71_TunnelIdleReaperSurvivesABackwardClockStep is the DEFECT gate for
// the only bound on a half-open CONNECT tunnel.
//
// idleCopyCounted re-arms a read deadline every half-window and reaps the
// tunnel when the shared activity stamp has been stale for a full window. The
// deadline is monotonic (netpoll converts it against runtimeNano), so the loop
// keeps WAKING after a backward step — it is the staleness test that stops
// being true. Pre-fix the relay re-arms forever: two goroutines, two FDs, a
// pooled relay buffer and the connection-limiter slot are pinned for the
// duration of the step on a tunnel whose peer is already gone.
func TestChaos71_TunnelIdleReaperSurvivesABackwardClockStep(t *testing.T) {
	setTunnelIdleTimeout(t, 200*time.Millisecond)

	// A half-open tunnel: both peers silent, neither closed.
	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() { clientPeer.Close(); destPeer.Close() })

	// The stamp was written before a one-hour backward step, so it now reads
	// one hour into the future.
	shared := new(atomic.Int64)
	shared.Store(time.Now().Add(clockStepBack).UnixNano())

	done := make(chan int64, 1)
	go func() { done <- idleCopyCounted(destProxy, clientProxy, clientProxy, shared) }()

	// Three windows is ample: the reaper decides at a deadline pop, one every
	// half-window.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idleCopyCounted never reaped a half-open tunnel after a backward clock step — " +
			"the only bound on a dead tunnel is wall-clock-dependent, so the FDs, goroutines and " +
			"connlimit slot stay pinned until the clock catches up")
	}
}

// TestChaos71_TunnelIdleReaperStillReapsAnOrdinaryStaleTunnel is the CONTROL
// that the guard did not replace the mechanism: an ordinary stale stamp (no
// clock step) must still reap.
func TestChaos71_TunnelIdleReaperStillReapsAnOrdinaryStaleTunnel(t *testing.T) {
	setTunnelIdleTimeout(t, 200*time.Millisecond)

	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() { clientPeer.Close(); destPeer.Close() })

	shared := new(atomic.Int64)
	shared.Store(time.Now().Add(-clockStepBack).UnixNano()) // genuinely idle for an hour

	done := make(chan int64, 1)
	go func() { done <- idleCopyCounted(destProxy, clientProxy, clientProxy, shared) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idleCopyCounted did not reap a tunnel idle for an hour")
	}
}

// TestChaos71_TunnelIdleReaperDoesNotReapAFreshTunnel is the CONTROL that the
// guard cannot become "always reap": a tunnel whose stamp is current must
// survive at least one full window.
func TestChaos71_TunnelIdleReaperDoesNotReapAFreshTunnel(t *testing.T) {
	setTunnelIdleTimeout(t, 400*time.Millisecond)

	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() { clientPeer.Close(); destPeer.Close() })

	shared := new(atomic.Int64)
	shared.Store(time.Now().UnixNano())

	done := make(chan int64, 1)
	go func() { done <- idleCopyCounted(destProxy, clientProxy, clientProxy, shared) }()

	select {
	case <-done:
		t.Fatal("idleCopyCounted reaped a tunnel whose activity stamp was current")
	case <-time.After(300 * time.Millisecond): // inside the window — must still be relaying
	}

	// Tear the relay down and JOIN it before returning. tunnelIdleTimeout is a
	// package global restored by t.Cleanup, so a relay goroutine outliving the
	// test body would read it while another test writes it.
	clientProxy.Close()
	destProxy.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idleCopyCounted did not return after both conns were closed")
	}
}

// ─── CK-3: the CDR (Sluice) circuit breaker ──────────────────────────────────

// TestChaos71_CDRBreakerRecoversAfterABackwardClockStep is the DEFECT gate for
// the open→half-open transition. The breaker's whole purpose is to re-probe a
// recovered Sluice after ResetTimeout; pre-fix a backward step pins it OPEN, so
// content-disarm stays unavailable for the duration of the step even though the
// Sluice came back.
func TestChaos71_CDRBreakerRecoversAfterABackwardClockStep(t *testing.T) {
	const reset = 50 * time.Millisecond
	b := newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: reset, HalfOpenProbes: 1})

	var clock atomic.Int64 // the injected wall clock, in unix nanos
	clock.Store(time.Now().UnixNano())
	b.setNowFn(func() time.Time { return time.Unix(0, clock.Load()) })

	b.OnFailure() // threshold 1 → open, openedAt = the pre-step clock
	if b.State() != cbStateOpen {
		t.Fatalf("breaker state = %d, want open", b.State())
	}

	// The clock steps back an hour. openedAt is now an hour in the future.
	clock.Add(-int64(clockStepBack))
	if b.Allow() {
		t.Fatal("breaker allowed a request immediately after the step — the step must not " +
			"short-circuit the reset timeout into an instant probe flood at a dependency " +
			"that may still be down")
	}

	// One full reset timeout AFTER the step must half-open the breaker.
	clock.Add(int64(reset + 10*time.Millisecond))
	if !b.Allow() {
		t.Fatal("breaker never left open after a backward clock step plus a full reset timeout — " +
			"CDR stays unavailable until the wall clock catches up")
	}
}

// TestChaos71_CDRBreakerStillHoldsOpenWithoutAClockStep is the CONTROL that the
// guard did not weaken the breaker: with a sane clock it still denies inside
// the reset timeout and still half-opens after it.
func TestChaos71_CDRBreakerStillHoldsOpenWithoutAClockStep(t *testing.T) {
	const reset = 50 * time.Millisecond
	b := newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: reset, HalfOpenProbes: 1})

	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	b.setNowFn(func() time.Time { return time.Unix(0, clock.Load()) })

	b.OnFailure()
	clock.Add(int64(reset / 2))
	if b.Allow() {
		t.Fatal("breaker allowed a request inside the reset timeout")
	}
	clock.Add(int64(reset))
	if !b.Allow() {
		t.Fatal("breaker did not half-open after the reset timeout")
	}
}

// ─── CK-4: the data-plane readiness grace ────────────────────────────────────

// TestChaos71_DPReadinessFailsWhenTheGraceCannotBeMeasured is the DEFECT gate
// for /ready's cp_poll row. The grace exists so a single missed poll does not
// eject the node; pre-fix a backward step makes the grace UNEXPIRABLE, so a
// node whose control-plane link is known dead keeps answering "ok" and a load
// balancer keeps routing production traffic to it on indefinitely stale config.
func TestChaos71_DPReadinessFailsWhenTheGraceCannotBeMeasured(t *testing.T) {
	audit.SetDPMode(true)
	t.Cleanup(func() { audit.SetDPMode(false) })

	prevFailing := dpControlPlanePollFailing.Load()
	prevSince := dpCPPollFailingSince.Load()
	t.Cleanup(func() {
		dpControlPlanePollFailing.Store(prevFailing)
		dpCPPollFailingSince.Store(prevSince)
	})

	dpControlPlanePollFailing.Store(true)
	// The transition stamp was written before a one-hour backward step.
	dpCPPollFailingSince.Store(time.Now().Add(clockStepBack).UnixNano())

	checks := map[string]*readinessCheck{}
	appendDPHealthChecks(checks)
	cp := checks["cp_poll"]
	if cp == nil {
		t.Fatal("cp_poll row missing")
	}
	if cp.Status != "fail" {
		t.Fatalf("cp_poll status = %q, want \"fail\": the grace window cannot be measured across a "+
			"backward clock step, and a node with a dead control-plane link must leave the "+
			"rotation rather than report ok until the clock catches up", cp.Status)
	}
}

// TestChaos71_DPReadinessStillHonoursTheGraceWindow is the CONTROL that the
// guard did not delete the grace: a transition that just happened is still
// inside the window and must NOT fail the probe.
func TestChaos71_DPReadinessStillHonoursTheGraceWindow(t *testing.T) {
	audit.SetDPMode(true)
	t.Cleanup(func() { audit.SetDPMode(false) })

	prevFailing := dpControlPlanePollFailing.Load()
	prevSince := dpCPPollFailingSince.Load()
	t.Cleanup(func() {
		dpControlPlanePollFailing.Store(prevFailing)
		dpCPPollFailingSince.Store(prevSince)
	})

	dpControlPlanePollFailing.Store(true)
	dpCPPollFailingSince.Store(time.Now().UnixNano())

	checks := map[string]*readinessCheck{}
	appendDPHealthChecks(checks)
	if got := checks["cp_poll"].Status; got != "ok" {
		t.Fatalf("cp_poll status = %q inside the grace window, want \"ok\"", got)
	}
}

// ─── CK-5: the roster-durability warning rate gates ──────────────────────────

// TestChaos71_RosterPersistWarningIsNotSuppressedByABackwardClockStep is the
// DEFECT gate for CHAOS-70's operator signal. The line is the ONLY notice that
// an admin credential/roster mutation applied in memory but did not reach the
// volume; pre-fix a backward step silences it for the duration of the step and
// only increments a suppressed counter nothing pages on.
func TestChaos71_RosterPersistWarningIsNotSuppressedByABackwardClockStep(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)

	rosterPersistLogLast.Store(time.Now().Add(clockStepBack).UnixNano())
	noteRosterPersistBestEffort("backup codes", errors.New("read-only file system"))

	if got := rosterPersistSuppress.Load(); got != 0 {
		t.Fatalf("rosterPersistSuppress = %d, want 0: a backward clock step suppressed the "+
			"durability warning instead of emitting it", got)
	}
}

// TestChaos71_RosterNotDurableWarningIsNotSuppressedByABackwardClockStep is the
// same gate for the second, deliberately separate rate gate.
func TestChaos71_RosterNotDurableWarningIsNotSuppressedByABackwardClockStep(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)

	rosterNotDurableLogLast.Store(time.Now().Add(clockStepBack).UnixNano())
	noteRosterNotDurable()

	if got := rosterNotDurableSuppress.Load(); got != 0 {
		t.Fatalf("rosterNotDurableSuppress = %d, want 0: a backward clock step suppressed the "+
			"non-durable-roster warning", got)
	}
}

// TestChaos71_RosterRateGatesStillSuppressWithinTheInterval is the CONTROL that
// the guards did not remove the rate limiting the gates exist for.
func TestChaos71_RosterRateGatesStillSuppressWithinTheInterval(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)

	err := errors.New("read-only file system")
	noteRosterPersistBestEffort("backup codes", err) // emits, claims the interval
	noteRosterPersistBestEffort("backup codes", err) // must be suppressed
	if got := rosterPersistSuppress.Load(); got != 1 {
		t.Fatalf("rosterPersistSuppress = %d, want 1 — the rate gate stopped suppressing", got)
	}

	noteRosterNotDurable()
	noteRosterNotDurable()
	if got := rosterNotDurableSuppress.Load(); got != 1 {
		t.Fatalf("rosterNotDurableSuppress = %d, want 1 — the rate gate stopped suppressing", got)
	}
}
