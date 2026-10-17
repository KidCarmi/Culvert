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
// THE WHOLE CLASS, enumerated at this revision. TWENTY-TWO interval comparisons
// in the tree are derived from an int64 stamp.
//
// The first version of this header claimed SEVENTEEN and called the inventory
// exhaustive. That was wrong, and Codex rejected it on PR #1650 (P2). The cause
// was the SEARCH, not an oversight about any one site: the original grep
// required the subtraction to sit syntactically beside the time call
// (`UnixNano() - x`), so it missed the far more common two-step form
//
//	now := time.Now().UnixNano()
//	... now - last ...
//
// which is how five further gates are written. One of those five compares
// against a bare literal (policy.go, `>= 300`), so even a generalised
// `int64(<duration>)` search missed it; finding it took walking every file that
// seeds an int64 from a time call. The lesson is recorded in §8c of the review
// doc: an inventory is only as exhaustive as the shapes its search can express,
// so state the shape you searched for, not that you looked everywhere.
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
//	UNGUARDED, CLOSED BY THE FIRST PASS (7) — recovery bounds and signals:
//	  proxy_tunnel.go                 tunnel idle reaper        CK-1
//	  internal/upstream/upstream.go   parent-proxy breaker      CK-2
//	  cdr_breaker.go                  Sluice/CDR breaker        CK-3
//	  readyz_dp_health.go             DP readiness grace        CK-4
//	  roster_persist_durability.go x2 durability log gates      CK-5
//	  internal/ocsp/ocsp.go           responder-cap log gate    CK-5
//
//	UNGUARDED, MISSED BY THE FIRST SEARCH, CLOSED HERE (5) — all CK-9:
//	  crashguard.go                   crash-evidence throttle   (Codex)
//	  internal/secscan/secscan.go     scanner degraded log      (Codex)
//	  internal/yara/yara.go           YARA degraded log         (Codex)
//	  cdr_proxy.go                    Sluice call-error log     (found re-sweeping)
//	  policy.go                       file-profile block warn   (found re-sweeping)
//
//	UNGUARDED, DELIBERATELY LEFT (2) — CK-8, recorded with its fix shape in
//	docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-10-17.md §7:
//	  internal/mcp/canary/budget_enforce.go rate window (Reserve + the read)
//	  — fail-CLOSED under a step, and inside a reviewed budget boundary.
//
// A new bound added on an int64 stamp is not structurally stopped from
// repeating this; CK-7 records the lint/AST option and why it is not trivial.
// CK-9 is the argument FOR building it: a convention applied by hand across 22
// sites in one repository was wrong at 5 of them.
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
//
// The idle bound now measures on the MONOTONIC basis relayEpoch establishes,
// which is why these gates inject stamps on that basis rather than wall-clock
// ones. The basis IS the fix: a wall-clock step cannot be represented in a
// monotonic stamp, so neither step direction can reach the verdict. The first
// gate pins the basis itself; the rest pin that the mechanism still works.

// TestChaos71_TunnelActivityStampIsNotOnTheWallClock is the PERMANENT DEFECT
// PROOF for both halves of CK-1.
//
// Every wall-clock failure of this bound — the backward step that stopped it
// reaping a dead tunnel, and the forward step that made it tear down a quiet
// live one — follows from the stamp being a unix-epoch value, because an int64
// of unix nanos forces time.Unix on the read side and the idleness test becomes
// a wall-clock subtraction. A monotonic stamp is nanos since process start:
// nine orders of magnitude smaller, and immune by construction.
//
// So this asserts the BASIS, not a behaviour. If anyone ever restores a
// wall-clock stamp, this fails immediately and names the reason, which no
// behavioural gate can do — the faults it prevents need a clock step to
// observe, and a test cannot step the host clock.
func TestChaos71_TunnelActivityStampIsNotOnTheWallClock(t *testing.T) {
	got := newTunnelActivityStamp().Load()
	// A monotonic stamp is bounded by this process's own age. A unix-nanos
	// stamp is ~1.8e18. Any plausible test-process age separates them.
	if limit := int64(24 * time.Hour); got > limit {
		t.Fatalf("activity stamp = %d, want < %d (monotonic nanos since process start).\n"+
			"A stamp this large is a unix-epoch value, which makes the idleness test a "+
			"WALL-CLOCK subtraction: a backward step then stops the reaper firing on a dead "+
			"tunnel, and a forward step tears down quiet live ones.", got, limit)
	}
	if got < 0 {
		t.Fatalf("activity stamp = %d, want >= 0", got)
	}
}

// TestChaos71_TunnelIdleForIgnoresAWallClockEpochStamp is a CONTROL, and
// deliberately labelled as one: it passes in BOTH trees, which is exactly what
// makes it a control rather than a proof. A unix-epoch stamp is ~1.8e18 — far in
// the "future" of a monotonic reading — so the monotonic implementation reaches
// its clamp here. The gate pins that the clamp holds, so a stamp on the wrong
// basis can never produce a REAPABLE idleness and tear down a live tunnel.
// (The basis itself is proved by the gate above, which does discriminate.)
func TestChaos71_TunnelIdleForIgnoresAWallClockEpochStamp(t *testing.T) {
	setTunnelIdleTimeout(t, 200*time.Millisecond)
	shared := new(atomic.Int64)
	shared.Store(time.Now().UnixNano())
	if got := tunnelIdleFor(shared); got >= tunnelIdleTimeout {
		t.Fatalf("tunnelIdleFor(unix-epoch stamp) = %v, >= the idle window: the read side is "+
			"still comparing against the wall clock", got)
	}
}

// TestChaos71_TunnelIdleReaperReapsAnIdleTunnel is the mechanism gate: a stamp
// older than the window on the live basis must still reap a half-open tunnel.
// This is the CHAOS-03 guarantee the monotonic switch must not have broken.
func TestChaos71_TunnelIdleReaperReapsAnIdleTunnel(t *testing.T) {
	setTunnelIdleTimeout(t, 200*time.Millisecond)

	// A half-open tunnel: both peers silent, neither closed.
	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() { clientPeer.Close(); destPeer.Close() })

	shared := new(atomic.Int64)
	shared.Store(relayMonoNanos() - int64(time.Hour)) // idle for an hour

	done := make(chan int64, 1)
	go func() { done <- idleCopyCounted(destProxy, clientProxy, clientProxy, shared) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idleCopyCounted did not reap a tunnel idle for an hour")
	}
}

// TestChaos71_TunnelIdleReaperDoesNotReapAFreshTunnel is the CONTROL that the
// bound cannot become "always reap": a tunnel seeded by the production helper
// must survive a full window.
func TestChaos71_TunnelIdleReaperDoesNotReapAFreshTunnel(t *testing.T) {
	setTunnelIdleTimeout(t, 400*time.Millisecond)

	clientProxy, clientPeer := net.Pipe()
	destProxy, destPeer := net.Pipe()
	t.Cleanup(func() { clientPeer.Close(); destPeer.Close() })

	shared := newTunnelActivityStamp()

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

// TestChaos71_RosterGateDoesNotMistakeItsOwnStalenessForARollback is the gate
// for the ordering defect the CK-5 guard itself introduced.
//
// The guard treats a negative interval as "the clock stepped back, emit". That
// is only sound while `now` cannot be OLDER than the stamp for an ordinary
// reason — and a clock sample hoisted above the CAS loop can be: a caller that
// loses the CAS re-reads a stamp the winner just wrote from a later sample. With
// a hoisted sample the loser saw a negative interval, read it as a rollback, and
// emitted a duplicate line while moving the stamp backwards — the amplification
// the CAS exists to prevent, arriving when the volume is already failing.
//
// Simulated deterministically: a stamp very slightly in the future is exactly
// what a loser observes. Microseconds cannot be a real clock correction, so the
// gate distinguishes an ordering artifact from the genuine rollback CK-5 covers
// (one hour, asserted above) without racing two goroutines.
func TestChaos71_RosterGateDoesNotMistakeItsOwnStalenessForARollback(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)

	err := errors.New("read-only file system")

	// A winner's stamp, a few microseconds ahead of a loser's hoisted sample.
	rosterPersistLogLast.Store(time.Now().Add(50 * time.Microsecond).UnixNano())
	noteRosterPersistBestEffort("backup codes", err)
	if got := rosterPersistSuppress.Load(); got != 1 {
		t.Fatalf("rosterPersistSuppress = %d, want 1: a stamp microseconds ahead is a lost CAS, "+
			"not a clock rollback, and must still suppress", got)
	}

	rosterNotDurableLogLast.Store(time.Now().Add(50 * time.Microsecond).UnixNano())
	noteRosterNotDurable()
	if got := rosterNotDurableSuppress.Load(); got != 1 {
		t.Fatalf("rosterNotDurableSuppress = %d, want 1", got)
	}
}

// TestChaos71_RosterGateNeverMovesItsStampBackwards pins the second half: the
// winner's stamp must not be replaced by an older one, whatever a loser decides.
func TestChaos71_RosterGateNeverMovesItsStampBackwards(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)

	winner := time.Now().Add(50 * time.Microsecond).UnixNano()
	rosterPersistLogLast.Store(winner)
	noteRosterPersistBestEffort("backup codes", errors.New("read-only file system"))
	if got := rosterPersistLogLast.Load(); got < winner {
		t.Fatalf("rosterPersistLogLast moved backwards: %d < %d", got, winner)
	}
}

// ─── CK-9: the five sites the first sweep's search MISSED ────────────────────
//
// Codex (PR #1650, P2) rejected the first write-up's claim of an exhaustive
// inventory and named three live comparisons with the same defect. It was right,
// and the cause was the SEARCH, not an oversight about any one site: the
// original grep required the subtraction to sit syntactically next to the time
// call (`UnixNano() - x`), so it saw none of the far more common two-step form
//
//	now := time.Now().UnixNano()
//	... now - last ...
//
// Re-running the sweep on the generalised shape found Codex's three plus two
// more it had not named (cdr_proxy.go, and policy.go — which compares against a
// bare literal 300, so even the generalised int64(...)-cast search missed it and
// it took walking every file that seeds an int64 from a time call).
//
// All five are log/evidence gates, so the fault is the CK-5 one: a backward step
// suppresses the notice for the whole step. crashguard is the sharpest, because
// crash evidence is the one record an operator cannot reconstruct afterwards.

// TestChaos71_CrashThrottleSurvivesABackwardClockStep is the DEFECT gate for the
// crash-evidence throttle. Pre-fix a backward step makes recordCrash return
// before updating lastCrash or emitting the stack-bearing log and audit entry,
// so every subsequent same-component crash is silently lost.
func TestChaos71_CrashThrottleSurvivesABackwardClockStep(t *testing.T) {
	const component = "chaos71-probe"
	crashThrottleMu.Lock()
	prev, had := crashThrottleLast[component]
	crashThrottleMu.Unlock()
	t.Cleanup(func() {
		crashThrottleMu.Lock()
		if had {
			crashThrottleLast[component] = prev
		} else {
			delete(crashThrottleLast, component)
		}
		crashThrottleMu.Unlock()
	})

	// Stamped before a one-hour backward step, so it reads an hour ahead.
	crashThrottleMu.Lock()
	crashThrottleLast[component] = time.Now().Add(clockStepBack).UnixNano()
	crashThrottleMu.Unlock()

	if !crashThrottleAllow(component) {
		t.Fatal("crashThrottleAllow suppressed a crash after a backward clock step — " +
			"recordCrash returns before the stack-bearing log and audit entry, so crash " +
			"evidence is lost for the duration of the step")
	}
}

// TestChaos71_CrashThrottleStillThrottles is the CONTROL: the per-second gate
// still collapses a flood on a sane clock.
func TestChaos71_CrashThrottleStillThrottles(t *testing.T) {
	const component = "chaos71-probe-control"
	t.Cleanup(func() {
		crashThrottleMu.Lock()
		delete(crashThrottleLast, component)
		crashThrottleMu.Unlock()
	})
	if !crashThrottleAllow(component) {
		t.Fatal("first crash of a component was throttled")
	}
	if crashThrottleAllow(component) {
		t.Fatal("second crash inside crashThrottleEvery was allowed — the throttle stopped throttling")
	}
}

// TestChaos71_CrashThrottleIgnoresAConcurrentClaimantsStamp is the CONTROL for
// the other side of the symmetric window: a stamp marginally ahead is a
// concurrent claimant, not a clock step, and must still throttle.
func TestChaos71_CrashThrottleIgnoresAConcurrentClaimantsStamp(t *testing.T) {
	const component = "chaos71-probe-ahead"
	t.Cleanup(func() {
		crashThrottleMu.Lock()
		delete(crashThrottleLast, component)
		crashThrottleMu.Unlock()
	})
	crashThrottleMu.Lock()
	crashThrottleLast[component] = time.Now().Add(50 * time.Microsecond).UnixNano()
	crashThrottleMu.Unlock()
	if crashThrottleAllow(component) {
		t.Fatal("a stamp microseconds ahead was treated as a clock rollback; it is a concurrent claimant")
	}
}

// TestChaos71_CDRCallErrorLogSurvivesABackwardClockStep is the DEFECT gate for
// the Sluice call-error line.
func TestChaos71_CDRCallErrorLogSurvivesABackwardClockStep(t *testing.T) {
	prev := cdrCallErrorLogAt.Load()
	t.Cleanup(func() { cdrCallErrorLogAt.Store(prev) })

	cdrCallErrorLogAt.Store(time.Now().Add(clockStepBack).UnixNano())
	before := cdrCallErrorLogAt.Load()
	noteCDRCallError(errors.New("sanitize failed"))
	if got := cdrCallErrorLogAt.Load(); got == before {
		t.Fatal("noteCDRCallError did not claim the interval after a backward clock step — " +
			"the Sluice call-error line stays suppressed until the clock catches up")
	}
}

// TestChaos71_FileProfileUnresolvedLogSurvivesABackwardClockStep is the DEFECT
// gate for policy.go's fail-closed file-profile warning. It is the site that
// compares against a bare literal, which is why the generalised search missed it
// too.
func TestChaos71_FileProfileUnresolvedLogSurvivesABackwardClockStep(t *testing.T) {
	prev := atomic.LoadInt64(&fileProfileUnresolvedLastLog)
	t.Cleanup(func() { atomic.StoreInt64(&fileProfileUnresolvedLastLog, prev) })

	future := time.Now().Add(clockStepBack).Unix() // SECONDS, not nanos
	atomic.StoreInt64(&fileProfileUnresolvedLastLog, future)
	noteFileProfileUnresolvedBlock("prof-1", "Chaos71 Probe")
	if got := atomic.LoadInt64(&fileProfileUnresolvedLastLog); got == future {
		t.Fatal("noteFileProfileUnresolvedBlock did not claim the interval after a backward clock " +
			"step — the only notice that a rule is blocking file transactions stays suppressed")
	}
}

// TestChaos71_FileProfileUnresolvedLogStillRateLimits is the CONTROL.
func TestChaos71_FileProfileUnresolvedLogStillRateLimits(t *testing.T) {
	prev := atomic.LoadInt64(&fileProfileUnresolvedLastLog)
	t.Cleanup(func() { atomic.StoreInt64(&fileProfileUnresolvedLastLog, prev) })

	atomic.StoreInt64(&fileProfileUnresolvedLastLog, 0)
	noteFileProfileUnresolvedBlock("prof-1", "Chaos71 Probe") // claims the interval
	claimed := atomic.LoadInt64(&fileProfileUnresolvedLastLog)
	noteFileProfileUnresolvedBlock("prof-1", "Chaos71 Probe") // must be suppressed
	if got := atomic.LoadInt64(&fileProfileUnresolvedLastLog); got != claimed {
		t.Fatalf("the 5-minute gate re-claimed immediately (%d -> %d): it stopped rate limiting", claimed, got)
	}
}
