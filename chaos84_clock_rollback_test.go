package main

// chaos84_clock_rollback_test.go — CHAOS-84: every bound that measures an
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
//	  proxy_tunnel.go                 tunnel idle reaper        CK-1 (CHAOS-83)
//	  internal/upstream/upstream.go   parent-proxy breaker      CK-2
//	  cdr_breaker.go                  Sluice/CDR breaker        CK-3 (main)
//	  readyz_dp_health.go             DP readiness grace        CK-4 (CHAOS-83)
//	  roster_persist_durability.go x2 durability log gates      CK-5 (CHAOS-83)
//	  internal/ocsp/ocsp.go           responder-cap log gate    CK-5
//
//	  Rows marked (CHAOS-83) are fixed by the sibling sweep #1644 (monotonic
//	  stamps, monotime.go) and (main) by the CDR breaker's monotonic rework
//	  already on main; this file gates only the rows this change still fixes.
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
	"sync/atomic"
	"testing"
	"time"
)

// clockStepBack is how far the wall clock moves backwards in these gates. One
// hour is both realistic (a DST/RTC/NTP correction) and larger than every
// window under test, which is what makes the measured interval negative.
const clockStepBack = time.Hour

// ─── CK-1, CK-3, CK-4, CK-5 (roster): owned elsewhere ────────────────────────
//
// The gates this file first carried for the tunnel idle reaper (CK-1), the CDR
// breaker (CK-3), the DP readiness grace (CK-4) and the two roster log gates
// (CK-5) were withdrawn when main was brought in, together with this PR's fixes
// for those sites:
//
//   - CK-3 is closed on main: the CDR breaker's ResetTimeout comparison reads
//     a monotonic stamp (openedMono / monoNow, cdr_breaker_monotonic_test.go).
//   - CK-1, CK-4 and the roster half of CK-5 are closed by the sibling sweep
//     CHAOS-83 (#1644), which moves all three package-main atomics onto one
//     monotonic primitive (monotime.go) and gates them in monotime_chaos_test.go.
//     Its readiness fix is preferred to the "unmeasurable grace counts as
//     expired" guard this PR first shipped, because a monotonic stamp cannot
//     go negative at all, so a routine backward NTP step cannot flip cp_poll to
//     fail before the grace has really elapsed.
//
// Keeping both fixes would have put two contradictory contracts on one row
// (this PR asserted a future stamp FAILS cp_poll; CHAOS-83 asserts it stays
// ok), so the overlap was resolved to one owner rather than merged twice.

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

// TestChaos84_CrashThrottleSurvivesABackwardClockStep is the DEFECT gate for the
// crash-evidence throttle. Pre-fix a backward step makes recordCrash return
// before updating lastCrash or emitting the stack-bearing log and audit entry,
// so every subsequent same-component crash is silently lost.
func TestChaos84_CrashThrottleSurvivesABackwardClockStep(t *testing.T) {
	const component = "chaos84-probe"
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

// TestChaos84_CrashThrottleStillThrottles is the CONTROL: the per-second gate
// still collapses a flood on a sane clock.
func TestChaos84_CrashThrottleStillThrottles(t *testing.T) {
	const component = "chaos84-probe-control"
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

// TestChaos84_CrashThrottleIgnoresAConcurrentClaimantsStamp is the CONTROL for
// the other side of the symmetric window: a stamp marginally ahead is a
// concurrent claimant, not a clock step, and must still throttle.
func TestChaos84_CrashThrottleIgnoresAConcurrentClaimantsStamp(t *testing.T) {
	const component = "chaos84-probe-ahead"
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

// TestChaos84_CDRCallErrorLogSurvivesABackwardClockStep is the DEFECT gate for
// the Sluice call-error line.
func TestChaos84_CDRCallErrorLogSurvivesABackwardClockStep(t *testing.T) {
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

// TestChaos84_FileProfileUnresolvedLogSurvivesABackwardClockStep is the DEFECT
// gate for policy.go's fail-closed file-profile warning. It is the site that
// compares against a bare literal, which is why the generalised search missed it
// too.
func TestChaos84_FileProfileUnresolvedLogSurvivesABackwardClockStep(t *testing.T) {
	prev := atomic.LoadInt64(&fileProfileUnresolvedLastLog)
	t.Cleanup(func() { atomic.StoreInt64(&fileProfileUnresolvedLastLog, prev) })

	future := time.Now().Add(clockStepBack).Unix() // SECONDS, not nanos
	atomic.StoreInt64(&fileProfileUnresolvedLastLog, future)
	noteFileProfileUnresolvedBlock("prof-1", "Chaos84 Probe")
	if got := atomic.LoadInt64(&fileProfileUnresolvedLastLog); got == future {
		t.Fatal("noteFileProfileUnresolvedBlock did not claim the interval after a backward clock " +
			"step — the only notice that a rule is blocking file transactions stays suppressed")
	}
}

// TestChaos84_FileProfileUnresolvedLogStillRateLimits is the CONTROL.
func TestChaos84_FileProfileUnresolvedLogStillRateLimits(t *testing.T) {
	prev := atomic.LoadInt64(&fileProfileUnresolvedLastLog)
	t.Cleanup(func() { atomic.StoreInt64(&fileProfileUnresolvedLastLog, prev) })

	atomic.StoreInt64(&fileProfileUnresolvedLastLog, 0)
	noteFileProfileUnresolvedBlock("prof-1", "Chaos84 Probe") // claims the interval
	claimed := atomic.LoadInt64(&fileProfileUnresolvedLastLog)
	noteFileProfileUnresolvedBlock("prof-1", "Chaos84 Probe") // must be suppressed
	if got := atomic.LoadInt64(&fileProfileUnresolvedLastLog); got != claimed {
		t.Fatalf("the 5-minute gate re-claimed immediately (%d -> %d): it stopped rate limiting", claimed, got)
	}
}
