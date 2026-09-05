package main

// mcp_canary_autostop.go — whole-Canary AUTOMATIC stop (First Controlled Canary review, blocker #7).
//
// The abort controller (internal/mcp/canary.AbortController) is the ONE abort authority and this
// file does not add a second. What it adds is the wiring that was missing: the authoritative breach
// signals that must reach it, and the one stop condition that has no signal at all because nothing
// is there to notice it — the passage of time.
//
// The distinction this file exists to enforce:
//
//	a breach is not a reason to reject one request.
//	it is a reason to revoke the experiment's authority to change reality again.
//
// Everything here converges on rt.tripCanaryAbort → AbortController.Trip. There is no second latch,
// no parallel registry, and no per-breach stop mechanism.
//
// SCOPE. This does NOT demote the node to Shadow. Automatic demotion is governed by blockers
// #10/#12 and inventing an internal path around them would be a lie told in code. What the latch
// revokes is EXECUTION AUTHORITY: no new reservation, and an already-admitted request fails the
// final live revalidation before Upstream.Call. `ModeCanary + ABORTED` is the truthful state until
// the separately-governed lifecycle transition exists, and the status surface says exactly that.

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// canaryNow and canaryAfterFunc are the clock/timer seams. Production is the real clock; a test
// injects both so a 15-minute window can be proven deterministically in microseconds without a
// sleep. They are process-global and swapped only by tests (swapCanaryClock).
var (
	canaryNow       = time.Now
	canaryAfterFunc = func(d time.Duration, f func()) func() {
		t := time.AfterFunc(d, f)
		return func() { t.Stop() }
	}
)

// ── the window deadline: the one stop condition with no request to carry it ──────────────────

// reconcileWindowDeadlineLocked establishes the correct window posture for an armed activation.
// Caller holds cr.mu.
//
// It is the SINGLE place the deadline is acted on, and it is called from both begin and restore so
// the two paths cannot disagree. Two outcomes:
//
//   - the deadline has already passed → the abort is latched here, synchronously, BEFORE the caller
//     releases cr.mu. That ordering is the point: a restart after expiry must never expose an
//     execution-eligible activation to an admission path, not even briefly.
//   - the deadline is in the future → a watchdog is armed for the REMAINING time. Never for a fresh
//     full window: the deadline is derived from the persisted activation instant, so a restart
//     cannot extend the experiment by restarting its clock.
//
// A clock that has rolled back cannot manufacture authority either: the remaining time is computed
// from the same absolute deadline, and Reserve independently fails closed on a negative elapsed.
func reconcileWindowDeadlineLocked(rt *canaryRuntime, capb rollout.Capability, cr *canaryCapRuntime) {
	stopWindowWatchdogLocked(cr)
	if !cr.active || cr.enforcer == nil || cr.aborter == nil {
		return
	}
	// Recovery establishing that the total allowance is already spent is itself an automatic stop:
	// an experiment with no execution allowance left is over, and must not wait for an N+1 request
	// to discover that (blocker #7 §7). Checked before the window so a Canary that is both spent
	// and expired records the allowance as its first cause, which is the more specific truth.
	if cr.enforcer.Remaining() <= 0 {
		tripAutoStopLocked(rt, capb, cr, "budget_exhausted", canaryNow())
		return
	}
	deadline := cr.enforcer.WindowDeadline()
	if deadline.IsZero() {
		return // no window configured — nothing to time out (ValidateBudget already refuses this)
	}
	now := canaryNow()
	if !now.Before(deadline) {
		// Already expired. Latch here, under the same lock the admission path takes, so there is no
		// window in which a restored activation reads as eligible.
		tripAutoStopLocked(rt, capb, cr, "window_expired", now)
		return
	}
	gen := cr.generation
	cr.windowStop = canaryAfterFunc(deadline.Sub(now), func() {
		// Runs WITHOUT cr.mu — tripCanaryAbort takes it.
		//
		// Two guards, and both are load-bearing. GENERATION: a timer that outlives its activation
		// (a demote/re-activate racing the stop) must not abort the activation that replaced it.
		// DEADLINE: the timer is a convenience, not the authority — it re-derives the absolute
		// deadline and refuses to act early, so a spurious or mis-scheduled fire cannot end an
		// experiment that still has time left. The authority is the deadline itself, which is why
		// restore re-evaluates it independently of any timer.
		if globalCanaryRuntime.currentGeneration(capb) != gen {
			return
		}
		if d, ok := globalCanaryRuntime.windowDeadline(capb); ok && canaryNow().Before(d) {
			return
		}
		rt.tripCanaryAbort(capb, "window_expired", canaryNow())
	})
}

// tripAutoStopLocked latches an automatic-stop code on an armed activation. Caller holds cr.mu, so
// it performs the Trip + persist inline rather than re-entering tripCanaryAbort (which would
// deadlock on the same mutex). It reaches the SAME AbortController — there is still exactly one
// abort authority — and the fail-closed persist handling is identical.
func tripAutoStopLocked(rt *canaryRuntime, capb rollout.Capability, cr *canaryCapRuntime, code string, now time.Time) {
	if cr.aborter == nil {
		return
	}
	if res := cr.aborter.Trip(code, cr.generation, now); res == canary.TripCanaryLatched {
		if err := canaryRuntimePersist(rt, capb, cr); err != nil {
			// Same doctrine as tripCanaryAbort: a safety latch that did not persist must not be
			// revivable by a restart, so the durable record is removed.
			_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "auto-stop", err)
		}
	}
}

// stopWindowWatchdogLocked cancels any armed watchdog. Caller holds cr.mu. Idempotent.
func stopWindowWatchdogLocked(cr *canaryCapRuntime) {
	if cr.windowStop != nil {
		cr.windowStop()
		cr.windowStop = nil
	}
}

// windowDeadline reports the activation's absolute deadline and whether one is armed. Read-only,
// for the status surface.
func (rt *canaryRuntime) windowDeadline(capb rollout.Capability) (time.Time, bool) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.enforcer == nil {
		return time.Time{}, false
	}
	d := cr.enforcer.WindowDeadline()
	return d, !d.IsZero()
}

// ── the breach funnel: engine facts → the ONE abort authority ────────────────────────────────

// canarySafetyFunnel implements execution.CanarySafety for one capability. It is the ONLY adapter
// between the execution engine's authoritative safety facts and rt.tripCanaryAbort, and it holds no
// state of its own: the counters live in the generation-bound HealthMonitor, and the latch lives in
// the generation-bound AbortController. It therefore cannot become a second abort authority, and a
// funnel that outlives its activation trips nothing (Trip is generation-strict).
type canarySafetyFunnel struct {
	rt   *canaryRuntime
	capb rollout.Capability
}

func newCanarySafetyFunnel(capb rollout.Capability) *canarySafetyFunnel {
	return &canarySafetyFunnel{rt: globalCanaryRuntime, capb: capb}
}

// Breach routes an authoritative whole-Canary breach code straight to the abort authority. The
// capability string is checked against THIS funnel's capability: the two capabilities are
// physically isolated, and a breach reported for one must never stop the other.
func (f *canarySafetyFunnel) Breach(capability, code string) {
	if f == nil || f.rt == nil || capability != f.capb.String() {
		return
	}
	f.rt.tripCanaryAbort(f.capb, code, canaryNow())
}

// AttemptSettled feeds one settled attempt to the generation-bound health detectors and trips the
// abort if the population now proves a breach. The classification lives here rather than in the
// engine because only the composition layer knows the activation generation — a settle reported by
// an engine that outlived its activation must not count against the next one.
func (f *canarySafetyFunnel) AttemptSettled(capability string, failed bool, latency time.Duration) {
	if f == nil || f.rt == nil || capability != f.capb.String() {
		return
	}
	code, ok := f.rt.observeAttemptSettled(f.capb, failed, latency)
	if ok && code != "" {
		f.rt.tripCanaryAbort(f.capb, code, canaryNow())
	}
}

// observeAttemptSettled records one settled attempt against the capability's health monitor and
// returns the breach code the population now proves (ok=false when nothing is armed). It persists
// the updated counters so a restart cannot wipe accumulated failure evidence.
//
// It does NOT trip: the trip is the caller's, on the ONE authority, without this lock held.
func (rt *canaryRuntime) observeAttemptSettled(capb rollout.Capability, failed bool, latency time.Duration) (string, bool) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.health == nil {
		return "", false
	}
	code := cr.health.Observe(cr.generation, failed, latency)
	// AUTHORITY CONSUMED (blocker #7 §7). Latch only when the allowance is spent AND nothing is
	// still in flight, i.e. the FINAL AUTHORIZED ATTEMPT HAS SETTLED.
	//
	// Both halves are required and the second is the subtle one. Remaining()==0 alone is true the
	// moment the last slot is RESERVED, which with N concurrent requests for N slots is while
	// N-1 of them are still mid-flight — latching there revokes authority the experiment had
	// already granted, and those requests fail the final revalidation instead of making the
	// invocation they were authorized to make. That is precisely the "do not abort the Nth request
	// before its authorized side effect" rule, and the concurrency gate
	// (TestLiveRace_RacersEqualToBudgetAllCross) fails loudly when it is broken.
	//
	// Inflight()==0 is meaningful here because the gate's Release is deferred inside callUpstream
	// and therefore runs BEFORE runExecute's outcome-commit defer: by the time a settle is
	// reported, that attempt's own slot is already returned.
	if code == "" && cr.enforcer != nil && cr.enforcer.Remaining() <= 0 && cr.enforcer.Inflight() == 0 {
		code = "budget_exhausted"
	}
	if err := canaryRuntimePersist(rt, capb, cr); err != nil {
		// Failure evidence that did not persist is evidence a restart would forget. The abort (if
		// any) is still returned and latched by the caller — the safe direction — and the persist
		// failure is logged rather than swallowed.
		logger.Printf("MCP canary runtime: persist after health observation for %s failed: %q",
			capb.String(), sanitizeLog(err.Error()))
	}
	return code, true
}

// ── operator truth (blocker #7 §20) ──────────────────────────────────────────────────────────

// canaryAbortStatus is the bounded, secret-free operator view of the automatic-stop state. Scalars
// and fixed tokens only — never a tenant, subject, server, tool or payload.
type canaryAbortStatus struct {
	Generation uint64 `json:"generation"`
	Aborted    bool   `json:"aborted"`
	// FirstAbortReason is the code that LATCHED the abort. It is the first cause and never
	// changes: a later breach cannot rewrite why the experiment stopped.
	FirstAbortReason string `json:"first_abort_reason,omitempty"`
	AbortedAtUnix    int64  `json:"aborted_at_unix,omitempty"`
	// ExecutionAuthority is the honest answer to "can this node still change the world". It is the
	// field to read, not Mode: a node stays ModeCanary after an abort until the separately
	// governed lifecycle transition (blockers #10/#12) runs, so mode alone would report a stopped
	// experiment as a running one.
	ExecutionAuthority string `json:"execution_authority"` // "granted" | "revoked" | "none"
	WindowDeadlineUnix int64  `json:"window_deadline_unix,omitempty"`
	WindowExpired      bool   `json:"window_expired"`
	HealthSamples      int    `json:"health_samples"`
	HealthFailures     int    `json:"health_failures"`
	HealthMeanMillis   int64  `json:"health_mean_latency_ms"`
}

// canaryAbortStatusFor builds the operator view for one capability.
//
// It exists because "Mode: Canary" stops being the whole truth the instant the abort latches. This
// surface must never let an operator read a stopped experiment as a healthy one, so it reports
// execution AUTHORITY separately from mode and names the first cause.
func canaryAbortStatusFor(capb rollout.Capability) canaryAbortStatus {
	rt := globalCanaryRuntime
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	gen, active := cr.generation, cr.active
	var aborted bool
	var code string
	var atUnix int64
	if cr.aborter != nil {
		snap := cr.aborter.Snapshot()
		aborted, code = snap.Aborted, snap.Code
		if snap.AtUnixNano != 0 {
			atUnix = snap.AtUnixNano / int64(time.Second)
		}
	}
	var deadline time.Time
	if cr.enforcer != nil {
		deadline = cr.enforcer.WindowDeadline()
	}
	samples, failures, mean := cr.health.Stats()
	cr.mu.Unlock()

	authority := "none"
	switch {
	case active && aborted:
		authority = "revoked"
	case active:
		authority = "granted"
	}
	st := canaryAbortStatus{
		Generation:         gen,
		Aborted:            aborted,
		FirstAbortReason:   code,
		AbortedAtUnix:      atUnix,
		ExecutionAuthority: authority,
		HealthSamples:      samples,
		HealthFailures:     failures,
		HealthMeanMillis:   mean.Milliseconds(),
	}
	if !deadline.IsZero() {
		st.WindowDeadlineUnix = deadline.Unix()
		st.WindowExpired = !canaryNow().Before(deadline)
	}
	return st
}

// abortedNow / abortCodeNow are read-only accessors for the status surface and the gates.
func (rt *canaryRuntime) abortedNow(capb rollout.Capability) bool {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.aborter != nil && cr.aborter.Aborted(cr.generation)
}

func (rt *canaryRuntime) abortCodeNow(capb rollout.Capability) string {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	return cr.aborter.AbortCode()
}
