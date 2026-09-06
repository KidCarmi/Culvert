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
	// RE-DERIVE the population verdict before arming anything. Observe returns the breach code and
	// the CALLER latches it, so the counters and the latch are two separate durable writes: a crash
	// between them leaves a record whose numbers already prove a breach and whose abort controller
	// says the activation is healthy. Restore must therefore re-ask the question rather than trust
	// that the previous process got as far as latching (Codex P1). Checked after the allowance and
	// before the window so a first cause reflects the most specific fact available.
	if code := cr.health.Verdict(); code != "" {
		tripAutoStopLocked(rt, capb, cr, code, canaryNow())
		return
	}
	deadline := cr.enforcer.WindowDeadline()
	if deadline.IsZero() {
		return // no window configured — nothing to time out (ValidateBudget already refuses this)
	}
	now := canaryNow()
	// The FULL two-ended predicate, the same one the final boundary uses. Testing only
	// `now.Before(deadline)` here left an asymmetry I introduced in the previous round: with the
	// clock rolled back BEHIND the persisted activation instant, WindowOpen is false — every
	// admission is closed — while the upper-bound test reads "plenty of time left", so nothing
	// latched and a watchdog was armed for a deadline potentially far in the future. The callback
	// repeated the same one-ended check and re-armed, so `auto_stop` reported GRANTED authority
	// indefinitely on a Canary that could not execute at all (Codex round 4 P2).
	//
	// The code is window_expired for both ends. It names the time box refusing to authorize
	// execution, which is what has happened; a clock behind the activation cannot be used to reason
	// about elapsed time at all, so there is no weaker honest answer.
	if !cr.enforcer.WindowOpen(now) {
		// Latch here, under the same lock the admission path takes, so there is no window in which
		// a restored activation reads as eligible.
		tripAutoStopLocked(rt, capb, cr, "window_expired", now)
		return
	}
	gen := cr.generation
	armWindowWatchdogLocked(rt, capb, cr, gen, deadline.Sub(now))
}

// armWindowWatchdogLocked schedules the one-shot expiry timer. Caller holds cr.mu.
func armWindowWatchdogLocked(rt *canaryRuntime, capb rollout.Capability, cr *canaryCapRuntime, gen uint64, in time.Duration) {
	if in < 0 {
		in = 0
	}
	cr.windowStop = canaryAfterFunc(in, func() {
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
		// ONE CLOCK SAMPLE DECIDES EVERY BRANCH BELOW, and that is the point of the variable.
		//
		// Read separately, the openness test, the "is the deadline still ahead" test, the re-arm
		// duration and the trip timestamp were FOUR samples. A clock stepping backwards between any
		// two of them lets the callback pick contradictory branches: the first sample says the
		// window is open, the second is already before the activation instant, and the callback
		// re-arms — possibly for a very long time — on a window that is in fact closed, leaving
		// Aborted and the immutable first cause unset (Codex round 12). A rollback must move the
		// callback to ONE verdict, not between two.
		now := canaryNow()
		if d, ok := globalCanaryRuntime.windowDeadlineIfOpen(capb, now); ok && now.Before(d) {
			// FIRED EARLY, and this must RE-ARM rather than return. time.AfterFunc measures a
			// duration; the deadline is absolute wall-clock. If the clock moves backwards after
			// activation the timer still fires on schedule while the deadline is genuinely still in
			// the future — and a one-shot timer that simply returns leaves the activation with NO
			// watchdog at all, back to waiting for a request to notice (Codex P1). Re-arming for
			// the remaining time keeps the traffic-independence claim true.
			rt.rearmWindowWatchdog(capb, gen, d.Sub(now))
			return
		}
		// The generation travels with the trip and is verified under the same lock that latches:
		// this callback cannot be cancelled once it is running, so a demote-and-reactivate between
		// the check above and the trip must not abort the replacement.
		rt.tripCanaryAbortForGeneration(capb, gen, "window_expired", now)
	})
}

// rearmWindowWatchdog re-schedules the watchdog for an activation that is still current. It takes
// cr.mu itself because it runs from the timer callback, which holds no lock.
func (rt *canaryRuntime) rearmWindowWatchdog(capb rollout.Capability, gen uint64, in time.Duration) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.generation != gen {
		return
	}
	stopWindowWatchdogLocked(cr)
	armWindowWatchdogLocked(rt, capb, cr, gen, in)
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

// windowDeadlineIfOpen reports the deadline ONLY while the window is open at both ends. The
// watchdog callback uses it rather than windowDeadline so a clock rolled back behind the activation
// cannot make an early fire re-arm indefinitely: the window is closed, so the callback falls through
// to the trip instead.
// now is supplied by the caller rather than read here, so a caller that must decide several things
// about the same instant decides them all against ONE sample (Codex round 12).
func (rt *canaryRuntime) windowDeadlineIfOpen(capb rollout.Capability, now time.Time) (time.Time, bool) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.enforcer == nil || !cr.enforcer.WindowOpen(now) {
		return time.Time{}, false
	}
	d := cr.enforcer.WindowDeadline()
	return d, !d.IsZero()
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
func (f *canarySafetyFunnel) Breach(capability string, gen uint64, code string) {
	if f == nil || f.rt == nil || capability != f.capb.String() {
		return
	}
	// Defence in depth against the wildcard. This funnel is the generation-BOUND reporter: every
	// caller observed a specific activation, so a zero is always a caller bug. It matters more than
	// an ordinary guard because zero is not inert downstream — tripCanaryAbortForGeneration reads
	// wantGen == 0 as "whatever is current" and skips the generation check, so a zero slipping
	// through here stops a live experiment on the strength of an unattributable observation. The
	// wildcard stays available where it is intended, on the unbound tripCanaryAbort (Codex round 18).
	if gen == 0 {
		return
	}
	// gen is the ATTEMPT's activation, not the current one. The trip verifies it under the same
	// lock that latches, so a breach reported by a request that outlived its activation is
	// discarded rather than charged to whatever activation replaced it.
	f.rt.tripCanaryAbortForGeneration(f.capb, gen, code, canaryNow())
}

// Generation snapshots this capability's activation generation for a request that has not reserved
// a slot yet. The runtime pipeline calls it ONCE, beside the rollout resolution, and carries the
// value to any pre-executor breach it reports.
//
// It exists instead of a BreachAtCurrentActivation helper that resolved the generation at REPORT
// time. That helper's premise — "no slot was reserved, so this request was not admitted under any
// activation, so use the one admitting right now" — is false in the way that matters: the request
// was RESOLVED under an activation even though it was not ADMITTED under one, and between those
// two moments a demote-and-reactivate can intervene. A request that resolved under G1 then stopped
// the G2 that replaced it (Codex round 16) — the round-1 "safety reports carried no activation
// generation" finding, reintroduced in a seam added five rounds later.
//
// A zero generation means no activation is running, and the generation-bound Breach discards it.
func (f *canarySafetyFunnel) Generation(capability string) uint64 {
	if f == nil || f.rt == nil || capability != f.capb.String() {
		return 0
	}
	return f.rt.currentGeneration(f.capb)
}

// AttemptSettled feeds one settled attempt to the generation-bound health detectors and trips the
// abort if the population now proves a breach. The classification lives here rather than in the
// engine because only the composition layer knows the activation generation — a settle reported by
// an engine that outlived its activation must not count against the next one.
func (f *canarySafetyFunnel) AttemptSettled(capability string, gen uint64, failed bool, latency time.Duration) {
	if f == nil || f.rt == nil || capability != f.capb.String() {
		return
	}
	// The latch happens INSIDE observeAttemptSettled, under the same lock that records the
	// observation. Returning a code for the caller to trip left a window in which a third request
	// could take cr.mu, reserve the remaining slot and pass the final boundary between the sample
	// that proved the breach and the latch that acted on it (Codex round 3 P1).
	f.rt.observeAttemptSettled(f.capb, gen, failed, latency)
}

// observeAttemptSettled records one settled attempt against the capability's health monitor and
// returns the breach code the population now proves (ok=false when nothing is armed). It persists
// the updated counters so a restart cannot wipe accumulated failure evidence.
//
// It does NOT trip: the trip is the caller's, on the ONE authority, without this lock held.
func (rt *canaryRuntime) observeAttemptSettled(capb rollout.Capability, gen uint64, failed bool, latency time.Duration) {
	cr := rt.capRuntime(capb)
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if !cr.active || cr.health == nil || cr.generation != gen {
		return
	}
	// Observe and the latch it may prove are ONE critical section. Splitting them — recording here
	// and tripping from the caller after the lock is released — leaves a window in which the
	// population already proves the Canary must stop and the runtime still says it may execute, and
	// a request that takes the lock in that window reserves and crosses the boundary legitimately.
	if code := cr.health.Observe(gen, failed, latency); code != "" {
		tripAutoStopLocked(rt, capb, cr, code, canaryNow())
		return // tripAutoStopLocked persisted (or failed closed) already
	}
	if err := canaryRuntimePersist(rt, capb, cr); err != nil {
		// FAIL CLOSED. These counters are declared restart-durable safety state, and the reason is
		// the whole point of persisting them: a detector that resets on restart is one a crash can
		// silently disarm. Logging a persist failure and carrying on would leave the process one
		// restart away from treating the next bad attempt as the FIRST sample — the detector
		// admitting work it had already seen enough to stop (Codex round 1 P1).
		//
		// So the same doctrine as a failed abort persist applies: the durable record is removed, so
		// a restart restores nothing rather than restoring an activation whose evidence is stale.
		// The in-memory counters remain, so this process keeps judging correctly; what is refused is
		// the claim that the evidence would survive.
		logger.Printf("MCP canary runtime: persist after health observation for %s failed: %q; disarming durable state (fail-closed)",
			capb.String(), sanitizeLog(err.Error()))
		_ = rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "health", err)
	}
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
	// The window is read with the SAME two-ended predicate admission uses, under the same lock.
	// Reporting `!now.Before(deadline)` tested only the upper end, so a clock rolled BEHIND the
	// activation instant — where WindowOpen is false and every reservation is already denied —
	// still rendered window_expired:false and execution_authority:"granted". With a long window
	// that misleading state persists until the one-shot watchdog fires, which is exactly the
	// interval an operator would be reading this surface to decide whether to intervene
	// (Codex round 6 P2). The operator view must not be more optimistic than the admission gate.
	var deadline time.Time
	windowClosed := false
	if cr.enforcer != nil {
		deadline = cr.enforcer.WindowDeadline()
		windowClosed = !cr.enforcer.WindowOpen(canaryNow())
	}
	samples, failures, mean := cr.health.Stats()
	cr.mu.Unlock()

	// "granted" must mean the node can still change the world, and a closed window makes that
	// false whether or not the latch has caught up yet: every reservation is already denied. The
	// window is therefore folded into the REPORT — and only into the report. Nothing in the
	// admission path reads this value, so this is not a second abort authority (that stays
	// AbortController alone); it is the surface refusing to be more optimistic than the gate it
	// describes, during exactly the interval an operator would consult it (Codex round 6 P2).
	authority := "none"
	switch {
	case active && (aborted || windowClosed):
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
		st.WindowExpired = windowClosed
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
