package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Whole-Canary AUTOMATIC ABORT (First Controlled Canary review, blocker #7).
//
// The invariant every gate here serves:
//
//	a breach is not a reason to reject one request.
//	it is a reason to revoke the experiment's authority to change reality again.
//
// The distinction is the whole point, so the negative controls matter as much as the gates: a
// Canary that aborted on every fail-closed refusal would pass a naive "does it stop" test while
// being useless, and one that stops only the triggering request passes "did the bad request fail"
// while leaving the experiment running.

// ── the abort latch revokes authority, not just one request ──────────────────────────────────

// A latched abort must make the ALREADY-ADMITTED request fail the final live revalidation, so no
// physical side effect follows an abort that landed after admission.
//
// This is the closure condition for blocker #7 under the owner's decision that automatic demotion
// is NOT required: authority is revoked by the latch itself, at the boundary, before Upstream.Call.
// The abort is latched from inside ToolStillCurrent — which preCallGuard evaluates immediately
// BEFORE the live revalidation — so the interleaving is exact and deterministic rather than raced.
func TestAutoStop_LatchedAbortStopsAnAlreadyAdmittedRequestBeforeTheCall(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 5)
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway
	in := liveExecInput(policy.OpRead, "t1", "p1")

	// Latch the abort at the boundary, after this request has already been admitted and has its
	// budget slot. ToolStillCurrent returns true, so the request is NOT refused for drift — the
	// only thing that can stop it now is the abort latch.
	in.ToolStillCurrent = func() bool {
		globalCanaryRuntime.tripCanaryAbort(capb, "scope_escape", time.Unix(0, 2))
		return true
	}
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 {
		t.Fatalf("SECURITY: an abort latched after admission must stop the request BEFORE Upstream.Call, calls=%d", up.callCount())
	}
	if out.Executed {
		t.Fatal("a request stopped by the abort latch must not report executed")
	}
}

// The CONTROL for the gate above: with no abort latched, the identical fixture crosses. Without
// this, "no upstream call" could mean the harness never worked.
func TestAutoStop_ControlUnabortedRequestStillCrosses(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 5)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return true }
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 1 {
		t.Fatalf("control: an unaborted request must cross exactly once, calls=%d", up.callCount())
	}
}

// After the latch, no NEW reservation is possible — admission itself is closed.
func TestAutoStop_LatchedAbortMakesNewReservationImpossible(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	swapCanaryClock(t, func() time.Time { return now })
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("control: a healthy activation must grant, got %s", o)
	}
	rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	rt.tripCanaryAbort(capb, "outcome_evidence_loss", now)
	// The latch must also be OBSERVABLE, and stay observable across reads. Admission closing and
	// the latch reading true are two different questions — every operator surface and every other
	// gate asks the second one — so a latch that cleared itself when read would leave admission
	// correctly shut while the node reported a healthy experiment.
	if !rt.abortedNow(capb) {
		t.Fatal("the abort must be observable immediately after it latches")
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("SECURITY: no reservation may be granted after the abort latched, got %s", o)
	}
	if !rt.abortedNow(capb) {
		t.Fatal("the abort must STILL read as latched after being read — the latch is monotonic")
	}
}

// ── the time box stops the experiment with no traffic at all ─────────────────────────────────

// The deadline must fire without any request arriving. Before blocker #7 the window was evaluated
// only inside Reserve, so a Canary with no traffic stayed Canary past its window indefinitely.
func TestAutoStop_WindowExpiresWithNoTrafficAtAll(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := time.Unix(1_700_000_000, 0)
	nowP := start
	swapCanaryClockVar(t, &nowP)
	fireIndex, armedFor, _ := swapCanaryTimer(t)

	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Arming happens on activation, for the FULL window and not a poll interval.
	if got := armedFor(); got != runtimeTestBudget(3).Window {
		t.Fatalf("the watchdog must be armed for the whole window, got %s want %s", got, runtimeTestBudget(3).Window)
	}
	if rt.abortedNow(capb) {
		t.Fatal("control: a fresh activation must not be aborted")
	}
	// NOT ONE REQUEST is made. Time passes; the watchdog fires.
	nowP = start.Add(runtimeTestBudget(3).Window)
	fireIndex(0)

	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: the window must stop the Canary with no request to notice it (blocker #7 §11)")
	}
	if code := rt.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("the automatic stop must be recorded as window_expired, got %q", code)
	}
}

// A watchdog that fires for a SUPERSEDED activation must trip nothing.
func TestAutoStop_StaleWatchdogCannotAbortALaterActivation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := time.Unix(1_700_000_000, 0)
	nowP := start
	swapCanaryClockVar(t, &nowP)
	fireIndex, _, _ := swapCanaryTimer(t)

	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), start); err != nil {
		t.Fatalf("begin gen1: %v", err)
	}
	// A new activation supersedes the first; the first activation's timer is now stale.
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), start); err != nil {
		t.Fatalf("begin gen2: %v", err)
	}
	fireIndex(0) // gen1's callback — stale now that gen2 is current
	if rt.abortedNow(capb) {
		t.Fatal("a watchdog from a superseded activation must never abort the current one")
	}
}

// ── restart semantics: the window is absolute ────────────────────────────────────────────────

// A restart AFTER expiry must restore into a non-executable state, and must do so before any
// admission path can observe an eligible activation.
func TestAutoStop_RestartAfterExpiryRestoresAborted(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := time.Unix(1_700_000_000, 0)
	nowP := start
	swapCanaryClockVar(t, &nowP)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// The process dies and comes back AFTER the window closed.
	nowP = start.Add(runtimeTestBudget(3).Window + time.Second)
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()

	if o, _ := fresh.reserveCanaryExecution(capb, nowP, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: a restart after expiry must never grant a reservation")
	}
	if !fresh.abortedNow(capb) {
		t.Fatal("a restart after expiry must restore into the aborted state, not merely deny")
	}
	if code := fresh.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("the restored stop reason must be window_expired, got %q", code)
	}
}

// A restart BEFORE expiry must not extend the experiment: the remaining lifetime is what is left of
// the ORIGINAL window, never a fresh full one.
func TestAutoStop_RestartNeverGrantsAFreshWindow(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := time.Unix(1_700_000_000, 0)
	window := runtimeTestBudget(3).Window
	nowP := start
	swapCanaryClockVar(t, &nowP)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	deadlineBefore, ok := rt.windowDeadline(capb)
	if !ok {
		t.Fatal("an armed activation must expose a deadline")
	}

	// Restart most of the way through the window.
	nowP = start.Add(window - time.Minute)
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()

	deadlineAfter, ok := fresh.windowDeadline(capb)
	if !ok {
		t.Fatal("the restored activation must still expose a deadline")
	}
	if !deadlineAfter.Equal(deadlineBefore) {
		t.Fatalf("SECURITY: a restart must not move the deadline (fresh window): before=%s after=%s",
			deadlineBefore, deadlineAfter)
	}
	// And the remaining lifetime is the ORIGINAL remainder, not the full window.
	if remaining := deadlineAfter.Sub(nowP); remaining > time.Minute {
		t.Fatalf("SECURITY: remaining lifetime %s exceeds the original remainder", remaining)
	}
}

// A clock that moves BACKWARD must not manufacture authority.
func TestAutoStop_ClockRollbackGrantsNoExtraAuthority(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := time.Unix(1_700_000_000, 0)
	nowP := start
	swapCanaryClockVar(t, &nowP)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Roll the clock back before the activation instant and try to reserve.
	rolled := start.Add(-time.Hour)
	if o, _ := rt.reserveCanaryExecution(capb, rolled, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: a clock rollback must not grant a reservation")
	}
}

// ── outcome_evidence_loss: the #1306 signal that used to stop nothing ─────────────────────────

// A physical invocation whose terminal outcome cannot be made durable is a whole-Canary breach.
// The invocation reached the peer; the record of what it did did not survive. The Canary can no
// longer account for its own effects, which is the one claim the experiment rests on.
//
// Before this change the condition incremented a counter whose production implementation was an
// empty method body — evidence loss was observable in principle and stopped nothing in practice.
// The fault is injected at the REAL spool backend, where a full or read-only volume would produce
// it, not at a stubbed CommitDecision.
func TestAutoStop_OutcomeEvidenceLossAbortsTheWholeCanary(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	fb := &faultyBackend{Backend: spool.NewOSBackend()}
	rig := armCanaryWithRealPeerBackend(t, p, 10, fb)
	capb := rollout.CapabilityGateway

	// CONTROL on this exact rig: while the backend is healthy the fixture executes and the Canary
	// stays un-aborted. Without it, an abort after the fault could be an artefact of the harness.
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("control: the fixture must be able to execute, out=%+v", out)
	}
	if globalCanaryRuntime.abortedNow(capb) {
		t.Fatal("control: a healthy execution must not abort the Canary")
	}

	// Fail the THIRD append of the next request: decision and send intent both commit, the
	// invocation crosses the wire, and the TERMINAL OUTCOME is what cannot be persisted.
	// Fail from the ordinal two appends ahead: this request's decision (#1) and send intent (#2)
	// commit, and the TERMINAL OUTCOME (#3) is the append that cannot be made durable.
	fb.failFrom.Store(fb.appends.Load() + 3)
	before := p.count()
	_ = rig.exec(peerExecInput(p, policy.OpRead))
	if p.count() != before+1 {
		t.Fatalf("premise: the invocation must have reached the peer, delta=%d", p.count()-before)
	}
	if !globalCanaryRuntime.abortedNow(capb) {
		t.Fatal("SECURITY: a physical invocation whose outcome evidence was lost must abort the whole Canary")
	}
	if code := globalCanaryRuntime.abortCodeNow(capb); code != "outcome_evidence_loss" {
		t.Fatalf("the first cause must be outcome_evidence_loss, got %q", code)
	}
}

// ── first cause is preserved ─────────────────────────────────────────────────────────────────

// A second breach must never rewrite why the experiment stopped. The first cause is what an
// operator investigates; a racing later breach overwriting it would send them after the wrong thing.
func TestAutoStop_FirstCausePreservedAcrossLaterBreaches(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	rt.tripCanaryAbort(capb, "scope_escape", now)
	rt.tripCanaryAbort(capb, "outcome_evidence_loss", now.Add(time.Second))
	rt.tripCanaryAbort(capb, "window_expired", now.Add(2*time.Second))
	if code := rt.abortCodeNow(capb); code != "scope_escape" {
		t.Fatalf("the FIRST cause must survive later breaches, got %q", code)
	}
}

// ── per-request refusals must NOT stop the experiment ────────────────────────────────────────

// The negative control for the whole blocker. A Canary that aborted on every fail-closed refusal
// would satisfy a naive "does a breach stop it" test while being useless: a healthy Canary produces
// policy denials all day.
func TestAutoStop_RequestScopedRefusalsNeverStopTheCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	for _, code := range []string{"policy_deny", "stale_decision", "credential_not_ready",
		"response_inspection_block", "emergency_kill_for_request", "allowance_consumed"} {
		if res := rt.tripCanaryAbort(capb, code, now); res != canary.TripRequestScoped {
			t.Fatalf("%q is a per-request refusal and must not latch, got %s", code, res)
		}
		if rt.abortedNow(capb) {
			t.Fatalf("SECURITY: %q must not stop the whole Canary", code)
		}
	}
}

// ── the health detectors reach the abort authority ───────────────────────────────────────────

// The error-rate detector must be able to stop the experiment INSIDE the three-execution corpus.
func TestAutoStop_ElevatedErrorRateAbortsWithinTheCorpus(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}
	f.AttemptSettled(capb.String(), rt.currentGeneration(capb), true, time.Second) // 1 failure — below the floor
	if rt.abortedNow(capb) {
		t.Fatal("one failure is below the sample floor and must not stop the Canary")
	}
	f.AttemptSettled(capb.String(), rt.currentGeneration(capb), false, time.Second) // 1 of 2 = 50%
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: 50% failure at the sample floor must abort within the 3-execution corpus")
	}
	if code := rt.abortCodeNow(capb); code != "elevated_error_rate" {
		t.Fatalf("first cause must be elevated_error_rate, got %q", code)
	}
}

// The latency detector, same requirement: reachable inside three executions.
func TestAutoStop_LatencyPathologyAbortsWithinTheCorpus(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}
	// One attempt at the hard limit: no floor needed.
	f.AttemptSettled(capb.String(), rt.currentGeneration(capb), false, canary.HealthLatencyHardLimit)
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: a single attempt at the hard latency limit must abort the Canary")
	}
	if code := rt.abortCodeNow(capb); code != "latency_pathology" {
		t.Fatalf("first cause must be latency_pathology, got %q", code)
	}
}

// A healthy population must never stop the experiment, however many attempts settle.
func TestAutoStop_HealthyPopulationNeverStopsTheCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}
	for i := 0; i < 5; i++ {
		f.AttemptSettled(capb.String(), rt.currentGeneration(capb), false, 100*time.Millisecond)
		if rt.abortedNow(capb) {
			t.Fatalf("a healthy attempt must not stop the Canary (i=%d)", i)
		}
	}
}

// A breach reported for the OTHER capability must not stop this one — the two are isolated.
func TestAutoStop_BreachIsCapabilityIsolated(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(rollout.CapabilityGateway, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin gateway: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: rollout.CapabilityGateway}
	f.Breach(rollout.CapabilityManagement.String(), rt.currentGeneration(rollout.CapabilityGateway), "scope_escape")
	if rt.abortedNow(rollout.CapabilityGateway) {
		t.Fatal("a breach reported for Management must never abort Gateway")
	}
}

// An UNKNOWN breach code must fail CLOSED to a whole-Canary latch: a typo may only ever stop the
// experiment, never silently let it continue.
func TestAutoStop_UnknownBreachCodeFailsClosed(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}
	f.Breach(capb.String(), rt.currentGeneration(capb), "a_code_no_taxonomy_knows")
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: an unrecognised breach code must fail closed to a whole-Canary latch")
	}
}

// ── independent_witness_mismatch: authoritative reconciliation contradicts our own record ────

// duplicateWitness is a CONTROLLED witness fixture reporting the one observation that is a
// physical-effect breach by construction: the same AttemptID invoked more than once. It is a local
// fixture, not a production witness adapter — wiring a real one is blocker #1/#8. What this proves
// is that when such a verdict eventually arrives, it ALREADY has a load-bearing path to the abort.
type duplicateWitness struct{ count int }

func (w duplicateWitness) LookupAttempt(context.Context, string) (execution.WitnessObservation, error) {
	return execution.WitnessObservation{
		Count: w.count, Complete: true, CompletenessWatermark: "w1",
		ServerID: "s1", Method: "tools/call",
	}, nil
}

func TestAutoStop_WitnessConflictAbortsTheWholeCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	ex := newReconcileTestExecutor(t, &canarySafetyFunnel{rt: rt, capb: capb})
	orphan := execution.RecoveredAttempt{
		AttemptID: "att-1", ReservationID: "res-1", ActivationGeneration: rt.currentGeneration(capb),
		State: execution.AttemptReconciliationRequired, Reconciliation: model.ReconRequired,
	}

	// CONTROL: a single observation is not a conflict and must not stop the experiment.
	ev, err := ex.ReconcileAndReport(context.Background(), duplicateWitness{count: 1}, orphan, "s1", "tools/call", capb.String(), now.UnixNano())
	if err != nil {
		t.Fatalf("reconcile (control): %v", err)
	}
	if ev.Result == model.ReconConflict {
		t.Fatalf("control: one observation is not a conflict, got %s", ev.Result)
	}
	if rt.abortedNow(capb) {
		t.Fatal("control: a non-conflicting reconciliation must not stop the Canary")
	}

	// The breach: the SAME attempt observed twice. One authorized reservation, two physical effects.
	ev, err = ex.ReconcileAndReport(context.Background(), duplicateWitness{count: 2}, orphan, "s1", "tools/call", capb.String(), now.UnixNano())
	if err != nil {
		t.Fatalf("reconcile (conflict): %v", err)
	}
	if ev.Result != model.ReconConflict {
		t.Fatalf("premise: a duplicated attempt must derive a conflict, got %s", ev.Result)
	}
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: an authoritative physical-effect contradiction must abort the whole Canary")
	}
	if code := rt.abortCodeNow(capb); code != "independent_witness_mismatch" {
		t.Fatalf("first cause must be independent_witness_mismatch, got %q", code)
	}
}

// ── budget: traffic-independent once the authority is consumed ───────────────────────────────

// The Nth request must still make the invocation it was authorized to make, and the experiment must
// then stop WITHOUT waiting for an N+1 request to discover it is over.
func TestAutoStop_BudgetExhaustionStopsWithoutAnNPlusOneRequest(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 2) // exactly two authorized executions
	capb := rollout.CapabilityGateway

	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("the 1st authorized execution must cross, out=%+v", out)
	}
	if globalCanaryRuntime.abortedNow(capb) {
		t.Fatal("the experiment must not stop while allowance remains")
	}
	// The FINAL authorized execution: it must still make its invocation.
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("SECURITY: the Nth request must not be aborted before its authorized side effect, out=%+v", out)
	}
	if p.count() != 2 {
		t.Fatalf("both authorized invocations must have reached the peer, got %d", p.count())
	}
	// And now — with NO further request — the experiment is over.
	if !globalCanaryRuntime.abortedNow(capb) {
		t.Fatal("SECURITY: once the final authorized attempt settles, the Canary must stop without an N+1 request")
	}
	if code := globalCanaryRuntime.abortCodeNow(capb); code != "budget_exhausted" {
		t.Fatalf("the automatic stop must be recorded as budget_exhausted, got %q", code)
	}
}

// A DENIED reservation must itself latch the abort, with nothing else having happened. This is
// deliberately separate from TestAutoStop_BudgetExhaustionStopsWithoutAnNPlusOneRequest: that gate
// proves the traffic-INDEPENDENT half (the latch on the final settle), and it therefore still passes
// if the reserve-site trip is deleted — the settle-site latch covers for it. Here nothing settles at
// all (the first slot is still in flight), so the only thing that can stop the experiment is the
// refusal itself. Without both gates, one of the two paths could be removed unnoticed.
func TestAutoStop_DeniedReservationItselfTripsBudgetExhausted(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(1), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("premise: the single authorized reservation must be granted, got %v", o)
	}
	// The slot is NEVER released and nothing settles, so no other latch path can fire.
	if rt.abortedNow(capb) {
		t.Fatal("premise: an in-flight authorized execution must not have stopped the experiment")
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatal("the N+1 reservation must be denied")
	}
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: a refused reservation past the allowance must stop the whole Canary")
	}
	if code := rt.abortCodeNow(capb); code != "budget_exhausted" {
		t.Fatalf("first cause must be budget_exhausted, got %q", code)
	}
}

// ── corrupt durable state must never load as healthy ─────────────────────────────────────────

// A persisted runtime record that cannot be trusted must restore to a NON-executable posture. The
// dangerous failure is the opposite: a corrupt file read as "active, not aborted".
func TestAutoStop_CorruptPersistedStateNeverLoadsAsExecutable(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Corrupt the durable record.
	if err := os.WriteFile(canaryRuntimeStatePath(capb), []byte(`{"schema_version":1,"generation":`), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: a corrupt durable record must never restore into an executable activation")
	}
	if st := canaryAbortStatusFor(capb); st.ExecutionAuthority == "granted" {
		t.Fatalf("a corrupt record must not report granted execution authority, got %+v", st)
	}
}

// ── operator truth: mode is not the whole truth after an abort ───────────────────────────────

// The status surface must never let an aborted experiment read as healthy just because the node is
// still in ModeCanary — the lifecycle transition is blockers #10/#12 and has not run.
func TestAutoStop_StatusReportsRevokedAuthorityWhileStillModeCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if st := canaryAbortStatusFor(capb); st.ExecutionAuthority != "granted" || st.Aborted {
		t.Fatalf("control: a healthy activation must report granted authority, got %+v", st)
	}
	rt.tripCanaryAbort(capb, "scope_escape", now)

	st := canaryAbortStatusFor(capb)
	if !st.Aborted {
		t.Fatal("the status must report the abort")
	}
	if st.ExecutionAuthority != "revoked" {
		t.Fatalf("an aborted Canary must report REVOKED execution authority, got %q", st.ExecutionAuthority)
	}
	if st.FirstAbortReason != "scope_escape" {
		t.Fatalf("the status must name the first cause, got %q", st.FirstAbortReason)
	}
	if st.WindowDeadlineUnix == 0 {
		t.Fatal("the status must expose the window deadline")
	}
}

// ── drift: the request fails closed AND the experiment stops ─────────────────────────────────

// realAdmissionGate builds the PRODUCTION admission gate with only the live-tier LIFECYCLE seam
// stubbed. That one seam has to go: the live tier is deliberately never armed in this build, so the
// production `admit` would reject before the trust check is ever reached, and a gate that never
// reaches the classifier proves nothing about it. Everything the drift gates are about —
// mcpLiveTrustRevalidate's own classification, the tripBreach routing, the budget reservation — is
// the real thing.
//
// The earlier version of these gates stubbed trustOK as well, which made them VACUOUS: the campaign
// mutated the real classifier and the gates passed anyway (M65/M66 survived). Stub the smallest
// thing that is in the way, never the thing under test.
func realAdmissionGate(t *testing.T, capb rollout.Capability) *mcpLiveSideEffectGate {
	t.Helper()
	g := newMCPLiveSideEffectGate(capb)
	g.admit = func() (func(), bool) { return func() {}, true }
	return g
}

// driftGateInput is one admission input against the seeded controlled target.
func driftGateInput(sid, tool, fp string, now time.Time) execution.LiveGateInput {
	return execution.LiveGateInput{
		Capability: 0, Operation: policy.OpRead, Tenant: ttTenant, Principal: liveRequester,
		ServerID: sid, ToolName: tool, Fingerprint: fp, Now: now,
	}
}

// armDriftFixture seeds the real inventory + a real four-eyes live approval and begins a real Canary
// activation, returning the gate and the reviewed identity. Everything downstream is production code.
func armDriftFixture(t *testing.T, rt *canaryRuntime, capb rollout.Capability) (g *mcpLiveSideEffectGate, sid, tool, fpHex string, now time.Time) {
	t.Helper()
	resetInventory(t)
	resetExecDeps(t)
	_, cat, sid, tool, fpHex := seedToolTrustInventory(t)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn)
	requestAndApproveLive(t, sid, tool, fpHex, cat.Current().Revision())
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	return realAdmissionGate(t, capb), sid, tool, fpHex, mcpToolTrust.now()
}

// republishToolWithNewFingerprint re-publishes the SAME server/tool with a changed input schema, so
// the live target's fingerprint no longer equals the one the request was reviewed and decided
// against. That is the rug-pull the taxonomy names.
func republishToolWithNewFingerprint(t *testing.T, sid, tool string) {
	t.Helper()
	republishTool(t, sid, tool, true, `{"type":"object","properties":{"added":{"type":"string"}}}`)
}

// republishServerDisabled re-publishes the SAME tool under a DISABLED server: the approved trust
// anchor is gone.
func republishServerDisabled(t *testing.T, sid, tool string) {
	t.Helper()
	republishTool(t, sid, tool, false, `{"type":"object"}`)
}

func republishTool(t *testing.T, sid, tool string, enabled bool, schema string) {
	t.Helper()
	en := "true"
	if !enabled {
		en = "false"
	}
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"` + ttTenant + `","servers":[
	  {"server_id":"` + sid + `","endpoint":"e","pinned_identity":"id","enabled":` + en + `,
	   "tools":[{"name":"` + tool + `","input_schema":` + schema + `}]}
	]}`))
	if err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)
}

func TestAutoStop_ToolFingerprintDriftAbortsTheWholeCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	g, sid, tool, fpHex, now := armDriftFixture(t, rt, capb)

	// PREMISE: the exact reviewed request is admitted, and admitting it stops nothing.
	d := g.AdmitSideEffect(driftGateInput(sid, tool, fpHex, now))
	if !d.Admit {
		t.Fatalf("premise: the exact reviewed request must be admitted, reason=%s", d.Reason.Code())
	}
	if d.Release != nil {
		d.Release()
	}
	if rt.abortedNow(capb) {
		t.Fatal("control: an admitted, authorized request must not stop the Canary")
	}

	// THE RUG-PULL: the live tool is no longer the reviewed tool. The request still carries the
	// fingerprint it was decided against.
	republishToolWithNewFingerprint(t, sid, tool)
	if d := g.AdmitSideEffect(driftGateInput(sid, tool, fpHex, now)); d.Admit {
		t.Fatal("a request whose reviewed fingerprint no longer matches the live tool must fail closed")
	}
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: a rug-pull is not merely a bad request — the whole Canary must stop")
	}
	if code := rt.abortCodeNow(capb); code != "tool_fingerprint_drift" {
		t.Fatalf("first cause must be tool_fingerprint_drift, got %q", code)
	}
}

func TestAutoStop_ServerIdentityDriftAbortsTheWholeCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	g, sid, tool, fpHex, now := armDriftFixture(t, rt, capb)

	if d := g.AdmitSideEffect(driftGateInput(sid, tool, fpHex, now)); !d.Admit {
		t.Fatalf("premise: the reviewed request must be admitted first, reason=%s", d.Reason.Code())
	} else if d.Release != nil {
		d.Release()
	}

	// The approved trust anchor is gone.
	republishServerDisabled(t, sid, tool)
	if d := g.AdmitSideEffect(driftGateInput(sid, tool, fpHex, now)); d.Admit {
		t.Fatal("the request must fail closed when the approved trust anchor is gone")
	}
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: losing the approved server identity must stop the whole Canary")
	}
	if code := rt.abortCodeNow(capb); code != "server_identity_drift" {
		t.Fatalf("first cause must be server_identity_drift, got %q", code)
	}
}

// THE CONTROL for both drift gates: a request that is merely UNAUTHORIZED — the reviewed target is
// intact, there is simply no live approval for it — must fail closed WITHOUT stopping the
// experiment. A Canary that aborted on every unauthorized request would be useless, and this is the
// line §16 draws. It runs the same real classifier, so it also proves the classifier distinguishes
// the two rather than the gates distinguishing them for it.
func TestAutoStop_MerelyUnauthorizedRequestDoesNotStopTheCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	resetInventory(t)
	resetExecDeps(t)
	_, _, sid, tool, fpHex := seedToolTrustInventory(t)
	_, clkFn := liveFakeClock()
	composeToolTrust(t, clkFn) // NO approval is ever requested or granted
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	g := realAdmissionGate(t, capb)

	if d := g.AdmitSideEffect(driftGateInput(sid, tool, fpHex, mcpToolTrust.now())); d.Admit {
		t.Fatal("an unauthorized request must still fail closed")
	}
	if rt.abortedNow(capb) {
		t.Fatal("SECURITY: refusing an unauthorized request must NOT stop the experiment")
	}
}

// ── credential safety ────────────────────────────────────────────────────────────────────────

// There is no production producer for credential_safety_failure today: the broker prevents
// client-token passthrough BY CONSTRUCTION rather than detecting it at runtime, and credentials are
// blocker #9. What this pins is the requirement that IS in scope — when such a signal is reported,
// it denies and stops the whole experiment, with no "continue because the next tool may not need a
// credential" path.
func TestAutoStop_CredentialSafetyFailureAbortsTheWholeCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}
	f.Breach(capb.String(), rt.currentGeneration(capb), "credential_safety_failure")
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: a credential-safety failure must stop the whole Canary")
	}
	if code := rt.abortCodeNow(capb); code != "credential_safety_failure" {
		t.Fatalf("first cause must be credential_safety_failure, got %q", code)
	}
	if o, _ := rt.reserveCanaryExecution(capb, canaryRuntimeTestNow, rtIdent); o == canary.BudgetGranted {
		t.Fatal("no further execution may be admitted after a credential-safety failure")
	}
}

// ── scope escape ─────────────────────────────────────────────────────────────────────────────

// An execution reaching an identity beyond the enumerated blast radius is containment failing, and
// containment failing ends the experiment.
func TestCanaryRuntime_ScopeEscapeTripsWholeCanaryAbort(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Consume the enumerated identities, then present one beyond them.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("control: the first in-scope identity must be granted, got %s", o)
	}
	rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	escaped := canary.ExecutionIdentity{Principal: "p-out", Tool: "t-out", Server: "s-out"}
	for i := 0; i < 8; i++ {
		if o, _ := rt.reserveCanaryExecution(capb, now, escaped); o.IdentityCapExceeded() {
			break
		}
		rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
		escaped = canary.ExecutionIdentity{
			Principal: escaped.Principal + "x", Tool: escaped.Tool + "x", Server: escaped.Server + "x",
		}
	}
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: an identity beyond the enumerated blast radius must stop the whole Canary")
	}
	if code := rt.abortCodeNow(capb); code != "scope_escape" {
		t.Fatalf("first cause must be scope_escape, got %q", code)
	}
}

// ── Codex round 1: every report is bound to the activation that produced it ───────────────────

// A breach reported by a request that outlived its activation must NOT stop the activation that
// replaced it. The engine releases lifecycle admission before its deferred outcome commit, so a
// demote-and-reactivate can complete while an in-flight request still holds an attempt record.
func TestAutoStop_StaleBreachNeverStopsTheNextActivation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	oldGen, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	newGen, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now)
	if err != nil {
		t.Fatalf("re-begin: %v", err)
	}
	if newGen == oldGen {
		t.Fatal("premise: the re-activation must be a new generation")
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}

	// The old request finally reports. It names the activation it belonged to.
	f.Breach(capb.String(), oldGen, "outcome_evidence_loss")
	if rt.abortedNow(capb) {
		t.Fatal("SECURITY: a breach from a superseded activation must not stop the one that replaced it")
	}
	// THE CONTROL: the same breach naming the CURRENT activation still stops it, so the guard is a
	// generation check and not a way to lose breaches.
	f.Breach(capb.String(), newGen, "outcome_evidence_loss")
	if !rt.abortedNow(capb) {
		t.Fatal("a breach naming the current activation must stop it")
	}
}

// Same rule for the population detectors: a settled attempt from a superseded activation must not
// enter the new activation's sample set, or one experiment's failures judge another.
func TestAutoStop_StaleSettledAttemptNeverCountsAgainstTheNextActivation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	oldGen, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("re-begin: %v", err)
	}
	f := &canarySafetyFunnel{rt: rt, capb: capb}

	// Two failures from the OLD activation would be an elevated error rate if they landed.
	f.AttemptSettled(capb.String(), oldGen, true, time.Second)
	f.AttemptSettled(capb.String(), oldGen, true, time.Second)
	if rt.abortedNow(capb) {
		t.Fatal("SECURITY: a superseded activation's failures must not stop the current one")
	}
	if s, fl, _ := rt.capRuntime(capb).health.Stats(); s != 0 || fl != 0 {
		t.Fatalf("a stale sample must not enter the new population, samples=%d failures=%d", s, fl)
	}
}

// A watchdog that fires EARLY — the wall clock moved backwards after activation, so the duration
// elapsed but the absolute deadline has not — must RE-ARM. A one-shot timer that simply returns
// leaves the activation with no watchdog and back to waiting for a request.
func TestAutoStop_EarlyWatchdogFireReArmsInsteadOfDisarming(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	fireIndex, _, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if armedCount() != 1 {
		t.Fatalf("begin must arm exactly one watchdog, got %d", armedCount())
	}
	// The timer fires EARLY: its duration elapsed in real time, but the absolute deadline has not
	// been reached (a clock that ran ahead and was corrected back, still INSIDE the window). This
	// is deliberately not a rollback BEHIND the activation instant — that closes the window at its
	// lower end and must LATCH, which
	// TestAutoStop_ClockBehindActivationLatchesAtRestoreInsteadOfArming covers.
	nowP = canaryRuntimeTestNow.Add(10 * time.Minute)
	fireIndex(0)
	if rt.abortedNow(capb) {
		t.Fatal("an early fire must not latch — the deadline has not passed")
	}
	if armedCount() != 2 {
		t.Fatalf("SECURITY: an early fire must RE-ARM the watchdog, armed=%d", armedCount())
	}
	// The replacement watchdog still stops the experiment once the deadline genuinely passes.
	nowP = canaryRuntimeTestNow.Add(2 * time.Hour)
	fireIndex(1)
	if !rt.abortedNow(capb) {
		t.Fatal("the re-armed watchdog must stop the experiment at the real deadline")
	}
	if code := rt.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("first cause must be window_expired, got %q", code)
	}
}

// The final reservation may be refused at the boundary and never send. The slot is still released,
// so the allowance is spent with nothing in flight — and the experiment must stop THERE, not wait
// for an N+1 request to discover it. Before the fix the exhaustion latch hung off the settled-
// attempt path, which deliberately excludes definitely-not-sent.
func TestAutoStop_ExhaustionLatchesWhenTheFinalSlotNeverSends(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(1), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("the single authorized reservation must be granted, got %v", o)
	}
	// The boundary refuses it — an emergency kill, a tool drift. Nothing was sent, so NO attempt
	// settles; only the slot comes back.
	rt.releaseCanaryExecution(capb, gen)
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: the allowance is spent and nothing is in flight — the experiment must stop")
	}
	if code := rt.abortCodeNow(capb); code != "budget_exhausted" {
		t.Fatalf("first cause must be budget_exhausted, got %q", code)
	}
	if st := canaryAbortStatusFor(capb); st.ExecutionAuthority != "revoked" {
		t.Fatalf("the status must not keep reporting granted authority, got %q", st.ExecutionAuthority)
	}
}

// A crash between persisting the detector counters and latching the abort leaves a record whose
// numbers already prove a breach and whose controller says the activation is healthy. Restore must
// RE-DERIVE the verdict, not trust that the previous process got as far as latching.
func TestAutoStop_RestoreReDerivesABreachTheCountersAlreadyProve(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)

	// Hand-build the crash shape: counters that prove an elevated error rate, abort NOT latched.
	st := canaryRuntimeState{
		SchemaVersion: canaryRuntimeSchemaVersion,
		Capability:    capb.String(),
		Generation:    gen,
		Active:        true,
		BuildVersion:  currentRuntimeIdentity().BuildVersion,
		Budget:        runtimeTestBudget(3),
		BudgetSnapshot: canary.BudgetSnapshot{Generation: gen, StartUnixNano: now.UnixNano(), TotalReserved: 2,
			Principals: []string{"p1"}, Tools: []string{"t1"}, Servers: []string{"s1"}},
		AbortSnapshot:  canary.AbortSnapshot{Generation: gen},
		HealthSnapshot: canary.HealthSnapshot{Generation: gen, Samples: 2, Failures: 2, LatencySumNs: int64(2 * time.Second)},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()

	if !fresh.abortedNow(capb) {
		t.Fatal("SECURITY: a restored population that already proves a breach must latch, not resume")
	}
	if code := fresh.abortCodeNow(capb); code != "elevated_error_rate" {
		t.Fatalf("the re-derived first cause must name the breach the counters prove, got %q", code)
	}
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: such an activation must not grant execution")
	}
}

// A health snapshot that is absent, foreign-generation or damaged must refuse the whole restore.
// Restoring with a CLEARED detector is execution authority with the evidence wiped.
func TestAutoStop_DamagedHealthSnapshotNeverRestoresAsExecutable(t *testing.T) {
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	for name, snap := range map[string]canary.HealthSnapshot{
		"absent":             {},
		"foreign generation": {Generation: 99, Samples: 1},
		"damaged counters":   {Generation: 1, Samples: 1, Failures: 5},
	} {
		t.Run(name, func(t *testing.T) {
			rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
			st := canaryRuntimeState{
				SchemaVersion:  canaryRuntimeSchemaVersion,
				Capability:     capb.String(),
				Generation:     1,
				Active:         true,
				BuildVersion:   currentRuntimeIdentity().BuildVersion,
				Budget:         runtimeTestBudget(3),
				BudgetSnapshot: canary.BudgetSnapshot{Generation: 1, StartUnixNano: now.UnixNano()},
				AbortSnapshot:  canary.AbortSnapshot{Generation: 1},
				HealthSnapshot: snap,
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			fresh := &canaryRuntime{}
			globalCanaryRuntime = fresh
			fresh.restore()
			if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
				t.Fatalf("SECURITY: a %s health snapshot must not restore into an executable activation", name)
			}
			if s := canaryAbortStatusFor(capb); s.ExecutionAuthority == "granted" {
				t.Fatalf("SECURITY: a %s health snapshot must not report granted authority", name)
			}
			_ = rt
		})
	}
}

// Failing to persist a below-threshold observation is not a logging matter: the counters are
// declared restart-durable safety state, and a restart that loses them lets the detector treat the
// next bad attempt as the first sample. The durable record is removed so a restart restores nothing.
func TestAutoStop_HealthPersistFailureFailsClosed(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); err != nil {
		t.Fatalf("premise: begin must have written a durable record: %v", err)
	}
	prev := canaryRuntimePersist
	canaryRuntimePersist = func(_ *canaryRuntime, _ rollout.Capability, _ *canaryCapRuntime) error {
		return errors.New("injected health persist failure")
	}
	t.Cleanup(func() { canaryRuntimePersist = prev })

	// ONE failure — below the floor, so nothing trips and the old code would only have logged.
	f := &canarySafetyFunnel{rt: rt, capb: capb}
	f.AttemptSettled(capb.String(), gen, true, time.Second)

	if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
		t.Fatal("SECURITY: a failed health persist must remove the durable record so a restart cannot resume with stale evidence")
	}
	canaryRuntimePersist = prev
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: a restart after a failed health persist must not revive an executable activation")
	}
}

// ── Codex round 2 ─────────────────────────────────────────────────────────────────────────────

// A request admitted just before the deadline must NOT reach the upstream after it. The watchdog is
// asynchronous and time.AfterFunc gives no ordering guarantee against the request goroutine, so the
// final boundary evaluates the absolute deadline itself rather than trusting the latch to have
// already happened.
func TestAutoStop_ExpiredWindowStopsAnAlreadyAdmittedRequestAtTheBoundary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	// The watchdog is captured and never fired: this gate is about the BOUNDARY, and firing the
	// timer would prove the watchdog instead.
	_, _, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)
	if o, _ := rt.reserveCanaryExecution(capb, canaryRuntimeTestNow, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("premise: a reservation inside the window must be granted, got %v", o)
	}
	if !rt.generationActive(capb, gen) {
		t.Fatal("premise: the admitted request must pass the boundary while the window is open")
	}
	if armedCount() != 1 {
		t.Fatalf("premise: exactly one watchdog armed, got %d", armedCount())
	}

	// The window elapses while the request sits between admission and preCallGuard. The watchdog
	// has NOT run — that is the whole point.
	nowP = canaryRuntimeTestNow.Add(2 * time.Hour)
	if rt.generationActive(capb, gen) {
		t.Fatal("SECURITY: an already-admitted request must not cross the boundary after the window expired")
	}
	if rt.abortedNow(capb) {
		t.Fatal("premise check: the watchdog was never fired, so this gate is proving the boundary, not the latch")
	}
}

// A health snapshot claiming more samples than the activation ever reserved is damaged in the one
// direction that makes the detector LESS likely to fire: fabricated clean samples dilute a real
// failure rate below the threshold. Valid() cannot see it — the invariant is across two snapshots.
func TestAutoStop_InflatedSampleCountNeverRestoresAsExecutable(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)
	st := canaryRuntimeState{
		SchemaVersion: canaryRuntimeSchemaVersion,
		Capability:    capb.String(),
		BuildVersion:  currentRuntimeIdentity().BuildVersion,
		Generation:    gen,
		Active:        true,
		Budget:        runtimeTestBudget(3),
		// ONE reservation was actually made…
		BudgetSnapshot: canary.BudgetSnapshot{Generation: gen, StartUnixNano: now.UnixNano(), TotalReserved: 1,
			Principals: []string{"p1"}, Tools: []string{"t1"}, Servers: []string{"s1"}},
		AbortSnapshot: canary.AbortSnapshot{Generation: gen},
		// …but the detector claims a hundred clean samples, which would dilute the next two
		// failures to 2/102 instead of the 1/2 that must stop the experiment.
		HealthSnapshot: canary.HealthSnapshot{Generation: gen, Samples: 100},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()

	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: a health snapshot claiming more samples than reservations must not restore into an executable activation")
	}
	if s := canaryAbortStatusFor(capb); s.ExecutionAuthority == "granted" {
		t.Fatalf("such a record must not report granted authority, got %q", s.ExecutionAuthority)
	}
}

// THE CONTROL: samples EQUAL to the reservations is the ordinary healthy shape (every reservation
// settled), and fewer is normal too (a reservation refused at the boundary settles nothing). Neither
// may be refused, or an ordinary restart would disarm a healthy experiment.
func TestAutoStop_HonestSampleCountsStillRestore(t *testing.T) {
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	for name, sn := range map[string]struct{ reserved, samples int }{
		"every reservation settled": {reserved: 2, samples: 2},
		"one never settled":         {reserved: 2, samples: 1},
		"nothing settled yet":       {reserved: 1, samples: 0},
	} {
		t.Run(name, func(t *testing.T) {
			rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
			if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), now); err != nil {
				t.Fatalf("begin: %v", err)
			}
			gen := rt.currentGeneration(capb)
			st := canaryRuntimeState{
				SchemaVersion: canaryRuntimeSchemaVersion,
				Capability:    capb.String(),
				BuildVersion:  currentRuntimeIdentity().BuildVersion,
				Generation:    gen,
				Active:        true,
				Budget:        runtimeTestBudget(9),
				BudgetSnapshot: canary.BudgetSnapshot{Generation: gen, StartUnixNano: now.UnixNano(), TotalReserved: sn.reserved,
					Principals: []string{"p1"}, Tools: []string{"t1"}, Servers: []string{"s1"}},
				AbortSnapshot:  canary.AbortSnapshot{Generation: gen},
				HealthSnapshot: canary.HealthSnapshot{Generation: gen, Samples: sn.samples},
			}
			raw, err := json.Marshal(st)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			fresh := &canaryRuntime{}
			globalCanaryRuntime = fresh
			fresh.restore()
			if !fresh.armed(capb) {
				t.Fatalf("an honest record (%s) must still restore — refusing it would disarm a healthy experiment", name)
			}
		})
	}
}

// ── Codex round 3 ─────────────────────────────────────────────────────────────────────────────

// The observation and the latch it proves are ONE critical section. Split, a third request could
// take cr.mu between them, reserve the remaining slot and pass the final boundary while the
// population had already proved the Canary must stop.
func TestAutoStop_HealthBreachLatchesUnderTheSameLockAsTheObservation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)
	f := &canarySafetyFunnel{rt: rt, capb: capb}

	f.AttemptSettled(capb.String(), gen, true, time.Second) // 1 failure, below the floor
	if rt.abortedNow(capb) {
		t.Fatal("one failure is below the floor")
	}
	// The observation that proves the breach must leave the runtime ALREADY latched: the funnel
	// performs no second step, so there is no window for a racing reservation.
	f.AttemptSettled(capb.String(), gen, false, time.Second) // 1 of 2 = 50%
	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: the observation that proves the breach must latch it, not hand a code to a later step")
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o == canary.BudgetGranted {
		t.Fatal("SECURITY: no reservation may be granted once the population proved the breach")
	}
}

// The final boundary must refuse a clock that rolled back BEHIND the activation instant, not only
// one that ran past the deadline. Every other gate in the runtime treats negative elapsed time as a
// closed window; the boundary must agree or an already-admitted request crosses during exactly that
// condition.
func TestAutoStop_ClockRollbackBehindActivationClosesTheBoundary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	_, _, _ = swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	gen := rt.currentGeneration(capb)
	if o, _ := rt.reserveCanaryExecution(capb, canaryRuntimeTestNow, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("premise: the reservation must be granted, got %v", o)
	}
	if !rt.generationActive(capb, gen) {
		t.Fatal("premise: the boundary is open while the clock is sane")
	}
	// The clock rolls back BEHIND the activation instant while the request is in flight.
	nowP = canaryRuntimeTestNow.Add(-time.Minute)
	if rt.generationActive(capb, gen) {
		t.Fatal("SECURITY: a clock rolled back behind the activation must close the boundary, not merely the upper deadline")
	}
}

// ── Codex round 4 ─────────────────────────────────────────────────────────────────────────────

// A clock rolled back BEHIND the persisted activation instant closes every admission, so the
// activation must LATCH at restore rather than arm a watchdog for a deadline that still looks
// distant. Otherwise the status surface reports granted authority on a Canary that cannot execute
// at all — and the watchdog callback, repeating the same one-ended check, re-arms forever.
func TestAutoStop_ClockBehindActivationLatchesAtRestoreInsteadOfArming(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	_, _, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if armedCount() != 1 {
		t.Fatalf("premise: a healthy activation arms one watchdog, got %d", armedCount())
	}

	// Restart with the clock BEHIND the activation instant. The deadline is still an hour away by
	// the upper-bound test, but the window is not open.
	nowP = canaryRuntimeTestNow.Add(-time.Hour)
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()

	if !fresh.abortedNow(capb) {
		t.Fatal("SECURITY: a clock behind the activation closes every admission — the activation must latch, not arm")
	}
	if code := fresh.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("first cause must be window_expired, got %q", code)
	}
	if st := canaryAbortStatusFor(capb); st.ExecutionAuthority == "granted" {
		t.Fatal("SECURITY: the status must not report granted authority while every admission is closed")
	}
	if o, _ := fresh.reserveCanaryExecution(capb, nowP, rtIdent); o == canary.BudgetGranted {
		t.Fatal("no reservation may be granted")
	}
}

// The same rollback reached WITHOUT a restart: the activation is armed and healthy, the clock rolls
// back behind the activation instant while the process runs, and the watchdog then fires. The
// callback must LATCH, not re-arm — otherwise it re-arms on every fire, forever, while every
// admission is closed and the status surface keeps reporting granted authority. This is the path
// the restore gate cannot reach, and the reason the callback consults a window-open-aware accessor
// rather than the bare deadline.
func TestAutoStop_WatchdogFiringUnderRollbackLatchesInsteadOfReArming(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	fireIndex, _, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if armedCount() != 1 {
		t.Fatalf("premise: one watchdog armed, got %d", armedCount())
	}
	// The clock rolls back BEHIND the activation instant while the activation is live.
	nowP = canaryRuntimeTestNow.Add(-time.Hour)
	fireIndex(0)

	if !rt.abortedNow(capb) {
		t.Fatal("SECURITY: a watchdog firing while the window is closed at its LOWER end must latch, not re-arm")
	}
	if code := rt.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("first cause must be window_expired, got %q", code)
	}
	if armedCount() != 1 {
		t.Fatalf("a latching callback must not also arm a replacement watchdog, armed=%d", armedCount())
	}
}

// THE CONTROL: a clock inside the window still arms a watchdog and grants authority, so the
// two-ended predicate cannot be satisfied by latching everything.
func TestAutoStop_ClockInsideTheWindowStillArmsNormally(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	_, _, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	nowP = canaryRuntimeTestNow.Add(time.Minute) // inside the 1h window
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()

	if fresh.abortedNow(capb) {
		t.Fatal("an activation restored INSIDE its window must not latch")
	}
	if armedCount() < 2 {
		t.Fatalf("the restore must arm a watchdog for the remaining time, armed=%d", armedCount())
	}
	if st := canaryAbortStatusFor(capb); st.ExecutionAuthority != "granted" {
		t.Fatalf("a healthy restored activation still holds authority, got %q", st.ExecutionAuthority)
	}
}

// A reservation that arrives after the deadline must record window_expired, not budget_exhausted.
// Both are whole-Canary stops, but the first cause is IMMUTABLE, so folding them together made the
// operator-visible reason depend on a race: whoever noticed first — this admission or the watchdog —
// decided what the same underlying fact was called.
func TestAutoStop_WindowDenialAtAdmissionRecordsWindowExpired(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	// The watchdog is captured and never fired: this gate is about the ADMISSION path naming the
	// cause, and firing the timer would let the watchdog name it instead.
	_, _, _ = swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(9), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Plenty of allowance remains — only the time box has closed.
	past := canaryRuntimeTestNow.Add(2 * time.Hour)
	nowP = past
	if o, _ := rt.reserveCanaryExecution(capb, past, rtIdent); o != canary.BudgetDeniedWindow {
		t.Fatalf("premise: a reserve past the window must be denied on window, got %v", o)
	}
	if !rt.abortedNow(capb) {
		t.Fatal("a window denial is a whole-Canary stop")
	}
	if code := rt.abortCodeNow(capb); code != "window_expired" {
		t.Fatalf("the time box closing must be recorded as window_expired, not %q — "+
			"the cause must not depend on whether admission or the watchdog noticed first", code)
	}
}

// THE CONTROL: a genuine allowance exhaustion still records budget_exhausted, so the split cannot
// be satisfied by renaming everything.
func TestAutoStop_TotalExhaustionStillRecordsBudgetExhausted(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := canaryRuntimeTestNow
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(1), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("premise: the single reservation must be granted, got %v", o)
	}
	// The slot is held in flight so the release-site latch cannot fire first.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedTotal {
		t.Fatalf("premise: the N+1 must be denied on total, got %v", o)
	}
	if code := rt.abortCodeNow(capb); code != "budget_exhausted" {
		t.Fatalf("a spent allowance must still be budget_exhausted, got %q", code)
	}
}

// TestAutoStop_StatusIsNeverMoreOptimisticThanAdmission is the gate for the operator surface's own
// window predicate.
//
// The rollback fixes taught the boundary, the arm path and the watchdog callback to use the
// enforcer's two-ended WindowOpen. The STATUS builder kept testing only the upper deadline, so in
// the interval between a clock rolling behind the activation instant and the one-shot watchdog
// firing — which with a long window is the whole remaining timer duration — every reservation was
// already denied while the surface rendered window_expired:false and execution_authority:"granted"
// (Codex round 6 P2). That interval is exactly when an operator reads this to decide whether to
// intervene, and it was the one moment the surface lied.
//
// The timer is swapped and deliberately NEVER fired, so nothing can latch: this pins what the
// status reports on its own, from the same predicate admission uses.
func TestAutoStop_StatusIsNeverMoreOptimisticThanAdmission(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	nowP := canaryRuntimeTestNow
	swapCanaryClockVar(t, &nowP)
	_, _, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), canaryRuntimeTestNow); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if armedCount() != 1 {
		t.Fatalf("premise: a healthy activation arms one watchdog, got %d", armedCount())
	}
	// THE CONTROL, in the same test so a fix cannot satisfy it by reporting expiry always: inside
	// the window the surface reports a live experiment.
	if st := canaryAbortStatusFor(capb); st.WindowExpired || st.ExecutionAuthority != "granted" {
		t.Fatalf("premise: an open window must report a live experiment, got expired=%v authority=%q",
			st.WindowExpired, st.ExecutionAuthority)
	}

	// The clock rolls BEHIND the activation instant. The watchdog is never fired, so the abort
	// latch is untouched — this is purely what the surface says on its own.
	nowP = canaryRuntimeTestNow.Add(-time.Hour)
	if rt.abortedNow(capb) {
		t.Fatal("premise: nothing may have latched — the watchdog was never fired")
	}

	// THE STATUS IS READ FIRST, BEFORE ANY REQUEST, and that ordering is the whole gate.
	//
	// A reservation attempt would itself latch window_expired, after which the surface reports
	// revoked authority for the ORDINARY reason and this test would pass against a status builder
	// that never learned the window at all. That is the round-5 lesson repeating one test later: a
	// fixture that reaches the right answer through the wrong path proves nothing. The interval
	// Codex named is precisely the one where NOTHING has arrived to latch — no traffic, no timer —
	// and the operator is reading the surface to decide whether to intervene.
	st := canaryAbortStatusFor(capb)
	if !st.WindowExpired {
		t.Fatal("SECURITY: admission is closed and the surface reports the window open — " +
			"an operator reading this sees a running experiment that cannot run")
	}
	if st.ExecutionAuthority == "granted" {
		t.Fatalf("SECURITY: no reservation can be granted, so authority is not granted, got %q",
			st.ExecutionAuthority)
	}
	if rt.abortedNow(capb) {
		t.Fatal("the surface must report the closed window WITHOUT latching — reporting is not " +
			"deciding, and the abort controller stays the one authority")
	}

	// Only now confirm the surface was describing something real: admission is in fact closed.
	if o, _ := rt.reserveCanaryExecution(capb, nowP, rtIdent); o == canary.BudgetGranted {
		t.Fatal("the surface reported a closed window; a reservation must actually be denied")
	}
}

// TestAutoStop_WatchdogDecidesEveryBranchFromOneClockSample pins the single-sample discipline in the
// watchdog callback.
//
// The callback has to decide four things about the same instant: is the window open, is the deadline
// still ahead, how long is left, and when did the trip happen. Read separately those were FOUR clock
// samples, and a wall-clock step landing between any two of them lets the callback pick contradictory
// branches — the first sample says the window is open while the next is already behind the activation
// instant, so it treats the fire as early and re-arms for a duration measured against the ROLLED-BACK
// clock. On a one-hour window that is a two-hour sleep on a Canary that cannot admit anything (Codex
// round 12).
//
// The observable is the re-armed duration: with one sample it is the true remainder measured at that
// instant; with the split samples it is the remainder measured from before the activation began.
func TestAutoStop_WatchdogDecidesEveryBranchFromOneClockSample(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	start := canaryRuntimeTestNow
	budget := runtimeTestBudget(3)
	window := budget.Window

	// The clock is normal for the activation, then steps: the callback's FIRST read lands inside
	// the window, and every later read is an hour BEFORE the activation instant.
	inside := start.Add(window / 2)
	rolledBack := start.Add(-time.Hour)
	nowP := start
	swapCanaryClockVar(t, &nowP)
	fireIndex, armedFor, armedCount := swapCanaryTimer(t)
	if _, err := rt.beginCanaryActivation(capb, budget, start); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if armedCount() != 1 {
		t.Fatalf("premise: a healthy activation arms one watchdog, got %d", armedCount())
	}

	swapCanaryClockSeq(t, inside, rolledBack)
	fireIndex(0)

	if armedCount() != 2 {
		t.Fatalf("the callback fired inside the window, so it must RE-ARM, armed=%d", armedCount())
	}
	want := start.Add(window).Sub(inside) // the true remainder at the instant the callback decided
	if got := armedFor(); got != want {
		t.Fatalf("SECURITY: the watchdog was re-armed for %v, want %v — a clock step between the "+
			"callback's reads let it measure the remaining window from an instant it had already "+
			"rejected, scheduling the only traffic-independent stop far past the real deadline",
			got, want)
	}
}
