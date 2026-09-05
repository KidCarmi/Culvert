package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// §20 concurrency / race matrix + §22 red-team for the LIVE-tier phase. Run under -race. The
// concurrency tests use channels/barriers and deterministic counts (not timing sleeps): the budget
// enforcer + lifecycle admission are serialized, so the number of executions that cross the boundary
// is an EXACT function of the budget, whatever the interleaving.

// §20: concurrent executions respect the whole-Canary budget.
//
// The security invariant is an INEQUALITY — at most `total` executions may cross
// the boundary, whatever the interleaving. It is deliberately NOT an equality, and
// the reason is worth stating because this test used to assert one:
//
// When more requests race than the budget allows, the reservation that exhausts the
// budget TRIPS the whole-Canary abort (`budget_exhausted`). Once latched, the
// boundary's generation revalidation refuses every request still in flight —
// including ones that already hold a granted reservation. So an over-budget burst
// can legitimately end with FEWER physical effects than the budget, down to zero,
// while the slots are still consumed (conservative consumption, §12).
//
// Whether that happens is a race between the abort latching and the in-flight
// requests reaching the wire, so `== total` was only ever true when the window
// between reservation and send was narrow. Committing the durable send intent in
// that window (review blocker #8) widened it, which is what made the old assertion
// fail — the behavior it was pinning was never guaranteed. The intent commit's
// position is frozen by the boundary ordering and must not move to make an equality
// hold: policy/trust/budget → durable send intent → freshness → generation
// revalidation → emergency kill → Upstream.Call.
//
// Restoring `== total` here would therefore make the abort controller doing its job
// look like a failure, and the pressure would be to weaken the abort.
func TestLiveRace_ConcurrentExecutionsRespectBudget(t *testing.T) {
	const total = 3
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, total)
	ex := cfg.Deps.Executor
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in := liveExecInput(policy.OpRead, "t1", "p1")
			_ = ex.Execute(context.Background(), in, ex.Resolve(in))
		}()
	}
	wg.Wait()

	if got := up.callCount(); got > total {
		t.Fatalf("PHYSICAL EFFECT BREACH: at most %d executions may cross the boundary, got %d", total, got)
	}
	// The shortfall must be EXPLAINED, not merely tolerated. Exactly `total` slots
	// must have been consumed: that is what distinguishes "the abort stopped them"
	// from "executions silently vanished", and without it the inequality above would
	// hide the second case entirely.
	cr := globalCanaryRuntime.capRuntime(rollout.CapabilityGateway)
	cr.mu.Lock()
	spent := cr.enforcer.TotalReserved()
	cr.mu.Unlock()
	if spent != total {
		t.Fatalf("exactly %d reservations must be consumed regardless of interleaving, got %d", total, spent)
	}
}

// §20: the LIVENESS half, where it is actually guaranteed. With exactly as many
// racers as slots nothing exhausts the budget, so nothing trips the abort and every
// admitted request must reach the upstream.
//
// This is the positive control for the inequality above: without it, that gate would
// pass on a build where NO execution can ever cross the boundary.
func TestLiveRace_RacersEqualToBudgetAllCross(t *testing.T) {
	const total = 3
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, total)
	ex := cfg.Deps.Executor
	var wg sync.WaitGroup
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			in := liveExecInput(policy.OpRead, "t1", "p1")
			_ = ex.Execute(context.Background(), in, ex.Resolve(in))
		}()
	}
	wg.Wait()
	if got := up.callCount(); got != total {
		t.Fatalf("with %d racers for %d slots every request must cross, got %d", total, total, got)
	}
}

// §20: arm vs quiesce vs admit vs release under contention — no data race, consistent final state.
func TestLiveRace_ArmQuiesceAdmitStress(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = lt.arm(true, "armed")
				if rel, ok := lt.admitExecution(); ok {
					rel()
				}
				_ = lt.quiesce(func(func() int) int { return 0 })
			}
		}()
	}
	wg.Wait()
	// Final consistency: the lifecycle-object armed view and the execdeps bit agree, and the in-flight
	// count is balanced back to zero.
	if lt.armed() != liveExecDepsConfigured(false) {
		t.Fatalf("armed view (%v) and execdeps bit (%v) diverged under contention", lt.armed(), liveExecDepsConfigured(false))
	}
	if lt.inFlightCount() != 0 {
		t.Fatalf("in-flight count must balance back to 0, got %d", lt.inFlightCount())
	}
}

// §20: a rollback (demote) concurrent with executions — no execution proceeds after the generation
// is invalidated, and no data race.
func TestLiveRace_RollbackWhileRequestsInFlight(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 1000)
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway
	var started sync.WaitGroup
	var done sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 6; i++ {
		started.Add(1)
		done.Add(1)
		go func() {
			started.Done()
			defer done.Done()
			in := liveExecInput(policy.OpRead, "t1", "p1")
			for {
				select {
				case <-stop:
					return
				default:
					_ = ex.Execute(context.Background(), in, ex.Resolve(in))
				}
			}
		}()
	}
	started.Wait()
	// Demote concurrently; then stop the workers.
	if err := globalCanaryRuntime.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	close(stop)
	done.Wait()
	// After the demotion is observed, no NEW execution can be granted a budget slot.
	postCalls := up.callCount()
	in := liveExecInput(policy.OpRead, "t1", "p1")
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != postCalls {
		t.Fatalf("no execution may cross the boundary after the generation is invalidated, delta=%d", up.callCount()-postCalls)
	}
}

// ── §22 red-team: each attack maps to a defending gate; none may reach the upstream. ──

// approval revoked between preflight and the call: the runtime trust revalidation at the boundary
// denies even though the transition preflight passed.
func TestLiveRedTeam_ApprovalRevokedAfterPreflight(t *testing.T) {
	up := &recordingUpstream{}
	// trustOK starts true, then a shared flag flips it to simulate a revoke after admission of the
	// activation but before the boundary revalidation.
	var revoked atomic.Bool
	cfg := armCanaryLiveTierTrust(t, up, func() bool { return !revoked.Load() }, 10)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	// First call: trusted ⇒ executes.
	if out := ex.Execute(context.Background(), in, ex.Resolve(in)); !out.Executed {
		t.Fatalf("baseline trusted call must execute, out=%+v", out)
	}
	// Revoke, then call again: the boundary revalidation denies (Upstream.Call unchanged).
	revoked.Store(true)
	before := up.callCount()
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != before || out.Reason != mcperr.ReasonLiveTrustRevalidationFailed {
		t.Fatalf("a revoked approval must deny at the boundary, calls delta=%d reason=%s", up.callCount()-before, out.Reason.Code())
	}
}

// an OpControl operation disguised in the read RiskClass bucket is rejected by the per-request
// read-first gate (never the server readOnlyHint).
func TestLiveRedTeam_ControlDisguisedInReadBucket(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpControl, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 || out.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("OpControl must be rejected by read-first, calls=%d reason=%s", up.callCount(), out.Reason.Code())
	}
}

// an execution attempted while quiescing is rejected (attacker races a quiesce to slip a request in).
func TestLiveRedTeam_ExecutionDuringQuiesceRejected(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	// Quiesce first (unarms + closes admission), then attempt an execution.
	_ = quiesceLiveTier(rollout.CapabilityGateway, time.Second)
	in := liveExecInput(policy.OpRead, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 {
		t.Fatalf("a quiesced tier must admit no execution, calls=%d", up.callCount())
	}
	if out.Reason != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("quiesce refusal reason=%s want rollout_mode_invalid", out.Reason.Code())
	}
}

// an old Canary generation cannot be resurrected: after a demotion, restore does not re-arm.
func TestLiveRedTeam_OldGenerationNotResurrectedOnRestore(t *testing.T) {
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	capb := rollout.CapabilityGateway
	if _, err := globalCanaryRuntime.beginCanaryActivation(capb, runtimeTestBudget(10), time.Unix(0, 1)); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := globalCanaryRuntime.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	// A restart re-reads durable state; the demoted generation must not come back armed.
	globalCanaryRuntime.restore()
	if globalCanaryRuntime.armed(capb) || globalCanaryRuntime.executionEligible(capb, time.Unix(0, 1)) {
		t.Fatal("a demoted generation must never resurrect as armed/eligible on restore (CP replay / restart)")
	}
}

// armCanaryLiveTierTrust is armCanaryLiveTier with a caller-controlled trust predicate (for the
// revoke-after-preflight red-team). Everything else is the real production path.
func armCanaryLiveTierTrust(t *testing.T, up *recordingUpstream, trust func() bool, budgetTotal int) *mcpruntime.Config {
	t.Helper()
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())
	gw := getMCPRollout().gateway
	prevCfg := gw.CurrentConfig()
	if err := gw.SetConfig(*gwCanaryCfg(1), "test", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("SetConfig canary: %v", err)
	}
	t.Cleanup(func() { _ = gw.SetConfig(prevCfg, "test-restore", time.Unix(0, 2).UnixNano()) })
	gate := liveRealGate(rollout.CapabilityGateway, true)
	gate.trustOK = func(string, string, string, string, time.Time) bool { return trust() }
	cfg := &mcpruntime.Config{}
	if err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream: up, Events: liveTestEvents(t),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
		LiveGate:        gate,
	}); err != nil {
		t.Fatalf("compose: %v", err)
	}
	if err := mcpLiveTierFor(rollout.CapabilityGateway).arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if _, err := globalCanaryRuntime.beginCanaryActivation(rollout.CapabilityGateway, runtimeTestBudget(budgetTotal), time.Unix(0, 1)); err != nil {
		t.Fatalf("begin: %v", err)
	}
	return cfg
}
