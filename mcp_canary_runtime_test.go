package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// rtIdent is a single fixed execution identity for runtime tests not exercising the identity
// caps (runtimeTestBudget caps each dimension at 1, so reusing it keeps the distinct count at 1).
var rtIdent = canary.ExecutionIdentity{Principal: "p1", Tool: "t1", Server: "s1"}

// withCanaryRuntimeTestEnv points dataDir + the global canary runtime at fresh state and pins a
// deterministic build version, restoring all three on cleanup.
func withCanaryRuntimeTestEnv(t *testing.T, buildVer string) *canaryRuntime {
	t.Helper()
	prevDir, prevVer, prevCommit, prevRt := dataDir, version, buildCommit, globalCanaryRuntime
	dataDir = t.TempDir()
	version = buildVer
	buildCommit = testBuildCommit // composed identity = "<buildVer>+<commit>" so currentRuntimeIdentity().Valid() (Codex P1, round-22)
	globalCanaryRuntime = &canaryRuntime{}
	t.Cleanup(func() { dataDir = prevDir; version = prevVer; buildCommit = prevCommit; globalCanaryRuntime = prevRt })
	// Every test in this file activates at canaryRuntimeTestNow. Pin the auto-stop clock to it, or
	// the absolute window deadline derived from that activation instant is years in the past
	// against the real clock and each activation would begin life window_expired — which is
	// CORRECT behaviour being applied to a fake activation instant. Tests that exercise the window
	// itself override this with swapCanaryClockVar and move time explicitly.
	swapCanaryClock(t, func() time.Time { return canaryRuntimeTestNow })
	return globalCanaryRuntime
}

// canaryRuntimeTestNow is the single activation instant this file's tests operate at.
var canaryRuntimeTestNow = time.Unix(1_700_000_000, 0)

func runtimeTestBudget(total int) canary.Budget {
	return canary.Budget{
		MaxTotalExecutions:      total,
		MaxExecutionsPerMinute:  1000,
		MaxConcurrentExecutions: 1000,
		MaxPrincipals:           1, MaxTools: 1, MaxServers: 1,
		Window: time.Hour,
	}
}

// TestCanaryRuntime_DormantDefault proves the shipped posture: with no activation, no generation
// exists, nothing is execution-eligible, and a reserve is denied (nothing is armed).
func TestCanaryRuntime_DormantDefault(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	if rt.currentGeneration(capb) != 0 {
		t.Fatal("no activation ⇒ generation 0")
	}
	if rt.executionEligible(capb, time.Now()) {
		t.Fatal("a dormant runtime must never be execution-eligible")
	}
	if o, _ := rt.reserveCanaryExecution(capb, time.Unix(1, 0), rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("a reserve with no activation must be denied, got %s", o)
	}
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
		t.Fatal("a dormant runtime must not create durable state merely by being read")
	}
}

// TestCanaryRuntime_BudgetExhaustionTripsWholeCanaryAbort integrates §3+§4: reserving up to the
// total cap grants exactly N, the N+1th exhausts the budget which TRIPS the whole-Canary abort, and
// once aborted the runtime is no longer execution-eligible (future execution immediately ineligible).
func TestCanaryRuntime_BudgetExhaustionTripsWholeCanaryAbort(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	const N = 4
	gen, err := rt.beginCanaryActivation(capb, runtimeTestBudget(N), now)
	if err != nil {
		t.Fatalf("beginCanaryActivation: %v", err)
	}
	if gen != 1 {
		t.Fatalf("first activation must be generation 1, got %d", gen)
	}
	for i := 0; i < N; i++ {
		if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
			t.Fatalf("reserve %d of %d must be granted, got %s", i+1, N, o)
		}
		rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	}
	// The N+1th exhausts the budget → whole-Canary abort.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedTotal {
		t.Fatalf("the N+1th reserve must be denied on total, got %s", o)
	}
	if rt.executionEligible(capb, now) {
		t.Fatal("budget exhaustion must trip the whole-Canary abort — no longer eligible")
	}
	// Every later reserve is denied because the Canary is aborted (not merely out of budget).
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("an aborted Canary must deny every reserve, got %s", o)
	}
}

// TestCanaryRuntime_WindowExpiryEndsEligibility is the Codex P2 (round-13) proof: an activation with
// total budget remaining but whose time-boxed Window has elapsed is NOT execution-eligible, so the
// status surface never reports execution_eligible:true for a Canary whose every reserve would return
// BudgetDeniedWindow. The window is part of eligibility, not merely of a per-request Reserve.
func TestCanaryRuntime_WindowExpiryEndsEligibility(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	b := runtimeTestBudget(100) // plenty of total slots remain; only the window will end eligibility
	if _, err := rt.beginCanaryActivation(capb, b, now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Inside the window (Window == 1h): eligible, with slots to spare.
	if !rt.executionEligible(capb, now.Add(59*time.Minute)) {
		t.Fatal("an armed activation inside its window with slots remaining must be eligible")
	}
	// Past the window: NOT eligible even though the total budget is untouched.
	if rt.executionEligible(capb, now.Add(time.Hour+time.Second)) {
		t.Fatal("SECURITY: an activation past its window must not be execution-eligible (every reserve denies on window)")
	}
	// A reserve at that instant confirms the window gate agrees with the eligibility read.
	if o, _ := rt.reserveCanaryExecution(capb, now.Add(time.Hour+time.Second), rtIdent); o != canary.BudgetDeniedWindow {
		t.Fatalf("a reserve past the window must be denied on window, got %s", o)
	}
	// A backward clock step (now earlier than the activation instant) also ends eligibility.
	if rt.executionEligible(capb, now.Add(-time.Second)) {
		t.Fatal("SECURITY: a backward clock step must not be execution-eligible (fail closed)")
	}
}

// TestCanaryRuntime_ThrottleEndsEligibility is the Codex round-14 P2 proof: an activation whose
// MaxConcurrentExecutions is filled (or whose per-minute rate is spent) is NOT execution-eligible even
// with total budget and window remaining, because every reserve would deny on the throttle. The
// eligibility read must reflect the throttle gates, not just abort/total/window.
func TestCanaryRuntime_ThrottleEndsEligibility(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	b := runtimeTestBudget(100) // plenty of total/window; concurrency is the binding gate
	b.MaxConcurrentExecutions = 1
	if _, err := rt.beginCanaryActivation(capb, b, now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if !rt.executionEligible(capb, now) {
		t.Fatal("a fresh activation with budget must be execution-eligible")
	}
	// Reserve one and do NOT release: the single concurrency slot is now filled.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("reserve must be granted, got %s", o)
	}
	if rt.executionEligible(capb, now) {
		t.Fatal("SECURITY: with MaxConcurrentExecutions filled, execution must not be eligible (every reserve denies on concurrency)")
	}
	// Release the slot: eligible again (concurrency freed; total/rate/window all have room).
	rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	if !rt.executionEligible(capb, now) {
		t.Fatal("after releasing the concurrency slot, execution must be eligible again")
	}
}

// TestCanaryRuntime_PerRequestTripDoesNotStopCanary proves the taxonomy split at the runtime: a
// per-request abort code does not stop the Canary, while a whole-Canary code does.
func TestCanaryRuntime_PerRequestTripDoesNotStopCanary(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(10), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if r := rt.tripCanaryAbort(capb, "policy_deny", now); r != canary.TripRequestScoped {
		t.Fatalf("a per-request code must be request-scoped, got %s", r)
	}
	if !rt.executionEligible(capb, now) {
		t.Fatal("a per-request fail-closed must NOT stop the Canary")
	}
	if r := rt.tripCanaryAbort(capb, "scope_escape", now); r != canary.TripCanaryLatched {
		t.Fatalf("a whole-Canary code must latch, got %s", r)
	}
	if rt.executionEligible(capb, now) {
		t.Fatal("a whole-Canary breach must stop the Canary")
	}
}

// TestCanaryRuntime_RestartPreservesSpendAndAbort is the §7 restart-recovery proof: the budget spend
// and the abort latch survive a process restart (a fresh runtime restoring the same durable files).
func TestCanaryRuntime_RestartPreservesSpendAndAbort(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i := 0; i < 3; i++ {
		if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
			t.Fatalf("reserve %d: %s", i, o)
		}
		rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	}
	// Simulate a restart: a brand-new runtime restoring the SAME durable state.
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.currentGeneration(capb) != 1 {
		t.Fatalf("restart must preserve the generation, got %d", fresh.currentGeneration(capb))
	}
	// The spend carried forward: 2 remaining, not 5 (no restart replay of the budget).
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("restored budget must still grant within remaining, got %s", o)
	}
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("restored budget: 2nd remaining grant, got %s", o)
	}
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedTotal {
		t.Fatalf("SECURITY: a restart must not replay a spent budget — N+1 must deny, got %s", o)
	}
}

// TestCanaryRuntime_RestartPreservesAbortLatch proves an abort survives a restart: a runtime that
// was aborted before the restart stays aborted (never silently cleared).
func TestCanaryRuntime_RestartPreservesAbortLatch(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(10), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	rt.tripCanaryAbort(capb, "credential_safety_failure", now)
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a whole-Canary abort must survive a restart (never auto-cleared)")
	}
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("an aborted-then-restarted Canary must deny reserves, got %s", o)
	}
}

// TestCanaryRuntime_BuildMismatchDisarms proves a materially changed runtime does not resume a live
// budget/abort: a durable state written under a different build restores DISARMED (fail closed).
func TestCanaryRuntime_BuildMismatchDisarms(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v1.0.0")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Restart under a DIFFERENT build.
	version = "v2.0.0"
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a build change must disarm the Canary runtime (no cross-build budget resume)")
	}
	// The monotonic generation is preserved so a re-activation bumps past the stale one.
	if fresh.currentGeneration(capb) != 1 {
		t.Fatalf("generation must be preserved across a build change, got %d", fresh.currentGeneration(capb))
	}
}

// TestCanaryRuntime_CommitMismatchDisarms is the Codex round-20 P1 proof: the durable runtime record
// is bound to the COMPOSED build identity (version+commit), so a different commit built under the SAME
// release tag does not resume the earlier build's active generation / budget / abort — matching the
// commit-bound attestation and rehearsal records.
func TestCanaryRuntime_CommitMismatchDisarms(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v1.0.0")
	buildCommit = "aaaa1111aaaa" // the build that ARMS the activation (hex commit; overrides the helper)
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Restart under the SAME version tag but a DIFFERENT commit.
	buildCommit = "bbbb2222bbbb"
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a different commit under the same version tag must disarm the runtime (commit-bound identity)")
	}
	// The monotonic generation is preserved so a fresh activation bumps past the stale one.
	if fresh.currentGeneration(capb) != 1 {
		t.Fatalf("generation must be preserved across a commit change, got %d", fresh.currentGeneration(capb))
	}
}

// TestCanaryRuntime_DemotionInvalidatesOldGeneration is the §8 anti-reuse proof: after a demotion,
// the OLD generation's budget/abort cannot be reused — a re-activation bumps the generation, and a
// reserve carrying the old generation is refused; the old spend does not carry into the new budget.
func TestCanaryRuntime_DemotionInvalidatesOldGeneration(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	gen1, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now)
	if err != nil {
		t.Fatalf("begin1: %v", err)
	}
	// Spend the whole gen-1 budget.
	for i := 0; i < 3; i++ {
		rt.reserveCanaryExecution(capb, now, rtIdent)
		rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	}
	// Demote (rollback), then re-activate: the new generation must be fresh (full budget, not
	// aborted, not carrying gen-1's spend).
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if rt.executionEligible(capb, now) {
		t.Fatal("a demoted Canary must not be execution-eligible")
	}
	gen2, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now)
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	if gen2 <= gen1 {
		t.Fatalf("a re-activation must bump the generation past %d, got %d", gen1, gen2)
	}
	// The new generation has a FRESH budget (the old spend did not carry in).
	for i := 0; i < 3; i++ {
		if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
			t.Fatalf("new-generation reserve %d must be granted (fresh budget), got %s", i, o)
		}
		rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	}
}

// TestCanaryRuntime_RestartAfterDemotionStaysDisarmed proves the durable state after a demotion
// restores disarmed (no execution), and a stale gen-keyed budget snapshot cannot resurrect it.
func TestCanaryRuntime_RestartAfterDemotionStaysDisarmed(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(3), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a demoted-then-restarted Canary must stay disarmed")
	}
	if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("a demoted-then-restarted runtime must deny reserves, got %s", o)
	}
}

// TestCanaryRuntime_CapabilityIsolation proves the two capability runtimes are fully isolated: a
// Management activation (with its own generation, budget, and abort) never touches the Gateway
// runtime and vice versa. It also exercises every runtime method with the Management capability
// (Canary is Gateway-only in practice, but the runtime accounting is capability-parameterized and
// must stay isolated).
func TestCanaryRuntime_CapabilityIsolation(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	now := time.Unix(1_700_000_000, 0)
	gw, mg := rollout.CapabilityGateway, rollout.CapabilityManagement

	// Arm ONLY the Management runtime.
	if _, err := rt.beginCanaryActivation(mg, runtimeTestBudget(2), now); err != nil {
		t.Fatalf("begin(management): %v", err)
	}
	if rt.currentGeneration(gw) != 0 {
		t.Fatal("a Management activation must not bump the Gateway generation (isolation)")
	}
	if rt.currentGeneration(mg) != 1 {
		t.Fatalf("Management generation must be 1, got %d", rt.currentGeneration(mg))
	}
	if rt.executionEligible(gw, now) {
		t.Fatal("Gateway must stay dormant while only Management is armed")
	}
	if !rt.executionEligible(mg, now) {
		t.Fatal("Management must be execution-eligible after its activation")
	}
	// A per-request trip on Management does not stop it (taxonomy split holds per-capability).
	if r := rt.tripCanaryAbort(mg, "policy_deny", now); r != canary.TripRequestScoped {
		t.Fatalf("a per-request trip on management must be request-scoped, got %s", r)
	}
	// Reserve/release on Management only; Gateway is untouched.
	if o, _ := rt.reserveCanaryExecution(mg, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("management reserve must be granted, got %s", o)
	}
	rt.releaseCanaryExecution(mg, rt.currentGeneration(mg))
	if o, _ := rt.reserveCanaryExecution(gw, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("a Gateway reserve must be denied while only Management is armed, got %s", o)
	}
	// Demoting Management leaves Gateway untouched (still dormant).
	if err := rt.demoteCanary(mg); err != nil {
		t.Fatalf("demote(management): %v", err)
	}
	if rt.executionEligible(mg, now) || rt.executionEligible(gw, now) {
		t.Fatal("after demoting Management, neither capability is eligible")
	}
}

// TestCanaryRuntime_FailedDemoteDoesNotReviveOnRestart is the §4/§7 fail-closed-demotion proof
// (Codex P1): if persisting a demotion fails, the durable Active:true record must not survive to
// re-arm the Canary on restart. The runtime removes the durable file on a persist failure so a
// restart restores the dormant default.
func TestCanaryRuntime_FailedDemoteDoesNotReviveOnRestart(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Sanity: the durable record is active — a naive restart would revive it.
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); err != nil {
		t.Fatalf("begin must have written a durable active record: %v", err)
	}
	// Inject a persist failure for the demotion that leaves the prior active record on disk.
	prev := canaryRuntimePersist
	canaryRuntimePersist = func(_ *canaryRuntime, _ rollout.Capability, _ *canaryCapRuntime) error {
		return errors.New("injected demote persist failure")
	}
	t.Cleanup(func() { canaryRuntimePersist = prev })

	if err := rt.demoteCanary(capb); err == nil {
		t.Fatal("a demote whose persist fails must return the error, not report durable success")
	}
	// The fix removed the durable file so a restart cannot revive the activation.
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
		t.Fatal("a failed demote must remove the durable state to fail closed to dormant")
	}
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a failed demote must not revive the Canary on restart")
	}
}

// TestCanaryRuntime_BeginPersistFailureDisarms proves the §7 fail-closed begin (Codex P1): if the
// activation's durable write fails, the runtime disarms in memory so no execution path can reserve
// work for an activation that was never durably established.
func TestCanaryRuntime_BeginPersistFailureDisarms(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	prev := canaryRuntimePersist
	canaryRuntimePersist = func(_ *canaryRuntime, _ rollout.Capability, _ *canaryCapRuntime) error {
		return errors.New("injected begin persist failure")
	}
	t.Cleanup(func() { canaryRuntimePersist = prev })

	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err == nil {
		t.Fatal("begin must return the persist error")
	}
	if rt.executionEligible(capb, now) {
		t.Fatal("SECURITY: a begin whose persist failed must disarm in memory (no execution)")
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("a reserve after a failed begin must be denied, got %s", o)
	}
	// The generation is still bumped (monotonic), so a later begin cannot reuse it.
	if rt.currentGeneration(capb) != 1 {
		t.Fatalf("generation must stay bumped after a failed begin, got %d", rt.currentGeneration(capb))
	}
}

// TestCanaryRuntime_AbortPersistFailureRemovesState proves the §4 fail-closed abort (Codex P1): if
// persisting a whole-Canary abort fails, the durable record is removed so a restart cannot revive
// the (pre-abort, still Active/not-aborted) activation.
func TestCanaryRuntime_AbortPersistFailureRemovesState(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Inject a persist failure for the abort trip (leaves the pre-abort active record on disk).
	prev := canaryRuntimePersist
	canaryRuntimePersist = func(_ *canaryRuntime, _ rollout.Capability, _ *canaryCapRuntime) error {
		return errors.New("injected abort persist failure")
	}
	t.Cleanup(func() { canaryRuntimePersist = prev })

	if r := rt.tripCanaryAbort(capb, "scope_escape", now); r != canary.TripCanaryLatched {
		t.Fatalf("a whole-Canary trip must latch, got %s", r)
	}
	// The durable record must have been removed so a restart cannot revive the un-aborted activation.
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
		t.Fatal("a failed abort persist must remove the durable record to fail closed to dormant")
	}
	canaryRuntimePersist = prev
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a restart after a failed abort persist must not revive an eligible Canary")
	}
}

// TestCanaryRuntime_ReserveAbortPersistFailureRemovesState proves the §4 fail-closed handling when a
// RESERVE (not an explicit trip/demote) latches a whole-Canary abort whose persist fails (Codex P1):
// the durable record is removed so a restart cannot revive the pre-abort Active/not-aborted
// activation and re-admit previously-granted work. This is the reserve-triggered sibling of
// TestCanaryRuntime_AbortPersistFailureRemovesState.
func TestCanaryRuntime_ReserveAbortPersistFailureRemovesState(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	// A total budget of exactly 1: the 2nd reserve exhausts the blast radius → whole-Canary abort.
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(1), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("the first reserve must be granted, got %s", o)
	}
	rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
	// Sanity: a durable active record exists that a naive restart would revive.
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); err != nil {
		t.Fatalf("begin/reserve must have written a durable active record: %v", err)
	}
	// Inject a persist failure for the abort-latching reserve only.
	prev := canaryRuntimePersist
	canaryRuntimePersist = func(_ *canaryRuntime, _ rollout.Capability, _ *canaryCapRuntime) error {
		return errors.New("injected reserve-abort persist failure")
	}
	t.Cleanup(func() { canaryRuntimePersist = prev })

	// The 2nd reserve exhausts the total → latches a whole-Canary abort → persist fails.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedTotal {
		t.Fatalf("the exhausting reserve must be denied on total, got %s", o)
	}
	if rt.executionEligible(capb, now) {
		t.Fatal("the exhausting reserve must have latched the whole-Canary abort (no longer eligible)")
	}
	// The fix removes the durable record so a restart cannot revive the un-aborted activation.
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
		t.Fatal("a failed reserve-triggered abort persist must remove the durable record to fail closed to dormant")
	}
	canaryRuntimePersist = prev
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a restart after a failed reserve-abort persist must not revive an eligible Canary")
	}
}

// TestCanaryRuntime_ReserveNotSyncedPersistDeniesGrant is the Codex P1 (round-4) durability proof:
// when the runtime-state AtomicWrite returns fileutil.ErrReplacedNotSynced (the replacement is
// visible but not durably synced, so an immediate crash can lose it), the persist must be treated as
// a FAILURE — a granted reserve must be denied rather than authorizing a side effect, because a lost
// budget write would replay the slot on restart and break the monotonic non-replayable total. This
// exercises the REAL persistLocked path through the canaryAtomicWrite seam.
func TestCanaryRuntime_ReserveNotSyncedPersistDeniesGrant(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Inject a not-synced replacement for the next persist (the real persistLocked runs).
	prevWrite := canaryAtomicWrite
	canaryAtomicWrite = func(_ string, _ []byte, _ os.FileMode) error {
		return fileutil.ErrReplacedNotSynced
	}
	t.Cleanup(func() { canaryAtomicWrite = prevWrite })

	// The enforcer grants in memory, but the not-synced persist must turn the grant into a denial so
	// no side effect is authorized against a budget slot that may not survive a crash.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("SECURITY: a reserve whose persist is not durably synced must be denied, got %s", o)
	}
	// Restore durable writes: a restart-equivalent restore must not have been handed a granted slot
	// via a lost write — the budget still grants its full N (the denied reserve authorized nothing).
	canaryAtomicWrite = prevWrite
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	for i := 0; i < 5; i++ {
		if o, _ := fresh.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
			t.Fatalf("restored budget grant %d must succeed (denied reserve consumed no durable slot), got %s", i+1, o)
		}
		fresh.releaseCanaryExecution(capb, fresh.currentGeneration(capb))
	}
}

// TestCanaryRuntime_BeginNotSyncedPersistRemovesRecord is the Codex P1 (round-5) proof: when begin's
// persist replaces the target but cannot durably sync it (fileutil.ErrReplacedNotSynced), a VISIBLE
// Active record may be on disk even though begin returns failure and disarms only memory. Begin must
// durably remove that possibly-installed record so a restart cannot re-arm an activation the caller
// was told never became durable.
func TestCanaryRuntime_BeginNotSyncedPersistRemovesRecord(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	// Simulate a not-synced replacement: the record IS written (visible) but the write reports
	// ErrReplacedNotSynced, so begin must treat it as a failure AND remove the visible record.
	prevWrite := canaryAtomicWrite
	canaryAtomicWrite = func(path string, data []byte, perm os.FileMode) error {
		_ = os.WriteFile(path, data, perm) // the target is replaced and visible…
		return fileutil.ErrReplacedNotSynced
	}
	t.Cleanup(func() { canaryAtomicWrite = prevWrite })

	if _, err := rt.beginCanaryActivation(capb, runtimeTestBudget(5), now); err == nil {
		t.Fatal("a begin whose persist is not durably synced must return an error")
	}
	// Begin must have removed the visible-but-unsynced record.
	if _, err := os.Stat(canaryRuntimeStatePath(capb)); !os.IsNotExist(err) {
		t.Fatal("a not-synced begin must durably remove the possibly-installed Active record")
	}
	canaryAtomicWrite = prevWrite
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, now) {
		t.Fatal("SECURITY: a not-synced begin must not re-arm the activation on restart")
	}
}

// TestCanaryRuntime_PersistFailureReleasesConcurrencySlot is the Codex P2 (round-5) proof: when a
// reserve grants in memory but its persist fails (so the grant is turned into a denial and no side
// effect crosses the boundary), the in-flight concurrency slot Reserve took must be released — a
// single transient write failure must not permanently wedge concurrency. The monotonic total spend
// still stands (no replay).
func TestCanaryRuntime_PersistFailureReleasesConcurrencySlot(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	b := runtimeTestBudget(100)
	b.MaxConcurrentExecutions = 1 // one leaked slot would deny every later reserve on concurrency
	if _, err := rt.beginCanaryActivation(capb, b, now); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// Reserve #1: the enforcer grants, but the persist fails → the grant becomes a denial.
	prevWrite := canaryAtomicWrite
	canaryAtomicWrite = func(_ string, _ []byte, _ os.FileMode) error { return fileutil.ErrReplacedNotSynced }
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
		t.Fatalf("a granted reserve whose persist fails must be denied, got %s", o)
	}
	canaryAtomicWrite = prevWrite
	// Reserve #2 (durable writes restored) must be GRANTED — the leaked in-flight slot was released,
	// so concurrency is not wedged at 1.
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("SECURITY: a transient persist failure must not wedge concurrency; reserve #2 got %s", o)
	}
}

// TestSyncParentDir_ReportsFailure proves syncParentDir returns nil for a real directory and an error
// when the directory cannot be opened — so removeRuntimeStateAfterSafetyPersistFailure reports an
// un-synced removal as UNRESOLVED (Codex P1, round-5) rather than as a clean fail-closed removal.
func TestSyncParentDir_ReportsFailure(t *testing.T) {
	dir := t.TempDir()
	if err := syncParentDir(filepath.Join(dir, "some-file")); err != nil {
		t.Fatalf("syncing a valid parent directory must succeed, got %v", err)
	}
	if err := syncParentDir(filepath.Join(dir, "no-such-subdir", "file")); err == nil {
		t.Fatal("syncing a nonexistent parent directory must return an error (removal reported unresolved)")
	}
}

// TestRemoveRuntimeStateAfterSafetyPersistFailure_ReportsUnconfirmedDirSync is the Codex round-23 P1
// proof: content-invalidating and removing the runtime record is treated as a fail-closed COMPLETE
// removal only when the parent-directory fsync is CONFIRMED. A failed safety-mutation persist
// (ErrReplacedNotSynced) renamed a new record over the prior Active:true file without syncing the
// directory, so a crash could revert PAST the rename to that stale inode — which the content
// invalidation never truncated. So a dir-sync failure is reported UNRESOLVED (the error is returned)
// rather than logged as a durable removal.
func TestRemoveRuntimeStateAfterSafetyPersistFailure_ReportsUnconfirmedDirSync(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	path := canaryRuntimeStatePath(capb)

	// A CONFIRMED dir sync (production seam) ⇒ clean fail-closed removal; the record is gone and nil is
	// returned.
	if err := os.WriteFile(path, []byte(`{"active":true}`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "abort", errors.New("persist boom")); err != nil {
		t.Fatalf("a confirmed dir sync must report a durable removal, got %v", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Fatal("the record must be removed on a confirmed cleanup")
	}

	// An UNCONFIRMED dir sync (injected failure) ⇒ the cleanup returns that error (UNRESOLVED), never
	// nil — the stale pre-rename record could revive on a crash.
	prev := canarySyncParentDir
	dirSyncErr := errors.New("dir sync boom")
	canarySyncParentDir = func(string) error { return dirSyncErr }
	t.Cleanup(func() { canarySyncParentDir = prev })
	if err := os.WriteFile(path, []byte(`{"active":true}`), 0o600); err != nil {
		t.Fatalf("seed 2: %v", err)
	}
	if err := rt.removeRuntimeStateAfterSafetyPersistFailure(capb, "abort", errors.New("persist boom")); !errors.Is(err, dirSyncErr) {
		t.Fatalf("an unconfirmed dir sync must be reported UNRESOLVED, got %v", err)
	}
}

// TestInvalidateFileContentDurably_EmptiesFile is the Codex P1 (round-9) durability-anchor proof:
// invalidateFileContentDurably truncates a record to empty and fsyncs the FILE inode (independent of
// the parent-directory fsync), so a not-synced write whose directory cleanup cannot be synced is
// still failed closed — a crash-restored directory entry then points to an EMPTY file that decodes as
// corrupt (quarantined → not attested). A missing file is a no-op success.
func TestInvalidateFileContentDurably_EmptiesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rec.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"status":"passed"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := invalidateFileContentDurably(path); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after invalidate: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("invalidate must truncate the file to empty, size=%d", info.Size())
	}
	// A missing file is a no-op success (nothing to invalidate).
	if err := invalidateFileContentDurably(filepath.Join(dir, "absent.json")); err != nil {
		t.Fatalf("invalidating a missing file must succeed, got %v", err)
	}
}

// TestCanaryRuntime_StaleReleaseDoesNotFreeNewGeneration proves the §3 generation-bound release
// (Codex P1): a release carrying a superseded generation is a no-op and cannot free a concurrency
// slot on the current activation (which would admit an extra in-flight execution beyond the cap).
func TestCanaryRuntime_StaleReleaseDoesNotFreeNewGeneration(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	now := time.Unix(1_700_000_000, 0)
	b := runtimeTestBudget(100)
	b.MaxConcurrentExecutions = 1

	gen1, err := rt.beginCanaryActivation(capb, b, now)
	if err != nil {
		t.Fatalf("begin1: %v", err)
	}
	// Reserve under gen1 (do NOT release), then demote + reactivate → gen2.
	if o, g := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted || g != gen1 {
		t.Fatalf("gen1 reserve = (%s, gen %d), want granted gen %d", o, g, gen1)
	}
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	gen2, err := rt.beginCanaryActivation(capb, b, now)
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	// Reserve under gen2 (fills the single concurrency slot).
	if o, g := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted || g != gen2 {
		t.Fatalf("gen2 reserve = (%s, gen %d), want granted gen %d", o, g, gen2)
	}
	// A STALE release for gen1 must NOT free gen2's concurrency slot.
	rt.releaseCanaryExecution(capb, gen1)
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedConcurrency {
		t.Fatalf("SECURITY: a stale (gen1) release must not free gen2's concurrency slot; got %s", o)
	}
	// A correct gen2 release frees the slot.
	rt.releaseCanaryExecution(capb, gen2)
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetGranted {
		t.Fatalf("a correct-generation release must free the slot, got %s", o)
	}
}

// TestCanaryRuntime_RestoreForeignAbortSnapshotDisarms proves the §7 fix (Codex P1): an active
// durable record whose abort snapshot names a different generation is treated as corrupt and
// disarmed, so a foreign/missing abort snapshot can never silently clear an abort and re-arm.
func TestCanaryRuntime_RestoreForeignAbortSnapshotDisarms(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	// Craft an active record: budget snapshot matches gen 1, but the abort snapshot names gen 2.
	st := canaryRuntimeState{
		SchemaVersion: canaryRuntimeSchemaVersion,
		Capability:    capb.String(),
		BuildVersion:  currentRuntimeIdentity().BuildVersion, // THIS build's composed identity, so the disarm is attributable to the foreign abort snapshot, not a build mismatch
		Generation:    1,
		Active:        true,
		Budget:        runtimeTestBudget(5),
		BudgetSnapshot: canary.BudgetSnapshot{
			Generation: 1, TotalReserved: 0, StartUnixNano: 1, RateWindowStartNano: 1,
		},
		AbortSnapshot: canary.AbortSnapshot{Generation: 2}, // FOREIGN generation
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rt.restore()
	if rt.executionEligible(capb, time.Now()) {
		t.Fatal("SECURITY: an active record with a foreign-generation abort snapshot must disarm")
	}
}

// TestCanaryRuntime_RestoreReconcileDisarmsWithoutLiveMode is the Codex P1 (round-6) restart-recovery
// proof: the canary runtime and the rollout mode are restored from INDEPENDENT durable domains. If a
// node restarts with an ACTIVE runtime record but its rollout mode is not a live-execution mode (e.g.
// it was clamped by the restore preflight because a prerequisite was removed while down), the
// reconcile must disarm the runtime so a restart never resumes an execution-eligible runtime under a
// mode a fresh commit would reject.
func TestCanaryRuntime_RestoreReconcileDisarmsWithoutLiveMode(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	_ = rt
	capb := rollout.CapabilityGateway
	// Craft an ACTIVE durable runtime record, as if a Canary had been armed before the restart.
	st := canaryRuntimeState{
		SchemaVersion:  canaryRuntimeSchemaVersion,
		Capability:     capb.String(),
		BuildVersion:   currentRuntimeIdentity().BuildVersion, // THIS build's composed identity, so the disarm is attributable to the mode reconcile, not a build mismatch
		Generation:     1,
		Active:         true,
		Budget:         runtimeTestBudget(5),
		BudgetSnapshot: canary.BudgetSnapshot{Generation: 1, StartUnixNano: 1, RateWindowStartNano: 1},
		AbortSnapshot:  canary.AbortSnapshot{Generation: 1},
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(canaryRuntimeStatePath(capb), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Fresh singleton rollout — mode Disabled (NOT a live-execution mode), as a restore clamp leaves it.
	_ = getMCPRollout()
	prev := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPRollout = prev })

	// Runtime restore alone re-arms the active durable record…
	globalCanaryRuntime.restore()
	if !globalCanaryRuntime.armed(capb) {
		t.Fatal("precondition: restore must re-arm the active durable record")
	}
	// …but the reconcile disarms it because the rollout mode is not a live-execution mode.
	reconcileCanaryRuntimeAfterRestore()
	if globalCanaryRuntime.armed(capb) || globalCanaryRuntime.executionEligible(capb, time.Now()) {
		t.Fatal("SECURITY: a restored runtime with no live-execution rollout mode must be disarmed by the reconcile")
	}
	// The disarm is durable across a further restart.
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.executionEligible(capb, time.Now()) {
		t.Fatal("SECURITY: the reconcile disarm must survive a restart")
	}
}

// TestCanaryRuntime_CorruptStateQuarantined proves a tampered durable state is quarantined and the
// runtime falls back to the safe dormant default (fail closed).
func TestCanaryRuntime_CorruptStateQuarantined(t *testing.T) {
	rt := withCanaryRuntimeTestEnv(t, "v9.9.9")
	capb := rollout.CapabilityGateway
	path := canaryRuntimeStatePath(capb)
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"capability":"gateway","generation":1,"active":true,"injected":true}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	rt.restore()
	if rt.executionEligible(capb, time.Now()) {
		t.Fatal("a corrupt runtime state must fail closed to disarmed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a corrupt runtime state must be quarantined (moved aside)")
	}
	if matches, _ := filepath.Glob(path + ".corrupt.*"); len(matches) == 0 {
		t.Fatal("a corrupt runtime state must leave a .corrupt.* quarantine copy")
	}
}

// TestStrictDecodeCanaryRuntimeJSON_RejectsTrailingDelimiter proves the durable-record decoder rejects
// a valid object followed by any trailing token — including a "}" or "]" that dec.More() alone would let
// slip past (Codex P2 round-7, PR #1290).
func TestStrictDecodeCanaryRuntimeJSON_RejectsTrailingDelimiter(t *testing.T) {
	valid := `{"schema_version":1,"capability":"gateway","generation":1,"active":false}`
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"clean", valid, false},
		{"trailing_brace", valid + "}", true},
		{"trailing_bracket", valid + "]", true},
		{"trailing_value", valid + " 5", true},
	} {
		var st canaryRuntimeState
		err := strictDecodeCanaryRuntimeJSON([]byte(tc.raw), &st)
		if tc.wantErr && err == nil {
			t.Fatalf("%s: trailing data must be rejected (fail-closed)", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: a single valid value must decode, got %v", tc.name, err)
		}
	}
}
