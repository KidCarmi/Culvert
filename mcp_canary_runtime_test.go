package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// withCanaryRuntimeTestEnv points dataDir + the global canary runtime at fresh state and pins a
// deterministic build version, restoring all three on cleanup.
func withCanaryRuntimeTestEnv(t *testing.T, buildVer string) *canaryRuntime {
	t.Helper()
	prevDir, prevVer, prevRt := dataDir, version, globalCanaryRuntime
	dataDir = t.TempDir()
	version = buildVer
	globalCanaryRuntime = &canaryRuntime{}
	t.Cleanup(func() { dataDir = prevDir; version = prevVer; globalCanaryRuntime = prevRt })
	return globalCanaryRuntime
}

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
	if rt.executionEligible(capb) {
		t.Fatal("a dormant runtime must never be execution-eligible")
	}
	if o := rt.reserveCanaryExecution(capb, time.Unix(1, 0)); o != canary.BudgetDeniedInvalid {
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
		if o := rt.reserveCanaryExecution(capb, now); o != canary.BudgetGranted {
			t.Fatalf("reserve %d of %d must be granted, got %s", i+1, N, o)
		}
		rt.releaseCanaryExecution(capb)
	}
	// The N+1th exhausts the budget → whole-Canary abort.
	if o := rt.reserveCanaryExecution(capb, now); o != canary.BudgetDeniedTotal {
		t.Fatalf("the N+1th reserve must be denied on total, got %s", o)
	}
	if rt.executionEligible(capb) {
		t.Fatal("budget exhaustion must trip the whole-Canary abort — no longer eligible")
	}
	// Every later reserve is denied because the Canary is aborted (not merely out of budget).
	if o := rt.reserveCanaryExecution(capb, now); o != canary.BudgetDeniedInvalid {
		t.Fatalf("an aborted Canary must deny every reserve, got %s", o)
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
	if !rt.executionEligible(capb) {
		t.Fatal("a per-request fail-closed must NOT stop the Canary")
	}
	if r := rt.tripCanaryAbort(capb, "scope_escape", now); r != canary.TripCanaryLatched {
		t.Fatalf("a whole-Canary code must latch, got %s", r)
	}
	if rt.executionEligible(capb) {
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
		if o := rt.reserveCanaryExecution(capb, now); o != canary.BudgetGranted {
			t.Fatalf("reserve %d: %s", i, o)
		}
		rt.releaseCanaryExecution(capb)
	}
	// Simulate a restart: a brand-new runtime restoring the SAME durable state.
	fresh := &canaryRuntime{}
	globalCanaryRuntime = fresh
	fresh.restore()
	if fresh.currentGeneration(capb) != 1 {
		t.Fatalf("restart must preserve the generation, got %d", fresh.currentGeneration(capb))
	}
	// The spend carried forward: 2 remaining, not 5 (no restart replay of the budget).
	if o := fresh.reserveCanaryExecution(capb, now); o != canary.BudgetGranted {
		t.Fatalf("restored budget must still grant within remaining, got %s", o)
	}
	if o := fresh.reserveCanaryExecution(capb, now); o != canary.BudgetGranted {
		t.Fatalf("restored budget: 2nd remaining grant, got %s", o)
	}
	if o := fresh.reserveCanaryExecution(capb, now); o != canary.BudgetDeniedTotal {
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
	if fresh.executionEligible(capb) {
		t.Fatal("SECURITY: a whole-Canary abort must survive a restart (never auto-cleared)")
	}
	if o := fresh.reserveCanaryExecution(capb, now); o != canary.BudgetDeniedInvalid {
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
	if fresh.executionEligible(capb) {
		t.Fatal("SECURITY: a build change must disarm the Canary runtime (no cross-build budget resume)")
	}
	// The monotonic generation is preserved so a re-activation bumps past the stale one.
	if fresh.currentGeneration(capb) != 1 {
		t.Fatalf("generation must be preserved across a build change, got %d", fresh.currentGeneration(capb))
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
		rt.reserveCanaryExecution(capb, now)
		rt.releaseCanaryExecution(capb)
	}
	// Demote (rollback), then re-activate: the new generation must be fresh (full budget, not
	// aborted, not carrying gen-1's spend).
	if err := rt.demoteCanary(capb); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if rt.executionEligible(capb) {
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
		if o := rt.reserveCanaryExecution(capb, now); o != canary.BudgetGranted {
			t.Fatalf("new-generation reserve %d must be granted (fresh budget), got %s", i, o)
		}
		rt.releaseCanaryExecution(capb)
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
	if fresh.executionEligible(capb) {
		t.Fatal("SECURITY: a demoted-then-restarted Canary must stay disarmed")
	}
	if o := fresh.reserveCanaryExecution(capb, now); o != canary.BudgetDeniedInvalid {
		t.Fatalf("a demoted-then-restarted runtime must deny reserves, got %s", o)
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
	if rt.executionEligible(capb) {
		t.Fatal("a corrupt runtime state must fail closed to disarmed")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a corrupt runtime state must be quarantined (moved aside)")
	}
	if matches, _ := filepath.Glob(path + ".corrupt.*"); len(matches) == 0 {
		t.Fatal("a corrupt runtime state must leave a .corrupt.* quarantine copy")
	}
}
