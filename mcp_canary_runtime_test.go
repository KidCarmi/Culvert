package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if rt.executionEligible(capb) {
		t.Fatal("budget exhaustion must trip the whole-Canary abort — no longer eligible")
	}
	// Every later reserve is denied because the Canary is aborted (not merely out of budget).
	if o, _ := rt.reserveCanaryExecution(capb, now, rtIdent); o != canary.BudgetDeniedInvalid {
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
	if fresh.executionEligible(capb) {
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
		rt.reserveCanaryExecution(capb, now, rtIdent)
		rt.releaseCanaryExecution(capb, rt.currentGeneration(capb))
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
	if fresh.executionEligible(capb) {
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
	if rt.executionEligible(gw) {
		t.Fatal("Gateway must stay dormant while only Management is armed")
	}
	if !rt.executionEligible(mg) {
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
	if rt.executionEligible(mg) || rt.executionEligible(gw) {
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
	if fresh.executionEligible(capb) {
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
	if rt.executionEligible(capb) {
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
	if fresh.executionEligible(capb) {
		t.Fatal("SECURITY: a restart after a failed abort persist must not revive an eligible Canary")
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
		BuildVersion:  version,
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
	if rt.executionEligible(capb) {
		t.Fatal("SECURITY: an active record with a foreign-generation abort snapshot must disarm")
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
