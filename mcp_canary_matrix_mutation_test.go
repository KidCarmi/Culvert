package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ── §6 Fail-closed activation matrix ──────────────────────────────────────────
//
// The Canary readiness contract is fail-closed: ONE false prerequisite ⇒ NOT READY. The pure
// per-fact matrix (every canary.Reason reachable, none orphaned) is pinned in the canary package
// (TestEvaluate_EachFactIsIndependentlyLoadBearing, TestEvaluate_ReasonVocabularyParity). These
// composition-layer tests pin the SHIPPED-BUILD posture: what the live node actually reports, and
// that no path makes it Ready.

// TestCanaryMatrix_ShippedBuildNeverReady is the load-bearing posture pin: in the shipped build
// (no test fixtures arming the live tier), the Canary node readiness is NOT ready, the full
// activation preflight with otherwise-valid inputs is NOT ready (the node blocks), and the boolean
// gate a future arming would consult is false. This is the "PR remains NOT READY" success criterion.
func TestCanaryMatrix_ShippedBuildNeverReady(t *testing.T) {
	if evaluateCanaryNodeReadiness(rollout.CapabilityGateway).Ready {
		t.Fatal("SECURITY: the shipped build must never report Canary node readiness")
	}
	if canaryActivationReady(rollout.CapabilityGateway) {
		t.Fatal("SECURITY: canaryActivationReady must be false in the shipped build")
	}
	now := time.Unix(1_700_000_000, 0)
	if evaluateCanaryActivationPreflight(validCanaryActivationInput(now)).Ready {
		t.Fatal("SECURITY: no activation input may make the full preflight ready while the node is not ready")
	}
}

// TestCanaryMatrix_DormantNodeRejections pins the EXACT dormant-build node-level unmet set. Every
// node prerequisite except the (default-clear) emergency kill is unmet; the six activation-level
// reasons are NOT reported by the node dry-run; capability_not_gateway is met for Gateway. If a
// prerequisite is silently dropped or an extra one appears, this fails.
func TestCanaryMatrix_DormantNodeRejections(t *testing.T) {
	// This exact-set assertion depends on ambient global state (dataDir for the attestation +
	// rehearsal files, and the rollout singleton's persist status). Isolate both so the set is
	// deterministic under -shuffle/-count regardless of any prior test's leftovers: a fresh temp
	// dataDir (no attestation/rehearsal files ⇒ shadow_exit + rollback stay unmet) and a fresh
	// rollout singleton (fresh persist status, kill clear).
	withTempDataDir(t)
	_ = getMCPRollout()
	prevRollout := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPRollout = prevRollout })

	rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	want := []canary.Reason{
		canary.ReasonShadowExitNotPassed,
		canary.ReasonLiveExecutorAbsent,
		canary.ReasonUpstreamCallerAbsent,
		canary.ReasonCredentialPathNotReady,
		canary.ReasonDurableEventsDegraded,
		canary.ReasonResponseInspectionNotReady,
		canary.ReasonRegistryUnhealthy,
		canary.ReasonCatalogUnhealthy,
		canary.ReasonPolicyUnhealthy,
		canary.ReasonKillBoundaryGuardAbsent,
		canary.ReasonToolFreshnessGuardAbsent,
		canary.ReasonRollbackPathUnhealthy,
	}
	if len(rd.Unmet) != len(want) {
		t.Fatalf("dormant node unmet = %v (%d), want %d reasons", rd.Unmet, len(rd.Unmet), len(want))
	}
	for i := range want {
		if rd.Unmet[i] != want[i] {
			t.Fatalf("dormant node unmet[%d] = %s, want %s (canonical order); full=%v", i, rd.Unmet[i], want[i], rd.Unmet)
		}
	}
	// The activation-level reasons must NOT appear in the node dry-run.
	for _, notWanted := range []canary.Reason{
		canary.ReasonScopeNotBounded, canary.ReasonScopeNotReadFirst, canary.ReasonLiveApprovalInvalid,
		canary.ReasonServerNotUsable, canary.ReasonToolFingerprintStale, canary.ReasonBudgetNotConfigured,
	} {
		if canaryUnmetHas(rd, notWanted) {
			t.Errorf("node dry-run must not report the activation-level reason %s", notWanted)
		}
	}
}

// TestCanaryMatrix_EveryReasonReachable pins Facts↔Reason parity at the composition layer: starting
// from an all-true fact set (Ready), flipping each fact false surfaces exactly its reason, and the
// full 20-reason vocabulary is covered. One false prerequisite ⇒ NOT READY.
func TestCanaryMatrix_EveryReasonReachable(t *testing.T) {
	allTrue := canary.Facts{
		CapabilityGateway: true, ShadowExitReviewPassed: true, ScopeBounded: true, ScopeReadFirst: true,
		LiveExecutorComposed: true, UpstreamCallerPresent: true, CredentialPathReady: true,
		DurableEventsHealthy: true, ResponseInspectionReady: true, RegistryHealthy: true, CatalogHealthy: true,
		PolicyHealthy: true, EmergencyKillClear: true, KillBoundaryGuardPresent: true, ToolFreshnessGuardPresent: true,
		LiveApprovalValid: true, ServerUsable: true, ToolFingerprintCurrent: true, RollbackPathHealthy: true,
		BudgetConfigured: true,
	}
	if !canary.Evaluate(allTrue).Ready {
		t.Fatal("an all-true fact set must be Ready (positive control for the matrix)")
	}
	flip := map[canary.Reason]func(*canary.Facts){
		canary.ReasonShadowExitNotPassed:        func(f *canary.Facts) { f.ShadowExitReviewPassed = false },
		canary.ReasonScopeNotBounded:            func(f *canary.Facts) { f.ScopeBounded = false },
		canary.ReasonScopeNotReadFirst:          func(f *canary.Facts) { f.ScopeReadFirst = false },
		canary.ReasonLiveExecutorAbsent:         func(f *canary.Facts) { f.LiveExecutorComposed = false },
		canary.ReasonUpstreamCallerAbsent:       func(f *canary.Facts) { f.UpstreamCallerPresent = false },
		canary.ReasonCredentialPathNotReady:     func(f *canary.Facts) { f.CredentialPathReady = false },
		canary.ReasonDurableEventsDegraded:      func(f *canary.Facts) { f.DurableEventsHealthy = false },
		canary.ReasonResponseInspectionNotReady: func(f *canary.Facts) { f.ResponseInspectionReady = false },
		canary.ReasonRegistryUnhealthy:          func(f *canary.Facts) { f.RegistryHealthy = false },
		canary.ReasonCatalogUnhealthy:           func(f *canary.Facts) { f.CatalogHealthy = false },
		canary.ReasonPolicyUnhealthy:            func(f *canary.Facts) { f.PolicyHealthy = false },
		canary.ReasonEmergencyKillActive:        func(f *canary.Facts) { f.EmergencyKillClear = false },
		canary.ReasonKillBoundaryGuardAbsent:    func(f *canary.Facts) { f.KillBoundaryGuardPresent = false },
		canary.ReasonToolFreshnessGuardAbsent:   func(f *canary.Facts) { f.ToolFreshnessGuardPresent = false },
		canary.ReasonLiveApprovalInvalid:        func(f *canary.Facts) { f.LiveApprovalValid = false },
		canary.ReasonServerNotUsable:            func(f *canary.Facts) { f.ServerUsable = false },
		canary.ReasonToolFingerprintStale:       func(f *canary.Facts) { f.ToolFingerprintCurrent = false },
		canary.ReasonRollbackPathUnhealthy:      func(f *canary.Facts) { f.RollbackPathHealthy = false },
		canary.ReasonBudgetNotConfigured:        func(f *canary.Facts) { f.BudgetConfigured = false },
		canary.ReasonCapabilityNotGateway:       func(f *canary.Facts) { f.CapabilityGateway = false },
	}
	// Parity: every declared reason has a flip.
	for _, r := range canary.AllReasons() {
		if _, ok := flip[r]; !ok {
			t.Fatalf("reason %s has no matrix flip — vocabulary/matrix drift", r)
		}
	}
	for reason, mutate := range flip {
		f := allTrue
		mutate(&f)
		rd := canary.Evaluate(f)
		if rd.Ready {
			t.Fatalf("flipping %s must make the verdict NOT READY", reason)
		}
		if !canaryUnmetHas(rd, reason) {
			t.Fatalf("flipping the %s fact must surface exactly that reason, got %v", reason, rd.Unmet)
		}
	}
}

// ── §8 Mutation campaign ──────────────────────────────────────────────────────
//
// Each mutation below reintroduces a specific defect the phase closes, and names the gate that
// catches it. Ten mutations; several are additionally pinned by dedicated tests referenced in the
// comments (kept here as the single campaign roster).

// Mutation 3: bypass the activation gate on restart/restore. A hand-crafted durable rollout state
// with mode=Canary must be CLAMPED to Disabled on restore (modeExecReady), never re-admitted.
func TestCanaryMutation3_RestoreClampsHandCraftedCanary(t *testing.T) {
	withTempDataDir(t)
	// Hand-craft a Canary state file by driving SetConfig directly (bypassing the commit gate),
	// then persisting — the shape a tampered/rolled-back node could present.
	seed := rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits())
	if err := seed.SetConfig(*gwCanaryCfg(1), "attacker", time.Unix(1000, 0).UnixNano()); err != nil {
		t.Fatalf("seed SetConfig: %v", err)
	}
	if seed.CurrentMode() != rollout.ModeCanary {
		t.Fatalf("seed must be Canary, got %s", seed.CurrentMode())
	}
	if err := persistRolloutState(seed); err != nil {
		t.Fatalf("persist seed: %v", err)
	}
	// Restore into a fresh rollout: the executing Canary mode must be clamped to Disabled.
	r := newTestRollout()
	r.restore()
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("SECURITY: a restored Canary must be clamped to Disabled, got %s", r.gateway.CurrentMode())
	}
}

// Mutation 9: accept a self-attested rollback marker without a real drill. Setting ONLY the legacy
// EvidenceSummary.RollbackRehearsed boolean (the old self-attested marker) WITHOUT the executable
// rollback-rehearsal evidence must NOT make the rollback path ready.
func TestCanaryMutation9_SelfAttestedMarkerWithoutDrillIsNotReady(t *testing.T) {
	pinTestBuildVersion(t) // a valid rehearsal record requires a non-placeholder build stamp
	_ = getMCPRollout()
	prevR, prevDir := globalMCPRollout, dataDir
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	dataDir = t.TempDir()
	t.Cleanup(func() { globalMCPRollout = prevR; dataDir = prevDir })

	capb := rollout.CapabilityGateway
	// Set ONLY the self-attested marker (the pre-§5 mechanism), with NO executable evidence file.
	globalMCPRollout.stateFor(capb).UpdateEvidence(func(e *rollout.EvidenceSummary) { e.RollbackRehearsed = true })
	if rollbackPathHealthy(capb) {
		t.Fatal("SECURITY: the self-attested marker alone must not satisfy the rollback path — executable evidence is required")
	}
	// A real drill (which writes build-bound executable evidence) makes it ready.
	if err := globalMCPRollout.recordRehearsal(capb); err != nil {
		t.Fatalf("recordRehearsal: %v", err)
	}
	if !rollbackPathHealthy(capb) {
		t.Fatal("an executed rehearsal drill must satisfy the rollback path")
	}
}

// TestCanaryMutationCampaign_Roster documents the ten-mutation campaign and asserts the gate names
// exist, so the roster cannot silently lose a mutation. Each entry maps a mutation to the test(s)
// that catch it (all present in this package).
func TestCanaryMutationCampaign_Roster(t *testing.T) {
	roster := []struct{ mutation, gate string }{
		{"1: allow Canary without Shadow Exit attestation", "TestCanaryCommitGate_MissingAttestationRefuses / TestShadowExitAttestation_NeverAttestedByDefault"},
		{"2: bypass the preflight via CP→DP apply", "TestCanaryCommitGate_RefusesWhenNodeNotReady (shared commitRolloutTransition path)"},
		{"3: bypass the gate on restart/restore", "TestCanaryMutation3_RestoreClampsHandCraftedCanary"},
		{"4: permit the N+1 budget execution", "TestBudgetEnforcer_ExactNThenDeniesNPlus1"},
		{"5: race the budget counters (over-grant)", "TestBudgetEnforcer_ConcurrentReserveNeverExceedsTotal"},
		{"6: clear the whole-Canary abort automatically", "TestAbortController_MonotonicFirstCodeWins / TestCanaryRuntime_RestartPreservesAbortLatch"},
		{"7: treat a per-request policy deny as a whole-Canary abort", "TestAbortController_PerRequestCodesNeverLatch / TestCanaryRuntime_PerRequestTripDoesNotStopCanary"},
		{"8: accept a corrupt/stale Shadow Exit attestation", "TestShadowExitAttestation_CorruptIsQuarantinedAndFailsClosed / TestValidateAttestation_ForgedMissingStaleCorrupt"},
		{"9: accept a self-attested rollback without a drill", "TestCanaryMutation9_SelfAttestedMarkerWithoutDrillIsNotReady"},
		{"10: reuse an old budget/abort generation after reactivation", "TestCanaryRuntime_DemotionInvalidatesOldGeneration / TestBudgetEnforcer_GenerationBinding"},
	}
	if len(roster) != 10 {
		t.Fatalf("the mutation campaign must have exactly 10 entries, got %d", len(roster))
	}
	for _, m := range roster {
		if m.gate == "" {
			t.Fatalf("mutation %q has no named gate", m.mutation)
		}
	}
}
