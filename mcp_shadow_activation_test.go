package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// containsReason reports whether a preflight reason list carries code.
func containsReason(rs []string, code string) bool {
	for _, r := range rs {
		if r == code {
			return true
		}
	}
	return false
}

// TestPreflight_ManagementCapabilityFailsClosed pins that Shadow is Gateway-only: a
// Management capability preflight is never ready.
func TestPreflight_ManagementCapabilityFailsClosed(t *testing.T) {
	pf := evaluateShadowActivationPreflight(rollout.CapabilityManagement)
	if pf.Ready {
		t.Fatal("Management shadow preflight must never be ready (shadow is Gateway-only)")
	}
	if !containsReason(pf.Reasons, shadowPFNotGateway) {
		t.Fatalf("expected %s, got %v", shadowPFNotGateway, pf.Reasons)
	}
}

// TestPreflight_NotComposedIsNotReady pins that a node whose Shadow evaluator is not
// composed fails preflight with the composed-not-ready reason.
func TestPreflight_NotComposedIsNotReady(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway)
	if pf.Ready {
		t.Fatal("preflight must not be ready when the evaluator is not composed")
	}
	if !containsReason(pf.Reasons, shadowPFNotComposed) {
		t.Fatalf("expected %s, got %v", shadowPFNotComposed, pf.Reasons)
	}
}

// TestPreflight_ComposedClearsComposedReason pins that arming the shadow tier and marking
// composed removes the composed-not-ready reason (the other node-state reasons may still
// be present in a bare test process — that is the point of a fail-closed superset check).
func TestPreflight_ComposedClearsComposedReason(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway)
	if containsReason(pf.Reasons, shadowPFNotComposed) {
		t.Fatalf("composed node must not report %s, got %v", shadowPFNotComposed, pf.Reasons)
	}
	// The live tier must NOT be armed by arming shadow — so the forbidden-live reason
	// must never appear from a shadow-only composition.
	if containsReason(pf.Reasons, shadowPFLiveRequirement) {
		t.Fatalf("SECURITY: a shadow-only node must not report a live-execution requirement, got %v", pf.Reasons)
	}
}

// TestPreflight_RequiresInspectionComposed pins that a Shadow node without request
// inspection wired fails preflight (Codex P1, PR #1234) — Shadow must evaluate against
// inspection, never classify an inspection-rejectable input as would_execute.
func TestPreflight_RequiresInspectionComposed(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	// inspectionComposed deliberately left false.
	pf := evaluateShadowActivationPreflight(rollout.CapabilityGateway)
	if pf.Ready {
		t.Fatal("preflight must not be ready without request inspection composed")
	}
	if !containsReason(pf.Reasons, shadowPFNoInspection) {
		t.Fatalf("expected %s, got %v", shadowPFNoInspection, pf.Reasons)
	}
}

// TestGatewayServingReady_RequiresConfiguredAndPhaseReady pins the pure phase mapping the
// Shadow preflight relies on (Codex P1, PR #1234): "configured at startup" is NOT "live and
// serving". serve() sets PhaseReady synchronously, but a listener that later exits its serve
// loop with an error is PhaseDegraded while the observe state stays configured — so only
// (configured AND a present snapshot AND PhaseReady) counts as serving-ready.
func TestGatewayServingReady_RequiresConfiguredAndPhaseReady(t *testing.T) {
	ready := mcpruntime.HealthSnapshot{Phase: mcpruntime.PhaseReady}
	if !gatewayServingReady(mcpObserveConfigured, ready, true) {
		t.Fatal("configured + PhaseReady + snapshot present must be serving-ready")
	}
	// Every non-ready phase must fail even while the observe state stays configured — this is
	// exactly the degraded-serve-loop gap the fix closes.
	for _, p := range []mcpruntime.Phase{
		mcpruntime.PhaseDegraded, mcpruntime.PhaseStarting, mcpruntime.PhaseDraining,
		mcpruntime.PhaseStopped, mcpruntime.PhaseDisabled,
	} {
		if gatewayServingReady(mcpObserveConfigured, mcpruntime.HealthSnapshot{Phase: p}, true) {
			t.Fatalf("phase %v must not be serving-ready even while the observe state is configured", p)
		}
	}
	// No live snapshot (runtime not bound) ⇒ not serving-ready, whatever the state says.
	if gatewayServingReady(mcpObserveConfigured, ready, false) {
		t.Fatal("a missing gateway health snapshot must not be serving-ready")
	}
	// An unconfigured observe state ⇒ not serving-ready even against a stale PhaseReady snapshot.
	if gatewayServingReady(mcpObserveInvalid, ready, true) {
		t.Fatal("an unconfigured observe state must not be serving-ready")
	}
}

// TestPreflight_RequiresLiveListenerServing pins that the preflight requires the gateway
// listener to be LIVE and serving, not merely configured at startup (Codex P1, PR #1234).
// The observe state is held CONFIGURED throughout, so a preflight that consulted only the
// startup result would treat the listener as ready; the live probe is the sole decider.
// Mutation: reverting the preflight to the startup-state-only check clears the reason while
// the listener is degraded (state is configured) and fails the first assertion.
func TestPreflight_RequiresLiveListenerServing(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	globalMCPShadow.inspectionComposed.Store(true)

	prevStatus := getMCPObserveStatus()
	setMCPObserveStatus(mcpObserveActivation{State: mcpObserveConfigured})
	prevProbe := gatewayListenerReadyProbe
	t.Cleanup(func() {
		setMCPObserveStatus(prevStatus)
		gatewayListenerReadyProbe = prevProbe
	})

	// Listener started then degraded: observe state stays configured, live phase is not ready.
	gatewayListenerReadyProbe = func() bool { return false }
	if !containsReason(evaluateShadowActivationPreflight(rollout.CapabilityGateway).Reasons, shadowPFListenerNotReady) {
		t.Fatalf("a configured-but-degraded gateway listener must report %s", shadowPFListenerNotReady)
	}

	// Live and serving ⇒ the listener reason is cleared.
	gatewayListenerReadyProbe = func() bool { return true }
	if containsReason(evaluateShadowActivationPreflight(rollout.CapabilityGateway).Reasons, shadowPFListenerNotReady) {
		t.Fatal("a live, serving gateway listener must clear the listener-not-ready reason")
	}
}

// TestRunbookShadowScope_AdmitsWriteToolCall pins the operator runbook's documented Shadow
// scope (docs/operator/mcp-shadow-activation.md §2) against the runtime's risk classification
// (Codex P1, PR #1234): every Gateway tools/call is RiskWrite (policyOperation), so the scope
// MUST admit the write class or the controlled experiment records zero Shadow evaluations.
// It also pins the read-only mistake the runbook fix corrects — a read-only scope admits NO
// tools/call — so the doc cannot silently regress to a scope that shadows nothing.
func TestRunbookShadowScope_AdmitsWriteToolCall(t *testing.T) {
	lim := rollout.DefaultLimits()
	// A tools/call subject for the ONE controlled server + synthetic principal. Its Operation
	// is RiskWrite exactly as subjectFor(mapRisk(OpWrite)) produces for a Gateway tools/call.
	subj := rollout.Subject{
		Capability:  rollout.CapabilityGateway,
		ServerID:    "controlled-test-server",
		PrincipalID: "synthetic-shadow-principal",
		Operation:   rollout.RiskWrite,
	}

	// The documented scope: operations=[write] (2) with high_risk=true.
	documented := rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{"controlled-test-server"},
		Principals: []string{"synthetic-shadow-principal"},
		Operations: []rollout.RiskClass{rollout.RiskWrite},
		HighRisk:   true,
	}
	sc, err := rollout.Compile(documented, 1, lim)
	if err != nil {
		t.Fatalf("the documented runbook scope must validate: %v", err)
	}
	if !sc.Contains(subj) {
		t.Fatal("the documented runbook scope must ADMIT a write-class tools/call — otherwise the " +
			"controlled Shadow experiment records zero evaluations")
	}

	// The read-only scope the fix moves away from: it compiles, but admits NO tools/call.
	readOnly := rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{"controlled-test-server"},
		Principals: []string{"synthetic-shadow-principal"},
		Operations: []rollout.RiskClass{rollout.RiskRead},
	}
	roSc, err := rollout.Compile(readOnly, 1, lim)
	if err != nil {
		t.Fatalf("read-only scope compile: %v", err)
	}
	if roSc.Contains(subj) {
		t.Fatal("a read-only scope must NOT admit a write-class tools/call — this is exactly the " +
			"zero-evaluations bug the runbook fix documents")
	}
}

// TestShadowActivation_FailedPreflightDoesNotCommit is §15 mutation #7: a signed Shadow
// envelope reaching the CP→DP accept path with shadow deps ARMED but the node NOT ready
// (no telemetry/policy/inventory/listener) must be rejected by the preflight — no rollout
// commit, no distribution activation, no AckApplied. Mutation: removing the preflight
// gate lets the commit proceed (mode advances to Shadow) and fails this test.
func TestShadowActivation_FailedPreflightDoesNotCommit(t *testing.T) {
	s, _ := mcpProdSetup(t)
	resetExecDeps(t)
	resetShadowComposition(t)
	// Arm the shadow tier + mark composed so modeExecReady PASSES — this isolates the
	// preflight as the thing under test (otherwise the coarser exec-deps gate would reject
	// first and the preflight would never run).
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	// Deliberately leave telemetry/policy/inventory/listener UNSET so the preflight fails.

	a := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	env := mcpSignedGWEnv(t, s, 2, mcpShadowRollout(rollout.CapabilityGateway, 1))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})

	if getMCPRollout().gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatalf("SECURITY: a failed shadow preflight must not commit Shadow state, mode=%s", getMCPRollout().gateway.CurrentMode())
	}
	if getMCPRollout().gateway.Evidence().ShadowStartUnix != 0 {
		t.Fatal("no Shadow window may be stamped when the preflight fails")
	}
	if a.Active() != nil {
		t.Fatal("distribution must NOT activate when the shadow preflight fails (no split)")
	}
	if pa := a.PendingAck(); pa != nil && pa.State == cpdp.AckApplied {
		t.Fatal("no AckApplied may exist for a Shadow config the preflight rejected")
	}
}
