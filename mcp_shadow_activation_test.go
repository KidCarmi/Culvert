package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
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
