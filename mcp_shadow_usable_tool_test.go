package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestShadowScopeHasUsableTool_QuarantinedCatalogIsNotUsable proves the production reality
// Codex flagged (P1, PR #1234): catalog ingestion NEVER yields Usable ("approval is a later
// slice"), so even a fully-ingested tool on the controlled server is Quarantined and does NOT
// satisfy the Shadow usable-tool precondition. Without an approval/promotion slice the gate is
// therefore fail-closed in production, which is the intended posture.
func TestShadowScopeHasUsableTool_QuarantinedCatalogIsNotUsable(t *testing.T) {
	resetInventory(t)
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"controlled","endpoint":"e","pinned_identity":"id","enabled":true,
	   "tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)

	// Precondition: the tool IS ingested and present — but Quarantined, not Usable.
	if cat.Current().Len() == 0 {
		t.Fatal("precondition: the controlled server's tool must be ingested")
	}

	spec := rollout.ScopeSpec{
		Capability: rollout.CapabilityGateway,
		Servers:    []string{"controlled"},
		Operations: []rollout.RiskClass{rollout.RiskWrite},
		HighRisk:   true,
	}
	if shadowScopeHasUsableTool(spec, 1) {
		t.Fatal("a catalog whose only in-scope tool is Quarantined must NOT satisfy the usable-tool " +
			"gate — this is the zero-would_execute reality the gate closes until the approval slice ships")
	}

	// No inventory at all ⇒ also fail closed.
	publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
	if shadowScopeHasUsableTool(spec, 1) {
		t.Fatal("no inventory must fail the usable-tool gate closed")
	}
}

// TestPreflight_RequiresUsableToolInScope pins that the Shadow activation preflight fails
// closed unless the requested scope has a usable tool (Codex P1, PR #1234). It consumes the
// usable-tool probe: probe=false ⇒ the no_usable_shadow_tools reason is present; probe=true ⇒
// it is cleared. Mutation: removing the usable-tool check from the preflight never emits the
// reason and fails the first assertion.
func TestPreflight_RequiresUsableToolInScope(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	globalMCPShadow.inspectionComposed.Store(true)

	prevStatus := getMCPObserveStatus()
	setMCPObserveStatus(mcpObserveActivation{State: mcpObserveConfigured})
	prevListener := gatewayListenerReadyProbe
	prevUsable := shadowScopeUsableToolProbe
	t.Cleanup(func() {
		setMCPObserveStatus(prevStatus)
		gatewayListenerReadyProbe = prevListener
		shadowScopeUsableToolProbe = prevUsable
	})
	gatewayListenerReadyProbe = func() bool { return true }

	// No usable tool in scope ⇒ the reason is present and the preflight is not ready.
	shadowScopeUsableToolProbe = func(rollout.ScopeSpec, uint64) bool { return false }
	if !containsReason(evaluateShadowActivationPreflight(rollout.CapabilityGateway, rollout.ScopeSpec{}, 0).Reasons, shadowPFNoUsableTools) {
		t.Fatalf("a scope with no usable tool must report %s", shadowPFNoUsableTools)
	}

	// A usable in-scope tool ⇒ the reason is cleared.
	shadowScopeUsableToolProbe = func(rollout.ScopeSpec, uint64) bool { return true }
	if containsReason(evaluateShadowActivationPreflight(rollout.CapabilityGateway, rollout.ScopeSpec{}, 0).Reasons, shadowPFNoUsableTools) {
		t.Fatal("a usable in-scope tool must clear the no-usable-tools reason")
	}
}

// TestNodeReadiness_ExcludesScopeDependentUsableToolCheck pins the round-8 split (Codex P2,
// PR #1234): the scope-INDEPENDENT node-readiness dry-run must NEVER report
// no_usable_shadow_tools — that precondition is scope-dependent and belongs only to the
// apply/commit preflight. Before the first Observe→Shadow activation the active scope is the
// empty Observe/Disabled scope, so if the node status folded the usable-tool check in it would
// always report node-not-ready regardless of node health, and an operator could never see a
// healthy node. Mutation: making evaluateShadowNodeReadiness append the usable-tool reason (or
// having the dry-run call evaluateShadowActivationPreflight against the empty scope again) fails
// the first assertion.
func TestNodeReadiness_ExcludesScopeDependentUsableToolCheck(t *testing.T) {
	resetExecDeps(t)
	resetShadowComposition(t)
	markGatewayShadowDepsReady()
	globalMCPShadow.composed.Store(true)
	globalMCPShadow.inspectionComposed.Store(true)

	prevStatus := getMCPObserveStatus()
	setMCPObserveStatus(mcpObserveActivation{State: mcpObserveConfigured})
	prevListener := gatewayListenerReadyProbe
	prevUsable := shadowScopeUsableToolProbe
	t.Cleanup(func() {
		setMCPObserveStatus(prevStatus)
		gatewayListenerReadyProbe = prevListener
		shadowScopeUsableToolProbe = prevUsable
	})
	gatewayListenerReadyProbe = func() bool { return true }

	// No usable tool anywhere. The scope-independent node readiness must NEVER report the
	// usable-tool reason — it never consults the probe — regardless of which other node
	// prerequisites are (un)met in this minimal harness.
	shadowScopeUsableToolProbe = func(rollout.ScopeSpec, uint64) bool { return false }
	node := evaluateShadowNodeReadiness(rollout.CapabilityGateway)
	if containsReason(node.Reasons, shadowPFNoUsableTools) {
		t.Fatalf("node readiness must NOT report %s (it is scope-dependent, not a node property); reasons=%v",
			shadowPFNoUsableTools, node.Reasons)
	}

	// The scope-aware activation preflight, with the SAME probe returning false, MUST report it
	// on top of the exact node-readiness reasons — so the split moved the check onto the apply
	// path, it neither deleted it nor changed the node checks.
	full := evaluateShadowActivationPreflight(rollout.CapabilityGateway, rollout.ScopeSpec{}, 0)
	if !containsReason(full.Reasons, shadowPFNoUsableTools) {
		t.Fatalf("the activation preflight must still report %s when no usable tool is in scope; reasons=%v",
			shadowPFNoUsableTools, full.Reasons)
	}
	if len(full.Reasons) != len(node.Reasons)+1 {
		t.Fatalf("the activation preflight must be node reasons %v plus exactly the usable-tool reason, got %v",
			node.Reasons, full.Reasons)
	}
	if full.Ready {
		t.Fatal("the activation preflight must be not-ready when the usable-tool precondition fails")
	}
}
