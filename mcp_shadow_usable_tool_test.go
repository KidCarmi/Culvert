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
