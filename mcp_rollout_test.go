package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

func TestMCPRolloutDisabledByDefault(t *testing.T) {
	r := &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	if r.gateway.CurrentMode() != rollout.ModeDisabled || r.management.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("both capabilities must default to Disabled")
	}
	st := r.status()
	if st["production_locked"] != true {
		t.Fatal("production must be locked")
	}
}

func TestMCPRolloutCapabilityIsolation(t *testing.T) {
	r := &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	// A Gateway rollout config must never touch Management state.
	cfg := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeObserve,
		Scope: rollout.ScopeSpec{Capability: rollout.CapabilityGateway}, ConnectorMode: rollout.ConnectorLocalClient,
	}
	r.applyRolloutConfig(cfg, "test")
	if r.gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("gateway mode should advance to Observe")
	}
	if r.management.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("management mode must NOT change when a gateway config is applied (isolation)")
	}
}

func TestMCPRolloutEmergencyNarrowsOnly(t *testing.T) {
	r := &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	r.emergencyDisable(rollout.CapabilityGateway, "oncall")
	if !r.gateway.Killed() {
		t.Fatal("emergency disable must engage the gateway kill switch")
	}
	if r.management.Killed() {
		t.Fatal("gateway emergency must not affect management")
	}
	r.clearEmergency(rollout.CapabilityGateway)
	if r.gateway.Killed() {
		t.Fatal("clear emergency must release the kill switch")
	}
}

func TestMCPRolloutRejectsBadConnector(t *testing.T) {
	r := &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	// An outbound-connector config must be rejected (state unchanged).
	cfg := &rollout.SignedConfig{
		SelectorSchema: 1, Capability: rollout.CapabilityGateway, Mode: rollout.ModeObserve,
		Scope: rollout.ScopeSpec{Capability: rollout.CapabilityGateway}, ConnectorMode: rollout.ConnectorOutbound,
	}
	r.applyRolloutConfig(cfg, "test")
	if r.gateway.CurrentMode() != rollout.ModeDisabled {
		t.Fatal("a rejected connector-mode config must leave the state unchanged")
	}
}
