package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// The readiness split (docs/design/mcp/SHADOW-ACTIVATION.md §3). After Layer B (#1226)
// Shadow readiness and live-execution readiness are SEPARATE tiers with a strict,
// load-bearing invariant:
//
//	Shadow readiness MUST NOT imply live-execution readiness.
//	Live-execution readiness MUST NOT become true merely because Shadow is available.
//
// These are the security boundary that lets Shadow be activated on a controlled node
// while every Canary/Production transition stays fail-closed. Each assertion below is
// verified by a mutation that COMPILES and CHANGES BEHAVIOUR (see the mutation notes).

// resetExecDeps clears both tiers for both capabilities and restores them after the
// test, so an ordering/shuffle never leaks a set flag into another test.
func resetExecDeps(t *testing.T) {
	t.Helper()
	sg := globalExecDeps.shadowGateway.Load()
	sm := globalExecDeps.shadowManagement.Load()
	lg := globalExecDeps.gateway.Load()
	lm := globalExecDeps.management.Load()
	globalExecDeps.shadowGateway.Store(false)
	globalExecDeps.shadowManagement.Store(false)
	globalExecDeps.gateway.Store(false)
	globalExecDeps.management.Store(false)
	t.Cleanup(func() {
		globalExecDeps.shadowGateway.Store(sg)
		globalExecDeps.shadowManagement.Store(sm)
		globalExecDeps.gateway.Store(lg)
		globalExecDeps.management.Store(lm)
	})
}

// TestReadinessSplit_ShadowDoesNotImplyLive is the core invariant: arming the shadow
// tier must NOT arm the live tier. Mutation: making markGatewayShadowDepsReady also
// set globalExecDeps.gateway fails this test.
func TestReadinessSplit_ShadowDoesNotImplyLive(t *testing.T) {
	resetExecDeps(t)
	markGatewayShadowDepsReady()
	if !shadowDepsConfigured(false) {
		t.Fatal("shadow tier should be armed")
	}
	if liveExecDepsConfigured(false) {
		t.Fatal("SECURITY: arming shadow readiness must NOT arm live-execution readiness")
	}
	// Shadow may now transition; Canary/Production must still fail closed.
	if !modeExecReady(rollout.ModeShadow, false) {
		t.Fatal("Shadow must be admissible once shadow deps are ready")
	}
	if modeExecReady(rollout.ModeCanary, false) || modeExecReady(rollout.ModeProduction, false) {
		t.Fatal("SECURITY: Canary/Production must stay fail-closed with only shadow deps armed")
	}
}

// TestReadinessSplit_LiveDoesNotImplyShadowAndViceVersa pins the reverse and the
// capability isolation. Mutation: collapsing the two tiers into one flag fails here.
func TestReadinessSplit_LiveDoesNotImplyShadowAndViceVersa(t *testing.T) {
	resetExecDeps(t)
	// Arming the live tier alone (the future live composition) does not read the shadow
	// flag; both predicates answer only their own tier.
	markGatewayExecDepsReady()
	if !liveExecDepsConfigured(false) {
		t.Fatal("live tier should be armed")
	}
	// Live composition would arm shadow too in reality, but the FLAGS are independent:
	// the live hook must not set the shadow flag as a side effect.
	if shadowDepsConfigured(false) {
		t.Fatal("live-exec hook must not set the shadow flag as a side effect")
	}
}

// TestReadinessSplit_CapabilityIsolation pins that Gateway readiness never satisfies a
// Management gate and vice versa. Mutation: making shadowDepsConfigured ignore its
// capability argument fails here.
func TestReadinessSplit_CapabilityIsolation(t *testing.T) {
	resetExecDeps(t)
	markGatewayShadowDepsReady()
	if !shadowDepsConfigured(false) {
		t.Fatal("gateway shadow tier should be armed")
	}
	if shadowDepsConfigured(true) {
		t.Fatal("SECURITY: gateway shadow readiness must not satisfy a Management gate")
	}
	if modeExecReady(rollout.ModeShadow, true) {
		t.Fatal("SECURITY: Management Shadow must fail closed when only Gateway is armed")
	}
}

// TestReadinessSplit_ManagementLiveHookIsCapabilityLocal pins the Management symmetry of
// the split: the LIVE Management arming hook arms ONLY the live Management tier — it does
// not arm the shadow tier, the Gateway tier, or make a Management Shadow transition
// succeed. Mutation: making markManagementExecDepsReady also set shadowManagement (or
// gateway) fails here.
func TestReadinessSplit_ManagementLiveHookIsCapabilityLocal(t *testing.T) {
	resetExecDeps(t)
	markManagementExecDepsReady()
	if !liveExecDepsConfigured(true) {
		t.Fatal("management live tier should be armed")
	}
	if shadowDepsConfigured(true) {
		t.Fatal("the live Management hook must not arm the Management shadow tier")
	}
	if liveExecDepsConfigured(false) || shadowDepsConfigured(false) {
		t.Fatal("the Management hook must not arm any Gateway tier")
	}
	// A Management Shadow transition still fails closed (it needs the shadow tier).
	if modeExecReady(rollout.ModeShadow, true) {
		t.Fatal("SECURITY: Management Shadow must fail closed with only the live tier armed")
	}
}

// TestReadinessSplit_ModeExecReadyDefaults pins that Disabled/Observe need no readiness
// tier (they never touch the execution plane) while an executing mode does.
func TestReadinessSplit_ModeExecReadyDefaults(t *testing.T) {
	resetExecDeps(t)
	// Nothing armed.
	if !modeExecReady(rollout.ModeDisabled, false) || !modeExecReady(rollout.ModeObserve, false) {
		t.Fatal("Disabled/Observe must be ready with no execution deps")
	}
	if modeExecReady(rollout.ModeShadow, false) {
		t.Fatal("Shadow must fail closed with nothing armed")
	}
	if modeExecReady(rollout.ModeCanary, false) {
		t.Fatal("Canary must fail closed with nothing armed")
	}
}
