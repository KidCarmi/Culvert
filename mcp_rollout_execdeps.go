package main

import (
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Rollout execution-readiness gates (MCP Shadow / live-execution safety).
//
// A rollout mode above Observe drives some part of the guarded-execution plane, and
// after Layer B (#1226) that plane splits into TWO readiness tiers that MUST stay
// independent (see docs/design/mcp/SHADOW-ACTIVATION.md §3):
//
//   - SHADOW readiness — the non-executing evaluation plane: a composed
//     *execution.ShadowEvaluator (no upstream client, no materialize-capable broker),
//     durable events, policy/catalog/registry, an optional plan-only CredentialPlanner,
//     request inspection, rollout state, health/metrics. Shadow evaluates real traffic
//     and records evidence but NEVER crosses the irreversible side-effect boundary.
//
//   - LIVE-EXECUTION readiness — everything Shadow has PLUS the live capabilities:
//     a live *execution.Executor, the bounded UpstreamCaller, credential Materialize,
//     and the final kill-switch boundary recheck. Only Canary/Production need this.
//
// The two tiers are separate atomic.Bools with a strict, non-negotiable invariant:
//
//	Shadow readiness MUST NOT imply live-execution readiness.
//	Live-execution readiness MUST NOT become true merely because Shadow is available.
//
// So markGatewayShadowDepsReady sets ONLY the shadow tier, markGatewayExecDepsReady
// sets ONLY the live tier, and neither reads or writes the other. This phase composes
// the ShadowEvaluator (mcp_shadow_startup.go) and calls markGatewayShadowDepsReady;
// it composes NO live executor and never calls markGatewayExecDepsReady, so a Shadow
// transition can be admitted while every Canary/Production transition still fails
// closed at the same gate. The evolved execution-posture wall
// (mcp_execution_posture_test.go) pins that the LIVE hooks stay uncalled.

// execDepsRegistry tracks, per capability, the two independent readiness tiers. All
// four default to false (the Observe-only shipped posture). Values are process-global
// and set once at startup by the composition layer.
type execDepsRegistry struct {
	// shadow — the non-executing Shadow evaluation plane is composed.
	shadowGateway    atomic.Bool
	shadowManagement atomic.Bool
	// live — the live-execution plane (executor + upstream + materialize) is composed.
	// This phase never sets either; both stay false so Canary/Production fail closed.
	gateway    atomic.Bool
	management atomic.Bool
}

var globalExecDeps = &execDepsRegistry{}

// markGatewayShadowDepsReady is the registration hook the Shadow composition
// (mcp_shadow_startup.go) calls once it has composed the non-executing ShadowEvaluator
// and its evaluation-plane dependencies for the Gateway capability. It arms ONLY the
// shadow tier — it never touches the live tier, so composing Shadow can never make a
// live-execution transition succeed.
func markGatewayShadowDepsReady() { globalExecDeps.shadowGateway.Store(true) }

// markManagementShadowDepsReady mirrors the Gateway hook for Management. Management
// never executes an upstream tools/call, so this is provided for symmetry only; the
// Management Shadow path is not composed in this phase.
func markManagementShadowDepsReady() { globalExecDeps.shadowManagement.Store(true) }

// markGatewayExecDepsReady is the live-execution ARMING hook: it sets the Gateway live tier
// armed so a Canary/Production MODE transition can be authorized (modeExecReady). It has
// exactly ONE authoritative production caller — the live-tier arming path (mcp_live_tier.go's
// arm → setLiveExecDepsArmed), pinned by the evolved execution-posture wall. Arming composes
// no executor and reaches no upstream; it only flips this readiness bit. Setting it is a
// deliberate, node-readiness-gated act, never a side effect of another change.
func markGatewayExecDepsReady() { globalExecDeps.gateway.Store(true) }

// markManagementExecDepsReady mirrors the Gateway live hook for Management.
func markManagementExecDepsReady() { globalExecDeps.management.Store(true) }

// clearGatewayExecDepsReady DISARMS the Gateway live tier (quiesce / restart fail-closed
// posture). Once cleared, modeExecReady refuses every live-execution transition again. It is
// safe to call redundantly.
func clearGatewayExecDepsReady() { globalExecDeps.gateway.Store(false) }

// clearManagementExecDepsReady mirrors the Gateway disarm for Management.
func clearManagementExecDepsReady() { globalExecDeps.management.Store(false) }

// setLiveExecDepsArmed is the single arm/disarm dispatcher the live-tier lifecycle uses to keep
// the authoritative execdeps armed bit in lock-step with the lifecycle state. arm passes true
// (→ markGateway/ManagementExecDepsReady), quiesce/restart pass false (→ the clear hooks). It
// is the ONLY production path that toggles the live armed bit; the wall permits the arming file
// to reach the underlying hooks through it.
func setLiveExecDepsArmed(capb rollout.Capability, armed bool) {
	if capb == rollout.CapabilityManagement {
		if armed {
			markManagementExecDepsReady()
		} else {
			clearManagementExecDepsReady()
		}
		return
	}
	if armed {
		markGatewayExecDepsReady()
	} else {
		clearGatewayExecDepsReady()
	}
}

// shadowDepsConfigured reports whether the non-executing Shadow evaluation plane for a
// capability is composed. False (fail-closed) is the shipped default.
func shadowDepsConfigured(capbManagement bool) bool {
	if capbManagement {
		return globalExecDeps.shadowManagement.Load()
	}
	return globalExecDeps.shadowGateway.Load()
}

// liveExecDepsConfigured reports whether the LIVE-execution plane for a capability is
// composed. False (fail-closed) is the shipped default for both capabilities, and this
// phase never sets it. It is deliberately independent of the shadow tier: a Shadow-only
// node reports shadowDepsConfigured==true and liveExecDepsConfigured==false.
func liveExecDepsConfigured(capbManagement bool) bool {
	if capbManagement {
		return globalExecDeps.management.Load()
	}
	return globalExecDeps.gateway.Load()
}

// modeExecReady reports whether the readiness tier a target mode REQUIRES is composed
// for the capability. It is the single decision every rollout-transition gate uses so
// the shadow-vs-live split is expressed in exactly one place:
//
//   - Canary/Production require the LIVE tier (liveExecDepsConfigured).
//   - Shadow requires only the SHADOW tier (shadowDepsConfigured).
//   - Disabled/Observe require nothing.
//
// Fail-closed: an unknown mode falls through to the Shadow/Observe arms and is only
// admitted if it is Disabled/Observe.
func modeExecReady(mode rollout.Mode, capbManagement bool) bool {
	switch {
	case mode.RequiresLiveExecution():
		return liveExecDepsConfigured(capbManagement)
	case mode == rollout.ModeShadow:
		return shadowDepsConfigured(capbManagement)
	default:
		return true
	}
}
