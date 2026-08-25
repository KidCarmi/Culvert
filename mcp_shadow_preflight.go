package main

import "github.com/KidCarmi/Culvert/internal/mcp/rollout"

// Shadow activation preflight (SHADOW-ACTIVATION.md §14). Before a node ACCEPTS a
// transition to Shadow, it must verify it is genuinely able to EVALUATE Shadow traffic
// and record the evidence — otherwise a "Shadow" mode would claim a contract the node
// cannot satisfy. The preflight returns a bounded, sanitized reason list (never a
// secret, path, tenant, or raw error); an empty list means ready. A failed preflight
// REJECTS the activation fail-closed.
//
// It is used at two points: the CP→DP accept path (applyMCPCapabilityEnvelope) gates a
// signed Shadow config on it, and the admin surface exposes it read-only as an operator
// dry-run before publishing a Shadow config.

// shadowPreflightResult is the structured, safe preflight outcome.
type shadowPreflightResult struct {
	Ready   bool     `json:"ready"`
	Reasons []string `json:"reasons"` // bounded classification codes; empty ⇒ ready
}

// Bounded preflight reason codes (fixed vocabulary; never interpolated with runtime data).
const (
	shadowPFNotGateway       = "shadow_not_supported_for_capability"
	shadowPFNotComposed      = "shadow_evaluator_not_composed"
	shadowPFLiveRequirement  = "forbidden_live_execution_requirement"
	shadowPFNoEvents         = "durable_events_unavailable"
	shadowPFNoPolicy         = "policy_unavailable"
	shadowPFNoInventory      = "registry_or_catalog_unavailable"
	shadowPFListenerNotReady = "gateway_listener_not_ready"
	shadowPFKillActive       = "emergency_kill_active"
)

// evaluateShadowActivationPreflight verifies node readiness to activate Shadow for a
// capability. It is pure w.r.t. state (reads node-local holders, no mutation) and
// fail-closed: any missing prerequisite adds a reason and marks the result not-ready.
func evaluateShadowActivationPreflight(capb rollout.Capability) shadowPreflightResult {
	// Shadow (an upstream-evaluation concept) is Gateway-only. Management never evaluates
	// an upstream tools/call, so a Management Shadow activation fails closed here.
	if capb != rollout.CapabilityGateway {
		return shadowPreflightResult{Ready: false, Reasons: []string{shadowPFNotGateway}}
	}

	var reasons []string
	// The non-executing evaluator must be composed AND its readiness tier armed.
	if !globalMCPShadow.composed.Load() || !shadowDepsConfigured(false) {
		reasons = append(reasons, shadowPFNotComposed)
	}
	// A Shadow activation must NEVER require or imply live-execution readiness — the whole
	// point of the readiness split. If the live tier is somehow armed, refuse (a Shadow
	// evaluation must not run on a node that also believes it can execute upstream).
	if liveExecDepsConfigured(false) {
		reasons = append(reasons, shadowPFLiveRequirement)
	}
	// Durable events are mandatory (evidence-before-report). The shared telemetry holder
	// is the source of truth for the composed events manager.
	if sharedTelemetry() == nil {
		reasons = append(reasons, shadowPFNoEvents)
	}
	// A real decision requires the node-local policy snapshot and the registry/catalog.
	if !mcpPolicy.composed() {
		reasons = append(reasons, shadowPFNoPolicy)
	}
	if reg, cat := mcpInventory.sharedInventory(); reg == nil || cat == nil {
		reasons = append(reasons, shadowPFNoInventory)
	}
	// The Gateway listener must be configured/serving.
	if getMCPObserveStatus().State != mcpObserveConfigured {
		reasons = append(reasons, shadowPFListenerNotReady)
	}
	// An engaged emergency kill switch stops admission; activating Shadow into it would be
	// misleading (no traffic would be evaluated). Refuse until the kill is cleared.
	if getMCPRollout().stateFor(capb).Killed() {
		reasons = append(reasons, shadowPFKillActive)
	}
	return shadowPreflightResult{Ready: len(reasons) == 0, Reasons: reasons}
}
