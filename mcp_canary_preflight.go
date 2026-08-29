package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Canary activation preflight (ADR-0035). This is the root composition-layer bridge between
// live node state and the pure internal/mcp/canary readiness engine. It reads node-local
// holders (no mutation, no I/O beyond a tool-trust reconcile) and produces the machine-
// verifiable Canary readiness verdict.
//
// It imports NEITHER internal/mcp/execution NOR internal/mcp/upstreamclient — it reasons
// about the live tier through the execdeps registry (liveExecDepsConfigured), so wiring the
// preflight can never itself compose or reach a live executor. In the shipped build the live
// tier is never armed, so this always returns NOT-READY with at least live_executor_absent
// (plus the boundary-guard, upstream, and credential facts, which the live composition would
// assert). Canary activation is therefore fail-closed and reviewable without ever being
// reachable — the point of this phase.
//
// It is consulted at the CP→DP apply path (applyMCPCapabilityEnvelope) as defense-in-depth
// for a RequiresLiveExecution mode — AFTER modeExecReady already fails such a transition
// closed — and is exposed read-only on the admin surface as an operator dry-run.

// shadowExitReviewAttested reports whether the full 13-criterion Shadow Exit Review is
// attested for this node/scope. There is deliberately NO runtime attestation surface yet:
// the review is a governance artifact, and the separately-reviewed Canary arming activation
// is what would supply the attestation. Until then this returns false, so Canary readiness
// carries shadow_exit_review_not_passed — a truthful "this prerequisite is not machine-
// attested here", never a silent pass.
func shadowExitReviewAttested() bool { return false }

// canaryNodeFacts fills the SCOPE-INDEPENDENT half of the Canary facts for a capability from
// live node state. The live-execution-specific facts (executor, upstream, credential path,
// boundary guards) derive from liveExecDepsConfigured: the guarded live executor — whose
// final kill-generation and tool-freshness boundary guards are independently pinned by
// internal/mcp/execution's PREREQ-MCP-KILL-1 tests — is composed as ONE unit, so those facts
// are true exactly when the live tier is armed (never, in this build). The evaluation-plane
// facts (events, policy, inventory, inspection, kill) derive from their own live signals so a
// future live node with, say, degraded durable events fails on that specific fact.
func canaryNodeFacts(capb rollout.Capability) canary.Facts {
	live := liveExecDepsConfigured(capb == rollout.CapabilityManagement)
	reg, cat := mcpInventory.sharedInventory()
	return canary.Facts{
		CapabilityGateway:      capb == rollout.CapabilityGateway,
		ShadowExitReviewPassed: shadowExitReviewAttested(),

		// Live-execution plane (composed as one unit; absent in this build).
		LiveExecutorComposed:      live,
		UpstreamCallerPresent:     live,
		CredentialPathReady:       live,
		KillBoundaryGuardPresent:  live,
		ToolFreshnessGuardPresent: live,

		// Evaluation plane — each from its own live signal.
		DurableEventsHealthy:    durableEventsHealthy(capb),
		ResponseInspectionReady: globalMCPShadow.inspectionComposed.Load(),
		RegistryHealthy:         reg != nil,
		CatalogHealthy:          cat != nil,
		PolicyHealthy:           mcpPolicy.composed(),
		EmergencyKillClear:      !getMCPRollout().stateFor(capb).Killed(),

		// Rollback: a node whose rollout coordinator is live can always demote (narrowing-only
		// emergency disable is unconditional); reflect that the coordinator exists.
		RollbackPathHealthy: getMCPRollout() != nil,

		// Scope/approval/budget facts default false here; the activation preflight sets them.
		ScopeBounded:           false,
		ScopeReadFirst:         false,
		LiveApprovalValid:      false,
		ServerUsable:           false,
		ToolFingerprintCurrent: false,
		BudgetConfigured:       false,
	}
}

// durableEventsHealthy reports whether the durable-event plane is actually HEALTHY for the
// Canary's capability domain — not merely present. A live execution commits an
// evidence-before-side-effect decision through this plane; if the domain's critical durability
// is degraded, a decision may not be durably recorded before the irreversible side effect, so
// Canary must NOT be ready (Codex P1-B, PR #1249). It is fail-closed: false unless the
// telemetry runtime is composed AND the matching capability domain reports the "normal"
// critical state (a degraded/recovering/unknown domain, or a missing domain snapshot, all fail
// closed).
func durableEventsHealthy(capb rollout.Capability) bool {
	t := sharedTelemetry()
	if t == nil {
		return false
	}
	mgr := t.Manager()
	if mgr == nil {
		return false
	}
	dom := evmodel.CapGateway
	if capb == rollout.CapabilityManagement {
		dom = evmodel.CapManagement
	}
	dh, ok := mgr.Health().Domains[dom]
	if !ok {
		return false
	}
	return dh.CriticalState == "normal"
}

// CanaryActivationInput carries the scope-dependent activation inputs the preflight layers on
// top of node readiness: the requested Canary scope, one candidate live_execution approval
// PER SCOPED TOOL (each bound to that tool's exact current target — never a single
// unconstrained approval trusted for the whole scope; Codex P1-C), and the blast-radius
// budget. All are supplied by the (future) activation caller; the pure canary validators decide.
type CanaryActivationInput struct {
	Capability rollout.Capability
	Scope      rollout.ScopeSpec
	ScopeRev   uint64
	// ToolApprovals must exactly cover every tool in Scope.Tools — one valid live_execution
	// approval bound to each scoped tool's exact current target. A partial or over-broad set
	// fails closed (LiveApprovalValid stays false).
	ToolApprovals []canary.ToolApprovalBinding
	Budget        canary.Budget
	// ServerUsable / FingerprintCurrent are the live-observation facts the caller resolves
	// from the registry/catalog for the exact targets (kept as inputs so the preflight stays
	// pure w.r.t. inventory beyond the node scan).
	ServerUsable       bool
	FingerprintCurrent bool
	Now                time.Time
}

// evaluateCanaryNodeReadiness returns the scope-independent Canary node readiness verdict.
// It is the operator dry-run surface: before any Canary scope is chosen, it reports which
// node-level prerequisites hold. In this build it always carries live_executor_absent.
func evaluateCanaryNodeReadiness(capb rollout.Capability) canary.Readiness {
	return canary.Evaluate(canaryNodeFacts(capb))
}

// evaluateCanaryActivationPreflight returns the FULL Canary readiness verdict for a capability
// plus a requested scope, candidate live approval, and budget. It layers the scope/approval/
// budget/target facts (decided by the pure canary validators) onto node readiness. Fail-
// closed: any unmet prerequisite appears in Unmet and Ready stays false.
func evaluateCanaryActivationPreflight(in CanaryActivationInput) canary.Readiness {
	f := canaryNodeFacts(in.Capability)
	f.ScopeBounded = canary.ValidateScope(in.Scope, in.ScopeRev) == canary.ScopeOK
	f.ScopeReadFirst = canary.ScopeReadFirst(in.Scope)
	// LiveApprovalValid is true only when EVERY scoped tool has its own valid live_execution
	// approval bound to that exact tool identity — never a single unconstrained approval.
	f.LiveApprovalValid = canary.ValidateScopeApprovals(in.Scope, in.ToolApprovals, in.Now) == canary.ScopeApprovalOK
	f.ServerUsable = in.ServerUsable
	f.ToolFingerprintCurrent = in.FingerprintCurrent
	f.BudgetConfigured = canary.ValidateBudget(in.Budget) == canary.BudgetOK
	return canary.Evaluate(f)
}

// canaryActivationReady is the single boolean gate a future arming activation would consult
// for a RequiresLiveExecution mode. It is intentionally redundant with modeExecReady (which
// already fails such a transition closed on the unarmed live tier): defense-in-depth, and the
// reason list it can surface names EVERY missing prerequisite, not just the exec-deps one.
// Always false in this build.
func canaryActivationReady(capb rollout.Capability) bool {
	return evaluateCanaryNodeReadiness(capb).Ready
}

// mcpCanaryStatus is the read-only Canary readiness surface exposed under GET
// /api/mcp/rollout (the "canary" sub-view). It reports, for the Gateway capability, whether
// the node is Canary-ready (always false here), the machine-readable unmet-prerequisite list,
// the FULL prerequisite vocabulary an operator must satisfy, and the fixed first-Canary
// bounds/ceilings — so the activation contract is observable without SSH and without any
// ability to activate. Values only; no secret, tenant, or path ever appears.
func mcpCanaryStatus() map[string]any {
	rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	unmet := make([]string, 0, len(rd.Unmet))
	for _, r := range rd.Unmet {
		unmet = append(unmet, string(r))
	}
	all := canary.AllReasons()
	allStr := make([]string, 0, len(all))
	for _, r := range all {
		allStr = append(allStr, string(r))
	}
	return map[string]any{
		// Canary is architecturally defined but never armed in this build.
		"defined":              true,
		"node_ready":           rd.Ready,
		"unmet":                unmet,
		"all_prerequisites":    allStr,
		"live_execution_armed": liveExecDepsConfigured(false),
		"first_canary_bounds": map[string]any{
			"max_servers":            canary.MaxCanaryServers,
			"max_tools":              canary.MaxCanaryTools,
			"max_principals":         canary.MaxCanaryPrincipals,
			"max_total_ceiling":      canary.FirstCanaryMaxTotalCeiling,
			"max_window_hours":       int(canary.FirstCanaryMaxWindowCeiling.Hours()),
			"max_approval_ttl_hours": int(canary.MaxInitialCanaryApprovalTTL.Hours()),
			"read_first":             true,
		},
	}
}
