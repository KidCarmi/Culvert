package main

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
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

// shadowExitReviewAttested is defined in mcp_canary_attestation.go — it reads the durable,
// schema-versioned, build-bound Shadow Exit Review attestation (§1). It feeds
// canary.Facts.ShadowExitReviewPassed below; it is never a hard-coded boolean.

// canaryNodeFacts fills the SCOPE-INDEPENDENT half of the Canary facts for a capability from
// live node state. The live-execution-specific facts (executor, upstream, credential path,
// boundary guards) derive from liveExecDepsConfigured: the guarded live executor — whose
// final kill-generation and tool-freshness boundary guards are independently pinned by
// internal/mcp/execution's PREREQ-MCP-KILL-1 tests — is composed as ONE unit, so those facts
// are true exactly when the live tier is armed (never, in this build). The evaluation-plane
// facts (events, policy, inventory, inspection, kill) derive from their own live signals so a
// future live node with, say, degraded durable events fails on that specific fact.
func canaryNodeFacts(capb rollout.Capability) canary.Facts {
	// The durableMu-dependent facts (kill-clear, rollback-mechanics health, coordinator-rehearsal) come
	// from the process singleton via their own LOCKING reads — this is the dry-run/status path with no
	// lock held.
	r := getMCPRollout()
	return canaryNodeFactsWith(capb, !r.stateFor(capb).Killed(), rollbackPathHealthy(capb),
		coordinatorRollbackRehearsedFn(r, capb, false))
}

// canaryNodeFactsLocked is canaryNodeFacts for a caller that ALREADY holds r.durableMu (the commit's
// in-lock revalidation — Codex P1). It reads the two durableMu-sensitive facts from r WITHOUT
// re-locking: the kill state through State's own mutex, and rollback health through the LOCKED
// variant (rollbackPathReadyLocked). Every other fact reads a holder unrelated to durableMu, so it
// is safe to gather while the commit holds the lock.
func canaryNodeFactsLocked(r *mcpRollout, capb rollout.Capability) canary.Facts {
	return canaryNodeFactsWith(capb, !r.stateFor(capb).Killed(), r.rollbackPathReadyLocked(capb),
		coordinatorRollbackRehearsedFn(r, capb, true))
}

// canaryNodeFactsWith fills the scope-independent Canary facts, taking the durableMu-dependent facts
// (kill-clear, rollback-mechanics health, coordinator-rehearsal) as parameters so both the locking
// dry-run (canaryNodeFacts) and the in-lock commit revalidation (canaryNodeFactsLocked) share one fact
// table without either re-entering the non-reentrant durableMu.
func canaryNodeFactsWith(capb rollout.Capability, emergencyKillClear, rollbackHealthy, coordinatorRehearsed bool) canary.Facts {
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
		EmergencyKillClear:      emergencyKillClear,

		// Rollback: NOT mere coordinator existence. A durable, rehearsed rollback path is
		// required — emergencyDisable that only lands in memory can be silently re-admitted on
		// restart (Codex P1, PR #1249). See rollbackPathHealthy. This is rollback MECHANICS evidence.
		RollbackPathHealthy: rollbackHealthy,
		// The AUTHORITATIVE rollback path (coordinator-routed rehearsal, CANARY-ROLLBACK-COORDINATOR-
		// REHEARSAL) is a SEPARATE hard prerequisite from the mechanics rehearsal above. It is TRUE only
		// when a coordinator-routed drill left valid durable build-bound evidence; the caller resolves it
		// under the correct lock discipline and passes it in.
		RollbackCoordinatorRehearsed: coordinatorRehearsed,

		// Scope/approval/budget facts default false here. They are ACTIVATION-level, so the node
		// dry-run (EvaluateNode) skips them entirely — they are set and evaluated only by
		// evaluateCanaryActivationPreflight once an operator supplies a scope, approval, and
		// budget (Codex P2, PR #1249).
		ScopeBounded:           false,
		ScopeReadFirst:         false,
		ScopeExactFirstCanary:  false,
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

// coordinatorRollbackRehearsedFn reports whether the AUTHORITATIVE rollback path — a rehearsal routed
// through the real commitRolloutTransitionAt coordinator, so it exercises that coordinator's Shadow
// preflight, emergency-kill, revision, durability, and rollback guards — has been rehearsed for the
// capability. It is a SEAM: production is productionCoordinatorRollbackRehearsed, which returns FALSE
// in this build. The existing executable rehearsal drives rollbackPathHealthy and proves rollback
// MECHANICS (persist/restore) only, NOT that the authoritative coordinator would permit the demotion,
// so this is a SEPARATE hard prerequisite (CANARY-ROLLBACK-COORDINATOR-REHEARSAL) that keeps Canary
// readiness false — no transition can be READY merely because the mechanics rehearsal passed. It is
// OPEN by owner decision (the coordinator-routed rehearsal is a follow-up, not this PR); a future
// change flips the production impl to a real per-capability coordinator-rehearsal check. Tests that
// must exercise downstream activation logic arm this seam.
var coordinatorRollbackRehearsedFn = productionCoordinatorRollbackRehearsed

// productionCoordinatorRollbackRehearsed validates the CANARY-ROLLBACK-COORDINATOR-REHEARSAL
// prerequisite from DURABLE, build-bound evidence: it is TRUE only when a coordinator-routed rollback
// rehearsal (mcp_canary_coordinator_rehearsal.go — the Canary→Shadow→Observe demotion driven through
// the authoritative commitRolloutTransitionCore, then recovered to Observe) has succeeded for THIS
// build and left a valid record. Fail-closed: a missing/corrupt/incomplete/not-routed/stale-build
// record (and the shipped default, where no such rehearsal has run) returns false, so row 20 stays open
// until a real coordinator-routed drill succeeds. It NEVER short-circuits on the mechanics rehearsal:
// the two facts are DISTINCT (rollback_path_healthy vs rollback_coordinator_rehearsal_pending).
// The `locked` parameter names whether the caller already holds r.durableMu (the 1c gate does; the
// dry-run does not), so the fact reads the durable evidence via the correct locked/locking accessor and
// never re-enters the non-reentrant durableMu.
func productionCoordinatorRollbackRehearsed(r *mcpRollout, capb rollout.Capability, locked bool) bool {
	if r == nil {
		return false
	}
	if locked {
		return r.coordinatorRollbackRehearsalAttestedLocked(capb)
	}
	return r.coordinatorRollbackRehearsalAttested(capb)
}

// rollbackPathHealthy reports whether the deterministic Canary→Shadow/Observe rollback path is
// actually durable and EXECUTABLY rehearsed for the capability — not merely that the rollout
// coordinator object exists, and no longer merely that a self-attested boolean was toggled. A
// Canary must be instantly, RELIABLY reversible; if the coordinator's durable state is degraded or
// a write failed, an emergency demotion may land only in memory and be silently re-admitted on
// restart, and if rollback was never PROVEN reversible the reversal is unproven (Codex P1,
// PR #1249). §5 (Canary Activation Gate): the rehearsal fact is now driven by durable, build-bound
// executable evidence — a record that a REAL Canary→Shadow→Observe demotion drill produced through
// the actual persist/restore path — so an operator toggling a marker, or an ancient drill against a
// materially changed runtime, no longer satisfies it. Fail-closed: false unless the coordinator
// exists AND its persistence is not degraded/write_failed AND rollbackRehearsalAttested validates a
// current-build record. Until an operator runs the drill this is false — one more reason the
// dormant Canary is never ready.
func rollbackPathHealthy(capb rollout.Capability) bool {
	r := getMCPRollout()
	// rollbackPathReady reads persistStatus AND the durable rehearsal evidence under durableMu, so
	// it never observes the pre-persist window of an in-flight rehearsal (Codex P1, PR #1249).
	return r != nil && r.rollbackPathReady(capb)
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
	// ToolCatalogUsable — every scoped tool is currently catalog.Usable at the exact
	// fingerprint+format being bound (blocker #13). Resolved from authoritative inventory by
	// canaryScopedToolsCatalogUsable, never supplied by a request.
	ToolCatalogUsable bool
	Now               time.Time
}

// evaluateCanaryNodeReadiness returns the scope-independent Canary node readiness verdict.
// It is the operator dry-run surface: before any Canary scope is chosen, it reports which
// NODE-level prerequisites hold, and never reports an activation-input fact (scope/approval/
// budget/server/fingerprint) as unmet — those are decided only once a scope is supplied, by
// evaluateCanaryActivationPreflight (Codex P2, PR #1249). It uses canary.EvaluateNode so
// node_ready reflects node deficiencies alone. In this build it always carries
// live_executor_absent.
func evaluateCanaryNodeReadiness(capb rollout.Capability) canary.Readiness {
	return canary.EvaluateNode(canaryNodeFacts(capb))
}

// canaryActivationInputs are the ACTIVATION-level facts a Canary transition needs beyond the
// signed scope: one valid live_execution approval per scoped tool, the blast-radius budget, and the
// target server-usability / tool-fingerprint observations. They are resolved from AUTHORITATIVE
// node state (never request-supplied), so a signed Canary config can never smuggle them.
type canaryActivationInputs struct {
	ToolApprovals      []canary.ToolApprovalBinding
	Budget             canary.Budget
	ServerUsable       bool
	FingerprintCurrent bool
	ToolCatalogUsable  bool
}

// canaryActivationInputsProbe derives the authoritative activation-level inputs for a Canary
// transition into a scope. It is a SEAM: production is productionCanaryActivationInputs. Tests arm
// it to supply valid inputs.
var canaryActivationInputsProbe = productionCanaryActivationInputs

// productionCanaryActivationInputs resolves the activation-level inputs from AUTHORITATIVE node
// state, never a request. As of the live-execution-trust slice it wires ONE of them for real — the
// per-tool live_execution approvals, pulled from the tool-trust store — so the
// live_execution_approval_invalid readiness row becomes SATISFIABLE (a scope whose every tool has a
// valid, four-eyes, ≤24h, exact-target live approval passes canary.ValidateScopeApprovals; a stock
// node with no approved target still reports it unmet — §13/§27).
//
// Budget, ServerUsable, and FingerprintCurrent stay fail-closed (zero values) DELIBERATELY: this
// build ships no authoritative budget store, and the live tier is never armed. So even a fully
// approved scope leaves canary_budget_not_configured (+ server/fingerprint) unmet AND the node fact
// LiveExecutorComposed stays false — the ultimate backstop — so the FULL activation preflight can
// still never be satisfied and no Canary transition can occur (§0/§22). Wiring live approvals is a
// pure READ (the tool-trust store + the catalog observation); it arms nothing.
func productionCanaryActivationInputs(_ rollout.Capability, scope rollout.ScopeSpec, _ uint64) canaryActivationInputs {
	return canaryActivationInputs{
		ToolApprovals: buildLiveApprovalBindings(scope),
		// Blocker #13: catalog usability is an ACTIVATION FACT, resolved here from the
		// authoritative catalog rather than assumed by a runbook step. It is a pure read and
		// promotes nothing — the governed shadow_evaluation lifecycle is the only writer.
		ToolCatalogUsable: canaryScopedToolsCatalogUsable(scope),
	}
}

// liveApprovalKey indexes an active live_execution approval by its exact (tenant, server, tool)
// identity so a scoped tool binds only to an approval for the SAME tenant — an approval for another
// tenant can never count as coverage (the tenant-isolation half of §13).
type liveApprovalKey struct{ tenant, serverID, toolName string }

// buildLiveApprovalBindings resolves, for every (tenant × tool) the scope admits, the tool's CURRENT
// authoritative target (registry+catalog via the coordinator's loadTarget — never a request value)
// and the active live_execution approval(s) that bind that exact (tenant, server, tool). It returns
// one canary.ToolApprovalBinding per matching approval, so canary.ValidateScopeApprovals then decides
// coverage: a scoped tool with no matching approval, an approval whose target fingerprint drifted
// from the current observation (rug-pull, §8) or from the scope's declared fingerprint, a wrong-tenant
// approval, or a duplicate all fail closed there. It is a pure read and NEVER promotes catalog.Usable
// (live trust is orthogonal to Shadow usability, §15). An uncomposed coordinator or missing inventory
// yields no bindings (fail-closed → the row stays unmet).
func buildLiveApprovalBindings(scope rollout.ScopeSpec) []canary.ToolApprovalBinding {
	if len(scope.Tools) == 0 || len(scope.Tenants) == 0 {
		return nil
	}
	// Use the coordinator clock (time.Now in production; injectable in tests) so the active-live
	// snapshot and the store share one clock; canary.SatisfiesLiveExecution re-checks expiry at the
	// caller's in.Now, which is the authoritative instant.
	now := mcpToolTrust.now()
	byTool := make(map[liveApprovalKey][]*tooltrust.ToolApproval)
	for _, a := range mcpToolTrust.activeLiveApprovals(now) {
		k := liveApprovalKey{tenant: a.Tenant, serverID: a.ServerID, toolName: a.ToolName}
		byTool[k] = append(byTool[k], a)
	}
	var bindings []canary.ToolApprovalBinding
	for _, tenant := range scope.Tenants {
		for i := range scope.Tools {
			st := scope.Tools[i]
			ti := mcpToolTrust.loadTarget(st.Server, st.Name)
			// A tool absent from the current catalog, or owned by a different tenant than the scope
			// admits, has no resolvable target — emit no binding, so the scoped tool is uncovered.
			if !ti.found || ti.target.Tenant != tenant {
				continue
			}
			target := canary.LiveTarget{
				Tenant:            tenant,
				ServerID:          st.Server,
				ToolName:          st.Name,
				Fingerprint:       ti.target.Fingerprint,
				FingerprintFormat: ti.target.FingerprintFormatVersion,
			}
			// The server's pinned identity comes from the SAME registry snapshot loadTarget
			// resolved the target from, so the activation binds the identity and the fingerprint
			// as they were actually observed together (§3).
			//
			// A second lookup would not do, and the comment that used to sit here claimed an
			// atomicity the code did not have: Registry.Repin and the catalog re-ingest that
			// follows it are separate publications, so between them a fresh read returns I2 while
			// this target still carries F1. Persisting that (F1, I2) pair as reviewed would make a
			// later identity rotation compare as REVIEWED — an approval issued for I1 authorizing
			// execution under I2 (Codex P1, PR #1360, round 3).
			ident := ti.pinnedIdentity
			for _, a := range byTool[liveApprovalKey{tenant: tenant, serverID: st.Server, toolName: st.Name}] {
				bindings = append(bindings, canary.ToolApprovalBinding{
					Target: target, Approval: a, ServerIdentity: ident,
				})
			}
		}
	}
	return bindings
}

// evaluateCanaryActivationPreflight returns the FULL Canary readiness verdict for a capability
// plus a requested scope, candidate live approval, and budget. It layers the scope/approval/
// budget/target facts (decided by the pure canary validators) onto node readiness. Fail-
// closed: any unmet prerequisite appears in Unmet and Ready stays false.
func evaluateCanaryActivationPreflight(in CanaryActivationInput) canary.Readiness {
	return evaluateActivationOnFacts(canaryNodeFacts(in.Capability), in)
}

// evaluateCanaryActivationPreflightLocked is evaluateCanaryActivationPreflight for a caller that
// ALREADY holds r.durableMu — the commit path revalidates the full verdict inside its serialized
// section against THIS rollout's live state (Codex P1). It gathers the node facts via the LOCKED
// path (no durableMu re-entry) and layers the same scope/approval/budget facts on top.
func evaluateCanaryActivationPreflightLocked(r *mcpRollout, in CanaryActivationInput) canary.Readiness {
	return evaluateActivationOnFacts(canaryNodeFactsLocked(r, in.Capability), in)
}

// evaluateActivationOnFacts layers the ACTIVATION-level scope/approval/budget/target facts onto a
// pre-gathered node fact table and returns the full pure verdict. Shared by the locking and
// already-locked preflight entry points so the activation logic exists once.
func evaluateActivationOnFacts(f canary.Facts, in CanaryActivationInput) canary.Readiness {
	f.ScopeBounded = canary.ValidateScope(in.Scope, in.ScopeRev) == canary.ScopeOK
	f.ScopeReadFirst = canary.ScopeReadFirst(in.Scope)
	// EXACT FIRST-CANARY SHAPE (blocker #5). ScopeBounded proves the scope is within the
	// Canary ARCHITECTURE's caps, which deliberately admit more than the one reviewed
	// experiment. This is the separate, narrower question: is the SIGNED scope exactly one
	// tenant / one server / one fully-pinned tool / one explicitly named principal, and
	// nothing else? It is evaluated HERE, in the authoritative activation preflight that
	// every caller (the locked commit gate and the restart reconcile) routes through, so a
	// wider signed scope yields Ready:false and can never activate — rather than being
	// caught later by a runtime side-effect gate, which would mean a Canary had already
	// gone live. in.Scope is the SIGNED activation scope (cfg.Scope on the commit path,
	// the restored config on the reconcile path): never a request value, never a
	// runtime observation, never narrowed by what happened to be called.
	f.ScopeExactFirstCanary = canary.ValidateFirstCanaryScope(in.Scope, in.ScopeRev) == canary.FirstCanaryScopeOK
	// LiveApprovalValid is true only when EVERY scoped tool has its own valid live_execution
	// approval bound to that exact tool identity — never a single unconstrained approval.
	f.LiveApprovalValid = canary.ValidateScopeApprovals(in.Scope, in.ToolApprovals, in.Now) == canary.ScopeApprovalOK
	f.ServerUsable = in.ServerUsable
	f.ToolFingerprintCurrent = in.FingerprintCurrent
	f.ToolCatalogUsable = in.ToolCatalogUsable
	f.BudgetConfigured = canary.ValidateBudget(in.Budget) == canary.BudgetOK
	return canary.Evaluate(f)
}

// canaryActivationReady is the boolean NODE gate a future arming activation would consult for
// a RequiresLiveExecution mode. It takes only a capability (no scope/approval/budget), so it
// reports node-level readiness (canary.EvaluateNode): whether the NODE is prepared for a
// Canary, independent of any specific scope. It is intentionally redundant with modeExecReady
// (which already fails such a transition closed on the unarmed live tier): defense-in-depth,
// and the reason list it can surface names every missing NODE prerequisite. The per-scope
// activation decision is evaluateCanaryActivationPreflight. Always false in this build.
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
		// Read-only view of the dormant activation runtime (§3/§4): the current activation
		// generation, whether a budget/abort controller are armed, and whether an execution could
		// be reserved right now. In the shipped build these are always the dormant zero values
		// (generation 0, not eligible) — no Canary ever activated.
		"activation_runtime": map[string]any{
			"generation":          globalCanaryRuntime.currentGeneration(rollout.CapabilityGateway),
			"execution_eligible":  globalCanaryRuntime.executionEligible(rollout.CapabilityGateway, time.Now()),
			"budget_ceilings_are": "first_canary",
			// Automatic-stop truth (blocker #7 §20). execution_eligible alone cannot distinguish
			// "no Canary ever activated" from "a Canary activated and was aborted", and mode alone
			// keeps saying Canary after an abort. auto_stop names the first cause and reports
			// execution AUTHORITY separately, so a stopped experiment is never read as healthy.
			"auto_stop": canaryAbortStatusFor(rollout.CapabilityGateway),
			// Bounded pre-admission drift evidence (§6). The runtime pipeline refuses a decision
			// whose tool drifted before the executor is reached; that refusal binds to no
			// activation, so it deliberately latches nothing. Counting it by reason code is the
			// only way an operator learns the catalog moved under a decision — and a counter with
			// no reader is not evidence, so it is reported here. Read-only: nothing consults it.
			"pre_admission_drift": canaryPreAdmissionDriftCounts(rollout.CapabilityGateway.String()),
		},
		"first_canary_bounds": map[string]any{
			"max_servers":            canary.MaxCanaryServers,
			"max_tools":              canary.MaxCanaryTools,
			"max_principals":         canary.MaxCanaryPrincipals,
			"max_total_ceiling":      canary.FirstCanaryMaxTotalCeiling,
			"max_window_hours":       int(canary.FirstCanaryMaxWindowCeiling.Hours()),
			"max_approval_ttl_hours": int(canary.MaxInitialCanaryApprovalTTL.Hours()),
			"read_first":             true,
		},
		// The EXACT first-experiment shape (blocker #5), distinct from first_canary_bounds
		// above. Those are the Canary ARCHITECTURE's caps, which a later graduation phase may
		// raise; this is the narrower shape the FIRST experiment was reviewed as, enforced in
		// the activation preflight (canary_scope_not_exact_first_canary). Surfacing both keeps
		// the difference visible to an operator: a scope inside the bounds can still be far
		// wider than the one reviewed experiment, and will not activate.
		"first_canary_exact_scope": map[string]any{
			"tenants":                1,
			"servers":                1,
			"tools":                  1,
			"principals":             1,
			"clients":                0,
			"agents":                 0,
			"groups":                 0,
			"environments":           0,
			"bare_tool_fingerprints": 0,
			"exclusions":             0,
			"percent":                0,
			"duplicates_allowed":     false,
			"wildcard_identifiers":   false,
			"identity_counted_by":    "principals_only",
			"validated_from":         "signed_activation_scope",
			"enforced_in":            "canary_activation_preflight",
			"rejection_reasons":      firstCanaryScopeReasonStrings(),
			"unmet_readiness_reason": string(canary.ReasonScopeNotExactFirstCanary),
		},
	}
}

// mcpAuthoritativeTarget is what the inventory currently says about one tool identity: whether it
// resolves at all, whether the server behind it is still usable, and the target itself. The three
// are returned together because they come from ONE snapshot read and must not be re-derived
// separately (see the pinnedIdentity field comment in mcp_tooltrust.go).
type mcpAuthoritativeTarget struct {
	// Found reports that the tool resolves to an authoritative target.
	Found bool
	// Usable reports that the server behind it is still usable — present, enabled, and identity-
	// verified. Meaningful only when Found.
	Usable bool
	// RegistryPinDiverged reports that the registry's CURRENT pin is not the identity the catalog
	// record was built against — the repin/re-ingest window. The target below describes the
	// catalog's coherent view, so a request routed by the registry's pin would not reach the
	// workload this target names. Meaningful only when Found.
	RegistryPinDiverged bool
	// Target is the reviewed-shaped record, valid only when Found.
	Target canary.ReviewedTarget
}

// mcpCurrentAuthoritativeTarget reads the CURRENT authoritative target for one tool identity —
// the same registry + catalog fusion the live-trust precheck uses, and the same pointer-published
// inventory, so it carries the lock profile the §5 audit established and adds no new edge.
//
// It deliberately takes NO decision fingerprint and makes NO eligibility judgement. Its one caller
// is the reviewed-target comparison, which asks "what is this tool NOW?" so it can be held against
// what the activation was reviewed for. Folding an eligibility check in here would reintroduce the
// defect that made this path necessary: eligibility is scope- and decision-relative, and a target
// that moved is exactly the case those relations reject before the question can be asked.
//
// Found=false means the tool does not resolve at all (absent from the catalog, or no inventory
// composed). The caller treats that as "nothing to compare", never as drift.
//
// Usable is reported SEPARATELY from the target because "the tool still carries the reviewed
// fingerprint and identity" and "the server the experiment was authorized against is still in
// force" are two different facts, and only the first is a property of the reviewed record. An
// unusable server is an authoritative breach here for exactly the reason mcpLiveTrustPrecheck
// already gives it one (see its !ServerUsable branch): the trust anchor the activation was
// approved against is gone, and the safe response is to stop changing reality. Reporting it here
// too is what keeps the two paths from answering the same question differently — this one now runs
// for EVERY dispatched request, so it is the path that has to carry the verdict when a policy or
// inspection rejection stops the precheck from ever running (Codex P1, PR #1360, round 3).
func mcpCurrentAuthoritativeTarget(serverID, toolName string) mcpAuthoritativeTarget {
	if mcpToolTrust == nil {
		return mcpAuthoritativeTarget{}
	}
	ti := mcpToolTrust.loadTarget(serverID, toolName)
	if !ti.found {
		return mcpAuthoritativeTarget{}
	}
	return mcpAuthoritativeTarget{
		Found:               true,
		Usable:              ti.target.ServerUsable,
		RegistryPinDiverged: ti.registryPinDiverged,
		Target: canary.ReviewedTarget{
			Tenant:            ti.target.Tenant,
			ServerID:          serverID,
			ToolName:          toolName,
			Fingerprint:       ti.target.Fingerprint,
			FingerprintFormat: ti.target.FingerprintFormatVersion,
			// From the SAME snapshot as the fingerprint above — never a second lookup. See the
			// pinnedIdentity field comment in mcp_tooltrust.go.
			ServerIdentity: ti.pinnedIdentity,
		},
	}
}

// reviewedTargetsFromBindings projects the approval bindings the activation preflight just PROVED
// into the activation's reviewed-target snapshot (§3).
//
// Each binding's Target is the CURRENT authoritative target resolved from the registry + catalog,
// and canary.ValidateScopeApprovals has already established that every scoped (tenant, server,
// tool) carries its own valid, four-eyes, exact-target live approval bound to it. So this is a
// projection of what the review passed on — not a later reconstruction of what "must have been"
// reviewed, which is exactly the move §3 forbids.
//
// Duplicates are left for canary.CanonicalizeReviewedTargets to judge: several approvals may bind
// the same target, and it is that function's job — not this one's — to decide whether identical
// entries collapse or disagreeing ones are refused. Resolving ambiguity here by overwriting would
// be the "last one wins" §4 rules out.
//
// It performs NO lookup of its own: every field, the server identity included, comes from the
// binding the preflight validated. A second read here would sample the inventory at a later
// instant than the one the review passed on, which is precisely the reconstruction §3 forbids.
func reviewedTargetsFromBindings(bindings []canary.ToolApprovalBinding) []canary.ReviewedTarget {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]canary.ReviewedTarget, 0, len(bindings))
	for i := range bindings { // index-based: the binding carries a 32-byte digest
		t := bindings[i].Target
		// The reviewed operation class comes from the APPROVAL — the four-eyes artifact bound
		// to this exact fingerprint — and from nowhere else. A binding with no approval, or an
		// approval that never stated the class, projects OpUnset, which
		// canary.CanonicalizeReviewedTargets refuses: the activation does not arm rather than
		// arming with a target it cannot classify. That refusal is the point. Defaulting the
		// class here — in either direction — would make this function the authority on tool
		// semantics, which is precisely what §4 forbids.
		var class policy.OperationClass
		if a := bindings[i].Approval; a != nil {
			class, _ = canary.OperationClassFromReviewed(a.ReviewedOperationClass)
		}
		out = append(out, canary.ReviewedTarget{
			Tenant:            t.Tenant,
			ServerID:          t.ServerID,
			ToolName:          t.ToolName,
			Fingerprint:       t.Fingerprint,
			FingerprintFormat: t.FingerprintFormat,
			ServerIdentity:    bindings[i].ServerIdentity,
			OperationClass:    class,
		})
	}
	return out
}

// firstCanaryScopeReasonStrings renders the complete exact-first-Canary rejection vocabulary
// for the read-only status surface, so an operator can see every way a signed scope can fail
// the exact-shape gate without reading the source. Values only — the vocabulary is fixed and
// never carries tenant, host, or error text.
func firstCanaryScopeReasonStrings() []string {
	all := canary.AllFirstCanaryScopeReasons()
	out := make([]string, 0, len(all))
	for _, r := range all {
		out = append(out, string(r))
	}
	return out
}

// canaryScopedToolsCatalogUsable resolves the blocker-#13 activation fact: is EVERY (tenant × tool)
// the scope admits currently `catalog.Usable` at the EXACT fingerprint and fingerprint FORMAT the
// activation is binding?
//
// WHY THIS IS AN ACTIVATION FACT AND NOT A RUNBOOK STEP. Catalog usability is enforced by the
// POLICY ENGINE, not here: a Quarantined tool is hard-overridden to ActionQuarantine before any
// operator ALLOW rule is consulted. Without this fact a node could hold a valid live approval, a
// valid reviewed target, an exact scope and a read-first class, report Ready:true, and then have
// every request die at that override — readiness reported for an experiment that cannot execute a
// single call.
//
// IT IS NOT CATALOG HEALTH. ReasonCatalogUnhealthy already answers "is the catalog readable"; this
// answers "did THIS ONE governed target pass the trust lifecycle". A perfectly healthy catalog whose
// record for the scoped tool is Quarantined satisfies the first and fails this one.
//
// IT PROMOTES NOTHING. This is a pure read on the request-free activation path. The only writer of
// catalog.Usable is the governed shadow_evaluation lifecycle (ApproveShadow → promoteFor →
// catalog.Promote) and its reconcile; a live_execution approval never reaches it (§15).
//
// EXACT-CURRENT BINDING (§5) comes from reading the CURRENT record and comparing three things:
//
//   - eligibility is exactly catalog.Usable — the sticky Quarantined floor means a republish to a
//     new fingerprint re-enters review, so F2 can never inherit F1's usability;
//   - the record's digest equals the scope's PINNED fingerprint, so a usable record for some other
//     revision of the tool cannot satisfy a scope pinned to this one;
//   - the record's fingerprint FORMAT VERSION equals the one the trust path observed for the same
//     target. Format is part of the identity, not decoration: two records can carry the same digest
//     under different format versions, and treating those as one target is the defect
//     TestReadFirstClass_FingerprintFormatIsPartOfTheBinding pins one subsystem over.
//
// Fail-closed everywhere: an empty scope, absent inventory, a missing record, a tenant the scope
// does not own, or any disagreement yields false, and the row stays unmet.
func canaryScopedToolsCatalogUsable(scope rollout.ScopeSpec) bool {
	if len(scope.Tools) == 0 || len(scope.Tenants) == 0 {
		return false
	}
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		return false
	}
	// ONE catalog snapshot for the whole decision: every tool is judged against the same
	// published state, so a concurrent re-ingest cannot make the verdict internally inconsistent.
	snap := cat.Current()
	for _, tenant := range scope.Tenants {
		for i := range scope.Tools {
			st := scope.Tools[i]
			rec, ok := snap.Get(catalog.ToolKey{Server: registry.ServerID(st.Server), Name: st.Name})
			if !ok {
				return false
			}
			if rec.Eligibility != catalog.Usable {
				return false
			}
			sum := rec.Fingerprint.Sum()
			if !strings.EqualFold(hex.EncodeToString(sum[:]), st.Fingerprint) {
				return false
			}
			// The trust path's own observation of the same target. Requiring the two to agree on
			// BOTH digest and format binds this fact to the identity the activation actually
			// carries, rather than to whatever the catalog happens to say on its own.
			ti := mcpToolTrust.loadTarget(st.Server, st.Name)
			if !ti.found || ti.target.Tenant != tenant {
				return false
			}
			if ti.target.Fingerprint != tooltrust.FingerprintDigest(sum) ||
				ti.target.FingerprintFormatVersion != rec.Fingerprint.FormatVersion {
				return false
			}
		}
	}
	return true
}
