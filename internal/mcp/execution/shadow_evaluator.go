package execution

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ── Layer B — a Shadow capability object that does not POSSESS live execution ──
//
// The ShadowEvaluator is a distinct type from the (live) Executor. Its dependency
// graph contains NO upstream client and NO materialize-capable broker — only the
// narrow, plan-only CredentialPlanner. It is therefore incapable of an upstream call
// or credential materialization, in Go types, not by comment or runtime check
// (SH-INV-2, docs/design/mcp/SHADOW-ARCHITECTURE.md §3 Layer B). The capability
// absence is pinned structurally by shadow_capability_test.go (reflection over the
// type graph) and shadow_no_execute_test.go.

// CredentialPlanner is the NARROW, plan-only credential capability a caller supplies to a
// Shadow evaluator. Plan is metadata-only: no provider call, no cache decrypt, no secret;
// it deliberately does NOT expose Materialize. *broker.Broker satisfies it. NOTE: this
// interface is the CALLER-FACING config type only — a ShadowEvaluator does NOT retain the
// planner as an interface value (which would keep the concrete broker recoverable by a
// type assertion). NewShadowEvaluator extracts the bound `Plan` METHOD VALUE and drops the
// interface (see the `plan` field + `NewShadowEvaluator`), so the materialize-capable
// concrete value is genuinely unreachable from the stored evaluator, not merely un-called
// (SEC — Codex P2 on PR #1226).
type CredentialPlanner interface {
	Plan(broker.PlanInput) (broker.CredentialPlan, error)
}

// ShadowOutcome is the formal Model-1 Shadow verdict: what a fully-enforcing mode
// (Canary/Production) WOULD do with this request, computed without executing it. It is
// never a permissive-passthrough label — a policy DENY is WOULD_BLOCK, never
// WOULD_EXECUTE (SH-INV, §8 of the phase brief).
type ShadowOutcome string

// The bounded set of Model-1 Shadow outcomes. Each names what a fully-enforcing mode
// would do at the pre-side-effect boundary; the differential equivalence test pins them
// to the live executor's decision.
const (
	ShadowWouldExecute                 ShadowOutcome = "would_execute"
	ShadowWouldBlock                   ShadowOutcome = "would_block"
	ShadowWouldRequireApproval         ShadowOutcome = "would_require_approval"
	ShadowWouldRequireConfirmation     ShadowOutcome = "would_require_confirmation"
	ShadowWouldFailCredentialReadiness ShadowOutcome = "would_fail_credential_readiness"
	ShadowWouldFailInspection          ShadowOutcome = "would_fail_inspection"
	ShadowWouldFailStaleDecision       ShadowOutcome = "would_fail_stale_decision"
	ShadowWouldFailHardControl         ShadowOutcome = "would_fail_hard_control"
)

// credential readiness sub-facts (§12): Plan proves METADATA validity only; it does
// NOT prove a remote provider is reachable, and Shadow must not call Materialize to
// find out. So materialization readiness is honestly "not evaluated". The identifiers
// deliberately avoid the "cred" token (gosec G101 matches it as a hardcoded-credential
// name) — these are bounded status LABELS, never secrets.
const (
	planStatusValid   = "credential_plan_valid"
	planStatusInvalid = "credential_plan_invalid"
	planStatusNone    = "no_credential_profile"
	// planStatusNoPlanner — a profile is named but no planning capability is composed.
	// This MIRRORS the live no-broker path (Config.Broker nil ⇒ no Authorization is
	// attached and the call proceeds), so the outcome stays WOULD_EXECUTE; the label
	// carries the truthful nuance that the request would run with NO credential attached.
	planStatusNoPlanner = "no_planner_composed"
	materializeNotEval  = "not_evaluated"
	inspectionWouldPass = "would_pass"
	inspectionWouldFail = "would_fail"
	inspectionNotEval   = "not_evaluated"
)

// ShadowConfig wires a ShadowEvaluator. It CANNOT carry an UpstreamCaller or a
// materialize-capable *broker.Broker — those fields do not exist on this struct. That
// absence is the Layer-B capability-security invariant.
type ShadowConfig struct {
	// State is the capability-local rollout state (Gateway). Required.
	State *rollout.State
	// Planner is the OPTIONAL plan-only credential capability. nil ⇒ credential
	// readiness is reported as not-evaluated (a Shadow evaluator is constructible with
	// no credential capability at all).
	Planner CredentialPlanner
	// Events is the durable-event manager. Required: evidence-before-report is
	// mandatory, so a nil Events fails every evaluation closed.
	Events *events.Manager
	// Metrics is the optional rollout telemetry sink.
	Metrics Metrics
	// Clock is injected for tests; nil ⇒ time.Now.
	Clock func() time.Time
	// Actor labels events emitted by this evaluator.
	Actor string
}

// ShadowEvaluator is the non-executing Shadow capability object. It implements
// runtime.ExecutionProvider, but holds no upstream client and no materialize-capable
// broker, so it cannot perform an upstream call or materialize a credential. A request
// that resolves to EffectExecute (impossible in Shadow mode) fails CLOSED here.
type ShadowEvaluator struct {
	cfg ShadowConfig // Planner is CLEARED before storage (see New); the evaluator never retains the interface value
	// plan is the ONLY credential capability the evaluator holds: the bound Plan method
	// value extracted from the supplied planner. A method value is an opaque closure over
	// its receiver — Go exposes no way to recover the receiver from it — so even if the
	// caller supplied a *broker.Broker, this field cannot be type-asserted back to it and
	// Materialize is genuinely unreachable. nil ⇒ no planning capability was supplied.
	plan       func(broker.PlanInput) (broker.CredentialPlan, error)
	allowances *allowanceStore // read-only PREDICTION (wouldSatisfy); never consumed
}

var _ runtime.ExecutionProvider = (*ShadowEvaluator)(nil)

// NewShadowEvaluator constructs a Shadow evaluator. Note what it does NOT require: no
// upstream client, no materializing broker. A Shadow evaluator is fully constructible
// with neither. It NARROWS the supplied planner to its Plan method value and drops the
// interface, so no materialize-capable concrete value is retained (Codex P2).
func NewShadowEvaluator(cfg ShadowConfig) (*ShadowEvaluator, error) {
	if cfg.State == nil {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "execution", "nil rollout state")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Metrics == nil {
		cfg.Metrics = noopMetrics{}
	}
	var plan func(broker.PlanInput) (broker.CredentialPlan, error)
	if cfg.Planner != nil {
		plan = cfg.Planner.Plan // bound method value — cannot be asserted back to the concrete planner
	}
	// Drop the interface value so the concrete (possibly materialize-capable) planner is
	// not retained anywhere reachable from the evaluator.
	cfg.Planner = nil
	return &ShadowEvaluator{cfg: cfg, plan: plan, allowances: newAllowanceStore()}, nil
}

// Execute is the runtime.ExecutionProvider entry for a Shadow-only runtime. It
// resolves the rollout disposition and dispatches — but it has no execute path.
func (s *ShadowEvaluator) Execute(ctx context.Context, in runtime.ExecInput) runtime.ExecOutput {
	if s.cfg.State.Killed() {
		return s.blocked(in, mcperr.ReasonRolloutEmergencyActive, false)
	}
	subj := subjectFor(in)
	action := mapAction(in.Decision.Action)
	hardFail, hardReason := hardFailure(in)
	res := s.cfg.State.ResolveFor(subj, action, hardFail, hardReason, true)
	s.cfg.Metrics.ObserveResolution(in.Capability.String(), res)

	switch res.Disposition {
	case rollout.EffectRecordOnly:
		return s.recordOnly(in, res)
	case rollout.EffectShadowEvaluate:
		return s.evaluate(ctx, in)
	case rollout.EffectBlock:
		return s.blocked(in, res.BlockReason, res.ShadowOverride)
	case rollout.EffectExecute:
		// A Shadow evaluator possesses no live capability. An execute disposition is
		// impossible in Shadow mode; if one ever reached here it fails CLOSED rather
		// than silently doing nothing (defense in depth — there is no execute path to
		// take even if this branch were removed).
		return s.blocked(in, mcperr.ReasonRolloutModeInvalid, false)
	default:
		return s.blocked(in, mcperr.ReasonRolloutModeInvalid, false)
	}
}

// evaluate produces the formal ShadowDecision for an in-scope Shadow request. It
// computes the Model-1 outcome (what a fully-enforcing mode WOULD do), derives
// credential readiness from Plan alone, records durable evidence, and returns. There
// is NO reference to an upstream client or Materialize anywhere on this path.
func (s *ShadowEvaluator) evaluate(_ context.Context, in runtime.ExecInput) runtime.ExecOutput {
	if s.cfg.Events == nil {
		return s.blocked(in, mcperr.ReasonEventDurabilityDegraded, false)
	}
	d := s.decide(in)

	// Durable evidence BEFORE reporting (evidence-before-report). The committed
	// callback performs NO side effect — it exists only so a failed durable commit
	// fails the evaluation closed. The event names it a shadow evaluation.
	facts := shadowDecisionFacts(in, d)
	if err := s.cfg.Events.CommitThenAct(facts, func(spool.CommitReceipt) error { return nil }); err != nil {
		return s.blocked(in, mcperr.ReasonOf(err), false)
	}

	return runtime.ExecOutput{
		Status:          200,
		Disposition:     dispObserve, // a record-shaped, explicitly non-executed result
		Reason:          mcperr.ReasonObserveOnly,
		ResponseBody:    shadowResult(in.MessageID, d),
		ExecutionState:  "shadow_evaluated",
		Executed:        false,
		EvaluatedAction: in.Decision.Action.String(),
		EffectiveAction: "shadow_evaluate",
		ShadowOverride:  d.ShadowOverride,
	}
}

// ShadowDecision is the structured, truthful verdict recorded for a Shadow evaluation.
// It preserves the policy verdict (EvaluatedAction) SEPARATELY from the enforcement
// prediction (Outcome), so a DENY / REQUIRE_APPROVAL / REQUIRE_CONFIRMATION is never
// laundered into a plain WOULD_EXECUTE.
type ShadowDecision struct {
	EvaluatedAction    string        // the raw policy action (never softened)
	Outcome            ShadowOutcome // Model-1 enforcement prediction
	ShadowOverride     bool          // policy itself is restrictive (non-allow-class)
	CredentialPlan     string        // credential_plan_valid / _invalid / no_credential_profile
	MaterializeReady   string        // always not_evaluated (§12 — Shadow never materializes)
	RequestInspection  string        // would_pass / would_fail (from the pre-executor hard-fail source)
	ResponseInspection string        // always not_evaluated (§13 — no upstream response exists)
}

// decide computes the ShadowDecision. It mirrors, in the same order, the pre-side-effect
// decision the LIVE executor reaches for an in-scope enforcing request (kill checked by
// the caller): hard control → policy class → allowance → stale → credential readiness →
// execute. Differential equivalence with the live path is pinned by
// shadow_live_equivalence_test.go.
func (s *ShadowEvaluator) decide(in runtime.ExecInput) ShadowDecision {
	action := mapAction(in.Decision.Action)
	hardFail, _ := hardFailure(in)
	d := ShadowDecision{
		EvaluatedAction:    in.Decision.Action.String(),
		ShadowOverride:     !action.IsAllowClass(),
		CredentialPlan:     planStatusNone,
		MaterializeReady:   materializeNotEval,
		RequestInspection:  requestInspectionStatus(in),
		ResponseInspection: inspectionNotEval,
	}

	// 1. Hard controls (policy hard override or the pre-executor inspection hard block).
	if hardFail {
		if in.Inspection != nil && in.Inspection.HardFail {
			d.Outcome = ShadowWouldFailInspection // RequestInspection already would_fail
		} else {
			d.Outcome = ShadowWouldFailHardControl
		}
		return d
	}

	// 2. Policy verdict classes that a fully-enforcing mode blocks/gates.
	switch action {
	case rollout.ActionKindDenied:
		d.Outcome = ShadowWouldBlock
		return d
	case rollout.ActionKindApproval:
		d.Outcome = ShadowWouldRequireApproval
		return d
	case rollout.ActionKindConfirm:
		d.Outcome = ShadowWouldRequireConfirmation
		return d
	case rollout.ActionKindRedaction:
		// The guarded-execute path performs no request-argument redaction and fails
		// closed (executor.go), so a fully-enforcing mode would block a redaction action.
		d.Outcome = ShadowWouldBlock
		return d
	}

	// 3. Allow-class: allowance would-satisfy (non-destructive prediction).
	if needsAllowance(action) && !s.allowances.wouldSatisfy(in, action, s.cfg.Clock()) {
		d.Outcome = ShadowWouldBlock
		return d
	}

	// 4. Stale decision (tool drift re-check — pure, no side effect).
	if in.ToolStillCurrent != nil && !in.ToolStillCurrent() {
		d.Outcome = ShadowWouldFailStaleDecision
		return d
	}

	// 5. Credential readiness from Plan alone (metadata; never Materialize).
	if profileRef := in.Decision.Obligations.CredentialProfile; profileRef != "" {
		if s.plan == nil {
			// No planning capability is composed. Shadow must PREDICT what live does, not
			// fail closed: the live executor gates credential materialization on
			// `useBroker := e.cfg.Broker != nil && profileRef != ""` (run.go), so with no
			// broker it attaches NO Authorization and PROCEEDS to the call. Failing closed
			// here would diverge from live enforcement (Codex P2). The outcome stays
			// WOULD_EXECUTE; the label records that the request would run with no credential
			// attached — the truthful nuance an operator needs to read from the evidence.
			d.CredentialPlan = planStatusNoPlanner
		} else if _, err := s.plan(planInput(in, profileRef)); err != nil {
			d.CredentialPlan = planStatusInvalid
			d.Outcome = ShadowWouldFailCredentialReadiness
			return d
		} else {
			d.CredentialPlan = planStatusValid
		}
	}

	// 6. Everything an enforcing mode checks before the side-effect boundary passed.
	d.Outcome = ShadowWouldExecute
	return d
}

// requestInspectionStatus reports the truthful request-inspection sub-fact (§13): when no
// inspection ran (no provider/profile composed, in.Inspection == nil) it is NOT_EVALUATED,
// never a false would_pass — a skipped inspection did not "pass". would_pass is reserved
// for an inspection that actually ran without a hard failure (Codex P2).
func requestInspectionStatus(in runtime.ExecInput) string {
	if in.Inspection == nil {
		return inspectionNotEval
	}
	if in.Inspection.HardFail {
		return inspectionWouldFail
	}
	return inspectionWouldPass
}

// shadowDecisionFacts builds the durable evidence for a Shadow evaluation. It reuses the
// execute path's decisionFacts (same identity/decision/snapshot shape) and re-stamps the
// execution state as a shadow evaluation, never an execution. The recorded action stays
// the raw policy action; the enforcement prediction rides in the Shadow-outcome fields so
// the archive can reconstruct WHY the evaluation reached its verdict without materializing
// a secret or making an upstream call.
func shadowDecisionFacts(in runtime.ExecInput, d ShadowDecision) events.DecisionFacts {
	facts := decisionFacts(in)
	facts.Decision.ExecutionState = "shadow_evaluated"
	facts.Decision.ShadowOutcome = string(d.Outcome)
	facts.Decision.ShadowOverride = d.ShadowOverride
	// Persist the ShadowDecision SUB-FACTS too (Codex P2), not just the final outcome: the
	// durable archive must let a Canary-readiness analysis distinguish, within one outcome,
	// a valid credential plan from an unplanned/absent one and a passed request inspection
	// from an un-evaluated one — otherwise two WOULD_EXECUTE records are indistinguishable
	// and the readiness analysis promised by SHADOW-ARCHITECTURE.md lives only in the
	// transient response body.
	facts.Decision.ShadowCredentialPlan = d.CredentialPlan
	facts.Decision.ShadowMaterializeReady = d.MaterializeReady
	facts.Decision.ShadowRequestInspection = d.RequestInspection
	facts.Decision.ShadowResponseInspection = d.ResponseInspection
	return facts
}

// recordOnly is the out-of-scope (observe-behaviour) Shadow output.
func (s *ShadowEvaluator) recordOnly(in runtime.ExecInput, res rollout.Resolution) runtime.ExecOutput {
	return runtime.ExecOutput{
		Status: 200, Disposition: dispObserve, Reason: mcperr.ReasonObserveOnly,
		ResponseBody: observeResult(in.MessageID, in.Decision), ExecutionState: "not_implemented",
		EvaluatedAction: in.Decision.Action.String(), EffectiveAction: "record_only", ShadowOverride: res.ShadowOverride,
	}
}

// blocked is the terminal Shadow block output.
func (s *ShadowEvaluator) blocked(in runtime.ExecInput, reason mcperr.Reason, override bool) runtime.ExecOutput {
	s.cfg.Metrics.ObserveBlock(in.Capability.String(), reason)
	return runtime.ExecOutput{
		Status: 200, Disposition: dispReject, Reason: reason,
		ResponseBody: errorResult(in.MessageID, reason), ExecutionState: "blocked",
		EvaluatedAction: in.Decision.Action.String(), EffectiveAction: "block",
		HardFailure: rollout.IsHardFailure(reason), ShadowOverride: override,
	}
}
