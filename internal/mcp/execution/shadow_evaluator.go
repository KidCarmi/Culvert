package execution

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
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

// Resolve implements runtime.ExecutionProvider: it resolves the rollout disposition for
// this request EXACTLY ONCE (no side effect) so the runtime can route on it and hand the
// SAME resolution back to Execute. A killed capability resolves to an emergency block
// (never record-only), so the runtime routes it to Execute rather than its inline path.
func (s *ShadowEvaluator) Resolve(in runtime.ExecInput) rollout.Resolution {
	return resolveDisposition(s.cfg.State, in)
}

// Execute is the runtime.ExecutionProvider entry for a Shadow-only runtime. It acts on the
// PRE-RESOLVED mode/scope disposition — it never re-resolves mode or scope (F7 single
// resolution, Codex P2 #1234) — and dispatches. It has no execute path.
//
// The one thing it DOES re-read is the emergency kill: the kill switch is an immediate
// admission stop (admin surface + runbook contract), so a kill engaged AFTER Resolve but
// before this evaluation commits must still stop it — otherwise the evaluator would commit
// durable evidence and return a would_* verdict AFTER the operator's emergency stop. This is
// orthogonal to single-resolution: it reads only the monotonic kill flag and can only make
// the outcome MORE restrictive (an emergency block), never turn a record-only into an
// evaluation or an evaluation into an execute, so it cannot reopen the routing TOCTOU that
// F7 closed (Codex P2, PR #1234).
func (s *ShadowEvaluator) Execute(ctx context.Context, in runtime.ExecInput, res rollout.Resolution) runtime.ExecOutput {
	if s.cfg.State.Killed() {
		return s.blocked(in, mcperr.ReasonRolloutEmergencyActive, false)
	}
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

// KillActive implements runtime.ExecutionProvider: it reports whether this capability's
// emergency kill switch is engaged, for the runtime's record-only fall-through re-check.
func (s *ShadowEvaluator) KillActive() bool { return s.cfg.State.Killed() }

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
	// Bounded, low-cardinality metric: ONE evaluation + its formal Model-1 verdict. The
	// outcome enum is the only label; no tenant/subject/tool/argument is ever recorded.
	// Emitted ONLY AFTER the durable commit succeeds (evidence-before-report): on a commit
	// failure the evaluator returns a block (counted as an evaluation error), and recording
	// a would_* verdict here too would double-count and overstate successful Shadow outcomes
	// during exactly the durability failures an operator needs to see (Codex P2, PR #1234).
	s.cfg.Metrics.ObserveShadowOutcome(in.Capability.String(), string(d.Outcome))

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
// the caller): hard control → policy class → allowance → upstream-server usability →
// credential readiness → stale → execute. Credential precedes the (boundary) stale
// re-check because run.go plans the credential before callUpstream's final drift check
// (Codex P2). Differential equivalence with the live path is pinned by
// shadow_live_equivalence_test.go and shadow_prediction_parity_test.go.
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
	if outcome, gated := policyClassOutcome(action); gated {
		d.Outcome = outcome
		return d
	}

	// 3. Allow-class: allowance would-satisfy (non-destructive prediction).
	if needsAllowance(action) && !s.allowances.wouldSatisfy(in, action, s.cfg.Clock()) {
		d.Outcome = ShadowWouldBlock
		return d
	}

	// 4. Upstream server usability. The live path refuses an absent or unusable server
	// record inside runExecute — BEFORE the durable commit, the credential plan and the
	// call — with ReasonUpstreamServerUnusable, a HardServerTrust hard failure, so it sits
	// exactly here: after the allowance consumption, before credential planning.
	//
	// SR-02. This is NOT already covered by the hard-control step above. The policy engine
	// reads server state from the DECISION snapshot, while the executor re-reads the LIVE
	// registry (runtime dispatchExecute) — which is the whole reason the live refusal
	// exists. A record disabled, identity-mismatched or deregistered in that window
	// reaches decide() with no hard override set, and without this gate Shadow promised
	// WOULD_EXECUTE for a server enforcement will not call.
	if in.Server == nil || !in.Server.Usable() {
		d.Outcome = ShadowWouldFailHardControl
		return d
	}

	// 5. Credential readiness from Plan alone (metadata; never Materialize). This PRECEDES
	// the boundary drift re-check to match the LIVE order exactly (Codex P2): run.go plans
	// the credential (materializeAndCall → Broker.Plan) BEFORE callUpstream performs the
	// final drift check, so a request that is BOTH credential-invalid AND drifted returns
	// the credential-readiness failure in enforcement. The runtime already refuses INITIAL
	// (pre-dispatch) drift before the provider (SHADOW-EVIDENCE-ROUTING-1), so the only
	// drift decide() can observe is POST-ENTRY (boundary) drift — whose live precedence is
	// credential-first.
	planStatus, planReady := s.credentialReadiness(in)
	if !planReady {
		d.CredentialPlan = planStatus
		d.Outcome = ShadowWouldFailCredentialReadiness
		return d
	}
	if planStatus != "" {
		d.CredentialPlan = planStatus
	}

	// 6. Stale decision (post-entry tool drift — the boundary re-check). Reached only when
	// the credential (if any) planned cleanly, mirroring callUpstream's drift check AFTER
	// Broker.Plan. Pure, no side effect.
	if in.ToolStillCurrent != nil && !in.ToolStillCurrent() {
		d.Outcome = ShadowWouldFailStaleDecision
		return d
	}

	// 7. Everything an enforcing mode checks before the side-effect boundary passed.
	d.Outcome = ShadowWouldExecute
	return d
}

// policyClassOutcome maps a policy verdict class that a fully-enforcing mode blocks or
// gates onto its Model-1 outcome. gated=false means the action is allow-class and the
// evaluation continues to the allowance, server, credential and staleness steps.
//
// Extracted from decide() only to keep it under the cyclop threshold; the mapping and its
// order are unchanged. Every arm is a REFUSAL — nothing here can produce WOULD_EXECUTE, so
// a class added without an arm falls through to the allow-class steps and must therefore
// be an allow-class action.
func policyClassOutcome(action rollout.ActionKind) (ShadowOutcome, bool) {
	switch action {
	case rollout.ActionKindDenied:
		return ShadowWouldBlock, true
	case rollout.ActionKindApproval:
		return ShadowWouldRequireApproval, true
	case rollout.ActionKindConfirm:
		return ShadowWouldRequireConfirmation, true
	case rollout.ActionKindRedaction:
		// The guarded-execute path performs no request-argument redaction and fails
		// closed (executor.go), so a fully-enforcing mode would block a redaction action.
		return ShadowWouldBlock, true
	default:
		return "", false
	}
}

// credentialReadiness derives the credential sub-fact from Plan alone — metadata only,
// never Materialize. It returns the status label to record and whether the request would
// still reach the call; ready=false means a fully-enforcing mode would fail credential
// readiness. An empty status with ready=true means no credential profile was named, so the
// caller keeps its planStatusNone default.
//
// Extracted from decide() only to keep it under the cyclop threshold; the semantics and
// the position of this step in the live order are unchanged.
func (s *ShadowEvaluator) credentialReadiness(in runtime.ExecInput) (string, bool) {
	profileRef := in.Decision.Obligations.CredentialProfile
	if profileRef == "" {
		return "", true
	}
	if s.plan == nil {
		// No planning capability is composed but a credential IS required. Shadow PREDICTS what live
		// does, and live now FAILS CLOSED here: a credential-required request with no broker would
		// otherwise reach the upstream with NO Authorization, letting a credential-required operation
		// hit an upstream that accepts ambient/unauthenticated access (Codex P2 round-6, PR #1290). The
		// live executor blocks this before any side effect (run.go: profileRef != "" && Broker == nil ⇒
		// ReasonCredentialProfileMissing), so Shadow reports WOULD_FAIL_CREDENTIAL_READINESS to stay
		// equivalent; the planStatusNoPlanner label records WHY (no planner composed).
		return planStatusNoPlanner, false
	}
	if _, err := s.plan(planInput(in, profileRef)); err != nil {
		return planStatusInvalid, false
	}
	return planStatusValid, true
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

// shadowEvidence is THE single mapping from a ShadowDecision to the durable/reportable
// Shadow sub-facts. Both the transient JSON-RPC response (shadowResult) and the durable
// event (shadowDecisionFacts) derive from this ONE function, so the record an operator
// reads back from the archive is fact-for-fact identical to what the client saw at
// request time (SHADOW-EVIDENCE-ROUTING-1 §3 parity). The raw evaluated policy action is
// NOT duplicated here: it is carried in DecisionEvidence.Action (its single home).
func shadowEvidence(d ShadowDecision) model.ShadowEvidence {
	return model.ShadowEvidence{
		Outcome:                  string(d.Outcome),
		Override:                 d.ShadowOverride,
		CredentialPlan:           d.CredentialPlan,
		MaterializationReadiness: d.MaterializeReady,
		RequestInspection:        d.RequestInspection,
		ResponseInspection:       d.ResponseInspection,
	}
}

// shadowDecisionFacts builds the durable evidence for a Shadow evaluation. It reuses the
// execute path's decisionFacts (same identity/decision/snapshot shape), re-stamps the
// execution state as a shadow evaluation (never an execution), and attaches the complete
// durable ShadowEvidence built from the SAME ShadowDecision returned to the client. The
// event is thereby a SchemaVersionV2 Shadow decision event (buildEvent), which persists
// the full enforcement prediction so the archive reconstructs WHY the evaluation reached
// its verdict — with no secret, credential value, or upstream call (SHADOW-EVIDENCE-ROUTING-1).
func shadowDecisionFacts(in runtime.ExecInput, d ShadowDecision) events.DecisionFacts {
	facts := decisionFacts(in)
	facts.Decision.ExecutionState = "shadow_evaluated"
	ev := shadowEvidence(d)
	facts.Shadow = &ev
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
