package execution

import (
	"context"

	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// shadowOutcome is the bounded verdict of a Shadow evaluation. Shadow answers
// "would this request execute?" and stops; it NEVER crosses the irreversible
// side-effect boundary (run.go:71 Upstream.Call / broker Materialize).
type shadowOutcome string

const (
	// shadowWouldExecute — every precondition an executing mode checks up to the
	// side-effect boundary is satisfied; a live mode WOULD have executed.
	shadowWouldExecute shadowOutcome = "would_execute"
	// shadowWouldFailCredentialReadiness — the credential profile does not PLAN
	// cleanly (missing/disabled/version-stale/power-exceeded). Derived from the
	// metadata-only broker Plan; no secret is ever materialized to learn this.
	shadowWouldFailCredentialReadiness shadowOutcome = "would_fail_credential_readiness"
)

// shadowEvaluate is the ONLY executor path reached for rollout.EffectShadowEvaluate.
// It computes the would-be outcome and records durable evidence, and it contains NO
// call to e.cfg.Upstream.Call or e.cfg.Broker.Materialize anywhere on its path — a
// Shadow runtime evaluates, it does not execute (SH-INV-1/2,
// docs/design/mcp/SHADOW-ARCHITECTURE.md §3). The absence of any execute/materialize
// call on this path is pinned structurally by shadow_no_execute_test.go and the
// posture wall.
//
// The ctx is accepted for signature symmetry with runExecute and future
// deadline-bounded credential-readiness probes; the current Plan check is pure.
func (e *Executor) shadowEvaluate(_ context.Context, in runtime.ExecInput, res rollout.Resolution) runtime.ExecOutput {
	if e.cfg.Events == nil {
		// Evidence-before-report is mandatory. With no durability seam a Shadow
		// evaluation cannot record its decision, so fail closed exactly as the execute
		// path does (run.go:36-39) rather than report an un-recorded would-execute.
		return e.blocked(in, mcperr.ReasonEventDurabilityDegraded, false)
	}

	// Credential READINESS is derived from a metadata-only Plan. Shadow NEVER
	// materializes a secret: Plan touches no provider and decrypts no cache, and
	// Materialize is unreachable from this method. A profile that will not plan is
	// reported as WOULD_FAIL_CREDENTIAL_READINESS rather than a spurious WOULD_EXECUTE.
	outcome := shadowWouldExecute
	if e.cfg.Broker != nil && in.Decision.Obligations.CredentialProfile != "" {
		if _, err := e.cfg.Broker.Plan(planInput(in, in.Decision.Obligations.CredentialProfile)); err != nil {
			outcome = shadowWouldFailCredentialReadiness
		}
	}

	// Durably record the Shadow decision BEFORE reporting (the same
	// evidence-before-report ordering as the execute path). The committed callback
	// performs NO side effect — it exists only so that a failed durable commit fails
	// the evaluation closed, never silently. The event's execution_state names it a
	// shadow evaluation, never an execution.
	facts := decisionFacts(in)
	facts.Decision.ExecutionState = "shadow_evaluated"
	if err := e.cfg.Events.CommitThenAct(facts, func(spool.CommitReceipt) error { return nil }); err != nil {
		return e.blocked(in, mcperr.ReasonOf(err), false)
	}

	return runtime.ExecOutput{
		Status:          200,
		Disposition:     dispObserve, // a record-shaped, explicitly non-executed result
		Reason:          mcperr.ReasonObserveOnly,
		ResponseBody:    shadowResult(in.MessageID, outcome, res.ShadowOverride),
		ExecutionState:  "shadow_evaluated",
		Executed:        false,
		EvaluatedAction: in.Decision.Action.String(),
		EffectiveAction: "shadow_evaluate",
		ShadowOverride:  res.ShadowOverride,
	}
}
