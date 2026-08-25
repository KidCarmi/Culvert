package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// ActionKind is the rollout-local view of a PR-6 policy decision's disposition. The
// runtime maps policy.Action → ActionKind so this leaf package never imports the
// policy engine. The mapping preserves the allow-class distinction exactly.
type ActionKind uint8

const (
	// ActionKindDenied — DENY or QUARANTINE (a block-class decision).
	ActionKindDenied ActionKind = iota
	// ActionKindAllow — ALLOW or MONITOR (execute subject to obligations/hard controls).
	ActionKindAllow
	// ActionKindConfirm — REQUIRE_CONFIRMATION (no execution without confirmation).
	ActionKindConfirm
	// ActionKindApproval — REQUIRE_APPROVAL (no execution without an approval receipt).
	ActionKindApproval
	// ActionKindAllowOnce — ALLOW_ONCE (one-call allowance, consumed atomically).
	ActionKindAllowOnce
	// ActionKindAllowSession — ALLOW_FOR_SESSION (session-bounded allowance).
	ActionKindAllowSession
	// ActionKindRedaction — ALLOW_WITH_REDACTION (execute only the transformed args).
	ActionKindRedaction
)

// IsAllowClass reports whether the action executes (subject to obligations + hard
// controls). Mirrors policy.Action.IsAllowClass: ALLOW, MONITOR, ALLOW_ONCE,
// ALLOW_FOR_SESSION, ALLOW_WITH_REDACTION.
func (a ActionKind) IsAllowClass() bool {
	switch a {
	case ActionKindAllow, ActionKindAllowOnce, ActionKindAllowSession, ActionKindRedaction:
		return true
	default:
		return false
	}
}

// EffectiveDisposition is what the rollout mode actually does with a request after
// combining mode, scope, hard failures, the policy action, and obligations.
type EffectiveDisposition uint8

const (
	// EffectRecordOnly — record the decision; NO upstream execution (Disabled,
	// Observe, or out-of-scope with no shadow fallback).
	EffectRecordOnly EffectiveDisposition = iota
	// EffectExecute — perform the real guarded upstream execution.
	EffectExecute
	// EffectBlock — block the call (a hard failure in any mode, or an enforced
	// non-allow decision / unsatisfied obligation in Canary/Production).
	EffectBlock
	// EffectShadowEvaluate — Shadow mode: compute the would-be outcome
	// (WOULD_EXECUTE / WOULD_BLOCK) and record durable evidence, but NEVER perform the
	// upstream side effect. This is a DISTINCT disposition from EffectExecute
	// precisely so a Shadow request can never share the execute path with
	// Canary/Production. The executor routes it to a non-executing evaluator that holds
	// no path to Upstream.Call or credential materialization (SH-INV-1/2,
	// docs/design/mcp/SHADOW-ARCHITECTURE.md §3). Shadow does not execute; it evaluates.
	EffectShadowEvaluate
)

// String returns a stable token for the disposition.
func (d EffectiveDisposition) String() string {
	switch d {
	case EffectRecordOnly:
		return "record_only"
	case EffectExecute:
		return "execute"
	case EffectBlock:
		return "block"
	case EffectShadowEvaluate:
		return "shadow_evaluate"
	default:
		return "unknown"
	}
}

// ResolveInput is the fully-resolved evidence the mode resolver combines. The
// caller (the runtime executor) supplies the resolved policy action, whether the
// subject is in the active/shadow scope, whether a fixed hard failure fired, and
// whether allow-class obligations were satisfied.
type ResolveInput struct {
	Mode Mode
	// InScope reports whether the subject is inside THIS mode's active scope.
	InScope bool
	// ShadowEnabled + ShadowInScope drive the Canary/Production out-of-scope
	// fallback: outside Canary scope a subject retains Shadow behavior when a shadow
	// scope is enabled and the subject is in it; otherwise Observe behavior.
	ShadowEnabled bool
	ShadowInScope bool
	// Action is the PR-6 policy decision's disposition class.
	Action ActionKind
	// HardFailure reports whether a fixed hard failure fired (auth/server/credential/
	// availability/destination/tool/management/inspection). It blocks in EVERY mode.
	HardFailure bool
	// HardReason is the classified reason for a hard failure (informational).
	HardReason mcperr.Reason
	// ObligationsSatisfied reports whether allow-class obligations were met (an
	// ALLOW_ONCE consumed, an ALLOW_FOR_SESSION within its bound). Trivially true for
	// plain ALLOW/MONITOR/REDACTION. Only consulted in Canary/Production.
	ObligationsSatisfied bool
}

// Resolution is the truthful mode-resolution result. It preserves the evaluated
// policy action UNCHANGED and records the effective disposition separately.
type Resolution struct {
	Disposition     EffectiveDisposition
	EvaluatedAction ActionKind
	EffectiveAction ActionKind
	InScope         bool
	HardFailure     bool
	ShadowOverride  bool
	Executed        bool
	BlockReason     mcperr.Reason
}

// Resolve computes the effective disposition. It is pure (no I/O, no clock) and
// fail-closed: an unknown mode blocks. It NEVER downgrades a hard failure and
// NEVER overwrites the evaluated policy action.
func Resolve(in ResolveInput) Resolution {
	r := Resolution{EvaluatedAction: in.Action, EffectiveAction: in.Action, InScope: in.InScope, HardFailure: in.HardFailure}
	switch in.Mode {
	case ModeDisabled, ModeObserve:
		// Never any upstream execution; the decision is recorded as-is.
		r.Disposition = EffectRecordOnly
		return r
	case ModeShadow:
		return resolveShadow(in, r)
	case ModeCanary, ModeProduction:
		return resolveEnforcing(in, r)
	default:
		r.Disposition = EffectBlock
		r.BlockReason = mcperr.ReasonRolloutModeInvalid
		return r
	}
}

func resolveShadow(in ResolveInput, r Resolution) Resolution {
	if !in.InScope {
		// Outside the shadow scope: Observe behavior (record, no execution).
		r.Disposition = EffectRecordOnly
		return r
	}
	// Shadow NEVER crosses the irreversible side-effect boundary (SH-INV-1) and NEVER
	// ENFORCES: every in-scope request — including a hard failure — is routed to the
	// non-executing EffectShadowEvaluate disposition so the evaluator records a truthful
	// Model-1 outcome (WOULD_EXECUTE / WOULD_BLOCK / WOULD_FAIL_*). A hard failure is NOT
	// downgraded to an EffectBlock here: emitting a block in Shadow is indistinguishable
	// from real enforcement, whereas Shadow must only ever PREDICT — the evaluator maps a
	// hard failure to WOULD_FAIL_HARD_CONTROL / WOULD_FAIL_INSPECTION and a policy
	// non-allow to WOULD_BLOCK / WOULD_REQUIRE_*. `Executed` stays false. The evaluated
	// policy action is preserved unchanged; the effective action is the would-be allow.
	r.Disposition = EffectShadowEvaluate
	r.Executed = false
	r.EffectiveAction = ActionKindAllow
	if in.HardFailure {
		// Carry the classified hard reason for evidence; the evaluator owns the outcome.
		r.BlockReason = in.HardReason
	}
	if !in.Action.IsAllowClass() {
		// Policy verdict is itself restrictive; the evaluator records a policy-driven
		// would-block and this flags that the enforcement prediction diverges from allow.
		r.ShadowOverride = true
	}
	return r
}

func resolveEnforcing(in ResolveInput, r Resolution) Resolution {
	if !in.InScope {
		// Outside Canary/Production scope: fall back to Shadow if enabled+in-scope,
		// otherwise Observe. Never expand enforcement to the whole fleet.
		if in.ShadowEnabled && in.ShadowInScope {
			sh := in
			sh.Mode = ModeShadow
			sh.InScope = true
			return resolveShadow(sh, Resolution{EvaluatedAction: in.Action, EffectiveAction: in.Action, InScope: true, HardFailure: in.HardFailure})
		}
		r.Disposition = EffectRecordOnly
		return r
	}
	if in.HardFailure {
		r.Disposition = EffectBlock
		r.EffectiveAction = ActionKindDenied
		r.BlockReason = in.HardReason
		return r
	}
	if !in.Action.IsAllowClass() {
		// DENY / QUARANTINE / REQUIRE_CONFIRMATION / REQUIRE_APPROVAL all block under
		// full enforcement (the confirmation/approval is fed into policy re-eval, so a
		// still-non-allow action means the obligation was not satisfied).
		r.Disposition = EffectBlock
		r.BlockReason = blockReasonForAction(in.Action)
		return r
	}
	if !in.ObligationsSatisfied {
		// An allow-class action whose allowance/obligation was not satisfied (e.g. an
		// ALLOW_ONCE already consumed, an ALLOW_FOR_SESSION over its bound).
		r.Disposition = EffectBlock
		r.EffectiveAction = ActionKindDenied
		r.BlockReason = mcperr.ReasonAllowanceConsumed
		return r
	}
	r.Disposition = EffectExecute
	r.Executed = true
	return r
}

func blockReasonForAction(a ActionKind) mcperr.Reason {
	switch a {
	case ActionKindConfirm:
		return mcperr.ReasonConfirmationRequired
	case ActionKindApproval:
		return mcperr.ReasonApprovalRequired
	default:
		return mcperr.ReasonExecutionNotPermitted
	}
}
