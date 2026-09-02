// Package execution implements the PR-11 guarded Model-A execution path — the
// runtime.ExecutionProvider that turns the decision-only Gateway into a bounded,
// rollout-mode-gated executor. It is wired ONLY for the Gateway capability and
// ONLY when rollout distribution arms it (disabled by default). It composes the
// existing engines without weakening any of them: rollout (mode/scope/hard-failure),
// the PR-6 policy decision (already computed), PR-7 inspection/DLP for the response,
// the PR-4 credential broker (materialization with no token passthrough), the PR-8
// events manager (commit-before-side-effect), and the PR-11 upstream client.
package execution

import (
	"context"
	"encoding/json"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// UpstreamCaller is the injected upstream client (interface for testability).
type UpstreamCaller interface {
	Call(ctx context.Context, target upstreamclient.Target, method string, params json.RawMessage, opts upstreamclient.CallOptions) (*upstreamclient.Response, error)
}

// Config wires an Executor for the Gateway capability.
type Config struct {
	// State is the capability-local rollout state (Gateway). Required.
	State *rollout.State
	// Broker materializes the approved-server credential (nil ⇒ no credential is
	// attached; the upstream call carries no Authorization).
	Broker *broker.Broker
	// Events is the PR-8 durable-event manager. Required for the commit-before-
	// side-effect guarantee; a nil Events fails every execution closed.
	Events *events.Manager
	// Upstream is the bounded upstream MCP client. Required.
	Upstream UpstreamCaller
	// ResponseProfile is the PR-7 inspection profile used to inspect + DLP the
	// upstream response before returning it to the client.
	ResponseProfile inspection.Profile
	// Metrics is the optional rollout telemetry sink.
	Metrics Metrics
	// Clock is injected for tests; nil ⇒ time.Now.
	Clock func() time.Time
	// Actor labels events emitted by this executor.
	Actor string
	// LiveGate is the OPTIONAL composition-layer side-effect gate consulted at the boundary
	// BEFORE the executor's own tool-freshness + emergency-kill re-check, so the kill re-read
	// stays the LAST authoritative check before Upstream.Call (PREREQ-MCP-KILL-1). It owns the
	// gates that live OUTSIDE this package — Canary blast-radius budget reservation, runtime
	// live-execution trust revalidation, and read-first enforcement. nil ⇒ the executor is
	// byte-identical to the pre-gate path (the ShadowEvaluator and any non-live composition
	// never set it). See livegate.go.
	LiveGate LiveExecutionGate
}

// Executor implements runtime.ExecutionProvider. It is the LIVE object: it possesses
// the upstream client and the materialize-capable broker and is composed ONLY for
// Canary/Production (both prohibited today). Its Shadow-fallback disposition
// (out-of-scope Canary → Shadow) is delegated to a distinct, capability-reduced
// *ShadowEvaluator so the shadow path never touches this object's live capabilities.
type Executor struct {
	cfg        Config
	allowances *allowanceStore
	shadow     *ShadowEvaluator // capability-reduced; handles EffectShadowEvaluate
}

var _ runtime.ExecutionProvider = (*Executor)(nil)

// New constructs an Executor. It fails closed if the required collaborators are
// missing.
func New(cfg Config) (*Executor, error) {
	if cfg.State == nil {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "execution", "nil rollout state")
	}
	if cfg.Upstream == nil {
		return nil, mcperr.New(mcperr.ReasonListenerConfigInvalid, "execution", "nil upstream client")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Metrics == nil {
		cfg.Metrics = noopMetrics{}
	}
	// Build the capability-reduced Shadow evaluator that handles EffectShadowEvaluate.
	// It receives ONLY the plan-only credential capability — never the materialize-
	// capable *broker.Broker itself — and no upstream client at all, so the shadow path
	// structurally cannot reach Upstream.Call or Materialize even though it lives inside
	// the live Executor (SH-INV-2, Layer B).
	shCfg := ShadowConfig{
		State:   cfg.State,
		Events:  cfg.Events,
		Metrics: cfg.Metrics,
		Clock:   cfg.Clock,
		Actor:   cfg.Actor,
	}
	if cfg.Broker != nil {
		// Supply the broker as the plan-only CredentialPlanner. NewShadowEvaluator narrows
		// it to the bound Plan method value and drops the interface, so the Shadow evaluator
		// never retains the materialize-capable *broker.Broker (Codex P2).
		shCfg.Planner = cfg.Broker
	}
	shadow, err := NewShadowEvaluator(shCfg)
	if err != nil {
		return nil, err
	}
	// The embedded shadow evaluator SHARES this executor's allowance store (Codex P2).
	// Live execution consumes ALLOW_ONCE / ALLOW_FOR_SESSION grants from it; the shadow
	// path reads the SAME store non-destructively via wouldSatisfy. Without sharing, a
	// Canary out-of-scope → shadow fallback (or a demotion) would let the shadow see a
	// fresh grant and predict WOULD_EXECUTE where the same executor would return
	// allowance_consumed. wouldSatisfy never mutates, so sharing keeps the read-only
	// contract intact.
	allow := newAllowanceStore()
	shadow.allowances = allow
	return &Executor{cfg: cfg, allowances: allow, shadow: shadow}, nil
}

// Resolve implements runtime.ExecutionProvider: it resolves the effective rollout
// disposition for this request EXACTLY ONCE (no side effect), so routing and execution
// use the same snapshot. A killed capability resolves to an emergency block.
func (e *Executor) Resolve(in runtime.ExecInput) rollout.Resolution {
	return resolveDisposition(e.cfg.State, in)
}

// Execute is the runtime.ExecutionProvider entry. It acts on the PRE-RESOLVED mode/scope
// disposition (it never re-resolves mode or scope — F7 single resolution, Codex P2 #1234)
// and dispatches record-only / block / execute.
//
// It re-reads ONLY the emergency kill: the kill switch is an immediate admission stop, so a
// kill engaged AFTER Resolve but before the irreversible upstream call must still stop it.
// This is orthogonal to single-resolution — it reads only the monotonic kill flag and can
// only make the outcome MORE restrictive (an emergency block), so it cannot reopen the
// routing TOCTOU F7 closed. Fail-closed here matters most on the LIVE path: it stops an
// upstream side effect that Resolve had cleared microseconds before the operator hit kill.
func (e *Executor) Execute(ctx context.Context, in runtime.ExecInput, res rollout.Resolution) runtime.ExecOutput {
	// Capture the authoritative emergency-kill generation at ADMISSION, before the
	// admission check, so the irreversible side-effect boundary can detect any emergency
	// kill engaged while this request is in flight — even one later cleared (Model B /
	// monotonic epoch, PREREQ-MCP-KILL-1). A kill that races between this capture and the
	// Killed() check below is caught by that check; one that races after it is caught at the
	// boundary because the generation will have advanced past admKillGen.
	admKillGen := e.cfg.State.KillGeneration()
	if e.cfg.State.Killed() {
		return e.blocked(in, mcperr.ReasonRolloutEmergencyActive, false)
	}
	subj := subjectFor(in)
	action := mapAction(in.Decision.Action)
	e.cfg.Metrics.ObserveResolution(in.Capability.String(), res)

	switch res.Disposition {
	case rollout.EffectRecordOnly:
		return e.recordOnly(in, res)
	case rollout.EffectShadowEvaluate:
		// Shadow: compute the would-be outcome and record evidence, but NEVER execute.
		// Delegated to the capability-reduced ShadowEvaluator, which holds no path to
		// Upstream.Call or Materialize (SH-INV-1/2). The live Executor's own upstream
		// client and broker are unreachable from this branch.
		return e.shadow.evaluate(ctx, in)
	case rollout.EffectBlock:
		return e.blocked(in, res.BlockReason, res.ShadowOverride)
	case rollout.EffectExecute:
		if action == rollout.ActionKindRedaction {
			// ALLOW_WITH_REDACTION requires a re-validated request-argument transform
			// before egress; the guarded-execute path performs NO request redaction, so
			// fail closed rather than send untransformed arguments upstream (mirrors the
			// decision-only path's fail-closed redaction guard in runtime/policy.go).
			return e.blocked(in, mcperr.ReasonRedactionFailed, false)
		}
		if needsAllowance(action) {
			if !e.allowances.consume(in, action, e.cfg.Clock()) {
				return e.blocked(in, mcperr.ReasonAllowanceConsumed, false)
			}
		}
		return e.runExecute(ctx, in, subj, res, admKillGen)
	default:
		return e.blocked(in, mcperr.ReasonRolloutModeInvalid, false)
	}
}

// KillActive implements runtime.ExecutionProvider: it reports whether this capability's
// emergency kill switch is engaged, for the runtime's record-only fall-through re-check.
func (e *Executor) KillActive() bool { return e.cfg.State.Killed() }

// recordOnly returns the decision-only (observe) result: the true policy action is
// recorded, no upstream call is made.
func (e *Executor) recordOnly(in runtime.ExecInput, res rollout.Resolution) runtime.ExecOutput {
	return runtime.ExecOutput{
		Status:          200,
		Disposition:     dispObserve,
		Reason:          mcperr.ReasonObserveOnly,
		ResponseBody:    observeResult(in.MessageID, in.Decision),
		ExecutionState:  "not_implemented",
		EvaluatedAction: in.Decision.Action.String(),
		EffectiveAction: "record_only",
		ShadowOverride:  res.ShadowOverride,
	}
}

// blocked returns a terminal JSON-RPC error result. The evaluated policy action is
// read from in.Decision (never softened), so it is not a parameter.
func (e *Executor) blocked(in runtime.ExecInput, reason mcperr.Reason, shadowOverride bool) runtime.ExecOutput {
	e.cfg.Metrics.ObserveBlock(in.Capability.String(), reason)
	return runtime.ExecOutput{
		Status:          200,
		Disposition:     dispReject,
		Reason:          reason,
		ResponseBody:    errorResult(in.MessageID, reason),
		ExecutionState:  "blocked",
		EvaluatedAction: in.Decision.Action.String(),
		EffectiveAction: "block",
		HardFailure:     rollout.IsHardFailure(reason),
		ShadowOverride:  shadowOverride,
	}
}

// subjectFor builds the rollout.Subject from the resolved policy input.
func subjectFor(in runtime.ExecInput) rollout.Subject {
	s := rollout.Subject{
		Capability:  rollout.CapabilityGateway,
		Tenant:      in.Input.Principal.Tenant,
		PrincipalID: in.Input.Principal.SubjectID,
		Groups:      in.Input.Principal.Groups,
		Operation:   mapRisk(in.Input.Operation.Class),
	}
	if in.Input.Server != nil {
		s.ServerID = in.Input.Server.ServerID
	}
	if in.Input.Tool != nil {
		s.ToolName = in.Input.Tool.Name
		s.ToolFingerprint = in.Input.Tool.FingerprintHash
	}
	if in.Input.Agent != nil {
		s.AgentID = in.Input.Agent.AgentID
	}
	s.ClientID = in.Input.Client.ClientID
	return s
}

// mapRisk maps a policy operation class to a rollout risk class.
func mapRisk(c policy.OperationClass) rollout.RiskClass {
	switch c {
	case policy.OpWrite:
		return rollout.RiskWrite
	case policy.OpDestructive:
		return rollout.RiskDestructive
	default:
		// Read/Discovery/Control are treated as read-only/reversible for scoping.
		return rollout.RiskRead
	}
}

// hardFailure reports whether a fixed hard failure fired for this request (a policy
// hard override or a PR-7 inspection hard block).
func hardFailure(in runtime.ExecInput) (bool, mcperr.Reason) {
	if in.Inspection != nil && in.Inspection.HardFail {
		return true, in.Inspection.HardReason
	}
	if in.Decision.HardOverride {
		return true, policyHardReason(in.Decision)
	}
	return false, mcperr.ReasonNone
}

// policyHardReason maps a policy hard-override decision to a classified reason for
// the hard-failure taxonomy.
func policyHardReason(d policy.Decision) mcperr.Reason {
	switch d.Reason {
	case policy.ReasonTenantMismatch:
		return mcperr.ReasonTenantMismatch
	case policy.ReasonServerIdentityChanged:
		return mcperr.ReasonServerIdentityMismatch
	case policy.ReasonServerDisabled:
		return mcperr.ReasonUnregisteredServer
	case policy.ReasonToolUnknown:
		return mcperr.ReasonUnknownTool
	case policy.ReasonToolPrivilegeExpansion:
		return mcperr.ReasonPrivilegeExpansion
	case policy.ReasonManagementMutationNotApproved:
		return mcperr.ReasonManagementToolUnauthorized
	case policy.ReasonIdentityAmbiguous:
		return mcperr.ReasonSessionIdentityBound
	default:
		return mcperr.ReasonExecutionNotPermitted
	}
}

// needsAllowance reports whether the action consumes a per-call/session allowance.
func needsAllowance(a rollout.ActionKind) bool {
	return a == rollout.ActionKindAllowOnce || a == rollout.ActionKindAllowSession
}

// resolveDisposition resolves the effective rollout disposition for a request EXACTLY
// ONCE — the SINGLE point at which the mutable rollout state is read for this request, so
// routing (record-only vs not) and execution act on the same snapshot and can never
// diverge across a concurrent transition (Codex P2, PR #1234). A KILLED capability
// resolves to an emergency block (never record-only): admission is stopped, so the
// runtime routes it to Execute, which emits the block, rather than to its inline Observe
// path. It performs no side effect.
func resolveDisposition(st *rollout.State, in runtime.ExecInput) rollout.Resolution {
	action := mapAction(in.Decision.Action)
	if st.Killed() {
		return rollout.Resolution{
			Disposition: rollout.EffectBlock, BlockReason: mcperr.ReasonRolloutEmergencyActive,
			EvaluatedAction: action, EffectiveAction: action,
		}
	}
	subj := subjectFor(in)
	hardFail, hardReason := hardFailure(in)
	return st.ResolveFor(subj, action, hardFail, hardReason, true)
}
