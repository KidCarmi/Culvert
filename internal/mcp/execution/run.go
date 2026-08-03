package execution

import (
	"context"
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/events"
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// runExecute performs the real guarded upstream execution for an in-scope
// executing mode. The mandatory order is preserved: policy already ran, then
// credential planning, then a DURABLE P-CRIT commit BEFORE any cache decrypt /
// provider fetch / credential materialization / upstream call (via the credential
// gate or CommitThenAct), then the upstream call inside the materialization
// callback, then response inspection + DLP, then the result. A failure at any step
// leaves NO downstream side effect.
func (e *Executor) runExecute(ctx context.Context, in runtime.ExecInput, _ rollout.Subject, res rollout.Resolution) runtime.ExecOutput {
	if e.cfg.Events == nil {
		// No durability seam ⇒ fail closed (commit-before-side-effect is mandatory).
		return e.blocked(in, mcperr.ReasonEventDurabilityDegraded, false)
	}
	if in.Server == nil {
		return e.blocked(in, mcperr.ReasonUpstreamServerUnusable, false)
	}
	if !in.Server.Usable() {
		return e.blocked(in, mcperr.ReasonUpstreamServerUnusable, false)
	}
	target := upstreamclient.Target{
		ServerID:       string(in.Server.ID),
		Endpoint:       string(in.Server.Endpoint),
		PinnedIdentity: string(in.Server.PinnedIdentity),
	}
	idempotent := in.Input.Operation.Class == policy.OpRead || in.Input.Operation.Class == policy.OpDiscovery

	var upResp *upstreamclient.Response
	var upErr error
	callUpstream := func(authHeader string) error {
		r, err := e.cfg.Upstream.Call(ctx, target, in.Method, json.RawMessage(in.RawParams), upstreamclient.CallOptions{
			Idempotent: idempotent, AuthHeader: authHeader, WireID: "u-" + target.ServerID,
		})
		upResp, upErr = r, err
		return err
	}

	profileRef := in.Decision.Obligations.CredentialProfile
	if e.cfg.Broker != nil && profileRef != "" {
		if out, blocked := e.materializeAndCall(ctx, in, profileRef, callUpstream); blocked {
			return out
		}
	} else {
		// No credential profile: still commit the decision durably BEFORE the upstream
		// call, so a commit failure prevents the side effect.
		if err := e.cfg.Events.CommitThenAct(decisionFacts(in), func(spool.CommitReceipt) error {
			return callUpstream("")
		}); err != nil {
			return e.blocked(in, mcperr.ReasonOf(err), false)
		}
	}

	if upErr != nil {
		e.cfg.Metrics.ObserveUpstream(in.Capability.String(), "error")
		return e.blocked(in, mcperr.ReasonOf(upErr), false)
	}
	if upResp == nil {
		return e.blocked(in, mcperr.ReasonUpstreamCallFailed, false)
	}
	e.cfg.Metrics.ObserveUpstream(in.Capability.String(), "success")
	if upResp.Error != nil {
		// A bounded, sanitized upstream JSON-RPC error is forwarded (never raw text).
		return runtime.ExecOutput{Status: 200, Disposition: dispReject, Reason: mcperr.ReasonUpstreamCallFailed,
			ResponseBody: upstreamErrorResult(in.MessageID), ExecutionState: "executed", Executed: true,
			EvaluatedAction: in.Decision.Action.String(), EffectiveAction: "execute"}
	}

	// Response DLP: inspect the FULL upstream result BEFORE returning it to the
	// client. A hard block (secret/PII/schema/oversize) refuses the content.
	ir := inspection.InspectResponse(ctx, e.cfg.ResponseProfile, inspection.ResponseInput{
		Tool: toolRef(in), Body: []byte(upResp.Result),
	}, in.Now)
	if ir.HardFail {
		e.cfg.Metrics.ObserveDLPBlock(in.Capability.String(), true)
		return e.blocked(in, ir.HardReason, false)
	}
	// A non-hard redact/block disposition (e.g. the default profile classifies
	// financial data as DispRedact) still requires transformation before egress. The
	// guarded-execute path performs no response redaction, so anything but a
	// pass/label disposition fails closed rather than forwarding the untransformed
	// result to the client.
	if disp := ir.Summary.Disposition; disp != inspection.DispPass && disp != inspection.DispLabel {
		e.cfg.Metrics.ObserveDLPBlock(in.Capability.String(), true)
		return e.blocked(in, mcperr.ReasonRedactionFailed, false)
	}

	// Best-effort outcome event (ordinary criticality; never blocks the response).
	_, _ = e.cfg.Events.CommitDecision(outcomeFacts(in))
	e.cfg.Metrics.ObserveExecution(in.Capability.String(), true)

	effective := "execute"
	if res.ShadowOverride {
		effective = "shadow_execute"
	}
	return runtime.ExecOutput{
		Status: 200, Disposition: dispExecuted, Reason: mcperr.ReasonNone,
		ResponseBody: executedResult(in.MessageID, upResp.Result), ExecutionState: "executed", Executed: true,
		EvaluatedAction: in.Decision.Action.String(), EffectiveAction: effective, ShadowOverride: res.ShadowOverride,
	}
}

// materializeAndCall runs the broker materialization with the PR-8 credential gate
// (which durably commits the credential decision BEFORE any cache decrypt/provider
// fetch/materialization) and performs the upstream call inside the zeroizing
// callback. It returns (out, true) when the flow is blocked before/at execution.
func (e *Executor) materializeAndCall(ctx context.Context, in runtime.ExecInput, profileRef string, callUpstream func(string) error) (runtime.ExecOutput, bool) {
	plan, err := e.cfg.Broker.Plan(planInput(in, profileRef))
	if err != nil {
		return e.blocked(in, mcperr.ReasonOf(err), false), true
	}
	gate := e.cfg.Events.NewCredentialGate()
	_, mErr := e.cfg.Broker.Materialize(ctx, plan, gate, func(kind profile.CredentialKind, m *provider.Material) error {
		return callUpstream(authFromMaterial(kind, m))
	})
	if mErr != nil {
		return e.blocked(in, mcperr.ReasonOf(mErr), false), true
	}
	return runtime.ExecOutput{}, false
}

// authFromMaterial builds the upstream Authorization header from the materialized
// APPROVED-SERVER credential. The bytes live only for this call; the Material is
// zeroized when the broker callback returns.
func authFromMaterial(kind profile.CredentialKind, m *provider.Material) string {
	switch kind {
	case profile.KindBearerToken:
		if b, ok := m.Field(provider.FieldToken); ok {
			return "Bearer " + string(b)
		}
	case profile.KindAPIKey:
		if b, ok := m.Field(provider.FieldAPIKey); ok {
			return "ApiKey " + string(b)
		}
	}
	return ""
}

// planInput builds the broker plan input from the resolved request. It carries the
// PR-3 resolved identity (never a raw token) and the policy-selected profile.
func planInput(in runtime.ExecInput, profileRef string) broker.PlanInput {
	pi := broker.PlanInput{
		Identity:  in.Identity,
		Profile:   profile.ID(profileRef),
		Operation: mapProfileOp(in.Input.Operation.Class),
	}
	if in.Input.Server != nil {
		pi.Environment = profile.Environment(in.Input.Server.Environment)
	}
	if in.Input.Tool != nil && in.Input.Server != nil {
		pi.Tool = &profile.ToolBinding{Server: registry.ServerID(in.Input.Server.ServerID), Name: in.Input.Tool.Name}
	}
	return pi
}

// mapProfileOp maps a policy operation class to a credential operation class.
func mapProfileOp(c policy.OperationClass) profile.OperationClass {
	switch c {
	case policy.OpWrite:
		return profile.OpWrite
	case policy.OpDestructive:
		return profile.OpDestructive
	case policy.OpControl:
		return profile.OpAdmin
	default:
		return profile.OpRead
	}
}

// toolRef builds the inspection tool reference for response inspection.
func toolRef(in runtime.ExecInput) inspection.ToolRef {
	tr := inspection.ToolRef{}
	if in.Input.Tool != nil {
		tr.Name = in.Input.Tool.Name
		tr.ServerID = in.Input.Tool.ServerID
		tr.FingerprintHex = in.Input.Tool.FingerprintHash
	}
	return tr
}

// decisionFacts builds the durable decision fact for the no-credential
// commit-before-upstream path. A write/destructive execution is CRITICAL (the
// commit MUST succeed before the irreversible upstream call); a read is ordinary
// (its commit still gates the call via CommitThenAct, but a loss is tolerated).
// Criticality and action class are coupled so the fact passes model validation.
func decisionFacts(in runtime.ExecInput) events.DecisionFacts {
	crit, ac := criticalityFor(in.Input.Operation.Class)
	return events.DecisionFacts{
		Capability:  model.CapGateway,
		Criticality: crit,
		ActionClass: ac,
		Identity: model.IdentityEvidence{
			Tenant: in.Input.Principal.Tenant, PrincipalID: in.Input.Principal.SubjectID, PrincipalType: "workload",
		},
		Decision: model.DecisionEvidence{
			Action: in.Decision.Action.String(), ReasonCode: string(in.Decision.Reason),
			ExecutionState: "executing",
		},
		SnapshotHash: in.SnapshotHash,
	}
}

// outcomeFacts builds the ordinary-criticality outcome fact emitted after a
// successful execution (best-effort; never blocks the response).
func outcomeFacts(in runtime.ExecInput) events.DecisionFacts {
	f := decisionFacts(in)
	f.Criticality = model.CritOrdinary
	f.ActionClass = model.ActionClassRead
	f.Decision.ExecutionState = "executed"
	return f
}

// criticalityFor couples an operation class to a valid (criticality, action class)
// pair: write/destructive are critical; everything else is ordinary read.
func criticalityFor(c policy.OperationClass) (model.Criticality, model.ActionClass) {
	switch c {
	case policy.OpWrite:
		return model.CritCritical, model.ActionClassWrite
	case policy.OpDestructive:
		return model.CritCritical, model.ActionClassDestructive
	default:
		return model.CritOrdinary, model.ActionClassRead
	}
}
