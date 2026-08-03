package runtime

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// ExecutionProvider is the PR-11 guarded-execution seam. It is consulted AFTER a
// decision-point request has passed inspection + the PR-6 policy evaluation, and
// it owns the rollout-mode resolution + (for an in-scope executing mode) the real
// guarded upstream execution. A nil provider ⇒ the runtime stays decision-only.
//
// The provider MUST NOT be consulted for Management (which never executes an
// upstream tools/call); the runtime only wires it for the Gateway capability.
type ExecutionProvider interface {
	// Execute runs the guarded rollout-mode path and returns the terminal result +
	// the observation fields to record. It performs its OWN durable
	// commit-before-side-effect; the runtime does not pre-commit for this path.
	Execute(ctx context.Context, in ExecInput) ExecOutput
}

// ExecInput carries the already-resolved request facts the executor needs. It
// contains no raw token; RawArgs is the exact (already-inspected) tools/call
// params for the upstream leg.
type ExecInput struct {
	Capability   protocol.Capability
	Method       string
	MessageID    jsonrpc.ID
	RawParams    []byte
	Decision     policy.Decision
	Input        policy.DecisionInput
	Inspection   *inspection.Result // nil when inspection did not run
	Identity     *identity.ResolvedContext
	Server       *registry.ServerRecord // resolved server record (nil for tools/list on management)
	SnapshotHash string
	Now          time.Time
}

// ExecOutput is the executor's truthful result. The runtime maps it into the
// terminal Outcome and records the observation fields.
type ExecOutput struct {
	Status          int
	Disposition     Disposition
	Reason          mcperr.Reason
	ResponseBody    []byte
	ExecutionState  string // "executed" | "not_implemented" | "blocked" | "shadow_recorded"
	EvaluatedAction string
	EffectiveAction string
	ShadowOverride  bool
	HardFailure     bool
	Executed        bool
}

// dispatchExecute hands a decision-point outcome to the guarded executor and maps
// the result back into a terminal Outcome. It is only reached when p.executor is
// non-nil (the disabled-by-default posture keeps the decision-only path).
func (p *pipeline) dispatchExecute(rb *recBuilder, req Request, msg jsonrpc.Message, ctx *identity.ResolvedContext, in policy.DecisionInput, d policy.Decision, insp inspectionRun, snapshotHash string, now time.Time) Outcome {
	var srv *registry.ServerRecord
	if req.ServerID != "" && p.deps.Registry != nil {
		if rec, ok := p.deps.Registry.Current().Get(registry.ServerID(req.ServerID)); ok {
			srv = &rec
		}
	}
	var inspResult *inspection.Result
	if insp.ran {
		r := insp.result
		inspResult = &r
	}
	ei := ExecInput{
		Capability:   p.capability,
		Method:       msg.Method,
		MessageID:    msg.ID,
		RawParams:    []byte(msg.Params),
		Decision:     d,
		Input:        in,
		Inspection:   inspResult,
		Identity:     ctx,
		Server:       srv,
		SnapshotHash: snapshotHash,
		Now:          now,
	}
	out := p.executor.Execute(context.Background(), ei)

	// Record the truthful observation fields.
	if out.EvaluatedAction != "" {
		rb.rec.PolicyAction = out.EvaluatedAction
	}
	if out.ExecutionState != "" {
		rb.rec.ExecutionState = out.ExecutionState
	}
	if out.Executed {
		p.ctr.requestsExecuted.Add(1)
	} else if out.Disposition == DispRejected {
		p.ctr.requestsRejected.Add(1)
	} else {
		p.ctr.observeOnly.Add(1)
	}
	return p.finish(rb, Outcome{Status: out.Status, Disposition: out.Disposition, Reason: out.Reason, ResponseBody: out.ResponseBody})
}
