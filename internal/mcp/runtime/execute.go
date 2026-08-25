package runtime

import (
	"context"
	"time"

	"encoding/hex"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
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

	// ToolStillCurrent re-resolves the decision's tool against the LIVE catalog and
	// reports whether it still carries the fingerprint the decision was computed
	// against. It is called by the executor at the LAST moment before the
	// irreversible upstream call.
	//
	// The check at the top of dispatchExecute NARROWS the decision/execution TOCTOU
	// window (OVN-09); it does not close it. After that check the executor still
	// commits durable evidence, plans credentials and fetches provider material —
	// all of which can block — while a concurrent execution.Discovery -> catalog
	// Ingest publishes a new snapshot. Only a re-check adjacent to the side effect
	// makes "the tool the decision was about" and "the tool being called" the same
	// tool.
	//
	// nil ⇒ no re-check (a caller with no catalog seam); the entry check still
	// applies. It returns a bool rather than an error so the executor maps it to
	// exactly one reason and cannot mistake a drift refusal for a transport fault.
	ToolStillCurrent func() bool
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
func (p *pipeline) dispatchExecute(ctx context.Context, rb *recBuilder, req Request, msg jsonrpc.Message, ident *identity.ResolvedContext, in policy.DecisionInput, d policy.Decision, insp inspectionRun, snapshotHash string, now time.Time) Outcome {
	// OVN-09 — decision/execution TOCTOU. The policy decision was computed against
	// a catalog SNAPSHOT. Between then and the irreversible upstream call there is a
	// real window (inspection, durable commit, credential planning, provider fetch)
	// in which a concurrent discovery — execution.Discovery -> catalog.Ingest
	// publishes a new snapshot — can change the tool the decision was made about.
	// Re-validate against the LIVE catalog and refuse a stale decision before any
	// side effect. This is the drift MCP-TOOL-001 / MCP-T-011 / MCP-T-016 exist to
	// prevent, and the executor never re-checked it.
	if out, stale := p.refuseOnToolDrift(rb, in, msg.ID); stale {
		return out
	}
	// The same predicate, handed to the executor to re-run adjacent to the upstream
	// call. Captured by value from this decision's input, so it can never be
	// satisfied by a DIFFERENT request's tool.
	toolStillCurrent := func() bool { return !p.toolHasDrifted(in) }
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
		Identity:     ident,
		Server:       srv,
		SnapshotHash: snapshotHash,
		Now:          now,

		ToolStillCurrent: toolStillCurrent,
	}
	// SEC-MCP-03. The executor performs the REAL upstream side effect and must
	// inherit the request's deadline and cancellation: with a DETACHED background
	// context here, a disconnected client, an exhausted RequestDeadline or a
	// shutdown could not stop an in-flight upstream call, and every ctx-honouring
	// stage the executor reaches (broker, provider, dial, TLS, response read,
	// response inspection) silently lost its bound.
	out := p.executor.Execute(ctx, ei)

	// Record the truthful observation fields.
	if out.EvaluatedAction != "" {
		rb.rec.PolicyAction = out.EvaluatedAction
	}
	if out.ExecutionState != "" {
		rb.rec.ExecutionState = out.ExecutionState
	}
	switch {
	case out.Executed:
		p.ctr.requestsExecuted.Add(1)
	case out.Disposition == DispRejected:
		p.ctr.requestsRejected.Add(1)
	default:
		p.ctr.observeOnly.Add(1)
	}
	return p.finish(rb, Outcome{Status: out.Status, Disposition: out.Disposition, Reason: out.Reason, ResponseBody: out.ResponseBody})
}

// refuseOnToolDrift re-resolves the decision's tool against the LIVE catalog and
// returns a terminal refusal when it no longer matches.
//
// It fails CLOSED in both directions: a fingerprint that moved, and a tool that
// has disappeared from the catalog entirely, are both stale decisions. A decision
// with no tool (tools/list, or a call whose tool never resolved) is unaffected —
// there is nothing to have drifted.
//
// It runs BEFORE the executor is reached, so no credential is planned, no event is
// committed and no upstream request is issued under a stale decision.
// toolHasDrifted reports whether the decision's tool no longer resolves, in the
// LIVE catalog, to the exact fingerprint the decision was computed against. A tool
// that has been REMOVED counts as drifted: the decision described something the
// catalog no longer offers.
//
// No tool in the decision, or no catalog seam, is not drift — there is nothing to
// compare, and inventing drift there would refuse traffic the gateway is
// configured to allow.
func (p *pipeline) toolHasDrifted(in policy.DecisionInput) bool {
	if in.Tool == nil || p.deps.Catalog == nil {
		return false
	}
	rec, ok := p.deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(in.Tool.ServerID), Name: in.Tool.Name,
	})
	if !ok {
		return true
	}
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:]) != in.Tool.FingerprintHash
}

func (p *pipeline) refuseOnToolDrift(rb *recBuilder, in policy.DecisionInput, id jsonrpc.ID) (Outcome, bool) {
	if !p.toolHasDrifted(in) {
		return Outcome{}, false
	}
	p.ctr.requestsRejected.Add(1)
	rb.rec.PolicyAction = "BLOCKED_BY_DECISION_STALE"
	rb.rec.PolicyReason = mcperr.ReasonDecisionSnapshotStale.Code()
	rb.rec.ExecutionState = "" // nothing executed
	return p.finish(rb, Outcome{
		Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonDecisionSnapshotStale,
		ResponseBody: inspectionError(id, mcperr.ReasonDecisionSnapshotStale),
	}), true
}
