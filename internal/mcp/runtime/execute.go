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
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// ExecutionProvider is the PR-11 guarded-execution seam. It is consulted AFTER a
// decision-point request has passed inspection + the PR-6 policy evaluation, and
// it owns the rollout-mode resolution + (for an in-scope executing mode) the real
// guarded upstream execution. A nil provider ⇒ the runtime stays decision-only.
//
// The provider MUST NOT be consulted for Management (which never executes an
// upstream tools/call); the runtime only wires it for the Gateway capability.
type ExecutionProvider interface {
	// Resolve resolves the effective rollout disposition for this request EXACTLY ONCE,
	// with no side effect (no commit, no upstream call). The runtime routes on it — a
	// record-only disposition (Observe / Disabled / out-of-scope, and a killed capability
	// resolves to a block, never record-only) keeps the runtime's inline Observe evidence
	// path — and hands the SAME resolution back to Execute. Resolving once and carrying it
	// into execution is what closes the TOCTOU: routing and execution can never observe two
	// different snapshots of the mutable rollout state across a concurrent transition, so a
	// request never falls through as Observe without its Shadow evaluation, nor reaches the
	// evaluator's record-only path without the inline durable commit (Codex P2, PR #1234).
	Resolve(in ExecInput) rollout.Resolution
	// Execute runs the guarded rollout-mode path for a PRE-RESOLVED disposition and returns
	// the terminal result + the observation fields to record. It NEVER re-resolves the
	// rollout state — it acts on the resolution Resolve produced. It performs its OWN
	// durable commit-before-side-effect; the runtime does not pre-commit for this path.
	Execute(ctx context.Context, in ExecInput, res rollout.Resolution) ExecOutput
	// KillActive reports whether the capability's emergency kill switch is currently engaged.
	// The runtime consults it on the RECORD-ONLY fall-through, so an emergency admission stop
	// blocks even the inline Observe path; the executing path is covered by Execute's own
	// entry re-check. Reading only the monotonic kill flag can only make the outcome more
	// restrictive, so it does not reopen the single-resolution TOCTOU (Codex P2, PR #1234).
	KillActive() bool
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

// buildExecInput materializes the ExecInput the executor needs from the resolved
// decision facts. It is pure (a registry snapshot read + a captured drift predicate)
// so it can be built once and used both for the RecordsOnly routing probe and for
// Execute, guaranteeing the disposition the runtime routes on is computed from the
// exact same input the executor acts on.
func (p *pipeline) buildExecInput(req Request, msg jsonrpc.Message, ident *identity.ResolvedContext, in policy.DecisionInput, d policy.Decision, insp inspectionRun, snapshotHash string, now time.Time) ExecInput {
	// The drift predicate, captured by value from this decision's input, so it can
	// never be satisfied by a DIFFERENT request's tool.
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
	return ExecInput{
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
}

// dispatchExecute hands a decision-point outcome to the guarded executor and maps
// the result back into a terminal Outcome. It is reached only for a NON-record-only
// disposition (Shadow evaluate / Canary-Production execute / hard block): a
// record-only disposition keeps the runtime's inline Observe evidence path instead
// (dispatchPolicy), so a composed evaluator never displaces the decision-event commit.
// It receives the resolution the runtime already resolved and passes it to Execute, so
// the disposition is never re-resolved.
func (p *pipeline) dispatchExecute(ctx context.Context, rb *recBuilder, ei ExecInput, res rollout.Resolution) Outcome {
	// OVN-09 — decision/execution TOCTOU. The policy decision was computed against
	// a catalog SNAPSHOT. Between then and the irreversible upstream call there is a
	// real window (inspection, durable commit, credential planning, provider fetch)
	// in which a concurrent discovery — execution.Discovery -> catalog.Ingest
	// publishes a new snapshot — can change the tool the decision was made about.
	// Re-validate against the LIVE catalog and refuse a stale decision before any
	// side effect. This is the drift MCP-TOOL-001 / MCP-T-011 / MCP-T-016 exist to
	// prevent, and the executor never re-checked it.
	if out, stale := p.refuseOnToolDrift(rb, ei.Input, ei.MessageID); stale {
		return out
	}
	// SEC-MCP-03. The executor performs the REAL upstream side effect and must
	// inherit the request's deadline and cancellation: with a DETACHED background
	// context here, a disconnected client, an exhausted RequestDeadline or a
	// shutdown could not stop an in-flight upstream call, and every ctx-honouring
	// stage the executor reaches (broker, provider, dial, TLS, response read,
	// response inspection) silently lost its bound.
	out := p.executor.Execute(ctx, ei, res)

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
	if hex.EncodeToString(sum[:]) != in.Tool.FingerprintHash {
		return true
	}
	// ELIGIBILITY IS A SEPARATE AXIS FROM THE FINGERPRINT, and checking only the
	// fingerprint misses an entire class of revocation. catalog.DisableServer copies
	// each record and changes ONLY Eligibility (to ServerDisabled) and Revision --
	// the fingerprint is deliberately preserved, because the tool's shape did not
	// change, its server's identity did. A fingerprint-only check therefore reports
	// "still current" for a tool the catalog has just marked unusable, which is the
	// operator action that says "stop calling this server". The same holds for a
	// transition into Quarantined or ReviewRequired.
	//
	// Compared through policyDisposition -- the SAME mapping the decision input was
	// built with (policy.go) -- so this asks exactly the question the decision
	// answered, rather than a second, independently-drifting notion of "eligible".
	disp, drift := policyDisposition(rec.Eligibility)
	return disp != in.Tool.Disposition || drift != in.Tool.Drift
}

func (p *pipeline) refuseOnToolDrift(rb *recBuilder, in policy.DecisionInput, id jsonrpc.ID) (Outcome, bool) {
	if !p.toolHasDrifted(in) {
		return Outcome{}, false
	}
	// AUTHORITATIVE DRIFT, and refusing the request is only half the answer.
	//
	// The reviewed tool is no longer the one the decision was computed against. For an ordinary
	// gateway that is a stale decision and nothing more; for a CANARY it is proof the experiment's
	// premise — a pinned, reviewed target — no longer holds, and the experiment must stop rather
	// than merely decline this request. Detected here and left unreported, a rug-pull landing
	// before this check stopped nothing, and every later request against the new fingerprint failed
	// approval validation instead, which reads as ordinary denial (Codex round 14).
	//
	// The seam is nil in every non-Canary composition, so this is a no-op there.
	p.deps.reportCanaryBreach(p.capability.String(), "tool_fingerprint_drift")
	p.ctr.requestsRejected.Add(1)
	rb.rec.PolicyAction = "BLOCKED_BY_DECISION_STALE"
	rb.rec.PolicyReason = mcperr.ReasonDecisionSnapshotStale.Code()
	rb.rec.ExecutionState = "" // nothing executed
	return p.finish(rb, Outcome{
		Status: 200, Disposition: DispRejected, Reason: mcperr.ReasonDecisionSnapshotStale,
		ResponseBody: inspectionError(id, mcperr.ReasonDecisionSnapshotStale),
	}), true
}
