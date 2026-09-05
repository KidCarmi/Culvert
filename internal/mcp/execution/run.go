package execution

import (
	"context"
	"encoding/json"
	"errors"

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

// errToolDriftedBeforeCall aborts the commit-then-act callback when the decision's
// tool changed under it. It never escapes this package: the caller maps it to
// mcperr.ReasonDecisionSnapshotStale before returning.
var errToolDriftedBeforeCall = errors.New("mcp: tool drifted between decision and upstream call")

// errKilledAtBoundary aborts the commit-then-act callback when the authoritative
// emergency-kill generation advanced between admission and the irreversible upstream
// side effect (PREREQ-MCP-KILL-1). Like errToolDriftedBeforeCall it never escapes this
// package: the caller maps it to mcperr.ReasonRolloutEmergencyActive before returning,
// on BOTH the credential and no-credential paths.
var errKilledAtBoundary = errors.New("mcp: emergency kill engaged before upstream call")

// runExecute performs the real guarded upstream execution for an in-scope
// executing mode. The mandatory order is preserved: policy already ran, then
// credential planning, then a DURABLE P-CRIT commit BEFORE any cache decrypt /
// provider fetch / credential materialization / upstream call (via the credential
// gate or CommitThenAct), then the upstream call inside the materialization
// callback, then response inspection + DLP, then the result. A failure at any step
// leaves NO downstream side effect.
func (e *Executor) runExecute(ctx context.Context, in runtime.ExecInput, _ rollout.Subject, res rollout.Resolution, admKillGen uint64) (out runtime.ExecOutput) {
	if reason, ok := executePreconditionFailure(e, in); !ok {
		return e.blocked(in, reason, false)
	}
	target := upstreamclient.Target{
		ServerID:       string(in.Server.ID),
		Endpoint:       string(in.Server.Endpoint),
		PinnedIdentity: string(in.Server.PinnedIdentity),
	}
	idempotent := in.Input.Operation.Class == policy.OpRead || in.Input.Operation.Class == policy.OpDiscovery

	// PHYSICAL-EFFECT ACCOUNTING (review blockers #6/#8).
	//
	// attempt is non-nil once a durable send intent has been committed for a
	// side-effect-bearing invocation; sendState is the conservative truth about
	// whether the peer could have acted. The terminal outcome is emitted from ONE
	// deferred commit rather than at each return, because this function has seven
	// exit paths and the previous code recorded an outcome on exactly one of them
	// (the success path) — upstream errors, DLP blocks and boundary refusals left no
	// post-call evidence at all.
	var attempt *attemptRecord
	sendState := model.SendStateUnset
	// Declared BEFORE the deferred commit so that commit can read the upstream leg's own verdict.
	var upResp *upstreamclient.Response
	var upErr error
	defer func() {
		if attempt == nil {
			return // no durable intent ⇒ no physical attempt to account for
		}
		// The UPSTREAM LEG's own verdict, computed here because this is where it is
		// known. "Did the peer give us a usable answer?" is a different question from
		// "did Culvert return a result?", and a different question again from "did the
		// invocation reach the peer?" — the health detector needs the first, and only
		// this scope has it (Codex round 5 P1).
		//
		// A JSON-RPC `error` object is the THIRD shape a failure arrives in, and it is the
		// most ordinary one: the transport succeeded, the body decoded, and the peer is
		// telling us the tool did not work. Client.Call returns it as a non-nil Response with
		// a nil Go error, so a transport-only predicate read it as a SUCCESS — while
		// finishUpstream, two hundred lines down, already classifies exactly that response as
		// ReasonUpstreamCallFailed. The detector disagreed with the code beside it, and two
		// such tool failures produced zero failures, never reached the 1-of-2 threshold, and
		// admitted a third execution against a target that had just failed twice (Codex round
		// 6 P1 — the same defect class as round 5, one shape further in).
		e.commitAttemptOutcome(in, attempt, sendState, out)
	}()

	// OVN-09 (residual window). callUpstream is the ONE place either branch performs
	// the irreversible side effect, so the last-moment drift re-check belongs here
	// rather than at each call site: a later branch added above this line inherits it.
	//
	// The runtime's entry check narrowed the decision/execution window; everything
	// between it and this line — the durable decision commit, credential planning,
	// provider material fetch — can block for as long as those take, and a
	// concurrent catalog ingest during that time would otherwise let the upstream
	// call run under a decision made about a tool that no longer exists or has been
	// redefined. Re-checking here makes the refusal precede the side effect.
	bf := &boundaryRefusal{}
	// decisionRef is the committed decision's EventID, captured from CommitThenAct's
	// receipt and required on the terminal outcome event.
	var decisionRef string
	callUpstream := func(authHeader string) error {
		// (1) Composition-layer LIVE side-effect gate — budget reservation, runtime live-trust
		// revalidation, read-first — runs BEFORE preCallGuard so the emergency-kill re-read
		// stays the LAST authoritative check before Upstream.Call (PREREQ-MCP-KILL-1). A denial
		// fails closed with the gate's bounded reason and Upstream.Call is never reached. On an
		// admit, Release runs after the upstream leg (deferred) so a reserved slot is never
		// leaked even if the freshness/kill guard below then aborts (§11). nil gate ⇒ unchanged.
		adm, admErr := e.admitSideEffect(in)
		if admErr != nil {
			bf.gateRefused, bf.gateReason = true, adm.reason
			return admErr
		}
		release, revalidate := adm.release, adm.revalidate
		reservationID, activationGen := adm.reservationID, adm.activationGen
		// THE HEALTH SAMPLE IS REPORTED BEFORE THE RESERVATION GOES BACK, IN ONE DEFER, AND THE
		// ORDER INSIDE IT IS THE POINT.
		//
		// Reporting the settle and releasing the slot are not independent bookkeeping. The settle
		// is what may latch elevated_error_rate, and the release is what lets the NEXT request
		// reserve. Split the other way round — release deferred here, settle deferred by the outer
		// runExecute — the release necessarily ran first, because an inner closure's defers run
		// when the closure returns. With MaxConcurrentExecutions of 1 that is not a theoretical
		// gap: the second failed call returns, its slot comes back, a waiting third request
		// reserves and crosses Upstream.Call, and only then does the second sample arrive and prove
		// the Canary should have stopped at 1-of-2. The threshold was reachable and still did not
		// prevent the next physical invocation (Codex round 7 P1).
		//
		// This is the round-3 latch-atomicity finding one level further out: there the latch was
		// not atomic with the OBSERVATION, here the observation was not ordered against the
		// RELEASE. Both are the same mistake — treating the pieces of one decision as separate
		// events — and both are fixed by making the sequence explicit rather than emergent.
		//
		// It is ONE defer with two statements rather than two defers relying on LIFO, because the
		// ordering is a security property and must be readable as one. release stays deferred so a
		// reserved slot is never leaked when a later boundary guard refuses (§11).
		defer func() {
			e.reportAttemptSettled(in, attempt, sendState, upstreamLegFailed(upResp, upErr))
			if release != nil {
				release()
			}
		}()
		// DURABLE SEND INTENT (§6) — committed AFTER the budget reservation (so it can
		// name the slot) and BEFORE the final boundary guards, because its purpose is
		// to survive a crash that happens after the peer receives bytes. Only a
		// side-effect-bearing method gets one: lifecycle/discovery traffic invokes no
		// tool and must never consume an execution reservation or inflate the
		// physical-effect count (§4).
		//
		// Failing to persist the intent means the send MUST NOT happen: an
		// unattributable physical invocation is precisely what this mechanism exists
		// to prevent, so this fails CLOSED.
		rec, ierr := e.openAttempt(in, attemptBinding{
			reservationID: reservationID,
			activationGen: activationGen,
			decisionRef:   decisionRef,
		})
		if ierr != nil {
			bf.gateRefused, bf.gateReason = true, mcperr.ReasonOf(ierr)
			return errLiveGateRefused
		}
		attempt = rec
		// (2) Last-moment boundary re-checks (tool drift, then the composition-layer live-generation
		// revalidation, then the emergency kill) run inside preCallGuard so nothing sits between them and
		// Upstream.Call. The kill re-read stays LAST (PREREQ-MCP-KILL-1). A demoted-generation refusal is
		// mapped to the gate-refusal classification path with a bounded rollout reason.
		if gerr := e.preCallGuard(in, admKillGen, revalidate); gerr != nil {
			// The physical call never began, so this is the ONE case where
			// definitely_not_sent is mechanically provable rather than inferred.
			sendState = model.SendDefinitelyNotSent
			cls := classifyBoundaryError(gerr)
			bf.stale, bf.killed = cls.stale, cls.killed
			if cls.demoted {
				bf.gateRefused, bf.gateReason = true, mcperr.ReasonRolloutModeInvalid
			}
			return gerr
		}
		// Once the call BEGINS, request bytes may already be on the wire. Assume the
		// conservative state up front so any panic, cancellation or transport fault
		// from here on is recorded as may_have_been_sent rather than silently
		// defaulting to "not sent" (§6). NOTHING blocking is introduced between the
		// final kill re-read above and this call.
		//
		// The two adjustments below only ever move this state on POSITIVE evidence,
		// one in each direction: proof the peer answered, or proof no bytes were ever
		// sent. Absent either, the conservative assumption stands.
		sendState = model.SendMayHaveBeenSent
		r, err := e.cfg.Upstream.Call(ctx, target, in.Method, json.RawMessage(in.RawParams), upstreamclient.CallOptions{
			Idempotent: idempotent, AuthHeader: authHeader, WireID: "u-" + target.ServerID,
			AttemptID: attemptIDOf(attempt),
		})
		if upstreamclient.SendNeverStarted(err) {
			// The call was refused before any request bytes existed — method not
			// admitted, an invalid target, pool admission refused, an endpoint that
			// would not canonicalize, a resolve failure, a request that would not
			// build. Recording may_have_been_sent there is conservative but FALSE, and
			// it costs twice: the outcome claims Executed for an invocation that never
			// happened, and the attempt is sent to witness reconciliation with nothing
			// to establish (Codex round 14).
			//
			// This is the only way definitely_not_sent becomes reachable from inside
			// the call, and the fact is absent by default: an unmarked error — from a
			// path nobody classified, or a test double — keeps the conservative state.
			sendState = model.SendDefinitelyNotSent
		}
		if r != nil || upstreamclient.ResponseObserved(err) {
			// The peer answered, so the invocation demonstrably reached it. This says
			// nothing about whether the response is USABLE — a non-200, an unreadable
			// body or undecodable bytes all land here with a nil response and an error —
			// and nothing about whether the response is later blocked by inspection.
			//
			// Inferring receipt from a successfully DECODED response alone was too
			// narrow: a peer that answers badly has still run the tool, and recording
			// that as may_have_been_sent sent a known-executed attempt to witness
			// reconciliation with nothing left to establish. This only ever moves
			// uncertainty DOWN a step that real evidence supports; it can never reach
			// definitely_not_sent, which is reachable only from POSITIVE evidence that
			// no request bytes ever existed — the boundary refusal above, or the
			// never-started fact the client marks on a leg that failed before
			// client.Do.
			sendState = model.SendPeerResponseReceived
		}
		upResp, upErr = r, err
		return err
	}

	// SEC-MCP-09. The DECISION event commits durably BEFORE anything that can have a
	// side effect, on BOTH paths and through the SAME primitive. Previously only the
	// no-credential branch went through CommitThenAct; the credential branch relied
	// solely on the broker's own CREDENTIAL_SELECT gate, so an executed
	// write/destructive tools/call with a credential profile — the ordinary
	// enterprise shape — left NO critical decision event on record naming the policy
	// action, matched rule, snapshot hash or action class. A commit failure now
	// blocks the side effect identically on both paths, and the broker's
	// pre-materialization gate still adds its own commit before any provider or
	// cache is touched (defense in depth, not a substitute).
	profileRef := in.Decision.Obligations.CredentialProfile
	if out, done := e.commitThenCall(ctx, in, profileRef, callUpstream, &decisionRef, bf); done {
		return out
	}
	return e.finishUpstreamLeg(ctx, in, upResp, upErr, res)
}

// finishUpstreamLeg maps the upstream leg's result to the terminal output.
//
// A nil response with a nil error is treated as a FAILURE, not a success: the
// guarded path has no meaning for "the call returned nothing", and reading it as
// success would let an unexecuted request report as executed.
func (e *Executor) finishUpstreamLeg(ctx context.Context, in runtime.ExecInput, upResp *upstreamclient.Response, upErr error, res rollout.Resolution) runtime.ExecOutput {
	if upErr != nil {
		e.cfg.Metrics.ObserveUpstream(in.Capability.String(), "error")
		return e.blocked(in, mcperr.ReasonOf(upErr), false)
	}
	if upResp == nil {
		return e.blocked(in, mcperr.ReasonUpstreamCallFailed, false)
	}
	e.cfg.Metrics.ObserveUpstream(in.Capability.String(), "success")
	return e.finishUpstream(ctx, in, upResp, res)
}

// preCallGuard runs the last-moment boundary re-validations immediately before the
// irreversible upstream side effect and returns the sentinel to abort with (mapped to a reason
// by the caller), or nil to proceed.
//
// Ordering is deliberate. Tool freshness is EVALUATED first because the ToolStillCurrent
// callback may itself observe or change authoritative state (in the boundary tests it engages
// the emergency kill), so its result is captured before the kill generation is read. But the
// emergency kill is PARAMOUNT in the refusal PRECEDENCE: if the monotonic kill generation has
// advanced past the value captured at admission, an emergency kill was engaged while this
// request was in flight (even one already cleared — the ABA case, and even when the tool ALSO
// drifted) and the refusal is reported as rollout_emergency_active rather than staleness — the
// operator's emergency stop is the reason the call did not happen, and metering it as staleness
// would undercount emergency blocks (§9 telemetry truth). Reading the generation AFTER invoking
// the freshness callback is also what closes the "callback engages the kill and returns drift"
// window Codex flagged on PR #1248. The kill re-read is the FINAL authoritative revalidation —
// it re-reads SOLELY the monotonic kill generation, so it does not re-resolve
// mode/scope/policy/approval and cannot reopen the F7 single-resolution TOCTOU, and only ever
// makes the outcome MORE restrictive. This is the ONE side-effect boundary shared by both the
// credential and no-credential paths, so the check lives here and nowhere else, and callUpstream
// places NOTHING between this guard and Upstream.Call.
func (e *Executor) preCallGuard(in runtime.ExecInput, admKillGen uint64, liveRevalidate func() bool) error {
	drifted := in.ToolStillCurrent != nil && !in.ToolStillCurrent()
	// The composition-layer live-generation revalidation is evaluated BEFORE the kill re-read (like the
	// freshness callback), so the kill generation stays the LAST authoritative state read before
	// Upstream.Call. It NEVER engages the kill, so evaluating it here cannot reopen the F7 TOCTOU. A
	// nil predicate (no gate, or Shadow) leaves this byte-identical to the pre-gate boundary.
	liveDemoted := liveRevalidate != nil && !liveRevalidate()
	if e.cfg.State.KillGeneration() != admKillGen {
		return errKilledAtBoundary // emergency stop is paramount, even if the tool also drifted or demoted
	}
	if drifted {
		return errToolDriftedBeforeCall
	}
	if liveDemoted {
		return errLiveGenerationDemotedAtBoundary // the reserved Canary generation was demoted mid-flight
	}
	return nil
}

// classifyBoundaryRefusal maps a boundary drift/kill refusal detected by callUpstream to its
// terminal block, or reports ok=false when neither fired. Kill is classified FIRST — an
// emergency stop is the paramount reason. killedAtCall and staleAtCall are mutually exclusive
// (preCallGuard returns on drift before the kill re-check), so the order only fixes which named
// reason each refusal carries; both read as a fail-closed refusal, never a transport/durability
// fault or ReasonNone. Shared by the no-credential (CommitThenAct-error) and credential
// (materializeAndCall-absorbed) branches so both reclassify identically.
func (e *Executor) classifyBoundaryRefusal(in runtime.ExecInput, killedAtCall, staleAtCall, gateRefused bool, gateReason mcperr.Reason) (runtime.ExecOutput, bool) {
	switch {
	case killedAtCall:
		return e.blocked(in, mcperr.ReasonRolloutEmergencyActive, false), true
	case staleAtCall:
		return e.blocked(in, mcperr.ReasonDecisionSnapshotStale, false), true
	case gateRefused:
		// The composition-layer gate denied the side effect (budget exhausted, live-trust
		// revoked/expired/drifted, or not read-first). Surface its bounded reason, never a
		// transport/durability fault or ReasonNone. The gate runs BEFORE the kill re-check, so a
		// gate refusal and a kill refusal are mutually exclusive by construction (kill wins only
		// if the gate admitted first) — the ordering here just fixes the named reason.
		r := gateReason
		if r == mcperr.ReasonNone {
			r = mcperr.ReasonRolloutModeInvalid // defensive: a gate must always name a reason
		}
		return e.blocked(in, r, false), true
	default:
		return runtime.ExecOutput{}, false
	}
}

// upstreamLegFailed is the health detector's failure predicate: did the UPSTREAM LEG fail?
//
// Three shapes, and all three are the TARGET failing rather than Culvert refusing:
//
//   - a transport or protocol error (err) — no answer, or an unusable one;
//   - a nil response with no error, a defensive impossibility treated as a failure because
//     "no answer and no reason" is not evidence of health;
//   - a decoded JSON-RPC error object — the peer answered and said the tool failed.
//
// It is deliberately NOT out.Executed. A response-DLP block AFTER a successful peer answer is
// Culvert's own policy working, not the target misbehaving, and counting it would let a healthy
// Canary abort itself for its own controls firing. The question this predicate answers is "is the
// target misbehaving", never "did the client get a result".
func upstreamLegFailed(resp *upstreamclient.Response, err error) bool {
	return err != nil || resp == nil || resp.Error != nil
}

// finishUpstream processes a successful upstream response: it forwards a sanitized
// JSON-RPC error, runs response DLP before egress (failing closed on any hard block
// OR a redact/block disposition the guarded path cannot transform), records the
// best-effort outcome event, and returns the executed result.
func (e *Executor) finishUpstream(ctx context.Context, in runtime.ExecInput, upResp *upstreamclient.Response, res rollout.Resolution) runtime.ExecOutput {
	if upResp.Error != nil {
		// A bounded, sanitized upstream JSON-RPC error is forwarded (never raw text).
		return runtime.ExecOutput{Status: 200, Disposition: dispReject, Reason: mcperr.ReasonUpstreamCallFailed,
			ResponseBody: upstreamErrorResult(in.MessageID), ExecutionState: "executed", Executed: true,
			EvaluatedAction: in.Decision.Action.String(), EffectiveAction: "execute"}
	}
	// Response DLP: inspect the FULL upstream result BEFORE returning it to the
	// client. A hard block (secret/PII/schema/oversize) refuses the content; a
	// non-hard redact/block disposition (e.g. the default profile classifies
	// financial data as DispRedact) also fails closed, since the guarded-execute path
	// performs no response redaction and must never forward untransformed content.
	ir := inspection.InspectResponse(ctx, e.cfg.ResponseProfile, inspection.ResponseInput{
		Tool: toolRef(in), Body: []byte(upResp.Result),
	}, in.Now)
	if ir.HardFail {
		e.cfg.Metrics.ObserveDLPBlock(in.Capability.String(), true)
		return e.blocked(in, ir.HardReason, false)
	}
	if !responseEgressAllowed(ir.Summary.Disposition) {
		e.cfg.Metrics.ObserveDLPBlock(in.Capability.String(), true)
		return e.blocked(in, mcperr.ReasonRedactionFailed, false)
	}

	// The terminal outcome event is emitted by runExecute's single deferred commit,
	// which covers EVERY exit path (success, upstream error, DLP block, boundary
	// refusal) rather than this one. Committing here too would double-record the
	// success path and still leave the others silent.
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

// responseEgressAllowed reports whether an inspection disposition permits returning
// the upstream result unchanged. Only pass/label are egress-safe; redact/block/unset
// require a transform the guarded path does not perform, so they fail closed.
func responseEgressAllowed(d inspection.Disposition) bool {
	return d == inspection.DispPass || d == inspection.DispLabel
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
		// A boundary refusal — tool drift, emergency kill, OR the composition-layer live-gate
		// (errToolDriftedBeforeCall / errKilledAtBoundary / errLiveGateRefused) — is reclassified
		// AND metered exactly once by the caller via classifyBoundaryRefusal. Building a blocked
		// output here would meter it a SECOND time — and, because all three sentinels are
		// package-private (ReasonOf == ReasonNone), that premature meter would land on the `none`
		// reason series, double-counting the refusal and contaminating reason/total-rate telemetry
		// (Codex P2, PR #1248 for drift/kill; PR #1290 for the live gate). Return the un-metered
		// signal and let the caller own the single classification+meter. errors.Is unwraps in case
		// the broker wraps the callback error.
		if errors.Is(mErr, errKilledAtBoundary) || errors.Is(mErr, errToolDriftedBeforeCall) || errors.Is(mErr, errLiveGateRefused) || errors.Is(mErr, errLiveGenerationDemotedAtBoundary) {
			return runtime.ExecOutput{}, true
		}
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
	f := events.DecisionFacts{
		Capability:  model.CapGateway,
		Criticality: crit,
		ActionClass: ac,
		Identity: model.IdentityEvidence{
			Tenant:      in.Input.Principal.Tenant,
			PrincipalID: in.Input.Principal.SubjectID,
			// SEC-MCP-08. Mirror the AUTHENTICATED subject kind. This was hard-coded
			// "workload" while the runtime models token subjects as humans, so every
			// execution event misattributed a human actor as a workload — an error no
			// downstream consumer of the archive can detect or correct.
			PrincipalType: subjectKindString(in.Input.Principal.Kind),
			ClientID:      in.Input.Client.ClientID,
		},
		Decision: model.DecisionEvidence{
			Action: in.Decision.Action.String(), ReasonCode: string(in.Decision.Reason),
			MatchedRuleID:  string(in.Decision.MatchedRule),
			PolicyRevision: uint64(in.Decision.PolicyRevision),
			OperationClass: in.Input.Operation.Class.String(),
			ExecutionState: "executing",

			PolicySnapshotHash: in.SnapshotHash,
		},
		SnapshotHash: in.SnapshotHash,
	}
	if in.Input.Server != nil {
		f.Identity.ServerID = in.Input.Server.ServerID
	}
	if in.Input.Tool != nil {
		f.Identity.ToolName = in.Input.Tool.Name
		f.Identity.ToolFingerprint = in.Input.Tool.FingerprintHash
	}
	return f
}

// subjectKindString maps the policy subject kind to the event-model principal type.
// The empty string for an unset kind is deliberate: an event must not invent a
// principal type it was never told.
func subjectKindString(k policy.SubjectKind) string {
	switch k {
	case policy.SubjectHuman:
		return "human"
	case policy.SubjectWorkload:
		return "workload"
	default:
		return ""
	}
}

// outcomeFacts builds the ordinary-criticality outcome fact emitted after a
// successful execution (best-effort; never blocks the response).
func outcomeFacts(in runtime.ExecInput) events.DecisionFacts {
	f := decisionFacts(in)
	// Criticality and ActionClass are ONE coupled pair, and model.Event.Validate
	// enforces it: an ordinary event carrying a critical action class is rejected
	// ("critical action class on an ordinary event"). They must therefore be set
	// together or not at all.
	//
	// A previous version of this function set only Criticality, leaving the write or
	// destructive ActionClass inherited from decisionFacts. Every mutating execution
	// then produced an outcome event that failed validation — and because the commit
	// below is best-effort, the failure was discarded and the evidence vanished
	// silently. That is strictly worse than the mislabelling it was meant to fix: an
	// outcome that says "read" is wrong, an outcome that does not exist is unknowable.
	//
	// The outcome stays ORDINARY: it is emitted after the side effect, so its
	// durability policy must not be able to drive the critical domain degraded for an
	// operation that already happened. The real classification is not lost — it rides
	// on Decision.OperationClass, which decisionFacts sets from the actual operation
	// class and which no downstream consumer has to infer from ActionClass.
	f.Criticality, f.ActionClass = model.CritOrdinary, model.ActionClassRead
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

// attemptBinding is the authorization identity a physical attempt must carry. It is
// a struct rather than three parameters so a future field cannot be silently dropped
// at one call site.
type attemptBinding struct {
	reservationID string
	activationGen uint64
	decisionRef   string
}

// openAttempt commits the DURABLE SEND INTENT for a side-effect-bearing invocation,
// or returns (nil, nil) when this method invokes no tool.
//
// It is committed AFTER the budget reservation (so it can name the slot) and BEFORE
// the final boundary guards, because its purpose is to survive a crash that happens
// after the peer receives bytes. Only a side-effect-bearing method gets one:
// lifecycle/discovery traffic invokes no tool and must never consume an execution
// reservation or inflate the physical-effect count (§4).
//
// Every failure here is FAIL-CLOSED — the caller must not send. An unattributable
// physical invocation is precisely what this mechanism exists to prevent.
func (e *Executor) openAttempt(in runtime.ExecInput, b attemptBinding) (*attemptRecord, error) {
	if !upstreamclient.ClassifyMethod(in.Method).SideEffectBearing() {
		return nil, nil
	}
	// METERED-EXECUTION IDENTITY GATE. A gate being wired at all means this is a
	// metered Canary execution, and such an execution MUST be attributable: an effect
	// with no reservation identity cannot be tied to the slot that paid for it, and
	// one with no activation generation cannot be recognized as an orphan of a
	// superseded generation after a restart. Either omission would silently degrade
	// the physical-effect ledger to the pre-#6/#8 state.
	//
	// Zero values remain legitimate ONLY for a nil gate (legacy/non-metered paths),
	// which never reaches this branch.
	if e.cfg.LiveGate != nil && (b.reservationID == "" || b.activationGen == 0) {
		return nil, mcperr.New(mcperr.ReasonEventEvidenceMissing, "execution.attempt",
			"metered execution without reservation identity")
	}
	// The decision ref must already exist: this runs INSIDE CommitThenAct's callback,
	// after the decision commit. A missing ref means the terminal outcome could never
	// be persisted, so it fails closed here rather than sending and losing the record.
	if b.decisionRef == "" {
		return nil, mcperr.New(mcperr.ReasonEventEvidenceMissing, "execution.attempt",
			"no committed decision to reference")
	}
	return e.commitSendIntent(in, b.reservationID, b.activationGen, b.decisionRef)
}

// executePreconditionFailure reports the block reason when the guarded path cannot
// run at all, and ok=true when every precondition holds.
//
// A nil Events seam fails closed because commit-before-side-effect is mandatory; an
// absent or unusable server record means there is no approved destination to reach;
// and a credential-required decision with no broker has no way to satisfy its own
// obligation. Every case is checked BEFORE any attempt accounting is armed, so a
// refusal here can never leave a half-formed physical-effect record.
func executePreconditionFailure(e *Executor, in runtime.ExecInput) (mcperr.Reason, bool) {
	switch {
	case e.cfg.Events == nil:
		return mcperr.ReasonEventDurabilityDegraded, false
	case in.Server == nil, !in.Server.Usable():
		return mcperr.ReasonUpstreamServerUnusable, false
	case in.Decision.Obligations.CredentialProfile != "" && e.cfg.Broker == nil:
		// A credential is REQUIRED (the decision carries a CredentialProfile
		// obligation) but no broker is composed to plan/materialize it. Fail CLOSED:
		// reaching the upstream with an empty Authorization header would let a
		// credential-required operation hit an upstream that accepts ambient or
		// unauthenticated access, bypassing the required credential planning (Codex P2
		// round-6, PR #1290). The nil-broker composition is valid ONLY for tools that
		// need no credential.
		return mcperr.ReasonCredentialProfileMissing, false
	}
	return mcperr.ReasonNone, true
}

// boundaryRefusal names which final guard refused, so the caller can map it to a
// bounded reason without repeating the errors.Is chain.
type boundaryRefusal struct {
	stale   bool
	killed  bool
	demoted bool
	// gateRefused/gateReason carry a composition-layer gate denial, which reaches the
	// same classification path as a boundary guard refusal but names its own reason.
	gateRefused bool
	gateReason  mcperr.Reason
}

// classifyBoundaryError decodes a preCallGuard refusal. The three causes are
// mutually exclusive by construction (preCallGuard returns on the first), so this
// only fixes which named reason each refusal carries.
func classifyBoundaryError(err error) boundaryRefusal {
	return boundaryRefusal{
		stale:   errors.Is(err, errToolDriftedBeforeCall),
		killed:  errors.Is(err, errKilledAtBoundary),
		demoted: errors.Is(err, errLiveGenerationDemotedAtBoundary),
	}
}

// commitThenCall performs the durable decision commit and the guarded upstream leg,
// returning (out, true) when the request is terminal here and (zero, false) when the
// caller should go on to map the upstream result.
//
// SEC-MCP-09. The DECISION event commits durably BEFORE anything that can have a
// side effect, on BOTH paths and through the SAME primitive. Previously only the
// no-credential branch went through CommitThenAct; the credential branch relied
// solely on the broker's own CREDENTIAL_SELECT gate, so an executed
// write/destructive tools/call with a credential profile — the ordinary enterprise
// shape — left NO critical decision event on record naming the policy action,
// matched rule, snapshot hash or action class. A commit failure blocks the side
// effect identically on both paths, and the broker's pre-materialization gate still
// adds its own commit before any provider or cache is touched (defense in depth, not
// a substitute).
func (e *Executor) commitThenCall(ctx context.Context, in runtime.ExecInput, profileRef string,
	callUpstream func(string) error, decisionRef *string, bf *boundaryRefusal,
) (runtime.ExecOutput, bool) {
	useBroker := e.cfg.Broker != nil && profileRef != ""
	var blockedOut runtime.ExecOutput
	var didBlock bool
	err := e.cfg.Events.CommitThenAct(decisionFacts(in), func(rcpt spool.CommitReceipt) error {
		*decisionRef = rcpt.EventID()
		if !useBroker {
			return callUpstream("")
		}
		blockedOut, didBlock = e.materializeAndCall(ctx, in, profileRef, callUpstream)
		return nil
	})
	if err != nil {
		// A boundary drift/kill/gate refusal outranks the generic error mapping and
		// must read as its own reason, never as a transport/durability fault. This
		// branch carries the NO-credential path, whose callUpstream error escapes
		// CommitThenAct verbatim.
		if out, ok := e.classifyBoundaryRefusal(in, bf.killed, bf.stale, bf.gateRefused, bf.gateReason); ok {
			return out, true
		}
		return e.blocked(in, mcperr.ReasonOf(err), false), true
	}
	if didBlock {
		// The CREDENTIAL path never lets callUpstream's error escape CommitThenAct:
		// materializeAndCall swallows it into a blocked ExecOutput whose reason is
		// ReasonOf(errToolDriftedBeforeCall)/ReasonOf(errKilledAtBoundary) ==
		// ReasonNone (both sentinels are package-private and unregistered). A drift or
		// emergency-kill refusal detected inside the broker callback must therefore be
		// reclassified HERE too, or clients and block telemetry would read `none` where
		// the no-credential path reads the correct reason.
		if out, ok := e.classifyBoundaryRefusal(in, bf.killed, bf.stale, bf.gateRefused, bf.gateReason); ok {
			return out, true
		}
		return blockedOut, true
	}
	return runtime.ExecOutput{}, false
}

// sideEffectAdmission is the composition-layer gate's grant: what to release, how to
// revalidate at the boundary, and the identity the physical effect is charged to.
type sideEffectAdmission struct {
	release       func()
	revalidate    func() bool
	reservationID string
	activationGen uint64
	reason        mcperr.Reason
}

// admitSideEffect runs the composition-layer LIVE side-effect gate — budget
// reservation, runtime live-trust revalidation, read-first.
//
// It runs BEFORE preCallGuard so the emergency-kill re-read stays the LAST
// authoritative check before Upstream.Call (PREREQ-MCP-KILL-1). A denial fails
// closed with the gate's bounded reason and Upstream.Call is never reached. On an
// admit the caller defers Release after the upstream leg, so a reserved slot is
// never leaked even if the freshness/kill guard then aborts (§11). A nil gate leaves
// this byte-identical to the pre-gate boundary.
func (e *Executor) admitSideEffect(in runtime.ExecInput) (sideEffectAdmission, error) {
	if e.cfg.LiveGate == nil {
		return sideEffectAdmission{}, nil
	}
	// AUXILIARY TRAFFIC IS NOT ADMITTED, because it has nothing to admit. Lifecycle
	// and discovery methods invoke no tool, so §4's contract — stated on openAttempt
	// and previously enforced only there — is that they must never consume an
	// execution reservation or inflate the physical-effect count. Running the gate
	// for them contradicted that contract in both directions: the production gate
	// validates tool trust against an empty tool binding and REFUSES, so an armed
	// Canary node could not complete a session handshake or list tools; a gate that
	// admitted instead would permanently spend a Canary slot on a call that can cause
	// no side effect, and MaxTotalExecutions would stop measuring physical
	// invocations — the accounting blocker #6 exists to make true.
	//
	// The classifier is the SAME fail-closed one openAttempt uses, and its default is
	// side-effect-bearing: exemption is granted only to classes positively known to
	// invoke no tool, so an unclassified method is metered, never exempted. Skipping
	// the gate does not weaken the boundary — preCallGuard's tool-freshness check and
	// the FINAL emergency-kill re-read read authoritative state directly
	// (e.cfg.State.KillGeneration() against the admission generation passed in by the
	// runtime), not through the gate, so they still run for every method.
	if !upstreamclient.ClassifyMethod(in.Method).SideEffectBearing() {
		return sideEffectAdmission{}, nil
	}
	d := e.cfg.LiveGate.AdmitSideEffect(e.liveGateInput(in))
	if !d.Admit {
		return sideEffectAdmission{reason: d.Reason}, errLiveGateRefused
	}
	return sideEffectAdmission{
		release:       d.Release,
		revalidate:    d.Revalidate,
		reservationID: d.ReservationID,
		activationGen: d.ActivationGeneration,
	}, nil
}
