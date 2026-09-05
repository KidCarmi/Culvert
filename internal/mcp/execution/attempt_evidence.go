package execution

// attempt_evidence.go — durable send intent and terminal outcome truth for one
// physical tool invocation (First Controlled Canary review §6, §8, §9, §10).

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// attemptRecord is the in-memory handle to a committed durable send intent. Its
// fields are the immutable snapshot the terminal outcome and any later
// reconciliation must agree on.
type attemptRecord struct {
	id            string
	reservationID string
	generation    uint64
	// decisionRef is the EventID of the committed decision this attempt belongs to.
	// model.Event.Validate REQUIRES a terminal outcome to reference one, so an
	// attempt that does not carry it produces an outcome that cannot be persisted —
	// and because the outcome commit is best-effort, the loss would be silent.
	decisionRef string
	// startedAt is the instant the durable send intent was committed — i.e. the moment this
	// attempt became a physical possibility. The settle-time delta is the attempt latency the
	// First-Canary latency detector judges. It deliberately spans the intent commit rather than
	// only Upstream.Call, because the question the detector answers is "how long is this
	// experiment taking to do one thing", not "how fast is the peer's socket".
	startedAt time.Time
}

// attemptIDOf returns the attempt identity to put on the wire, or "" when this
// invocation is not side-effect-bearing (lifecycle/discovery) and therefore has no
// attempt. Nil-safe so call sites stay free of branching.
func attemptIDOf(a *attemptRecord) string {
	if a == nil {
		return ""
	}
	return a.id
}

// commitSendIntent mints an attempt identity and DURABLY commits the send intent
// before the irreversible upstream call.
//
// It fails CLOSED. If the identity cannot be minted or the intent cannot be
// persisted, the caller must not send: a physical invocation with no durable record
// is unattributable, and after a crash it would be indistinguishable from an
// invocation that never happened.
func (e *Executor) commitSendIntent(in runtime.ExecInput, reservationID string, activationGen uint64, decisionRef string) (*attemptRecord, error) {
	id, err := newAttemptID()
	if err != nil {
		return nil, err
	}
	rec := &attemptRecord{
		id:            id,
		reservationID: reservationID,
		generation:    activationGen,
		decisionRef:   decisionRef,
		startedAt:     e.cfg.Clock(),
	}
	f := decisionFacts(in)
	f.Criticality, f.ActionClass = model.CritOrdinary, model.ActionClassRead
	f.Phase = model.PhaseSendIntent
	f.Outcome = &model.OutcomeEvidence{
		AttemptID:            rec.id,
		ReservationID:        rec.reservationID,
		ActivationGeneration: rec.generation,
		// PhysicalSendState is deliberately left UNSET. An intent with no terminal
		// outcome means "in flight or interrupted", which is exactly
		// ReconciliationRequired() — never "not sent".
	}
	if _, cerr := e.cfg.Events.CommitDecision(f); cerr != nil {
		return nil, mcperr.New(mcperr.ReasonEventDurabilityDegraded, "execution.attempt",
			"send intent not durable")
	}
	return rec, nil
}

// commitAttemptOutcome writes the ONE terminal outcome for a committed attempt,
// on every exit path.
//
// Loss of this record is NOT silent: a physical invocation whose fate is unknown is
// the `outcome_evidence_loss` condition, and the metric is the authoritative signal
// the (separately-scoped) whole-Canary abort wiring consumes. This function
// deliberately does not stop the Canary itself — that is blocker #7's job, and a
// second abort path here would be a parallel framework.
func (e *Executor) commitAttemptOutcome(in runtime.ExecInput, rec *attemptRecord, state model.PhysicalSendState, out runtime.ExecOutput) {
	f := outcomeFacts(in)
	f.Phase = model.PhaseOutcome
	// outcomeFacts stamps Decision.ExecutionState = "executed" for the success path.
	// A boundary refusal (freshness, generation, kill) is definitely_not_sent and its
	// ExecutionState is "blocked", so taking the stamp unconditionally persisted an
	// internally contradictory record — and the admin decision search READS that
	// field, so never-sent attempts would be reported and filtered as executions
	// (Codex round 1, P2). The terminal disposition is the authority here.
	if out.ExecutionState != "" {
		f.Decision.ExecutionState = out.ExecutionState
	}
	f.Outcome = &model.OutcomeEvidence{
		AttemptID:            rec.id,
		ReservationID:        rec.reservationID,
		ActivationGeneration: rec.generation,
		PhysicalSendState:    state,
		// REQUIRED by model.Event.Validate for a PhaseOutcome event. Omitting it made
		// every terminal outcome fail validation, and since this commit is
		// best-effort the record simply vanished — leaving every completed execution
		// indistinguishable from a crashed one on restart (caught by the controlled
		// HTTPS E2E, which reads the real spool rather than a test sink).
		DecisionRef: rec.decisionRef,
		// Executed answers "may a physical effect have happened?" — NOT "did Culvert
		// return a result?". That is the whole reason it is derived from the send
		// state and not from out.Executed, and the two disagree on every interesting
		// path: an ambiguous transport failure and a DLP block after the peer answered
		// are both out.Executed==false, and in both the tool HAS run.
		//
		// Deriving it from the terminal disposition instead was proposed and REJECTED
		// (Codex round 2, P2). It reads better locally — Executed=true beside
		// ExecutionState "blocked" looks contradictory — but it is the laundering this
		// whole change exists to prevent: it writes executed=false into the durable
		// record for invocations that demonstrably reached the peer, which is exactly
		// "uncertainty converted into executed=false". The apparent contradiction is
		// the design: Decision.ExecutionState is CULVERT's disposition (what the client
		// got), Outcome.Executed and PhysicalSendState are the PEER's reality. A
		// consumer that needs Culvert's disposition reads StatusClass, right below.
		// Pinned by TestOutcomeTruth_* and mutation M28.
		Executed:      state.MayHaveReachedPeer(),
		StatusClass:   out.ExecutionState,
		FailureReason: out.Reason.String(),
	}
	if _, cerr := e.cfg.Events.CommitDecision(f); cerr != nil {
		// A physical invocation may have happened and its terminal outcome is NOT durable: the
		// Canary can no longer reconstruct what it did to the world. That is a whole-Canary
		// breach, not a statistic. The metric stays for observability, but the SAFETY path is the
		// breach seam — before blocker #7 this condition incremented a counter whose production
		// implementation was an empty method body, so evidence loss stopped nothing at all.
		e.cfg.Metrics.ObserveOutcomeEvidenceLoss(in.Capability.String())
		e.cfg.Safety.Breach(in.Capability.String(), rec.generation, "outcome_evidence_loss")
	}
}

// reportAttemptSettled reports ONE settled post-admission attempt to the population detectors.
//
// IT IS CALLED FROM THE UPSTREAM LEG, BEFORE THE RESERVATION IS RELEASED AND BEFORE THE TERMINAL
// OUTCOME IS COMMITTED. Both orderings are security properties, and each was learned from a
// separate defect:
//
//   - BEFORE THE RELEASE (Codex round 7). The settle is what may latch elevated_error_rate; the
//     release is what admits the next request. Released first, a third request could reserve and
//     cross Upstream.Call before the second failure was even counted, so a reachable threshold
//     still failed to prevent the next physical invocation.
//   - BEFORE THE TERMINAL OUTCOME (Codex round 3). A crash between the two writes must over-count
//     an outcome record rather than erase failure evidence: restore legitimately accepts fewer
//     samples than reservations, so a missing sample is indistinguishable from an attempt that
//     never settled, while a missing OUTCOME is already the outcome_evidence_loss breach. Evidence
//     that survives one write too many is recoverable; evidence a crash erased is not.
//
// THE SAMPLE SET IS "INVOCATIONS ACTUALLY ATTEMPTED", and both exclusions matter:
//
//   - a request-scoped denial (policy, scope, allowance) never mints an attempt record and so
//     never reaches this function at all — a Canary must not abort itself for correctly refusing
//     requests;
//   - definitely_not_sent means a boundary guard refused AFTER the intent commit — an emergency
//     kill, a tool drift, a demotion. Nothing was sent, so there is no execution to judge.
//     Counting those would make an operator's own kill switch look like an error rate and latch
//     elevated_error_rate for the stop working exactly as designed.
//
// TWO further exclusions live here rather than in the caller: a CALLER CANCELLATION is not evidence
// about the target in either direction (see callerCancelled), and an error that carries its own
// whole-Canary classification is judged directly rather than through a rate (see
// upstreamBreachCode).
//
// The verdict is the UPSTREAM LEG's (see upstreamLegFailed), never Culvert's disposition: a
// response-DLP block after a successful peer answer is this gateway's policy working rather than
// the target being unhealthy.
func (e *Executor) reportAttemptSettled(in runtime.ExecInput, rec *attemptRecord, state model.PhysicalSendState, resp *upstreamclient.Response, err error) {
	if rec == nil || state == model.SendStateUnset || state == model.SendDefinitelyNotSent {
		return
	}
	if callerCancelled(err) {
		return
	}
	// A condition that carries its OWN immediate whole-Canary classification has already stopped
	// the experiment on its own terms, and must not also arrive through a rate — HealthMonitor's
	// contract says so in as many words. Counting it would report an identity breach as an ordinary
	// target failure on the persisted counters and the operator surface, and would let one event
	// contribute to two different stop decisions (Codex round 13).
	if upstreamBreachCode(err) != "" {
		return
	}
	e.cfg.Safety.AttemptSettled(in.Capability.String(), rec.generation, upstreamLegFailed(resp, err), e.cfg.Clock().Sub(rec.startedAt))
}
