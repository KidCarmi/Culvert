package execution

// attempt_evidence.go — durable send intent and terminal outcome truth for one
// physical tool invocation (First Controlled Canary review §6, §8, §9, §10).

import (
	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// attemptRecord is the in-memory handle to a committed durable send intent. Its
// fields are the immutable snapshot the terminal outcome and any later
// reconciliation must agree on.
type attemptRecord struct {
	id            string
	reservationID string
	generation    uint64
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
func (e *Executor) commitSendIntent(in runtime.ExecInput, reservationID string, activationGen uint64) (*attemptRecord, error) {
	id, err := newAttemptID()
	if err != nil {
		return nil, err
	}
	rec := &attemptRecord{
		id:            id,
		reservationID: reservationID,
		generation:    activationGen,
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
	f.Outcome = &model.OutcomeEvidence{
		AttemptID:            rec.id,
		ReservationID:        rec.reservationID,
		ActivationGeneration: rec.generation,
		PhysicalSendState:    state,
		// Executed reports Culvert's control flow; PhysicalSendState reports what the
		// PEER may have seen. They are recorded side by side precisely because they
		// can legitimately disagree: a response blocked by DLP is
		// peer_response_received with end-to-end failure.
		Executed:      state.MayHaveReachedPeer(),
		StatusClass:   out.ExecutionState,
		FailureReason: out.Reason.String(),
	}
	if _, cerr := e.cfg.Events.CommitDecision(f); cerr != nil {
		e.cfg.Metrics.ObserveOutcomeEvidenceLoss(in.Capability.String())
	}
}
