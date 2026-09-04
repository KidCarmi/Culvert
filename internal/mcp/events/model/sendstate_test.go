package model

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// TestPhysicalSendState_ConservativePredicates pins the direction of uncertainty
// (§6/§10): only the two states that positively prove the peer did not act may
// answer false to MayHaveReachedPeer. Everything else — including the unset zero
// value — must be treated as possibly-effective.
func TestPhysicalSendState_ConservativePredicates(t *testing.T) {
	mayReach := map[PhysicalSendState]bool{
		SendStateUnset:            true, // unknown is never a non-event
		SendMayHaveBeenSent:       true,
		SendPeerResponseReceived:  true,
		SendReconciledReceived:    true,
		SendDefinitelyNotSent:     false,
		SendReconciledNotReceived: false,
	}
	for s, want := range mayReach {
		if got := s.MayHaveReachedPeer(); got != want {
			t.Errorf("%q.MayHaveReachedPeer() = %v, want %v", s, got, want)
		}
	}

	needsRecon := map[PhysicalSendState]bool{
		SendStateUnset:            true,
		SendMayHaveBeenSent:       true,
		SendPeerResponseReceived:  false,
		SendReconciledReceived:    false,
		SendReconciledNotReceived: false,
		SendDefinitelyNotSent:     false,
	}
	for s, want := range needsRecon {
		if got := s.ReconciliationRequired(); got != want {
			t.Errorf("%q.ReconciliationRequired() = %v, want %v", s, got, want)
		}
	}
}

// TestPhysicalSendState_UnsetIsInvalidOnACommittedOutcome pins that the zero value
// is not an acceptable committed state — a terminal record must say something.
func TestPhysicalSendState_UnsetIsInvalidOnACommittedOutcome(t *testing.T) {
	if SendStateUnset.Valid() {
		t.Fatal("the unset zero value must not be a valid committed send state")
	}
	for _, s := range []PhysicalSendState{
		SendDefinitelyNotSent, SendMayHaveBeenSent, SendPeerResponseReceived,
		SendReconciledReceived, SendReconciledNotReceived,
	} {
		if !s.Valid() {
			t.Errorf("%q must be a valid state", s)
		}
	}
	if PhysicalSendState("made_up").Valid() {
		t.Fatal("an unrecognized state string must not be valid")
	}
}

// --- PhaseReconciliation structural gates -----------------------------------
//
// Reconciliation evidence is the one part of this ledger whose strings originate
// OUTSIDE the process: an independent witness supplies the source name, the
// completeness watermark and the evidence digest. These gates pin that the
// evidence cannot ride on the wrong phase and cannot grow a durable record
// without bound. Each negative gate is paired with a positive control on the same
// fixture so a change that made the fixture invalid for an unrelated reason could
// not leave the gate silently passing.

// baseReconciliation returns a minimal VALID reconciliation event.
func baseReconciliation() Event {
	e := baseDecision()
	e.Phase = PhaseReconciliation
	e.Reconciliation = &ReconciliationEvidence{
		AttemptID:            "att_0001",
		Result:               ReconRequired,
		ReconciledAtUnixNano: 2,
	}
	return e
}

// TestReconciliationEvent_ControlValid is the positive control for every gate
// below: this exact fixture, uncorrupted, must validate.
func TestReconciliationEvent_ControlValid(t *testing.T) {
	if err := baseReconciliation().Validate(); err != nil {
		t.Fatalf("valid reconciliation event rejected: %v", err)
	}
}

// TestReconciliation_RejectedOnNonReconciliationPhase pins that witness evidence
// cannot be attached to an event the reconciliation state machine never inspects.
func TestReconciliation_RejectedOnNonReconciliationPhase(t *testing.T) {
	e := baseDecision()
	e.Reconciliation = &ReconciliationEvidence{AttemptID: "att_0001", Result: ReconReceived}
	mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
}

// TestReconciliation_RejectsUnknownResult pins that an unrecognized result fails
// closed rather than being persisted as an opaque string a reader must guess at.
func TestReconciliation_RejectsUnknownResult(t *testing.T) {
	e := baseReconciliation()
	e.Reconciliation.Result = ReconciliationResult("received_probably")
	mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
}

// TestReconciliation_RejectsMissingAttemptIdentity pins that evidence which cannot
// name its attempt is not evidence.
func TestReconciliation_RejectsMissingAttemptIdentity(t *testing.T) {
	e := baseReconciliation()
	e.Reconciliation.AttemptID = ""
	mustReason(t, e.Validate(), mcperr.ReasonEventEvidenceMissing)
}

// TestReconciliation_RejectsOutcomeEvidence pins that a reconciliation event cannot
// smuggle a terminal outcome: reconciliation records knowledge, and a terminal
// outcome is the thing whose ABSENCE defines an orphan.
func TestReconciliation_RejectsOutcomeEvidence(t *testing.T) {
	e := baseReconciliation()
	e.Outcome = &OutcomeEvidence{AttemptID: "att_0001", Executed: true}
	mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
}

// TestReconciliation_BoundsWitnessSuppliedStrings pins the structural bound on
// every externally-supplied field. Unbounded witness input is the one way an
// outside party could grow a durable ledger record without limit.
func TestReconciliation_BoundsWitnessSuppliedStrings(t *testing.T) {
	over := string(make([]byte, maxFieldBytes+1))
	for _, tc := range []struct {
		name string
		set  func(*ReconciliationEvidence)
	}{
		{"witness_source", func(r *ReconciliationEvidence) { r.WitnessSource = over }},
		{"completeness_watermark", func(r *ReconciliationEvidence) { r.CompletenessWatermark = over }},
		{"evidence_digest", func(r *ReconciliationEvidence) { r.EvidenceDigest = over }},
		{"reservation_id", func(r *ReconciliationEvidence) { r.ReservationID = over }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := baseReconciliation()
			tc.set(e.Reconciliation)
			mustReason(t, e.Validate(), mcperr.ReasonEventTooLarge)
		})
	}
}

// TestOutcome_BoundsAttemptIdentityStrings pins the same bound on the attempt
// identity carried by send-intent and outcome events.
func TestOutcome_BoundsAttemptIdentityStrings(t *testing.T) {
	over := string(make([]byte, maxFieldBytes+1))
	e := baseDecision()
	e.Phase = PhaseSendIntent
	e.Outcome = &OutcomeEvidence{AttemptID: "att_0001", ReservationID: over}
	mustReason(t, e.Validate(), mcperr.ReasonEventTooLarge)
}
