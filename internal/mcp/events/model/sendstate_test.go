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
	// Attempt evidence is a v3 shape: an event carrying it under a v1 stamp is
	// unreadable to a build that predates the fields, so the pairing is enforced.
	e.SchemaVersion = SchemaVersionV3
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

// --- verdict-vs-facts gates (Codex round 6, P2) ------------------------------
//
// Until these existed the validator checked only enum membership, so a record
// claiming a RESOLVED verdict while reporting facts that cannot support it was
// durably committable — and recovery trusts the stored result rather than
// re-deriving it, so contradictory or incomplete witness data became definitive
// knowledge. Each negative gate is paired with a positive control on the same
// fixture.

// resolvedReconciliation returns a VALID record for one resolved verdict, so each
// gate below can corrupt exactly one field.
func resolvedReconciliation(res ReconciliationResult, count int) Event {
	e := baseReconciliation()
	e.Reconciliation.Result = res
	e.Reconciliation.ObservationCount = count
	e.Reconciliation.CompletenessWatermark = "wm-4711"
	return e
}

// TestReconciliation_ResolvedVerdictsAreValidWithTheirFacts is the CONTROL for
// every gate below. Without it they would all pass on a validator that had simply
// stopped accepting resolved verdicts at all.
func TestReconciliation_ResolvedVerdictsAreValidWithTheirFacts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		res   ReconciliationResult
		count int
	}{
		{"definitive absence", ReconNotReceived, 0},
		{"exactly one receipt", ReconReceived, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := resolvedReconciliation(tc.res, tc.count).Validate(); err != nil {
				t.Fatalf("control: a well-supported %q must validate: %v", tc.res, err)
			}
		})
	}
}

// TestReconciliation_ResolvedVerdictNeedsACompletenessProof pins the half that
// matters most: absence and "exactly one" are both claims about the WHOLE
// population, so neither can rest on a view the witness never proved complete.
func TestReconciliation_ResolvedVerdictNeedsACompletenessProof(t *testing.T) {
	for _, tc := range []struct {
		res   ReconciliationResult
		count int
	}{
		{ReconNotReceived, 0},
		{ReconReceived, 1},
	} {
		t.Run(string(tc.res), func(t *testing.T) {
			e := resolvedReconciliation(tc.res, tc.count)
			e.Reconciliation.CompletenessWatermark = ""
			mustReason(t, e.Validate(), mcperr.ReasonEventEvidenceMissing)
		})
	}
}

// TestReconciliation_ResolvedVerdictMustMatchItsCount pins the other half: the
// verdict names a count, so a record whose own count contradicts it is asserting
// knowledge its evidence denies.
func TestReconciliation_ResolvedVerdictMustMatchItsCount(t *testing.T) {
	for _, tc := range []struct {
		name  string
		res   ReconciliationResult
		count int
	}{
		{"absence with an observation", ReconNotReceived, 1},
		{"receipt with no observation", ReconReceived, 0},
		{"receipt with a duplicate", ReconReceived, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustReason(t, resolvedReconciliation(tc.res, tc.count).Validate(), mcperr.ReasonEventInvalid)
		})
	}
}

// TestReconciliation_RejectsANegativeObservationCount pins that a negative count is
// malformed input for EVERY verdict, including the unconstrained ones — it is not an
// observation, and left to fall through it reads as zero.
func TestReconciliation_RejectsANegativeObservationCount(t *testing.T) {
	for _, res := range []ReconciliationResult{ReconRequired, ReconConflict, ReconNotReceived, ReconReceived} {
		t.Run(string(res), func(t *testing.T) {
			e := resolvedReconciliation(res, -1)
			mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
		})
	}
}

// TestReconciliation_ConflictIsDeliberatelyUnconstrained pins a decision rather than
// an oversight. A conflict is reachable from a duplicate (count > 1) AND from a
// single observation whose binding contradicts the intent, and the observed binding
// is not carried on this record — so a count rule would reject a truthful conflict.
// Refusing to record a breach is a worse failure than recording one whose count
// looks unusual, so the alarm direction stays permissive.
func TestReconciliation_ConflictIsDeliberatelyUnconstrained(t *testing.T) {
	for _, count := range []int{0, 1, 2, 9} {
		e := resolvedReconciliation(ReconConflict, count)
		e.Reconciliation.CompletenessWatermark = ""
		if err := e.Validate(); err != nil {
			t.Fatalf("a conflict reporting count=%d must still be recordable: %v", count, err)
		}
	}
}

// TestReconciliation_TheFailClosedRecordIsCommittable is the durable half of round-8
// P2, paired with the producer-side gate in internal/mcp/execution.
//
// deriveReconResult answers ReconRequired for a malformed (negative) witness count.
// If the validator then rejects the record that answer produces, the documented
// fail-closed outcome cannot reach the append-only ledger at all — a rule that makes
// its own correct answer unrecordable. This pins that the record the producer now
// emits is committable, and that the negative count itself is still refused.
func TestReconciliation_TheFailClosedRecordIsCommittable(t *testing.T) {
	e := baseReconciliation()
	e.Reconciliation.Result = ReconRequired
	e.Reconciliation.WitnessSource = "controlled-recorder"
	e.Reconciliation.ObservationCount = 0 // the producer omits a malformed count
	if err := e.Validate(); err != nil {
		t.Fatalf("the fail-closed record must be committable: %v", err)
	}

	// CONTROL: the count itself is still refused, so this does not simply relax the
	// rule — it proves the producer must not emit one.
	e.Reconciliation.ObservationCount = -3
	mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
}

// TestPhysicalSendState_ProvesReceiptIsNotTheNegationOfMayHaveReachedPeer pins the
// distinction round-8 P1 turned on. The two predicates leave a deliberate MIDDLE
// GROUND — states that are neither proven-received nor proven-not-received — and
// may_have_been_sent is the whole reason reconciliation exists. A change that made
// one the negation of the other would collapse that middle ground and silently
// re-break the unanswered-POST case.
func TestPhysicalSendState_ProvesReceiptIsNotTheNegationOfMayHaveReachedPeer(t *testing.T) {
	for _, tc := range []struct {
		state          PhysicalSendState
		provesReceipt  bool
		mayHaveReached bool
	}{
		{SendPeerResponseReceived, true, true},
		{SendReconciledReceived, true, true},
		{SendMayHaveBeenSent, false, true}, // the middle ground
		{SendStateUnset, false, true},      // also the middle ground
		{SendDefinitelyNotSent, false, false},
		{SendReconciledNotReceived, false, false},
	} {
		if got := tc.state.ProvesReceipt(); got != tc.provesReceipt {
			t.Fatalf("%q ProvesReceipt = %v, want %v", tc.state, got, tc.provesReceipt)
		}
		if got := tc.state.MayHaveReachedPeer(); got != tc.mayHaveReached {
			t.Fatalf("%q MayHaveReachedPeer = %v, want %v", tc.state, got, tc.mayHaveReached)
		}
	}
	// The structural claim: at least one state is neither, so the predicates cannot be
	// collapsed into one.
	middle := 0
	for _, s := range []PhysicalSendState{
		SendStateUnset, SendDefinitelyNotSent, SendMayHaveBeenSent,
		SendPeerResponseReceived, SendReconciledReceived, SendReconciledNotReceived,
	} {
		if !s.ProvesReceipt() && s.MayHaveReachedPeer() {
			middle++
		}
	}
	if middle == 0 {
		t.Fatal("the predicates collapsed: no state is neither proven-received nor proven-not-received")
	}
}

// TestReconciliation_ADuplicateMustSayConflict pins round 9. Observing more than one
// matching invocation is a definitive exactly-once breach at ANY completeness, so a
// record reporting count > 1 must SAY conflict.
//
// Leaving reconciliation_required unconstrained let such a record be committed as
// "asserts nothing", and recovery trusts Result — settledReconOK's switch ignores
// reconciliation_required entirely — so the attempt was reported cleanly settled
// while its own facts recorded the duplicate physical effect this mechanism exists to
// detect.
func TestReconciliation_ADuplicateMustSayConflict(t *testing.T) {
	for _, res := range []ReconciliationResult{ReconRequired, ReconReceived, ReconNotReceived} {
		t.Run(string(res), func(t *testing.T) {
			e := baseReconciliation()
			e.Reconciliation.Result = res
			e.Reconciliation.ObservationCount = 2
			e.Reconciliation.CompletenessWatermark = "wm-1"
			mustReason(t, e.Validate(), mcperr.ReasonEventInvalid)
		})
	}

	// CONTROL: the conflict direction is NOT re-constrained. It stays reachable at any
	// count, because a conflict also arises from a single observation whose binding
	// contradicts the intent — and refusing to record a breach is the worst failure
	// available here.
	for _, count := range []int{0, 1, 2, 9} {
		e := baseReconciliation()
		e.Reconciliation.Result = ReconConflict
		e.Reconciliation.ObservationCount = count
		if err := e.Validate(); err != nil {
			t.Fatalf("a conflict reporting count=%d must still be recordable: %v", count, err)
		}
	}
}
