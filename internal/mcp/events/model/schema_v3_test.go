package model

import (
	"strings"
	"testing"
)

// baseAttemptOutcome returns a minimal VALID v3 attempt-outcome event.
func baseAttemptOutcome() Event {
	e := baseDecision()
	e.SchemaVersion = SchemaVersionV3
	e.Phase = PhaseOutcome
	e.Outcome = &OutcomeEvidence{
		DecisionRef: "evt_dec1", Executed: true,
		AttemptID: "att_0001", ReservationID: "res_0001", ActivationGeneration: 2,
		PhysicalSendState: SendPeerResponseReceived,
	}
	return e
}

// TestSchemaV3_ControlAttemptOutcomeIsValid is the positive control for every gate
// below: this exact fixture, unmodified, must validate. Without it a gate could pass
// because the fixture is broken for an unrelated reason.
func TestSchemaV3_ControlAttemptOutcomeIsValid(t *testing.T) {
	if err := baseAttemptOutcome().Validate(); err != nil {
		t.Fatalf("the v3 control fixture must be valid: %v", err)
	}
}

// TestSchemaV3_AttemptEvidenceUnderAnOlderStampIsRejected is the load-bearing
// direction. CanonicalBytes covers the attempt fields, so a record carrying them
// while claiming v1 is unreadable to a build that predates them: that build drops
// what it does not know, recomputes a different digest, and reports the record as
// SPOOL CORRUPTION. A version rollback would then raise the alarm reserved for
// tampering and abort recovery, instead of refusing a cleanly unsupported schema.
func TestSchemaV3_AttemptEvidenceUnderAnOlderStampIsRejected(t *testing.T) {
	e := baseAttemptOutcome()
	e.SchemaVersion = SchemaVersionV1
	err := e.Validate()
	if err == nil {
		t.Fatal("attempt evidence stamped v1 was accepted")
	}
	if !strings.Contains(err.Error(), "schema v3") {
		t.Fatalf("the v1 refusal must name the schema, got: %v", err)
	}
	// v2 is refused too, but by the SHADOW rule that reaches it first (a v2 event is a
	// Shadow decision event by construction, and this is an outcome phase). The reason
	// differs; the refusal is what matters, and asserting the v3 wording here would be
	// pinning which rule happens to run first rather than the contract.
	e2 := baseAttemptOutcome()
	e2.SchemaVersion = SchemaVersionV2
	if err := e2.Validate(); err == nil {
		t.Fatal("attempt evidence stamped v2 was accepted")
	}
}

// TestSchemaV3_StampWithoutEvidenceIsRejected is the reverse pairing. A v3 stamp on
// an ordinary record would silently make it unreadable to a build that could
// otherwise have read it — the same damage in the opposite direction.
func TestSchemaV3_StampWithoutEvidenceIsRejected(t *testing.T) {
	e := baseDecision()
	e.SchemaVersion = SchemaVersionV3
	if err := e.Validate(); err == nil {
		t.Fatal("a v3 stamp with no attempt evidence was accepted")
	}
}

// TestSchemaV3_LegacyOutcomeFieldsDoNotTriggerTheStamp is the digest-compatibility
// half. The ORIGINAL OutcomeEvidence fields must not be treated as v3 evidence:
// counting them would re-stamp every pre-existing outcome event, changing digests
// that must stay byte-identical across this change.
func TestSchemaV3_LegacyOutcomeFieldsDoNotTriggerTheStamp(t *testing.T) {
	e := baseDecision()
	e.Phase = PhaseOutcome
	e.Outcome = &OutcomeEvidence{
		DecisionRef: "evt_dec1", Executed: true, StatusClass: "executed",
		DurationMs: 12, UpstreamResponseClass: "ok", InspectionResult: "pass",
		FailureReason: "none",
	}
	if e.CarriesAttemptEvidence() {
		t.Fatal("the original v1 outcome fields must not be read as v3 evidence")
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("a v1 outcome event must stay valid at v1: %v", err)
	}
	// The new keys must be ABSENT from the encoding, which is what keeps the digest
	// of a pre-existing outcome event unchanged.
	b, err := e.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, k := range []string{"attempt_id", "reservation_id", "activation_generation", "physical_send_state", "reconciliation"} {
		if strings.Contains(string(b), k) {
			t.Fatalf("a v1 outcome event encoded the v3 key %q, changing its digest", k)
		}
	}
}

// TestSchemaV3_EachAttemptFieldAloneTriggersTheStamp pins that the predicate is not
// satisfied by only one field. A record carrying any single v3 field under an older
// stamp is just as unreadable as one carrying all of them.
func TestSchemaV3_EachAttemptFieldAloneTriggersTheStamp(t *testing.T) {
	cases := map[string]func(*OutcomeEvidence){
		"attempt_id":            func(o *OutcomeEvidence) { o.AttemptID = "att_1" },
		"reservation_id":        func(o *OutcomeEvidence) { o.ReservationID = "res_1" },
		"activation_generation": func(o *OutcomeEvidence) { o.ActivationGeneration = 1 },
		"physical_send_state":   func(o *OutcomeEvidence) { o.PhysicalSendState = SendMayHaveBeenSent },
	}
	for name, set := range cases {
		e := baseDecision()
		e.Phase = PhaseOutcome
		e.Outcome = &OutcomeEvidence{DecisionRef: "evt_dec1", Executed: true}
		set(e.Outcome)
		if !e.CarriesAttemptEvidence() {
			t.Fatalf("%s alone did not trigger the v3 stamp", name)
		}
		if err := e.Validate(); err == nil {
			t.Fatalf("%s alone under a v1 stamp was accepted", name)
		}
	}
}

// TestSchemaV3_ShadowAndAttemptEvidenceAreMutuallyExclusive pins the assumption the
// single-valued stamp rests on: a Shadow evaluation never sends anything, so it has
// no attempt to identify. If both shapes could coexist, one of them would have to be
// recorded under a version that does not describe it.
func TestSchemaV3_ShadowAndAttemptEvidenceAreMutuallyExclusive(t *testing.T) {
	e := baseAttemptOutcome()
	e.Shadow = &ShadowEvidence{
		Outcome: "would_execute", CredentialPlan: "credential_plan_valid",
		MaterializationReadiness: "not_evaluated", RequestInspection: "would_pass",
		ResponseInspection: "not_evaluated",
	}
	if err := e.Validate(); err == nil {
		t.Fatal("an event carrying both shadow and attempt evidence was accepted")
	}
}
