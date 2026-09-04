package main

// mcp_canary_evidence_freeze_test.go — PERMANENT gates for the durable-evidence
// truth that closes (or fails to close) review blocker #8.
//
// THE PROOF RULE THIS FILE ENFORCES:
//
//	Any security-critical evidence test used to close blocker #8 must exercise the
//	REAL validator and/or read the committed record back from the REAL spool. A
//	permissive fake sink is useful for unit isolation; it is NOT proof of durable
//	evidence truth.
//
// The rule is not an abstraction. It was earned twice:
//
//   - Resolution{} — an executor gate that asserted "zero upstream calls" passed
//     while asserting nothing, because the zero-value resolution never attempted an
//     execution. Caught only by a POSITIVE CONTROL on the same fixture.
//   - DecisionRef — every terminal PhaseOutcome failed validation for want of a
//     decision reference, and because the outcome commit is best-effort the record
//     vanished. On restart, EVERY completed execution looked exactly like a crash.
//     Caught only by reading the real spool; every unit test passed throughout,
//     because they commit through a sink that does not validate.
//
// Both are permanent examples, so both are pinned here rather than remembered.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// outcomeEventFixture builds a PhaseOutcome event that IS valid, so a gate that
// removes exactly one field is measuring that field and nothing else.
func outcomeEventFixture() model.Event {
	return model.Event{
		SchemaVersion: model.SchemaVersion,
		EventID:       "evt_out01",
		Phase:         model.PhaseOutcome,
		Criticality:   model.CritOrdinary,
		Partition:     model.PartOrd,
		Capability:    model.CapGateway,
		ActionClass:   model.ActionClassRead,
		NodeID:        "dp-1",
		DomainID:      "dp-1|gateway|P-ORD",
		TimeUnixNano:  2,
		ReplayID:      "rpl_out01",
		CorrelationID: "cor_0001",
		Identity:      model.IdentityEvidence{Tenant: "acme", PrincipalID: "user-1", PrincipalType: "human"},
		Decision:      model.DecisionEvidence{Action: "ALLOW", ReasonCode: "MCP.POLICY.OK", PolicyRevision: 1, CatalogRevision: 1},
		Outcome: &model.OutcomeEvidence{
			DecisionRef:          "evt_0001",
			AttemptID:            "att_0001",
			ReservationID:        "rsv_0001",
			ActivationGeneration: 1,
			PhysicalSendState:    model.SendPeerResponseReceived,
			Executed:             true,
		},
	}
}

// TestEvidenceFreeze_ControlOutcomeFixtureIsValid is the POSITIVE CONTROL. Without
// it, the gate below could pass because the fixture is broken for some unrelated
// reason rather than because DecisionRef is load-bearing.
func TestEvidenceFreeze_ControlOutcomeFixtureIsValid(t *testing.T) {
	if err := outcomeEventFixture().Validate(); err != nil {
		t.Fatalf("the outcome fixture must be valid before a field is removed from it: %v", err)
	}
}

// TestEvidenceFreeze_OutcomeWithoutDecisionRefFailsValidation freezes the exact
// defect the controlled HTTPS E2E found. Removing ONLY the decision reference must
// make the event unpersistable — loudly, at the validator — rather than producing a
// record that quietly never lands.
func TestEvidenceFreeze_OutcomeWithoutDecisionRefFailsValidation(t *testing.T) {
	e := outcomeEventFixture()
	e.Outcome.DecisionRef = ""
	err := e.Validate()
	if err == nil {
		t.Fatal("a terminal outcome without a decision ref must fail validation")
	}
	if got := mcperr.ReasonOf(err); got != mcperr.ReasonEventEvidenceMissing {
		t.Fatalf("reason = %v, want %v", got, mcperr.ReasonEventEvidenceMissing)
	}
}

// TestEvidenceFreeze_OutcomeWithMalformedDecisionRefFailsValidation pins the other
// half: a decision ref that is present but not a real event identifier is not a
// reference. Accepting it would restore the silent-loss class through a different
// door — a record that names nothing is as unusable as one that names nothing at all.
func TestEvidenceFreeze_OutcomeWithMalformedDecisionRefFailsValidation(t *testing.T) {
	for _, bad := range []string{"0001", "rpl_0001", "evt_" + string(make([]byte, 300))} {
		e := outcomeEventFixture()
		e.Outcome.DecisionRef = bad
		if err := e.Validate(); err == nil {
			t.Fatalf("a malformed decision ref (%q) must fail validation", bad)
		}
	}
}

// TestEvidenceFreeze_CompletedInvocationIsSettledThroughTheRealSpool is the
// end-to-end half of the proof rule, and the one a permissive sink cannot satisfy.
// It runs a real controlled execution, reads the committed records back out of the
// REAL spool, validates each against the REAL validator, and derives the restart
// state from them:
//
//	completed physical invocation
//	  => exactly one VALID PhaseSendIntent
//	  => exactly one VALID PhaseOutcome
//	  => restart recovery = SETTLED
//	  => orphan count = 0
func TestEvidenceFreeze_CompletedInvocationIsSettledThroughTheRealSpool(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("setup: the controlled execution must succeed, out=%+v", out)
	}
	if p.count() != 1 {
		t.Fatalf("setup: the peer must have received exactly one invocation, got %d", p.count())
	}
	attemptID := p.observed()[0].AttemptID

	evs, _ := rig.spoolEventsAll(t)
	var intents, outcomes int
	for i := range evs {
		// EVERY committed record goes through the real validator. A record that the
		// spool holds but the validator rejects is the shape that produced the
		// DecisionRef loss, and it must be impossible to reach this assertion.
		if err := evs[i].Validate(); err != nil {
			t.Fatalf("a committed event fails the real validator (%v): phase=%v", err, evs[i].Phase)
		}
		if evs[i].Outcome == nil || evs[i].Outcome.AttemptID != attemptID {
			continue
		}
		switch evs[i].Phase {
		case model.PhaseSendIntent:
			intents++
		case model.PhaseOutcome:
			outcomes++
			if evs[i].Outcome.DecisionRef == "" {
				t.Fatal("the committed outcome carries no decision ref: it could not have been persisted")
			}
		}
	}
	if intents != 1 {
		t.Fatalf("one physical invocation must leave exactly one durable send intent, got %d", intents)
	}
	if outcomes != 1 {
		t.Fatalf("one physical invocation must leave exactly one terminal outcome, got %d", outcomes)
	}

	rep := rig.recover(t)
	if len(rep.Orphans) != 0 {
		t.Fatalf("a completed invocation must leave ZERO orphans, got %+v", rep.Orphans)
	}
	rec, found := findAttempt(rep, attemptID)
	if !found {
		t.Fatalf("restart recovery lost the completed attempt: %+v", rep)
	}
	if rec.State != execution.AttemptSettled {
		t.Fatalf("restart recovery must report SETTLED, got %q", rec.State)
	}
	if rec.TerminalSendState != model.SendPeerResponseReceived {
		t.Fatalf("a peer that answered must settle as peer_response_received, got %q", rec.TerminalSendState)
	}
}
