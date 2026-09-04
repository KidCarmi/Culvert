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
	"io"
	"net/http"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// outcomeEventFixture builds a PhaseOutcome event that IS valid, so a gate that
// removes exactly one field is measuring that field and nothing else.
func outcomeEventFixture() model.Event {
	return model.Event{
		// Attempt evidence is a v3 shape. Stamping it v1 would make the record
		// unreadable to a build that predates the fields — it would drop them, compute
		// a different digest, and report SPOOL CORRUPTION on an ordinary version
		// rollback rather than the clean unsupported-schema refusal.
		SchemaVersion: model.SchemaVersionV3,
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

// TestEvidenceFreeze_AttemptEvidenceIsStampedV3OnTheRealSpool pins the schema stamp
// on the REAL write path, not on a fixture.
//
// The attempt-identity and physical-send fields are covered by the canonical digest,
// so a record that carries them while claiming the old version is UNREADABLE to a
// build that predates them: it drops the fields it does not know, recomputes a
// different digest, and reports the record as SPOOL CORRUPTION. A version rollback
// would raise the alarm reserved for tampering and disk damage — and abort recovery —
// where the honest answer is "this record is newer than me". The stamp is what makes
// that answer expressible.
//
// The second half is the compatibility half: the ordinary DECISION event committed by
// the very same execution must stay v1, so this change moves no pre-existing record's
// digest.
func TestEvidenceFreeze_AttemptEvidenceIsStampedV3OnTheRealSpool(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("setup: the controlled execution must succeed, out=%+v", out)
	}
	attemptID := p.observed()[0].AttemptID

	evs, _ := rig.spoolEventsAll(t)
	var attemptEvents, plainEvents int
	for i := range evs {
		e := evs[i]
		if e.CarriesAttemptEvidence() {
			attemptEvents++
			if e.SchemaVersion != model.SchemaVersionV3 {
				t.Fatalf("a committed %v event carrying attempt evidence is stamped v%d, want v3",
					e.Phase, e.SchemaVersion)
			}
			continue
		}
		plainEvents++
		if e.SchemaVersion != model.SchemaVersion {
			t.Fatalf("a committed %v event carrying NO attempt evidence is stamped v%d, want the default v%d — "+
				"re-stamping an ordinary record changes a digest that must not change",
				e.Phase, e.SchemaVersion, model.SchemaVersion)
		}
	}
	// Controls. Without these the loop above passes vacuously on an empty spool, or on
	// one where the execution somehow committed only one class of record.
	if attemptEvents == 0 {
		t.Fatal("control: the execution committed no attempt evidence at all")
	}
	if plainEvents == 0 {
		t.Fatal("control: the execution committed no ordinary record, so the v1 half proves nothing")
	}
	if attemptID == "" {
		t.Fatal("control: the peer recorded no attempt id")
	}
}

// outcomeExecutedFlag reads Outcome.Executed off the committed terminal record for
// one attempt, from the REAL spool.
func outcomeExecutedFlag(t *testing.T, rig *peerRig, attemptID string) (executed, found bool) {
	t.Helper()
	evs, _ := rig.spoolEventsAll(t)
	for i := range evs {
		e := evs[i]
		if e.Phase != model.PhaseOutcome || e.Outcome == nil || e.Outcome.AttemptID != attemptID {
			continue
		}
		return e.Outcome.Executed, true
	}
	return false, false
}

// TestOutcomeTruth_AnUncertainSendIsNeverRecordedAsNotExecuted freezes the decision
// that Outcome.Executed answers "may a physical effect have happened?" rather than
// "did Culvert return a result?".
//
// Deriving it from the terminal disposition was proposed and rejected: it reads
// better locally, because executed=true beside a "blocked" execution state looks
// contradictory, but it writes executed=false into the durable record for
// invocations that demonstrably reached the peer. That is precisely the conversion
// this whole change exists to prevent. The two fields are recorded side by side
// BECAUSE they answer different questions.
func TestOutcomeTruth_AnUncertainSendIsNeverRecordedAsNotExecuted(t *testing.T) {
	p := startControlledPeer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("the controlled peer cannot hijack, so the drop cannot be simulated")
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	})
	rig := armCanaryWithRealPeer(t, p, 10)
	out := rig.exec(peerExecInput(p, policy.OpRead))

	// Controls: the peer received it, and Culvert's own disposition really is the
	// "blocked/not executed" one that makes this case interesting at all.
	if p.count() != 1 {
		t.Fatalf("control: the peer must have received exactly one invocation, got %d", p.count())
	}
	if out.Executed {
		t.Fatalf("control: an ambiguous drop must not report executed to the client, out=%+v", out)
	}

	executed, found := outcomeExecutedFlag(t, rig, p.observed()[0].AttemptID)
	if !found {
		t.Fatal("the ambiguous attempt committed no terminal outcome")
	}
	if !executed {
		t.Fatal("an invocation that may have reached the peer was durably recorded as NOT executed — " +
			"this is uncertainty converted into executed=false")
	}
}

// TestOutcomeTruth_ADLPBlockAfterTheAnswerStaysExecuted is the second half: the peer
// answered, so the tool ran. Culvert refusing to hand the response to the client is
// its own disposition and changes nothing about the effect.
func TestOutcomeTruth_ADLPBlockAfterTheAnswerStaysExecuted(t *testing.T) {
	pemBody := "-----BEGIN RSA " + "PRIVATE KEY-----" + "\\nMIIB\\n" + "-----END RSA " + "PRIVATE KEY-----"
	p := startControlledPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"u-s1","result":{"leak":"`+pemBody+`"}}`)
	})
	rig := armCanaryWithRealPeer(t, p, 10)
	out := rig.exec(peerExecInput(p, policy.OpRead))
	if out.Disposition != mcpruntime.DispRejected {
		t.Fatalf("control: the response must be refused before egress, out=%+v", out)
	}
	executed, found := outcomeExecutedFlag(t, rig, p.observed()[0].AttemptID)
	if !found {
		t.Fatal("the DLP-blocked attempt committed no terminal outcome")
	}
	if !executed {
		t.Fatal("a DLP block on egress erased a physical effect the peer had already performed")
	}
}

// TestOutcomeTruth_ABoundaryRefusalIsRecordedAsNotExecuted is the CONTROL that stops
// the two gates above from passing on an implementation that simply hardcodes
// executed=true. A refusal at the final boundary is the one case where
// definitely_not_sent is mechanically provable, and it must record executed=false.
//
// It asserts only the Executed flag; the fuller record-shape control for the same
// path (send state, and that the persisted decision state does not claim executed)
// is TestHTTPSE2E_BoundaryRefusalIsNotRecordedAsExecuted.
func TestOutcomeTruth_ABoundaryRefusalIsRecordedAsNotExecuted(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeerGate(t, p, 10, true, demoteAtBoundary)
	out := rig.exec(peerExecInput(p, policy.OpRead))

	if p.count() != 0 {
		t.Fatalf("control: a boundary refusal must send zero bytes, peer saw %d", p.count())
	}
	if out.Executed {
		t.Fatalf("control: a boundary refusal must not report executed, out=%+v", out)
	}
	evs, _ := rig.spoolEventsAll(t)
	var checked int
	for i := range evs {
		e := evs[i]
		if e.Phase != model.PhaseOutcome || e.Outcome == nil {
			continue
		}
		checked++
		if e.Outcome.Executed {
			t.Fatal("a provably never-sent attempt was recorded as executed")
		}
	}
	if checked == 0 {
		t.Fatal("control: the boundary refusal committed no terminal outcome to check")
	}
}
