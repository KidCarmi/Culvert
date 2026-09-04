package execution

// reconcile_test.go — deterministic witness-reconciliation gates (review §11).
//
// ANTI-VACUITY: every negative gate is paired with a positive control on the SAME
// fixture, differing only in the one condition under test. Without that, a gate
// that "observes no state change" can pass simply because the engine was never
// reached — the failure mode that made the first draft of the executor gates
// meaningless.

import (
	"context"
	"errors"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

type stubWitness struct {
	obs WitnessObservation
	err error
}

func (w stubWitness) LookupAttempt(context.Context, string) (WitnessObservation, error) {
	return w.obs, w.err
}

func orphanFor(t *testing.T) RecoveredAttempt {
	t.Helper()
	id, err := newAttemptID()
	if err != nil {
		t.Fatalf("newAttemptID: %v", err)
	}
	return RecoveredAttempt{
		AttemptID: id, ReservationID: "rsv_1", ActivationGeneration: 7,
		State: AttemptReconciliationRequired,
	}
}

// baseObservation is the shape that DOES reconcile to received. Negative gates
// mutate exactly one field so the control is meaningful.
func baseObservation(o RecoveredAttempt) WitnessObservation {
	return WitnessObservation{
		Count: 1, Complete: true, CompletenessWatermark: "wm-1",
		ServerID: "s1", Method: "tools/call", ReservationID: o.ReservationID,
		Source: "controlled-witness", EvidenceDigest: "sha256:abc",
	}
}

func reconcile(t *testing.T, o RecoveredAttempt, w Witness) model.ReconciliationEvidence {
	t.Helper()
	ev, err := ReconcileOrphan(context.Background(), w, o, "s1", "tools/call", 1234)
	if err != nil {
		t.Fatalf("ReconcileOrphan: %v", err)
	}
	return ev
}

// (1) exactly one receipt → reconciled_received. This is also the POSITIVE CONTROL
// every negative gate below is measured against.
func TestReconcile_ExactlyOneReceiptIsReceived(t *testing.T) {
	o := orphanFor(t)
	ev := reconcile(t, o, stubWitness{obs: baseObservation(o)})
	if ev.Result != model.ReconReceived {
		t.Fatalf("one matching receipt must reconcile to received, got %q", ev.Result)
	}
	if ev.AttemptID != o.AttemptID || ev.ReservationID != o.ReservationID || ev.ActivationGeneration != 7 {
		t.Fatalf("evidence must bind the ORIGINAL identity, got %+v", ev)
	}
	if ev.ObservationCount != 1 || ev.WitnessSource == "" {
		t.Fatalf("evidence must retain the witness facts, got %+v", ev)
	}
}

// (2) zero receipts + proven completeness → reconciled_not_received.
func TestReconcile_ZeroWithCompletenessIsNotReceived(t *testing.T) {
	o := orphanFor(t)
	obs := baseObservation(o)
	obs.Count = 0
	ev := reconcile(t, o, stubWitness{obs: obs})
	if ev.Result != model.ReconNotReceived {
		t.Fatalf("zero receipts with proven completeness must be not_received, got %q", ev.Result)
	}
	if ev.CompletenessWatermark == "" {
		t.Fatal("a definitive not_received must record the completeness proof it relied on")
	}
}

// (3) zero receipts WITHOUT completeness → stays reconciliation_required.
// Absence from a possibly-incomplete log proves nothing.
func TestReconcile_ZeroWithoutCompletenessStaysRequired(t *testing.T) {
	o := orphanFor(t)
	for _, tc := range []struct {
		name string
		mut  func(*WitnessObservation)
	}{
		{"not complete", func(w *WitnessObservation) { w.Count, w.Complete = 0, false }},
		{"complete but no watermark", func(w *WitnessObservation) { w.Count, w.CompletenessWatermark = 0, "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := baseObservation(o)
			tc.mut(&obs)
			ev := reconcile(t, o, stubWitness{obs: obs})
			if ev.Result != model.ReconRequired {
				t.Fatalf("absence without a completeness proof must stay required, got %q", ev.Result)
			}
			if ev.Result == model.ReconNotReceived {
				t.Fatal("unknown must never be collapsed into not_received")
			}
		})
	}
	// CONTROL: same fixture, completeness restored ⇒ engine genuinely resolves.
	obs := baseObservation(o)
	obs.Count = 0
	if ev := reconcile(t, o, stubWitness{obs: obs}); ev.Result != model.ReconNotReceived {
		t.Fatalf("control: with completeness proven the engine must resolve, got %q", ev.Result)
	}
}

// (4) two receipts → conflict. A duplicate physical invocation for one attempt is a
// blocker-#6 invariant breach and must never normalize to "received".
func TestReconcile_DuplicateReceiptsAreConflict(t *testing.T) {
	o := orphanFor(t)
	obs := baseObservation(o)
	obs.Count = 2
	ev := reconcile(t, o, stubWitness{obs: obs})
	if ev.Result != model.ReconConflict {
		t.Fatalf("two physical invocations for one attempt must be a conflict, got %q", ev.Result)
	}
	if ev.ObservationCount != 2 {
		t.Fatalf("the breach magnitude must be retained verbatim, got %d", ev.ObservationCount)
	}
}

// (6) matching AttemptID but wrong binding → conflict, not success.
func TestReconcile_WrongBindingIsConflict(t *testing.T) {
	o := orphanFor(t)
	for _, tc := range []struct {
		name string
		mut  func(*WitnessObservation)
	}{
		{"wrong server", func(w *WitnessObservation) { w.ServerID = "s-other" }},
		{"wrong method", func(w *WitnessObservation) { w.Method = "tools/list" }},
		{"wrong reservation", func(w *WitnessObservation) { w.ReservationID = "rsv_other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := baseObservation(o)
			tc.mut(&obs)
			if ev := reconcile(t, o, stubWitness{obs: obs}); ev.Result != model.ReconConflict {
				t.Fatalf("contradictory binding must be a conflict, got %q", ev.Result)
			}
		})
	}
	// CONTROL: unmutated binding reconciles, proving the engine was reached.
	if ev := reconcile(t, o, stubWitness{obs: baseObservation(o)}); ev.Result != model.ReconReceived {
		t.Fatalf("control: consistent binding must reconcile to received, got %q", ev.Result)
	}
}

// (7) witness unavailable / malformed → unresolved. Never manufactured certainty.
func TestReconcile_WitnessUnavailableStaysUnresolved(t *testing.T) {
	o := orphanFor(t)
	for _, tc := range []struct {
		name string
		w    Witness
	}{
		{"error", stubWitness{err: errors.New("timeout")}},
		{"no witness wired", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := reconcile(t, o, tc.w)
			if ev.Result != model.ReconRequired {
				t.Fatalf("an unusable witness must leave the attempt required, got %q", ev.Result)
			}
		})
	}
	// CONTROL: a working witness on the same orphan resolves.
	if ev := reconcile(t, o, stubWitness{obs: baseObservation(o)}); ev.Result != model.ReconReceived {
		t.Fatalf("control: a working witness must resolve, got %q", ev.Result)
	}
}

// (11) a settled attempt is not an orphan and must not enter reconciliation.
func TestReconcile_SettledAttemptIsRejected(t *testing.T) {
	o := orphanFor(t)
	o.State = AttemptSettled
	if _, err := ReconcileOrphan(context.Background(), stubWitness{obs: baseObservation(o)}, o, "s1", "tools/call", 1); err == nil {
		t.Fatal("a settled attempt must not be reconciled as an orphan")
	}
}

// (7) reconciliation never changes authorization — it produces evidence only, and
// the type system offers no resend/refund/reservation handle at all.
func TestReconcile_ProducesEvidenceNotAuthority(t *testing.T) {
	o := orphanFor(t)
	obs := baseObservation(o)
	obs.Count = 0
	ev := reconcile(t, o, stubWitness{obs: obs})
	if ev.Result != model.ReconNotReceived {
		t.Fatalf("setup: expected not_received, got %q", ev.Result)
	}
	// Even the strongest "it never happened" verdict returns nothing executable and
	// leaves the original generation and reservation intact.
	if ev.ActivationGeneration != o.ActivationGeneration || ev.ReservationID != o.ReservationID {
		t.Fatal("reconciliation must not mutate the attempt's authorization binding")
	}
}

// (9) the state machine: no transition back to executable, and a contradictory
// later result is not silently accepted.
func TestReconcile_TransitionRules(t *testing.T) {
	if !ReconcileTransitionAllowed(model.ReconRequired, model.ReconReceived) {
		t.Fatal("required -> received must be allowed")
	}
	if !ReconcileTransitionAllowed(model.ReconRequired, model.ReconNotReceived) {
		t.Fatal("required -> not_received must be allowed")
	}
	if !ReconcileTransitionAllowed(model.ReconRequired, model.ReconConflict) {
		t.Fatal("required -> conflict must be allowed")
	}
	if !ReconcileTransitionAllowed(model.ReconReceived, model.ReconReceived) {
		t.Fatal("re-deriving the same result must be idempotent")
	}
	if ReconcileTransitionAllowed(model.ReconNotReceived, model.ReconReceived) {
		t.Fatal("a resolved result must not silently flip to its opposite")
	}
}

// (8)+(9)+(12) ledger-level: idempotent repeat, contradictory second record fails
// closed, malformed reconciliation evidence fails closed on restart.
func TestRecovery_ReconciliationLedgerSemantics(t *testing.T) {
	id := mustAttemptID(t)
	reconEvent := func(res model.ReconciliationResult) model.Event {
		return model.Event{Phase: model.PhaseReconciliation, Reconciliation: &model.ReconciliationEvidence{
			AttemptID: id, ReservationID: "rsv_1", ActivationGeneration: 7, Result: res,
		}}
	}

	t.Run("idempotent repeat", func(t *testing.T) {
		rep, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_1", 7), reconEvent(model.ReconReceived), reconEvent(model.ReconReceived),
		))
		if err != nil {
			t.Fatalf("an identical repeated reconciliation must be idempotent: %v", err)
		}
		if len(rep.Orphans) != 1 || rep.Orphans[0].Reconciliation != model.ReconReceived {
			t.Fatalf("expected one received-orphan, got %+v", rep.Orphans)
		}
	})

	t.Run("contradictory second record fails closed", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_1", 7), reconEvent(model.ReconNotReceived), reconEvent(model.ReconReceived),
		)); err == nil {
			t.Fatal("a contradictory later reconciliation must fail closed, not silently win")
		}
	})

	t.Run("malformed reconciliation fails closed", func(t *testing.T) {
		bad := model.Event{Phase: model.PhaseReconciliation, Reconciliation: &model.ReconciliationEvidence{
			AttemptID: id, Result: model.ReconciliationResult("made_up"),
		}}
		if _, err := RecoverAttempts(readerWith(intentEvent(id, "rsv_1", 7), bad)); err == nil {
			t.Fatal("an unknown reconciliation result must fail closed on restart")
		}
	})

	t.Run("unreconciled orphan rests at required", func(t *testing.T) {
		rep, err := RecoverAttempts(readerWith(intentEvent(id, "rsv_1", 7)))
		if err != nil {
			t.Fatalf("RecoverAttempts: %v", err)
		}
		if rep.Orphans[0].Reconciliation != model.ReconRequired {
			t.Fatalf("an unreconciled orphan must rest at required, got %q", rep.Orphans[0].Reconciliation)
		}
	})
}

// (10) reconciling a generation-7 orphan leaves generation-8 authority untouched.
func TestRecovery_ReconcilingOldGenerationDoesNotAffectNewer(t *testing.T) {
	oldID, newID := mustAttemptID(t), mustAttemptID(t)
	rep, err := RecoverAttempts(readerWith(
		intentEvent(oldID, "rsv_old", 7),
		model.Event{Phase: model.PhaseReconciliation, Reconciliation: &model.ReconciliationEvidence{
			AttemptID: oldID, ReservationID: "rsv_old", ActivationGeneration: 7, Result: model.ReconNotReceived,
		}},
		intentEvent(newID, "rsv_new", 8),
		outcomeEvent(newID, "rsv_new", 8, model.SendPeerResponseReceived),
	))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	if len(rep.Orphans) != 1 || rep.Orphans[0].ActivationGeneration != 7 {
		t.Fatalf("the old orphan must stay historical under generation 8, got %+v", rep.Orphans)
	}
	if rep.Orphans[0].Reconciliation != model.ReconNotReceived {
		t.Fatalf("the old orphan's KNOWLEDGE may improve, got %q", rep.Orphans[0].Reconciliation)
	}
	// Even proven-not-received, the generation-7 attempt yields no allowance and the
	// generation-8 attempt is unchanged.
	if len(rep.Settled) != 1 || rep.Settled[0].ActivationGeneration != 8 {
		t.Fatalf("generation-8 authority must be unchanged, got %+v", rep.Settled)
	}
}

// --- Codex round 1 findings -------------------------------------------------

// TestReconcile_NegativeCountNeverResolvesAbsence pins Codex round-1 P1. A negative
// observation count is impossible for a well-formed witness, so it is malformed
// data, not an observation. Falling through to the zero-count branch would turn
// garbage into a definitive "never happened" — the one direction this engine must
// never manufacture.
func TestReconcile_NegativeCountNeverResolvesAbsence(t *testing.T) {
	o := orphanFor(t)
	for _, n := range []int{-1, -1000} {
		obs := baseObservation(o)
		obs.Count = n
		obs.Complete, obs.CompletenessWatermark = true, "wm-1"
		if got := reconcile(t, o, stubWitness{obs: obs}).Result; got != model.ReconRequired {
			t.Fatalf("count=%d must stay reconciliation_required, got %q", n, got)
		}
	}
	// CONTROL on the same fixture: a real zero WITH a completeness proof does resolve,
	// so the gate above is measuring the negative count and not a broken fixture.
	zero := baseObservation(o)
	zero.Count, zero.Complete, zero.CompletenessWatermark = 0, true, "wm-1"
	if got := reconcile(t, o, stubWitness{obs: zero}).Result; got != model.ReconNotReceived {
		t.Fatalf("control: a proven zero must resolve not_received, got %q", got)
	}
}

// TestRecovery_ReconciliationMustMatchTheIntentBinding pins Codex round-1 P1. An
// attempt id alone is not enough: a well-formed `reconciled_not_received` naming a
// different reservation or generation would downgrade this orphan's uncertainty on
// the strength of a claim about some other execution.
func TestRecovery_ReconciliationMustMatchTheIntentBinding(t *testing.T) {
	id := mustAttemptID(t)
	reconEvent := func(res string, gen uint64) model.Event {
		return model.Event{Phase: model.PhaseReconciliation, Reconciliation: &model.ReconciliationEvidence{
			AttemptID: id, ReservationID: res, ActivationGeneration: gen, Result: model.ReconNotReceived,
		}}
	}

	t.Run("wrong reservation fails closed", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_authorized", 7), reconEvent("rsv_other", 7),
		)); err == nil {
			t.Fatal("reconciliation naming a different reservation must fail closed")
		}
	})

	t.Run("wrong generation fails closed", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_authorized", 7), reconEvent("rsv_authorized", 8),
		)); err == nil {
			t.Fatal("reconciliation naming a different generation must fail closed")
		}
	})

	// CONTROL: the matching binding IS applied, so the two gates above are measuring
	// the mismatch rather than reconciliation being inert.
	rep, err := RecoverAttempts(readerWith(
		intentEvent(id, "rsv_authorized", 7), reconEvent("rsv_authorized", 7),
	))
	if err != nil {
		t.Fatalf("control: a matching reconciliation must apply: %v", err)
	}
	if len(rep.Orphans) != 1 || rep.Orphans[0].Reconciliation != model.ReconNotReceived {
		t.Fatalf("control: expected a not_received orphan, got %+v", rep.Orphans)
	}
}
