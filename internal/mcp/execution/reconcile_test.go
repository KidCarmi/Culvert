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

// TestReconcile_DefinitiveAbsenceRequiresAMatchingBinding pins Codex round-3 P1.
//
// The binding check originally guarded only the Count==1 branch, which left the
// more dangerous direction open: a witness reporting a COMPLETE view of a DIFFERENT
// reservation, server or method, containing zero invocations, resolved this attempt
// to "never happened". That is not contradictory evidence — it is an answer to a
// question nobody asked — and turning it into definitive absence is exactly the
// conversion this engine exists to prevent.
//
// It was invisible downstream as well: ReconcileOrphan records the ORPHAN's own
// reservation on the evidence, so recovery's binding check compared a value against
// itself and could never see the mismatch.
func TestReconcile_DefinitiveAbsenceRequiresAMatchingBinding(t *testing.T) {
	o := orphanFor(t)
	cases := map[string]func(*WitnessObservation){
		"reservation": func(obs *WitnessObservation) { obs.ReservationID = "rsv_other" },
		"server":      func(obs *WitnessObservation) { obs.ServerID = "s-other" },
		"method":      func(obs *WitnessObservation) { obs.Method = "tools/other" },
	}
	for name, breakIt := range cases {
		obs := baseObservation(o)
		obs.Count, obs.Complete, obs.CompletenessWatermark = 0, true, "wm-1"
		breakIt(&obs)
		if got := reconcile(t, o, stubWitness{obs: obs}).Result; got != model.ReconRequired {
			t.Fatalf("a proven zero for a mismatched %s must stay reconciliation_required, got %q", name, got)
		}
	}
	// CONTROL on the same fixture: a matching binding with a proven zero DOES resolve.
	// Without it, this gate would pass on an implementation that had simply stopped
	// resolving absence at all — which would be a different bug, not a fix.
	ok := baseObservation(o)
	ok.Count, ok.Complete, ok.CompletenessWatermark = 0, true, "wm-1"
	if got := reconcile(t, o, stubWitness{obs: ok}).Result; got != model.ReconNotReceived {
		t.Fatalf("control: a proven zero with a matching binding must resolve not_received, got %q", got)
	}
}

// TestReconcile_MismatchedAbsenceIsNotReportedAsAConflict pins the CHOICE of verdict,
// which is a decision rather than an obvious consequence.
//
// A conflict asserts a breach of the exactly-once invariant. Zero observations of
// some OTHER authorization is no evidence of a breach, so reporting one would
// manufacture an alarm from inapplicable data — the mirror of manufacturing absence,
// and the easier direction for a misdirected or hostile witness to trigger. Knowledge
// is simply unchanged.
func TestReconcile_MismatchedAbsenceIsNotReportedAsAConflict(t *testing.T) {
	o := orphanFor(t)
	obs := baseObservation(o)
	obs.Count, obs.Complete, obs.CompletenessWatermark = 0, true, "wm-1"
	obs.ReservationID = "rsv_other"
	if got := reconcile(t, o, stubWitness{obs: obs}).Result; got == model.ReconConflict {
		t.Fatal("a mismatched ZERO-count observation must not be reported as a conflict")
	}
	// CONTROL: a mismatched ONE-count observation IS a conflict — contradictory
	// evidence about an effect that was actually observed.
	one := baseObservation(o)
	one.Count, one.ReservationID = 1, "rsv_other"
	if got := reconcile(t, o, stubWitness{obs: one}).Result; got != model.ReconConflict {
		t.Fatalf("control: a mismatched observed invocation must be a conflict, got %q", got)
	}
}

// TestReconcile_ExactlyOneNeedsTheSameCompletenessProofAsAbsence pins Codex round-4
// P1. "Exactly one" is a claim about the whole population, so it needs the same
// completeness proof "never happened" does. Requiring it for absence but not for
// receipt was an asymmetry with a real consequence: ReconReceived is defined as
// exactly one and is treated as RESOLVED, so a partial view containing one
// invocation settled an attempt whose duplicate simply lay outside the observed set
// — hiding the precise thing blocker #6 exists to detect.
func TestReconcile_ExactlyOneNeedsTheSameCompletenessProofAsAbsence(t *testing.T) {
	o := orphanFor(t)
	for name, breakIt := range map[string]func(*WitnessObservation){
		"not_complete":              func(obs *WitnessObservation) { obs.Complete = false },
		"complete_but_no_watermark": func(obs *WitnessObservation) { obs.CompletenessWatermark = "" },
	} {
		obs := baseObservation(o)
		obs.Count = 1
		breakIt(&obs)
		if got := reconcile(t, o, stubWitness{obs: obs}).Result; got != model.ReconRequired {
			t.Fatalf("%s: one invocation in an unproven view must stay reconciliation_required, got %q", name, got)
		}
	}
	// CONTROL on the same fixture: one invocation in a PROVEN view does resolve, so
	// the gate is measuring the completeness proof and not a fixture that can never
	// resolve at all.
	ok := baseObservation(o)
	ok.Count, ok.Complete, ok.CompletenessWatermark = 1, true, "wm-1"
	if got := reconcile(t, o, stubWitness{obs: ok}).Result; got != model.ReconReceived {
		t.Fatalf("control: a proven single observation must resolve received, got %q", got)
	}
	// And a DUPLICATE is still a conflict even in a partial view: a duplicate seen is
	// a duplicate, and a wider view could only find more. Completeness must never
	// become a way to downgrade an observed breach.
	dup := baseObservation(o)
	dup.Count, dup.Complete, dup.CompletenessWatermark = 2, false, ""
	if got := reconcile(t, o, stubWitness{obs: dup}).Result; got != model.ReconConflict {
		t.Fatalf("a duplicate must be a conflict regardless of completeness, got %q", got)
	}
}

// TestReconcile_AnUnboundOrphanCannotBeResolvedByAnotherAuthorization pins Codex
// round-4 P2. When the local intent leaves a dimension empty — a legacy or nil-gate
// orphan with no durable ReservationID — "not reported" was read as "agrees", so a
// witness could present a complete view SCOPED TO SOME OTHER AUTHORIZATION and have
// it resolve this orphan. Nothing contradicted, but nothing corroborated either.
func TestReconcile_AnUnboundOrphanCannotBeResolvedByAnotherAuthorization(t *testing.T) {
	unbound := orphanFor(t)
	unbound.ReservationID = "" // no durable binding to corroborate against

	absent := baseObservation(unbound)
	absent.Count, absent.Complete, absent.CompletenessWatermark = 0, true, "wm-1"
	absent.ReservationID = "rsv_someone_else"
	if got := reconcile(t, unbound, stubWitness{obs: absent}).Result; got != model.ReconRequired {
		t.Fatalf("an unbound orphan must not be resolved absent by another authorization's view, got %q", got)
	}

	present := baseObservation(unbound)
	present.Count, present.Complete, present.CompletenessWatermark = 1, true, "wm-1"
	present.ReservationID = "rsv_someone_else"
	if got := reconcile(t, unbound, stubWitness{obs: present}).Result; got != model.ReconRequired {
		t.Fatalf("an unbound orphan must not be resolved received by another authorization's view, got %q", got)
	}

	// CONTROL: the same unbound orphan IS resolvable when the witness reports only
	// dimensions the intent can corroborate. Without this the gate would pass on an
	// implementation that had simply stopped resolving unbound orphans at all.
	ok := baseObservation(unbound)
	ok.Count, ok.Complete, ok.CompletenessWatermark = 0, true, "wm-1"
	ok.ReservationID = ""
	if got := reconcile(t, unbound, stubWitness{obs: ok}).Result; got != model.ReconNotReceived {
		t.Fatalf("control: a corroborated complete zero must resolve not_received, got %q", got)
	}
}

// TestRecovery_ReconciliationAgainstASettledAttemptIsNotDiscarded pins Codex round-4
// P2. Reconciliation evidence for a SETTLED attempt is unusual but reachable — a
// late terminal outcome racing an orphan reconciliation leaves both in the stream —
// and only the orphan branch consulted the index, so it was ignored entirely.
//
// Ignoring it discards one of two authoritative claims about the same physical
// effect and reports the attempt as cleanly settled. A witness saying "never
// received" beside an outcome saying the peer ANSWERED is a direct contradiction,
// and picking a winner would be manufacturing certainty.
func TestRecovery_ReconciliationAgainstASettledAttemptIsNotDiscarded(t *testing.T) {
	id := mustAttemptID(t)
	recon := func(res string, gen uint64, r model.ReconciliationResult) model.Event {
		return model.Event{Phase: model.PhaseReconciliation, Reconciliation: &model.ReconciliationEvidence{
			AttemptID: id, ReservationID: res, ActivationGeneration: gen, Result: r,
		}}
	}
	settled := func(st model.PhysicalSendState) []model.Event {
		return []model.Event{intentEvent(id, "rsv_a", 7), outcomeEvent(id, "rsv_a", 7, st)}
	}
	withRecon := func(st model.PhysicalSendState, ev model.Event) *fixtureReader {
		return readerWith(append(settled(st), ev)...)
	}

	for name, tc := range map[string]struct {
		state model.PhysicalSendState
		ev    model.Event
	}{
		"not_received against a peer that answered": {
			model.SendPeerResponseReceived, recon("rsv_a", 7, model.ReconNotReceived)},
		"not_received against an ambiguous send": {
			model.SendMayHaveBeenSent, recon("rsv_a", 7, model.ReconNotReceived)},
		"received against a provably never-sent outcome": {
			model.SendDefinitelyNotSent, recon("rsv_a", 7, model.ReconReceived)},
		"witness-observed duplicate": {
			model.SendPeerResponseReceived, recon("rsv_a", 7, model.ReconConflict)},
		"wrong reservation": {
			model.SendPeerResponseReceived, recon("rsv_other", 7, model.ReconReceived)},
		"wrong generation": {
			model.SendPeerResponseReceived, recon("rsv_a", 8, model.ReconReceived)},
	} {
		if _, err := RecoverAttempts(withRecon(tc.state, tc.ev)); err == nil {
			t.Fatalf("%s: must fail closed rather than report a clean settled attempt", name)
		}
	}

	// CONTROLS on the same fixture. A settled attempt with NO reconciliation, and one
	// whose reconciliation AGREES, must both still settle — otherwise the gates above
	// would pass on an implementation that had simply stopped settling anything.
	for name, evs := range map[string][]model.Event{
		"no reconciliation": settled(model.SendPeerResponseReceived),
		"corroborating received": append(settled(model.SendPeerResponseReceived),
			recon("rsv_a", 7, model.ReconReceived)),
		"reconciliation_required asserts nothing": append(settled(model.SendPeerResponseReceived),
			recon("rsv_a", 7, model.ReconRequired)),
	} {
		rep, err := RecoverAttempts(readerWith(evs...))
		if err != nil {
			t.Fatalf("control %q: must still settle: %v", name, err)
		}
		if len(rep.Settled) != 1 || len(rep.Orphans) != 0 {
			t.Fatalf("control %q: expected exactly one settled attempt, got %+v", name, rep)
		}
	}
}
