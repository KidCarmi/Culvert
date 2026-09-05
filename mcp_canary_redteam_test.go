package main

// mcp_canary_redteam_test.go — Step 6C: adversarial cases against the ACTUAL
// end-to-end physical-effect path (review blockers #6/#8).
//
// Every case below is dispositioned. There is no "unlikely" outcome: each attack
// lands in exactly one of
//
//	PREVENTED                      — the effect could not happen
//	DETECTED + reconciliation_required — it may have happened; the ledger says so
//	DETECTED + conflict            — the evidence contradicts itself, loudly
//	REMAINING BLOCKER              — recorded as still open, not explained away
//
// The disposition is asserted in the test, not written in a comment, so a change
// that silently downgrades one (say, conflict -> received) fails here.
//
// Anti-vacuity: each negative case is paired with a positive control proving the
// same fixture can reach the peer, persist a valid event, and settle a valid
// attempt. Two defects in this program survived until a control exposed them.

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/execution"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// ── transport-level attacks against the live path ───────────────────────────

// TestRedTeam01_PeerReadsThenRSTsIsExactlyOneEffect — PREVENTED (no second send).
// A peer that fully reads the POST and then resets is the classic
// retry-authorizing shape. It must not produce a second physical invocation.
func TestRedTeam01_PeerReadsThenRSTsIsExactlyOneEffect(t *testing.T) {
	p := startControlledPeer(t, receiveThenDrop)
	rig := armCanaryWithRealPeer(t, p, 10)
	_ = rig.exec(peerExecInput(p, policy.OpRead))
	if got := p.count(); got != 1 {
		t.Fatalf("a read-then-RST peer must receive EXACTLY one invocation, got %d", got)
	}
}

// TestRedTeam02_ResponseLostAfterProcessingIsNeverANonEvent — DETECTED, never
// laundered. The peer processed the call and the response was lost. Culvert cannot
// know the tool did not run, so it must not record that it did not.
func TestRedTeam02_ResponseLostAfterProcessingIsNeverANonEvent(t *testing.T) {
	p := startControlledPeer(t, receiveThenDrop)
	rig := armCanaryWithRealPeer(t, p, 10)
	_ = rig.exec(peerExecInput(p, policy.OpRead))

	rep := rig.recover(t)
	rec, ok := findAttempt(rep, p.observed()[0].AttemptID)
	if !ok {
		t.Fatalf("the invocation must remain attributable: %+v", rep)
	}
	if rec.TerminalSendState == model.SendDefinitelyNotSent {
		t.Fatal("a lost response must never be recorded as definitely_not_sent")
	}
	if !rec.TerminalSendState.MayHaveReachedPeer() {
		t.Fatalf("a lost response must stay possibly-effective, got %q", rec.TerminalSendState)
	}
}

// TestRedTeam03_DeathAfterIntentBeforeSendIsReconciliationRequired — DETECTED +
// reconciliation_required. The most conservative crash point: the intent is durable
// but nothing was sent. Culvert cannot distinguish this from a crash AFTER the send,
// and must not try: both rest at reconciliation_required.
func TestRedTeam03_DeathAfterIntentBeforeSendIsReconciliationRequired(t *testing.T) {
	id := mustAttemptIDMain(t)
	rep, err := execution.RecoverAttempts(mainReaderWith(intentEventMain(id, "rsv_1", 4)))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	rec, ok := findAttempt(rep, id)
	if !ok || rec.State != execution.AttemptReconciliationRequired {
		t.Fatalf("an intent with no outcome must rest at reconciliation_required, got ok=%v rec=%+v", ok, rec)
	}
	if rec.Reconciliation.Resolved() {
		t.Fatalf("recovery alone must not resolve it, got %q", rec.Reconciliation)
	}
	// CONTROL: the same reader with a terminal outcome settles, so the gate above is
	// measuring the missing outcome and not a broken fixture.
	ok2, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(id, "rsv_1", 4),
		outcomeEventMain(id, "rsv_1", 4, model.SendPeerResponseReceived),
	))
	if err != nil || len(ok2.Settled) != 1 || len(ok2.Orphans) != 0 {
		t.Fatalf("control: a complete pair must settle, err=%v rep=%+v", err, ok2)
	}
}

// TestRedTeam04_DeathAfterPeerReceiptIsReconciliationRequired — DETECTED +
// reconciliation_required, proven on the REAL spool with a real physical POST
// already delivered.
func TestRedTeam04_DeathAfterPeerReceiptIsReconciliationRequired(t *testing.T) {
	p := startControlledPeer(t, respondOK)
	rig := armCanaryWithRealPeer(t, p, 10)
	if out := rig.exec(peerExecInput(p, policy.OpRead)); !out.Executed {
		t.Fatalf("setup: the execution must succeed, out=%+v", out)
	}
	attemptID := p.observed()[0].AttemptID

	evs, seqs := rig.spoolEventsAll(t)
	intentSeq, ok := seqOfPhase(evs, seqs, model.PhaseSendIntent, attemptID)
	if !ok {
		t.Fatal("no durable send intent — the crash window would be unrecoverable")
	}
	rep, err := execution.RecoverAttempts(&truncatedReader{src: rig.events.Spool(model.CapGateway), upTo: intentSeq})
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	rec, found := findAttempt(rep, attemptID)
	if !found || rec.State != execution.AttemptReconciliationRequired {
		t.Fatalf("a crash after peer receipt must be reconciliation_required, got found=%v rec=%+v", found, rec)
	}
}

// TestRedTeam05_SpoolRejectsTheOutcomeAfterPeerSuccess — DETECTED +
// reconciliation_required. The peer succeeded but the outcome could not be
// persisted. The invocation happened; the ledger must show an unresolved attempt
// rather than nothing at all.
//
// This is the shape the shipped DecisionRef defect produced on EVERY execution,
// which is why it is a red-team case and not a hypothetical.
func TestRedTeam05_SpoolRejectsTheOutcomeAfterPeerSuccess(t *testing.T) {
	id := mustAttemptIDMain(t)
	// The outcome never landed: only the intent survives.
	rep, err := execution.RecoverAttempts(mainReaderWith(intentEventMain(id, "rsv_9", 2)))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	rec, ok := findAttempt(rep, id)
	if !ok {
		t.Fatal("a rejected outcome must not erase the attempt from the ledger")
	}
	if rec.State != execution.AttemptReconciliationRequired {
		t.Fatalf("want reconciliation_required, got %q", rec.State)
	}
}

// ── evidence-level attacks ──────────────────────────────────────────────────

// TestRedTeam06_MalformedAndOversizedEvidenceIsRefused — PREVENTED at the
// validator. Witness-supplied strings are the only ledger content that originates
// outside this process.
func TestRedTeam06_MalformedAndOversizedEvidenceIsRefused(t *testing.T) {
	// Malformed attempt identity in recovery.
	if _, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain("not-an-attempt-id", "rsv_1", 1),
	)); err == nil {
		t.Fatal("a malformed attempt identity must fail recovery closed")
	}
	// Oversized witness evidence at the validator.
	e := baseReconciliationMain()
	e.Reconciliation.EvidenceDigest = string(make([]byte, 9000))
	if err := e.Validate(); err == nil {
		t.Fatal("oversized witness evidence must be refused")
	}
	// CONTROL: the same fixture, bounded, validates.
	if err := baseReconciliationMain().Validate(); err != nil {
		t.Fatalf("control: the reconciliation fixture must be valid: %v", err)
	}
}

// TestRedTeam07_DuplicatedAttemptIDIsAConflictNotAMerge — DETECTED + fails closed.
// Two intents naming one attempt means the count is no longer trustworthy; silently
// merging them would hide a duplicate physical effect.
func TestRedTeam07_DuplicatedAttemptIDIsAConflictNotAMerge(t *testing.T) {
	id := mustAttemptIDMain(t)
	if _, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(id, "rsv_1", 1), intentEventMain(id, "rsv_2", 1),
	)); err == nil {
		t.Fatal("a duplicated attempt id must fail recovery closed")
	}
}

// TestRedTeam08_RepeatedReservationIDIsNamedAsABreach — DETECTED + conflict.
// Two DISTINCT attempts naming one reservation means one slot authorized two
// potential physical effects — the blocker-#6 invariant breach in ledger form.
//
// This case found a real gap. Recovery listed such attempts individually, which is
// VISIBLE but not the same as DETECTED: nothing distinguished "two attempts" from
// "two attempts one slot paid for". Recovery now names the breach explicitly while
// still returning a usable report, because failing the derivation closed would
// leave the operator with no account of the very attempts that need reconciling.
func TestRedTeam08_RepeatedReservationIDIsNamedAsABreach(t *testing.T) {
	a, b := mustAttemptIDMain(t), mustAttemptIDMain(t)
	rep, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(a, "rsv_same", 1), intentEventMain(b, "rsv_same", 1),
	))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	if !rep.HasReservationBreach() {
		t.Fatal("one reservation bound to two attempts must be NAMED as a breach, not merely listed")
	}
	if len(rep.ReservationBreaches) != 1 || rep.ReservationBreaches[0].ReservationID != "rsv_same" {
		t.Fatalf("the breach must name the offending slot, got %+v", rep.ReservationBreaches)
	}
	if got := rep.ReservationBreaches[0].AttemptIDs; len(got) != 2 {
		t.Fatalf("the breach must name every attempt charged to the slot, got %v", got)
	}
	// Both attempts stay in the report: the breach is additional information, never
	// a reason to lose track of work that still needs reconciling.
	if len(rep.Orphans) != 2 {
		t.Fatalf("both attempts must remain reconcilable, got %+v", rep.Orphans)
	}

	// CONTROL: distinct reservations on the same fixture produce NO breach, so the
	// signal is specific rather than firing on any two attempts.
	clean, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(a, "rsv_one", 1), intentEventMain(b, "rsv_two", 1),
	))
	if err != nil {
		t.Fatalf("control: RecoverAttempts: %v", err)
	}
	if clean.HasReservationBreach() {
		t.Fatalf("control: distinct reservations must not report a breach, got %+v", clean.ReservationBreaches)
	}

	// CONTROL: an attempt with NO reservation identity must not fabricate a breach —
	// an empty id names no slot, and a false breach would discredit the real signal.
	legacy, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(a, "", 1), intentEventMain(b, "", 1),
	))
	if err != nil {
		t.Fatalf("control: RecoverAttempts: %v", err)
	}
	if legacy.HasReservationBreach() {
		t.Fatalf("control: empty reservation ids must not group into a breach, got %+v", legacy.ReservationBreaches)
	}
}

// TestRedTeam09_OldGenerationEvidenceReplayedGrantsNothing — PREVENTED. Replaying a
// superseded generation's evidence into recovery must not confer any authority on
// the current generation.
func TestRedTeam09_OldGenerationEvidenceReplayedGrantsNothing(t *testing.T) {
	old, cur := mustAttemptIDMain(t), mustAttemptIDMain(t)
	rep, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(old, "rsv_old", 1),
		intentEventMain(cur, "rsv_new", 9),
		outcomeEventMain(cur, "rsv_new", 9, model.SendPeerResponseReceived),
	))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	if len(rep.Orphans) != 1 || rep.Orphans[0].ActivationGeneration != 1 {
		t.Fatalf("the replayed old-generation attempt must stay a generation-1 orphan, got %+v", rep.Orphans)
	}
	if len(rep.Settled) != 1 || rep.Settled[0].ActivationGeneration != 9 {
		t.Fatalf("the current generation must be unaffected, got %+v", rep.Settled)
	}
}

// TestRedTeam10_OutcomeWithWrongReservationFailsClosed — DETECTED + fails closed.
// An outcome that names the right attempt but the wrong reservation is contradictory
// evidence; accepting it would let an effect be charged to a slot that did not
// authorize it.
func TestRedTeam10_OutcomeWithWrongReservationFailsClosed(t *testing.T) {
	id := mustAttemptIDMain(t)
	if _, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(id, "rsv_authorized", 1),
		outcomeEventMain(id, "rsv_other", 1, model.SendPeerResponseReceived),
	)); err == nil {
		t.Fatal("an outcome naming a different reservation must fail closed")
	}
	// CONTROL: the matching pair settles.
	rep, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(id, "rsv_authorized", 1),
		outcomeEventMain(id, "rsv_authorized", 1, model.SendPeerResponseReceived),
	))
	if err != nil || len(rep.Settled) != 1 {
		t.Fatalf("control: a matching pair must settle, err=%v rep=%+v", err, rep)
	}
}

// TestRedTeam11_OutcomeWithWrongGenerationFailsClosed — DETECTED + fails closed.
func TestRedTeam11_OutcomeWithWrongGenerationFailsClosed(t *testing.T) {
	id := mustAttemptIDMain(t)
	if _, err := execution.RecoverAttempts(mainReaderWith(
		intentEventMain(id, "rsv_1", 3),
		outcomeEventMain(id, "rsv_1", 4, model.SendPeerResponseReceived),
	)); err == nil {
		t.Fatal("an outcome naming a different activation generation must fail closed")
	}
}

// TestRedTeam12_WitnessSeesTwoPOSTsForOneAttemptIsConflict — DETECTED + conflict.
// This is the physical-effect invariant breach itself. It must NEVER normalize to
// "received": reporting a duplicate effect as a success is the one outcome that
// would hide the thing blocker #6 exists to make countable.
func TestRedTeam12_WitnessSeesTwoPOSTsForOneAttemptIsConflict(t *testing.T) {
	orphan := execution.RecoveredAttempt{
		AttemptID: mustAttemptIDMain(t), ReservationID: "rsv_1", ActivationGeneration: 1,
		State: execution.AttemptReconciliationRequired,
	}
	w := fixedWitness{obs: execution.WitnessObservation{
		Count: 2, Complete: true, CompletenessWatermark: "wm-1",
		ServerID: "s1", Method: "tools/call", ReservationID: "rsv_1", Source: "controlled",
	}}
	ev, err := execution.ReconcileOrphan(context.Background(), w, orphan, "s1", "tools/call", 1)
	if err != nil {
		t.Fatalf("ReconcileOrphan: %v", err)
	}
	if ev.Result != model.ReconConflict {
		t.Fatalf("two physical invocations for one attempt must be a CONFLICT, got %q", ev.Result)
	}
	if ev.ObservationCount != 2 {
		t.Fatalf("the observed count must be retained verbatim, got %d", ev.ObservationCount)
	}
	// CONTROL: exactly one receipt on the same fixture resolves received, so the
	// gate measures the duplicate and not a fixture that can never resolve.
	w1 := w
	w1.obs.Count = 1
	ev1, err := execution.ReconcileOrphan(context.Background(), w1, orphan, "s1", "tools/call", 1)
	if err != nil || ev1.Result != model.ReconReceived {
		t.Fatalf("control: one receipt must resolve received, err=%v result=%q", err, ev1.Result)
	}
}

// TestRedTeam13_AuxiliaryPOSTsInterleavedAreNotCounted — PREVENTED. Lifecycle and
// discovery traffic between tool calls must not inflate the physical-effect count
// or consume a reservation.
func TestRedTeam13_AuxiliaryPOSTsInterleavedAreNotCounted(t *testing.T) {
	for _, aux := range []string{"initialize", "notifications/initialized", "ping", "tools/list"} {
		if upstreamclient.ClassifyMethod(aux).SideEffectBearing() {
			t.Fatalf("%q must not be counted as a physical tool effect", aux)
		}
	}
	// CONTROLS: the metered method IS counted, and an unknown method fails CLOSED as
	// counted — so the exclusion above is a specific allowlist, not a blanket.
	if !upstreamclient.ClassifyMethod("tools/call").SideEffectBearing() {
		t.Fatal("control: tools/call must be side-effect-bearing")
	}
	if !upstreamclient.ClassifyMethod("vendor/undocumented").SideEffectBearing() {
		t.Fatal("control: an unknown method must fail closed as side-effect-bearing")
	}
}

// TestRedTeam14_KillDuringTheHistoricalRetryWindowCannotResend — PREVENTED. Under
// the historical retry behavior a re-send happened with NO kill re-read between
// attempts. Retry-free removes the window entirely: there is no second attempt for
// a kill to have to race.
func TestRedTeam14_KillDuringTheHistoricalRetryWindowCannotResend(t *testing.T) {
	p := startControlledPeer(t, receiveThenDrop)
	rig := armCanaryWithRealPeer(t, p, 10)
	_ = rig.exec(peerExecInput(p, policy.OpRead))
	if got := p.count(); got != 1 {
		t.Fatalf("there must be no retry window at all, peer saw %d POSTs", got)
	}
	engageKillForTest(t)
	before := p.count()
	_ = rig.exec(peerExecInput(p, policy.OpRead))
	if p.count() != before {
		t.Fatalf("a killed gateway must send nothing: %d -> %d", before, p.count())
	}
}

// TestRedTeam15_RepeatedRestartsKeepTheOrphanStable — DETECTED, stable. Deriving the
// same ledger many times must yield the same unresolved orphan: recovery is a pure
// function of durable evidence, so a restart loop cannot drift an attempt toward
// "settled" or lose it.
func TestRedTeam15_RepeatedRestartsKeepTheOrphanStable(t *testing.T) {
	id := mustAttemptIDMain(t)
	r := mainReaderWith(intentEventMain(id, "rsv_1", 5))
	for i := 0; i < 25; i++ {
		rep, err := execution.RecoverAttempts(r)
		if err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		if len(rep.Orphans) != 1 || len(rep.Settled) != 0 {
			t.Fatalf("restart %d drifted: %+v", i, rep)
		}
		if rep.Orphans[0].State != execution.AttemptReconciliationRequired {
			t.Fatalf("restart %d changed the state to %q", i, rep.Orphans[0].State)
		}
	}
}

// TestRedTeam16_ValidatorRejectsWhatAPermissiveSinkWouldAccept — the PROOF RULE as
// an adversarial case. A test sink that does not validate accepts an event the real
// validator refuses; only the validator-backed path can be trusted as evidence of
// durable truth.
func TestRedTeam16_ValidatorRejectsWhatAPermissiveSinkWouldAccept(t *testing.T) {
	e := outcomeEventFixture()
	e.Outcome.DecisionRef = "" // the shipped defect
	if err := e.Validate(); err == nil {
		t.Fatal("the real validator must reject an outcome with no decision ref")
	}
	// A permissive sink accepts it — demonstrated, not asserted about, so the claim
	// "a fake sink is not sufficient proof" is grounded in this tree.
	sink := permissiveSink{}
	if err := sink.accept(e); err != nil {
		t.Fatalf("control: a permissive sink accepts the invalid event by construction: %v", err)
	}
	// CONTROL: the valid fixture passes both.
	if err := outcomeEventFixture().Validate(); err != nil {
		t.Fatalf("control: the valid fixture must validate: %v", err)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// permissiveSink models the shape of a non-validating test sink: it accepts
// anything. It exists so TestRedTeam16 can DEMONSTRATE the gap rather than assert
// that it exists.
type permissiveSink struct{}

func (permissiveSink) accept(model.Event) error { return nil }

// baseReconciliationMain is a valid PhaseReconciliation event for package-main gates.
func baseReconciliationMain() model.Event {
	e := outcomeEventFixture()
	e.Phase = model.PhaseReconciliation
	e.Outcome = nil
	e.Reconciliation = &model.ReconciliationEvidence{
		AttemptID: "att_0001", Result: model.ReconRequired, ReconciledAtUnixNano: 3,
	}
	return e
}
