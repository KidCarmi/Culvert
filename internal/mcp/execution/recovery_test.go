package execution

// recovery_test.go — deterministic orphan-recovery gates (review §10).
// No sleeps and no real crashes: a crash is modelled exactly as it appears in the
// durable ledger — an intent that was committed and an outcome that never was.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// fixtureReader is a deterministic EvidenceReader over an in-memory event list.
// It reproduces the real reader's paging contract so recovery's loop is exercised
// rather than bypassed.
type fixtureReader struct {
	byPart map[model.Partition][]model.Event
	failOn model.Partition // when set, this partition reports unreadable evidence
	hasErr bool
}

func (f *fixtureReader) CommittedForExport(part model.Partition, after uint64, maxRecords int) ([]model.Event, []uint64, uint64, error) {
	if f.hasErr && part == f.failOn {
		return nil, nil, after, errUnreadableFixture
	}
	all := f.byPart[part]
	// Paginate in uint64 space throughout: narrowing the cursor to int to compare it
	// against len() is the conversion gosec flags, and it is avoidable here rather
	// than worth suppressing.
	total := uint64(len(all))
	if after >= total {
		return nil, nil, after, nil
	}
	end := total
	if maxRecords > 0 {
		if n := after + uint64(maxRecords); n < end {
			end = n
		}
	}
	out := all[after:end]
	seqs := make([]uint64, 0, len(out))
	for i := range out {
		seqs = append(seqs, after+uint64(i)+1)
	}
	return out, seqs, end, nil
}

var errUnreadableFixture = &fixtureErr{}

type fixtureErr struct{}

func (*fixtureErr) Error() string { return "unreadable" }

func mustAttemptID(t *testing.T) string {
	t.Helper()
	id, err := newAttemptID()
	if err != nil {
		t.Fatalf("newAttemptID: %v", err)
	}
	return id
}

func intentEvent(id, resID string, gen uint64) model.Event {
	return model.Event{Phase: model.PhaseSendIntent, Outcome: &model.OutcomeEvidence{
		AttemptID: id, ReservationID: resID, ActivationGeneration: gen,
	}}
}

func outcomeEvent(id, resID string, gen uint64, st model.PhysicalSendState) model.Event {
	return model.Event{Phase: model.PhaseOutcome, Outcome: &model.OutcomeEvidence{
		AttemptID: id, ReservationID: resID, ActivationGeneration: gen, PhysicalSendState: st,
	}}
}

func readerWith(evs ...model.Event) *fixtureReader {
	return &fixtureReader{byPart: map[model.Partition][]model.Event{model.PartOrd: evs}}
}

// (1) Intent committed, no send, crash. (2) Intent committed, peer received the
// request, crash before outcome. Both look IDENTICAL in the ledger — which is
// exactly why the recovered state is reconciliation_required and not
// may_have_been_sent: the record cannot distinguish them, so it must not claim to.
func TestRecovery_IntentWithoutOutcomeIsOrphan(t *testing.T) {
	id := mustAttemptID(t)
	rep, err := RecoverAttempts(readerWith(intentEvent(id, "rsv_1", 7)))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	if len(rep.Orphans) != 1 || len(rep.Settled) != 0 {
		t.Fatalf("expected exactly one orphan, got %d orphans / %d settled", len(rep.Orphans), len(rep.Settled))
	}
	o := rep.Orphans[0]
	if o.AttemptID != id || o.ReservationID != "rsv_1" || o.ActivationGeneration != 7 {
		t.Fatalf("orphan must retain the ORIGINAL identity, got %+v", o)
	}
	if o.State != AttemptReconciliationRequired {
		t.Fatalf("orphan state must be reconciliation_required, got %q", o.State)
	}
	if o.TerminalSendState != model.SendStateUnset {
		t.Fatalf("recovery must not synthesize a send state for an orphan, got %q", o.TerminalSendState)
	}
	// The subtle rule: an orphan is NOT may_have_been_sent. A surviving path that
	// began the call may assert that; a crashed process knows strictly less.
	if o.TerminalSendState == model.SendMayHaveBeenSent {
		t.Fatal("an orphan must not be recorded as may_have_been_sent")
	}
}

// (3) Intent + valid outcome ⇒ NOT an orphan.
func TestRecovery_IntentWithValidOutcomeIsSettled(t *testing.T) {
	id := mustAttemptID(t)
	rep, err := RecoverAttempts(readerWith(
		intentEvent(id, "rsv_1", 7),
		outcomeEvent(id, "rsv_1", 7, model.SendPeerResponseReceived),
	))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	if len(rep.Orphans) != 0 || len(rep.Settled) != 1 {
		t.Fatalf("expected settled, got %d orphans / %d settled", len(rep.Orphans), len(rep.Settled))
	}
	if rep.Settled[0].TerminalSendState != model.SendPeerResponseReceived {
		t.Fatalf("settled attempt must carry its committed send state, got %q", rep.Settled[0].TerminalSendState)
	}
}

// (4) Corrupted outcome must fail closed — never be read as "completed".
func TestRecovery_CorruptedOutcomeFailsClosed(t *testing.T) {
	id := mustAttemptID(t)
	_, err := RecoverAttempts(readerWith(
		intentEvent(id, "rsv_1", 7),
		outcomeEvent(id, "rsv_1", 7, model.PhysicalSendState("not_a_real_state")),
	))
	if err == nil {
		t.Fatal("an unknown physical send state must fail closed, not settle the attempt")
	}
}

// (5) Mismatched reservation / generation must fail closed.
func TestRecovery_MismatchedBindingFailsClosed(t *testing.T) {
	id := mustAttemptID(t)
	t.Run("reservation", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_1", 7),
			outcomeEvent(id, "rsv_OTHER", 7, model.SendPeerResponseReceived),
		)); err == nil {
			t.Fatal("reservation mismatch must fail closed")
		}
	})
	t.Run("generation", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_1", 7),
			outcomeEvent(id, "rsv_1", 9, model.SendPeerResponseReceived),
		)); err == nil {
			t.Fatal("generation mismatch must fail closed")
		}
	})
}

// Ambiguity is unsafe evidence: never silently pick the newest record.
func TestRecovery_DuplicateAndUnpairedRecordsFailClosed(t *testing.T) {
	id := mustAttemptID(t)
	t.Run("duplicate intent", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_1", 7), intentEvent(id, "rsv_1", 7),
		)); err == nil {
			t.Fatal("duplicate send intents for one attempt must fail closed")
		}
	})
	t.Run("multiple outcomes", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent(id, "rsv_1", 7),
			outcomeEvent(id, "rsv_1", 7, model.SendPeerResponseReceived),
			outcomeEvent(id, "rsv_1", 7, model.SendDefinitelyNotSent),
		)); err == nil {
			t.Fatal("multiple terminal outcomes for one attempt must fail closed")
		}
	})
	t.Run("outcome without intent", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			outcomeEvent(id, "rsv_1", 7, model.SendPeerResponseReceived),
		)); err == nil {
			t.Fatal("a terminal outcome with no authorizing intent must fail closed")
		}
	})
	t.Run("malformed attempt id", func(t *testing.T) {
		if _, err := RecoverAttempts(readerWith(
			intentEvent("not-a-minted-id", "rsv_1", 7),
		)); err == nil {
			t.Fatal("a malformed attempt identity must fail closed")
		}
	})
}

// Unreadable evidence is not an empty ledger.
func TestRecovery_UnreadableEvidenceFailsClosed(t *testing.T) {
	r := readerWith(intentEvent(mustAttemptID(t), "rsv_1", 7))
	r.hasErr, r.failOn = true, model.PartOrd
	if _, err := RecoverAttempts(r); err == nil {
		t.Fatal("unreadable durable evidence must fail closed, not report zero orphans")
	}
}

// (6) Repeated restart: recovery is stable and idempotent over the same ledger.
func TestRecovery_RepeatedRestartIsIdempotent(t *testing.T) {
	a, b := mustAttemptID(t), mustAttemptID(t)
	r := readerWith(intentEvent(a, "rsv_a", 7), intentEvent(b, "rsv_b", 7))
	first, err := RecoverAttempts(r)
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := RecoverAttempts(r)
		if err != nil {
			t.Fatalf("restart %d: %v", i, err)
		}
		if len(again.Orphans) != len(first.Orphans) {
			t.Fatalf("restart %d changed the orphan set: %d vs %d", i, len(again.Orphans), len(first.Orphans))
		}
		for j := range again.Orphans {
			if again.Orphans[j] != first.Orphans[j] {
				t.Fatalf("restart %d mutated orphan %d: %+v vs %+v", i, j, again.Orphans[j], first.Orphans[j])
			}
		}
	}
}

// (7) Restart under a NEWER generation: the old orphan remains historical. It stays
// visible, keeps its original generation, and never becomes allowance for G+1.
func TestRecovery_OldGenerationOrphanStaysHistorical(t *testing.T) {
	oldID, newID := mustAttemptID(t), mustAttemptID(t)
	rep, err := RecoverAttempts(readerWith(
		intentEvent(oldID, "rsv_old", 7),
		intentEvent(newID, "rsv_new", 8),
		outcomeEvent(newID, "rsv_new", 8, model.SendPeerResponseReceived),
	))
	if err != nil {
		t.Fatalf("RecoverAttempts: %v", err)
	}
	if len(rep.Orphans) != 1 {
		t.Fatalf("the generation-7 orphan must remain visible under generation 8, got %d", len(rep.Orphans))
	}
	if rep.Orphans[0].ActivationGeneration != 7 {
		t.Fatalf("orphan must retain its ORIGINAL generation, got %d", rep.Orphans[0].ActivationGeneration)
	}
	if rep.Orphans[0].AttemptID != oldID {
		t.Fatal("recovery must never mint a new attempt identity")
	}
	// The recovery surface exposes no execution capability at all: it returns
	// evidence, never a resend handle. That is the structural reason an orphan
	// cannot become allowance in a later generation.
}
