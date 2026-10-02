package ops

import (
	"path/filepath"
	"testing"
	"time"
)

// OverrideInterrupted re-terminalizes ONLY an interrupted op; a real terminal
// outcome is never rewritten.
func TestOverrideInterrupted_NarrowToInterruptedOps(t *testing.T) {
	m := NewManager(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	m.MarkAllInterrupted([]InterruptedOp{{OpID: "01HX0000000000000000000001", Kind: KindUpgradeApply, Actor: "cp"}})
	if err := m.OverrideInterrupted("01HX0000000000000000000001", StateSucceeded, "", map[string]interface{}{"reconciled": true}); err != nil {
		t.Fatalf("override interrupted: %v", err)
	}
	op := m.Get("01HX0000000000000000000001")
	if op.State != StateSucceeded || op.FailureReason != "" || op.Result["reconciled"] != true {
		t.Fatalf("op after override: %+v", op)
	}
	// Second override: no longer interrupted → refused.
	if err := m.OverrideInterrupted("01HX0000000000000000000001", StateFailed, ReasonHealthFailed, nil); err == nil {
		t.Fatal("override of a non-interrupted op must be refused")
	}
	// A genuinely failed op is never rewritten.
	genuine, _ := m.Begin(KindUpgradeApply, "cp", "", nil)
	_ = m.Finish(genuine.ID, StateFailed, ReasonHealthFailed, nil)
	if err := m.OverrideInterrupted(genuine.ID, StateSucceeded, "", nil); err == nil {
		t.Fatal("override of a real failure must be refused")
	}
	if err := m.OverrideInterrupted("unknown", StateSucceeded, "", nil); err == nil {
		t.Fatal("unknown op must be refused")
	}
	if err := m.OverrideInterrupted(genuine.ID, StateRunning, "", nil); err == nil {
		t.Fatal("non-terminal state must be refused")
	}
}

// A reconciled verdict must survive the NEXT restart. The agent's startup
// order is MarkAllInterrupted (journal, no idempotency key on the op) → load
// the idempotency index → ReconcileOnStartup → OverrideInterrupted; the
// override used to update only the in-memory op, so the persisted record kept
// its non-terminal admission state and a third process materialized the same
// op as failed(agent_restart_interrupted) — a retry with the original key got
// the wrong answer (Codex review, PR #1528). Verified failing against the
// pre-fix OverrideInterrupted.
func TestOverrideInterrupted_PersistsReconciledOutcomeAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()

	// Process 1: admit a keyed op and crash before it finishes.
	m1 := idempMgr(t, dir, func() time.Time { return now })
	op, _, err := m1.BeginIdempotent(KindUpgradeApply, "cp", "k-reconcile", map[string]interface{}{"image_ref": "x"})
	if err != nil {
		t.Fatal(err)
	}

	// Process 2: the real startup order — journal Phase A first (no key on
	// the op), THEN the index, THEN the reconciler's override.
	m2 := NewManager(func() time.Time { return now.Add(time.Minute) })
	m2.MarkAllInterrupted([]InterruptedOp{{OpID: op.ID, Kind: KindUpgradeApply, Actor: "cp"}})
	m2.EnableIdempotencyPersistence(filepath.Join(dir, "idempotency.json"))
	if _, err := m2.LoadIdempotencyIndex(); err != nil {
		t.Fatal(err)
	}
	if got := m2.Get(op.ID); got == nil || got.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Fatalf("precondition: op should be interrupted, got %+v", got)
	}
	if err := m2.OverrideInterrupted(op.ID, StateSucceeded, "", map[string]interface{}{"reconciled": true}); err != nil {
		t.Fatal(err)
	}
	if m2.IdempPersistErrors() != 0 {
		t.Fatalf("persist errors: %d", m2.IdempPersistErrors())
	}

	// Process 3: a fresh load must see the reconciled outcome, and the
	// original idempotency key must dedupe to it.
	m3 := idempMgr(t, dir, func() time.Time { return now.Add(2 * time.Minute) })
	got := m3.Get(op.ID)
	if got == nil || got.State != StateSucceeded || got.FailureReason != "" || got.Result["reconciled"] != true {
		t.Fatalf("reconciled outcome did not survive the restart: %+v", got)
	}
	again, deduped, err := m3.BeginIdempotent(KindUpgradeApply, "cp", "k-reconcile", nil)
	if err != nil || !deduped || again.ID != op.ID || again.State != StateSucceeded {
		t.Fatalf("retry with the original key: deduped=%v err=%v op=%+v", deduped, err, again)
	}
}
