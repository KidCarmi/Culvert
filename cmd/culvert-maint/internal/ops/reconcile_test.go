package ops

import (
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
