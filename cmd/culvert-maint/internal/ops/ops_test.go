package ops

import (
	"strings"
	"testing"
	"time"
)

func TestNewID_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		id := NewID()
		if len(id) != 26 { // ULID canonical length
			t.Fatalf("ULID length: got %d (id=%q)", len(id), id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("ULID collision at %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestState_IsTerminal(t *testing.T) {
	if StatePending.IsTerminal() || StateRunning.IsTerminal() {
		t.Fatal("pending/running must not be terminal")
	}
	for _, s := range []State{StateSucceeded, StateFailed, StateCancelled} {
		if !s.IsTerminal() {
			t.Errorf("%s should be terminal", s)
		}
	}
}

func TestIsStateChanging_D16a_NoProductionKinds(t *testing.T) {
	// Synthetic kind is the only state-changing kind in D1.6a — used
	// by tests to exercise the lock framework without introducing
	// real production state-changing operations.
	if !IsStateChanging(SyntheticStateChangingKind) {
		t.Errorf("%q (synthetic, test-only) should be state-changing", SyntheticStateChangingKind)
	}

	// D1.6b/c kinds are NOT yet wired in production; they must NOT be
	// reported as state-changing in D1.6a. When D1.6b lands, the
	// stateChangingKinds map will gain these entries together with
	// matching handler + template + sudoers + tests.
	for _, k := range []string{
		"backup.create",
		"restore.commit",
		"cleanups.create",
		"upgrades.apply",
		"rollbacks.create",
	} {
		if IsStateChanging(k) {
			t.Errorf("D1.6a must not treat %q as state-changing — that kind belongs to a future slice", k)
		}
	}

	// Read-only kinds and unknowns are never state-changing.
	for _, k := range []string{"restore.dryrun", "upgrades.check", "status.read", "unknown.kind", ""} {
		if IsStateChanging(k) {
			t.Errorf("%q should NOT be state-changing", k)
		}
	}
}

func TestManager_Begin_RejectsEmptyKindOrActor(t *testing.T) {
	m := NewManager(nil)
	if _, err := m.Begin("", "actor", "", nil); err == nil {
		t.Error("expected error for empty kind")
	}
	if _, err := m.Begin("kind", "", "", nil); err == nil {
		t.Error("expected error for empty actor")
	}
}

func TestManager_ReadOnlyOpsRunConcurrently(t *testing.T) {
	m := NewManager(nil)
	o1, err := m.Begin("status.read", "actor1", "", nil)
	if err != nil {
		t.Fatalf("first read-only: %v", err)
	}
	o2, err := m.Begin("status.read", "actor2", "", nil)
	if err != nil {
		t.Fatalf("second read-only must not conflict: %v", err)
	}
	if o1.ID == o2.ID {
		t.Fatalf("op IDs should be unique")
	}
	if m.Holder() != nil {
		t.Errorf("read-only ops must not hold the maintenance lock")
	}
}

func TestManager_StateChangingOpAcquiresLock(t *testing.T) {
	m := NewManager(nil)
	op, err := m.Begin(SyntheticStateChangingKind, "actor", "", nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if op.LockHeldBy != op.ID {
		t.Errorf("lock_held_by should equal op_id, got %q want %q", op.LockHeldBy, op.ID)
	}
	holder := m.Holder()
	if holder == nil || holder.ID != op.ID {
		t.Errorf("Holder() should reflect the running op")
	}
}

func TestManager_SecondStateChangingOpReturnsConflict(t *testing.T) {
	m := NewManager(nil)
	o1, err := m.Begin(SyntheticStateChangingKind, "actor1", "", nil)
	if err != nil {
		t.Fatalf("first state-changing: %v", err)
	}
	_, err = m.Begin(SyntheticStateChangingKind, "actor2", "", nil)
	if err == nil {
		t.Fatal("expected conflict on second state-changing op")
	}
	if !IsConflict(err) {
		t.Fatalf("expected *Conflict, got %T: %v", err, err)
	}
	var c *Conflict
	if !asConflict(err, &c) {
		t.Fatalf("Conflict assertion failed")
	}
	if c.Holder == nil || c.Holder.ID != o1.ID {
		t.Errorf("Conflict.Holder should be the first op (id=%s)", o1.ID)
	}
	if !strings.Contains(c.Error(), o1.Kind) {
		t.Errorf("Conflict.Error should name holder kind, got: %v", c)
	}
}

// asConflict avoids importing errors.As inline in the test for clarity.
func asConflict(err error, out **Conflict) bool {
	c, ok := err.(*Conflict)
	if ok {
		*out = c
	}
	return ok
}

func TestManager_FinishReleasesLockAndAllowsNextOp(t *testing.T) {
	m := NewManager(nil)
	o1, err := m.Begin(SyntheticStateChangingKind, "actor1", "", nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := m.Finish(o1.ID, StateSucceeded, "", nil); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if m.Holder() != nil {
		t.Errorf("Holder must be nil after Finish")
	}
	o2, err := m.Begin(SyntheticStateChangingKind, "actor2", "", nil)
	if err != nil {
		t.Fatalf("second op should now succeed: %v", err)
	}
	if o2.LockHeldBy != o2.ID {
		t.Errorf("second op should hold the lock")
	}
}

func TestManager_FinishRecordsTerminalStateAndReason(t *testing.T) {
	clock := time.Date(2026, 5, 3, 1, 23, 45, 0, time.UTC)
	m := NewManager(func() time.Time { return clock })
	op, err := m.Begin(SyntheticStateChangingKind, "actor", "", nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := m.Finish(op.ID, StateFailed, ReasonTimeout, map[string]interface{}{"err": "boom"}); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	got := m.Get(op.ID)
	if got.State != StateFailed {
		t.Errorf("state: got %s", got.State)
	}
	if got.FailureReason != string(ReasonTimeout) {
		t.Errorf("failure_reason: got %s", got.FailureReason)
	}
	if got.Finished == nil || !got.Finished.Equal(clock) {
		t.Errorf("Finished timestamp: got %v want %v", got.Finished, clock)
	}
	if got.Result["err"] != "boom" {
		t.Errorf("result lost")
	}
}

func TestManager_FinishRejectsNonTerminalState(t *testing.T) {
	m := NewManager(nil)
	op, _ := m.Begin(SyntheticStateChangingKind, "a", "", nil)
	if err := m.Finish(op.ID, StateRunning, "", nil); err == nil {
		t.Error("expected error finishing into running")
	}
	if err := m.Finish(op.ID, StatePending, "", nil); err == nil {
		t.Error("expected error finishing into pending")
	}
}

func TestManager_FinishUnknownIDFails(t *testing.T) {
	m := NewManager(nil)
	if err := m.Finish("not-a-real-id", StateSucceeded, "", nil); err == nil {
		t.Error("expected error for unknown op_id")
	}
}

func TestManager_AddStageAppendsAndStamps(t *testing.T) {
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m := NewManager(func() time.Time { return clock })
	op, _ := m.Begin(SyntheticStateChangingKind, "actor", "", nil)

	if err := m.AddStage(op.ID, Stage{Name: "preflight", State: StateSucceeded}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}
	if err := m.AddStage(op.ID, Stage{Name: "compose-run", State: StateRunning}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	got := m.Get(op.ID)
	if len(got.Progress) != 2 {
		t.Fatalf("want 2 stages, got %d", len(got.Progress))
	}
	for i, s := range got.Progress {
		if s.Started.IsZero() {
			t.Errorf("stage %d Started must be stamped", i)
		}
	}
}

func TestManager_GetReturnsSnapshot(t *testing.T) {
	m := NewManager(nil)
	op, _ := m.Begin(SyntheticStateChangingKind, "actor", "", map[string]interface{}{"k": "v"})

	snap := m.Get(op.ID)
	if snap == nil {
		t.Fatal("Get nil")
	}
	// Mutate the snapshot; internal state must not change.
	snap.Params["k"] = "MUTATED"
	got := m.Get(op.ID)
	if got.Params["k"] != "v" {
		t.Errorf("Get must return defensive copy; got %v", got.Params["k"])
	}
}

func TestManager_GetUnknownReturnsNil(t *testing.T) {
	m := NewManager(nil)
	if op := m.Get("does-not-exist"); op != nil {
		t.Errorf("Get unknown id: want nil, got %v", op)
	}
}

func TestManager_MarkAllInterruptedReturnsZeroForD16a(t *testing.T) {
	m := NewManager(nil)
	if n := m.MarkAllInterrupted(); n != 0 {
		t.Errorf("D1.6a in-memory model has nothing to scan, got %d", n)
	}
}

func TestManager_BeginStoresIdempotencyKey(t *testing.T) {
	m := NewManager(nil)
	op, _ := m.Begin(SyntheticStateChangingKind, "a", "abc-123", nil)
	got := m.Get(op.ID)
	if got.IdempotencyKey != "abc-123" {
		t.Errorf("idempotency_key: got %q", got.IdempotencyKey)
	}
}
