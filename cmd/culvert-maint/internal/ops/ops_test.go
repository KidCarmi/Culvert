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

func TestIsStateChanging_ProductionAndFutureKinds(t *testing.T) {
	// Synthetic kind is reserved for tests that need to exercise the
	// lock framework without depending on a specific production kind.
	if !IsStateChanging(SyntheticStateChangingKind) {
		t.Errorf("%q (synthetic, test-only) should be state-changing", SyntheticStateChangingKind)
	}

	// State-changing production kinds (D1.6b + D1.6c upgrade apply +
	// image rollback).
	for _, k := range []string{KindBackupCreate, KindRestoreCommit, KindCleanupCommit, KindUpgradeApply, KindRollbackCreate} {
		if !IsStateChanging(k) {
			t.Errorf("production kind %q must be state-changing", k)
		}
	}

	// Read-only kinds and unknowns are never state-changing.
	for _, k := range []string{
		KindBackupList, KindRestoreDryRun, KindCleanupDryRun,
		"upgrades.check", "status.read", "unknown.kind", "",
	} {
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

// D1.6b — production state-changing kinds.
func TestIsStateChanging_D16bKinds(t *testing.T) {
	for _, k := range []string{KindBackupCreate, KindRestoreCommit, KindCleanupCommit} {
		if !IsStateChanging(k) {
			t.Errorf("%s should be state-changing", k)
		}
	}
	for _, k := range []string{KindBackupList, KindRestoreDryRun, KindCleanupDryRun} {
		if IsStateChanging(k) {
			t.Errorf("%s must NOT be state-changing (read-only)", k)
		}
	}
}

// D1.6b — idempotency dedup.
func TestBeginIdempotent_DupReturnsSameOp(t *testing.T) {
	m := NewManager(nil)
	a, deduped, err := m.BeginIdempotent(KindBackupList, "uid=1,user=cp", "key-A", nil)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if deduped {
		t.Errorf("first call must not be deduped")
	}
	b, deduped, err := m.BeginIdempotent(KindBackupList, "uid=1,user=cp", "key-A", nil)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if !deduped {
		t.Errorf("second call with same (actor,kind,key) must be deduped")
	}
	if b.ID != a.ID {
		t.Errorf("dedup must return same op_id; got %s vs %s", b.ID, a.ID)
	}
}

func TestBeginIdempotent_DifferentActorIsNotDeduped(t *testing.T) {
	m := NewManager(nil)
	a, _, err := m.BeginIdempotent(KindBackupList, "uid=1,user=cp", "k", nil)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, deduped, err := m.BeginIdempotent(KindBackupList, "uid=2,user=other", "k", nil)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if deduped || b.ID == a.ID {
		t.Errorf("same key + different actor must produce a fresh op")
	}
}

func TestBeginIdempotent_DifferentKindIsNotDeduped(t *testing.T) {
	m := NewManager(nil)
	a, _, _ := m.BeginIdempotent(KindBackupList, "uid=1,user=cp", "k", nil)
	b, deduped, _ := m.BeginIdempotent(KindRestoreDryRun, "uid=1,user=cp", "k", nil)
	if deduped || b.ID == a.ID {
		t.Errorf("same actor+key but different kind must produce a fresh op")
	}
}

func TestBeginIdempotent_EmptyKeyDisablesDedup(t *testing.T) {
	m := NewManager(nil)
	a, deduped, _ := m.BeginIdempotent(KindBackupList, "uid=1", "", nil)
	if deduped {
		t.Error("first call without key cannot be deduped")
	}
	b, deduped, _ := m.BeginIdempotent(KindBackupList, "uid=1", "", nil)
	if deduped {
		t.Error("empty key must always admit a fresh op")
	}
	if b.ID == a.ID {
		t.Errorf("empty key must produce distinct op_ids; got same: %s", a.ID)
	}
}

// Dedup runs BEFORE the lock check: a second submission of a
// state-changing op with a duplicate key must NOT return 409.
func TestBeginIdempotent_DedupBeforeLockCheck(t *testing.T) {
	m := NewManager(nil)
	a, _, err := m.BeginIdempotent(KindBackupCreate, "uid=1,user=cp", "k", nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	b, deduped, err := m.BeginIdempotent(KindBackupCreate, "uid=1,user=cp", "k", nil)
	if err != nil {
		t.Fatalf("dup must not 409: %v", err)
	}
	if !deduped {
		t.Error("dup state-changing call should be deduped, not blocked by lock")
	}
	if b.ID != a.ID {
		t.Errorf("dedup must return original op_id")
	}
	if IsConflict(err) {
		t.Errorf("dup must NOT be Conflict")
	}
}

// Item #10: idempotency cache TTL + opportunistic purge.
//
// Old entries (whose `When` is older than the manager's
// idempCacheTTL relative to the manager's clock) are cleaned up
// opportunistically the next time BeginIdempotent runs. This keeps
// the cache from growing unboundedly over a long process lifetime.
func TestBeginIdempotent_PurgeStaleEntries(t *testing.T) {
	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	m := NewManagerWithTTL(clock, 1*time.Hour)

	// Admit an op at t=0 with an idempotency_key.
	if _, _, err := m.BeginIdempotent(KindBackupList, "uid=1", "key-old", nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	if got := m.IdempCacheSize(); got != 1 {
		t.Errorf("after first call cache size: got %d want 1", got)
	}

	// Advance the clock by 2h (past the 1h TTL). The next
	// BeginIdempotent should purge the stale entry.
	now = now.Add(2 * time.Hour)
	if _, _, err := m.BeginIdempotent(KindBackupList, "uid=2", "key-new", nil); err != nil {
		t.Fatalf("second: %v", err)
	}
	// Cache should now contain only the fresh entry — the stale one
	// was purged opportunistically.
	if got := m.IdempCacheSize(); got != 1 {
		t.Errorf("after purge cache size: got %d want 1 (stale entry should be gone)", got)
	}

	// Verify the OLD key no longer dedupes — readmitting under
	// "key-old" produces a fresh op_id, NOT the stale one.
	freshOp, deduped, _ := m.BeginIdempotent(KindBackupList, "uid=1", "key-old", nil)
	if deduped {
		t.Errorf("purged stale entry must NOT dedupe; got deduped=true")
	}
	if freshOp == nil {
		t.Fatal("expected fresh op")
	}
	if got := m.IdempCacheSize(); got != 2 {
		t.Errorf("after readmit cache size: got %d want 2", got)
	}
}

// TTL=0 (or default) keeps backward compat for callers that don't
// care about TTL — the default 24h applies.
func TestNewManager_AppliesDefaultIdempTTL(t *testing.T) {
	m := NewManager(nil)
	if m.idempCacheTTL != DefaultIdempCacheTTL {
		t.Errorf("default TTL: got %s want %s", m.idempCacheTTL, DefaultIdempCacheTTL)
	}
	m2 := NewManagerWithTTL(nil, 0)
	if m2.idempCacheTTL != DefaultIdempCacheTTL {
		t.Errorf("TTL=0 should fall back to default; got %s", m2.idempCacheTTL)
	}
}

// Without dedup, the second state-changing op fights for the lock.
func TestBeginIdempotent_DifferentKeyReturns409OnLockedSlot(t *testing.T) {
	m := NewManager(nil)
	if _, _, err := m.BeginIdempotent(KindBackupCreate, "uid=1", "k1", nil); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, _, err := m.BeginIdempotent(KindBackupCreate, "uid=2", "k2", nil)
	if !IsConflict(err) {
		t.Errorf("second state-changing op with different key must be 409, got: %v", err)
	}
}
