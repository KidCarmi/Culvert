package ops

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func idempMgr(t *testing.T, dir string, clock func() time.Time) *Manager {
	t.Helper()
	m := NewManager(clock)
	m.EnableIdempotencyPersistence(filepath.Join(dir, "idempotency.json"))
	if _, err := m.LoadIdempotencyIndex(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

// A journaled op's idempotency entry + terminal outcome survive a "restart"
// (a fresh Manager over the same file): the retry dedupes to the prior op.
func TestIdempotencyIndex_SurvivesRestartWithTerminalOutcome(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()
	m1 := idempMgr(t, dir, func() time.Time { return now })
	op, deduped, err := m1.BeginIdempotent(KindUpgradeApply, "cp", "k1", map[string]interface{}{"image_ref": "x"})
	if err != nil || deduped {
		t.Fatalf("begin: %v deduped=%v", err, deduped)
	}
	if err := m1.Finish(op.ID, StateSucceeded, "", map[string]interface{}{"upgrade_succeeded": true}); err != nil {
		t.Fatal(err)
	}
	if m1.IdempPersistErrors() != 0 {
		t.Fatalf("persist errors: %d", m1.IdempPersistErrors())
	}
	if _, err := os.Stat(filepath.Join(dir, "idempotency.json")); err != nil {
		t.Fatalf("index file: %v", err)
	}

	m2 := idempMgr(t, dir, func() time.Time { return now.Add(time.Minute) })
	again, deduped, err := m2.BeginIdempotent(KindUpgradeApply, "cp", "k1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !deduped || again.ID != op.ID || again.State != StateSucceeded || again.Result["upgrade_succeeded"] != true {
		t.Fatalf("retry after restart must dedupe to the prior terminal op: deduped=%v op=%+v", deduped, again)
	}
	// Different actor / key / kind ⇒ fresh admission (and the lock is free: the
	// restored op is terminal).
	fresh, deduped, err := m2.BeginIdempotent(KindUpgradeApply, "cp", "k2", nil)
	if err != nil || deduped || fresh.ID == op.ID {
		t.Fatalf("fresh key: err=%v deduped=%v id=%s", err, deduped, fresh.ID)
	}
}

// An entry whose op never reached terminal (crash mid-flight) materializes as
// failed(agent_restart_interrupted) — the agent never guesses success — and an
// op already registered (by MarkAllInterrupted) is left alone.
func TestIdempotencyIndex_InFlightMaterializesInterrupted(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()
	m1 := idempMgr(t, dir, func() time.Time { return now })
	op, _, _ := m1.BeginIdempotent(KindRollbackCreate, "cp", "k", nil)
	// crash: no Finish

	m2 := NewManager(func() time.Time { return now.Add(time.Second) })
	m2.MarkAllInterrupted([]InterruptedOp{{OpID: op.ID, Kind: KindRollbackCreate, Actor: "cp"}})
	m2.EnableIdempotencyPersistence(filepath.Join(dir, "idempotency.json"))
	if n, err := m2.LoadIdempotencyIndex(); err != nil || n != 1 {
		t.Fatalf("load: n=%d err=%v", n, err)
	}
	again, deduped, _ := m2.BeginIdempotent(KindRollbackCreate, "cp", "k", nil)
	if !deduped || again.State != StateFailed || again.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Fatalf("in-flight entry must dedupe to the interrupted op: %+v", again)
	}

	m3 := idempMgr(t, dir, func() time.Time { return now.Add(time.Second) })
	again3, deduped, _ := m3.BeginIdempotent(KindRollbackCreate, "cp", "k", nil)
	if !deduped || again3.State != StateFailed || again3.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Fatalf("without MarkAllInterrupted the index itself must materialize interrupted: %+v", again3)
	}
}

// Non-journaled kinds are never persisted; expired entries are dropped on
// load; the file is bounded.
func TestIdempotencyIndex_ScopeTTLAndBound(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_700_000_000, 0).UTC()
	m1 := idempMgr(t, dir, func() time.Time { return now })
	bk, _, err := m1.BeginIdempotent(KindBackupCreate, "cp", "b1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = m1.Finish(bk.ID, StateSucceeded, "", nil)
	if _, err := os.Stat(filepath.Join(dir, "idempotency.json")); err == nil {
		t.Fatal("a non-journaled kind must not create the index")
	}
	for i := 0; i < maxPersistedIdemp+10; i++ {
		op, _, err := m1.BeginIdempotent(KindUpgradeApply, "cp", "u"+string(rune('A'+i%26))+string(rune('a'+i/26)), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = m1.Finish(op.ID, StateFailed, ReasonHealthFailed, nil)
	}
	m2 := idempMgr(t, dir, func() time.Time { return now.Add(time.Minute) })
	if n := m2.IdempCacheSize(); n > maxPersistedIdemp {
		t.Fatalf("index must be bounded at %d, got %d", maxPersistedIdemp, n)
	}
	// Past the TTL nothing is restored.
	m3 := idempMgr(t, dir, func() time.Time { return now.Add(DefaultIdempCacheTTL + time.Hour) })
	if n := m3.IdempCacheSize(); n != 0 {
		t.Fatalf("expired entries must be dropped on load, got %d", n)
	}
}

// A corrupt index is reported and the manager starts empty — never fatal.
func TestIdempotencyIndex_CorruptStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "idempotency.json"), []byte("{junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil)
	m.EnableIdempotencyPersistence(filepath.Join(dir, "idempotency.json"))
	n, err := m.LoadIdempotencyIndex()
	if err == nil || n != 0 {
		t.Fatalf("corrupt index: n=%d err=%v", n, err)
	}
	if _, _, berr := m.BeginIdempotent(KindUpgradeApply, "cp", "k", nil); berr != nil {
		t.Fatalf("admission must continue: %v", berr)
	}
}
