package ops

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"culvert-maint/internal/idem"
)

const idemActor = "uid=1000,user=cp"

// restartableManager returns a Manager with a durable store over dir — one
// agent process. Calling it again with the same dir is the restart: a new
// Manager (empty memory) and a freshly opened store.
func restartableManager(t *testing.T, dir string, clock func() time.Time) *Manager {
	t.Helper()
	m := NewManager(clock)
	store, err := idem.Open(dir, idem.Options{Now: clock, Logf: t.Logf})
	if err != nil {
		t.Fatalf("idem.Open: %v", err)
	}
	m.SetIdempotencyStore(store)
	return m
}

func mustBegin(t *testing.T, m *Manager, kind, actor, key string, params map[string]interface{}) *Op {
	t.Helper()
	op, deduped, err := m.BeginIdempotent(kind, actor, key, params)
	if err != nil {
		t.Fatalf("BeginIdempotent(%s,%s): %v", kind, key, err)
	}
	if deduped {
		t.Fatalf("BeginIdempotent(%s,%s): unexpectedly deduped onto %s", kind, key, op.ID)
	}
	return op
}

// TestIdempotency_SameKeyDifferentPayloadRefusedInProcess: without any store,
// while the first op is still live, a different payload under its key is
// refused and names the op the key belongs to. (It used to return the first
// op as if it were the same request.)
func TestIdempotency_SameKeyDifferentPayloadRefusedInProcess(t *testing.T) {
	m := NewManager(nil)
	first := mustBegin(t, m, KindBackupCreate, idemActor, "k", map[string]interface{}{"filename": "a.tar.gz"})

	_, deduped, err := m.BeginIdempotent(KindBackupCreate, idemActor, "k", map[string]interface{}{"filename": "b.tar.gz"})
	var mm *IdempotencyMismatch
	if !errors.As(err, &mm) || deduped {
		t.Fatalf("want *IdempotencyMismatch, got deduped=%v err=%v", deduped, err)
	}
	if mm.OpID != first.ID || mm.Kind != KindBackupCreate {
		t.Errorf("mismatch names %s/%s, want %s/%s", mm.OpID, mm.Kind, first.ID, KindBackupCreate)
	}
	if m.ActiveSize() != 1 {
		t.Errorf("a refused submission admitted an op: active=%d", m.ActiveSize())
	}
	// The same payload still dedupes, with the keys built in another order.
	same, deduped, err := m.BeginIdempotent(KindBackupCreate, idemActor, "k", map[string]interface{}{"filename": "a.tar.gz"})
	if err != nil || !deduped || same.ID != first.ID {
		t.Fatalf("same payload: deduped=%v err=%v id=%v", deduped, err, same)
	}
}

// TestIdempotency_CompletedResultReplayedAfterRestart is the core contract: a
// finished keyed op is answered from its record by a new process — same op_id,
// same terminal state and result — without admitting anything, and while a
// different state-changing op holds the maintenance lock.
func TestIdempotency_CompletedResultReplayedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	params := map[string]interface{}{"filename": "a.tar.gz", "encrypt": false}

	m1 := restartableManager(t, dir, nil)
	first := mustBegin(t, m1, KindBackupCreate, idemActor, "k", params)
	if err := m1.AddStage(first.ID, Stage{Name: "run_cli_backup", State: StateSucceeded}); err != nil {
		t.Fatal(err)
	}
	if err := m1.Finish(first.ID, StateSucceeded, "", map[string]interface{}{"archive": "a.tar.gz"}); err != nil {
		t.Fatal(err)
	}
	want := m1.Get(first.ID)

	m2 := restartableManager(t, dir, nil) // restart
	holder := mustBegin(t, m2, KindRestoreCommit, "uid=2", "", nil)

	got, deduped, err := m2.BeginIdempotent(KindBackupCreate, idemActor, "k", params)
	if err != nil {
		t.Fatalf("replay while the lock is held must not conflict: %v", err)
	}
	if !deduped {
		t.Fatal("replay was admitted as new work")
	}
	if got.ID != want.ID || got.State != StateSucceeded || got.Kind != KindBackupCreate || got.Actor != idemActor {
		t.Fatalf("replayed op differs: %+v", got)
	}
	if !reflect.DeepEqual(got.Result, want.Result) {
		t.Errorf("result: got %v want %v", got.Result, want.Result)
	}
	if got.Finished == nil || !got.Finished.Equal(*want.Finished) || !got.Started.Equal(want.Started) {
		t.Errorf("timestamps differ: got %v/%v want %v/%v", got.Started, got.Finished, want.Started, want.Finished)
	}
	if len(got.Progress) != 1 || got.Progress[0].Name != "run_cli_backup" || got.Progress[0].State != StateSucceeded {
		t.Errorf("progress: %+v", got.Progress)
	}
	if got.LockHeldBy != want.LockHeldBy {
		t.Errorf("lock_held_by: got %q want %q", got.LockHeldBy, want.LockHeldBy)
	}
	// Nothing was admitted and the lock did not move.
	if m2.ActiveSize() != 1 {
		t.Errorf("active=%d, want only the holder", m2.ActiveSize())
	}
	if h := m2.Holder(); h == nil || h.ID != holder.ID {
		t.Errorf("maintenance lock holder changed: %+v", h)
	}
	// GET by id answers too; plain Get (memory only) does not.
	if rec := m2.GetRecorded(first.ID); rec == nil || rec.State != StateSucceeded {
		t.Errorf("GetRecorded: %+v", rec)
	}
	if m2.Get(first.ID) != nil {
		t.Error("Get must stay memory-only")
	}
	if !m2.HasLiveIdempotent(idemActor, KindBackupCreate, "k") {
		t.Error("HasLiveIdempotent = false: a replay would be charged an execution slot")
	}
}

// TestIdempotency_FailedResultReplayedAfterRestart: a recorded failure is
// replayed as that failure, not retried.
func TestIdempotency_FailedResultReplayedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	m1 := restartableManager(t, dir, nil)
	first := mustBegin(t, m1, KindBackupCreate, idemActor, "k", nil)
	if err := m1.Finish(first.ID, StateFailed, ReasonCLIError, map[string]interface{}{"agent_error": "boom"}); err != nil {
		t.Fatal(err)
	}
	m2 := restartableManager(t, dir, nil)
	got, deduped, err := m2.BeginIdempotent(KindBackupCreate, idemActor, "k", nil)
	if err != nil || !deduped {
		t.Fatalf("deduped=%v err=%v", deduped, err)
	}
	if got.ID != first.ID || got.State != StateFailed || got.FailureReason != string(ReasonCLIError) || got.Result["agent_error"] != "boom" {
		t.Fatalf("got %+v", got)
	}
}

// TestIdempotency_InterruptedIsUnknownAndNotRerun: admitted, never finished,
// process gone. The retry gets the original op_id as
// failed(agent_restart_interrupted) with outcome unknown; nothing is admitted.
// A new key proceeds.
func TestIdempotency_InterruptedIsUnknownAndNotRerun(t *testing.T) {
	dir := t.TempDir()
	m1 := restartableManager(t, dir, nil)
	first := mustBegin(t, m1, KindBackupCreate, idemActor, "k", nil)
	// m1 "dies" here: no Finish.

	m2 := restartableManager(t, dir, nil)
	got, deduped, err := m2.BeginIdempotent(KindBackupCreate, idemActor, "k", nil)
	if err != nil || !deduped {
		t.Fatalf("deduped=%v err=%v", deduped, err)
	}
	if got.ID != first.ID {
		t.Fatalf("op_id %s, want the original %s", got.ID, first.ID)
	}
	if got.State != StateFailed || got.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Fatalf("want failed(agent_restart_interrupted), got %s(%s)", got.State, got.FailureReason)
	}
	if got.Result["outcome"] != "unknown" {
		t.Fatalf("result.outcome = %v, want unknown", got.Result["outcome"])
	}
	if m2.ActiveSize() != 0 || m2.Holder() != nil {
		t.Fatalf("the interrupted op was re-admitted: active=%d holder=%v", m2.ActiveSize(), m2.Holder())
	}
	if rec := m2.GetRecorded(first.ID); rec == nil || rec.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Errorf("GetRecorded: %+v", rec)
	}
	// The operator proceeds deliberately with a new key.
	fresh := mustBegin(t, m2, KindBackupCreate, idemActor, "k-2", nil)
	if fresh.ID == first.ID {
		t.Error("new key returned the old op")
	}
}

// TestIdempotency_JournalProjectionAnswersForJournaledKinds: for an
// upgrades.apply the journal's startup projection (MarkAllInterrupted) is
// already in memory under the same op_id; the keyed retry returns that op, with
// what the journal knows, and not a second, poorer answer.
func TestIdempotency_JournalProjectionAnswersForJournaledKinds(t *testing.T) {
	dir := t.TempDir()
	params := map[string]interface{}{"image_ref": "r@sha256:abc"}
	m1 := restartableManager(t, dir, nil)
	first := mustBegin(t, m1, KindUpgradeApply, idemActor, "k", params)

	m2 := restartableManager(t, dir, nil)
	journalResult := map[string]interface{}{"journal_phase": "restarting", "docker_state": "unknown"}
	if n := m2.MarkAllInterrupted([]InterruptedOp{{OpID: first.ID, Kind: KindUpgradeApply, Actor: idemActor, Result: journalResult}}); n != 1 {
		t.Fatalf("MarkAllInterrupted = %d", n)
	}
	got, deduped, err := m2.BeginIdempotent(KindUpgradeApply, idemActor, "k", params)
	if err != nil || !deduped {
		t.Fatalf("deduped=%v err=%v", deduped, err)
	}
	if got.ID != first.ID || got.State != StateFailed || got.FailureReason != string(ReasonAgentRestartInterrupted) {
		t.Fatalf("got %+v", got)
	}
	if got.Result["journal_phase"] != "restarting" {
		t.Errorf("the journal's projection was not the answer: %v", got.Result)
	}
	if m2.ActiveSize() != 1 || m2.Holder() != nil {
		t.Errorf("a new op was admitted: active=%d", m2.ActiveSize())
	}
}

// TestIdempotency_DifferentPayloadRefusedAfterRestart: the fingerprint is
// durable, so the refusal survives the restart for finished and interrupted
// records alike.
func TestIdempotency_DifferentPayloadRefusedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	m1 := restartableManager(t, dir, nil)
	done := mustBegin(t, m1, KindBackupCreate, idemActor, "done", map[string]interface{}{"filename": "a"})
	if err := m1.Finish(done.ID, StateSucceeded, "", nil); err != nil {
		t.Fatal(err)
	}
	cut := mustBegin(t, m1, KindBackupList, idemActor, "cut", map[string]interface{}{"x": 1})

	m2 := restartableManager(t, dir, nil)
	for _, tc := range []struct{ kind, key, opID string }{
		{KindBackupCreate, "done", done.ID},
		{KindBackupList, "cut", cut.ID},
	} {
		_, _, err := m2.BeginIdempotent(tc.kind, idemActor, tc.key, map[string]interface{}{"filename": "OTHER"})
		var mm *IdempotencyMismatch
		if !errors.As(err, &mm) || mm.OpID != tc.opID {
			t.Errorf("%s/%s: want mismatch naming %s, got %v", tc.kind, tc.key, tc.opID, err)
		}
	}
	if m2.ActiveSize() != 0 {
		t.Errorf("a refused submission admitted an op: active=%d", m2.ActiveSize())
	}
}

// TestIdempotency_ScopeAfterRestart: another actor, another kind and the empty
// key are all independent of a recorded request — each is admitted as new work.
func TestIdempotency_ScopeAfterRestart(t *testing.T) {
	dir := t.TempDir()
	m1 := restartableManager(t, dir, nil)
	first := mustBegin(t, m1, KindBackupList, idemActor, "k", nil)
	if err := m1.Finish(first.ID, StateSucceeded, "", nil); err != nil {
		t.Fatal(err)
	}
	m2 := restartableManager(t, dir, nil)
	otherActor := mustBegin(t, m2, KindBackupList, "uid=2000,user=other", "k", nil)
	otherKind := mustBegin(t, m2, KindRestoreDryRun, idemActor, "k", nil)
	noKey1 := mustBegin(t, m2, KindBackupList, idemActor, "", nil)
	noKey2 := mustBegin(t, m2, KindBackupList, idemActor, "", nil)
	seen := map[string]bool{first.ID: true}
	for _, op := range []*Op{otherActor, otherKind, noKey1, noKey2} {
		if seen[op.ID] {
			t.Errorf("op %s is not independent", op.ID)
		}
		seen[op.ID] = true
	}
	// Un-keyed ops leave no durable record.
	if err := m2.Finish(noKey1.ID, StateSucceeded, "", nil); err != nil {
		t.Fatal(err)
	}
	m3 := restartableManager(t, dir, nil)
	if m3.GetRecorded(noKey1.ID) != nil {
		t.Error("an un-keyed op was recorded durably")
	}
}

// TestIdempotency_AdmissionIsWriteAhead: by the time BeginIdempotent returns —
// before the caller could build or run a stage — the admission record is on
// disk and a second process already sees it.
func TestIdempotency_AdmissionIsWriteAhead(t *testing.T) {
	dir := t.TempDir()
	m1 := restartableManager(t, dir, nil)
	first := mustBegin(t, m1, KindBackupCreate, idemActor, "k", nil)

	peek, err := idem.Open(dir, idem.Options{Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	rec, found, err := peek.Lookup(idemActor, KindBackupCreate, "k")
	if err != nil || !found || rec.OpID != first.ID {
		t.Fatalf("no durable admission record at return: found=%v err=%v rec=%+v", found, err, rec)
	}
}

// TestIdempotency_UnwritableStoreRefusesKeyedKeepsUnkeyed: fail closed for the
// key, open for everything else, and the refusal leaves no op and no lock.
func TestIdempotency_UnwritableStoreRefusesKeyedKeepsUnkeyed(t *testing.T) {
	dir := t.TempDir()
	m := restartableManager(t, dir, nil)
	if err := os.RemoveAll(filepath.Join(dir, "idempotency")); err != nil { // the write-ahead record can no longer be written
		t.Fatal(err)
	}
	_, deduped, err := m.BeginIdempotent(KindBackupCreate, idemActor, "k", nil)
	var un *IdempotencyUnavailable
	if !errors.As(err, &un) || deduped || un.Unreadable {
		t.Fatalf("want *IdempotencyUnavailable (store), got deduped=%v err=%v", deduped, err)
	}
	if !errors.Is(err, idem.ErrUnavailable) {
		t.Errorf("cause not preserved: %v", err)
	}
	if m.ActiveSize() != 0 || m.Holder() != nil || m.IdempCacheSize() != 0 {
		t.Fatalf("a refused admission left state: active=%d holder=%v cache=%d", m.ActiveSize(), m.Holder(), m.IdempCacheSize())
	}
	unkeyed := mustBegin(t, m, KindBackupCreate, idemActor, "", nil)
	if unkeyed.LockHeldBy != unkeyed.ID {
		t.Error("un-keyed admission did not proceed normally")
	}
}

// TestIdempotency_UnopenableStoreRefusesKeyedKeepsUnkeyed: the stand-in main
// installs when the store cannot be opened at all.
func TestIdempotency_UnopenableStoreRefusesKeyedKeepsUnkeyed(t *testing.T) {
	m := NewManager(nil)
	m.SetIdempotencyStore(idem.Unavailable(errors.New("state_dir unreadable")))
	_, _, err := m.BeginIdempotent(KindBackupList, idemActor, "k", nil)
	var un *IdempotencyUnavailable
	if !errors.As(err, &un) {
		t.Fatalf("want *IdempotencyUnavailable, got %v", err)
	}
	if !m.HasLiveIdempotent(idemActor, KindBackupList, "k") {
		t.Error("a refusal must not be charged a read-only slot")
	}
	mustBegin(t, m, KindBackupList, idemActor, "", nil)
}

// TestIdempotency_CorruptRecordRefusesThatKeyOnly: an unreadable record means
// "unknown whether it ran" for its key; other keys are served.
func TestIdempotency_CorruptRecordRefusesThatKeyOnly(t *testing.T) {
	dir := t.TempDir()
	m1 := restartableManager(t, dir, nil)
	bad := mustBegin(t, m1, KindBackupCreate, idemActor, "bad", nil)
	if err := m1.Finish(bad.ID, StateSucceeded, "", nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "idempotency"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries=%v err=%v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "idempotency", entries[0].Name()), []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	m2 := restartableManager(t, dir, nil)
	_, _, err = m2.BeginIdempotent(KindBackupCreate, idemActor, "bad", nil)
	var un *IdempotencyUnavailable
	if !errors.As(err, &un) || !un.Unreadable {
		t.Fatalf("want *IdempotencyUnavailable{Unreadable}, got %v", err)
	}
	if m2.ActiveSize() != 0 {
		t.Fatal("the request behind an unreadable record was admitted again")
	}
	mustBegin(t, m2, KindBackupCreate, idemActor, "good", nil)
}

// TestIdempotency_InProcessDedupeUnchangedWithStore: with a store installed the
// live-op dedupe still comes from memory and still precedes the lock check.
func TestIdempotency_InProcessDedupeUnchangedWithStore(t *testing.T) {
	m := restartableManager(t, t.TempDir(), nil)
	a := mustBegin(t, m, KindBackupCreate, idemActor, "k", nil)
	b, deduped, err := m.BeginIdempotent(KindBackupCreate, idemActor, "k", nil)
	if err != nil || !deduped || b.ID != a.ID || b.State != StateRunning {
		t.Fatalf("deduped=%v err=%v op=%+v", deduped, err, b)
	}
	_, _, err = m.BeginIdempotent(KindBackupCreate, idemActor, "other", nil)
	if !IsConflict(err) {
		t.Fatalf("a different key must still conflict on the lock, got %v", err)
	}
}

// TestIdempotency_TTLAppliesAcrossRestart: past the TTL a recorded key is free
// again, exactly as the in-memory entry would be.
func TestIdempotency_TTLAppliesAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	m1 := restartableManager(t, dir, clock)
	first := mustBegin(t, m1, KindBackupList, idemActor, "k", nil)
	if err := m1.Finish(first.ID, StateSucceeded, "", nil); err != nil {
		t.Fatal(err)
	}
	now = now.Add(DefaultIdempCacheTTL - time.Minute)
	m2 := restartableManager(t, dir, clock)
	if got, deduped, err := m2.BeginIdempotent(KindBackupList, idemActor, "k", nil); err != nil || !deduped || got.ID != first.ID {
		t.Fatalf("inside the TTL: deduped=%v err=%v", deduped, err)
	}
	now = now.Add(2 * time.Minute)
	m3 := restartableManager(t, dir, clock)
	fresh := mustBegin(t, m3, KindBackupList, idemActor, "k", nil)
	if fresh.ID == first.ID {
		t.Fatal("expired key returned the old op")
	}
}

// TestIdempotency_RecordHoldsNoResolvedSecret: the record is built from the
// sanitised params only; what the handler never put in params cannot reach it.
func TestIdempotency_RecordHoldsNoResolvedSecret(t *testing.T) {
	dir := t.TempDir()
	m := restartableManager(t, dir, nil)
	op := mustBegin(t, m, KindBackupCreate, idemActor, "k", map[string]interface{}{ // #nosec G101 -- test fixture: passphrase_ref is an env-var reference, not a credential
		"filename": "a.enc", "encrypt": true, "passphrase_ref": "env:CULVERT_BACKUP_PASSPHRASE",
	})
	if err := m.Finish(op.ID, StateSucceeded, "", nil); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "idempotency"))
	raw, err := os.ReadFile(filepath.Join(dir, "idempotency", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]interface{}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	params, _ := rec["params"].(map[string]interface{}) //nolint:errcheck // asserted below
	if params["passphrase_ref"] != "env:CULVERT_BACKUP_PASSPHRASE" {
		t.Errorf("params: %v", params)
	}
	for k := range params {
		if k != "filename" && k != "encrypt" && k != "passphrase_ref" {
			t.Errorf("record carries a param the request did not: %q", k)
		}
	}
	if fp, _ := rec["fingerprint"].(string); len(fp) != 64 { //nolint:errcheck // length check covers a missing key
		t.Errorf("fingerprint missing or not SHA-256 hex: %q", fp)
	}
}
