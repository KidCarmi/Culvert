package server

// journal_retire_test.go — when a later operation retires the record of an
// earlier, interrupted one, and when it must not.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

const staleOpULID = "01HZZZZZZZZZZZZZZZZZZZZZZY"

func seedStaleRecord(t *testing.T, jnl *journal.Journal) {
	t.Helper()
	now := time.Now().UTC()
	if err := jnl.Write(journal.Record{
		OpID: staleOpULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting,
		Actor: "uid=0", StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func runRetireCase(t *testing.T, kind string, stages func() ([]ops.FlowStage, *opError), opts ...startOpt) (*Server, *journal.Journal, *ops.Op) {
	t.Helper()
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	seedStaleRecord(t, jnl)
	op, _, e := srv.startAsyncOp(nil, auth.PeerInfo{UID: 1000, Username: "cp"}, kind, "", nil, stages, opts...)
	if e != nil {
		t.Fatalf("admit: %+v", e)
	}
	srv.opWG.Wait()
	return srv, jnl, srv.opts.Ops.Get(op.ID)
}

func failingStages() ([]ops.FlowStage, *opError) {
	return []ops.FlowStage{{
		Name: "boom", FailureReason: ops.ReasonCommandError,
		Run: func(context.Context) ([]byte, []byte, error) { return nil, nil, errors.New("boom") },
	}}, nil
}

func TestRetire_SuccessOfAnEstablishingOpRetiresStaleRecords(t *testing.T) {
	srv, jnl, op := runRetireCase(t, ops.KindUpgradeApply, quickStages, withRetiresInterrupted(func() bool { return true }))
	if op.State != ops.StateSucceeded {
		t.Fatalf("op = %s", op.State)
	}
	if _, found, _ := jnl.Read(staleOpULID); found {
		t.Error("stale record survived a later successful image change")
	}
	ids, _ := op.Result["superseded_interrupted_ops"].([]interface{}) //nolint:errcheck // absent → nil, asserted below
	if len(ids) != 1 || ids[0] != staleOpULID {
		t.Errorf("op result must name what it retired: %#v", op.Result)
	}
	// The retirement is audited against the retired op, naming the retirer.
	events, err := audit.Recent(srv.opts.AuditPath, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range events {
		if ev.OpID == staleOpULID && strings.HasSuffix(ev.Kind, auditKindSuperseded) && ev.Params["superseded_by"] == op.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("no %s audit entry for the retired op", auditKindSuperseded)
	}
}

func TestRetire_NotOnFailure(t *testing.T) {
	_, jnl, op := runRetireCase(t, ops.KindUpgradeApply, failingStages, withRetiresInterrupted(func() bool { return true }))
	if op.State != ops.StateFailed {
		t.Fatalf("op = %s", op.State)
	}
	if _, found, _ := jnl.Read(staleOpULID); !found {
		t.Error("a FAILED op retired an interrupted record")
	}
}

func TestRetire_NotWhenTheOpEstablishedNothing(t *testing.T) {
	// An already-current apply: succeeded, but the tag was not re-pinned.
	_, jnl, op := runRetireCase(t, ops.KindUpgradeApply, quickStages, withRetiresInterrupted(func() bool { return false }))
	if op.State != ops.StateSucceeded {
		t.Fatalf("op = %s", op.State)
	}
	if _, found, _ := jnl.Read(staleOpULID); !found {
		t.Error("an op that established no image state retired an interrupted record")
	}
}

func TestRetire_NotByOtherKinds(t *testing.T) {
	// A data rollback (no option) and a backup must leave the journal alone.
	for _, kind := range []string{ops.KindRollbackCreate, ops.KindBackupCreate} {
		_, jnl, op := runRetireCase(t, kind, quickStages)
		if op.State != ops.StateSucceeded {
			t.Fatalf("%s = %s", kind, op.State)
		}
		if _, found, _ := jnl.Read(staleOpULID); !found {
			t.Errorf("%s retired an interrupted record", kind)
		}
	}
}

// TestRetire_UnreadableJournalRetiresNothing: with one corrupt file present the
// list fails closed, and a record that cannot be told apart is not removed.
func TestRetire_UnreadableJournalRetiresNothing(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	seedStaleRecord(t, jnl)
	if err := os.WriteFile(filepath.Join(jnl.Dir(), "01HZZZZZZZZZZZZZZZZZZZZZZX.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := srv.retireSupersededRecords(testOpULID, "uid=0"); len(got) != 0 {
		t.Errorf("retired %v from an unreadable journal", got)
	}
	if _, err := os.Stat(filepath.Join(jnl.Dir(), staleOpULID+".json")); err != nil {
		t.Errorf("stale record gone: %v", err)
	}
}

// Codex review on #2039: a startup reconcile that left a record needing
// recovery must stop reporting recovery_required once a later successful
// image change retired that record, and must keep reporting it otherwise. The
// nested reconcile record stays as history.
func TestRetire_ResolvesStartupRecoveryRequired(t *testing.T) {
	const otherOp = "01HZZZZZZZZZZZZZZZZZZZZZZW"
	seedTracker := func(srv *Server) {
		tr := NewReconcileTracker()
		tr.put(ReconcileRecord{OpID: staleOpULID, Kind: "upgrade", Decision: "recovery_required",
			Reason: "target_live_ungated", Outcome: OutcomeRecoveryRequired})
		srv.reconcileTracker = tr
	}

	t.Run("retired record clears the flag", func(t *testing.T) {
		srv, jnl := newJournalTestServer(t)
		srv.opts.Cfg.ProxyRepo = repo
		seedStaleRecord(t, jnl)
		seedTracker(srv)
		if !srv.reconcileTracker.RecoveryRequired() {
			t.Fatal("premise: startup left recovery_required")
		}
		if got := srv.retireSupersededRecords(testOpULID, "uid=0"); len(got) != 1 {
			t.Fatalf("retired %v", got)
		}
		if srv.reconcileTracker.RecoveryRequired() {
			t.Error("recovery_required still reported after the record was retired")
		}
		r, ok := srv.reconcileTracker.RecordFor(staleOpULID)
		if !ok || r.Outcome != OutcomeRecoveryRequired || r.SupersededBy != testOpULID {
			t.Errorf("startup history lost or unattributed: %+v ok=%v", r, ok)
		}
	})

	t.Run("failed retirement keeps the flag", func(t *testing.T) {
		srv, jnl := newJournalTestServer(t)
		seedStaleRecord(t, jnl)
		seedTracker(srv)
		if err := os.WriteFile(filepath.Join(jnl.Dir(), "01HZZZZZZZZZZZZZZZZZZZZZZX.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		srv.retireSupersededRecords(testOpULID, "uid=0")
		if !srv.reconcileTracker.RecoveryRequired() {
			t.Error("recovery_required cleared although nothing was retired")
		}
	})

	t.Run("a different record keeps the flag", func(t *testing.T) {
		srv, _ := newJournalTestServer(t)
		seedTracker(srv)
		srv.reconcileTracker.markSuperseded(otherOp, testOpULID)
		if !srv.reconcileTracker.RecoveryRequired() {
			t.Error("superseding an unrelated op cleared recovery_required")
		}
	})
}

// TestRetire_AuditFailureKeepsRecord: a record is removed only after its
// supersession audit entry has been written (AGT-005, "the removal is audited
// first"). With the audit log refusing writes, nothing is retired, the record
// on disk is unchanged, and no entry names the pair.
//
// This is the later-success counterpart of
// TestStartupReconcile_AuditFailureKeepsRecord. Without it, swapping the
// audit write and the journal removal in retireSupersededRecords passes every
// other test and the lifecycle conformance run: they observe the state after
// both calls succeeded, where the two orders are indistinguishable.
func TestRetire_AuditFailureKeepsRecord(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	seedStaleRecord(t, jnl)

	before, found, err := jnl.Read(staleOpULID)
	if err != nil || !found {
		t.Fatalf("fixture: stale record not readable: found=%v err=%v", found, err)
	}
	if err := srv.opts.Audit.Close(); err != nil { // every later audit write fails
		t.Fatalf("fixture: close audit log: %v", err)
	}

	if got := srv.retireSupersededRecords(testOpULID, "uid=0"); len(got) != 0 {
		t.Errorf("retired %v although the audit entry could not be written", got)
	}
	after, found, err := jnl.Read(staleOpULID)
	if err != nil || !found {
		t.Fatalf("record removed although the audit entry could not be written: found=%v err=%v", found, err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("kept record changed:\nbefore %+v\nafter  %+v", before, after)
	}
	events, err := audit.Recent(srv.opts.AuditPath, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if events[i].OpID == staleOpULID && events[i].Params["superseded_by"] == testOpULID {
			t.Errorf("a closed audit log recorded the supersession: %+v", events[i])
		}
	}
}
