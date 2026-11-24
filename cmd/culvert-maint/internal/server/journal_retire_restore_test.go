package server

// journal_retire_restore_test.go — the second, narrower retirer (AGT-005): a
// restore that committed and passed its health check retires the records of
// earlier interrupted RESTORES, audit entry first, and never an upgrade's or an
// image rollback's.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/auth"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

const (
	staleRestoreULID      = "01HZZZZZZZZZZZZZZZZZZZZZR1"
	staleDataRollbackULID = "01HZZZZZZZZZZZZZZZZZZZZZR2"
	staleUpgradeULID      = "01HZZZZZZZZZZZZZZZZZZZZZV1"
	staleImageRbULID      = "01HZZZZZZZZZZZZZZZZZZZZZV2"
	staleUnknownKindULID  = "01HZZZZZZZZZZZZZZZZZZZZZX1"
)

// seedMixedRecords leaves one interrupted record of every class in the journal.
func seedMixedRecords(t *testing.T, jnl *journal.Journal) {
	t.Helper()
	now := time.Now().UTC()
	writeRecords(t, jnl, now, []journal.Record{
		{OpID: staleRestoreULID, Kind: ops.KindRestoreCommit, Phase: journal.PhaseAdmitted, RestoreStage: journal.RestoreStageCommitting},
		{OpID: staleDataRollbackULID, Kind: ops.KindRollbackCreate, Mode: "data", Phase: journal.PhaseAdmitted, RestoreStage: journal.RestoreStageStopping},
		{OpID: staleUpgradeULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting},
		{OpID: staleImageRbULID, Kind: ops.KindRollbackCreate, Mode: "image", Phase: journal.PhaseAdmitted},
		{OpID: staleUnknownKindULID, Kind: "something.else", Phase: journal.PhaseAdmitted},
	})
}

func writeRecords(t *testing.T, jnl *journal.Journal, now time.Time, recs []journal.Record) {
	t.Helper()
	for i := range recs {
		recs[i].Actor, recs[i].StartedAt, recs[i].UpdatedAt = "uid=0", now, now
		if err := jnl.Write(recs[i]); err != nil {
			t.Fatalf("seed %s: %v", recs[i].OpID, err)
		}
	}
}

func journalIDs(t *testing.T, jnl *journal.Journal) string {
	t.Helper()
	recs, err := jnl.List()
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(recs))
	for i := range recs {
		ids = append(ids, recs[i].OpID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

var (
	allStale       = strings.Join([]string{staleRestoreULID, staleDataRollbackULID, staleUpgradeULID, staleImageRbULID, staleUnknownKindULID}, ",")
	nonRestoreOnly = strings.Join([]string{staleUpgradeULID, staleImageRbULID, staleUnknownKindULID}, ",")
)

func sortedCSV(s string) string {
	parts := strings.Split(s, ",")
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// supersededAudits returns the kinds of the :interrupted_superseded entries
// written for opID that name byOpID.
func supersededAudits(t *testing.T, srv *Server, opID, byOpID string) []string {
	t.Helper()
	events, err := audit.Recent(srv.opts.AuditPath, 500)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for i := range events {
		ev := &events[i]
		if ev.OpID == opID && strings.HasSuffix(ev.Kind, auditKindSuperseded) && ev.Params["superseded_by"] == byOpID {
			kinds = append(kinds, ev.Kind)
		}
	}
	return kinds
}

// supersededInResult returns the op ids an operation's result says it retired,
// sorted and comma-joined.
func supersededInResult(op *ops.Op) string {
	ids, _ := op.Result["superseded_interrupted_ops"].([]interface{}) //nolint:errcheck // absent → nil
	named := make([]string, 0, len(ids))
	for _, id := range ids {
		if sid, ok := id.(string); ok {
			named = append(named, sid)
		}
	}
	sort.Strings(named)
	return strings.Join(named, ",")
}

// TestRetireRestore_SuccessRetiresRestoreRecordsOnly: a restore of either kind
// that committed and passed its health check retires the two interrupted
// restore-class records — each with its audit entry — and leaves the upgrade,
// the image rollback and the unknown-kind record exactly where they were.
func TestRetireRestore_SuccessRetiresRestoreRecordsOnly(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			seedMixedRecords(t, rig.jnl)

			op := rig.run(t, k.kind)
			if op.State != ops.StateSucceeded {
				t.Fatalf("op = %s(%s)", op.State, op.FailureReason)
			}
			if got := journalIDs(t, rig.jnl); got != sortedCSV(nonRestoreOnly) {
				t.Errorf("journal after a successful restore = %s\nwant only the non-restore records %s", got, sortedCSV(nonRestoreOnly))
			}
			if named := supersededInResult(op); named != sortedCSV(staleRestoreULID+","+staleDataRollbackULID) {
				t.Errorf("result.superseded_interrupted_ops = %s, want exactly the two restore records", named)
			}
			if op.Result["restore_committed"] != true {
				t.Errorf("the retirement dropped the op's own result: %+v", op.Result)
			}
			// Audited against the retired op, under its own kind, naming the retirer.
			if got := supersededAudits(t, rig.srv, staleRestoreULID, op.ID); len(got) != 1 || got[0] != ops.KindRestoreCommit+auditKindSuperseded {
				t.Errorf("audit for the retired restore.commit = %v", got)
			}
			if got := supersededAudits(t, rig.srv, staleDataRollbackULID, op.ID); len(got) != 1 || got[0] != ops.KindRollbackCreate+auditKindSuperseded {
				t.Errorf("audit for the retired data rollback = %v", got)
			}
			for _, kept := range []string{staleUpgradeULID, staleImageRbULID, staleUnknownKindULID} {
				if got := supersededAudits(t, rig.srv, kept, op.ID); len(got) != 0 {
					t.Errorf("a restore audited the retirement of %s: %v", kept, got)
				}
			}
		})
	}
}

// TestRetireRestore_NeverAnUpgradeRecord states the forbidden half on its own:
// with ONLY an interrupted upgrade and an interrupted image rollback
// outstanding, a successful restore retires nothing. A restore does not re-pin
// the image tag, so the hazard those records report is still there.
func TestRetireRestore_NeverAnUpgradeRecord(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			writeRecords(t, rig.jnl, time.Now().UTC(), []journal.Record{
				{OpID: staleUpgradeULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting},
				{OpID: staleImageRbULID, Kind: ops.KindRollbackCreate, Mode: "image", Phase: journal.PhaseAdmitted},
				// A forged stage does not turn an upgrade record into a restore record.
				{OpID: staleUnknownKindULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting, RestoreStage: journal.RestoreStageCommitted},
			})
			op := rig.run(t, k.kind)
			if op.State != ops.StateSucceeded {
				t.Fatalf("op = %s(%s)", op.State, op.FailureReason)
			}
			if got := journalIDs(t, rig.jnl); got != sortedCSV(nonRestoreOnly) {
				t.Errorf("journal = %s, want all three image records kept", got)
			}
			if _, ok := op.Result["superseded_interrupted_ops"]; ok {
				t.Errorf("result names retired records: %+v", op.Result)
			}
		})
	}
}

// TestRetireRestore_NotWhenTheRestoreDidNotEstablishItsState: a restore that
// failed anywhere — refused preflight, failed stop, failed commit, failed
// start, failed health check — retires nothing.
func TestRetireRestore_NotWhenTheRestoreDidNotEstablishItsState(t *testing.T) {
	for name, arrange := range map[string]func(*restoreRig){
		"preflight fails":    func(r *restoreRig) { r.fail[restoreCmdDryRun] = true },
		"stop fails":         func(r *restoreRig) { r.fail[restoreCmdDown] = true },
		"commit fails":       func(r *restoreRig) { r.fail[restoreCmdCommit] = true },
		"start fails":        func(r *restoreRig) { r.fail[restoreCmdUp] = true },
		"health check fails": func(r *restoreRig) { r.healthFail.Store(true) },
	} {
		for _, k := range restoreKinds {
			t.Run(name+"/"+k.name, func(t *testing.T) {
				rig := newRestoreRig(t)
				arrange(rig)
				seedMixedRecords(t, rig.jnl)
				op := rig.run(t, k.kind)
				if op.State != ops.StateFailed {
					t.Fatalf("op = %s, want failed", op.State)
				}
				if got := journalIDs(t, rig.jnl); got != sortedCSV(allStale) {
					t.Errorf("a FAILED restore changed the journal: %s", got)
				}
			})
		}
	}
}

// TestRetireRestore_EstablishedNeedsCommitAndHealth pins the predicate itself.
func TestRetireRestore_EstablishedNeedsCommitAndHealth(t *testing.T) {
	for _, tc := range []struct {
		committed, health, want bool
	}{{false, false, false}, {true, false, false}, {false, true, false}, {true, true, true}} {
		f := &restoreFlow{committed: tc.committed, healthPassed: tc.health}
		if f.established() != tc.want {
			t.Errorf("committed=%v health=%v: established = %v", tc.committed, tc.health, f.established())
		}
	}
	// A success that did not establish (cannot happen with the real stages; the
	// option must still be honoured) retires nothing.
	srv, jnl := newJournalTestServer(t)
	seedMixedRecords(t, jnl)
	_, _, op := func() (*Server, *journal.Journal, *ops.Op) {
		o, _, e := srv.startAsyncOp(nil, testPeer(), ops.KindRestoreCommit, "", nil, quickStages, withRetiresRestoreRecords(func() bool { return false }))
		if e != nil {
			t.Fatalf("admit: %+v", e)
		}
		srv.opWG.Wait()
		return srv, jnl, srv.opts.Ops.Get(o.ID)
	}()
	if op.State != ops.StateSucceeded {
		t.Fatalf("op = %s", op.State)
	}
	if got := journalIDs(t, jnl); got != sortedCSV(allStale) {
		t.Errorf("an op that established nothing changed the journal: %s", got)
	}
}

// TestRetireRestore_AuditFailureKeepsRecord: the audit entry comes first. With
// the audit log closed the restore itself still succeeds, and every record is
// kept — nothing leaves the journal without a trace.
func TestRetireRestore_AuditFailureKeepsRecord(t *testing.T) {
	rig := newRestoreRig(t)
	seedMixedRecords(t, rig.jnl)
	_ = rig.srv.opts.Audit.Close() // every later audit write fails

	if got := rig.srv.retireSupersededRestoreRecords(testOpULID, "uid=0"); len(got) != 0 {
		t.Errorf("retired %v although no audit entry could be written", got)
	}
	if got := journalIDs(t, rig.jnl); got != sortedCSV(allStale) {
		t.Errorf("journal = %s, want every record kept", got)
	}

	// And through a whole operation.
	op := rig.run(t, ops.KindRestoreCommit)
	if op.State != ops.StateSucceeded {
		t.Fatalf("op = %s(%s); a failing audit log must not fail the restore", op.State, op.FailureReason)
	}
	if got := journalIDs(t, rig.jnl); got != sortedCSV(allStale) {
		t.Errorf("journal after a restore with the audit log closed = %s, want every record kept", got)
	}
	if _, ok := op.Result["superseded_interrupted_ops"]; ok {
		t.Errorf("result claims a retirement that did not happen: %+v", op.Result)
	}
}

// TestRetireRestore_UnreadableJournalRetiresNothing: one corrupt file makes the
// list fail closed; a record that cannot be told apart is not removed.
func TestRetireRestore_UnreadableJournalRetiresNothing(t *testing.T) {
	rig := newRestoreRig(t)
	seedMixedRecords(t, rig.jnl)
	writeCorruptRecord(t, rig.jnl)
	if got := rig.srv.retireSupersededRestoreRecords(testOpULID, "uid=0"); len(got) != 0 {
		t.Errorf("retired %v from an unreadable journal", got)
	}
	for _, id := range strings.Split(allStale, ",") {
		if !recordFileExists(rig.jnl, id) {
			t.Errorf("record %s gone", id)
		}
	}
}

// TestRetireRestore_ImageChangeStillRetiresEverything: the existing rule is
// unchanged — a successful upgrade or image rollback retires every other
// record, a restore's included.
func TestRetireRestore_ImageChangeStillRetiresEverything(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	seedMixedRecords(t, jnl)
	op, _, e := srv.startAsyncOp(nil, testPeer(), ops.KindUpgradeApply, "", nil, quickStages, withRetiresInterrupted(func() bool { return true }))
	if e != nil {
		t.Fatalf("admit: %+v", e)
	}
	srv.opWG.Wait()
	if got := srv.opts.Ops.Get(op.ID); got.State != ops.StateSucceeded {
		t.Fatalf("op = %s", got.State)
	}
	if got := journalIDs(t, jnl); got != "" {
		t.Errorf("journal after a successful image change = %s, want empty", got)
	}
	if got := supersededAudits(t, srv, staleRestoreULID, op.ID); len(got) != 1 || got[0] != ops.KindRestoreCommit+auditKindSuperseded {
		t.Errorf("audit for the restore record an upgrade retired = %v", got)
	}
}

func testPeer() auth.PeerInfo { return auth.PeerInfo{UID: 1000, Username: "cp"} }

func writeCorruptRecord(t *testing.T, jnl *journal.Journal) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(jnl.Dir(), "01HZZZZZZZZZZZZZZZZZZZZZZX.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func recordFileExists(jnl *journal.Journal, id string) bool {
	_, err := os.Stat(filepath.Join(jnl.Dir(), id+".json"))
	return err == nil
}
