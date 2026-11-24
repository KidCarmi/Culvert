package server

// terminal_record_test.go — ADR-0062 slice 1: an operation's record is kept
// after a failure that did not prove its end state safe (one test per row of
// the per-class table in terminal_record.go), and its terminal audit entry is
// written exactly once across a crash at any point of the terminal sequence.

import (
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// terminalEntries returns the op's terminal audit entries of its own kind.
func terminalEntries(t *testing.T, auditPath, opID, kind string) []audit.Event {
	t.Helper()
	all, err := audit.Recent(auditPath, 5000)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for i := range all {
		ev := &all[i]
		if ev.OpID == opID && ev.Kind == kind && ev.Outcome != audit.OutcomeStarted {
			out = append(out, *ev)
		}
	}
	return out
}

// assertKept: the op's own record is still there, stamped with its real
// outcome, audited, and its terminal entry is on file exactly once.
func assertKept(t *testing.T, jnl *journal.Journal, auditPath, opID, kind, outcome string) {
	t.Helper()
	rec, found, err := jnl.Read(opID)
	if err != nil || !found {
		t.Fatalf("record of failed op %s was removed (found=%v err=%v); the end state was not proven safe", opID, found, err)
	}
	if rec.TerminalOutcome != outcome || !rec.TerminalAudited || rec.TerminalSafe || rec.TerminalAt == nil {
		t.Errorf("kept record = outcome %q audited=%v safe=%v at=%v, want %q audited, not safe", rec.TerminalOutcome,
			rec.TerminalAudited, rec.TerminalSafe, rec.TerminalAt, outcome)
	}
	if n := len(terminalEntries(t, auditPath, opID, kind)); n != 1 {
		t.Errorf("%d terminal audit entries for %s, want 1", n, opID)
	}
}

// assertRemoved: the op's record is gone and its terminal entry is on file once.
func assertRemoved(t *testing.T, jnl *journal.Journal, auditPath, opID, kind string) {
	t.Helper()
	if _, found, _ := jnl.Read(opID); found {
		t.Errorf("record of op %s kept although its end state was proven safe", opID)
	}
	if n := len(terminalEntries(t, auditPath, opID, kind)); n != 1 {
		t.Errorf("%d terminal audit entries for %s, want 1", n, opID)
	}
}

// --- per-class keep/remove table, one test per row --------------------------

// upgrades.apply row 1: failed before the write-ahead barrier (pull) — the tag
// never moved: removed.
func TestEndState_Apply_FailedBeforeBarrier_Removed(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFor = []string{"pull"}
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" {
		t.Fatalf("op = %v", op["state"])
	}
	assertRemoved(t, rig.journal, rig.auditPath, opID, ops.KindUpgradeApply)
}

// upgrades.apply row 2: failed past the barrier with no inline rollback
// (disabled): kept with its real reason.
func TestEndState_Apply_FailedPastBarrierNoRollback_Kept(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew, "rollback_on_failure": false})
	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("op = %v/%v", op["state"], op["failure_reason"])
	}
	assertKept(t, rig.journal, rig.auditPath, opID, ops.KindUpgradeApply, "failed:health_failed")
	if rec, _, _ := rig.journal.Read(opID); rec == nil || rec.Phase != journal.PhaseRestarted {
		t.Errorf("kept record phase = %+v, want the phase the op last wrote (restarted)", rec)
	}
}

// upgrades.apply row 3: failed past the barrier, its inline rollback passed its
// gate and verify: removed (the op stays failed).
func TestEndState_Apply_InlineRollbackPassedGate_Removed(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	res := resultMap(t, op)
	if op["state"] != "failed" || res["rollback_succeeded"] != true {
		t.Fatalf("op = %v rollback=%v", op["state"], res)
	}
	assertRemoved(t, rig.journal, rig.auditPath, opID, ops.KindUpgradeApply)
}

// upgrades.apply row 4: failed past the barrier, its inline rollback failed its
// own gate: kept as rollback_failed.
func TestEndState_Apply_InlineRollbackFailedGate_Kept(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true, digOld: true}
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "rollback_failed" {
		t.Fatalf("op = %v/%v", op["state"], op["failure_reason"])
	}
	assertKept(t, rig.journal, rig.auditPath, opID, ops.KindUpgradeApply, "failed:rollback_failed")
}

// upgrades.apply row 5: success: removed.
func TestEndState_Apply_Succeeded_Removed(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	op, opID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "succeeded" {
		t.Fatalf("op = %v", op["state"])
	}
	assertRemoved(t, rig.journal, rig.auditPath, opID, ops.KindUpgradeApply)
}

// rollbacks.create mode=image row 1: failed at rollback_pull, before any tag
// move: removed.
func TestEndState_ImageRollback_FailedBeforeTagMove_Removed(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFor = []string{"pull"}
	op, opID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" {
		t.Fatalf("op = %v", op["state"])
	}
	assertRemoved(t, rig.journal, rig.auditPath, opID, ops.KindRollbackCreate)
}

// rollbacks.create mode=image row 2: failed in rollback_restart (its `up`), the
// stage that moves the tag: kept. Its phase is still admitted — the phase
// proves nothing for this class.
func TestEndState_ImageRollback_FailedInRestart_Kept(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.failFn = func(argv, _ []string) bool { return argvHas(argv, "up") }
	op, opID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" {
		t.Fatalf("op = %v", op["state"])
	}
	assertKept(t, rig.journal, rig.auditPath, opID, ops.KindRollbackCreate, "failed:command_error")
	if rec, _, _ := rig.journal.Read(opID); rec == nil || rec.Phase != journal.PhaseAdmitted {
		t.Errorf("kept record = %+v, want phase admitted (this class writes no later phase)", rec)
	}
}

// rollbacks.create mode=image row 3: the tag moved and the gate failed: kept.
func TestEndState_ImageRollback_FailedGate_Kept(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	op, opID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digNew})
	if op["state"] != "failed" || op["failure_reason"] != "health_failed" {
		t.Fatalf("op = %v/%v", op["state"], op["failure_reason"])
	}
	assertKept(t, rig.journal, rig.auditPath, opID, ops.KindRollbackCreate, "failed:health_failed")
}

// restore-class row 1 (both kinds): failed at the preflight, nothing stopped
// (RestoreStage preflight): removed.
func TestEndState_Restore_FailedBeforeStop_Removed(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			rig.fail[restoreCmdDryRun] = true
			op := rig.run(t, k.kind)
			if op.State != ops.StateFailed {
				t.Fatalf("op = %s", op.State)
			}
			assertRemoved(t, rig.jnl, rig.srv.opts.AuditPath, op.ID, k.kind)
		})
	}
}

// restore-class row 2: the stack was stopped (RestoreStage stopping or later)
// and the operation failed without a passed health check: kept.
func TestEndState_Restore_FailedAfterStop_Kept(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		stage        journal.RestoreStage
		arrange      func(*restoreRig)
	}{
		{"stop fails", "command_error", journal.RestoreStageStopping, func(r *restoreRig) { r.fail[restoreCmdDown] = true }},
		{"commit fails", "cli_error", journal.RestoreStageCommitFailed, func(r *restoreRig) { r.fail[restoreCmdCommit] = true }},
		{"health check fails", "health_failed", journal.RestoreStageStarted, func(r *restoreRig) { r.healthFail.Store(true) }},
	} {
		for _, k := range restoreKinds {
			t.Run(tc.name+"/"+k.name, func(t *testing.T) {
				rig := newRestoreRig(t)
				tc.arrange(rig)
				op := rig.run(t, k.kind)
				if op.State != ops.StateFailed {
					t.Fatalf("op = %s", op.State)
				}
				assertKept(t, rig.jnl, rig.srv.opts.AuditPath, op.ID, k.kind, "failed:"+tc.reason)
				if rec, _, _ := rig.jnl.Read(op.ID); rec == nil || rec.RestoreStage != tc.stage || rec.Phase != journal.PhaseAdmitted {
					t.Errorf("kept record = %+v, want restore stage %s at phase admitted", rec, tc.stage)
				}
			})
		}
	}
}

// restore-class row 3: committed and the health check after the restart passed,
// but the operation failed (here its `up` reported an error): removed.
func TestEndState_Restore_CommittedAndHealthy_Removed(t *testing.T) {
	for _, k := range restoreKinds {
		t.Run(k.name, func(t *testing.T) {
			rig := newRestoreRig(t)
			rig.fail[restoreCmdUp] = true
			op := rig.run(t, k.kind)
			if op.State != ops.StateFailed || op.Result["restore_committed"] != true {
				t.Fatalf("op = %s result=%v", op.State, op.Result)
			}
			assertRemoved(t, rig.jnl, rig.srv.opts.AuditPath, op.ID, k.kind)
		})
	}
}

// TestEndStateJudges pins the three judges on their in-memory evidence alone.
func TestEndStateJudges(t *testing.T) {
	apply := func(barrier, rbOK bool) bool {
		return applyEndStateSafe(&upgradeApplyAccumulator{barrierWritten: barrier, rollbackSucceeded: rbOK})("any")
	}
	if !apply(false, false) || apply(true, false) || !apply(true, true) {
		t.Error("apply judge: want safe iff no barrier or a passed inline rollback")
	}
	for stage, want := range map[string]bool{"capture_before": true, "rollback_pull": true, "rollback_restart": false,
		"rollback_health": false, "rollback_verify": false, "report": false, "": false} {
		if imageRollbackEndStateSafe(stage) != want {
			t.Errorf("image rollback judge(%q) = %v, want %v", stage, !want, want)
		}
	}
	restore := func(stop, committed, health bool) bool {
		return restoreEndStateSafe(&restoreFlow{stopRecorded: stop, committed: committed, healthPassed: health})("any")
	}
	if !restore(false, false, false) || restore(true, false, false) || restore(true, true, false) || restore(true, false, true) || !restore(true, true, true) {
		t.Error("restore judge: want safe iff never stopped, or committed and healthy")
	}
}

// --- crash windows of the terminal sequence, finished at the next start -----

func endedRecord(opID string) journal.Record {
	now := time.Now().UTC().Add(-time.Minute)
	return journal.Record{OpID: opID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarted, Actor: "uid=0,user=cp",
		TargetRef: repo + "@sha256:" + digNew, TargetDigest: digNew, PriorRef: repo + "@sha256:" + digOld, PriorDigest: digOld,
		StartedAt: now, UpdatedAt: now}
}

// recordTerminalThenKill runs the first step of the terminal sequence through
// the server's own adapter and stops there: the agent dies before the audit.
func recordTerminalThenKill(t *testing.T, jnl *journal.Journal, rec journal.Record, tm ops.Terminal) {
	t.Helper()
	if err := jnl.Write(rec); err != nil {
		t.Fatal(err)
	}
	if err := (terminalJournal{j: jnl}).RecordTerminal(rec.OpID, tm); err != nil {
		t.Fatal(err)
	}
}

// startup runs the per-record startup step on every record, like initJournal.
func startup(t *testing.T, srv *Server, jnl *journal.Journal) []ops.InterruptedOp {
	t.Helper()
	recs, err := jnl.List()
	if err != nil {
		t.Fatal(err)
	}
	var out []ops.InterruptedOp
	for i := range recs {
		AdoptAuditedTerminal(srv.opts.AuditPath, &recs[i])
		o, report, handled := SettleTerminalAtStartup(jnl, srv.opts.Audit, &recs[i], repo, 1000)
		if !handled {
			t.Fatalf("record %s not handled as ended: %+v", recs[i].OpID, recs[i])
		}
		if report {
			out = append(out, o)
		}
	}
	return out
}

func failedTerminal(reason ops.FailureReason, safe bool) ops.Terminal {
	return ops.Terminal{State: ops.StateFailed, Reason: reason, At: time.Now().UTC(), Safe: safe}
}

// Kill after the record step, before the audit: the next start writes the
// entry, once, and keeps the record; a second start writes nothing.
func TestTerminalCrash_KillBeforeAudit_StartupWritesItOnceAndKeeps(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	recordTerminalThenKill(t, jnl, endedRecord(testOpULID), failedTerminal(ops.ReasonHealthFailed, false))
	for start := 1; start <= 2; start++ {
		got := startup(t, srv, jnl)
		if len(got) != 1 || got[0].FailureReason != ops.ReasonHealthFailed || got[0].OpID != testOpULID {
			t.Fatalf("start %d: reported %+v, want the op with its real reason", start, got)
		}
		evs := terminalEntries(t, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply)
		if len(evs) != 1 || evs[0].Outcome != audit.OutcomeFailed || evs[0].FailureReason != "health_failed" || evs[0].Params["terminal_audit_repaired"] != true {
			t.Fatalf("start %d: terminal entries = %+v, want exactly one repaired failed(health_failed)", start, evs)
		}
		rec, found, _ := jnl.Read(testOpULID)
		if !found || !rec.TerminalAudited || rec.InterruptAudited || rec.InterruptedAt != nil || rec.InterruptedSeen != start {
			t.Fatalf("start %d: record = %+v", start, rec)
		}
	}
}

// Kill after the audit, before the settle: the entry is already there, so the
// next start writes none.
func TestTerminalCrash_KillAfterAuditBeforeSettle_NoDuplicate(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	tm := failedTerminal(ops.ReasonCommandError, false)
	recordTerminalThenKill(t, jnl, endedRecord(testOpULID), tm)
	at := tm.At
	if err := srv.opts.Audit.Write(audit.Event{Actor: "uid=0,user=cp", OpID: testOpULID, Kind: ops.KindUpgradeApply,
		Outcome: audit.OutcomeFailed, OutcomeAt: &at, FailureReason: "command_error"}); err != nil {
		t.Fatal(err)
	}
	for start := 1; start <= 2; start++ {
		startup(t, srv, jnl)
		if evs := terminalEntries(t, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply); len(evs) != 1 || evs[0].Params["terminal_audit_repaired"] != nil {
			t.Fatalf("start %d: terminal entries = %+v, want only the op's own", start, evs)
		}
	}
	assertKept(t, jnl, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply, "failed:command_error")
}

// A success killed before its audit: the entry is written at the next start,
// then the record is removed — never removed first.
func TestTerminalCrash_SucceededRecordIsAuditedThenRemoved(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	recordTerminalThenKill(t, jnl, endedRecord(testOpULID), ops.Terminal{State: ops.StateSucceeded, At: time.Now().UTC(), Safe: true})
	if got := startup(t, srv, jnl); len(got) != 0 {
		t.Fatalf("a succeeded op was reported as failed: %+v", got)
	}
	assertRemoved(t, jnl, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply)
	if evs := terminalEntries(t, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply); evs[0].Outcome != audit.OutcomeSucceeded {
		t.Errorf("entry = %+v, want succeeded", evs[0])
	}
}

// A failure the op proved safe, killed before its audit: audited, then removed.
func TestTerminalCrash_SafeFailureIsAuditedThenRemoved(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	recordTerminalThenKill(t, jnl, endedRecord(testOpULID), failedTerminal(ops.ReasonCommandError, true))
	if got := startup(t, srv, jnl); len(got) != 0 {
		t.Fatalf("a removed record was reported: %+v", got)
	}
	assertRemoved(t, jnl, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply)
}

// The audit log cannot be written at the start: nothing is removed or marked,
// even for a success, and the next start with a working log completes it.
func TestTerminalCrash_AuditUnavailableAtStartupKeepsTheRecordAsIs(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	recordTerminalThenKill(t, jnl, endedRecord(testOpULID), ops.Terminal{State: ops.StateSucceeded, At: time.Now().UTC(), Safe: true})
	_ = srv.opts.Audit.Close()
	startup(t, srv, jnl)
	rec, found, _ := jnl.Read(testOpULID)
	if !found || rec.TerminalAudited {
		t.Fatalf("record removed or marked audited without a durable entry: found=%v %+v", found, rec)
	}
	al, err := audit.New(srv.opts.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = al.Close() }()
	srv.opts.Audit = al
	startup(t, srv, jnl)
	assertRemoved(t, jnl, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply)
}

// The record step failed in the op's own process and so did the settle, but
// the audit entry was written: the start finds the entry and adopts it instead
// of writing an "interrupted" one.
func TestTerminalCrash_UnstampedRecordAdoptsTheAuditedOutcome(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	rec := endedRecord(testOpULID)
	if err := jnl.Write(rec); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := srv.opts.Audit.Write(audit.Event{Actor: "uid=0,user=cp", OpID: testOpULID, Kind: ops.KindUpgradeApply,
		Outcome: audit.OutcomeFailed, OutcomeAt: &now, FailureReason: "health_failed"}); err != nil {
		t.Fatal(err)
	}
	got := startup(t, srv, jnl)
	if len(got) != 1 || got[0].FailureReason != ops.ReasonHealthFailed {
		t.Fatalf("reported %+v, want the adopted real reason", got)
	}
	assertKept(t, jnl, srv.opts.AuditPath, testOpULID, ops.KindUpgradeApply, "failed:health_failed")
}

// A previous start's interruption entry is recognised as such, not adopted as
// the op's outcome, and not written again.
func TestAdoptAuditedTerminal_InterruptionEntryIsNotAnOutcome(t *testing.T) {
	srv, _ := newJournalTestServer(t)
	rec := endedRecord(testOpULID)
	now := time.Now().UTC()
	if err := srv.opts.Audit.Write(audit.Event{Actor: "agent:startup", OpID: testOpULID, Kind: ops.KindUpgradeApply,
		Outcome: audit.OutcomeFailed, OutcomeAt: &now, FailureReason: string(ops.ReasonAgentRestartInterrupted)}); err != nil {
		t.Fatal(err)
	}
	AdoptAuditedTerminal(srv.opts.AuditPath, &rec)
	if rec.TerminalOutcome != "" || !rec.InterruptAudited {
		t.Errorf("record = %+v, want interrupt_audited and no terminal outcome", rec)
	}
}

// --- retirement of a kept record --------------------------------------------

// A record kept by a failed apply is retired by a later successful image
// rollback, with its :interrupted_superseded entry, like an interrupted one.
func TestKeptRecord_RetiredByALaterSuccess(t *testing.T) {
	rig := modelRig(t)
	defer rig.stop()
	rig.unhealthyDigests = map[string]bool{digNew: true}
	_, failedID := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + "@sha256:" + digNew, "rollback_on_failure": false})
	assertKept(t, rig.journal, rig.auditPath, failedID, ops.KindUpgradeApply, "failed:health_failed")

	op, okID := rig.rollbackAndWait(t, map[string]interface{}{"mode": "image", "image_ref": repo + "@sha256:" + digOld})
	if op["state"] != "succeeded" {
		t.Fatalf("rollback = %v/%v", op["state"], op["failure_reason"])
	}
	if recs, err := rig.journal.List(); err != nil || len(recs) != 0 {
		t.Fatalf("journal after the later success = %+v err=%v, want empty", recs, err)
	}
	all, _ := audit.Recent(rig.auditPath, 1000) //nolint:errcheck // asserted below
	found := false
	for i := range all {
		if all[i].OpID == failedID && strings.HasSuffix(all[i].Kind, auditKindSuperseded) && all[i].Params["superseded_by"] == okID {
			found = true
		}
	}
	if !found {
		t.Error("no :interrupted_superseded entry for the kept record")
	}
	if n := len(terminalEntries(t, rig.auditPath, failedID, ops.KindUpgradeApply)); n != 1 {
		t.Errorf("%d terminal entries for the kept op, want 1", n)
	}
}

// A kept record whose terminal entry never became durable gets it written
// before a later success retires it, and is not retired when it cannot be.
func TestKeptRecord_RetirementCompletesAMissingTerminalEntryFirst(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	srv.opts.Cfg.ProxyRepo = repo
	recordTerminalThenKill(t, jnl, endedRecord(staleOpULID), failedTerminal(ops.ReasonHealthFailed, false))

	if got := srv.retireSupersededRecords(testOpULID, "uid=0"); len(got) != 1 {
		t.Fatalf("retired %v, want the kept record", got)
	}
	all, _ := audit.Recent(srv.opts.AuditPath, 100) //nolint:errcheck // asserted below
	var kinds []string
	for i := range all {
		if all[i].OpID == staleOpULID {
			kinds = append(kinds, all[i].Kind+"/"+string(all[i].Outcome))
		}
	}
	want := ops.KindUpgradeApply + "/failed," + ops.KindUpgradeApply + auditKindSuperseded + "/succeeded"
	if strings.Join(kinds, ",") != want {
		t.Errorf("audit for the kept op = %v, want %s (terminal entry first)", kinds, want)
	}
}

// --- converge decides a kept record with the same table ----------------------

// TestKeptRecord_ConvergeDecidesItLikeAnInterruptedRecord: the startup reconcile
// reaches the same decision, reason and outcome for a kept record of an op that
// ENDED as for the same record left by an interrupted op; a retired kept record
// keeps its single terminal entry.
func TestKeptRecord_ConvergeDecidesItLikeAnInterruptedRecord(t *testing.T) {
	scenarios := []struct {
		name, reason string
		phase        journal.Phase
		arrange      func(*reconRig)
		targetID     string
	}{
		{"realign", "tag_ahead_container_on_prior", journal.PhaseRestarting, func(r *reconRig) { r.world.pinned = cfgNew }, ""},
		{"recovery_required", "target_live_ungated", journal.PhaseRestarted, func(r *reconRig) {
			r.world.pinned, r.world.running = cfgNew, cfgNew
		}, "sha256:" + cfgNew},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			var results [2]ReconcileRecord
			var kept [2]bool
			for i, ended := range []bool{false, true} {
				r := newReconRig(t, true)
				sc.arrange(r)
				r.seed(t, sc.phase, func(rec *journal.Record) {
					rec.TargetImageID = sc.targetID
					if ended {
						at := time.Now().UTC()
						rec.TerminalOutcome, rec.TerminalAt, rec.TerminalAudited = "failed:command_error", &at, true
					}
				})
				results[i] = r.run(t)
				kept[i] = r.recordOnDisk(t) != nil
			}
			a, b := results[0], results[1]
			if a.Decision != sc.name || a.Reason != sc.reason {
				t.Fatalf("scenario not reached: %+v", a)
			}
			if a.Decision != b.Decision || a.Reason != b.Reason || a.Outcome != b.Outcome || kept[0] != kept[1] ||
				strings.Join(a.Actions, ",") != strings.Join(b.Actions, ",") {
				t.Errorf("interrupted record: %+v kept=%v\nkept terminal record: %+v kept=%v", a, kept[0], b, kept[1])
			}
		})
	}
}

// TestKeptRecord_OpensNoSettleHazard: the record of an op that ENDED is not a
// sign that a predecessor left a compose command in dockerd (its own process
// saw every command return; the durable marker covers one in doubt), so it
// does not start a settle wait or change later docker calls. A record without
// an outcome still does.
func TestKeptRecord_OpensNoSettleHazard(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	recordTerminalThenKill(t, jnl, endedRecord(testOpULID), failedTerminal(ops.ReasonHealthFailed, false))
	if srv.staleRecordOrUnreadable() {
		t.Error("a kept record of an op that ended counted as a predecessor hazard")
	}
	if err := jnl.Write(endedRecord(staleOpULID)); err != nil {
		t.Fatal(err)
	}
	if !srv.staleRecordOrUnreadable() {
		t.Error("an interrupted record no longer counts as a hazard")
	}
}

// TestKeptRecord_ConvergeWritesAMissingTerminalEntryBeforeRetiring: converge
// retires a kept record whose own terminal entry never became durable only
// after writing it, so the record never leaves before that entry.
func TestKeptRecord_ConvergeWritesAMissingTerminalEntryBeforeRetiring(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) {
		at := time.Now().UTC()
		rec.TerminalOutcome, rec.TerminalAt = "failed:command_error", &at
	})
	if got := r.run(t); got.Outcome != OutcomeConverged {
		t.Fatalf("result = %+v", got)
	}
	if r.recordOnDisk(t) != nil {
		t.Fatal("record not retired after verified convergence")
	}
	all, _ := audit.Recent(r.srv.opts.AuditPath, 100) //nolint:errcheck // asserted below
	var kinds []string
	for i := range all {
		if all[i].OpID == testOpULID {
			kinds = append(kinds, all[i].Kind+"/"+string(all[i].Outcome))
		}
	}
	want := ops.KindUpgradeApply + "/failed," + ops.KindUpgradeApply + ":reconciled/succeeded"
	if strings.Join(kinds, ",") != want {
		t.Errorf("audit for the kept op = %v, want %s (terminal entry first)", kinds, want)
	}
}
