package main

// startup_journal_test.go — initJournal in process: the parts of the startup
// contract that need a broken filesystem or an exact audit trail, which the
// process-level tests in startup_crash_recovery_test.go cannot arrange.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

const (
	startupRepo = "ghcr.io/kidcarmi/culvert"
	startupOp   = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
)

func seedJournal(t *testing.T, stateDir string, rec journal.Record) {
	t.Helper()
	jnl, err := journal.New(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := jnl.Write(rec); err != nil {
		t.Fatal(err)
	}
}

func startupAudit(t *testing.T, stateDir string) (al *audit.Logger, path string) {
	t.Helper()
	path = filepath.Join(stateDir, "audit.jsonl")
	al, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	return al, path
}

func interruptedEvents(t *testing.T, auditPath, opID string) []audit.Event {
	t.Helper()
	all, err := audit.Recent(auditPath, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for i := range all {
		ev := &all[i]
		if ev.OpID == opID && ev.Outcome == audit.OutcomeFailed && ev.FailureReason == string(ops.ReasonAgentRestartInterrupted) {
			out = append(out, *ev)
		}
	}
	return out
}

func dangerRecord() journal.Record {
	const dNew = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const dOld = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	started := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	return journal.Record{
		OpID: startupOp, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting, Actor: "uid=0,user=cp",
		TargetRef: startupRepo + "@sha256:" + dNew, TargetDigest: dNew,
		PriorRef: startupRepo + "@sha256:" + dOld, PriorDigest: dOld,
		StartedAt: started, UpdatedAt: started.Add(time.Minute),
	}
}

// TestInitJournal_AuditsOnceAndCountsStarts: three starts over one record give
// one audit entry, a count of three and a first-detection time that does not
// move.
func TestInitJournal_AuditsOnceAndCountsStarts(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, dangerRecord())
	al, auditPath := startupAudit(t, dir)

	var first *time.Time
	for start := 1; start <= 3; start++ {
		mgr := ops.NewManager(nil)
		jnl, _, err := initJournal(dir, mgr, al, startupRepo)
		if err != nil {
			t.Fatalf("start %d: %v", start, err)
		}
		rec, found, err := jnl.Read(startupOp)
		if err != nil || !found {
			t.Fatalf("start %d: record gone (found=%v err=%v) — startup must never remove one", start, found, err)
		}
		if rec.InterruptedSeen != start || !rec.InterruptAudited || rec.InterruptedAt == nil {
			t.Errorf("start %d: seen=%d audited=%v at=%v", start, rec.InterruptedSeen, rec.InterruptAudited, rec.InterruptedAt)
		}
		if first == nil {
			first = rec.InterruptedAt
		} else if !rec.InterruptedAt.Equal(*first) {
			t.Errorf("start %d: interrupted_at moved from %s to %s", start, first, rec.InterruptedAt)
		}
		if rec.Phase != journal.PhaseRestarting || rec.TargetRef == "" || rec.PriorRef == "" {
			t.Errorf("start %d: startup altered the operation's own fields: %+v", start, rec)
		}
		op := mgr.Get(startupOp)
		if op == nil || op.State != ops.StateFailed || op.FailureReason != string(ops.ReasonAgentRestartInterrupted) {
			t.Fatalf("start %d: op = %+v", start, op)
		}
		if !op.Started.Equal(dangerRecord().StartedAt) {
			t.Errorf("start %d: started_at = %s, want the journal's", start, op.Started)
		}
		if n := len(interruptedEvents(t, auditPath, startupOp)); n != 1 {
			t.Errorf("start %d: %d interruption audit entries, want 1", start, n)
		}
	}
	ev := interruptedEvents(t, auditPath, startupOp)[0]
	if ev.Kind != ops.KindUpgradeApply || ev.Actor != "uid=0,user=cp" {
		t.Errorf("audit entry kind=%q actor=%q", ev.Kind, ev.Actor)
	}
	if ev.Params["journal_phase"] != "restarting" || ev.Params["docker_state"] != "indeterminate" || ev.Params["docker_reconciled"] != false {
		t.Errorf("audit params = %#v", ev.Params)
	}
}

// TestInitJournal_ReadOnlyJournalStillReports: the record cannot be updated
// (full or read-only disk). Startup must still come up and mark the op; it
// then audits again at the next start rather than lose the entry.
func TestInitJournal_ReadOnlyJournalStillReports(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := t.TempDir()
	seedJournal(t, dir, dangerRecord())
	al, _ := startupAudit(t, dir)
	rdir := filepath.Join(dir, "reconcile")
	if err := os.Chmod(rdir, 0o500); err != nil { // #nosec G302 -- deliberately unwritable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(rdir, 0o700) }) // #nosec G302 -- restore for TempDir cleanup

	mgr := ops.NewManager(nil)
	if _, _, err := initJournal(dir, mgr, al, startupRepo); err != nil {
		t.Fatalf("an unwritable journal must not stop startup: %v", err)
	}
	if op := mgr.Get(startupOp); op == nil || op.State != ops.StateFailed {
		t.Errorf("op not marked: %+v", op)
	}
}

// TestInitJournal_AuditFailureIsRetried: the audit log is unavailable at the
// first start. The record must not be marked audited, so the next start writes
// the entry.
func TestInitJournal_AuditFailureIsRetried(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, dangerRecord())
	al, auditPath := startupAudit(t, dir)
	_ = al.Close() // every Write now fails

	mgr := ops.NewManager(nil)
	jnl, _, err := initJournal(dir, mgr, al, startupRepo)
	if err != nil {
		t.Fatalf("a failing audit log must not stop startup: %v", err)
	}
	rec, _, _ := jnl.Read(startupOp)
	if rec == nil || rec.InterruptAudited {
		t.Fatalf("record marked audited although the audit write failed: %+v", rec)
	}
	if mgr.Get(startupOp) == nil {
		t.Error("op not marked")
	}

	al2, err := audit.New(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = al2.Close() }()
	if _, _, err := initJournal(dir, ops.NewManager(nil), al2, startupRepo); err != nil {
		t.Fatal(err)
	}
	if n := len(interruptedEvents(t, auditPath, startupOp)); n != 1 {
		t.Errorf("%d audit entries after the retry, want 1", n)
	}
}

// TestInitJournal_EmptyJournalWritesNothing: the common start.
func TestInitJournal_EmptyJournalWritesNothing(t *testing.T) {
	dir := t.TempDir()
	al, auditPath := startupAudit(t, dir)
	if _, _, err := initJournal(dir, ops.NewManager(nil), al, startupRepo); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(auditPath); err != nil || fi.Size() != 0 {
		t.Errorf("audit log touched on a clean start: %v %v", fi, err)
	}
}

// TestInitJournal_UnknownKindIsNotRepeated: a record naming a kind outside the
// journaled set is reported as "unknown", not under a name the file chose.
func TestInitJournal_UnknownKindIsNotRepeated(t *testing.T) {
	dir := t.TempDir()
	rec := dangerRecord()
	rec.Kind = "restore.commit\nforged"
	seedJournal(t, dir, rec)
	al, auditPath := startupAudit(t, dir)
	mgr := ops.NewManager(nil)
	if _, _, err := initJournal(dir, mgr, al, startupRepo); err != nil {
		t.Fatal(err)
	}
	if op := mgr.Get(startupOp); op == nil || op.Kind != "unknown" {
		t.Errorf("op kind = %+v, want unknown", op)
	}
	if evs := interruptedEvents(t, auditPath, startupOp); len(evs) != 1 || evs[0].Kind != "unknown" {
		t.Errorf("audit = %+v", evs)
	}
}

// --- ADR-0062 slice 1: records of operations that ENDED ---------------------

func endedRecord(outcome string, safe bool) journal.Record {
	rec := dangerRecord()
	at := rec.UpdatedAt.Add(time.Minute)
	rec.Phase = journal.PhaseRestarted
	rec.TerminalOutcome, rec.TerminalAt, rec.TerminalSafe = outcome, &at, safe
	return rec
}

// terminalEvents returns the op's own terminal audit entries (its kind, any
// outcome but started), interruption entries included.
func terminalEvents(t *testing.T, auditPath, opID string) []audit.Event {
	t.Helper()
	all, err := audit.Recent(auditPath, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for i := range all {
		if all[i].OpID == opID && all[i].Kind == ops.KindUpgradeApply && all[i].Outcome != audit.OutcomeStarted {
			out = append(out, all[i])
		}
	}
	return out
}

// TestInitJournal_KeptFailedRecord_ReportedWithItsReasonAuditedOnce: the agent
// died after stamping the failed outcome and before the terminal audit. Two
// starts: the op is marked with its real reason both times, exactly one
// terminal entry is written (no interruption entry), and the record is kept.
func TestInitJournal_KeptFailedRecord_ReportedWithItsReasonAuditedOnce(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, endedRecord("failed:health_failed", false))
	al, auditPath := startupAudit(t, dir)
	for start := 1; start <= 2; start++ {
		mgr := ops.NewManager(nil)
		jnl, _, err := initJournal(dir, mgr, al, startupRepo)
		if err != nil {
			t.Fatalf("start %d: %v", start, err)
		}
		op := mgr.Get(startupOp)
		if op == nil || op.State != ops.StateFailed || op.FailureReason != string(ops.ReasonHealthFailed) {
			t.Fatalf("start %d: op = %+v, want failed(health_failed)", start, op)
		}
		evs := terminalEvents(t, auditPath, startupOp)
		if len(evs) != 1 || evs[0].FailureReason != "health_failed" {
			t.Fatalf("start %d: terminal entries = %+v, want exactly one failed(health_failed)", start, evs)
		}
		if n := len(interruptedEvents(t, auditPath, startupOp)); n != 0 {
			t.Errorf("start %d: %d interruption entries for an op that ended", start, n)
		}
		rec, found, _ := jnl.Read(startupOp)
		if !found || !rec.TerminalAudited || rec.InterruptedSeen != start {
			t.Errorf("start %d: record = %+v found=%v", start, rec, found)
		}
	}
}

// TestInitJournal_EndedSucceededRecord_AuditedThenRemoved: a success cut
// before its audit entry: the start writes the entry once, removes the record
// (with reconcile_on_startup off: this ends the op's own terminal sequence),
// and does not report a failed operation.
func TestInitJournal_EndedSucceededRecord_AuditedThenRemoved(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, endedRecord("succeeded", true))
	al, auditPath := startupAudit(t, dir)
	for start := 1; start <= 2; start++ {
		mgr := ops.NewManager(nil)
		jnl, _, err := initJournal(dir, mgr, al, startupRepo)
		if err != nil {
			t.Fatal(err)
		}
		if op := mgr.Get(startupOp); op != nil {
			t.Errorf("start %d: a succeeded op was marked: %+v", start, op)
		}
		if _, found, _ := jnl.Read(startupOp); found {
			t.Errorf("start %d: record of a succeeded op kept", start)
		}
		if evs := terminalEvents(t, auditPath, startupOp); len(evs) != 1 || evs[0].Outcome != audit.OutcomeSucceeded {
			t.Errorf("start %d: terminal entries = %+v, want one succeeded", start, evs)
		}
	}
}

// TestInitJournal_KillAfterTerminalAudit_NoSecondEntry: the entry is already
// on file; the start writes none and keeps the unsafe record.
func TestInitJournal_KillAfterTerminalAudit_NoSecondEntry(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, endedRecord("failed:command_error", false))
	al, auditPath := startupAudit(t, dir)
	now := time.Now().UTC()
	if err := al.Write(audit.Event{Actor: "uid=0,user=cp", OpID: startupOp, Kind: ops.KindUpgradeApply,
		Outcome: audit.OutcomeFailed, OutcomeAt: &now, FailureReason: "command_error"}); err != nil {
		t.Fatal(err)
	}
	jnl, _, err := initJournal(dir, ops.NewManager(nil), al, startupRepo)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(terminalEvents(t, auditPath, startupOp)); n != 1 {
		t.Errorf("%d terminal entries, want 1", n)
	}
	if rec, found, _ := jnl.Read(startupOp); !found || !rec.TerminalAudited {
		t.Errorf("record = %+v found=%v, want kept and audited", rec, found)
	}
}

// TestInitJournal_EndedRecordWithAuditUnavailable_NotRemoved: a succeeded
// record is never removed before its entry is durable.
func TestInitJournal_EndedRecordWithAuditUnavailable_NotRemoved(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, endedRecord("succeeded", true))
	al, auditPath := startupAudit(t, dir)
	_ = al.Close()
	jnl, _, err := initJournal(dir, ops.NewManager(nil), al, startupRepo)
	if err != nil {
		t.Fatal(err)
	}
	if rec, found, _ := jnl.Read(startupOp); !found || rec.TerminalAudited {
		t.Fatalf("record = %+v found=%v, want kept and not audited", rec, found)
	}
	al2, err := audit.New(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = al2.Close() }()
	if _, _, err := initJournal(dir, ops.NewManager(nil), al2, startupRepo); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := jnl.Read(startupOp); found {
		t.Error("record still there after the entry could be written")
	}
	if n := len(terminalEvents(t, auditPath, startupOp)); n != 1 {
		t.Errorf("%d terminal entries, want 1", n)
	}
}

// TestInitJournal_InterruptionEntryNotRepeatedAfterACrash: a start wrote the
// interruption entry and died before the record remembered it. The next start
// finds the entry and does not write a second one.
func TestInitJournal_InterruptionEntryNotRepeatedAfterACrash(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, dangerRecord())
	al, auditPath := startupAudit(t, dir)
	now := time.Now().UTC()
	if err := al.Write(audit.Event{Actor: "uid=0,user=cp", OpID: startupOp, Kind: ops.KindUpgradeApply, Outcome: audit.OutcomeFailed,
		OutcomeAt: &now, FailureReason: string(ops.ReasonAgentRestartInterrupted)}); err != nil {
		t.Fatal(err)
	}
	mgr := ops.NewManager(nil)
	jnl, _, err := initJournal(dir, mgr, al, startupRepo)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(interruptedEvents(t, auditPath, startupOp)); n != 1 {
		t.Errorf("%d interruption entries, want 1", n)
	}
	if rec, _, _ := jnl.Read(startupOp); rec == nil || !rec.InterruptAudited || rec.TerminalOutcome != "" {
		t.Errorf("record = %+v", rec)
	}
	if op := mgr.Get(startupOp); op == nil || op.FailureReason != string(ops.ReasonAgentRestartInterrupted) {
		t.Errorf("op = %+v", op)
	}
}
