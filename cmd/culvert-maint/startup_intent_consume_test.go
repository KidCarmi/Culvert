package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// intentRecordAtStart seeds an upgrade record whose `compose up` never
// returned (the agent died in it) and returns the journal it is in.
func intentRecordAtStart(t *testing.T, dir string) *journal.Journal {
	t.Helper()
	rec := dangerRecord()
	rec.BeginCommand(journal.MutationComposeUp, rec.UpdatedAt)
	seedJournal(t, dir, rec)
	jnl, err := journal.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return jnl
}

func readStartupRecord(t *testing.T, jnl *journal.Journal) *journal.Record {
	t.Helper()
	rec, found, err := jnl.Read(startupOp)
	if err != nil || !found {
		t.Fatalf("read: %v found=%v", err, found)
	}
	return rec
}

// TestStartup_AnIntentThatCannotBeConsumedStopsTheStart: the agent died inside
// `compose up`, and at the next start the journal cannot be written. If that
// start served, it would report the interruption without having recorded that
// it looked; an operator could react (stop the stack), and the start after
// that would find the same open intent and take it for new. So this start
// does not happen: an error, no audit entry, nothing changed on disk. The
// first start that CAN write is then the first start, and is told.
func TestStartup_AnIntentThatCannotBeConsumedStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	jnl := intentRecordAtStart(t, dir)
	al, auditPath := startupAudit(t, dir)
	now := time.Now().UTC()

	jnl.SetWriteErrorForTest(errors.New("read-only file system"))
	_, err := reportInterrupted(jnl, al, readStartupRecord(t, jnl), startupRepo, now)
	if err == nil || !strings.Contains(err.Error(), "compose up") {
		t.Fatalf("err = %v, want a refusal that names the command", err)
	}
	if evs := interruptedEvents(t, auditPath, startupOp); len(evs) != 0 {
		t.Errorf("%d audit entries from a start that must not have happened", len(evs))
	}
	disk := readStartupRecord(t, jnl)
	if disk.Intent == nil || disk.Cut != nil || disk.InterruptedSeen != 0 {
		t.Fatalf("disk after the refused start: intent=%+v cut=%+v seen=%d, want untouched", disk.Intent, disk.Cut, disk.InterruptedSeen)
	}

	jnl.SetWriteErrorForTest(nil)
	if _, err := reportInterrupted(jnl, al, readStartupRecord(t, jnl), startupRepo, now); err != nil {
		t.Fatalf("the start after the disk recovered: %v", err)
	}
	disk = readStartupRecord(t, jnl)
	if disk.Intent != nil || !disk.CutByThisStart(journal.MutationComposeUp) || disk.InterruptedSeen != 1 {
		t.Errorf("first start that could write: intent=%+v cut=%+v seen=%d, want consumed, attributed, seen=1", disk.Intent, disk.Cut, disk.InterruptedSeen)
	}
	if evs := interruptedEvents(t, auditPath, startupOp); len(evs) != 1 {
		t.Errorf("%d audit entries, want exactly 1", len(evs))
	}
}

// TestStartup_AnUnwritableJournalWithoutAnIntentStillReports: the existing
// rule is unchanged for every record that has no open intent. Nothing about
// such a record can be misread by a later start, so the agent comes up and
// reports from memory.
func TestStartup_AnUnwritableJournalWithoutAnIntentStillReports(t *testing.T) {
	dir := t.TempDir()
	seedJournal(t, dir, dangerRecord())
	jnl, err := journal.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	al, _ := startupAudit(t, dir)
	jnl.SetWriteErrorForTest(errors.New("read-only file system"))
	o, err := reportInterrupted(jnl, al, readStartupRecord(t, jnl), startupRepo, time.Now().UTC())
	if err != nil || o.OpID != startupOp {
		t.Fatalf("op=%q err=%v, want the interruption reported", o.OpID, err)
	}
}

// TestInitJournal_RefusesToServeOverAnIntentItCannotConsume: the same rule
// through initJournal, with a record this build may not rewrite at all (a
// newer agent wrote it) that carries an open intent. Reporting it and leaving
// the intent open would hand the next start of the newer agent stale evidence.
func TestInitJournal_RefusesToServeOverAnIntentItCannotConsume(t *testing.T) {
	dir := t.TempDir()
	rec := dangerRecord()
	rec.BeginCommand(journal.MutationComposeUp, rec.UpdatedAt)
	seedJournal(t, dir, rec)
	// Raise the schema on disk past this build's, as a newer agent would.
	bumpSchemaOnDisk(t, dir, startupOp, journal.SchemaCurrent+1)
	al, _ := startupAudit(t, dir)
	mgr := ops.NewManager(nil)
	if _, err := initJournal(dir, mgr, al, startupRepo); err == nil || !strings.Contains(err.Error(), "refusing to serve") {
		t.Fatalf("initJournal err = %v, want a refusal to serve", err)
	}
	if op := mgr.Get(startupOp); op != nil {
		t.Errorf("the op was marked by a start that refused to serve: %+v", op)
	}
}

// bumpSchemaOnDisk rewrites the "schema" key of a record file in place.
func bumpSchemaOnDisk(t *testing.T, stateDir, opID string, schema int) {
	t.Helper()
	path := filepath.Join(stateDir, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["schema"] = schema
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}
