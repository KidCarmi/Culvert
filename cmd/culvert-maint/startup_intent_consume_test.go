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

// diedInsideUp seeds an upgrade record and leaves it as an agent killed inside
// that operation's `compose up` leaves it.
func diedInsideUp(t *testing.T, dir string, rec journal.Record) {
	t.Helper()
	seedJournal(t, dir, rec)
	jnl, err := journal.New(dir) // the process that dies
	if err != nil {
		t.Fatal(err)
	}
	if found, err := jnl.BeginCommand(rec.OpID, journal.MutationComposeUp, time.Now().UTC()); err != nil || !found {
		t.Fatalf("begin: found=%v err=%v", found, err)
	}
}

func recordFileRaw(t *testing.T, dir, opID string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "reconcile", opID+".json")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestInitJournal_TakesTheIntentOnceAndInEveryMode: initJournal is what every
// start runs, whatever reconcile_on_startup says. The first start after a
// death inside `compose up` is told; the intent is gone from disk; the start
// after that is told nothing (cases A and E), with nothing left to compare.
func TestInitJournal_TakesTheIntentOnceAndInEveryMode(t *testing.T) {
	dir := t.TempDir()
	diedInsideUp(t, dir, dangerRecord())
	al, _ := startupAudit(t, dir)

	_, died, err := initJournal(dir, ops.NewManager(nil), al, startupRepo)
	if err != nil {
		t.Fatal(err)
	}
	if died[startupOp] != journal.MutationComposeUp {
		t.Fatalf("first start: died = %v, want %s: compose up", died, startupOp)
	}
	if raw := recordFileRaw(t, dir, startupOp); strings.Contains(raw, `"intent"`) || !strings.Contains(raw, `"attributed": true`) {
		t.Errorf("record after the first start:\n%s\nwant no intent and a cut marked attributed", raw)
	}
	_, died, err = initJournal(dir, ops.NewManager(nil), al, startupRepo)
	if err != nil {
		t.Fatal(err)
	}
	if len(died) != 0 {
		t.Errorf("second start: died = %v, want nothing", died)
	}
}

// TestTakeCommandIntents_AnIntentThatCannotBeRemovedStopsTheStart: the journal
// cannot be written. A start that served would report the interruption with
// the intent still open on disk; after an operator reacted to that report, the
// next start would take the same intent for new. So the start is refused, and
// the first start that can write is the one that is told.
func TestTakeCommandIntents_AnIntentThatCannotBeRemovedStopsTheStart(t *testing.T) {
	dir := t.TempDir()
	diedInsideUp(t, dir, dangerRecord())
	jnl, err := journal.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := jnl.List()
	if err != nil {
		t.Fatal(err)
	}
	jnl.SetWriteErrorForTest(errors.New("read-only file system"))
	if _, err := takeCommandIntents(jnl, recs); err == nil || !strings.Contains(err.Error(), "compose up") || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err = %v, want a refusal that names the command and the directory", err)
	}
	if raw := recordFileRaw(t, dir, startupOp); !strings.Contains(raw, `"intent"`) {
		t.Fatalf("disk after the refused start:\n%s\nwant the intent untouched", raw)
	}
	jnl.SetWriteErrorForTest(nil)
	recs, _ = jnl.List()
	died, err := takeCommandIntents(jnl, recs)
	if err != nil || died[startupOp] != journal.MutationComposeUp {
		t.Fatalf("first start that can write: died=%v err=%v, want attributed", died, err)
	}
}

// TestInitJournal_ARefusedStartLeavesNothingBehind: two records are left. The
// older one has no intent; the newer one has an intent this build cannot
// remove (a newer agent wrote the record). The start is refused BEFORE
// anything is audited, counted or marked for either record, and the message
// says what to do, which is not "make the directory writable".
func TestInitJournal_ARefusedStartLeavesNothingBehind(t *testing.T) {
	dir := t.TempDir()
	const newerOp = "01J00000000000000000000000" // sorts after startupOp
	seedJournal(t, dir, dangerRecord())          // older, no intent
	newer := dangerRecord()
	newer.OpID = newerOp
	diedInsideUp(t, dir, newer)
	bumpSchemaOnDisk(t, dir, newerOp, journal.SchemaCurrent+1)
	olderBefore := recordFileRaw(t, dir, startupOp)

	al, auditPath := startupAudit(t, dir)
	mgr := ops.NewManager(nil)
	_, _, err := initJournal(dir, mgr, al, startupRepo)
	if err == nil || !strings.Contains(err.Error(), "refusing to serve") || !strings.Contains(err.Error(), "newer agent version") {
		t.Fatalf("initJournal err = %v, want a refusal that names the newer agent version", err)
	}
	if strings.Contains(err.Error(), "writable") {
		t.Errorf("the refusal for a newer-version record tells the operator to fix permissions: %v", err)
	}
	for _, op := range []string{startupOp, newerOp} {
		if evs := interruptedEvents(t, auditPath, op); len(evs) != 0 {
			t.Errorf("%d audit entries for %s from a start that was refused", len(evs), op)
		}
		if mgr.Get(op) != nil {
			t.Errorf("op %s was marked by a start that was refused", op)
		}
	}
	if after := recordFileRaw(t, dir, startupOp); after != olderBefore {
		t.Errorf("the older record was rewritten by a refused start:\n%s", after)
	}
}

// TestTakeCommandIntents_NothingToTakeNeedsNoWrite: a start that finds no open
// intent concludes nothing and writes nothing here, so an unwritable journal
// cannot make it conclude otherwise (a consumed intent cannot "look current"
// again: there is nothing on disk that says so).
func TestTakeCommandIntents_NothingToTakeNeedsNoWrite(t *testing.T) {
	dir := t.TempDir()
	diedInsideUp(t, dir, dangerRecord())
	al, _ := startupAudit(t, dir)
	if _, died, err := initJournal(dir, ops.NewManager(nil), al, startupRepo); err != nil || len(died) != 1 {
		t.Fatalf("first start: died=%v err=%v", died, err)
	}
	jnl, err := journal.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := jnl.List()
	jnl.SetWriteErrorForTest(errors.New("read-only file system"))
	died, err := takeCommandIntents(jnl, recs)
	if err != nil || len(died) != 0 {
		t.Fatalf("second start on an unwritable journal: died=%v err=%v, want nothing and no refusal", died, err)
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
