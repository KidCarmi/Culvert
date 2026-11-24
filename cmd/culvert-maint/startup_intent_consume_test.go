package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/audit"
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
	if _, err := takeCommandIntents(jnl, filepath.Join(dir, "audit.jsonl"), recs); err == nil || !strings.Contains(err.Error(), "compose up") || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("err = %v, want a refusal that names the command and the directory", err)
	}
	if raw := recordFileRaw(t, dir, startupOp); !strings.Contains(raw, `"intent"`) {
		t.Fatalf("disk after the refused start:\n%s\nwant the intent untouched", raw)
	}
	jnl.SetWriteErrorForTest(nil)
	recs, _ = jnl.List()
	died, err := takeCommandIntents(jnl, filepath.Join(dir, "audit.jsonl"), recs)
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
	died, err := takeCommandIntents(jnl, filepath.Join(dir, "audit.jsonl"), recs)
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

// TestInitJournal_AnIntentAnOlderAgentHasSeenIsTakenButNotAttributed: the
// agent died inside `compose up`; an older agent version was then started on
// the directory (it counts its start and leaves the intent it does not know);
// then this version starts. It removes the intent and concludes nothing: the
// stack has been through a start that reported, and may have been touched.
func TestInitJournal_AnIntentAnOlderAgentHasSeenIsTakenButNotAttributed(t *testing.T) {
	dir := t.TempDir()
	diedInsideUp(t, dir, dangerRecord())
	// The older agent's start: interrupted_seen 0 → 1, every other key kept.
	path := filepath.Join(dir, "reconcile", startupOp+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["interrupted_seen"] = 1
	out, _ := json.Marshal(m)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	al, _ := startupAudit(t, dir)
	_, died, err := initJournal(dir, ops.NewManager(nil), al, startupRepo)
	if err != nil {
		t.Fatal(err)
	}
	if len(died) != 0 {
		t.Errorf("died = %v, want nothing: a start had counted the record since the command was begun", died)
	}
	if after := recordFileRaw(t, dir, startupOp); strings.Contains(after, `"intent"`) || !strings.Contains(after, `"attributed": false`) {
		t.Errorf("record after the start:\n%s\nwant the intent removed and a cut marked not attributed", after)
	}
}

// TestInitJournal_AnOperationThatEndedDidNotDieInItsCommand: the audit log
// holds the operation's terminal entry, which is written only after every
// stage returned. Its record still carries an open intent (the close, and the
// record's later updates, could not be written at the time). The start
// removes the intent and attributes nothing: one operation is never reported
// both as ended and as having died inside `compose up`.
func TestInitJournal_AnOperationThatEndedDidNotDieInItsCommand(t *testing.T) {
	for name, outcome := range map[string]audit.Event{
		"ended failed":    {Outcome: audit.OutcomeFailed, FailureReason: string(ops.ReasonCLIError)},
		"ended succeeded": {Outcome: audit.OutcomeSucceeded},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			diedInsideUp(t, dir, dangerRecord()) // the intent that was never closed
			al, _ := startupAudit(t, dir)
			ev := outcome
			ev.Actor, ev.OpID, ev.Kind = "uid=0,user=cp", startupOp, ops.KindUpgradeApply
			if err := al.Write(ev); err != nil {
				t.Fatal(err)
			}
			_, died, err := initJournal(dir, ops.NewManager(nil), al, startupRepo)
			if err != nil {
				t.Fatal(err)
			}
			if len(died) != 0 {
				t.Errorf("died = %v for an operation whose terminal audit entry is on file", died)
			}
			// A succeeded operation's record is removed by this start (its
			// removal is finished); a failed one's may be kept.
			raw, rerr := os.ReadFile(filepath.Join(dir, "reconcile", startupOp+".json")) // #nosec G304 -- test-owned temp dir
			if rerr != nil && !os.IsNotExist(rerr) {
				t.Fatal(rerr)
			}
			if strings.Contains(string(raw), `"intent"`) || strings.Contains(string(raw), `"attributed": true`) {
				t.Errorf("record after the start:\n%s\nwant the intent removed and no attributed cut", raw)
			}
		})
	}
}

// TestInitJournal_ANewerAgentsIntentIsRefusedBeforeAnythingIsTaken: two records
// hold intents; the later one was written by a newer agent and cannot be
// rewritten here. The start is refused before the FIRST record is touched: its
// intent is still there for the start that can serve.
func TestInitJournal_ANewerAgentsIntentIsRefusedBeforeAnythingIsTaken(t *testing.T) {
	dir := t.TempDir()
	const newerOp = "01J00000000000000000000000" // sorts after startupOp
	diedInsideUp(t, dir, dangerRecord())
	newer := dangerRecord()
	newer.OpID = newerOp
	diedInsideUp(t, dir, newer)
	bumpSchemaOnDisk(t, dir, newerOp, journal.SchemaCurrent+1)
	before := recordFileRaw(t, dir, startupOp)

	al, _ := startupAudit(t, dir)
	if _, _, err := initJournal(dir, ops.NewManager(nil), al, startupRepo); err == nil || !strings.Contains(err.Error(), "newer agent version") {
		t.Fatalf("err = %v, want the newer-agent refusal", err)
	}
	if after := recordFileRaw(t, dir, startupOp); after != before {
		t.Errorf("the first record was rewritten by a start that was refused:\n%s", after)
	}
}

// TestTakeCommandIntents_AnUnreadableAuditLogAttributesNothing: whether the
// operation ended cannot be established. The intent is removed and nothing is
// attributed: not knowing is not evidence of a death.
func TestTakeCommandIntents_AnUnreadableAuditLogAttributesNothing(t *testing.T) {
	dir := t.TempDir()
	diedInsideUp(t, dir, dangerRecord())
	jnl, err := journal.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := jnl.List()
	notALog := filepath.Join(dir, "audit-is-a-directory")
	if err := os.Mkdir(notALog, 0o700); err != nil {
		t.Fatal(err)
	}
	died, err := takeCommandIntents(jnl, notALog, recs)
	if err != nil || len(died) != 0 {
		t.Fatalf("died=%v err=%v, want nothing attributed and no refusal", died, err)
	}
	if raw := recordFileRaw(t, dir, startupOp); strings.Contains(raw, `"intent"`) || strings.Contains(raw, `"attributed": true`) {
		t.Errorf("record:\n%s\nwant the intent removed and not attributed", raw)
	}
}
