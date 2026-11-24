package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	intentOp  = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	intentOp2 = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
)

// agentLife is one agent process on a state directory: its own Journal (and
// with it its own idea of which commands it is inside).
type agentLife struct {
	t   *testing.T
	dir string
	j   *Journal
}

func newLife(t *testing.T, dir string) *agentLife {
	t.Helper()
	j, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &agentLife{t: t, dir: dir, j: j}
}

func (a *agentLife) seed(opID string) {
	a.t.Helper()
	now := time.Now().UTC()
	if err := a.j.Write(Record{OpID: opID, Kind: "upgrades.apply", Phase: PhaseRestarting, StartedAt: now, UpdatedAt: now}); err != nil {
		a.t.Fatal(err)
	}
}

// start does what an agent start does with the journal (main.go initJournal):
// take every intent durably, then count the start in every record. It returns
// what that start may conclude, op id → command.
func (a *agentLife) start() map[string]string {
	a.t.Helper()
	recs, err := a.j.List()
	if err != nil {
		a.t.Fatal(err)
	}
	died := map[string]string{}
	for i := range recs {
		cmd, attributed, had := recs[i].TakeIntent()
		if !had {
			continue
		}
		if err := a.j.Write(recs[i]); err != nil {
			a.t.Fatalf("take: %v", err)
		}
		if attributed {
			died[recs[i].OpID] = cmd
		}
	}
	for i := range recs {
		recs[i].InterruptedSeen++
		if err := a.j.Write(recs[i]); err != nil {
			a.t.Fatal(err)
		}
	}
	return died
}

// phaseAdvance is any ordinary read-modify-write of the record by a running
// operation.
func (a *agentLife) phaseAdvance(opID string) {
	a.t.Helper()
	rec, found, err := a.j.Read(opID)
	if err != nil || !found {
		a.t.Fatalf("read: %v found=%v", err, found)
	}
	rec.Phase = PhaseRestarted
	if err := a.j.Write(*rec); err != nil {
		a.t.Fatal(err)
	}
}

// olderAgentStart is a start of an agent built before this file but after the
// lossless rewrite (ADR-0062 slice 2): it counts the start and carries the
// keys it does not know, `intent` among them, through its rewrite.
func olderAgentStart(t *testing.T, dir, opID string) {
	t.Helper()
	path := filepath.Join(dir, "reconcile", opID+".json")
	raw, err := os.ReadFile(path) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	seen, _ := m["interrupted_seen"].(float64)
	m["interrupted_seen"] = seen + 1
	out, _ := json.Marshal(m)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func rawRecordFile(t *testing.T, dir, opID string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "reconcile", opID+".json")) // #nosec G304 -- test-owned temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestIntent_AttributionSequences: what the LAST agent start of each sequence
// may conclude about `compose up` of the operation. The rows are the
// acceptance cases of ADR-0062 slice 3 and the sequences on which reviews of
// #2093 and of the first version of this code found a wrong answer.
func TestIntent_AttributionSequences(t *testing.T) {
	type world struct {
		t    *testing.T
		dir  string
		life *agentLife
		last map[string]string
	}
	begin := func(w *world) {
		if _, err := w.life.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC()); err != nil {
			w.t.Fatal(err)
		}
	}
	end := func(w *world) {
		if err := w.life.j.EndCommand(intentOp); err != nil {
			w.t.Fatal(err)
		}
	}
	endFails := func(w *world) {
		w.life.j.SetWriteErrorForTest(errors.New("no space left on device"))
		if err := w.life.j.EndCommand(intentOp); err == nil {
			w.t.Fatal("test setup: the close was expected to fail")
		}
		w.life.j.SetWriteErrorForTest(nil)
	}
	advance := func(w *world) { w.life.phaseAdvance(intentOp) }
	// restart: the process is gone (killed, or stopped) and a new one starts.
	restart := func(w *world) { w.life = newLife(w.t, w.dir); w.last = w.life.start() }
	older := func(w *world) { olderAgentStart(w.t, w.dir, intentOp) }

	for _, tc := range []struct {
		name  string
		steps []func(*world)
		want  bool
	}{
		{"positive: died inside up; the first start after it", []func(*world){begin, restart}, true},
		{"A/E: a start has looked (in any mode); the next one is told nothing", []func(*world){begin, restart, restart}, false},
		{"C: the command returned to a live agent; the agent restarted later", []func(*world){begin, end, restart}, false},
		{"C: died in up, then a recovery whose own up returned (failed), then a restart", []func(*world){begin, restart, begin, end, restart}, false},
		{"positive: a recovery that died inside its own up is attributable once more", []func(*world){begin, restart, begin, restart}, true},
		{"and not at the start after that", []func(*world){begin, restart, begin, restart, restart}, false},
		{"no command was ever begun", []func(*world){restart}, false},
		{"downgrade: an older agent that carries the intent started in between", []func(*world){begin, older, restart}, false},
		{"downgrade, twice", []func(*world){begin, older, older, restart}, false},
		{"one failed close, then the operation's next record write, then killed", []func(*world){begin, endFails, advance, restart}, false},
		{"one failed close, retried by a later successful close", []func(*world){begin, endFails, end, restart}, false},
		// The stated residual, pinned so that it stays stated: the close could
		// not be written and the record was never written again before the
		// process ended. The next start cannot tell this from a death inside
		// the command.
		{"RESIDUAL: failed close, no later write of the record, process ends", []func(*world){begin, endFails, restart}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{t: t, dir: t.TempDir()}
			w.life = newLife(t, w.dir)
			w.life.seed(intentOp)
			for _, st := range tc.steps {
				st(w)
			}
			if got := w.last[intentOp] == MutationComposeUp; got != tc.want {
				t.Errorf("the last start concludes died-in-up = %v, want %v\nrecord: %s", got, tc.want, rawRecordFile(t, w.dir, intentOp))
			}
			if strings.Contains(rawRecordFile(t, w.dir, intentOp), `"intent"`) {
				t.Errorf("an intent is still on disk after an agent start:\n%s", rawRecordFile(t, w.dir, intentOp))
			}
		})
	}
}

// TestIntent_IsPerRecordAndPerCommand (case B): what one operation's record
// says is no evidence about another's, and each command is reported as itself.
func TestIntent_IsPerRecordAndPerCommand(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	a.seed(intentOp)
	a.seed(intentOp2)
	if _, err := a.j.BeginCommand(intentOp2, MutationComposeDown, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	died := newLife(t, dir).start()
	if _, ok := died[intentOp]; ok {
		t.Errorf("the other record is attributed something: %v", died)
	}
	if died[intentOp2] != MutationComposeDown {
		t.Errorf("died = %v, want %s: compose down", died, intentOp2)
	}
}

// TestIntent_NoClockDecides (case D): the time a command was begun is written
// for the reader and decides nothing, whatever the starting agent's clock says.
func TestIntent_NoClockDecides(t *testing.T) {
	for name, began := range map[string]time.Time{
		"begun years in the future": time.Now().AddDate(5, 0, 0),
		"begun decades ago":         time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
		"zero time":                 {},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			a := newLife(t, dir)
			a.seed(intentOp)
			if _, err := a.j.BeginCommand(intentOp, MutationComposeUp, began); err != nil {
				t.Fatal(err)
			}
			if died := newLife(t, dir).start(); died[intentOp] != MutationComposeUp {
				t.Errorf("first start: %v, want attributed", died)
			}
			if died := newLife(t, dir).start(); len(died) != 0 {
				t.Errorf("second start: %v, want nothing", died)
			}
		})
	}
}

// TestIntent_BeginWithoutARecordWritesNothing: an operation that has no
// journal record gets none from its command.
func TestIntent_BeginWithoutARecordWritesNothing(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	found, err := a.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC())
	if found || err != nil {
		t.Fatalf("found=%v err=%v, want false, nil", found, err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "reconcile", intentOp+".json")); !os.IsNotExist(serr) {
		t.Errorf("a record file appeared for an operation that had none (err=%v)", serr)
	}
	if err := a.j.EndCommand(intentOp); err != nil {
		t.Errorf("EndCommand without a record: %v", err)
	}
}

// TestIntent_WriteNeverCarriesAnIntentTheProcessIsNotInside: the self-healing
// rule on its own. While the command is in flight a rewrite keeps the intent;
// after it returned, or in a process that never began it, a rewrite drops it.
func TestIntent_WriteNeverCarriesAnIntentTheProcessIsNotInside(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	a.seed(intentOp)
	if _, err := a.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	a.phaseAdvance(intentOp) // e.g. rollback_armed written while `up` runs
	if !strings.Contains(rawRecordFile(t, dir, intentOp), `"intent"`) {
		t.Fatal("a rewrite during the command dropped its intent")
	}
	other := newLife(t, dir) // a process that is not inside the command
	other.phaseAdvance(intentOp)
	if strings.Contains(rawRecordFile(t, dir, intentOp), `"intent"`) {
		t.Fatal("a process that is not inside the command wrote its intent back")
	}
}

// TestIntent_WhatTheRecordMustSay: a record is a file that can be edited, and
// can come from another agent version. Only an intent for one of the two
// commands, begun at the record's current start count, is evidence.
func TestIntent_WhatTheRecordMustSay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		intent CommandIntent
		seen   int
		want   bool
	}{
		{"control", CommandIntent{Command: MutationComposeUp, Epoch: 0}, 0, true},
		{"control, on a record starts have counted", CommandIntent{Command: MutationComposeUp, Epoch: 3}, 3, true},
		{"begun before a start that counted", CommandIntent{Command: MutationComposeUp, Epoch: 0}, 1, false},
		{"epoch ahead of the count", CommandIntent{Command: MutationComposeUp, Epoch: 2}, 1, false},
		{"negative epoch and count", CommandIntent{Command: MutationComposeUp, Epoch: -1}, -1, false},
		{"not a command the agent runs", CommandIntent{Command: "docker system prune", Epoch: 0}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Record{OpID: intentOp, InterruptedSeen: tc.seen}
			in := tc.intent
			r.Intent = &in
			_, attributed, had := r.TakeIntent()
			if !had || attributed != tc.want || r.Intent != nil || r.Cut == nil || r.Cut.Attributed != tc.want {
				t.Errorf("had=%v attributed=%v intent=%+v cut=%+v, want taken with attributed=%v", had, attributed, r.Intent, r.Cut, tc.want)
			}
		})
	}
}

// slice2Phases is the closed phase set of the agent between ADR-0062 slice 2
// and this change (journal.go validPhases at 11dd85c). Frozen on purpose: it
// stands for THAT binary.
var slice2Phases = map[Phase]struct{}{
	"admitted": {}, "captured": {}, "resolved": {}, "pulled": {},
	"restarting": {}, "restarted": {}, "verified": {},
}

// slice2AgentList is List as the agent at 11dd85c runs it: strict-ULID file
// names, the first-generation fence skipped BY NAME and no other, json decode,
// the closed phase set, fail-closed on the first failure. Its initJournal
// refuses to serve when this returns an error.
func slice2AgentList(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if id == "00000000000000000000000000" {
			continue
		}
		if _, err := ulid.ParseStrict(id); err != nil {
			return err
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- test temp dir
		if err != nil {
			return err
		}
		var r struct {
			Phase Phase `json:"phase"`
		}
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("%w: %v", ErrCorruptRecord, err)
		}
		if _, ok := slice2Phases[r.Phase]; !ok {
			return fmt.Errorf("%w: unknown phase %q", ErrCorruptRecord, r.Phase)
		}
	}
	return nil
}

// TestIntentFence_KeepsEveryOlderAgentOutWhileAnIntentIsOpen: while a record
// holds an open intent, an agent of either older generation refuses to serve
// on this directory (it would not take the intent, and may serve without
// counting its start). Once the intent is gone both start normally, and the
// record needs no schema above 1.
func TestIntentFence_KeepsEveryOlderAgentOutWhileAnIntentIsOpen(t *testing.T) {
	dir := t.TempDir()
	rdir := filepath.Join(dir, "reconcile")
	a := newLife(t, dir)
	a.seed(intentOp)
	before := rawRecordFile(t, dir, intentOp)
	for name, list := range map[string]func(string) error{"slice-2 agent": slice2AgentList, "pre-ADR agent": olderAgentList} {
		if err := list(rdir); err != nil {
			t.Fatalf("%s refuses a journal with no intent: %v", name, err)
		}
	}
	if _, err := a.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rawRecordFile(t, dir, intentOp), `"schema"`) {
		t.Error("an open intent raised the record's schema")
	}
	if on, _ := a.j.FenceActive(); on {
		t.Error("an open intent put the FIRST-generation fence up (slice-2 agents skip it; it would be no use)")
	}
	for name, list := range map[string]func(string) error{"slice-2 agent": slice2AgentList, "pre-ADR agent": olderAgentList} {
		if err := list(rdir); !errors.Is(err, ErrCorruptRecord) {
			t.Errorf("%s with an intent open: List err = %v, want it to fail closed", name, err)
		}
	}
	if recs, err := a.j.List(); err != nil || len(recs) != 1 {
		t.Errorf("this build's List with the fence up: %d records, err %v; want the one record", len(recs), err)
	}
	if err := a.j.EndCommand(intentOp); err != nil {
		t.Fatal(err)
	}
	for name, list := range map[string]func(string) error{"slice-2 agent": slice2AgentList, "pre-ADR agent": olderAgentList} {
		if err := list(rdir); err != nil {
			t.Errorf("%s after the command returned: %v, want it to start", name, err)
		}
	}
	// A record whose command has returned is byte-identical to what it was.
	if after := rawRecordFile(t, dir, intentOp); after != before {
		t.Errorf("record after the command returned differs from before it:\n%s\n---\n%s", before, after)
	}
}

// TestIntentFence_UpExactlyWhileAnIntentIsOnDisk: across two records, a failed
// close healed by a later write, a record removed with its intent open, and an
// agent start that takes what a dead process left.
func TestIntentFence_UpExactlyWhileAnIntentIsOnDisk(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	a.seed(intentOp)
	a.seed(intentOp2)
	want := func(when string, on bool) {
		t.Helper()
		if got, err := a.j.IntentFenceActive(); err != nil || got != on {
			t.Fatalf("%s: intent fence = %v (err %v), want %v", when, got, err, on)
		}
	}
	now := time.Now().UTC()
	want("nothing begun", false)
	_, _ = a.j.BeginCommand(intentOp, MutationComposeUp, now)
	_, _ = a.j.BeginCommand(intentOp2, MutationComposeDown, now)
	want("two open", true)
	_ = a.j.EndCommand(intentOp)
	want("one still open", true)
	a.j.SetWriteErrorForTest(errors.New("no space left on device"))
	_ = a.j.EndCommand(intentOp2) // the close cannot be written
	a.j.SetWriteErrorForTest(nil)
	want("close failed: the intent is still on disk", true)
	a.phaseAdvance(intentOp2) // the operation's next write drops it
	want("stale intent dropped by a later write", false)

	_, _ = a.j.BeginCommand(intentOp, MutationComposeUp, now)
	want("open again", true)
	if err := a.j.Remove(intentOp); err != nil {
		t.Fatal(err)
	}
	want("its record removed", false)

	_, _ = a.j.BeginCommand(intentOp2, MutationComposeUp, now) // and the agent dies here
	a = newLife(t, dir)
	want("after the death, before any start of this build", true)
	a.start()
	a.j.ReleaseIntentFence() // as main.go takeCommandIntents does
	want("after a start took the intent", false)
}

// TestIntentFence_NoFenceNoIntent: if the fence cannot be written, the intent
// is not written either. Nothing can then be attributed, and no older agent
// can find an intent it would not take.
func TestIntentFence_NoFenceNoIntent(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	a.seed(intentOp)
	// Only the fence write fails; the record itself could be written.
	orig := writeIntentFence
	writeIntentFence = func(string, []byte, os.FileMode) error { return errors.New("no space left on device") }
	_, err := a.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC())
	writeIntentFence = orig
	if err == nil {
		t.Fatal("BeginCommand reported success without a fence")
	}
	if strings.Contains(rawRecordFile(t, dir, intentOp), `"intent"`) {
		t.Error("an intent is on disk without its fence")
	}
	if died := newLife(t, dir).start(); len(died) != 0 {
		t.Errorf("the next start concludes %v from a command whose intent was never written", died)
	}
}

// TestIntentFence_StaysWhenTheJournalCannotBeJudged: a file in the journal that
// cannot be read may be a record with an open intent. The fence is kept.
func TestIntentFence_StaysWhenTheJournalCannotBeJudged(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	a.seed(intentOp)
	a.seed(intentOp2)
	_, _ = a.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC())
	if err := os.WriteFile(filepath.Join(dir, "reconcile", intentOp2+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = a.j.EndCommand(intentOp)
	if on, _ := a.j.IntentFenceActive(); !on {
		t.Error("the fence was removed although one journal file cannot be read")
	}
}
