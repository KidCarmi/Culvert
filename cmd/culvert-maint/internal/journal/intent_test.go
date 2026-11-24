package journal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestIntent_NeedsNoSchemaAndNoFence: a record with an open intent is written
// at schema 1 with no downgrade fence. An agent older than the lossless
// rewrite drops the key (nothing is attributed); one that carries it counts
// its start, which the epoch catches (the "downgrade" rows above).
func TestIntent_NeedsNoSchemaAndNoFence(t *testing.T) {
	dir := t.TempDir()
	a := newLife(t, dir)
	a.seed(intentOp)
	before := rawRecordFile(t, dir, intentOp)
	if _, err := a.j.BeginCommand(intentOp, MutationComposeUp, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	during := rawRecordFile(t, dir, intentOp)
	if strings.Contains(during, `"schema"`) {
		t.Errorf("an open intent raised the record's schema:\n%s", during)
	}
	if on, _ := a.j.FenceActive(); on {
		t.Error("an open intent put the downgrade fence up")
	}
	if err := a.j.EndCommand(intentOp); err != nil {
		t.Fatal(err)
	}
	// A record whose command has returned is byte-identical to what it was.
	if after := rawRecordFile(t, dir, intentOp); after != before {
		t.Errorf("record after the command returned differs from before it:\n%s\n---\n%s", before, after)
	}
}
