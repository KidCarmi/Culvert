package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const intentOp = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

func intentRec() Record {
	now := time.Now().UTC()
	return Record{OpID: intentOp, Kind: "upgrades.apply", Phase: PhaseRestarting, StartedAt: now, UpdatedAt: now}
}

const seenCap = 1_000_000

// TestIntent_AttributionSequences walks a record through agent lives. Each
// step is what one process does to the record; want is CutByThisStart for
// `compose up` as the reconcile of the LAST start in the sequence would read
// it. The rows are the acceptance cases of ADR-0062 slice 3 (from the three
// reviews of #2093) reduced to the record.
func TestIntent_AttributionSequences(t *testing.T) {
	now := time.Now().UTC()
	begin := func(r *Record) { r.BeginCommand(MutationComposeUp, now) }
	end := func(r *Record) { r.EndCommand() }
	start := func(r *Record) { r.SeenByStartup(now, seenCap) }
	for _, tc := range []struct {
		name  string
		steps []func(*Record)
		want  bool
	}{
		{"positive: died inside up, first start after it", []func(*Record){begin, start}, true},
		{"A/E: a start has already looked (any mode); the next one is told nothing", []func(*Record){begin, start, start}, false},
		{"C: the command returned to a live agent, then the agent restarted", []func(*Record){begin, end, start}, false},
		{"C: an earlier cut, then a command that returned (a failed restore), then a restart", []func(*Record){begin, start, begin, end, start}, false},
		{"positive: a recovery that died in its own up is attributable once more", []func(*Record){begin, start, begin, start}, true},
		{"and not after the start that follows", []func(*Record){begin, start, begin, start, start}, false},
		{"no command was ever begun", []func(*Record){start}, false},
		{"begun, and the process is still alive (no start has seen it)", []func(*Record){begin}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := intentRec()
			for _, st := range tc.steps {
				st(&r)
			}
			if got := r.CutByThisStart(MutationComposeUp); got != tc.want {
				t.Errorf("CutByThisStart = %v, want %v (record: intent=%+v cut=%+v seen=%d)", got, tc.want, r.Intent, r.Cut, r.InterruptedSeen)
			}
		})
	}
}

// TestIntent_NoClockDecides (case D): the start's clock is behind the time the
// command was begun, or far ahead of it. The intent is consumed all the same,
// attributed to that start, and spent at the next one.
func TestIntent_NoClockDecides(t *testing.T) {
	began := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for name, startClock := range map[string]time.Time{
		"clock behind began":   began.Add(-6 * time.Hour),
		"clock years after it": began.AddDate(3, 0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			r := intentRec()
			r.BeginCommand(MutationComposeUp, began)
			r.SeenByStartup(startClock, seenCap)
			if r.Intent != nil || !r.CutByThisStart(MutationComposeUp) {
				t.Fatalf("first start: intent=%+v cut=%+v, want consumed and attributed", r.Intent, r.Cut)
			}
			r.SeenByStartup(began.Add(time.Minute), seenCap) // the clock is right again
			if r.CutByThisStart(MutationComposeUp) {
				t.Error("a later start, with the clock in range, is told the agent died in the command")
			}
		})
	}
}

// TestIntent_IsPerRecordAndPerCommand (case B): what one operation's record
// says is no evidence about another's, and a cut `compose down` is not a cut
// `compose up`.
func TestIntent_IsPerRecordAndPerCommand(t *testing.T) {
	now := time.Now().UTC()
	older, newer := intentRec(), intentRec()
	newer.OpID = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
	newer.BeginCommand(MutationComposeUp, now)
	older.SeenByStartup(now, seenCap)
	newer.SeenByStartup(now, seenCap)
	if older.CutByThisStart(MutationComposeUp) || older.Cut != nil {
		t.Errorf("the older record carries a cut it never had: %+v", older.Cut)
	}
	if !newer.CutByThisStart(MutationComposeUp) {
		t.Error("the newer record's own cut is not reported")
	}
	if newer.CutByThisStart(MutationComposeDown) {
		t.Error("a cut `compose up` reads as a cut `compose down`")
	}
}

// TestIntent_AtTheStartCounterCap: once the per-record start counter stops
// advancing, a start can no longer be told from the one before it. Nothing is
// attributed then, neither a new cut nor one taken earlier.
func TestIntent_AtTheStartCounterCap(t *testing.T) {
	now := time.Now().UTC()
	r := intentRec()
	r.InterruptedSeen = 2
	r.BeginCommand(MutationComposeUp, now)
	r.SeenByStartup(now, 3) // advances to the cap: still a distinct start
	if !r.CutByThisStart(MutationComposeUp) {
		t.Fatal("the start that reached the cap is distinct and must be attributed")
	}
	r.SeenByStartup(now, 3) // cannot advance
	if r.CutByThisStart(MutationComposeUp) {
		t.Error("an earlier cut still matches once the counter is stuck")
	}
	r.BeginCommand(MutationComposeUp, now)
	r.SeenByStartup(now, 3)
	if r.Intent != nil || r.CutByThisStart(MutationComposeUp) {
		t.Errorf("at the cap: intent=%+v cut=%+v, want consumed and not attributed", r.Intent, r.Cut)
	}
}

// TestIntent_IsDurableAndFenced: the intent survives Write/Read, the record
// is schema 2, and the downgrade fence is in place before the record is (an
// agent that predates the field would drop it on its next rewrite).
func TestIntent_IsDurableAndFenced(t *testing.T) {
	dir := t.TempDir()
	j, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := intentRec()
	if err := j.Write(r); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); on {
		t.Fatal("fence active for a record without an intent")
	}
	r.BeginCommand(MutationComposeUp, time.Now().UTC())
	if err := j.Write(r); err != nil {
		t.Fatal(err)
	}
	if on, err := j.FenceActive(); err != nil || !on {
		t.Fatalf("fence active = %v (%v) with an open intent on disk, want true", on, err)
	}
	got, found, err := j.Read(intentOp)
	if err != nil || !found {
		t.Fatalf("read: %v found=%v", err, found)
	}
	if got.Intent == nil || got.Intent.Command != MutationComposeUp || got.EffectiveSchema() < SchemaFenced {
		t.Fatalf("read back intent=%+v schema=%d", got.Intent, got.EffectiveSchema())
	}
	got.SeenByStartup(time.Now().UTC(), seenCap)
	if err := j.Write(*got); err != nil {
		t.Fatal(err)
	}
	again, _, _ := j.Read(intentOp)
	if again.Intent != nil || !again.CutByThisStart(MutationComposeUp) {
		t.Fatalf("after the start's write: intent=%+v cut=%+v", again.Intent, again.Cut)
	}
	// A consumed cut needs no fence: the record is schema 1 again (no "schema"
	// key on disk) and the fence is gone with the last record that needed it.
	raw, _ := os.ReadFile(filepath.Join(j.Dir(), intentOp+".json")) // #nosec G304 -- test-owned temp dir
	if strings.Contains(string(raw), `"schema"`) || again.EffectiveSchema() != 1 {
		t.Errorf("record with a consumed cut is not schema 1:\n%s", raw)
	}
	if on, _ := j.FenceActive(); on {
		t.Error("the fence is still up for a record whose intent was consumed")
	}
}

// TestIntent_FenceOnlyWhileOpen: the fence goes up with the intent and comes
// down when the command returns; another record that still has an open intent
// keeps it up.
func TestIntent_FenceOnlyWhileOpen(t *testing.T) {
	j, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a, b := intentRec(), intentRec()
	b.OpID = "01BX5ZZKBKACTAV9WEVGEMMVRZ"
	a.BeginCommand(MutationComposeUp, now)
	b.BeginCommand(MutationComposeDown, now)
	for _, r := range []Record{a, b} {
		if err := j.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	a.EndCommand()
	if err := j.Write(a); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); !on {
		t.Fatal("the fence came down while another record still has an open intent")
	}
	b.EndCommand()
	if err := j.Write(b); err != nil {
		t.Fatal(err)
	}
	if on, _ := j.FenceActive(); on {
		t.Fatal("the fence is still up with no open intent left")
	}
}

// TestIntent_AForgedCutDoesNotMatch: the record is a file anyone with access
// to the state directory can edit. A cut that names start 0 on a record no
// start has counted must not read as "this start".
func TestIntent_AForgedCutDoesNotMatch(t *testing.T) {
	r := intentRec()
	r.Cut = &CommandCut{Command: MutationComposeUp, Seen: 0}
	if r.CutByThisStart(MutationComposeUp) {
		t.Error("cut.seen 0 matches interrupted_seen 0")
	}
	r.Cut.Seen, r.InterruptedSeen = -1, -1
	if r.CutByThisStart(MutationComposeUp) {
		t.Error("a negative ordinal matches")
	}
}
