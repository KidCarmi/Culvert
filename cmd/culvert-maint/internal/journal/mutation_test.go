package journal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func openMut(t *testing.T, dir string) (*MutationLog, MutationAtOpen) {
	t.Helper()
	m, at, err := OpenMutationLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	return m, at
}

// cleanMut returns a log on a state directory that is past its first use: the
// "unknown" marker of the first open has been cleared.
func cleanMut(t *testing.T) (m *MutationLog, dir string) {
	t.Helper()
	dir = t.TempDir()
	m, _ = openMut(t, dir)
	if err := m.End(); err != nil {
		t.Fatal(err)
	}
	return m, dir
}

// TestMutationLog_FirstUseIsDurablyUnknown: the first open of a state directory
// cannot tell whether an older agent left a command unfinished. That doubt is
// written down, so a second start (inside the window, or after the first one
// failed half-way) still finds it; it is not "only up"; and it goes away only
// when End clears it.
func TestMutationLog_FirstUseIsDurablyUnknown(t *testing.T) {
	dir := t.TempDir()
	if _, at := openMut(t, dir); !at.FirstUse || !at.Pending || at.OnlyUp {
		t.Fatalf("first open = %+v, want FirstUse, Pending, not OnlyUp", at)
	}
	m, at := openMut(t, dir)
	if at.FirstUse || !at.Pending || at.OnlyUp {
		t.Fatalf("second open without an End = %+v, want Pending (the first-use doubt), not FirstUse, not OnlyUp", at)
	}
	if err := m.End(); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); at.FirstUse || at.Pending {
		t.Fatalf("open after End = %+v, want clean", at)
	}
}

// TestMutationLog_BeginIsSeenUntilEnd: a marker written by Begin is found by
// the next open, whether or not the process that wrote it is still there, and
// is gone after End. End without a marker is not an error.
func TestMutationLog_BeginIsSeenUntilEnd(t *testing.T) {
	m, dir := cleanMut(t)
	if err := m.Begin(MutationComposeUp); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); !at.Pending || !at.OnlyUp {
		t.Fatalf("after Begin(up): next open = %+v, want Pending and OnlyUp", at)
	}
	if !m.Pending() {
		t.Error("Pending() is false after Begin")
	}
	if err := m.End(); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); at.Pending || at.OnlyUp {
		t.Fatalf("after End: next open = %+v, want nothing", at)
	}
	if m.Pending() {
		t.Error("Pending() is true after End")
	}
	if err := m.End(); err != nil {
		t.Errorf("End without a marker: %v", err)
	}
}

// TestMutationLog_UnreadableIsPending: anything at the marker's path that is
// not "absent" counts as a marker.
func TestMutationLog_UnreadableIsPending(t *testing.T) {
	_, dir := cleanMut(t)
	if err := os.Mkdir(filepath.Join(dir, mutationDirName, mutationFileName), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); !at.Pending || at.OnlyUp {
		t.Fatalf("a non-file at the marker path: open = %+v, want Pending and not OnlyUp", at)
	}
}

// TestMutationLog_BeginFailsClosed: without its directory the marker cannot be
// written and Begin says so.
func TestMutationLog_BeginFailsClosed(t *testing.T) {
	dir := t.TempDir()
	m, _ := openMut(t, dir)
	if err := os.RemoveAll(filepath.Join(dir, mutationDirName)); err != nil {
		t.Fatal(err)
	}
	if err := m.Begin("compose up"); err == nil {
		t.Fatal("Begin reported success although nothing could be written")
	}
}

// TestMutationLog_NamesEveryCommandSinceTheLastEnd: a later command must not
// make an earlier, unfinished one look milder. A down followed by an up, with
// no End in between, is still a marker that names a down; the same holds
// across a restart, and for content that cannot be understood.
func TestMutationLog_NamesEveryCommandSinceTheLastEnd(t *testing.T) {
	m, dir := cleanMut(t)
	if err := m.Begin(MutationComposeDown); err != nil {
		t.Fatal(err)
	}
	if err := m.Begin(MutationComposeUp); err != nil {
		t.Fatal(err)
	}
	m2, at := openMut(t, dir)
	if !at.Pending || at.OnlyUp {
		t.Fatalf("down then up: open = %+v, want Pending and not OnlyUp", at)
	}
	// The next process adds an up of its own: still not "only up".
	if err := m2.Begin(MutationComposeUp); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); at.OnlyUp {
		t.Fatal("a marker carried over a restart lost the down it named")
	}

	if err := os.WriteFile(filepath.Join(dir, mutationDirName, mutationFileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); !at.Pending || at.OnlyUp {
		t.Fatalf("a marker that names no command: open = %+v, want Pending and not OnlyUp", at)
	}
}

// TestMutationLog_AHalfDoneFirstUseIsAFirstUseAgain: the first open died, or
// failed, after it made the directory and before the doubt was on disk. The
// next open must not take the bare directory for "past first use".
func TestMutationLog_AHalfDoneFirstUseIsAFirstUseAgain(t *testing.T) {
	// The directory alone.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, mutationDirName), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); !at.FirstUse || !at.Pending || at.OnlyUp {
		t.Fatalf("bare directory: open = %+v, want FirstUse and Pending", at)
	}

	// The marker written, the sentinel not yet: still a first use, and the
	// marker is kept.
	dir = t.TempDir()
	m, _ := openMut(t, dir)
	if err := os.Remove(filepath.Join(dir, mutationDirName, mutationSentinelName)); err != nil {
		t.Fatal(err)
	}
	_ = m
	if _, at := openMut(t, dir); !at.FirstUse || !at.Pending {
		t.Fatalf("marker without sentinel: open = %+v, want FirstUse and Pending", at)
	}
	if _, at := openMut(t, dir); at.FirstUse || !at.Pending {
		t.Fatalf("after a completed first use: open = %+v, want Pending and not FirstUse", at)
	}

	// A first use that finds a marker naming only `up` (written by a version
	// whose sentinel was lost) is still not "only up": the doubt is wider.
	dir = t.TempDir()
	m, _ = openMut(t, dir)
	if err := m.End(); err != nil {
		t.Fatal(err)
	}
	if err := m.Begin(MutationComposeUp); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, mutationDirName, mutationSentinelName)); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); !at.FirstUse || !at.Pending || at.OnlyUp {
		t.Fatalf("first use over an up-only marker: open = %+v, want FirstUse, Pending, not OnlyUp", at)
	}
}

// TestMutationLog_NoSentinelBeforeTheMarkerIsDurable: the sentinel says "past
// first use". It must not exist unless the "unknown" marker was written first;
// otherwise a first start that fails to write the marker would be taken for a
// clean state directory at the next start. Open still returns a usable log,
// with the doubt held in memory, and does not let the marker grow when the
// failing first use is retried.
func TestMutationLog_NoSentinelBeforeTheMarkerIsDurable(t *testing.T) {
	dir := t.TempDir()
	mdir := filepath.Join(dir, mutationDirName)
	// Something that makes writing pending.json fail: a directory in its place.
	if err := os.MkdirAll(filepath.Join(mdir, mutationFileName), 0o750); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		m, at, err := OpenMutationLog(dir)
		if err == nil {
			t.Fatal("OpenMutationLog reported success although the marker could not be written")
		}
		if m == nil || !at.Pending || !m.Pending() {
			t.Fatalf("after a failed first use: log=%v at=%+v, want a usable log with the doubt pending", m, at)
		}
		if _, serr := os.Stat(filepath.Join(mdir, mutationSentinelName)); serr == nil {
			t.Fatal("the sentinel was written although the first-use marker was not")
		}
		if err := m.Begin(MutationComposeUp); err == nil {
			t.Fatal("Begin succeeded although nothing can be written")
		}
	}

	// A first use whose marker write works but which is retried (the sentinel
	// keeps failing) does not append "unknown" again each time.
	dir = t.TempDir()
	m, _ := openMut(t, dir)
	if err := os.Remove(filepath.Join(dir, mutationDirName, mutationSentinelName)); err != nil {
		t.Fatal(err)
	}
	m2, _ := openMut(t, dir)
	if got := len(m2.open); got != len(m.open) {
		t.Errorf("a repeated first use grew the marker from %d to %d commands", len(m.open), got)
	}
}

// TestMutationLog_FreshUpOf pins the only evidence a start may use to put an
// outage down to an operation's own interrupted `compose up`: the marker names
// nothing but `compose up`, all of it for ONE operation, and no earlier start
// has found it.
func TestMutationLog_FreshUpOf(t *testing.T) {
	const opA, opB = "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01BX5ZZKBKACTAV9WEVGEMMVRZ"
	type step struct{ cmd, op string }
	for _, tc := range []struct {
		name  string
		steps []step
		want  string
	}{
		{"one up of one operation", []step{{MutationComposeUp, opA}}, opA},
		{"two ups of the same operation", []step{{MutationComposeUp, opA}, {MutationComposeUp, opA}}, opA},
		{"ups of two operations", []step{{MutationComposeUp, opA}, {MutationComposeUp, opB}}, ""},
		{"an up without an operation", []step{{MutationComposeUp, ""}}, ""},
		{"one attributed, one not", []step{{MutationComposeUp, opA}, {MutationComposeUp, ""}}, ""},
		{"a down of the operation", []step{{MutationComposeDown, opA}}, ""},
		{"down then up of the operation", []step{{MutationComposeDown, opA}, {MutationComposeUp, opA}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			m, _ := openMut(t, dir)
			if err := m.End(); err != nil { // past the first-use doubt
				t.Fatal(err)
			}
			for _, st := range tc.steps {
				if err := m.BeginFor(st.cmd, st.op); err != nil {
					t.Fatal(err)
				}
			}
			_, at := openMut(t, dir)
			if at.FreshUpOf != tc.want {
				t.Errorf("first start after the cut: FreshUpOf = %q, want %q (%+v)", at.FreshUpOf, tc.want, at)
			}
			if !at.Pending {
				t.Error("the marker is not pending")
			}
			// Single use: the start above has seen it. The next one is told
			// nothing, while the marker itself (and what it means for the
			// settle wait) is unchanged.
			_, again := openMut(t, dir)
			if again.FreshUpOf != "" {
				t.Errorf("second start: FreshUpOf = %q, want none (the marker was already found once)", again.FreshUpOf)
			}
			if again.Pending != at.Pending || again.OnlyUp != at.OnlyUp || again.NamesCommand != at.NamesCommand {
				t.Errorf("second start reads the marker differently: %+v, first %+v", again, at)
			}
		})
	}
}

// TestMutationLog_FreshUpOf_ACutRetryIsFreshAgain: the start that found the
// marker runs `compose up` for the same operation and dies in it. The next
// start is the first to find THAT cut, and it still belongs to the operation.
// A command for another operation in between ends the attribution.
func TestMutationLog_FreshUpOf_ACutRetryIsFreshAgain(t *testing.T) {
	const opA, opB = "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01BX5ZZKBKACTAV9WEVGEMMVRZ"
	dir := t.TempDir()
	m, _ := openMut(t, dir)
	if err := m.End(); err != nil {
		t.Fatal(err)
	}
	if err := m.BeginFor(MutationComposeUp, opA); err != nil {
		t.Fatal(err)
	}
	m2, at := openMut(t, dir)
	if at.FreshUpOf != opA {
		t.Fatalf("FreshUpOf = %q, want %q", at.FreshUpOf, opA)
	}
	if err := m2.BeginFor(MutationComposeUp, opA); err != nil { // the restore's own up, cut
		t.Fatal(err)
	}
	m3, at := openMut(t, dir)
	if at.FreshUpOf != opA {
		t.Fatalf("after a cut retry for the same operation: FreshUpOf = %q, want %q", at.FreshUpOf, opA)
	}
	if err := m3.BeginFor(MutationComposeUp, opB); err != nil {
		t.Fatal(err)
	}
	if _, at := openMut(t, dir); at.FreshUpOf != "" {
		t.Fatalf("after another operation's up: FreshUpOf = %q, want none", at.FreshUpOf)
	}
}

// TestMutationLog_FreshUpOf_NeedsTheMarkerToSayWhose: a marker written by an
// agent that did not record operations (or by one that dropped them) names no
// owner, and a marker already stamped as seen stays seen.
func TestMutationLog_FreshUpOf_NeedsTheMarkerToSayWhose(t *testing.T) {
	const opA = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	for name, body := range map[string]string{
		"no ops field":       `{"commands":["compose up"],"started_at":"2026-01-01T00:00:00Z"}`,
		"ops shorter":        `{"commands":["compose up","compose up"],"ops":["` + opA + `"],"started_at":"2026-01-01T00:00:00Z"}`,
		"already seen":       `{"commands":["compose up"],"ops":["` + opA + `"],"seen":true,"started_at":"2026-01-01T00:00:00Z"}`,
		"first-use unknown":  `{"commands":["unknown","compose up"],"ops":["","` + opA + `"],"started_at":"2026-01-01T00:00:00Z"}`,
		"empty operation id": `{"commands":["compose up"],"ops":[""],"started_at":"2026-01-01T00:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			m, _ := openMut(t, dir)
			if err := m.End(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, mutationDirName, mutationFileName), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, at := openMut(t, dir); at.FreshUpOf != "" || !at.Pending {
				t.Errorf("open = %+v, want Pending and no FreshUpOf", at)
			}
		})
	}
}

// TestMutationLog_FreshUpOf_NotGrantedWhenTheStampCannotBeWritten: single use
// rests on the durable "seen" stamp. If it cannot be written, this start is
// told nothing: it could otherwise be told the same thing again later.
func TestMutationLog_FreshUpOf_NotGrantedWhenTheStampCannotBeWritten(t *testing.T) {
	const opA = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	dir := t.TempDir()
	m, _ := openMut(t, dir)
	if err := m.End(); err != nil {
		t.Fatal(err)
	}
	if err := m.BeginFor(MutationComposeUp, opA); err != nil {
		t.Fatal(err)
	}
	orig := writeMarkerFile
	writeMarkerFile = func(string, []byte, os.FileMode) error { return errors.New("read-only file system") }
	_, at, _ := OpenMutationLog(dir)
	writeMarkerFile = orig
	if at.FreshUpOf != "" || !at.Pending || !at.OnlyUp {
		t.Errorf("open with an unwritable marker = %+v, want Pending, OnlyUp and no FreshUpOf", at)
	}
	// Nothing was stamped, so the start after it is still the first to be told.
	if _, at := openMut(t, dir); at.FreshUpOf != opA {
		t.Errorf("next open, writable again: FreshUpOf = %q, want %q", at.FreshUpOf, opA)
	}
}
