package journal

import (
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
