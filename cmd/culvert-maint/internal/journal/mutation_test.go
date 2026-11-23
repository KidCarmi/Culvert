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

// TestMutationLog_FirstUseThenClean: the first open of a state directory
// cannot tell whether an older agent left a command unfinished (FirstUse);
// every later open without a marker is clean.
func TestMutationLog_FirstUseThenClean(t *testing.T) {
	dir := t.TempDir()
	if _, at := openMut(t, dir); !at.FirstUse || at.Pending {
		t.Fatalf("first open = %+v, want FirstUse and not Pending", at)
	}
	if _, at := openMut(t, dir); at.FirstUse || at.Pending {
		t.Fatalf("second open = %+v, want neither", at)
	}
}

// TestMutationLog_BeginIsSeenUntilEnd: a marker written by Begin is found by
// the next open, whether or not the process that wrote it is still there, and
// is gone after End. End without a marker is not an error.
func TestMutationLog_BeginIsSeenUntilEnd(t *testing.T) {
	dir := t.TempDir()
	m, _ := openMut(t, dir)
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
	dir := t.TempDir()
	openMut(t, dir)
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
	dir := t.TempDir()
	m, _ := openMut(t, dir)
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
