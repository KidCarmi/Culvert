package writerlock

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// flock is tied to the open file DESCRIPTION, not the process, so two
// independent opens conflict inside one process exactly as two processes do.
// That is what makes Held testable without re-exec.

func mustTake(t *testing.T, dir string) *Lock {
	t.Helper()
	got := Take(dir)
	if got.Verdict != Acquired || got.Lock == nil || got.Cause != nil {
		t.Fatalf("Take(%q) = %+v, want Acquired with a lock and no cause", dir, got)
	}
	t.Cleanup(func() { _ = got.Lock.Close() })
	return got.Lock
}

func skipWithoutFlock(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("advisory locking is not available on this platform")
	}
}

func TestTake_FirstAcquiresSecondIsHeld(t *testing.T) {
	skipWithoutFlock(t)
	dir := t.TempDir()
	mustTake(t, dir)

	second := Take(dir)
	if second.Verdict != Held {
		t.Fatalf("second verdict = %v (cause=%v), want Held", second.Verdict, second.Cause)
	}
	if second.Lock != nil {
		t.Fatal("a Held attempt must not hand out a lock")
	}
	if second.Cause != nil {
		t.Fatalf("Held is an answer, not a failure; cause = %v", second.Cause)
	}
	if want := filepath.Join(dir, FileName); second.Path != want {
		t.Fatalf("path = %q, want %q", second.Path, want)
	}
}

func TestTake_CloseReleasesTheLock(t *testing.T) {
	skipWithoutFlock(t)
	dir := t.TempDir()
	first := Take(dir)
	if first.Verdict != Acquired {
		t.Fatalf("first: %+v", first)
	}
	if got := Take(dir).Verdict; got != Held {
		t.Fatalf("while open: verdict = %v, want Held", got)
	}
	if err := first.Lock.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	mustTake(t, dir)
}

// A Held attempt closes its own descriptor. If it leaked, the holder's lock
// would still be intact, so this checks the other direction: the refused
// attempts must not have disturbed the holder, and must not keep the lock
// alive after the holder closes.
func TestTake_RefusedAttemptsNeitherStealNorKeepTheLock(t *testing.T) {
	skipWithoutFlock(t)
	dir := t.TempDir()
	first := Take(dir)
	if first.Verdict != Acquired {
		t.Fatalf("first: %+v", first)
	}
	for i := 0; i < 5; i++ {
		if got := Take(dir).Verdict; got != Held {
			t.Fatalf("attempt %d: verdict = %v, want Held", i, got)
		}
	}
	if err := first.Lock.Close(); err != nil {
		t.Fatal(err)
	}
	mustTake(t, dir)
}

func TestTake_DirectoriesAreIndependent(t *testing.T) {
	skipWithoutFlock(t)
	a, b := t.TempDir(), t.TempDir()
	mustTake(t, a)
	mustTake(t, b)
	if got := Take(a).Verdict; got != Held {
		t.Fatalf("a: verdict = %v, want Held", got)
	}
	if got := Take(b).Verdict; got != Held {
		t.Fatalf("b: verdict = %v, want Held", got)
	}
}

func TestTake_NoDirectoryIsUndeterminedWithNoPath(t *testing.T) {
	got := Take("")
	if got.Verdict != Undetermined || got.Cause == nil || got.Lock != nil {
		t.Fatalf("Take(\"\") = %+v, want Undetermined with a cause and no lock", got)
	}
	if got.Path != "" {
		t.Fatalf("path = %q, want empty: no directory was named", got.Path)
	}
}

// The unopenable root is a regular FILE, not a 0o500 directory: CI runs as
// uid 0, which bypasses directory permissions. ENOTDIR is refused for root too.
func TestTake_RootThatIsAFileIsUndetermined(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "data-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := Take(notADir)
	if got.Verdict != Undetermined || got.Cause == nil || got.Lock != nil {
		t.Fatalf("got %+v, want Undetermined with a cause and no lock", got)
	}
	if want := filepath.Join(notADir, FileName); got.Path != want {
		t.Fatalf("path = %q, want %q", got.Path, want)
	}
	if b, err := os.ReadFile(notADir); err != nil || string(b) != "x" {
		t.Fatalf("the file standing in for the root was disturbed: %q, %v", b, err)
	}
}

func TestTake_UncreatableRootIsUndeterminedAndLeavesNothing(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent-is-a-file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "data")
	got := Take(root)
	if got.Verdict != Undetermined || got.Cause == nil || got.Lock != nil {
		t.Fatalf("got %+v, want Undetermined with a cause and no lock", got)
	}
	if want := filepath.Join(root, FileName); got.Path != want {
		t.Fatalf("path = %q, want %q", got.Path, want)
	}
}

// The directory exists but the lock file cannot be opened. A directory in the
// lock file's place is refused for uid 0 too (EISDIR), unlike a mode bit.
func TestTake_UnopenableLockFileIsUndetermined(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, FileName), 0o700); err != nil {
		t.Fatal(err)
	}
	got := Take(dir)
	if got.Verdict != Undetermined || got.Cause == nil || got.Lock != nil {
		t.Fatalf("got %+v, want Undetermined with a cause and no lock", got)
	}
	if want := filepath.Join(dir, FileName); got.Path != want {
		t.Fatalf("path = %q, want %q", got.Path, want)
	}
}

func TestTake_CreatesAnAbsentRootAndHoldsIt(t *testing.T) {
	skipWithoutFlock(t)
	root := filepath.Join(t.TempDir(), "not", "created", "yet")
	mustTake(t, root)

	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatalf("the root must exist after acquisition: %v", err)
	}
	if got := info.Mode().Perm(); got&^0o700 != 0 {
		t.Fatalf("created root mode = %o, want no bit outside 0700", got)
	}
	lf, err := os.Stat(filepath.Join(root, FileName))
	if err != nil {
		t.Fatalf("lock file: %v", err)
	}
	if lf.Size() != 0 {
		t.Fatalf("lock file size = %d, want 0", lf.Size())
	}
	if got := lf.Mode().Perm(); got&^0o600 != 0 {
		t.Fatalf("lock file mode = %o, want no bit outside 0600", got)
	}
	if got := Take(root).Verdict; got != Held {
		t.Fatalf("second verdict = %v, want Held", got)
	}
}

func TestTake_LeavesAnExistingRootModeAlone(t *testing.T) {
	skipWithoutFlock(t)
	root := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	mustTake(t, root)
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("root mode = %o, want 750 unchanged", got)
	}
}

// The lock file is expected to survive across boots: a file left behind by a
// process that no longer holds it is not a lock.
func TestTake_ALeftoverLockFileIsNotALock(t *testing.T) {
	skipWithoutFlock(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mustTake(t, dir)
}

func TestFileName_IsTheShippedName(t *testing.T) {
	// A running older process holds its lock on this exact name. Renaming it
	// would let a new binary boot beside an old one during an upgrade.
	if FileName != ".culvert-writer.lock" {
		t.Fatalf("FileName = %q", FileName)
	}
	if Acquired != 0 || Held != 1 || Undetermined != 2 {
		t.Fatalf("verdict values moved: %d %d %d", Acquired, Held, Undetermined)
	}
}
