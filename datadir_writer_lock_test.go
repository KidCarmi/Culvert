package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withFreshWriterLockState isolates the package globals the guard owns. The
// handle must be restored rather than merely cleared: a test that leaves a
// locked descriptor in place would hold the lock for the rest of the binary's
// life, and one that drops the production handle would release a lock a parallel
// test is relying on.
func withFreshWriterLockState(t *testing.T) {
	t.Helper()
	origHandle, origNotice := dataDirWriterLockHandle, dataDirWriterLockNotice
	dataDirWriterLockHandle, dataDirWriterLockNotice = nil, ""
	t.Cleanup(func() {
		if dataDirWriterLockHandle != nil && dataDirWriterLockHandle != origHandle {
			_ = dataDirWriterLockHandle.Close()
		}
		dataDirWriterLockHandle, dataDirWriterLockNotice = origHandle, origNotice
	})
}

// TestDataDirSingleWriter_SecondAttemptRefused is the CHAOS-103 gate: a second
// acquisition against a directory a LIVE holder already locked must refuse.
//
// flock is associated with the open file DESCRIPTION, not the process, so two
// independent os.OpenFile calls conflict inside one process exactly as two
// processes do (flock(2): "an attempt to lock the file using one of these file
// descriptors may be denied by a lock that the calling process has already
// placed via another file descriptor"). That is what makes this testable without
// re-exec, and it is the same property the production refusal rests on.
func TestDataDirSingleWriter_SecondAttemptRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("advisory locking is not available on this platform")
	}
	withFreshWriterLockState(t)
	dir := t.TempDir()

	if err := checkDataDirSingleWriter(dir); err != nil {
		t.Fatalf("first acquisition must succeed, got %v", err)
	}
	if dataDirWriterLockHandle == nil {
		t.Fatal("a successful acquisition must retain the descriptor for the life of the process")
	}
	if dataDirWriterLockNotice != "" {
		t.Fatalf("a clean acquisition must record no notice, got %q", dataDirWriterLockNotice)
	}

	verdict, path, cause := acquireDataDirWriterLock(dir)
	if verdict != dataDirWriterHeld {
		t.Fatalf("second acquisition verdict = %v, want dataDirWriterHeld (cause=%v)", verdict, cause)
	}
	if want := filepath.Join(dir, dataDirWriterLockName); path != want {
		t.Fatalf("lock path = %q, want %q", path, want)
	}
}

// TestDataDirSingleWriter_RefusalIsActionable pins what the operator reads. The
// refusal is the only thing standing between a double-start and silent mutual
// clobbering, so it has to name the remedy, not just the fault.
func TestDataDirSingleWriter_RefusalIsActionable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("advisory locking is not available on this platform")
	}
	withFreshWriterLockState(t)
	dir := t.TempDir()
	if err := checkDataDirSingleWriter(dir); err != nil {
		t.Fatalf("first acquisition: %v", err)
	}

	// A second guard call in the same process sees the live holder.
	second := checkDataDirSingleWriter(dir)
	if second == nil {
		t.Fatal("a live holder must refuse the boot")
	}
	if !errors.Is(second, errDataDirWriterHeld) {
		t.Fatalf("refusal must wrap errDataDirWriterHeld, got %v", second)
	}
	for _, want := range []string{dataDirWriterLockName, "CULVERT_DATA_DIR", allowMultipleWritersEnv} {
		if !strings.Contains(second.Error(), want) {
			t.Fatalf("refusal must mention %q; got %q", want, second.Error())
		}
	}
}

// TestDataDirSingleWriter_EscapeHatchStartsAnywayAndSaysSo holds the escape
// hatch honest: it must not silence the condition it overrides.
func TestDataDirSingleWriter_EscapeHatchStartsAnywayAndSaysSo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("advisory locking is not available on this platform")
	}
	withFreshWriterLockState(t)
	dir := t.TempDir()
	if err := checkDataDirSingleWriter(dir); err != nil {
		t.Fatalf("first acquisition: %v", err)
	}
	t.Setenv(allowMultipleWritersEnv, "1")

	if err := checkDataDirSingleWriter(dir); err != nil {
		t.Fatalf("with %s=1 the boot must proceed, got %v", allowMultipleWritersEnv, err)
	}
	if !strings.Contains(dataDirWriterLockNotice, allowMultipleWritersEnv) {
		t.Fatalf("the override must record a notice naming itself, got %q", dataDirWriterLockNotice)
	}
	if !strings.Contains(dataDirWriterLockNotice, "roster") {
		t.Fatalf("the notice must state what two writers cost, got %q", dataDirWriterLockNotice)
	}
}

// TestDataDirSingleWriter_UnobservableLockDegrades is the negative control for
// the fail-safe half of the rule. A root the process cannot create the lock file
// under is an existing documented degraded mode (CHAOS-05/07: a read-only or
// permission-denied volume still serves), so it must NOT become an unbootable
// gateway — it must boot and report.
//
// The unopenable root is a regular FILE rather than a 0o500 directory on
// purpose: the container CI runs as uid 0, which bypasses directory permissions,
// so a mode-based fixture would silently skip this control exactly where it
// matters. ENOTDIR is refused for root too.
func TestDataDirSingleWriter_UnobservableLockDegrades(t *testing.T) {
	withFreshWriterLockState(t)
	notADir := filepath.Join(t.TempDir(), "data-is-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	verdict, _, cause := acquireDataDirWriterLock(notADir)
	if verdict != dataDirWriterUndetermined {
		t.Fatalf("verdict = %v, want dataDirWriterUndetermined (cause=%v)", verdict, cause)
	}
	if err := checkDataDirSingleWriter(notADir); err != nil {
		t.Fatalf("an unobservable lock state must degrade, not refuse; got %v", err)
	}
	if !strings.Contains(dataDirWriterLockNotice, "not established") {
		t.Fatalf("the degraded path must record a notice, got %q", dataDirWriterLockNotice)
	}
	if dataDirWriterLockHandle != nil {
		t.Fatal("a failed acquisition must not retain a descriptor")
	}
}

// TestDataDirSingleWriter_NoRootConfiguredDegrades covers the one caller input
// the guard cannot act on at all.
func TestDataDirSingleWriter_NoRootConfiguredDegrades(t *testing.T) {
	withFreshWriterLockState(t)
	if err := checkDataDirSingleWriter(""); err != nil {
		t.Fatalf("an empty persisted-state root must degrade, got %v", err)
	}
	if dataDirWriterLockNotice == "" {
		t.Fatal("an empty persisted-state root must still be reported")
	}
}

// TestDataDirWriterLockNotice_EmittedOnce pins that the deferred notice reaches
// the application log and is not repeated by a later caller.
func TestDataDirWriterLockNotice_EmittedOnce(t *testing.T) {
	withFreshWriterLockState(t)
	dataDirWriterLockNotice = "DataDir: single-writer lock not established on \"x\" (test)"

	sink := captureLoggerForTest(t)
	logDataDirWriterLockNotice()
	logDataDirWriterLockNotice()

	if got := strings.Count(sink.String(), "single-writer lock not established"); got != 1 {
		t.Fatalf("notice emitted %d times, want exactly 1 (log=%q)", got, sink.String())
	}
	if dataDirWriterLockNotice != "" {
		t.Fatalf("the notice must be cleared after emission, got %q", dataDirWriterLockNotice)
	}
}

// TestDataDirWriterLock_NotInBackupManifest keeps the lock file out of the
// artifact set: an archived lock file restored onto another node would be a
// zero-byte file whose only meaning is a lock nobody holds, and adding it to the
// manifest would make the backup's required-artifact check depend on it.
func TestDataDirWriterLock_NotInBackupManifest(t *testing.T) {
	for _, art := range defaultBackupArtifacts(t.TempDir()) {
		if strings.Contains(art.SrcPath, dataDirWriterLockName) || strings.Contains(art.TarPath, dataDirWriterLockName) {
			t.Fatalf("the single-writer lock must not be a backup artifact, found %+v", art)
		}
	}
}

// TestDataDirSingleWriter_AcquiresOnAFirstBootWhoseRootDoesNotExistYet is the
// regression gate for the Codex P2 finding on PR #1750.
//
// The guard runs long before the statement that creates the data root
// (initPAC → loadPAC's MkdirAll), so on a genuine fresh install the lock-file
// open returned ENOENT, the guard degraded, and the process held NOTHING for
// its whole life — while startup went on to create the directory, so a second
// process could take the lock and boot alongside it. On a healthy filesystem,
// which is what made it worse than the degraded cases this rule is for.
//
// Reproduced before the fix with two real processes against a non-existent
// CULVERT_DATA_DIR: "NO LOCK FILE", both processes alive.
func TestDataDirSingleWriter_AcquiresOnAFirstBootWhoseRootDoesNotExistYet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("advisory locking is not available on this platform")
	}
	withFreshWriterLockState(t)
	root := filepath.Join(t.TempDir(), "data-not-created-yet")
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("premise broken: %q must not exist, stat err = %v", root, err)
	}

	if err := checkDataDirSingleWriter(root); err != nil {
		t.Fatalf("a first boot must acquire the lock, not refuse: %v", err)
	}
	if dataDirWriterLockHandle == nil {
		t.Fatal("a first boot must HOLD the lock; a degraded verdict here leaves the guard inert for the whole process lifetime")
	}
	if dataDirWriterLockNotice != "" {
		t.Fatalf("a first boot on a healthy volume must record no degraded notice, got %q", dataDirWriterLockNotice)
	}
	if _, err := os.Stat(filepath.Join(root, dataDirWriterLockName)); err != nil {
		t.Fatalf("the lock file must exist after acquisition: %v", err)
	}

	// And the lock it took must actually exclude a second process.
	if verdict, _, cause := acquireDataDirWriterLock(root); verdict != dataDirWriterHeld {
		t.Fatalf("second acquisition verdict = %v, want dataDirWriterHeld (cause=%v)", verdict, cause)
	}
}

// TestDataDirSingleWriter_DoesNotCreateTheRootWhenCreationFails keeps the
// fail-safe half intact now that the guard creates the root: a root that cannot
// be created must still degrade rather than refuse, and must not leave a
// half-made directory or a retained descriptor behind.
func TestDataDirSingleWriter_DoesNotCreateTheRootWhenCreationFails(t *testing.T) {
	withFreshWriterLockState(t)
	parent := filepath.Join(t.TempDir(), "parent-is-a-file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	root := filepath.Join(parent, "data") // cannot be created: parent is a file

	verdict, _, cause := acquireDataDirWriterLock(root)
	if verdict != dataDirWriterUndetermined {
		t.Fatalf("verdict = %v, want dataDirWriterUndetermined (cause=%v)", verdict, cause)
	}
	if err := checkDataDirSingleWriter(root); err != nil {
		t.Fatalf("an uncreatable root must degrade, not refuse; got %v", err)
	}
	if dataDirWriterLockHandle != nil {
		t.Fatal("a failed acquisition must not retain a descriptor")
	}
}

// TestDataDirSingleWriter_MustNotRunBeforeTheInterruptedRestoreRefusal pins the
// interaction the MkdirAll above creates.
//
// Acquiring the lock now CREATES the data root, and checkInterruptedRestore
// (RISK-005) diagnoses a restore commit killed mid-rename by exactly that root
// being ABSENT while a `.bak` sibling holds the operator's previous data. So
// running the single-writer guard first would create the root, make the refusal
// a no-op, and boot the gateway on an empty volume with the real data stranded
// in a `.bak` nobody is told about — losing the data that refusal exists to
// save.
//
// main's order makes this safe (checkInterruptedRestore exits the process
// before the guard is reached), and both halves are asserted here so a future
// reorder fails a test instead of silently destroying the evidence. Verified
// end to end against the built binary: with a well-formed `.bak` sibling the
// process exits 1 on "interrupted restore detected" and the root is still
// absent afterwards.
func TestDataDirSingleWriter_MustNotRunBeforeTheInterruptedRestoreRefusal(t *testing.T) {
	withFreshWriterLockState(t)
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "data") // absent: renamed aside, commit killed
	makeDir(t, parent, leftoverName("bak", time.Unix(1_700_000_000, 0), 4242))

	// Half one: the refusal fires on this state, so main exits before the guard.
	if err := checkInterruptedRestore(dataDir); err == nil {
		t.Fatal("premise broken: checkInterruptedRestore must refuse an absent root with a .bak sibling")
	}

	// Half two: the guard WOULD create the root, which is why it must run after.
	if err := checkDataDirSingleWriter(dataDir); err != nil {
		t.Fatalf("guard: %v", err)
	}
	if _, err := os.Stat(dataDir); err != nil {
		t.Fatalf("expected the guard to create the root (that is the hazard being pinned): %v", err)
	}
}
