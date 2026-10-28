package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
