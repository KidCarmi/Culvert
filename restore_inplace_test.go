package main

// restore_inplace_test.go — gates for the journaled in-place restore swap
// (restore_inplace.go): interruption at each phase boundary is recoverable in
// BOTH directions, recovery is idempotent, the boot guard refuses while a
// journal exists, the running proxy's data-dir lock makes the commit refuse,
// and the leftover scanner sees in-place leftovers without ever offering an
// unresolved journal's material for deletion.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// interruptCommit runs a full-mode commit against a fresh fixture and
// interrupts it at the given point. It returns the data dir and the names of
// the previous ("bob") and restored ("alice") markers.
func interruptCommit(t *testing.T, where string) (currentDir string) {
	t.Helper()
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	seedFile(t, currentDir, "proxy.log", []byte("previous log"), 0o600)
	switch where {
	case "between":
		commitInjectBetweenRenames = func() error { return os.ErrDeadlineExceeded }
		t.Cleanup(func() { commitInjectBetweenRenames = nil })
	case "evacuating":
		// Simulate a kill mid-evacuation: let the real commit reach the
		// promoting phase, then rewind the on-disk state to "evacuating with
		// one entry still live" by moving one entry back and rewriting the
		// journal. The resulting layout is exactly what a kill between two
		// renames of the evacuation loop leaves behind.
		commitInjectBetweenRenames = func() error { return os.ErrDeadlineExceeded }
		t.Cleanup(func() { commitInjectBetweenRenames = nil })
	}
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil {
		t.Fatal("expected the injected interruption")
	}
	if where == "evacuating" {
		j, present, jerr := readRestoreJournal(currentDir)
		if !present || jerr != nil {
			t.Fatalf("journal: present=%v err=%v", present, jerr)
		}
		bak := filepath.Join(currentDir, j.BakDir)
		if err := os.Rename(filepath.Join(bak, "proxy.log"), filepath.Join(currentDir, "proxy.log")); err != nil {
			t.Fatalf("rewind one entry: %v", err)
		}
		j.Phase = restorePhaseEvacuating
		if err := writeRestoreJournal(currentDir, j); err != nil {
			t.Fatal(err)
		}
	}
	return currentDir
}

func userEntries(t *testing.T, dir string) []string {
	t.Helper()
	names, err := listTopLevelUserEntries(dir)
	if err != nil {
		t.Fatalf("list %s: %v", dir, err)
	}
	return names
}

func TestRecoverRestore_Revert_FromPromoting(t *testing.T) {
	dir := interruptCommit(t, "between")
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err != nil {
		t.Fatalf("revert: %v\n%s", err, out.String())
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "bob") {
		t.Errorf("revert must bring the previous roster back; got %s", body)
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "proxy.log")); string(body) != "previous log" {
		t.Errorf("revert must bring previous non-archived files back; got %q", body)
	}
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be gone after revert")
	}
	if _, ok := readBak(t, dir); ok {
		t.Error("bak dir must be empty and removed after revert")
	}
	if !stagingExists(t, dir) {
		t.Error("staged content must be kept for inspection after revert")
	}
	if err := checkInterruptedRestore(dir); err != nil {
		t.Errorf("boot guard must pass after revert: %v", err)
	}
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err != errNoInterruptedRestore {
		t.Errorf("second revert must report nothing to recover, got %v", err)
	}
}

func TestRecoverRestore_Complete_FromPromoting(t *testing.T) {
	dir := interruptCommit(t, "between")
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err != nil {
		t.Fatalf("complete: %v\n%s", err, out.String())
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "alice") {
		t.Errorf("complete must land the restored roster; got %s", body)
	}
	if _, err := os.Stat(filepath.Join(dir, "proxy.log")); !os.IsNotExist(err) {
		t.Error("complete (full mode) must not resurrect non-archived previous files in the live tree")
	}
	bak, ok := readBak(t, dir)
	if !ok {
		t.Fatal("previous data must be preserved after complete")
	}
	if body, _ := os.ReadFile(filepath.Join(bak, "proxy.log")); string(body) != "previous log" {
		t.Error("previous non-archived file must be in the bak dir")
	}
	if stagingExists(t, dir) {
		t.Error("staging dir must be removed after complete")
	}
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be gone after complete")
	}
	if err := checkInterruptedRestore(dir); err != nil {
		t.Errorf("boot guard must pass after complete: %v", err)
	}
}

func TestRecoverRestore_Revert_FromEvacuating(t *testing.T) {
	dir := interruptCommit(t, "evacuating")
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err != nil {
		t.Fatalf("revert: %v\n%s", err, out.String())
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "bob") {
		t.Errorf("revert must bring the previous roster back; got %s", body)
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "proxy.log")); string(body) != "previous log" {
		t.Errorf("the still-live entry must survive revert; got %q", body)
	}
	if _, ok := readBak(t, dir); ok {
		t.Error("bak dir must be removed after revert")
	}
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be gone after revert")
	}
}

func TestRecoverRestore_Complete_FromEvacuating(t *testing.T) {
	dir := interruptCommit(t, "evacuating")
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err != nil {
		t.Fatalf("complete: %v\n%s", err, out.String())
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "alice") {
		t.Errorf("complete must land the restored roster; got %s", body)
	}
	bak, _ := readBak(t, dir)
	if body, _ := os.ReadFile(filepath.Join(bak, "proxy.log")); string(body) != "previous log" {
		t.Error("the still-live entry must be moved aside by complete")
	}
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be gone after complete")
	}
	live := userEntries(t, dir)
	for _, n := range live {
		if n == "proxy.log" {
			t.Error("proxy.log must not remain live after complete")
		}
	}
}

func TestRecoverRestore_InspectIsReadOnly(t *testing.T) {
	dir := interruptCommit(t, "between")
	before := userEntries(t, dir)
	var out bytes.Buffer
	if err := runRecoverRestore(dir, "", &out); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !strings.Contains(out.String(), "--confirm=revert") || !strings.Contains(out.String(), "--confirm=complete") {
		t.Errorf("inspect must print both options:\n%s", out.String())
	}
	if after := userEntries(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Errorf("inspect must not move anything: before=%v after=%v", before, after)
	}
	if _, present, _ := readRestoreJournal(dir); !present {
		t.Error("inspect must keep the journal")
	}
}

func TestRecoverRestore_NothingToRecover(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err != errNoInterruptedRestore {
		t.Fatalf("want errNoInterruptedRestore, got %v", err)
	}
}

func TestRecoverRestore_MalformedJournalRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(restoreJournalPath(dir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed journal must refuse, got %v", err)
	}
	if err := checkInterruptedRestore(dir); err == nil {
		t.Fatal("boot guard must refuse on a malformed journal")
	}
}

func TestRestoreCommit_RefusesWhilePriorJournalPending(t *testing.T) {
	dir := interruptCommit(t, "between")
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "carol", Role: RoleAdmin}}, 0)
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, dir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil || !strings.Contains(err.Error(), "interrupted restore is pending") {
		t.Fatalf("a second commit must refuse while a journal is pending, got %v", err)
	}
}

func TestRestoreCommit_RefusesWhileDataDirLockHeld(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	release, err := acquireDataDirLock(currentDir)
	if err != nil {
		t.Skipf("flock unavailable: %v", err)
	}
	defer release()
	// The lock is per open-file-description, so a second acquisition from
	// this same process (a stand-in for the cli container) must fail.
	_, cerr := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if cerr == nil || !strings.Contains(cerr.Error(), "locked by another Culvert process") {
		t.Fatalf("commit must refuse while the proxy holds the data-dir lock, got %v", cerr)
	}
	if _, ok := readBak(t, currentDir); ok {
		t.Error("a refused commit must not create a bak dir")
	}
	if stagingExists(t, currentDir) {
		t.Error("a refused commit must not leave a staging dir")
	}
	release()
	// And succeed once the lock is released (the stack was stopped).
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	}); err != nil {
		t.Fatalf("commit after release: %v", err)
	}
}

func TestLeftovers_InPlaceDiscoveredAndJournalProtected(t *testing.T) {
	dir := interruptCommit(t, "between")
	valid, skipped, err := discoverLeftovers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) != 0 {
		t.Errorf("an unresolved journal's staging/bak must not be cleanup candidates, got %+v", valid)
	}
	protected := 0
	for _, s := range skipped {
		if strings.Contains(s.Reason, "unresolved interrupted restore") {
			protected++
		}
	}
	if protected != 2 {
		t.Errorf("both journal-referenced dirs must be reported as protected, got %d: %+v", protected, skipped)
	}
	// Resolve it; the surviving bak dir becomes an ordinary candidate.
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err != nil {
		t.Fatal(err)
	}
	valid, _, err = discoverLeftovers(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) != 1 || valid[0].Kind != leftoverBak || !valid[0].InDir {
		t.Fatalf("want exactly the in-place bak as a candidate, got %+v", valid)
	}
	if err := runCleanupLeftovers(dir, cleanupOpts{Confirm: true}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, ok := readBak(t, dir); ok {
		t.Error("cleanup must delete the resolved in-place bak dir")
	}
	// The live data must be untouched by cleanup.
	if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "alice") {
		t.Error("cleanup must never touch live data")
	}
}

func TestStageArtifacts_SkipsRestoreInternals(t *testing.T) {
	// A previous bak dir and a stray lock file in dataDir must never be
	// carried over into a new staging tree (they are not user data).
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	old := filepath.Join(currentDir, restoreBakPrefix+"20260101T000000Z-1")
	if err := os.MkdirAll(old, 0o700); err != nil {
		t.Fatal(err)
	}
	seedFile(t, old, "junk.txt", []byte("old"), 0o600)
	seedFile(t, currentDir, dataDirLockName, []byte(""), 0o600)
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeTrustRootOnly, AcceptDPReenrollment: true})
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(currentDir, restoreBakPrefix+"20260101T000000Z-1", "junk.txt")); err != nil {
		t.Errorf("old in-place leftover must stay where it was (never evacuated, never deleted): %v", err)
	}
	entries, _ := os.ReadDir(currentDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), restoreBakPrefix) {
			if _, err := os.Stat(filepath.Join(currentDir, e.Name(), restoreBakPrefix+"20260101T000000Z-1")); err == nil {
				t.Errorf("old leftover must not be nested into the new bak dir %s", e.Name())
			}
			if _, err := os.Stat(filepath.Join(currentDir, e.Name(), dataDirLockName)); err == nil {
				t.Errorf("lock file must not be evacuated into %s", e.Name())
			}
		}
	}
}

// ─── restore guards: inspection root CA and admin roster (appliance readiness D) ─

func TestRestoreCommit_RootCAGuard_RefusesRemovalWithoutFlag(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	// Current node has an inspection root; the archive carries none, so a
	// full-mode commit would REMOVE it and the next boot would mint a new one.
	seedFile(t, currentDir, "ca.bundle", []byte("-----BEGIN CERTIFICATE-----\nroot-bytes\n-----END CERTIFICATE-----\n"), 0o600)

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil || !strings.Contains(err.Error(), "root CA") || !strings.Contains(err.Error(), "--accept-root-ca-change") {
		t.Fatalf("removing the root CA must be refused without the flag, got: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(currentDir, "ca.bundle")); serr != nil {
		t.Fatal("a refused commit must leave the current root CA in place")
	}
	if _, ok := readBak(t, currentDir); ok {
		t.Fatal("a refused commit must not create a bak dir")
	}
	// state-only keeps the current root: no guard, commit proceeds.
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeStateOnly, AcceptDPReenrollment: true})
	}); err != nil {
		t.Fatalf("state-only must keep the root CA and commit: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(currentDir, "ca.bundle")); serr != nil {
		t.Fatal("state-only must carry the current root CA over")
	}
}

func TestRestoreCommit_RootCAGuard_AcceptedWithFlag(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	seedFile(t, currentDir, "ca.bundle", []byte("old-root"), 0o600)
	out, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true, AcceptRootCAChange: true})
	})
	if err != nil {
		t.Fatalf("accepted root CA change must commit: %v", err)
	}
	if !strings.Contains(out, "Root CA change accepted") {
		t.Errorf("summary must say the change was accepted:\n%s", out)
	}
	if _, serr := os.Stat(filepath.Join(currentDir, "ca.bundle")); !os.IsNotExist(serr) {
		t.Fatal("full mode with an archive lacking ca.bundle removes it (the accepted outcome)")
	}
	bak, _ := readBak(t, currentDir)
	if body, _ := os.ReadFile(filepath.Join(bak, "ca.bundle")); string(body) != "old-root" {
		t.Error("the previous root must be preserved in the bak dir")
	}
}

func TestRestoreCommit_RefusesLeavingNoAdmin(t *testing.T) {
	// Archive roster has a viewer only; current node has an admin.
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "eve", Role: RoleViewer}}, 0)
	currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil || !strings.Contains(err.Error(), "NO admin") {
		t.Fatalf("a commit that leaves no admin must be refused, got: %v", err)
	}
	if body, _ := os.ReadFile(filepath.Join(currentDir, "ui_users.json")); !strings.Contains(string(body), "bob") {
		t.Fatal("refusal must leave the current roster untouched")
	}
	// trust-root-only keeps the current roster and is allowed.
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeTrustRootOnly, AcceptDPReenrollment: true})
	}); err != nil {
		t.Fatalf("trust-root-only keeps the roster and must commit: %v", err)
	}
}

// swapInPlace promotes, records the `promoted` marker, removes the (empty)
// staging dir and only then retires the journal; a kill between the rmdir and
// the journal removal leaves `promoting` + marker + no staging dir + every
// restored entry live. Pre-fix `--confirm=complete` failed forever on the
// missing dir (ENOENT) and the boot guard stayed armed (Codex + adversarial
// review, PR #1528). The owner review then found the opposite hole — a
// missing dir alone is NOT proof the content landed — so the marker is what
// completes it (TestRecoverRestore_Complete_MissingStagingWithoutMarker_Refuses
// is the control).
func TestRecoverRestore_Complete_StagingAlreadyRemoved(t *testing.T) {
	dir := interruptCommit(t, "between")
	// Finish the promotion by hand up to the last step, exactly as the real
	// commit does: promote, record the marker, remove staging, die before
	// the journal removal.
	j, present, err := readRestoreJournal(dir)
	if !present || err != nil {
		t.Fatalf("journal: present=%v err=%v", present, err)
	}
	staging := filepath.Join(dir, j.StagingDir)
	if _, err := moveTopLevelEntries(staging, dir); err != nil {
		t.Fatal(err)
	}
	j.Progress = restoreProgressPromoted
	if err := writeRestoreJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(staging); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err != nil {
		t.Fatalf("complete with staging already gone must succeed: %v\n%s", err, out.String())
	}
	if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "alice") {
		t.Errorf("restored roster must stay live; got %s", body)
	}
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be retired")
	}
	if err := checkInterruptedRestore(dir); err != nil {
		t.Errorf("boot guard must pass: %v", err)
	}
	if _, ok := readBak(t, dir); !ok {
		t.Error("previous data must still be preserved")
	}
}

// A journal whose bak dir no longer exists: COMPLETE does not need the
// previous data (it creates the dir it is about to evacuate into and says
// so), but REVERT refuses — the bak dir is created before the journal, so
// its absence means it was removed, possibly with content, and the live dir
// must not be touched on that evidence (owner review, PR #1528; the
// promoting-phase twin is TestRecoverRestore_Revert_MissingBakInPromoting_RefusesAndMovesNothing).
func TestRecoverRestore_MissingBakDir(t *testing.T) {
	t.Run("complete_recreates", func(t *testing.T) {
		dir := interruptCommit(t, "evacuating")
		j, _, _ := readRestoreJournal(dir)
		if err := os.RemoveAll(filepath.Join(dir, j.BakDir)); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := runRecoverRestore(dir, recoverActionComplete, &out); err != nil {
			t.Fatalf("complete with no bak dir: %v\n%s", err, out.String())
		}
		if _, present, _ := readRestoreJournal(dir); present {
			t.Error("journal must be retired")
		}
		if err := checkInterruptedRestore(dir); err != nil {
			t.Errorf("boot guard must pass: %v", err)
		}
		if body, _ := os.ReadFile(filepath.Join(dir, "ui_users.json")); !strings.Contains(string(body), "alice") {
			t.Errorf("restored roster must be live; got %s", body)
		}
	})
	t.Run("revert_refuses", func(t *testing.T) {
		dir := interruptCommit(t, "evacuating")
		j, _, _ := readRestoreJournal(dir)
		if err := os.RemoveAll(filepath.Join(dir, j.BakDir)); err != nil {
			t.Fatal(err)
		}
		live, _ := listTopLevelUserEntries(dir)
		var out bytes.Buffer
		if err := runRecoverRestore(dir, recoverActionRevert, &out); !errors.Is(err, errRecoveryMaterialMissing) {
			t.Fatalf("revert with no bak dir must refuse as missing material, got %v\n%s", err, out.String())
		}
		after, _ := listTopLevelUserEntries(dir)
		if strings.Join(live, ",") != strings.Join(after, ",") {
			t.Errorf("a refused revert must move nothing: before %v after %v", live, after)
		}
		if _, present, _ := readRestoreJournal(dir); !present {
			t.Error("journal must be kept")
		}
	})
}

// The data-dir lock is BIDIRECTIONAL: a proxy must not boot over a commit or
// recovery that holds it. Pre-fix holdDataDirLock warned and continued, so a
// `restart: unless-stopped` proxy started mid-evacuation, passed the
// interrupted-restore guard (the journal is written after the lock), served a
// half-moved /data and wrote into it, and the promotion then failed on
// "refusing to overwrite" (adversarial review, PR #1528).
func TestHoldDataDirLock_RefusesWhileCommitHoldsIt(t *testing.T) {
	dir := t.TempDir()
	release, err := acquireDataDirLock(dir) // the cli container's commit
	if err != nil {
		t.Skipf("flock unavailable: %v", err)
	}
	defer release()
	if err := holdDataDirLock(dir); !errors.Is(err, errDataDirLocked) {
		t.Fatalf("proxy boot must refuse while the lock is held, got %v", err)
	}
	release()
	if err := holdDataDirLock(dir); err != nil {
		t.Fatalf("boot after the commit released the lock: %v", err)
	}
	// CONTROL: an uncreatable lock (missing dir) is advisory, never fatal —
	// the first boot before init creates the directory must still serve.
	if err := holdDataDirLock(filepath.Join(dir, "does-not-exist")); err != nil {
		t.Fatalf("an uncreatable lock must not refuse the boot: %v", err)
	}
}

// nestedMountPointsUnder must see a nested mount through a SYMLINKED data dir
// (mountinfo reports real paths). Needs a real bind mount, so root only.
func TestNestedMountPointsUnder_ResolvesSymlinkedDataDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root for a bind mount")
	}
	realDir := t.TempDir()
	nested := filepath.Join(realDir, "yara")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(t.TempDir(), nested, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mount unavailable: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(nested, 0) })
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}
	if got := nestedMountPointsUnder(realDir); len(got) != 1 {
		t.Fatalf("via realDir path: %v, want the nested mount", got)
	}
	if got := nestedMountPointsUnder(link); len(got) != 1 {
		t.Fatalf("via symlink: %v, want the nested mount (pre-fix: hidden)", got)
	}
	// An unresolvable dir is reported as an obstacle, never as "no mounts".
	if got := nestedMountPointsUnder(filepath.Join(realDir, "missing")); len(got) != 1 {
		t.Fatalf("unresolvable dir: %v, want one obstacle entry", got)
	}
}

// The proxy's lifetime hold must survive garbage collection. Measured by the
// lifecycle harness (run 20261002T201749Z): a commit against a RUNNING stack
// printed "Restore committed." because holdDataDirLock dropped the release
// closure, the lock's *os.File became unreachable, and the runtime finalizer
// closed the descriptor — which releases a flock. A lock nobody references is
// a lock the GC removes.
func TestHoldDataDirLock_SurvivesGarbageCollection(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(releaseDataDirHoldForTest)
	if err := holdDataDirLock(dir); err != nil {
		t.Skipf("flock unavailable: %v", err)
	}
	// Finalizers run on their own goroutine after the GC cycle, so the
	// check is repeated across many cycles: against the pre-fix shape the
	// lock disappears within the first few, with the fix it never does.
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(5 * time.Millisecond)
		if _, err := acquireDataDirLock(dir); !errors.Is(err, errDataDirLocked) {
			t.Fatalf("the proxy's hold must still block a commit after GC (cycle %d), got %v", i, err)
		}
	}
}

// A dedicated ext4 volume mounted at /data carries a root-owned 0700
// `lost+found` the unprivileged proxy can neither read nor rename. The
// commit must leave it exactly where it is — never staged into the restore,
// never evacuated into the bak dir, never a collision — and still commit
// (lifecycle scenario G found the EACCES on a real loop-backed volume).
func TestRestoreCommit_LeavesLostAndFoundInPlace(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	lf := filepath.Join(currentDir, "lost+found")
	if err := os.Mkdir(lf, 0o700); err != nil {
		t.Fatal(err)
	}
	// Unreadable for a non-root test process — which is what the CI runner
	// is, and what makes this gate catch the error-first walk shape the first
	// fix shipped with (filepath.Walk hands an unreadable directory to the
	// callback WITH its readdir error). Root ignores the mode; there the
	// in-place assertions below are what the gate pins.
	if err := os.Chmod(lf, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lf, 0o700) })
	if os.Getuid() == 0 {
		t.Log("running as root: the EACCES half of this gate is exercised only by an unprivileged runner")
	}
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	}); err != nil {
		t.Fatalf("commit on a volume carrying lost+found: %v", err)
	}
	st, err := os.Lstat(lf)
	if err != nil || !st.IsDir() {
		t.Fatalf("lost+found must stay at the volume root: %v", err)
	}
	entries, err := os.ReadDir(currentDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), restoreBakPrefix) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(currentDir, e.Name(), "lost+found")); err == nil {
			t.Fatalf("lost+found was evacuated into %s", e.Name())
		}
	}
	if _, present, _ := readRestoreJournal(currentDir); present {
		t.Fatal("journal must be retired after a successful commit")
	}
	if _, err := os.Stat(filepath.Join(currentDir, "ui_users.json")); err != nil {
		t.Fatalf("restored content missing: %v", err)
	}
}

// An existing ca.bundle the restore cannot read is still a trust root the
// commit would move aside. Reading it as "absent" disarmed the root-CA guard
// and let a full restore replace it without --accept-root-ca-change (Codex P1,
// PR #1528). A directory in its place is unreadable even as root, so the gate
// does not depend on who runs the tests.
func TestRestoreCommit_RootCAGuard_UnreadableCurrentRootRefuses(t *testing.T) {
	src, currentDir, _, _ := makeCommitFixture(t, 0)
	if err := os.MkdirAll(filepath.Join(currentDir, "ca.bundle"), 0o750); err != nil {
		t.Fatal(err)
	}
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil || !strings.Contains(err.Error(), "cannot read the current ca.bundle") {
		t.Fatalf("an unreadable current root CA must refuse the commit, got: %v", err)
	}
	if fi, serr := os.Stat(filepath.Join(currentDir, "ca.bundle")); serr != nil || !fi.IsDir() {
		t.Fatal("a refused commit must leave the current ca.bundle untouched")
	}
	if _, ok := readBak(t, currentDir); ok {
		t.Fatal("a refused commit must not create a bak dir")
	}
}

// An existing roster the restore cannot read, or cannot parse, must not count
// as "no admins": that disarmed the no-admin guard and let a full restore of
// a pre-setup backup reopen unauthenticated setup (Codex P1, PR #1528).
func TestRestoreCommit_NoAdminGuard_UnreadableOrCorruptCurrentRoster(t *testing.T) {
	viewerOnly := []uiUserRecord{{Username: "eve", Role: RoleViewer}}
	t.Run("unreadable", func(t *testing.T) {
		src, _ := makeBackupWithRealCA(t, viewerOnly, 0)
		currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)
		p := filepath.Join(currentDir, "ui_users.json")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(p, 0o750); err != nil { // unreadable even as root
			t.Fatal(err)
		}
		_, err := captureStdout(t, func() error {
			return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
		})
		if err == nil || !strings.Contains(err.Error(), "cannot read the current ui_users.json") {
			t.Fatalf("an unreadable current roster must refuse, got: %v", err)
		}
	})
	t.Run("corrupt", func(t *testing.T) {
		src, _ := makeBackupWithRealCA(t, viewerOnly, 0)
		currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)
		if err := os.WriteFile(filepath.Join(currentDir, "ui_users.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := captureStdout(t, func() error {
			return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
		})
		if err == nil || !strings.Contains(err.Error(), "cannot be parsed") {
			t.Fatalf("a corrupt roster replaced by one with no admin must refuse, got: %v", err)
		}
	})
	// CONTROL: restoring a backup that brings an admin back still recovers a
	// corrupt roster — the remedy must stay available.
	t.Run("corrupt-recovered-by-a-backup-with-an-admin", func(t *testing.T) {
		src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
		currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)
		if err := os.WriteFile(filepath.Join(currentDir, "ui_users.json"), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := captureStdout(t, func() error {
			return runRestoreCommit(src, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true, AcceptRootCAChange: true})
		}); err != nil {
			t.Fatalf("a backup with an admin must recover a corrupt roster: %v", err)
		}
	})
}
