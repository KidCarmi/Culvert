package main

// restore_inplace_test.go — gates for the journaled in-place restore swap
// (restore_inplace.go): interruption at each phase boundary is recoverable in
// BOTH directions, recovery is idempotent, the boot guard refuses while a
// journal exists, the running proxy's data-dir lock makes the commit refuse,
// and the leftover scanner sees in-place leftovers without ever offering an
// unresolved journal's material for deletion.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if !strings.Contains(out.String(), "--confirm revert") || !strings.Contains(out.String(), "--confirm complete") {
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
