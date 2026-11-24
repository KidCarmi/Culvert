package main

// restore_inplace_test.go — the restore commit for a data directory that
// cannot be renamed as a whole (restore_inplace.go). The layout is forced with
// restoreForceInPlace; restore_mountpoint_test.go runs the same commit on a
// real bind mount, as root.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/writerlock"
)

func forceInPlaceRestore(t *testing.T) {
	t.Helper()
	restoreForceInPlace = true
	t.Cleanup(func() {
		restoreForceInPlace = false
		restoreInPlaceStepHook = nil
	})
}

// treeDigest is every regular file under dir with its mode and content hash,
// without the restore work area and the lock file. Two equal digests mean the
// data directory holds the same content.
func treeDigest(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if info.IsDir() {
			if rel == restoreWorkDirName {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == writerlock.FileName {
			return nil
		}
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(body)
		lines = append(lines, fmt.Sprintf("%s %o %s", rel, info.Mode().Perm(), hex.EncodeToString(sum[:])))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func inPlaceEntries(t *testing.T, dataDir, kind string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dataDir, restoreWorkDirName))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), "."+kind+".") {
			out = append(out, filepath.Join(dataDir, restoreWorkDirName, e.Name()))
		}
	}
	return out
}

func intentPresent(dataDir string) bool {
	return restorePathExists(filepath.Join(dataDir, restoreWorkDirName, restoreIntentName))
}

func readOutcome(t *testing.T, dataDir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dataDir, restoreWorkDirName, restoreOutcomeName))
	if err != nil {
		return ""
	}
	return string(body)
}

func commitInPlace(t *testing.T, src, dataDir string, mode restoreMode) (string, error) {
	t.Helper()
	return captureStdout(t, func() error {
		return runRestoreCommit(src, dataDir, "", restoreOpts{Mode: mode, AcceptDPReenrollment: true})
	})
}

func TestRestoreInPlace_FullCommit_ReplacesContentAndKeepsThePrevious(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	seedFile(t, dataDir, "proxy.log", []byte("a file no backup carries\n"), 0o600)
	before := treeDigest(t, dataDir)

	out, err := commitInPlace(t, src, dataDir, modeFull)
	if err != nil {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	users, _ := os.ReadFile(filepath.Join(dataDir, "ui_users.json"))
	if !strings.Contains(string(users), "alice") || strings.Contains(string(users), "bob") {
		t.Errorf("data directory does not hold the backup's users: %s", users)
	}
	if restorePathExists(filepath.Join(dataDir, "proxy.log")) {
		t.Error("a full restore left a file that is not in the backup")
	}
	baks := inPlaceEntries(t, dataDir, "bak")
	if len(baks) != 1 {
		t.Fatalf("want one backup directory in the work area, got %v", baks)
	}
	if got := treeDigest(t, baks[0]); got != before {
		t.Errorf("the kept previous content differs from what was there before:\nwant\n%s\ngot\n%s", before, got)
	}
	if intentPresent(dataDir) {
		t.Error("intent record still present after a commit")
	}
	if len(inPlaceEntries(t, dataDir, "staging")) != 0 {
		t.Error("staging directory left after a commit")
	}
	if !strings.Contains(readOutcome(t, dataDir), restoreOutcomeCommitted) {
		t.Errorf("outcome record = %q", readOutcome(t, dataDir))
	}
	if _, _, err := discoverLeftovers(dataDir); err != nil {
		t.Fatalf("discoverLeftovers: %v", err)
	}
	left, _, _ := discoverLeftovers(dataDir)
	if len(left) != 1 || left[0].Kind != leftoverBak || left[0].Path != baks[0] {
		t.Errorf("leftover tooling does not list the in-place backup: %+v", left)
	}
}

// TestRestoreInPlace_CrashAtEveryStep_NextStartHoldsThePreviousContent is the
// crash matrix: the commit is abandoned after each durable step, exactly as a
// killed process leaves it, and the next start must end with the content the
// directory had before the restore began — or, before any rename, simply
// still have it.
func TestRestoreInPlace_CrashAtEveryStep_NextStartHoldsThePreviousContent(t *testing.T) {
	for _, step := range []string{"staged", "intent", "evacuated", "installing", "installed", "verified"} {
		t.Run(step, func(t *testing.T) {
			forceInPlaceRestore(t)
			src, dataDir, _, _ := makeCommitFixture(t, 0)
			seedFile(t, dataDir, "proxy.log", []byte("previous\n"), 0o600)
			before := treeDigest(t, dataDir)

			reached := false
			restoreInPlaceStepHook = func(s string) error {
				if s == step {
					reached = true
					return errors.New("killed")
				}
				return nil
			}
			_, err := commitInPlace(t, src, dataDir, modeFull)
			if !reached || !errors.Is(err, errRestoreAbandoned) {
				t.Fatalf("commit was not abandoned at %q: reached=%v err=%v", step, reached, err)
			}
			restoreInPlaceStepHook = nil
			wantIntent := step != "staged"
			if intentPresent(dataDir) != wantIntent {
				t.Fatalf("intent record present=%v after a crash at %q, want %v", intentPresent(dataDir), step, wantIntent)
			}

			if err := recoverInPlaceRestoreAtBoot(dataDir, true); err != nil {
				t.Fatalf("startup recovery: %v", err)
			}
			if got := treeDigest(t, dataDir); got != before {
				t.Errorf("content after recovery differs from the content before the restore:\nwant\n%s\ngot\n%s", before, got)
			}
			if intentPresent(dataDir) {
				t.Error("intent record still present after recovery")
			}
			if wantIntent && !strings.Contains(readOutcome(t, dataDir), restoreOutcomeRolledBack) {
				t.Errorf("outcome record = %q, want %s", readOutcome(t, dataDir), restoreOutcomeRolledBack)
			}
			if wantIntent && len(inPlaceEntries(t, dataDir, "bak")) != 0 {
				t.Errorf("an emptied backup directory was left: %v", inPlaceEntries(t, dataDir, "bak"))
			}
			// The directory is usable: the same restore now commits. (A later
			// process has another pid and another second; the staging
			// directory a crash at "staged" leaves behind is an ordinary
			// leftover with the first one's suffix.)
			later := restoreNow().Add(time.Hour)
			orig := restoreNow
			restoreNow = func() time.Time { return later }
			t.Cleanup(func() { restoreNow = orig })
			if out, err := commitInPlace(t, src, dataDir, modeFull); err != nil {
				t.Fatalf("restore after recovery: %v\n%s", err, out)
			}
		})
	}
}

func TestRestoreInPlace_NextRestoreUndoesAnUnfinishedOneFirst(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	before := treeDigest(t, dataDir)
	restoreInPlaceStepHook = func(s string) error {
		if s == "installed" {
			return errors.New("killed")
		}
		return nil
	}
	if _, err := commitInPlace(t, src, dataDir, modeFull); !errors.Is(err, errRestoreAbandoned) {
		t.Fatalf("setup: %v", err)
	}
	restoreInPlaceStepHook = nil

	out, err := commitInPlace(t, src, dataDir, modeFull)
	if err != nil {
		t.Fatalf("second restore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "was undone first") {
		t.Errorf("the second restore did not say it undid the first:\n%s", out)
	}
	baks := inPlaceEntries(t, dataDir, "bak")
	if len(baks) != 1 || treeDigest(t, baks[0]) != before {
		t.Errorf("the kept previous content is not the content from before the FIRST restore: %v", baks)
	}
}

func TestRestoreInPlace_StartupWithoutTheLockRefusesAndChangesNothing(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	restoreInPlaceStepHook = func(s string) error {
		if s == "evacuated" {
			return errors.New("killed")
		}
		return nil
	}
	if _, err := commitInPlace(t, src, dataDir, modeFull); !errors.Is(err, errRestoreAbandoned) {
		t.Fatalf("setup: %v", err)
	}
	restoreInPlaceStepHook = nil
	mid := treeDigest(t, dataDir)

	err := recoverInPlaceRestoreAtBoot(dataDir, false)
	if err == nil || !strings.Contains(err.Error(), "may still be running") {
		t.Fatalf("want a refusal naming a possibly running restore, got %v", err)
	}
	if treeDigest(t, dataDir) != mid || !intentPresent(dataDir) {
		t.Error("a refused startup changed the data directory")
	}
}

func TestRestoreInPlace_UnusableIntentRecordStopsEverything(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       "{",
		"future version": `{"version":99,"suffix":"20260101T000000Z-1","phase":"evacuating"}`,
		"bad suffix":     `{"version":1,"suffix":"../x","phase":"evacuating"}`,
		"bad phase":      `{"version":1,"suffix":"20260101T000000Z-1","phase":"done"}`,
		"escaping name":  `{"version":1,"suffix":"20260101T000000Z-1","phase":"evacuating","old":["../etc"]}`,
		"work area name": `{"version":1,"suffix":"20260101T000000Z-1","phase":"evacuating","old":[".restore"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			forceInPlaceRestore(t)
			src, dataDir, _, _ := makeCommitFixture(t, 0)
			work := filepath.Join(dataDir, restoreWorkDirName)
			if err := os.MkdirAll(work, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(work, restoreIntentName), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			before := treeDigest(t, dataDir)
			if err := recoverInPlaceRestoreAtBoot(dataDir, true); err == nil {
				t.Error("startup accepted an unusable intent record")
			}
			if _, err := commitInPlace(t, src, dataDir, modeFull); err == nil {
				t.Error("a new restore ran over an unusable intent record")
			}
			if treeDigest(t, dataDir) != before {
				t.Error("the data directory changed although the record could not be used")
			}
		})
	}
}

func TestRestoreInPlace_VerificationFailureRollsBack(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	before := treeDigest(t, dataDir)
	restoreInPlaceStepHook = func(s string) error {
		if s == "installed" { // the restored file is damaged before it is re-read
			return os.WriteFile(filepath.Join(dataDir, "ui_users.json"), []byte("{}"), 0o600)
		}
		return nil
	}
	out, err := commitInPlace(t, src, dataDir, modeFull)
	if err == nil || !strings.Contains(err.Error(), "does not match the backup manifest") {
		t.Fatalf("want a verification failure, got %v\n%s", err, out)
	}
	if strings.Contains(out, "Restore committed") {
		t.Error("a restore whose content did not verify was reported as committed")
	}
	if treeDigest(t, dataDir) != before || intentPresent(dataDir) {
		t.Error("the previous content was not put back after the verification failure")
	}
}

func TestRestoreInPlace_LiveWriterRefusesBeforeAnyChange(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	held := writerlock.Take(dataDir)
	if held.Lock == nil {
		t.Fatalf("fixture: cannot take the writer lock on a fresh directory: %v", held.Cause)
	}
	defer func() { _ = held.Lock.Close() }()
	before := treeDigest(t, dataDir)

	_, err := commitInPlace(t, src, dataDir, modeFull)
	if err == nil || !strings.Contains(err.Error(), "stop it first") {
		t.Fatalf("want a refusal naming the running process, got %v", err)
	}
	if treeDigest(t, dataDir) != before || restorePathExists(filepath.Join(dataDir, restoreWorkDirName)) {
		t.Error("a refused restore touched the data directory")
	}
}

func TestRestoreInPlace_FailedValidationLeavesNoWorkArea(t *testing.T) {
	forceInPlaceRestore(t)
	_, dataDir, _, _ := makeCommitFixture(t, 0)
	before := treeDigest(t, dataDir)
	bad := filepath.Join(t.TempDir(), "bad.tar.gz")
	if err := os.WriteFile(bad, []byte("not an archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := commitInPlace(t, bad, dataDir, modeFull); err == nil {
		t.Fatal("an invalid archive was committed")
	}
	if treeDigest(t, dataDir) != before || restorePathExists(filepath.Join(dataDir, restoreWorkDirName)) {
		t.Error("a restore that failed validation left something behind (BKP-002)")
	}
}

func TestRestoreInPlace_SecondRestoreDoesNotSwallowTheWorkArea(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	for i, mode := range []restoreMode{modeFull, modeStateOnly, modeTrustRootOnly} {
		// The suffix has one-second resolution and the same pid.
		tick := restoreNow().Add(time.Duration(i+1) * time.Hour)
		orig := restoreNow
		restoreNow = func() time.Time { return tick }
		out, err := commitInPlace(t, src, dataDir, mode)
		restoreNow = orig
		if err != nil {
			t.Fatalf("restore %d (%s): %v\n%s", i, mode, err, out)
		}
	}
	baks := inPlaceEntries(t, dataDir, "bak")
	if len(baks) != 3 {
		t.Fatalf("want three kept backups, got %v", baks)
	}
	for _, dir := range append(baks, dataDir) {
		err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && p != filepath.Join(dataDir, restoreWorkDirName) && info.Name() == restoreWorkDirName {
				return fmt.Errorf("work area copied into %s", p)
			}
			if err == nil && p == filepath.Join(dataDir, restoreWorkDirName) {
				return filepath.SkipDir
			}
			return err
		})
		if err != nil {
			t.Error(err)
		}
	}
}

func TestRestoreDryRun_PrintsThePreflightVerdict(t *testing.T) {
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	before := treeDigest(t, dataDir)

	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, dataDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil || !strings.Contains(out, restorePreflightPrefix+"commit=ok layout=directory-swap") {
		t.Fatalf("dry-run: err=%v\n%s", err, out)
	}
	forceInPlaceRestore(t)
	out, err = captureStdout(t, func() error {
		return runRestoreDryRun(src, dataDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil || !strings.Contains(out, restorePreflightPrefix+"commit=ok layout=in-place") {
		t.Fatalf("in-place dry-run: err=%v\n%s", err, out)
	}
	if treeDigest(t, dataDir) != before || restorePathExists(filepath.Join(dataDir, restoreWorkDirName)) {
		t.Error("a dry-run wrote to the data directory")
	}
}

func TestRestoreDryRun_PreflightNamesAGuardThatWouldRefuse(t *testing.T) {
	src, dataDir, _, _ := makeCommitFixture(t, 2) // enrolled DPs + a different CA
	out, err := captureStdout(t, func() error {
		return runRestoreDryRun(src, dataDir, "", restoreOpts{Mode: modeFull})
	})
	if err != nil {
		t.Fatalf("a dry-run with a guard that would block still exits 0: %v", err)
	}
	if !strings.Contains(out, restorePreflightPrefix+"commit=refused") || !strings.Contains(out, "reason=dp_reenrollment_not_accepted") {
		t.Errorf("preflight verdict missing or wrong:\n%s", out)
	}
}

func TestCleanupLeftovers_NeverOffersTheBackupOfAnUnfinishedRestore(t *testing.T) {
	forceInPlaceRestore(t)
	src, dataDir, _, _ := makeCommitFixture(t, 0)
	restoreInPlaceStepHook = func(s string) error {
		if s == "evacuated" {
			return errors.New("killed")
		}
		return nil
	}
	if _, err := commitInPlace(t, src, dataDir, modeFull); !errors.Is(err, errRestoreAbandoned) {
		t.Fatalf("setup: %v", err)
	}
	restoreInPlaceStepHook = nil
	left, skipped, err := discoverLeftovers(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("the only copy of the previous content is offered for deletion: %+v", left)
	}
	if len(skipped) == 0 {
		t.Error("the skipped directories are not reported")
	}
}
