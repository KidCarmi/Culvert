package main

// restore_recovery_resume_test.go — owner-review round 3 (PR #1528) gates for
// the RESTARTABILITY of --recover-restore itself.
//
// The file header of restore_inplace.go used to promise that "a second
// interruption during recovery is recovered by running the same command
// again". It was false in both directions once a revert had begun returning
// the previous entries: the journal still said `promoting`, so the retry
// read the returned PREVIOUS entries as promoted RESTORED ones and refused to
// overwrite their namesakes in staging; `complete` collided the same way.
// Separately, a revert whose bak dir was missing parked the live data in
// staging, treated the absent bak as "nothing to move", and retired the
// journal over an EMPTY live dir. Every defect gate here was verified failing
// against the pre-fix tree; the trees are compared by CONTENT, not by the
// recovery command's exit status.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotTree maps every path under dir (relative, top-level restore
// internals excluded) to a content hash ("dir" for directories), so two
// directories can be compared for identity rather than for emptiness.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return out
	}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		if !strings.Contains(rel, string(filepath.Separator)) && isRestoreInternalEntry(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		body, rerr := os.ReadFile(p) // #nosec G304 -- test fixture
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(body)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", dir, err)
	}
	return out
}

func assertTreeEqual(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %d entries, want %d\n got:  %v\n want: %v", what, len(got), len(want), keys(got), keys(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s differs (got %q want %q)", what, k, short(got[k]), short(v))
		}
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// promotingFixture produces the exact layout of a commit killed between the
// two phases (every previous entry in bak, nothing promoted yet) and returns
// the data dir plus content snapshots of the PREVIOUS and RESTORED sets.
func promotingFixture(t *testing.T) (dir string, previous, restored map[string]string) {
	t.Helper()
	dir = interruptCommit(t, "between")
	j, present, err := readRestoreJournal(dir)
	if !present || err != nil || j.Phase != restorePhasePromoting {
		t.Fatalf("fixture: present=%v err=%v phase=%q", present, err, j.Phase)
	}
	previous = snapshotTree(t, filepath.Join(dir, j.BakDir))
	restored = snapshotTree(t, filepath.Join(dir, j.StagingDir))
	if len(previous) == 0 || len(restored) == 0 {
		t.Fatalf("fixture: previous=%d restored=%d entries", len(previous), len(restored))
	}
	return dir, previous, restored
}

// failAfterMoves installs the move seam so the Nth successful rename whose
// destination is under dst aborts the loop (a kill right after that rename).
func failAfterMoves(t *testing.T, dst string, n int) {
	t.Helper()
	count := 0
	restoreMoveHook = func(_, to string) error {
		if !strings.HasPrefix(to, dst+string(filepath.Separator)) {
			return nil
		}
		count++
		if count == n {
			return os.ErrDeadlineExceeded
		}
		return nil
	}
	t.Cleanup(func() { restoreMoveHook = nil })
}

// Finding 1 (P1): a revert killed while RETURNING the previous entries — the
// live dir then holds previous data under a `promoting` journal. Pre-fix the
// retry failed with "refusing to overwrite existing …staging/<name>" and the
// data dir stayed un-bootable in both directions.
func TestRecoverRestore_Revert_InterruptedDuringReturn_Resumes(t *testing.T) {
	dir, previous, restored := promotingFixture(t)
	failAfterMoves(t, dir, 1) // the first previous entry has landed live
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err == nil {
		t.Fatal("expected the injected interruption")
	}
	restoreMoveHook = nil
	j, present, err := readRestoreJournal(dir)
	if !present || err != nil {
		t.Fatalf("journal after interruption: present=%v err=%v", present, err)
	}
	if j.Recovery != restoreRecoveryRevert || j.Progress != restoreProgressUnpromoted {
		t.Fatalf("journal must record the direction and the un-promotion before the return begins; got recovery=%q progress=%q", j.Recovery, j.Progress)
	}
	if live := snapshotTree(t, dir); len(live) == 0 {
		t.Fatal("fixture: the interruption must have returned at least one previous entry")
	}
	out.Reset()
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err != nil {
		t.Fatalf("resumed revert must succeed: %v\n%s", err, out.String())
	}
	assertTreeEqual(t, "live data after resumed revert", snapshotTree(t, dir), previous)
	assertTreeEqual(t, "staging after resumed revert", snapshotTree(t, filepath.Join(dir, j.StagingDir)), restored)
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be retired")
	}
	if _, ok := readBak(t, dir); ok {
		t.Error("bak dir must be empty and removed after revert")
	}
	if err := checkInterruptedRestore(dir); err != nil {
		t.Errorf("boot guard must pass: %v", err)
	}
}

// A revert killed while UN-PROMOTING (some restored entries still live, some
// already parked) resumes and leaves the previous set live, byte for byte.
func TestRecoverRestore_Revert_InterruptedDuringUnpromote_Resumes(t *testing.T) {
	dir, previous, restored := promotingFixture(t)
	j, _, _ := readRestoreJournal(dir)
	staging := filepath.Join(dir, j.StagingDir)
	// Promote everything first (a real kill just before the journal removal
	// leaves this), then interrupt the revert's un-promotion after one entry.
	if _, err := moveTopLevelEntries(staging, dir); err != nil {
		t.Fatal(err)
	}
	failAfterMoves(t, staging, 1)
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err == nil {
		t.Fatal("expected the injected interruption")
	}
	restoreMoveHook = nil
	if j, _, _ := readRestoreJournal(dir); j.Progress != "" || j.Recovery != restoreRecoveryRevert {
		t.Fatalf("un-promotion must not be marked done while entries are still live; got recovery=%q progress=%q", j.Recovery, j.Progress)
	}
	out.Reset()
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err != nil {
		t.Fatalf("resumed revert must succeed: %v\n%s", err, out.String())
	}
	assertTreeEqual(t, "live data after resumed revert", snapshotTree(t, dir), previous)
	assertTreeEqual(t, "staging after resumed revert", snapshotTree(t, staging), restored)
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be retired")
	}
}

// A revert killed between the bak rmdir and the journal removal: the
// `returned` marker is the proof that lets the retry retire the journal with
// the bak dir gone — the ONLY shape in which a missing bak dir is accepted.
func TestRecoverRestore_Revert_InterruptedBeforeJournalRemoval_Retires(t *testing.T) {
	dir, previous, _ := promotingFixture(t)
	j, _, _ := readRestoreJournal(dir)
	bak := filepath.Join(dir, j.BakDir)
	if _, err := moveTopLevelEntries(bak, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(bak); err != nil {
		t.Fatal(err)
	}
	j.Recovery = restoreRecoveryRevert
	j.Progress = restoreProgressReturned
	if err := writeRestoreJournal(dir, j); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionRevert, &out); err != nil {
		t.Fatalf("retire after `returned`: %v\n%s", err, out.String())
	}
	assertTreeEqual(t, "live data", snapshotTree(t, dir), previous)
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be retired")
	}
}

// Finding 2 (P1): `promoting`, every restored entry live, bak dir missing.
// Pre-fix: revert parked the live data in staging, read the absent bak as
// "nothing to move", retired the journal and reported success over an EMPTY
// data dir with the boot guard disarmed.
func TestRecoverRestore_Revert_MissingBakInPromoting_RefusesAndMovesNothing(t *testing.T) {
	dir, _, restored := promotingFixture(t)
	j, _, _ := readRestoreJournal(dir)
	staging := filepath.Join(dir, j.StagingDir)
	if _, err := moveTopLevelEntries(staging, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, j.BakDir)); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, dir)
	assertTreeEqual(t, "fixture: live holds the restored set", before, restored)
	var out bytes.Buffer
	err := runRecoverRestore(dir, recoverActionRevert, &out)
	if !errors.Is(err, errRecoveryMaterialMissing) {
		t.Fatalf("revert with the bak dir missing must refuse as missing material, got %v\n%s", err, out.String())
	}
	assertTreeEqual(t, "live data must be untouched by the refusal", snapshotTree(t, dir), before)
	if _, present, _ := readRestoreJournal(dir); !present {
		t.Error("journal must be kept so the boot guard stays armed")
	}
	if err := checkInterruptedRestore(dir); err == nil {
		t.Error("boot guard must still refuse")
	}
	if jj, _, _ := readRestoreJournal(dir); jj.Progress != "" {
		t.Errorf("no progress marker may be written by a refused revert, got %q", jj.Progress)
	}
	// The same holds one phase earlier: an `evacuating` journal with no bak
	// dir cannot prove the live dir holds everything (the operator may have
	// removed a bak dir WITH content), so revert refuses there too.
	dir2 := interruptCommit(t, "evacuating")
	j2, _, _ := readRestoreJournal(dir2)
	if err := os.RemoveAll(filepath.Join(dir2, j2.BakDir)); err != nil {
		t.Fatal(err)
	}
	before2 := snapshotTree(t, dir2)
	if err := runRecoverRestore(dir2, recoverActionRevert, &out); !errors.Is(err, errRecoveryMaterialMissing) {
		t.Fatalf("evacuating revert with the bak dir missing must refuse, got %v", err)
	}
	assertTreeEqual(t, "live data (evacuating) must be untouched", snapshotTree(t, dir2), before2)
}

// Once a direction is recorded the other is refused — the recorded one is
// always finishable, and acting in the other direction on a layout the phase
// label no longer describes is exactly what finding 1 was.
func TestRecoverRestore_DirectionSwitchIsRefused(t *testing.T) {
	t.Run("revert_then_complete", func(t *testing.T) {
		dir, _, _ := promotingFixture(t)
		failAfterMoves(t, dir, 1)
		var out bytes.Buffer
		if err := runRecoverRestore(dir, recoverActionRevert, &out); err == nil {
			t.Fatal("expected the injected interruption")
		}
		restoreMoveHook = nil
		before := snapshotTree(t, dir)
		err := runRecoverRestore(dir, recoverActionComplete, &out)
		if err == nil || !strings.Contains(err.Error(), "already in progress") {
			t.Fatalf("complete after a started revert must be refused, got %v", err)
		}
		assertTreeEqual(t, "a refused switch must move nothing", snapshotTree(t, dir), before)
		if _, present, _ := readRestoreJournal(dir); !present {
			t.Error("journal must be kept")
		}
	})
	t.Run("complete_then_revert", func(t *testing.T) {
		dir, _, _ := promotingFixture(t)
		j, _, _ := readRestoreJournal(dir)
		failAfterMoves(t, dir, 1)
		var out bytes.Buffer
		if err := runRecoverRestore(dir, recoverActionComplete, &out); err == nil {
			t.Fatal("expected the injected interruption")
		}
		restoreMoveHook = nil
		before := snapshotTree(t, dir)
		err := runRecoverRestore(dir, recoverActionRevert, &out)
		if err == nil || !strings.Contains(err.Error(), "already in progress") {
			t.Fatalf("revert after a started complete must be refused, got %v", err)
		}
		assertTreeEqual(t, "a refused switch must move nothing", snapshotTree(t, dir), before)
		if jj, _, _ := readRestoreJournal(dir); jj.Recovery != restoreRecoveryComplete || jj.StagingDir != j.StagingDir {
			t.Errorf("journal must keep the recorded direction, got %+v", jj)
		}
	})
}

// A complete killed mid-promotion resumes and leaves the restored set live
// and the previous set preserved, byte for byte.
func TestRecoverRestore_Complete_InterruptedDuringPromote_Resumes(t *testing.T) {
	dir, previous, restored := promotingFixture(t)
	j, _, _ := readRestoreJournal(dir)
	failAfterMoves(t, dir, 1)
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err == nil {
		t.Fatal("expected the injected interruption")
	}
	restoreMoveHook = nil
	out.Reset()
	if err := runRecoverRestore(dir, recoverActionComplete, &out); err != nil {
		t.Fatalf("resumed complete must succeed: %v\n%s", err, out.String())
	}
	assertTreeEqual(t, "live data after resumed complete", snapshotTree(t, dir), restored)
	assertTreeEqual(t, "bak after resumed complete", snapshotTree(t, filepath.Join(dir, j.BakDir)), previous)
	if stagingExists(t, dir) {
		t.Error("staging dir must be removed")
	}
	if _, present, _ := readRestoreJournal(dir); present {
		t.Error("journal must be retired")
	}
}

// A missing staging dir is accepted by complete ONLY behind the `promoted`
// marker the commit writes before its rmdir; without it the dir may have
// been deleted with content, so complete refuses and moves nothing.
func TestRecoverRestore_Complete_MissingStagingWithoutMarker_Refuses(t *testing.T) {
	dir, _, _ := promotingFixture(t)
	j, _, _ := readRestoreJournal(dir)
	if err := os.RemoveAll(filepath.Join(dir, j.StagingDir)); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, dir)
	var out bytes.Buffer
	if err := runRecoverRestore(dir, recoverActionComplete, &out); !errors.Is(err, errRecoveryMaterialMissing) {
		t.Fatalf("complete with the staging dir missing and no marker must refuse, got %v\n%s", err, out.String())
	}
	assertTreeEqual(t, "live data must be untouched", snapshotTree(t, dir), before)
	if _, present, _ := readRestoreJournal(dir); !present {
		t.Error("journal must be kept")
	}
}

// The real commit path writes the `promoted` marker before it removes the
// staging dir, so a kill between those two steps is completable. Pinned
// structurally — the window is a few syscalls wide and cannot be scheduled
// from a test — with a behavioural half: a kill right after the LAST
// promotion rename (before the marker) must still complete, because staging
// is then present and empty.
func TestRestoreCommit_WritesPromotedMarkerBeforeRemovingStaging(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(pkgSourceDir(), "restore_inplace.go"))
	if err != nil {
		t.Fatal(err)
	}
	fn := string(body)
	fn = fn[strings.Index(fn, "func swapInPlace("):]
	fn = fn[:strings.Index(fn, "\n}\n")]
	mark := strings.Index(fn, "restoreProgressPromoted")
	rm := strings.Index(fn, "os.Remove(stagingDir)")
	if mark < 0 || rm < 0 || mark > rm {
		t.Fatalf("swapInPlace must record the promoted marker BEFORE removing the staging dir (marker@%d remove@%d)", mark, rm)
	}

	src, dir, _, _ := makeCommitFixture(t, 0)
	staged := 0
	restoreMoveHook = func(_, to string) error {
		// Count promotion renames (destination = the live dir) and die after
		// the last one; the fixture promotes exactly the staged set.
		if filepath.Dir(to) == dir {
			staged++
		}
		return nil
	}
	_, _ = captureStdout(t, func() error {
		return runRestoreCommit(src, dir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	restoreMoveHook = nil
	if staged == 0 {
		t.Fatal("fixture: no promotion observed")
	}
	// Second run: the same fixture, killed after the last promotion rename.
	src2, dir2, _, _ := makeCommitFixture(t, 0)
	n := 0
	restoreMoveHook = func(_, to string) error {
		if filepath.Dir(to) == dir2 {
			n++
			if n == staged {
				return os.ErrDeadlineExceeded
			}
		}
		return nil
	}
	t.Cleanup(func() { restoreMoveHook = nil })
	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(src2, dir2, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	}); err == nil {
		t.Fatal("expected the injected interruption")
	}
	restoreMoveHook = nil
	if j, _, _ := readRestoreJournal(dir2); j == nil || j.Progress != "" {
		t.Fatalf("marker must not be written before the loop finishes; got %+v", j)
	}
	var out bytes.Buffer
	if err := runRecoverRestore(dir2, recoverActionComplete, &out); err != nil {
		t.Fatalf("complete after the last promotion rename must succeed: %v\n%s", err, out.String())
	}
	if stagingExists(t, dir2) {
		t.Error("staging dir must be removed")
	}
}

// A journal carrying a direction or marker this build does not know is
// refused like any other malformed journal (fail closed, never guess).
func TestRestoreJournal_UnknownRecoveryFieldsRefused(t *testing.T) {
	for _, body := range []string{
		`{"version":1,"suffix":"x","phase":"promoting","staging_dir":".restore-staging.x","bak_dir":".restore-bak.x","recovery":"sideways"}`,
		`{"version":1,"suffix":"x","phase":"promoting","staging_dir":".restore-staging.x","bak_dir":".restore-bak.x","progress":"halfway"}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(restoreJournalPath(dir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, present, err := readRestoreJournal(dir); !present || err == nil {
			t.Errorf("journal %s must be refused (present=%v err=%v)", body, present, err)
		}
	}
}
