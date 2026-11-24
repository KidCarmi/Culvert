package main

// restore_inplace.go — the restore commit for a data directory that cannot be
// swapped as a whole.
//
// # WHY THIS EXISTS
//
// runRestoreCommit replaces the data directory with two renames of the
// directory itself: `/data` → `/data.bak.<sfx>`, then `/data.staging.<sfx>` →
// `/data`. That needs two things the shipped deployment does not have:
//
//   - a writable PARENT. The staging and backup directories are siblings of
//     `/data`, so they are created in `/`. The release image runs as the
//     unprivileged user `proxy`, which cannot create anything there. Measured
//     on real Docker with the real binary: every commit ended at
//     `mkdir /data.staging.<sfx>: permission denied`.
//   - a data directory that is NOT a mount point. docker-compose.yml mounts the
//     named volume `proxy-data` at `/data`, and rename(2) refuses to move a
//     mount point (EBUSY). restore_mountpoint_test.go used to pin that failure.
//
// So the one documented restore path could not commit in the one topology the
// product ships. This file is the commit for that topology: everything happens
// INSIDE the data directory, on the volume itself, where the process may write
// and where every rename stays on one filesystem.
//
// # THE SWAP
//
// The work area is `<dataDir>/.restore/`:
//
//	<base>.staging.<sfx>/   the new content, staged exactly as before
//	<base>.bak.<sfx>/       the previous content, kept after the commit
//	intent.json             present for as long as the swap is not committed
//	last-outcome.json       what the last commit or recovery did
//
// Order, each step durable before the next starts:
//
//  1. take the single-writer lock (a live proxy holds it: refuse, change nothing)
//  2. roll back an earlier swap that never committed, if one is recorded
//  3. stage the new content
//  4. write intent.json, phase "evacuating", listing every top-level name that
//     will leave and every name that will arrive
//  5. move every previous top-level entry into the backup directory
//  6. rewrite intent.json, phase "installing"
//  7. move every staged top-level entry into the data directory
//  8. re-read every restored file and compare it with the manifest
//  9. remove intent.json — THIS is the commit point
//
// A directory swap is one atomic rename; this is many. What makes it
// all-or-nothing is the intent record: while it exists the swap is not
// committed, and the phase plus the two name lists say exactly which renames to
// undo. A crash, a failed rename or a failed verification at any step ends in
// the previous content, restored rename by rename and then checked. Nothing is
// guessed: an unreadable or malformed intent record, or a name found in two
// places at once, stops the recovery and leaves everything where it is.
//
// The swap never rolls FORWARD. An interrupted restore is undone, not
// finished, because the previous content is the only state that was known to
// run; the operator (or the maintenance agent) asks again.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/writerlock"
)

const (
	// restoreWorkDirName is the work area inside the data directory. The
	// backup collector packs an explicit artifact list, so nothing under it is
	// ever archived, and stageArtifacts skips it when it walks the live tree.
	restoreWorkDirName = ".restore"
	restoreIntentName  = "intent.json"
	restoreOutcomeName = "last-outcome.json"

	restoreIntentVersion = 1

	restorePhaseEvacuating = "evacuating"
	restorePhaseInstalling = "installing"

	restoreOutcomeCommitted  = "committed"
	restoreOutcomeRolledBack = "rolled_back"

	// restoreFreeSpaceMargin is added to the staged size when free space is
	// checked: the swap itself only renames, but the intent and outcome
	// records and directory entries need room too.
	restoreFreeSpaceMargin = 8 << 20
)

// restoreForceInPlace makes the layout decision "in place" regardless of the
// filesystem. Test seam: a bind mount needs CAP_SYS_ADMIN and an unwritable
// parent needs a non-root user, and the swap logic is the same either way.
var restoreForceInPlace bool

// restoreInPlaceStepHook is called after each durable step of the in-place
// swap with the step's name ("staged", "intent", "evacuated", "installing",
// "installed", "verified"). Returning an error abandons the commit at that
// point WITHOUT cleaning up, which is what a killed process leaves behind.
// Production: nil.
var restoreInPlaceStepHook func(step string) error

// errRestoreAbandoned marks a commit stopped by restoreInPlaceStepHook. The
// caller must not roll back: the test is standing in for a dead process.
var errRestoreAbandoned = errors.New("restore: commit abandoned at an injected step")

// restoreIntent is the durable record of a swap that has started and has not
// committed. Every field is written by this process and read back only by the
// same code; the names are validated again on read because the file sits on a
// volume an operator can reach.
type restoreIntent struct {
	Version   int       `json:"version"`
	Suffix    string    `json:"suffix"`
	Mode      string    `json:"mode"`
	Phase     string    `json:"phase"`
	StartedAt time.Time `json:"started_at"`
	// Old are the top-level names that were in the data directory and are
	// moved to the backup directory. New are the top-level names of the
	// staged content.
	Old []string `json:"old"`
	New []string `json:"new"`
}

// restoreOutcome is the last thing the in-place swap did, kept on the volume
// so that it survives whoever asked for it.
type restoreOutcome struct {
	Outcome   string    `json:"outcome"`
	Suffix    string    `json:"suffix"`
	Mode      string    `json:"mode"`
	At        time.Time `json:"at"`
	Reason    string    `json:"reason,omitempty"`
	BackupDir string    `json:"backup_dir,omitempty"`
}

// restoreUsesInPlaceSwap reports whether the data directory has to be swapped
// from the inside: it is a mount point, or its parent is not writable by this
// process. Everywhere else the whole-directory swap is kept unchanged.
func restoreUsesInPlaceSwap(dataDir string) bool {
	if restoreForceInPlace {
		return true
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return false
	}
	return restoreDirIsMountPoint(abs) || !restoreDirWritable(filepath.Dir(abs))
}

// restoreWorkPaths returns the work area and the staging and backup
// directories of one swap. The directory names carry the same
// `<base>.<kind>.<sfx>` shape as the whole-directory swap so the leftover
// tooling recognises them.
func restoreWorkPaths(dataDir, suffix string) (work, staging, bak string) {
	base := filepath.Base(filepath.Clean(dataDir))
	work = filepath.Join(dataDir, restoreWorkDirName)
	return work, filepath.Join(work, base+".staging."+suffix), filepath.Join(work, base+".bak."+suffix)
}

// restoreSwapExcluded reports a top-level name the swap never moves: its own
// work area, and the single-writer lock, whose inode this process and any
// later one must keep agreeing on.
func restoreSwapExcluded(name string) bool {
	return name == restoreWorkDirName || name == writerlock.FileName
}

// restoreTopLevelNames lists dir's entries, sorted, without the excluded ones.
func restoreTopLevelNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !restoreSwapExcluded(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func restorePathExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// restoreSyncDir fsyncs a directory so the renames inside it are durable.
// Filesystems that cannot sync a directory report EINVAL; that is not a
// failure of the swap.
func restoreSyncDir(dir string) {
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- the data directory or a directory this code created under it
		_ = d.Sync()
		_ = d.Close()
	}
}

func writeRestoreIntent(work string, in *restoreIntent) error {
	body, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return fmt.Errorf("encode intent: %w", err)
	}
	return atomicWriteFile(filepath.Join(work, restoreIntentName), append(body, '\n'), 0o600)
}

func writeRestoreOutcome(work string, out restoreOutcome) {
	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return
	}
	// Informational: the swap's result does not depend on this record.
	_ = atomicWriteFile(filepath.Join(work, restoreOutcomeName), append(body, '\n'), 0o600)
}

// validRestoreSwapName admits a top-level name the swap may rename: one path
// element, nothing the swap excludes.
func validRestoreSwapName(name string) bool {
	if name == "" || name == "." || name == ".." || restoreSwapExcluded(name) {
		return false
	}
	return !strings.ContainsAny(name, "/\\\x00") && filepath.Base(name) == name
}

// validRestoreSuffix admits the `<YYYYMMDDTHHMMSSZ>-<pid>` suffix and nothing
// else, so a suffix read from disk can never name a path outside the work area.
func validRestoreSuffix(s string) bool {
	ts, pid, ok := strings.Cut(s, "-")
	if !ok {
		return false
	}
	if _, err := time.ParseInLocation("20060102T150405Z", ts, time.UTC); err != nil {
		return false
	}
	n, err := strconv.Atoi(pid)
	return err == nil && n >= 0 && strconv.Itoa(n) == pid
}

// readRestoreIntent returns the recorded intent, or (nil, nil) when no swap is
// outstanding. A record that exists and cannot be trusted is an error: the
// caller must stop, not guess.
func readRestoreIntent(dataDir string) (*restoreIntent, error) {
	path := filepath.Join(dataDir, restoreWorkDirName, restoreIntentName)
	body, err := os.ReadFile(path) // #nosec G304 -- a fixed name under the operator-configured data directory
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var in restoreIntent
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, fmt.Errorf("%s is not a readable restore intent record", path)
	}
	if in.Version != restoreIntentVersion {
		return nil, fmt.Errorf("%s has version %d; this build understands %d", path, in.Version, restoreIntentVersion)
	}
	if !validRestoreSuffix(in.Suffix) {
		return nil, fmt.Errorf("%s carries a malformed suffix", path)
	}
	if in.Phase != restorePhaseEvacuating && in.Phase != restorePhaseInstalling {
		return nil, fmt.Errorf("%s carries an unknown phase", path)
	}
	for _, list := range [][]string{in.Old, in.New} {
		for _, n := range list {
			if !validRestoreSwapName(n) {
				return nil, fmt.Errorf("%s lists a name the swap never moves", path)
			}
		}
	}
	return &in, nil
}

// rollbackInPlaceRestore undoes a swap that did not commit and returns the
// data directory to the content it had before. It only renames; it deletes
// nothing but the staged copy of the new content and its own records.
//
// It refuses, changing nothing further, when a name is found both in the data
// directory and in the backup directory: that is a state the swap cannot
// produce, so nothing here knows which of the two is the previous content.
func rollbackInPlaceRestore(dataDir string, in *restoreIntent, reason string) error {
	work, staging, bak := restoreWorkPaths(dataDir, in.Suffix)

	// Phase "installing": every previous entry is in the backup directory, and
	// some staged entries are in the data directory. Send those back first, so
	// the names are free for the previous content.
	if in.Phase == restorePhaseInstalling {
		for _, n := range in.New {
			live, staged := filepath.Join(dataDir, n), filepath.Join(staging, n)
			if !restorePathExists(live) {
				continue // not installed yet
			}
			if restorePathExists(staged) {
				return fmt.Errorf("restore: cannot undo the interrupted restore: %q exists both in the data directory and in %s", n, staging)
			}
			if err := os.MkdirAll(staging, 0o700); err != nil {
				return fmt.Errorf("restore: undo: %w", err)
			}
			if err := os.Rename(live, staged); err != nil {
				return fmt.Errorf("restore: undo: move the restored %q out again: %w", n, err)
			}
		}
	}
	for _, n := range in.Old {
		live, kept := filepath.Join(dataDir, n), filepath.Join(bak, n)
		if !restorePathExists(kept) {
			continue // never left
		}
		if restorePathExists(live) {
			return fmt.Errorf("restore: cannot undo the interrupted restore: %q exists both in the data directory and in %s", n, bak)
		}
		if err := os.Rename(kept, live); err != nil {
			return fmt.Errorf("restore: undo: move the previous %q back: %w", n, err)
		}
	}
	restoreSyncDir(dataDir)

	// The previous content is established only if every recorded name is back.
	for _, n := range in.Old {
		if !restorePathExists(filepath.Join(dataDir, n)) {
			return fmt.Errorf("restore: the interrupted restore was undone but the previous %q is missing; "+
				"nothing was deleted — inspect %s before starting Culvert", n, work)
		}
	}
	_ = os.Remove(bak)        // empty now; a non-empty one is kept and listed as a leftover
	_ = os.RemoveAll(staging) // #nosec G104 -- the staged copy of content that was never committed
	if err := os.Remove(filepath.Join(work, restoreIntentName)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("restore: the previous content is back but the intent record could not be removed: %w", err)
	}
	restoreSyncDir(work)
	writeRestoreOutcome(work, restoreOutcome{
		Outcome: restoreOutcomeRolledBack, Suffix: in.Suffix, Mode: in.Mode, At: restoreNow().UTC(), Reason: reason,
	})
	return nil
}

// recoverInterruptedInPlaceRestore rolls back a recorded, uncommitted swap.
// The caller MUST hold the single-writer lock: the record alone cannot tell a
// dead restore from one that is still renaming. Returns whether a swap was
// rolled back.
func recoverInterruptedInPlaceRestore(dataDir, reason string) (bool, error) {
	in, err := readRestoreIntent(dataDir)
	if err != nil {
		return false, fmt.Errorf("restore: an earlier restore did not finish and its record cannot be used (%w); "+
			"nothing was changed — inspect %s", err, filepath.Join(dataDir, restoreWorkDirName))
	}
	if in == nil {
		return false, nil
	}
	if err := rollbackInPlaceRestore(dataDir, in, reason); err != nil {
		return false, err
	}
	return true, nil
}

// recoverInPlaceRestoreAtBoot is main's guard, called right after the
// single-writer lock was decided. With no record outstanding it does nothing.
// With one, it rolls the data directory back to its previous content before
// anything reads it — but only while this process provably holds the lock.
// Without the lock a restore may still be running, and starting on a
// half-swapped directory is the one thing that must not happen: refuse.
func recoverInPlaceRestoreAtBoot(dataDir string, lockHeld bool) error {
	in, err := readRestoreIntent(dataDir)
	if err != nil {
		return fmt.Errorf("restore: an earlier restore did not finish and its record cannot be used (%w); "+
			"refusing to start on a data directory in an unknown state — inspect %s",
			err, filepath.Join(dataDir, restoreWorkDirName))
	}
	if in == nil {
		return nil
	}
	if !lockHeld {
		return fmt.Errorf("restore: an earlier restore of %q did not finish, and the single-writer lock could not be "+
			"established, so it may still be running; refusing to start. Stop every other Culvert process on this "+
			"data directory and start again", dataDir)
	}
	if err := rollbackInPlaceRestore(dataDir, in, "interrupted restore undone at startup"); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "Restore: an interrupted restore (%s, mode %s) was undone at startup; "+
		"the data directory holds its previous content. Run the restore again if it is still wanted.\n",
		in.Suffix, in.Mode)
	return nil
}

// verifyRestoredFiles re-reads every file the restore took from the archive
// and compares content and mode with the manifest. A commit is reported only
// for bytes that are provably on the volume.
func verifyRestoredFiles(dataDir string, manifest *backupManifest, mode restoreMode) error {
	for i := range manifest.Files {
		f := &manifest.Files[i]
		if !mode.fromTarball(f.Path) {
			continue
		}
		target := filepath.Join(dataDir, strings.TrimPrefix(f.Path, "data/"))
		if err := guardWithinDir(dataDir, target); err != nil {
			return fmt.Errorf("verify %s: %w", f.Path, err)
		}
		body, err := os.ReadFile(target) // #nosec G304 G703 -- guardWithinDir above; a manifest path under the operator-configured data directory
		if err != nil {
			return fmt.Errorf("verify %s: %w", f.Path, err)
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return fmt.Errorf("verify %s: content on disk does not match the backup manifest", f.Path)
		}
		want, perr := strconv.ParseUint(f.Mode, 8, 32)
		info, serr := os.Stat(target) // #nosec G703 -- the same guarded path as the read above
		if perr != nil || serr != nil || info.Mode().Perm() != os.FileMode(want)&os.ModePerm {
			return fmt.Errorf("verify %s: file mode on disk does not match the backup manifest", f.Path)
		}
	}
	return nil
}

// takeRestoreWriterLock takes the single-writer lock for the swap. A live
// holder is a running proxy: the restore is offline-only, and this is where
// that rule is enforced — at the directory, not at whoever asked. A lock whose
// state cannot be observed does not block, exactly as at boot.
func takeRestoreWriterLock(dataDir string) (*writerlock.Lock, error) {
	got := writerlock.Take(dataDir)
	if got.Verdict == writerlock.Held && !allowMultipleWriters() {
		return nil, fmt.Errorf("restore: a running Culvert process holds %s; stop it first (docker compose down) — "+
			"a restore replaces files that process is writing", got.Path)
	}
	return got.Lock, nil
}

// restoreStep reports one durable step to the test hook.
func restoreStep(step string) error {
	if restoreInPlaceStepHook == nil {
		return nil
	}
	if err := restoreInPlaceStepHook(step); err != nil {
		return fmt.Errorf("%w (%s): %w", errRestoreAbandoned, step, err)
	}
	return nil
}

// restoreMoveAll renames every name from one directory into another, stopping
// at the first failure.
func restoreMoveAll(names []string, from, to string) error {
	for _, n := range names {
		if err := os.Rename(filepath.Join(from, n), filepath.Join(to, n)); err != nil {
			return fmt.Errorf("move %q: %w", n, err)
		}
	}
	restoreSyncDir(from)
	restoreSyncDir(to)
	return nil
}

// commitRestoreInPlace is runRestoreCommit's steps 5–8 for a data directory
// that cannot be renamed. See the file comment for the order and its reasons.
func commitRestoreInPlace(dataDir string, files map[string][]byte, manifest *backupManifest, mode restoreMode, suffix string) error {
	lock, err := takeRestoreWriterLock(dataDir)
	if err != nil {
		return err
	}
	if lock != nil {
		defer func() { _ = lock.Close() }()
	}
	work, staging, bak := restoreWorkPaths(dataDir, suffix)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return fmt.Errorf("restore: create work area: %w", err)
	}
	undone, err := recoverInterruptedInPlaceRestore(dataDir, "interrupted restore undone by the next restore")
	if err != nil {
		return err
	}
	if undone {
		_, _ = fmt.Fprintln(os.Stdout, "An earlier restore that did not finish was undone first; the data directory held its previous content before this restore started.")
	}
	for _, p := range []string{staging, bak} {
		if restorePathExists(p) {
			return fmt.Errorf("restore: path %q already exists; remove it before retrying", p)
		}
	}

	_, _ = fmt.Fprintf(os.Stdout, "\nCommitting restore now (in place: %s cannot be renamed as a whole).\n", dataDir)
	_, _ = fmt.Fprintf(os.Stdout, "  Staging dir: %s\n", staging)
	_, _ = fmt.Fprintf(os.Stdout, "  Backup of the current content will be at: %s\n\n", bak)

	if err := stageArtifacts(staging, dataDir, files, manifest, mode); err != nil {
		_ = os.RemoveAll(staging) // #nosec G104 -- best-effort cleanup of content that never left staging
		return fmt.Errorf("restore: stage failed: %w", err)
	}
	// A non-full mode copies every live file it keeps, the lock file included.
	// The live lock stays where it is, so the copy is dropped.
	_ = os.Remove(filepath.Join(staging, writerlock.FileName))
	if err := restoreStep("staged"); err != nil {
		return err
	}

	in, err := planInPlaceSwap(dataDir, staging, mode, suffix)
	if err != nil {
		_ = os.RemoveAll(staging) // #nosec G104 -- nothing was moved yet
		return err
	}
	if err := runInPlaceSwap(dataDir, work, staging, bak, in, manifest, mode); err != nil {
		if errors.Is(err, errRestoreAbandoned) {
			return err
		}
		if rerr := rollbackInPlaceRestore(dataDir, in, "restore failed: "+err.Error()); rerr != nil {
			return fmt.Errorf("restore: COMMIT FAILED (%w) and the previous content could not be put back: %w", err, rerr)
		}
		return fmt.Errorf("restore: commit failed, the previous content was put back and nothing was changed: %w", err)
	}

	_, _ = fmt.Fprintf(os.Stdout, "\nRestore committed.\n")
	_, _ = fmt.Fprintf(os.Stdout, "  Previous content preserved at: %s\n", bak)
	_, _ = fmt.Fprintf(os.Stdout, "  (.bak is NOT auto-deleted; remove it with --cleanup-restore-leftovers when no longer needed.)\n")
	return nil
}

// planInPlaceSwap builds the intent record from what is on disk now.
func planInPlaceSwap(dataDir, staging string, mode restoreMode, suffix string) (*restoreIntent, error) {
	oldNames, err := restoreTopLevelNames(dataDir)
	if err != nil {
		return nil, fmt.Errorf("restore: list current content: %w", err)
	}
	newNames, err := restoreTopLevelNames(staging)
	if err != nil {
		return nil, fmt.Errorf("restore: list staged content: %w", err)
	}
	return &restoreIntent{
		Version: restoreIntentVersion, Suffix: suffix, Mode: mode.String(),
		Phase: restorePhaseEvacuating, StartedAt: restoreNow().UTC(), Old: oldNames, New: newNames,
	}, nil
}

// runInPlaceSwap performs steps 4–9. Any error it returns, other than an
// abandonment injected by a test, is answered by the caller with a rollback.
func runInPlaceSwap(dataDir, work, staging, bak string, in *restoreIntent, manifest *backupManifest, mode restoreMode) error {
	if err := writeRestoreIntent(work, in); err != nil {
		return fmt.Errorf("record intent: %w", err)
	}
	if err := restoreStep("intent"); err != nil {
		return err
	}
	if err := os.Mkdir(bak, 0o700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	if err := restoreMoveAll(in.Old, dataDir, bak); err != nil {
		return fmt.Errorf("move current content aside: %w", err)
	}
	if err := restoreStep("evacuated"); err != nil {
		return err
	}
	in.Phase = restorePhaseInstalling
	if err := writeRestoreIntent(work, in); err != nil {
		return fmt.Errorf("record intent: %w", err)
	}
	if err := restoreStep("installing"); err != nil {
		return err
	}
	if err := restoreMoveAll(in.New, staging, dataDir); err != nil {
		return fmt.Errorf("move restored content in: %w", err)
	}
	if err := restoreStep("installed"); err != nil {
		return err
	}
	if err := verifyRestoredFiles(dataDir, manifest, mode); err != nil {
		return err
	}
	if err := restoreStep("verified"); err != nil {
		return err
	}
	// Commit point.
	if err := os.Remove(filepath.Join(work, restoreIntentName)); err != nil {
		return fmt.Errorf("remove intent record: %w", err)
	}
	restoreSyncDir(work)
	_ = os.Remove(staging) // empty now
	writeRestoreOutcome(work, restoreOutcome{
		Outcome: restoreOutcomeCommitted, Suffix: in.Suffix, Mode: in.Mode, At: restoreNow().UTC(), BackupDir: bak,
	})
	return nil
}

// restorePreflightLine is the last line of a dry-run: one machine-readable
// verdict on whether a commit with the same arguments would be refused before
// it changed anything. The maintenance agent reads it BEFORE it stops the
// proxy, so a restore that cannot start never costs an outage.
//
// It is a line, not an exit code, on purpose: a dry-run that prints a plan
// with a guard that "would block" has always exited 0, and operators' scripts
// rely on that. An agent talking to an older image finds no line and behaves
// as it did before.
const restorePreflightPrefix = "RESTORE-PREFLIGHT v1 "

// restoreCommitRefusal returns why a commit would be refused before touching
// the data directory, or "" when nothing known stands in its way. It writes
// nothing.
func restoreCommitRefusal(dataDir string, a *commitAnalysis, files map[string][]byte) string {
	switch {
	case a.DPGuardWouldBlock:
		return "dp_reenrollment_not_accepted"
	case a.TOTPGuardWouldBlock:
		return "totp_counter_rollback_not_allowed"
	}
	if !restoreUsesInPlaceSwap(dataDir) {
		return ""
	}
	if !restoreDirWritable(dataDir) {
		return "data_dir_not_writable"
	}
	if _, err := readRestoreIntent(dataDir); err != nil {
		return "earlier_restore_record_unusable"
	}
	var need uint64
	for path, body := range files {
		if path != "manifest.json" {
			need += uint64(len(body))
		}
	}
	if free, known := restoreFreeBytes(dataDir); known && free < need+restoreFreeSpaceMargin {
		return "not_enough_free_space"
	}
	return ""
}

func printRestorePreflight(dataDir string, a *commitAnalysis, files map[string][]byte) {
	layout := "directory-swap"
	if restoreUsesInPlaceSwap(dataDir) {
		layout = "in-place"
	}
	if reason := restoreCommitRefusal(dataDir, a, files); reason != "" {
		_, _ = fmt.Fprintf(os.Stdout, "\n%scommit=refused layout=%s reason=%s\n", restorePreflightPrefix, layout, reason)
		return
	}
	_, _ = fmt.Fprintf(os.Stdout, "\n%scommit=ok layout=%s\n", restorePreflightPrefix, layout)
}
