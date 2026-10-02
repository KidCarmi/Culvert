package main

// restore_inplace.go — mount-point-safe restore commit (appliance readiness,
// register row ST-9 / the restore_mountpoint_test.go finding).
//
// runRestoreCommit used to swap /data by renaming the DIRECTORY ITSELF:
// `rename(/data, /data.bak.<ts>)` then `rename(/data.staging.<ts>, /data)`.
// That is a clean single-boundary design on a bare host, and it can NEVER
// work in the one topology the feature ships for: every Docker volume or
// bind mount is a mount point inside the container, and rename(2) refuses to
// move a mount point (EBUSY). The documented `docker compose --profile cli
// run --rm cli --restore … --confirm` path therefore failed on every real
// deployment, and restore_mountpoint_test.go pinned that failure as a fact
// rather than fixing it. Worse, had the rename succeeded, the `.bak` sibling
// would have landed on the container's EPHEMERAL overlay root — outside the
// volume — and been lost with the container.
//
// The swap now happens INSIDE the data directory, at the level of its
// top-level entries, and is JOURNALED so that an interruption at any point
// leaves a state that is recoverable deterministically in BOTH directions:
//
//	<dataDir>/.restore-staging.<ts>-<pid>/   the restored content, staged
//	<dataDir>/.restore-bak.<ts>-<pid>/       the previous content, moved aside
//	<dataDir>/.restore-journal.json          the commit journal (phase)
//
// Commit sequence (after the unchanged validate/analyze/guard/stage steps):
//
//	J1. write journal {phase: evacuating}      (fsync file + dir)
//	E.  rename every top-level entry of <dataDir> (except the .restore-*
//	    internals and the lock file) into .restore-bak.<suffix>/
//	J2. write journal {phase: promoting}
//	P.  rename every top-level entry of .restore-staging.<suffix>/ into
//	    <dataDir>/
//	J3. rmdir the (now empty) staging dir, remove the journal, fsync.
//
// There is no longer ONE atomic boundary; instead every state the process
// can be killed in is one of two well-defined phases, each with a
// deterministic REVERT and a deterministic COMPLETE:
//
//	evacuating: originals are split between <dataDir> (not yet moved) and
//	            the bak dir; nothing from staging has been promoted.
//	            revert   = move bak/* back into <dataDir>.
//	            complete = finish evacuating, then promote staging/*.
//	promoting:  every original is in the bak dir; <dataDir> holds only
//	            entries promoted from staging so far.
//	            revert   = move the promoted entries back into staging,
//	            then move bak/* back into <dataDir>.
//	            complete = promote the remaining staging/*.
//
// Both operations are idempotent (they act on the CURRENT directory state,
// never on a recorded list), so a second interruption during recovery is
// recovered by running the same command again.
//
// Recovery is EXPLICIT, never automatic: a journal present at boot refuses
// the boot (checkInterruptedRestore) and names the exact command. Resuming
// destructive work silently — in either direction — is the one thing this
// code must never do: the operator chooses whether the restore they were
// attempting should land or be undone.
//
// Why NOT keep the sibling layout and fall back: a sibling of a mount point
// is outside the volume (lost with the container) and a mount point cannot
// be renamed, so there is no deployment in which the sibling layout is
// preferable. The in-directory layout works identically on a bare host.
// Legacy sibling leftovers (`<dataDir>.bak.<ts>-<pid>`) from older builds
// stay discoverable by --list/--cleanup-restore-leftovers.
//
// Quiescing: the proxy holds an advisory flock on <dataDir>/.culvert.lock for
// its lifetime (restore_lock_unix.go); the commit and the recovery refuse to
// run while that lock is held, so "stop the stack first" is enforced rather
// than merely documented (the cli container shares the volume, and flock is
// inode-based, so it is visible across containers on one host).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// restoreInternalPrefix marks the top-level entries of dataDir that
	// belong to the restore machinery and are never user data.
	restoreInternalPrefix = ".restore-"
	restoreStagingPrefix  = restoreInternalPrefix + "staging."
	restoreBakPrefix      = restoreInternalPrefix + "bak."
	restoreJournalName    = restoreInternalPrefix + "journal.json"
	restoreJournalVersion = 1

	restorePhaseEvacuating = "evacuating"
	restorePhasePromoting  = "promoting"

	// dataDirLockName is the advisory lock the running proxy holds on its
	// data directory; see restore_lock_unix.go.
	dataDirLockName = ".culvert.lock"
)

// restoreJournal is the durable commit record. It carries NO content list on
// purpose: recovery is driven by what is on disk, so a stale or partial list
// can never make recovery act on the wrong entries.
type restoreJournal struct {
	Version    int       `json:"version"`
	Suffix     string    `json:"suffix"`
	Phase      string    `json:"phase"`
	StagingDir string    `json:"staging_dir"` // basename, inside dataDir
	BakDir     string    `json:"bak_dir"`     // basename, inside dataDir
	Mode       string    `json:"mode"`
	StartedAt  time.Time `json:"started_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// isRestoreInternalEntry reports whether a TOP-LEVEL dataDir entry name is
// owned by the restore/lock machinery (never user data, never evacuated,
// never promoted, never archived or carried over by stageArtifacts).
func isRestoreInternalEntry(name string) bool {
	return strings.HasPrefix(name, restoreInternalPrefix) || name == dataDirLockName
}

func restoreJournalPath(dataDir string) string {
	return filepath.Join(dataDir, restoreJournalName)
}

// writeRestoreJournal persists the journal durably (atomic rename + parent
// fsync via atomicWriteFile, then an explicit directory fsync so the journal
// is visible before the renames that depend on it).
func writeRestoreJournal(dataDir string, j *restoreJournal) error {
	j.UpdatedAt = restoreNow().UTC()
	if j.Version == 0 {
		j.Version = restoreJournalVersion
	}
	body, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("restore journal: marshal: %w", err)
	}
	if err := atomicWriteFile(restoreJournalPath(dataDir), body, 0o600); err != nil {
		return fmt.Errorf("restore journal: write: %w", err)
	}
	return fsyncDirBestEffort(dataDir)
}

// readRestoreJournal returns (journal, true, nil) when a journal exists,
// (nil, false, nil) when none does, and an error for an unreadable or
// malformed one — which is treated as an interrupted restore of unknown
// phase by every caller (fail closed: refuse, never guess).
func readRestoreJournal(dataDir string) (*restoreJournal, bool, error) {
	body, err := os.ReadFile(restoreJournalPath(dataDir)) // #nosec G304 -- operator-controlled data dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("restore journal: read: %w", err)
	}
	var j restoreJournal
	if err := json.Unmarshal(body, &j); err != nil {
		return nil, true, fmt.Errorf("restore journal: malformed: %w", err)
	}
	if j.Version != restoreJournalVersion {
		return nil, true, fmt.Errorf("restore journal: unsupported version %d (this build writes %d)", j.Version, restoreJournalVersion)
	}
	if j.Phase != restorePhaseEvacuating && j.Phase != restorePhasePromoting {
		return nil, true, fmt.Errorf("restore journal: unknown phase %q", j.Phase)
	}
	if !strings.HasPrefix(j.StagingDir, restoreStagingPrefix) || !strings.HasPrefix(j.BakDir, restoreBakPrefix) ||
		filepath.Base(j.StagingDir) != j.StagingDir || filepath.Base(j.BakDir) != j.BakDir {
		return nil, true, fmt.Errorf("restore journal: refusing malformed staging/bak names %q / %q", j.StagingDir, j.BakDir)
	}
	return &j, true, nil
}

func removeRestoreJournal(dataDir string) error {
	if err := os.Remove(restoreJournalPath(dataDir)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("restore journal: remove: %w", err)
	}
	return fsyncDirBestEffort(dataDir)
}

// fsyncDirBestEffort mirrors the parent-dir fsync atomicWriteFile performs;
// directory fsync is unsupported on some filesystems, so a failure to open or
// sync is tolerated (the renames themselves are durable on the next sync).
func fsyncDirBestEffort(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- operator-controlled data dir
	if err != nil {
		return nil
	}
	defer d.Close() //nolint:errcheck // best-effort directory sync
	_ = d.Sync()
	return nil
}

// listTopLevelUserEntries returns the sorted names of dir's top-level entries
// that are NOT restore internals. It never follows symlinks (ReadDir is
// Lstat-based) and never descends.
func listTopLevelUserEntries(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if isRestoreInternalEntry(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

// moveTopLevelEntries renames every top-level user entry of src into dst.
// It is the single primitive behind evacuation, promotion and both recovery
// directions, and it is idempotent: an entry already moved is simply absent
// from src on the next run. A destination collision is refused rather than
// clobbered — it cannot happen in the phase machine (an entry lives in
// exactly one of dataDir / staging / bak at any time) and if it ever does,
// overwriting is the one wrong answer.
func moveTopLevelEntries(src, dst string) (int, error) {
	names, err := listTopLevelUserEntries(src)
	if err != nil {
		return 0, fmt.Errorf("list %s: %w", src, err)
	}
	moved := 0
	for _, name := range names {
		from := filepath.Join(src, name)
		to := filepath.Join(dst, name)
		if _, err := os.Lstat(to); err == nil {
			return moved, fmt.Errorf("refusing to overwrite existing %s while moving %s", to, from)
		} else if !os.IsNotExist(err) {
			return moved, fmt.Errorf("lstat %s: %w", to, err)
		}
		if err := os.Rename(from, to); err != nil {
			return moved, fmt.Errorf("rename %s → %s: %w", from, to, err)
		}
		moved++
	}
	return moved, nil
}

// nestedMountPointsUnder returns mount points strictly below dir (Linux
// /proc/self/mountinfo; empty elsewhere). An entry of dataDir that is itself
// a mount point (e.g. a `./yara:/data/yara:ro` bind in docker-compose.yml)
// cannot be renamed, so the commit refuses BEFORE any destructive step
// instead of failing half-way through evacuation.
func nestedMountPointsUnder(dir string) []string {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only
	body, err := io.ReadAll(io.LimitReader(f, 4<<20))
	if err != nil {
		return nil
	}
	// mountinfo reports REAL paths, so dir must be resolved the same way: a
	// data dir reached through a symlink (CULVERT_DATA_DIR only requires an
	// absolute, clean path) would otherwise hide every nested mount and the
	// "refuse before anything destructive" promise would break mid-evacuation
	// with EBUSY (adversarial review, PR #1528). A dir that cannot be resolved
	// cannot be verified, so it is reported as its own obstacle: the caller
	// refuses rather than guesses.
	abs, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return []string{dir + " (cannot resolve: " + err.Error() + ")"}
	}
	abs, err = filepath.Abs(abs)
	if err != nil {
		return []string{dir + " (cannot resolve: " + err.Error() + ")"}
	}
	abs = filepath.Clean(abs)
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMountinfo(fields[4])
		if mp != abs && strings.HasPrefix(mp, abs+string(filepath.Separator)) {
			out = append(out, mp)
		}
	}
	sort.Strings(out)
	return out
}

// unescapeMountinfo decodes the octal escapes mountinfo uses for space, tab,
// newline and backslash in path fields.
func unescapeMountinfo(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// swapInPlace runs the journaled evacuate→promote sequence described in the
// file header. stagingDir and bakDir are ABSOLUTE paths inside dataDir.
func swapInPlace(dataDir, stagingDir, bakDir string, j *restoreJournal) error {
	if err := os.Mkdir(bakDir, 0o700); err != nil {
		return fmt.Errorf("mkdir bak (exclusive): %w", err)
	}
	j.Phase = restorePhaseEvacuating
	if err := writeRestoreJournal(dataDir, j); err != nil {
		_ = os.Remove(bakDir) // #nosec G104 -- best-effort cleanup of the empty dir
		return err
	}
	if _, err := moveTopLevelEntries(dataDir, bakDir); err != nil {
		return fmt.Errorf("evacuate current data: %w (interrupted restore — run --recover-restore)", err)
	}
	_ = fsyncDirBestEffort(bakDir)
	j.Phase = restorePhasePromoting
	if err := writeRestoreJournal(dataDir, j); err != nil {
		return fmt.Errorf("%w (interrupted restore — run --recover-restore)", err)
	}
	// Test seam: the critical window between the two phases.
	if commitInjectBetweenRenames != nil {
		if err := commitInjectBetweenRenames(); err != nil {
			return fmt.Errorf("injected: %w (interrupted restore — run --recover-restore)", err)
		}
	}
	if _, err := moveTopLevelEntries(stagingDir, dataDir); err != nil {
		return fmt.Errorf("promote staged data: %w (interrupted restore — run --recover-restore)", err)
	}
	if err := os.Remove(stagingDir); err != nil {
		// Staging must be empty now; anything else is a bug worth surfacing,
		// but the data has landed, so finish the journal rather than
		// leaving the boot guard armed over an empty directory.
		_, _ = fmt.Fprintf(os.Stderr, "WARN: could not remove empty staging dir %s: %v\n", stagingDir, err)
	}
	if err := removeRestoreJournal(dataDir); err != nil {
		return err
	}
	return nil
}

// restoreRecoverAction is the operator's explicit choice for an interrupted
// restore (--recover-restore --confirm <action>).
type restoreRecoverAction string

const (
	recoverActionRevert   restoreRecoverAction = "revert"
	recoverActionComplete restoreRecoverAction = "complete"
)

// errNoInterruptedRestore is returned by runRecoverRestore when no journal
// exists — the data directory is in a normal state.
var errNoInterruptedRestore = errors.New("no interrupted restore found (no restore journal in the data directory)")

// runRecoverRestore inspects (action == "") or resolves (action == revert |
// complete) an interrupted in-place restore. It is a one-shot CLI command;
// output goes to stdout so an operator can copy the next command verbatim.
func runRecoverRestore(dataDir string, action restoreRecoverAction, out io.Writer) error {
	j, present, err := readRestoreJournal(dataDir)
	if !present && err == nil {
		return errNoInterruptedRestore
	}
	if err != nil {
		return fmt.Errorf("%w — the journal cannot be trusted; inspect %s and the .restore-* directories by hand before removing the journal", err, restoreJournalPath(dataDir))
	}
	stagingDir := filepath.Join(dataDir, j.StagingDir)
	bakDir := filepath.Join(dataDir, j.BakDir)
	live, _ := listTopLevelUserEntries(dataDir)
	staged, _ := listTopLevelUserEntries(stagingDir)
	backed, _ := listTopLevelUserEntries(bakDir)

	_, _ = fmt.Fprintf(out, "Interrupted restore detected in %s\n", dataDir)
	_, _ = fmt.Fprintf(out, "  Started:        %s   (mode %s)\n", j.StartedAt.UTC().Format(time.RFC3339), j.Mode)
	_, _ = fmt.Fprintf(out, "  Phase:          %s\n", j.Phase)
	_, _ = fmt.Fprintf(out, "  Previous data:  %s   (%d top-level entries)\n", bakDir, len(backed))
	_, _ = fmt.Fprintf(out, "  Staged restore: %s   (%d top-level entries)\n", stagingDir, len(staged))
	_, _ = fmt.Fprintf(out, "  Live data dir:  %d top-level user entries\n", len(live))

	switch action {
	case "":
		_, _ = fmt.Fprintf(out, "\nChoose ONE and re-run with the stack still stopped:\n")
		_, _ = fmt.Fprintf(out, "  REVERT   (undo the restore, previous data back):   --recover-restore --confirm=revert\n")
		_, _ = fmt.Fprintf(out, "  COMPLETE (finish the restore, staged data lands):  --recover-restore --confirm=complete\n")
		return nil
	case recoverActionRevert:
		return recoverRevert(dataDir, stagingDir, bakDir, j, out)
	case recoverActionComplete:
		return recoverComplete(dataDir, stagingDir, bakDir, j, out)
	default:
		return fmt.Errorf("unknown recovery action %q (use --confirm=revert or --confirm=complete)", string(action))
	}
}

// moveTopLevelEntriesIfPresent is moveTopLevelEntries for the RECOVERY
// paths, where an absent source directory is a valid current state (a bak
// dir the operator removed, a staging dir promotion already emptied and
// removed): nothing to move, not an error. The commit path keeps the strict
// form — there, a missing dir is a bug.
func moveTopLevelEntriesIfPresent(src, dst string) (int, error) {
	if _, err := os.Lstat(src); os.IsNotExist(err) {
		return 0, nil
	}
	return moveTopLevelEntries(src, dst)
}

func recoverRevert(dataDir, stagingDir, bakDir string, j *restoreJournal, out io.Writer) error {
	if j.Phase == restorePhasePromoting {
		// Everything live was promoted from staging; put it back there so
		// the bak entries can return without collisions.
		if _, err := os.Lstat(stagingDir); os.IsNotExist(err) {
			if err := os.Mkdir(stagingDir, 0o700); err != nil {
				return fmt.Errorf("recreate staging dir: %w", err)
			}
		}
		n, err := moveTopLevelEntries(dataDir, stagingDir)
		if err != nil {
			return fmt.Errorf("revert: un-promote: %w", err)
		}
		_, _ = fmt.Fprintf(out, "  Moved %d promoted entr%s back to staging\n", n, entries(n))
	}
	n, err := moveTopLevelEntriesIfPresent(bakDir, dataDir)
	if err != nil {
		return fmt.Errorf("revert: restore previous data: %w", err)
	}
	_, _ = fmt.Fprintf(out, "  Moved %d previous entr%s back into %s\n", n, entries(n), dataDir)
	if err := os.Remove(bakDir); err != nil && !os.IsNotExist(err) {
		_, _ = fmt.Fprintf(out, "  WARN: previous-data dir %s not empty after revert: %v\n", bakDir, err)
	}
	if err := removeRestoreJournal(dataDir); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "\nRestore REVERTED. Previous data is live again.\n")
	_, _ = fmt.Fprintf(out, "  The staged restore content is kept at %s for inspection;\n", stagingDir)
	_, _ = fmt.Fprintf(out, "  remove it with --cleanup-restore-leftovers --confirm when no longer needed.\n")
	return nil
}

func recoverComplete(dataDir, stagingDir, bakDir string, j *restoreJournal, out io.Writer) error {
	if j.Phase == restorePhaseEvacuating {
		if err := os.MkdirAll(bakDir, 0o700); err != nil {
			return fmt.Errorf("complete: previous-data dir: %w", err)
		}
		n, err := moveTopLevelEntries(dataDir, bakDir)
		if err != nil {
			return fmt.Errorf("complete: finish evacuating: %w", err)
		}
		_, _ = fmt.Fprintf(out, "  Moved %d remaining previous entr%s aside\n", n, entries(n))
		j.Phase = restorePhasePromoting
		if err := writeRestoreJournal(dataDir, j); err != nil {
			return err
		}
	}
	// swapInPlace removes the (empty) staging dir BEFORE it retires the
	// journal, so a kill between those two steps leaves a `promoting` journal
	// with every restored entry already live and no staging dir at all. That
	// is a supported interruption point: completing it means retiring the
	// journal, never failing on the missing directory (Codex review, PR #1528).
	if _, serr := os.Lstat(stagingDir); os.IsNotExist(serr) {
		_, _ = fmt.Fprintf(out, "  Staged data was already fully promoted (staging dir gone); nothing left to move\n")
	} else {
		n, err := moveTopLevelEntries(stagingDir, dataDir)
		if err != nil {
			return fmt.Errorf("complete: promote staged data: %w", err)
		}
		_, _ = fmt.Fprintf(out, "  Promoted %d staged entr%s into %s\n", n, entries(n), dataDir)
		if err := os.Remove(stagingDir); err != nil && !os.IsNotExist(err) {
			_, _ = fmt.Fprintf(out, "  WARN: staging dir %s not empty after promotion: %v\n", stagingDir, err)
		}
	}
	if err := removeRestoreJournal(dataDir); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "\nRestore COMPLETED. Restored data is live.\n")
	_, _ = fmt.Fprintf(out, "  Previous data preserved at %s (never auto-deleted);\n", bakDir)
	_, _ = fmt.Fprintf(out, "  remove it with --cleanup-restore-leftovers --confirm when no longer needed.\n")
	return nil
}

// entries pluralises "entry" for the recovery transcript.
func entries(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
