package catdb

// resilient.go — CHAOS-50: surviving a corrupt Layer-2 community store.
//
// WHY THIS EXISTS
//
// The community category store is a BadgerDB directory on the data volume and
// it is opened on the BOOT path. Two things make that combination dangerous for
// an in-line gateway:
//
//  1. badger.Open does not always return an error. A corrupted `.sst` table
//     makes it PANIC from a goroutine badger itself spawns
//     (table.OpenTable ← newLevelsController), so no recover() at any call site
//     can contain it — the process dies.
//  2. Every other open failure it DOES return (torn MANIFEST, bad magic,
//     missing table, KEYREGISTRY damage) is unrecoverable by retrying: the
//     directory stays broken across restarts.
//
// Left alone, either one turns "one unclean kill of the container" into a
// permanent refusal to boot. That is the wrong posture for this particular
// store, because it holds NO authoritative state: it is a derived cache of a
// downloadable feed, and the syncer refills an empty one automatically on the
// next start. The CHAOS-05/07 contract already established the right rule for
// corrupt state on the boot path — quarantine the evidence, do not overwrite
// it, and keep booting — and this file extends that rule to a store whose
// failure mode badger will not let us catch.
//
// HOW
//
// A marker file is armed beside the directory for the duration of every open
// attempt and cleared when the attempt returns — success or error. A marker
// found at startup therefore means exactly one thing: a previous process
// entered badger.Open on this directory and never came back out. That is the
// only signal available for the uncatchable-panic case, and it also covers a
// SIGKILL/OOM landing inside Open. On that signal the directory is quarantined
// BEFORE badger is allowed near it again, so the second boot succeeds where the
// first one died.
//
// Quarantine is deliberately hard to trigger:
//
//   - a RETURNED error quarantines only when it is positively identified as
//     corruption. Environmental failures (another process holds the store, no
//     permission, read-only volume, no space, not a directory) degrade instead.
//     Renaming the directory would not fix any of them, and on the lock case it
//     would move a live store out from under its owner.
//   - the store's flock is probed before ANY quarantine, so a concurrent boot
//     that is still inside its own Open is never quarantined by the loser of
//     the race.
//   - anything unclassified degrades. The fail-safe default is to leave the
//     disk alone.
//
// The classifier matches on message text because badger v4 wraps these failures
// with y.Wrapf, which implements no Unwrap — errors.Is against every exported
// sentinel (ErrTruncateNeeded, y.ErrChecksumMismatch, ErrEncryptionKeyMismatch)
// returns false for all of them, verified empirically. String matching is the
// only mechanism available, so it is used only to WIDEN recovery, never to
// authorise destruction on its own: the environmental deny-list is consulted
// first and the lock probe gates the rename.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// quarantineSuffix is the prefix of the timestamped name a damaged store
// directory is moved aside to. It matches the `.corrupt.<unixnano>` convention
// the CHAOS-05/07 state-file quarantine already uses, so operators learn one
// naming rule for the whole data directory.
const quarantineSuffix = ".corrupt."

// maxQuarantinedCopies bounds how many damaged copies are kept. The store can
// be gigabytes, and a host that keeps producing corruption must not fill the
// volume with evidence — the newest copy is the diagnostically useful one.
const maxQuarantinedCopies = 1

// RecoveryTrigger names what caused a recovery attempt.
type RecoveryTrigger string

const (
	// TriggerNone means the store opened normally.
	TriggerNone RecoveryTrigger = ""
	// TriggerPoisonMarker means a previous process died inside badger.Open on
	// this directory (uncatchable panic, SIGKILL, OOM, or a fatal exit).
	TriggerPoisonMarker RecoveryTrigger = "poison_marker"
	// TriggerOpenError means badger.Open returned an error identified as
	// corruption of the on-disk store.
	TriggerOpenError RecoveryTrigger = "open_error"
)

// Recovery reports what OpenResilient had to do. It is data, not logging: the
// caller owns the log line, the alert, and the metrics, so this package stays
// free of policy about how a degradation is surfaced.
type Recovery struct {
	// Trigger is what prompted the recovery attempt (TriggerNone when the
	// store opened cleanly on the first try).
	Trigger RecoveryTrigger
	// Cause is the human-readable reason behind Trigger.
	Cause string
	// Quarantined reports whether the damaged directory was moved aside.
	Quarantined bool
	// QuarantinePath is where it was moved to (empty unless Quarantined).
	QuarantinePath string
	// Skipped explains why a recovery that was triggered did NOT quarantine —
	// a live lock holder, a missing directory, or a rename that failed. Empty
	// when nothing was skipped.
	Skipped string
	// ResidualQuarantines lists `.corrupt.*` siblings present at open time,
	// including any created by this call. A non-empty list after the operator
	// has reconciled the incident is their signal to clean up.
	ResidualQuarantines []string
}

// OpenResilient opens the community store, recovering from a store the previous
// run could not survive. It never panics on behalf of badger — the panic case
// is handled by refusing to hand badger a directory a previous process died
// inside of — and it never destroys data it has not first moved aside.
//
// Returns (db, recovery, nil) on success. On failure the caller MUST degrade
// (Layer-1-only categorisation) rather than treat it as fatal: this store is a
// cache, and refusing to boot an in-line gateway over a damaged cache is a
// self-inflicted outage.
func OpenResilient(dir string) (*CommunityDB, Recovery, error) {
	var rec Recovery
	marker := markerPath(dir)

	if markerPresent(marker) {
		rec.Trigger = TriggerPoisonMarker
		rec.Cause = "a previous start entered the store open and never returned (corrupt table, kill, or out-of-memory)"
		applyQuarantine(dir, &rec)
		// Clear the marker even when the quarantine was skipped: leaving it
		// armed would re-trigger on every subsequent boot and could eventually
		// quarantine a healthy store once the real holder exits.
		_ = os.Remove(marker)
	}

	db, err := openGuarded(dir, marker)
	if err == nil {
		rec.ResidualQuarantines = QuarantinedCopies(dir)
		return db, rec, nil
	}

	// A returned error. Quarantine only for positively-identified corruption,
	// and only if this call has not already quarantined once.
	if rec.Quarantined || classifyOpenError(err) != classCorrupt {
		rec.ResidualQuarantines = QuarantinedCopies(dir)
		return nil, rec, err
	}
	rec.Trigger = TriggerOpenError
	rec.Cause = err.Error()
	// Drop any skip reason recorded by the marker phase: this attempt is a fresh
	// decision, and a stale reason would misreport a quarantine that succeeded.
	rec.Skipped = ""
	applyQuarantine(dir, &rec)
	if !rec.Quarantined {
		rec.ResidualQuarantines = QuarantinedCopies(dir)
		return nil, rec, err
	}
	// Exactly one retry — a fresh directory. No loop: if this fails the fault
	// is environmental and retrying cannot help.
	db, err = openGuarded(dir, marker)
	rec.ResidualQuarantines = QuarantinedCopies(dir)
	if err != nil {
		return nil, rec, err
	}
	return db, rec, nil
}

// applyQuarantine moves dir aside, recording the outcome on rec. It refuses
// when the directory is absent, when another process holds the store lock, or
// when the lock state cannot be determined — the fail-safe default is to leave
// the disk alone.
func applyQuarantine(dir string, rec *Recovery) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			rec.Skipped = "no store directory present"
		} else {
			rec.Skipped = "cannot stat the store directory: " + err.Error()
		}
		return
	}
	free, err := dirLockFree(dir)
	switch {
	case err != nil:
		rec.Skipped = "cannot determine whether the store is in use: " + err.Error()
		return
	case !free:
		rec.Skipped = "another process holds the store lock"
		return
	}
	qpath, err := quarantineDir(dir)
	if err != nil {
		rec.Skipped = "could not move the damaged store aside: " + err.Error()
		return
	}
	rec.Quarantined = true
	rec.QuarantinePath = qpath
}

// openGuarded arms the poison marker for the duration of one badger.Open and
// clears it whichever way the call returns. If the call does NOT return — the
// uncatchable panic — the marker survives into the next boot, which is the
// entire point.
func openGuarded(dir, marker string) (*CommunityDB, error) {
	armMarker(marker)
	db, err := Open(dir)
	_ = os.Remove(marker)
	return db, err
}

// markerPath is a SIBLING of the store directory, not a file inside it, so
// quarantining the directory never carries the marker along with it.
func markerPath(dir string) string {
	return strings.TrimSuffix(dir, string(os.PathSeparator)) + ".opening"
}

// markerPresent requires a REGULAR file. Anything else at that path (a
// directory an operator or a bad mount left behind) is ignored rather than
// treated as a poison signal: os.Remove could not clear it, so it would
// quarantine a healthy store on every boot forever.
func markerPresent(marker string) bool {
	fi, err := os.Stat(marker)
	return err == nil && fi.Mode().IsRegular()
}

// armMarker writes and fsyncs the marker, then fsyncs its parent directory, so
// the breadcrumb survives a power loss as well as a panic. Best-effort: the
// marker is a safety net, and failing to write one must not stop the store from
// opening (that would be the refuse-to-boot posture this file exists to remove).
func armMarker(marker string) {
	// badger MkdirAll's the store directory itself, but the marker is a sibling
	// and is written FIRST — without this, the very first boot on a fresh volume
	// would run unprotected.
	_ = os.MkdirAll(filepath.Dir(marker), 0o700)
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.WriteString(fmt.Sprintf("pid=%d ts=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano)))
	_ = f.Sync()
	_ = f.Close()
	if d, derr := os.Open(filepath.Dir(marker)); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// quarantineDir renames dir aside and prunes older copies down to
// maxQuarantinedCopies. The rename is within the same parent directory, so it
// is an atomic metadata operation on one filesystem — never a copy, and it
// needs no free space for the data.
func quarantineDir(dir string) (string, error) {
	base := strings.TrimSuffix(dir, string(os.PathSeparator))
	qpath := fmt.Sprintf("%s%s%d", base, quarantineSuffix, time.Now().UnixNano())
	if err := os.Rename(base, qpath); err != nil {
		return "", err
	}
	pruneQuarantines(base)
	return qpath, nil
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last.
// Exported so the caller can re-surface an unreconciled quarantine from a
// PRIOR boot: the in-memory record is process-local, so without this a
// self-healed store looks pristine on the next restart while the evidence — and
// the disk it occupies — is still sitting there.
func QuarantinedCopies(dir string) []string {
	base := strings.TrimSuffix(dir, string(os.PathSeparator))
	if base == "" {
		return nil
	}
	matches, err := filepath.Glob(base + quarantineSuffix + "*")
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches) // fixed-width unixnano suffix ⇒ lexical == chronological
	return matches
}

// pruneQuarantines keeps only the newest maxQuarantinedCopies copies.
// Best-effort: a copy that cannot be removed simply stays.
func pruneQuarantines(base string) {
	copies := QuarantinedCopies(base)
	if len(copies) <= maxQuarantinedCopies {
		return
	}
	for _, old := range copies[:len(copies)-maxQuarantinedCopies] {
		_ = os.RemoveAll(old)
	}
}

// ── Open-error classification ────────────────────────────────────────────────

type openErrClass int

const (
	// classUnknown — not recognised. Degrade; never touch the disk.
	classUnknown openErrClass = iota
	// classEnvironment — the store may be perfectly intact; the environment is
	// the problem. Quarantining would fix nothing and could destroy a live store.
	classEnvironment
	// classCorrupt — the on-disk store is damaged and will keep failing.
	classCorrupt
)

// environmentalSignals are matched FIRST. Each is a fault of the host, the
// mount, or another process — never of the store's contents.
var environmentalSignals = []string{
	"another process is using", // dir flock held: a live owner. Renaming here is destructive.
	"not a directory",          // the volume is missing or a file sits at the path
	"permission denied",
	"read-only file system",
	"no space left on device",
	"too many open files",
	"input/output error", // failing block device: the bytes may be fine once it recovers
}

// corruptionSignals are the messages badger v4 emits for a damaged store,
// captured empirically (see the CHAOS-50 review for the fault → message table).
// None of them are reachable via errors.Is: badger wraps with y.Wrapf, which
// provides no Unwrap.
var corruptionSignals = []string{
	"manifest file might be corrupted",
	"manifest has bad magic",
	"manifest has checksum mismatch",
	"checksum mismatch",
	"file does not exist for table",
	"encryption key mismatch", // KEYREGISTRY damage; this store is never opened with a key
	"log truncate required",   // badger.ErrTruncateNeeded — the option to allow it no longer exists in v4
	"invalid magic",
}

func classifyOpenError(err error) openErrClass {
	if err == nil {
		return classUnknown
	}
	// Syscall-level environmental faults, checked structurally where the error
	// chain allows it. These are cheap and exact; the text match below is the
	// fallback for the ones badger flattens into a string.
	for _, target := range []error{
		fs.ErrPermission, fs.ErrNotExist,
		syscall.EROFS, syscall.ENOSPC, syscall.ENOTDIR, syscall.EACCES,
		syscall.EAGAIN, syscall.EMFILE, syscall.ENFILE, syscall.EIO,
	} {
		if errors.Is(err, target) {
			return classEnvironment
		}
	}
	msg := strings.ToLower(err.Error())
	for _, s := range environmentalSignals {
		if strings.Contains(msg, s) {
			return classEnvironment
		}
	}
	for _, s := range corruptionSignals {
		if strings.Contains(msg, s) {
			return classCorrupt
		}
	}
	return classUnknown
}
