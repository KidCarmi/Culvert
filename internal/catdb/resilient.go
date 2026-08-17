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
// Every open attempt arms its OWN marker file beside the directory and holds an
// flock on it for the duration of the attempt. A marker whose flock can be taken
// belongs to a process that is gone — the kernel releases flocks on death — so
// it means exactly one thing: that process entered badger.Open on this directory
// and never came back out. That is the only signal available for the
// uncatchable-panic case, and it also covers a SIGKILL/OOM landing inside Open.
// On that signal the directory is quarantined BEFORE badger is allowed near it
// again, so the second boot succeeds where the first one died.
//
// The marker is per-attempt and flock-owned rather than a single shared path
// because a shared one cannot survive concurrency: a second process booting
// while the first is still inside Open would clear the first process's
// breadcrumb, and if the first then hit the panic, nothing would be left for the
// next boot to act on — the crash loop would persist through the very mechanism
// meant to break it.
//
// Quarantine is deliberately hard to trigger:
//
//   - a RETURNED error quarantines only when it is positively identified as
//     corruption. Environmental failures (another process holds the store, no
//     permission, read-only volume, no space, not a directory) degrade instead.
//     Renaming the directory would not fix any of them, and on the lock case it
//     would move a live store out from under its owner.
//   - the store's own flock is HELD ACROSS THE RENAME, not merely probed before
//     it. Probing and releasing leaves a window in which another process can
//     start its own open and have its live directory renamed underneath it —
//     rename succeeds regardless of who holds an flock.
//   - anything unclassified degrades. The fail-safe default is to leave the
//     disk alone.
//
// The classifier matches on message text because badger v4 wraps these failures
// with y.Wrapf, which implements no Unwrap — errors.Is against every exported
// sentinel (ErrTruncateNeeded, y.ErrChecksumMismatch, ErrEncryptionKeyMismatch)
// returns false for all of them, verified empirically. String matching is the
// only mechanism available, so it is used only to WIDEN recovery, never to
// authorise destruction on its own: the environmental deny-list is consulted
// first and the directory lock gates the rename.

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

// markerSuffix / markerTempSuffix name the per-attempt open markers. The temp
// form is deliberately NOT a prefix match of the final form (no dot after
// "opening"), so the sweep's glob cannot pick up a marker still being armed.
const (
	markerSuffix     = ".opening."
	markerTempSuffix = ".openingtmp."
)

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

	if poison := abandonedMarkers(dir); len(poison) > 0 {
		rec.Trigger = TriggerPoisonMarker
		rec.Cause = "a previous start entered the store open and never returned (corrupt table, kill, or out-of-memory)"
		applyQuarantine(dir, &rec)
		if rec.Quarantined {
			// Clear only markers this call acted on. A skipped quarantine
			// leaves the condition unresolved, so the breadcrumbs must survive
			// for the next boot — and markers belonging to a LIVE opener are
			// never in this list to begin with.
			for _, m := range poison {
				_ = os.Remove(m)
			}
		}
	}

	db, err := openGuarded(dir)
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
	db, err = openGuarded(dir)
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
//
// The store lock is HELD ACROSS THE RENAME. Probing it and letting go first
// would leave a window in which another process acquires badger's directory
// lock and starts opening, only to have its live directory renamed underneath
// it: rename does not consult flocks, so the probe has to remain in force until
// the move is done.
func applyQuarantine(dir string, rec *Recovery) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			rec.Skipped = "no store directory present"
		} else {
			rec.Skipped = "cannot stat the store directory: " + err.Error()
		}
		return
	}
	lock, err := lockStore(dir)
	switch {
	case err != nil:
		rec.Skipped = "cannot determine whether the store is in use: " + err.Error()
		return
	case lock == nil:
		rec.Skipped = "another process holds the store lock"
		return
	}
	defer lock.release()

	qpath, err := quarantineDir(lock, dir)
	if err != nil {
		rec.Skipped = "could not move the damaged store aside: " + err.Error()
		return
	}
	rec.Quarantined = true
	rec.QuarantinePath = qpath
}

// openGuarded arms this attempt's marker for the duration of one badger.Open
// and clears it whichever way the call returns. If the call does NOT return —
// the uncatchable panic — the marker survives into the next boot with its flock
// released by the kernel, which is the entire point.
func openGuarded(dir string) (*CommunityDB, error) {
	attempt := beginAttempt(dir)
	db, err := Open(dir)
	attempt.end()
	return db, err
}

// ── locking ──────────────────────────────────────────────────────────────────

// heldLock is an flock the caller is responsible for releasing. It is passed to
// quarantineDir so the "lock is held across the rename" invariant is carried by
// the type rather than by a comment: there is no way to reach the rename
// without producing one, and a released handle is refused.
type heldLock struct {
	f        *os.File
	released bool
}

func (h *heldLock) release() {
	if !h.held() {
		return
	}
	unlockFile(h.f)
	_ = h.f.Close()
	h.released = true
}

func (h *heldLock) held() bool { return h != nil && h.f != nil && !h.released }

// errStoreLockNotHeld guards the rename against a future refactor that probes
// the lock and lets go before moving the directory. That ordering looks
// harmless and is not: rename does not consult flocks, so the window lets
// another process acquire badger's directory lock and start opening a store
// that is about to be renamed out from under it.
var errStoreLockNotHeld = errors.New("refusing to quarantine without holding the store lock")

// lockStore takes badger's directory lock. (nil, nil) means a live process
// holds it; (nil, err) means the lock state could not be determined. Only a
// non-nil handle authorises a quarantine.
func lockStore(dir string) (*heldLock, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	locked, lerr := flockFile(f)
	if lerr != nil || !locked {
		_ = f.Close()
		return nil, lerr
	}
	return &heldLock{f: f}, nil
}

// ── open-attempt markers ─────────────────────────────────────────────────────

// openAttempt is one in-flight badger.Open, represented on disk by a marker
// file this process holds an flock on.
type openAttempt struct {
	path string
	lock *heldLock
}

// beginAttempt arms a marker for this attempt. Best-effort: the marker is a
// safety net, and failing to write one must not stop the store from opening —
// that would be the refuse-to-boot posture this file exists to remove. A
// zero-value attempt is safe to end().
//
// The marker is created under a temporary name, flocked, and only then renamed
// into place, so it can never be observed existing-but-unlocked. Without that
// ordering a concurrent boot could catch the microsecond gap between create and
// flock and mistake a live attempt for a dead one.
func beginAttempt(dir string) *openAttempt {
	base := trimSep(dir)
	if base == "" {
		return &openAttempt{}
	}
	parent := filepath.Dir(base)
	// badger MkdirAll's the store directory itself, but the marker is a sibling
	// and is written FIRST — without this, the very first boot on a fresh volume
	// would run unprotected.
	_ = os.MkdirAll(parent, 0o700)

	stamp := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	tmp := base + markerTempSuffix + stamp
	final := base + markerSuffix + stamp

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return &openAttempt{}
	}
	locked, lerr := flockFile(f)
	if lerr != nil || !locked {
		_ = f.Close()
		_ = os.Remove(tmp)
		return &openAttempt{}
	}
	_, _ = fmt.Fprintf(f, "pid=%d ts=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	_ = f.Sync()
	// rename keeps the inode, so the flock taken above stays in force.
	if err := os.Rename(tmp, final); err != nil {
		unlockFile(f)
		_ = f.Close()
		_ = os.Remove(tmp)
		return &openAttempt{}
	}
	syncDir(parent)
	return &openAttempt{path: final, lock: &heldLock{f: f}}
}

// end releases and removes this attempt's marker. It touches no other process's
// marker.
func (a *openAttempt) end() {
	if a == nil {
		return
	}
	a.lock.release()
	if a.path != "" {
		_ = os.Remove(a.path)
	}
}

// abandonedMarkers returns the markers of open attempts whose owning process is
// gone — the poison signal. A marker whose flock cannot be taken belongs to a
// LIVE opener and is never returned: clearing or acting on it would destroy the
// breadcrumb of an attempt still in progress.
//
// It also reaps temp markers left by a death during arming. Those are not a
// poison signal (the owner never reached badger.Open), just litter.
func abandonedMarkers(dir string) []string {
	base := trimSep(dir)
	if base == "" {
		return nil
	}
	var dead []string
	for _, m := range globAll(base + markerSuffix + "*") {
		if lockableRegularFile(m) {
			dead = append(dead, m)
		}
	}
	for _, tmp := range globAll(base + markerTempSuffix + "*") {
		if lockableRegularFile(tmp) {
			_ = os.Remove(tmp)
		}
	}
	sort.Strings(dead)
	return dead
}

// lockableRegularFile reports whether path is a regular file no live process
// holds an flock on. Anything else — a directory an operator or a bad mount left
// behind, an unreadable path, an undeterminable lock state — is left strictly
// alone: os.Remove could not clear a directory, so treating one as a signal
// would quarantine a healthy store on every boot forever.
func lockableRegularFile(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // read-only probe handle; close error is not actionable
	locked, lerr := flockFile(f)
	if lerr != nil || !locked {
		return false
	}
	unlockFile(f)
	return true
}

func globAll(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

func trimSep(p string) string { return strings.TrimSuffix(p, string(os.PathSeparator)) }

func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// ── quarantine ───────────────────────────────────────────────────────────────

// quarantineDir renames dir aside and prunes older copies down to
// maxQuarantinedCopies. The rename is within the same parent directory, so it
// is an atomic metadata operation on one filesystem — never a copy, and it
// needs no free space for the data.
//
// The store lock is a REQUIRED argument and must still be held: see
// errStoreLockNotHeld.
func quarantineDir(lock *heldLock, dir string) (string, error) {
	if !lock.held() {
		return "", errStoreLockNotHeld
	}
	base := trimSep(dir)
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
	base := trimSep(dir)
	if base == "" {
		return nil
	}
	matches := globAll(base + quarantineSuffix + "*")
	if len(matches) == 0 {
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
