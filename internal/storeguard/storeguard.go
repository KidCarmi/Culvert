// Package storeguard is the store-agnostic engine for surviving a corrupt
// BadgerDB directory on a path that must not be allowed to kill the process.
//
// # WHY THIS EXISTS
//
// Culvert opens more than one BadgerDB directory on the data volume, and every
// one of them shares two properties that make the combination dangerous for an
// in-line gateway:
//
//  1. badger.Open does not always return an error. A corrupted `.sst` table
//     makes it PANIC from a goroutine badger itself spawns
//     (table.OpenTable ← newLevelsController), so no recover() at any call site
//     can contain it — the process dies. Verified empirically against
//     badger v4.9.6 for BOTH stores' option sets (see
//     `roadmap/CHAOS-ENGINEERING-REVIEW.md` §19.3 and §25.2).
//  2. Every other open failure it DOES return (torn MANIFEST, bad magic,
//     missing table, KEYREGISTRY damage) is unrecoverable by retrying: the
//     directory stays broken across restarts.
//
// Left alone, either one turns "one unclean kill of the container" into a
// permanent refusal to run. The CHAOS-05/07 contract established the right rule
// for corrupt state on the boot path — quarantine the evidence, do not
// overwrite it, and keep going — and this package carries that rule for any
// store whose failure mode badger will not let us catch.
//
// This code shipped first as `internal/catdb/resilient.go` (CHAOS-50) for the
// Layer-2 community category store. CHAOS-57 extracted it here unchanged so the
// request-history store (`internal/logstore`) could reuse it. The alternative —
// a second copy — would have duplicated the empirically-derived badger message
// table, which is exactly the artefact that must never drift: it is pinned by a
// test precisely so that a badger upgrade which rewords a message fails the
// build instead of silently switching recovery off.
//
// # HOW
//
// Every open attempt arms its OWN marker file beside the directory and holds an
// flock on it for the duration of the attempt. A marker whose flock can be taken
// belongs to a process that is gone — the kernel releases flocks on death — so
// it means exactly one thing: that process entered badger.Open on this directory
// and never came back out. That is the only signal available for the
// uncatchable-panic case, and it also covers a SIGKILL/OOM landing inside Open.
// On that signal the directory is quarantined BEFORE badger is allowed near it
// again, so the second start succeeds where the first one died.
//
// The marker is per-attempt and flock-owned rather than a single shared path
// because a shared one cannot survive concurrency: a second process starting
// while the first is still inside Open would clear the first process's
// breadcrumb, and if the first then hit the panic, nothing would be left for the
// next start to act on — the crash loop would persist through the very mechanism
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
//
// # WHAT IS PER-STORE
//
// Only the Policy. The shared corruption table is derived from what badger
// says, but what a given MESSAGE means depends on how the store is opened —
// see Policy for the case that forced this to be a parameter rather than a
// constant.
package storeguard

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

// QuarantineSuffix is the prefix of the timestamped name a damaged store
// directory is moved aside to. It matches the `.corrupt.<unixnano>` convention
// the CHAOS-05/07 state-file quarantine already uses, so operators learn one
// naming rule for the whole data directory.
const QuarantineSuffix = ".corrupt."

// MarkerSuffix / MarkerTempSuffix name the per-attempt open markers. The temp
// form is deliberately NOT a prefix match of the final form (no dot after
// "opening"), so the sweep cannot pick up a marker still being armed.
const (
	MarkerSuffix     = ".opening."
	MarkerTempSuffix = ".openingtmp."
)

// MaxQuarantinedCopies bounds how many damaged copies are kept. A store can be
// gigabytes, and a host that keeps producing corruption must not fill the
// volume with evidence — the newest copy is the diagnostically useful one.
const MaxQuarantinedCopies = 1

// Policy is the per-store part of the decision. Everything else in this package
// is store-agnostic.
//
// It exists because of one empirically-established divergence. badger reports
// KEYREGISTRY damage as "Encryption key mismatch", and for a store that is
// NEVER opened with an encryption key that message can only mean corruption —
// which is why the shared table lists it. For a store that IS opened with a key
// the same message additionally covers two conditions that are not corruption
// at all and whose data is perfectly intact: the operator changed the
// passphrase, or the key-derivation salt sidecar was lost. Measured on
// badger v4.9.6, all three produce an indistinguishable error (CHAOS-57; see
// `roadmap/CHAOS-ENGINEERING-REVIEW.md` §25.2). Quarantining on it would move a
// healthy store aside over an ordinary configuration change.
//
// So the rule a store may override is narrow and one-directional: a Policy can
// only ever make the guard LESS willing to touch the disk, never more. There is
// deliberately no field for adding corruption signals — widening destruction
// from a call site is how a shared safety mechanism becomes an unsafe one.
type Policy struct {
	// NeverCorrupt are errors.Is targets this store refuses to classify as
	// corruption. Structural and therefore exact — preferred over text.
	NeverCorrupt []error
	// NeverCorruptText are lowercase message fragments this store refuses to
	// classify as corruption. The text-level backstop for a condition whose
	// error does not survive as a comparable sentinel.
	NeverCorruptText []string
}

// neverCorrupt reports whether p exempts err from the corruption table.
func (p Policy) neverCorrupt(err error) bool {
	for _, target := range p.NeverCorrupt {
		if target != nil && errors.Is(err, target) {
			return true
		}
	}
	if len(p.NeverCorruptText) == 0 {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range p.NeverCorruptText {
		if s != "" && strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

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

// Recovery reports what Open had to do. It is data, not logging: the caller
// owns the log line, the alert, and the metrics, so this package stays free of
// policy about how a degradation is surfaced.
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

// Open opens a store through open, recovering from a directory the previous run
// could not survive. It never panics on behalf of badger — the panic case is
// handled by refusing to hand badger a directory a previous process died inside
// of — and it never destroys data it has not first moved aside.
//
// Returns (store, recovery, nil) on success. On failure the caller MUST decide
// how to degrade; this package never exits. For every store wired to it so far
// the answer has been the same: run without it, because refusing to run an
// in-line gateway over a damaged local store is a self-inflicted outage.
func Open[T any](dir string, policy Policy, open func(string) (T, error)) (T, Recovery, error) {
	var zero T
	var rec Recovery

	if poison := AbandonedMarkers(dir); len(poison) > 0 {
		rec.Trigger = TriggerPoisonMarker
		rec.Cause = "a previous start entered the store open and never returned (corrupt table, kill, or out-of-memory)"
		ApplyQuarantine(dir, &rec)
		if rec.Quarantined {
			// Clear only markers this call acted on. A skipped quarantine
			// leaves the condition unresolved, so the breadcrumbs must survive
			// for the next start — and markers belonging to a LIVE opener are
			// never in this list to begin with.
			for _, m := range poison {
				_ = os.Remove(m)
			}
		}
	}

	store, err := openGuarded(dir, open)
	if err == nil {
		rec.ResidualQuarantines = QuarantinedCopies(dir)
		return store, rec, nil
	}

	// A returned error. Quarantine only for positively-identified corruption,
	// and only if this call has not already quarantined once.
	if rec.Quarantined || ClassifyOpenError(err, policy) != ClassCorrupt {
		rec.ResidualQuarantines = QuarantinedCopies(dir)
		return zero, rec, err
	}
	rec.Trigger = TriggerOpenError
	rec.Cause = err.Error()
	// Drop any skip reason recorded by the marker phase: this attempt is a fresh
	// decision, and a stale reason would misreport a quarantine that succeeded.
	rec.Skipped = ""
	ApplyQuarantine(dir, &rec)
	if !rec.Quarantined {
		rec.ResidualQuarantines = QuarantinedCopies(dir)
		return zero, rec, err
	}
	// Exactly one retry — a fresh directory. No loop: if this fails the fault
	// is environmental and retrying cannot help.
	store, err = openGuarded(dir, open)
	rec.ResidualQuarantines = QuarantinedCopies(dir)
	if err != nil {
		return zero, rec, err
	}
	return store, rec, nil
}

// ApplyQuarantine moves dir aside, recording the outcome on rec. It refuses
// when the directory is absent, when another process holds the store lock, or
// when the lock state cannot be determined — the fail-safe default is to leave
// the disk alone.
//
// The store lock is HELD ACROSS THE RENAME. Probing it and letting go first
// would leave a window in which another process acquires badger's directory
// lock and starts opening, only to have its live directory renamed underneath
// it: rename does not consult flocks, so the probe has to remain in force until
// the move is done.
func ApplyQuarantine(dir string, rec *Recovery) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			rec.Skipped = "no store directory present"
		} else {
			rec.Skipped = "cannot stat the store directory: " + err.Error()
		}
		return
	}
	lock, err := LockStore(dir)
	switch {
	case err != nil:
		rec.Skipped = "cannot determine whether the store is in use: " + err.Error()
		return
	case lock == nil:
		rec.Skipped = "another process holds the store lock"
		return
	}
	defer lock.Release()

	qpath, err := QuarantineDir(lock, dir)
	if err != nil {
		rec.Skipped = "could not move the damaged store aside: " + err.Error()
		return
	}
	rec.Quarantined = true
	rec.QuarantinePath = qpath
}

// openGuarded arms this attempt's marker for the duration of one open call and
// clears it whichever way the call returns. If the call does NOT return — the
// uncatchable panic — the marker survives into the next start with its flock
// released by the kernel, which is the entire point.
func openGuarded[T any](dir string, open func(string) (T, error)) (T, error) {
	attempt := BeginAttempt(dir)
	store, err := open(dir)
	attempt.End()
	return store, err
}

// ── locking ──────────────────────────────────────────────────────────────────

// HeldLock is an flock the caller is responsible for releasing. It is passed to
// QuarantineDir so the "lock is held across the rename" invariant is carried by
// the type rather than by a comment: there is no way to reach the rename
// without producing one, and a released handle is refused.
type HeldLock struct {
	f        *os.File
	released bool
}

// Release drops the flock and closes the handle. Safe to call more than once.
func (h *HeldLock) Release() {
	if !h.Held() {
		return
	}
	unlockFile(h.f)
	_ = h.f.Close()
	h.released = true
}

// Held reports whether this handle still holds its flock.
func (h *HeldLock) Held() bool { return h != nil && h.f != nil && !h.released }

// ErrStoreLockNotHeld guards the rename against a future refactor that probes
// the lock and lets go before moving the directory. That ordering looks
// harmless and is not: rename does not consult flocks, so the window lets
// another process acquire badger's directory lock and start opening a store
// that is about to be renamed out from under it.
var ErrStoreLockNotHeld = errors.New("refusing to quarantine without holding the store lock")

// LockStore takes badger's directory lock. (nil, nil) means a live process
// holds it; (nil, err) means the lock state could not be determined. Only a
// non-nil handle authorises a quarantine.
func LockStore(dir string) (*HeldLock, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	locked, lerr := flockFile(f)
	if lerr != nil || !locked {
		_ = f.Close()
		return nil, lerr
	}
	return &HeldLock{f: f}, nil
}

// ── open-attempt markers ─────────────────────────────────────────────────────

// OpenAttempt is one in-flight badger.Open, represented on disk by a marker
// file this process holds an flock on.
//
// Both fields are exported because they are the attempt's observable state, not
// bookkeeping: Path is the breadcrumb a later start reads, and Lock is what
// distinguishes a live attempt from a dead one. Releasing Lock while leaving
// Path in place is precisely what the kernel does when a process dies inside
// badger.Open, which is the condition this whole package exists to detect.
type OpenAttempt struct {
	// Path is the marker file armed for this attempt, or "" when arming failed
	// (best-effort — a marker that cannot be written must not stop the open).
	Path string
	// Lock is the flock held for the attempt's duration; nil when arming failed.
	Lock *HeldLock
}

// BeginAttempt arms a marker for this attempt. Best-effort: the marker is a
// safety net, and failing to write one must not stop the store from opening —
// that would be the refuse-to-run posture this package exists to remove. A
// zero-value attempt is safe to End().
//
// The marker is created under a temporary name, flocked, and only then renamed
// into place, so it can never be observed existing-but-unlocked. Without that
// ordering a concurrent start could catch the microsecond gap between create and
// flock and mistake a live attempt for a dead one.
func BeginAttempt(dir string) *OpenAttempt {
	base := trimSep(dir)
	if base == "" {
		return &OpenAttempt{}
	}
	parent := filepath.Dir(base)
	// badger MkdirAll's the store directory itself, but the marker is a sibling
	// and is written FIRST — without this, the very first start on a fresh
	// volume would run unprotected.
	_ = os.MkdirAll(parent, 0o700)

	stamp := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	tmp := base + MarkerTempSuffix + stamp
	final := base + MarkerSuffix + stamp

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return &OpenAttempt{}
	}
	locked, lerr := flockFile(f)
	if lerr != nil || !locked {
		_ = f.Close()
		_ = os.Remove(tmp)
		return &OpenAttempt{}
	}
	_, _ = fmt.Fprintf(f, "pid=%d ts=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	_ = f.Sync()
	// rename keeps the inode, so the flock taken above stays in force.
	if err := os.Rename(tmp, final); err != nil {
		unlockFile(f)
		_ = f.Close()
		_ = os.Remove(tmp)
		return &OpenAttempt{}
	}
	syncDir(parent)
	return &OpenAttempt{Path: final, Lock: &HeldLock{f: f}}
}

// End removes this attempt's marker and then releases its lock, in that order.
// Releasing first would leave a window in which our own still-present marker
// reads as abandoned to a concurrently starting process. (The store lock would
// still veto its quarantine, so the window was never destructive — but a
// primitive that is only safe because a second one catches it is one refactor
// away from not being safe at all.) It touches no other process's marker.
func (a *OpenAttempt) End() {
	if a == nil {
		return
	}
	if a.Path != "" {
		_ = os.Remove(a.Path)
	}
	a.Lock.Release()
}

// AbandonedMarkers returns the markers of open attempts whose owning process is
// gone — the poison signal. A marker whose flock cannot be taken belongs to a
// LIVE opener and is never returned: clearing or acting on it would destroy the
// breadcrumb of an attempt still in progress.
//
// It also reaps temp markers left by a death during arming. Those are not a
// poison signal (the owner never reached badger.Open), just litter.
func AbandonedMarkers(dir string) []string {
	base := trimSep(dir)
	if base == "" {
		return nil
	}
	var dead []string
	for _, m := range siblings(base, MarkerSuffix) {
		if lockableRegularFile(m) {
			dead = append(dead, m)
		}
	}
	for _, tmp := range siblings(base, MarkerTempSuffix) {
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
// would quarantine a healthy store on every start forever.
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

// siblings returns every entry beside base whose name starts with
// filepath.Base(base)+suffix, newest-last by name.
//
// This deliberately does NOT use filepath.Glob. A store path is operator-
// configurable, and a glob metacharacter in it silently breaks the mechanism in
// BOTH directions — measured, not theorised:
//
//   - `/data/hist[1]` — `Glob("/data/hist[1].opening.*")` reads `[1]` as a
//     character class and looks for `/data/hist1.opening.*`, so the store's OWN
//     abandoned marker is never found. The poison signal is missed, badger is
//     handed the corrupt directory again, and the crash loop persists through
//     the very mechanism meant to break it.
//   - `/data/hist?` — matches a NEIGHBOURING store's marker, so a healthy store
//     is quarantined on someone else's evidence.
//
// Escaping the metacharacters would fix the first case but is platform-specific
// (backslash escaping does not work in Go's glob on Windows). A prefix match
// over the parent directory has no pattern semantics at all, so the class is
// gone rather than patched.
func siblings(base, suffix string) []string {
	dir := filepath.Dir(base)
	prefix := filepath.Base(base) + suffix
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), prefix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
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

// QuarantineDir renames dir aside and prunes older copies down to
// MaxQuarantinedCopies. The rename is within the same parent directory, so it
// is an atomic metadata operation on one filesystem — never a copy, and it
// needs no free space for the data.
//
// The store lock is a REQUIRED argument and must still be held: see
// ErrStoreLockNotHeld.
func QuarantineDir(lock *HeldLock, dir string) (string, error) {
	if !lock.Held() {
		return "", ErrStoreLockNotHeld
	}
	base := trimSep(dir)
	qpath := fmt.Sprintf("%s%s%d", base, QuarantineSuffix, time.Now().UnixNano())
	if err := os.Rename(base, qpath); err != nil {
		return "", err
	}
	pruneQuarantines(base)
	return qpath, nil
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last.
// Exported so the caller can re-surface an unreconciled quarantine from a
// PRIOR start: the in-memory record is process-local, so without this a
// self-healed store looks pristine on the next restart while the evidence — and
// the disk it occupies — is still sitting there.
func QuarantinedCopies(dir string) []string {
	base := trimSep(dir)
	if base == "" {
		return nil
	}
	matches := siblings(base, QuarantineSuffix)
	if len(matches) == 0 {
		return nil
	}
	sort.Strings(matches) // fixed-width unixnano suffix ⇒ lexical == chronological
	return matches
}

// pruneQuarantines keeps only the newest MaxQuarantinedCopies copies.
// Best-effort: a copy that cannot be removed simply stays.
func pruneQuarantines(base string) {
	copies := QuarantinedCopies(base)
	if len(copies) <= MaxQuarantinedCopies {
		return
	}
	for _, old := range copies[:len(copies)-MaxQuarantinedCopies] {
		_ = os.RemoveAll(old)
	}
}

// ── Open-error classification ────────────────────────────────────────────────

// OpenErrClass is the verdict on a returned open error.
type OpenErrClass int

const (
	// ClassUnknown — not recognised. Degrade; never touch the disk.
	ClassUnknown OpenErrClass = iota
	// ClassEnvironment — the store may be perfectly intact; the environment is
	// the problem. Quarantining would fix nothing and could destroy a live store.
	ClassEnvironment
	// ClassCorrupt — the on-disk store is damaged and will keep failing.
	ClassCorrupt
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
//
// "encryption key mismatch" is in this list because for a store opened WITHOUT
// an encryption key it can only mean KEYREGISTRY damage. A store opened WITH one
// must exempt it via Policy.NeverCorruptText — see Policy.
var corruptionSignals = []string{
	"manifest file might be corrupted",
	"manifest has bad magic",
	"manifest has checksum mismatch",
	"checksum mismatch",
	"file does not exist for table",
	"encryption key mismatch", // KEYREGISTRY damage — see Policy for the keyed-store caveat
	"log truncate required",   // badger.ErrTruncateNeeded — the option to allow it no longer exists in v4
	"invalid magic",
}

// ClassifyOpenError decides what a returned open error means for this store.
//
// Order is load-bearing: environmental first (a fault renaming cannot fix and
// where renaming could destroy a live store), then the policy's exemptions,
// then corruption, then degrade.
func ClassifyOpenError(err error, policy Policy) OpenErrClass {
	if err == nil {
		return ClassUnknown
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
			return ClassEnvironment
		}
	}
	msg := strings.ToLower(err.Error())
	for _, s := range environmentalSignals {
		if strings.Contains(msg, s) {
			return ClassEnvironment
		}
	}
	// The store's own exemptions are consulted BEFORE the corruption table, so a
	// policy can only ever hold the guard back from touching the disk.
	if policy.neverCorrupt(err) {
		return ClassUnknown
	}
	for _, s := range corruptionSignals {
		if strings.Contains(msg, s) {
			return ClassCorrupt
		}
	}
	return ClassUnknown
}
