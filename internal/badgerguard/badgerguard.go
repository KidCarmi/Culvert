package badgerguard

// badgerguard.go — surviving a Badger store the previous process could not.
//
// WHY THIS EXISTS
//
// A BadgerDB directory on the data volume is dangerous for an in-line gateway
// for two reasons that have nothing to do with the data it holds:
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
// permanent refusal to boot, or — for a store that can also be opened at
// RUNTIME — into an admin action that kills a serving gateway.
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
// again, so the second open succeeds where the first one died.
//
// The marker is per-attempt and flock-owned rather than a single shared path
// because a shared one cannot survive concurrency: a second process opening
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
//
// PROVENANCE
//
// This mechanism shipped as internal/catdb/resilient.go (CHAOS-50, review §19)
// for the Layer-2 community category store, which was then the only Badger
// store on the boot path. CHAOS-57 (§25) found the same uncatchable panic on
// the request-history store — recorded at the time as R-E, "next sweep
// candidate" — and moved the mechanism here rather than copying it, so the two
// stores cannot drift into two dialects of the same recovery. catdb keeps its
// exported API and delegates; its test suite is unchanged and is the proof the
// move was faithful.
//
// WHAT IS DELIBERATELY *NOT* SHARED
//
// The corruption signal list is per-store POLICY, not mechanism, because one
// signal means opposite things in the two stores. "encryption key mismatch" is
// KEYREGISTRY damage for a store that is never opened with a key, and is an
// ordinary recoverable ADMIN MISTAKE (passphrase changed or salt lost) for one
// that is. Quarantining on it would destroy an operator's history over a typo.
// Callers therefore pass a Policy, and the divergence is explicit and testable
// rather than buried in a shared constant.

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
// naming rule for the whole data directory. Exported because it is an on-disk
// contract an operator reads and a runbook names, not an implementation detail.
const QuarantineSuffix = ".corrupt."

// MarkerSuffix / MarkerTempSuffix name the per-attempt open markers. The temp
// form is deliberately NOT a prefix match of the final form (no dot after
// "opening"), so the sweep's glob cannot pick up a marker still being armed.
const (
	MarkerSuffix     = ".opening."
	MarkerTempSuffix = ".openingtmp."
)

// MaxQuarantinedCopies bounds how many damaged copies are kept. A store can be
// gigabytes, and a host that keeps producing corruption must not fill the
// volume with evidence — the newest copy is the diagnostically useful one.
const MaxQuarantinedCopies = 1

// Trigger names what caused a recovery attempt.
type Trigger string

const (
	// TriggerNone means the store opened normally.
	TriggerNone Trigger = ""
	// TriggerPoisonMarker means a previous process died inside badger.Open on
	// this directory (uncatchable panic, SIGKILL, OOM, or a fatal exit).
	TriggerPoisonMarker Trigger = "poison_marker"
	// TriggerOpenError means badger.Open returned an error identified as
	// corruption of the on-disk store.
	TriggerOpenError Trigger = "open_error"
)

// Recovery reports what Open had to do. It is data, not logging: the caller
// owns the log line, the alert, the audit event and the metrics, so this
// package stays free of policy about how a degradation is surfaced.
type Recovery struct {
	// Trigger is what prompted the recovery attempt (TriggerNone when the
	// store opened cleanly on the first try).
	Trigger Trigger
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

// Recovered reports whether this open had to move a damaged store aside.
func (r Recovery) Recovered() bool { return r.Quarantined }

// ── policy ───────────────────────────────────────────────────────────────────

// Policy is the per-store half of the decision: which returned errors count as
// "the bytes on disk are damaged". The mechanism (markers, locking, rename) is
// identical for every store; this is not, because the same badger message can
// mean damage in one store and a recoverable operator mistake in another.
type Policy struct {
	// Environmental are matched FIRST. Each is a fault of the host, the mount,
	// or another process — never of the store's contents.
	Environmental []string
	// Corruption are the messages that positively identify a damaged store.
	Corruption []string
}

// EnvironmentalSignals is the shared deny-list. It is consulted before the
// corruption list for every store: none of these are fixed by a rename, and on
// the lock case a rename would move a LIVE store out from under its owner.
func EnvironmentalSignals() []string {
	return []string{
		"another process is using", // dir flock held: a live owner. Renaming here is destructive.
		"not a directory",          // the volume is missing or a file sits at the path
		"permission denied",
		"read-only file system",
		"no space left on device",
		"too many open files",
		"input/output error", // failing block device: the bytes may be fine once it recovers
	}
}

// CorruptionSignals is the full set of messages badger v4 emits for a damaged
// store, captured empirically (see review §19 for the fault → message table).
// None of them are reachable via errors.Is: badger wraps with y.Wrapf, which
// provides no Unwrap.
//
// A store opened WITH an encryption key must remove "encryption key mismatch"
// via Policy.Without — for such a store that message is a changed passphrase or
// a lost salt, which is an admin mistake with a documented remedy, not damage.
func CorruptionSignals() []string {
	return []string{
		"manifest file might be corrupted",
		"manifest has bad magic",
		"manifest has checksum mismatch",
		"checksum mismatch",
		"file does not exist for table",
		"encryption key mismatch", // KEYREGISTRY damage — only for a store opened WITHOUT a key
		"log truncate required",   // badger.ErrTruncateNeeded — the option to allow it no longer exists in v4
		"invalid magic",
	}
}

// DefaultPolicy is the posture for a store opened WITHOUT an encryption key.
func DefaultPolicy() Policy {
	return Policy{Environmental: EnvironmentalSignals(), Corruption: CorruptionSignals()}
}

// Without returns a copy of p with the named corruption signals removed. It is
// the ONLY supported way to narrow the corruption list, so a divergence between
// two stores is a visible call at the call site rather than a forked constant.
// Removing a signal can only ever make quarantine LESS likely, which is the
// fail-safe direction.
func (p Policy) Without(signals ...string) Policy {
	drop := make(map[string]struct{}, len(signals))
	for _, s := range signals {
		drop[strings.ToLower(s)] = struct{}{}
	}
	out := Policy{Environmental: append([]string(nil), p.Environmental...)}
	for _, s := range p.Corruption {
		if _, skip := drop[strings.ToLower(s)]; skip {
			continue
		}
		out.Corruption = append(out.Corruption, s)
	}
	return out
}

// ── open ─────────────────────────────────────────────────────────────────────

// Open opens a Badger-backed store through the guard, recovering from a store
// the previous run could not survive. It never panics on behalf of badger —
// the panic case is handled by refusing to hand badger a directory a previous
// process died inside of — and it never destroys data it has not first moved
// aside.
//
// open is the caller's real constructor and is invoked at most twice: once
// normally, and once more only after a successful quarantine has replaced the
// directory with a clean one.
//
// Returns (store, recovery, nil) on success. On failure the caller MUST decide
// how to degrade; this package never exits the process.
func Open[T any](dir string, p Policy, open func(string) (T, error)) (T, Recovery, error) {
	var zero T
	var rec Recovery

	if poison := AbandonedMarkers(dir); len(poison) > 0 {
		rec.Trigger = TriggerPoisonMarker
		rec.Cause = "a previous open entered the store and never returned (corrupt table, kill, or out-of-memory)"
		skip := applyQuarantine(dir, &rec)
		// Retire the markers this call has settled. A marker must not outlive
		// the incident it describes, and there are exactly two ways it is
		// settled: the damaged store was moved aside, or there was NO store to
		// move aside.
		//
		// The second case is not a formality. A process killed after
		// BeginAttempt but BEFORE badger created the directory leaves a marker
		// describing a store that never existed. Keeping it — which is what
		// gating solely on Quarantined did — lets the very next open create a
		// healthy store beside the stale marker, and the open AFTER that
		// quarantines that healthy store and resets its history. So the
		// no-store skip has to clear, or the mechanism manufactures the data
		// loss it exists to prevent.
		//
		// skipBlocked still keeps them: a live lock holder, an unreadable path
		// or a failed rename all leave the condition genuinely unresolved, so
		// the breadcrumbs must survive for the next attempt. (Markers belonging
		// to a LIVE opener are never in this list to begin with.)
		if rec.Quarantined || skip == skipNoStore {
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
	if rec.Quarantined || Classify(err, p) != ClassCorrupt {
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

// quarantineSkip classifies WHY a quarantine did not happen, so the caller can
// tell "there was nothing to quarantine" from "something was in the way". The
// two demand opposite handling of the poison markers, and collapsing them into
// the single Skipped string was the bug described in Open.
type quarantineSkip int

const (
	// skipNone — the quarantine happened.
	skipNone quarantineSkip = iota
	// skipNoStore — there is no store directory. Nothing was ever created
	// here, so nothing can be damaged and nothing needs preserving.
	skipNoStore
	// skipBlocked — a live lock holder, an unreadable path, or a failed
	// rename. The condition is unresolved and the evidence must survive.
	skipBlocked
)

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
func ApplyQuarantine(dir string, rec *Recovery) { _ = applyQuarantine(dir, rec) }

// applyQuarantine is ApplyQuarantine plus the skip classification Open needs.
func applyQuarantine(dir string, rec *Recovery) quarantineSkip {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			rec.Skipped = "no store directory present"
			return skipNoStore
		}
		rec.Skipped = "cannot stat the store directory: " + err.Error()
		return skipBlocked
	}
	lock, err := LockStore(dir)
	switch {
	case err != nil:
		rec.Skipped = "cannot determine whether the store is in use: " + err.Error()
		return skipBlocked
	case lock == nil:
		rec.Skipped = "another process holds the store lock"
		return skipBlocked
	}
	defer lock.Release()

	qpath, err := QuarantineDir(lock, dir)
	if err != nil {
		rec.Skipped = "could not move the damaged store aside: " + err.Error()
		return skipBlocked
	}
	rec.Quarantined = true
	rec.QuarantinePath = qpath
	return skipNone
}

// openGuarded arms this attempt's marker for the duration of one badger.Open
// and clears it whichever way the call returns. If the call does NOT return —
// the uncatchable panic — the marker survives into the next attempt with its
// flock released by the kernel, which is the entire point.
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

// Release drops the flock and closes the handle. Idempotent, and safe on a nil
// receiver so callers can defer it unconditionally. Once released the handle is
// permanently unusable for a quarantine — see ErrStoreLockNotHeld.
func (h *HeldLock) Release() {
	if !h.Held() {
		return
	}
	unlockFile(h.f)
	_ = h.f.Close()
	h.released = true
}

// Held reports whether this handle still holds the lock. It is what
// QuarantineDir checks, so it is the enforcement point for "the store lock is
// held ACROSS the rename" rather than merely probed before it.
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
type OpenAttempt struct {
	path string
	lock *HeldLock
}

// BeginAttempt arms a marker for this attempt. Best-effort: the marker is a
// safety net, and failing to write one must not stop the store from opening —
// that would be the refuse-to-open posture this file exists to remove. A
// zero-value attempt is safe to End().
//
// The marker is created under a temporary name, flocked, and only then renamed
// into place, so it can never be observed existing-but-unlocked. Without that
// ordering a concurrent open could catch the microsecond gap between create and
// flock and mistake a live attempt for a dead one.
func BeginAttempt(dir string) *OpenAttempt {
	base := StoreBase(dir)
	if base == "" {
		return &OpenAttempt{}
	}
	parent := filepath.Dir(base)
	// badger MkdirAll's the store directory itself, but the marker is a sibling
	// and is written FIRST — without this, the very first open on a fresh volume
	// would run unprotected.
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
	return &OpenAttempt{path: final, lock: &HeldLock{f: f}}
}

// End removes this attempt's marker and then releases its lock, in that order.
// Releasing first would leave a window in which our own still-present marker
// reads as abandoned to a concurrent opener. (The store lock would still veto
// its quarantine, so the window was never destructive — but a primitive that is
// only safe because a second one catches it is one refactor away from not being
// safe at all.) It touches no other process's marker.
func (a *OpenAttempt) End() {
	if a == nil {
		return
	}
	if a.path != "" {
		_ = os.Remove(a.path)
	}
	a.lock.Release()
}

// MarkerPath is the on-disk marker representing this attempt, or "" when the
// attempt could not be armed (best-effort: a marker that cannot be written must
// never stop the store from opening). Read-only; the gates assert on its
// placement, which is part of the contract — the marker is a SIBLING of the
// store directory, never a child, because a child would be renamed away with
// the store it is meant to describe.
func (a *OpenAttempt) MarkerPath() string {
	if a == nil {
		return ""
	}
	return a.path
}

// ReleaseLock drops this attempt's flock WITHOUT removing its marker,
// simulating a process that died inside badger.Open: the kernel releases the
// lock, the breadcrumb stays. It exists for the gates that have to produce the
// poison signal without actually killing a process, and has no production
// caller — End is the only way an attempt is retired normally.
func (a *OpenAttempt) ReleaseLock() {
	if a == nil {
		return
	}
	a.lock.Release()
}

// AbandonedMarkers returns the markers of open attempts whose owning process is
// gone — the poison signal. A marker whose flock cannot be taken belongs to a
// LIVE opener and is never returned: clearing or acting on it would destroy the
// breadcrumb of an attempt still in progress.
//
// It also reaps temp markers left by a death during arming. Those are not a
// poison signal (the owner never reached badger.Open), just litter.
func AbandonedMarkers(dir string) []string {
	base := StoreBase(dir)
	if base == "" {
		return nil
	}
	var dead []string
	for _, m := range globAll(base + MarkerSuffix + "*") {
		if lockableRegularFile(m) {
			dead = append(dead, m)
		}
	}
	for _, tmp := range globAll(base + MarkerTempSuffix + "*") {
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
// would quarantine a healthy store on every open forever.
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

// StoreBase is the path every sidecar artifact of a store hangs off: the store
// directory with any trailing separator removed. Markers and quarantined copies
// are SIBLINGS of the store, so a caller that passes "dir/" and one that passes
// "dir" must land on the same names.
func StoreBase(p string) string { return strings.TrimSuffix(p, string(os.PathSeparator)) }

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
	base := StoreBase(dir)
	qpath := fmt.Sprintf("%s%s%d", base, QuarantineSuffix, time.Now().UnixNano())
	if err := os.Rename(base, qpath); err != nil {
		return "", err
	}
	pruneQuarantines(base)
	return qpath, nil
}

// QuarantinedCopies returns the `.corrupt.*` siblings of dir, newest last.
// Exported so the caller can re-surface an unreconciled quarantine from a
// PRIOR run: the in-memory record is process-local, so without this a
// self-healed store looks pristine on the next restart while the evidence — and
// the disk it occupies — is still sitting there.
func QuarantinedCopies(dir string) []string {
	base := StoreBase(dir)
	if base == "" {
		return nil
	}
	matches := globAll(base + QuarantineSuffix + "*")
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

// ErrClass is the verdict on a returned open error.
type ErrClass int

const (
	// ClassUnknown — not recognised. Degrade; never touch the disk.
	ClassUnknown ErrClass = iota
	// ClassEnvironment — the store may be perfectly intact; the environment is
	// the problem. Quarantining would fix nothing and could destroy a live store.
	ClassEnvironment
	// ClassCorrupt — the on-disk store is damaged and will keep failing.
	ClassCorrupt
)

// Classify decides whether a returned open error authorises a quarantine, under
// the caller's Policy. Environmental signals are matched FIRST so a store that
// merely cannot be reached is never moved aside.
func Classify(err error, p Policy) ErrClass {
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
	for _, s := range p.Environmental {
		if strings.Contains(msg, strings.ToLower(s)) {
			return ClassEnvironment
		}
	}
	for _, s := range p.Corruption {
		if strings.Contains(msg, strings.ToLower(s)) {
			return ClassCorrupt
		}
	}
	return ClassUnknown
}
