package badgerguard

// badgerguard_test.go — CHAOS-57 gates for the shared store guard.
//
// The mechanism's END-TO-END behaviour against real badger stores is proven by
// internal/catdb's suite (which predates this package and runs unchanged across
// the move — that is the evidence the extraction was faithful) and by
// internal/logstore's. What is proven HERE is what neither of those can say:
//
//   - the guard is genuinely store-AGNOSTIC. It is exercised with a fake open
//     func, so a future third store can adopt it without a fourth dialect.
//   - Policy composition. Without() is the ONLY sanctioned way for one store to
//     diverge from another's corruption posture, and it must narrow in the
//     fail-safe direction only.
//   - the ordering rules that are easy to "simplify" away: the poison marker is
//     acted on BEFORE the open, and the quarantine refuses a released lock.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fakeStore stands in for a *badger.DB. Using a type with no badger in it is
// the point: the guard must not know or care what it is opening.
type fakeStore struct{ dir string }

// newDirStore is an "open" that behaves like badger in the ways that matter: it
// creates the directory if absent, and fails if a non-directory is in the way.
func newDirStore(dir string) (*fakeStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &fakeStore{dir: dir}, nil
}

func tempStore(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "store")
}

// ── the guard is store-agnostic ──────────────────────────────────────────────

func TestOpen_CleanOpenLeavesNoTrace(t *testing.T) {
	dir := tempStore(t)
	s, rec, err := Open(dir, DefaultPolicy(), newDirStore)
	if err != nil || s == nil {
		t.Fatalf("Open = (%v, %v), want a store", s, err)
	}
	if rec.Trigger != TriggerNone || rec.Quarantined || rec.Recovered() {
		t.Errorf("a healthy open reported a recovery: %+v", rec)
	}
	if m, _ := filepath.Glob(StoreBase(dir) + MarkerSuffix + "*"); len(m) != 0 {
		t.Errorf("open markers left behind: %v", m)
	}
	if len(QuarantinedCopies(dir)) != 0 {
		t.Error("a healthy open produced a quarantined copy")
	}
}

// The marker must be armed for the DURATION of the open, so a process that dies
// inside it leaves the breadcrumb. Observing it from within the open func is the
// only way to prove the arming is not, say, done after the call returns.
func TestOpen_MarkerIsArmedDuringTheOpenAndIsASibling(t *testing.T) {
	dir := tempStore(t)
	var seen []string
	_, _, err := Open(dir, DefaultPolicy(), func(d string) (*fakeStore, error) {
		seen, _ = filepath.Glob(StoreBase(dir) + MarkerSuffix + "*")
		return newDirStore(d)
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("markers visible during the open = %v, want exactly 1 — a death inside the open would leave no breadcrumb", seen)
	}
	// A marker INSIDE the store directory would be renamed away together with
	// the store it is meant to describe, so it must be a sibling.
	if filepath.Dir(seen[0]) != filepath.Dir(StoreBase(dir)) {
		t.Errorf("marker %q is not a sibling of the store directory", seen[0])
	}
}

// The whole point of the mechanism: a marker with no live owner means a
// previous process entered the open and never returned, so the directory is
// moved aside BEFORE the open func is called again — not after it fails,
// because the failure mode being recovered from is one that never returns.
func TestOpen_PoisonMarkerQuarantinesBeforeCallingOpen(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	marker := StoreBase(dir) + MarkerSuffix + "999-1"
	if err := os.WriteFile(marker, []byte("pid=999\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}

	quarantinedWhenOpened := false
	_, rec, err := Open(dir, DefaultPolicy(), func(d string) (*fakeStore, error) {
		quarantinedWhenOpened = len(QuarantinedCopies(dir)) == 1
		return newDirStore(d)
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if rec.Trigger != TriggerPoisonMarker || !rec.Quarantined {
		t.Fatalf("poison marker did not trigger a quarantine: %+v", rec)
	}
	if !quarantinedWhenOpened {
		t.Error("the store was still in place when the open ran — the quarantine must happen FIRST, " +
			"because the fault it recovers from never returns to be handled afterwards")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the acted-on marker survived; the next open would quarantine a healthy store")
	}
}

// Quarantine MOVES, never deletes. Everything downstream — the runbooks, the
// residual-copy metrics, the operator's ability to recover data — depends on it.
func TestOpen_QuarantinePreservesTheDamagedCopy(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	canary := filepath.Join(dir, "canary")
	if err := os.WriteFile(canary, []byte("evidence"), 0o600); err != nil {
		t.Fatalf("seed canary: %v", err)
	}
	if err := os.WriteFile(StoreBase(dir)+MarkerSuffix+"1-1", nil, 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}

	_, rec, err := Open(dir, DefaultPolicy(), newDirStore)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !rec.Quarantined {
		t.Fatal("no quarantine happened")
	}
	b, err := os.ReadFile(filepath.Join(rec.QuarantinePath, "canary"))
	if err != nil || string(b) != "evidence" {
		t.Errorf("the damaged copy was destroyed rather than moved aside (%v)", err)
	}
	if !strings.Contains(rec.QuarantinePath, QuarantineSuffix) {
		t.Errorf("quarantine path %q does not use the .corrupt.<ts> convention", rec.QuarantinePath)
	}
}

// A returned error that is NOT positively identified as corruption must degrade
// without touching the disk. The fail-safe default is to leave it alone.
func TestOpen_UnclassifiedErrorNeverQuarantines(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	boom := errors.New("something nobody has seen before")
	_, rec, err := Open(dir, DefaultPolicy(), func(string) (*fakeStore, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the original error passed through", err)
	}
	if rec.Quarantined || len(QuarantinedCopies(dir)) != 0 {
		t.Error("an unrecognised error moved the store aside; unclassified must degrade")
	}
}

// Corruption recovers in ONE call: quarantine, then exactly one retry against a
// fresh directory. A second boot to complete recovery would still leave one
// start in which the appliance does not come up.
func TestOpen_CorruptErrorQuarantinesAndRetriesOnce(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	calls := 0
	s, rec, err := Open(dir, DefaultPolicy(), func(d string) (*fakeStore, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("MANIFEST has bad magic")
		}
		return newDirStore(d)
	})
	if err != nil || s == nil {
		t.Fatalf("Open = (%v, %v), want recovery in one call", s, err)
	}
	if calls != 2 {
		t.Errorf("open func called %d times, want exactly 2 (one failure, one retry — never a loop)", calls)
	}
	if rec.Trigger != TriggerOpenError || !rec.Quarantined {
		t.Errorf("recovery not recorded: %+v", rec)
	}
	if len(rec.ResidualQuarantines) != 1 {
		t.Errorf("ResidualQuarantines = %v, want the copy this call created", rec.ResidualQuarantines)
	}
}

// A retry that also fails must not quarantine a second time in the same call:
// that would consume the evidence budget and could destroy the copy just made.
func TestOpen_RetryFailureDoesNotQuarantineTwice(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, rec, err := Open(dir, DefaultPolicy(), func(string) (*fakeStore, error) {
		return nil, errors.New("MANIFEST has bad magic")
	})
	if err == nil {
		t.Fatal("Open succeeded against an always-failing open func")
	}
	if !rec.Quarantined {
		t.Fatal("no quarantine happened")
	}
	if got := len(QuarantinedCopies(dir)); got != 1 {
		t.Errorf("quarantined copies = %d, want exactly 1 per call", got)
	}
}

// Evidence must be bounded: a host that keeps producing corruption cannot be
// allowed to fill the volume with copies of the store.
func TestOpen_QuarantinedCopiesAreBounded(t *testing.T) {
	dir := tempStore(t)
	for i := 0; i < 4; i++ {
		if _, err := newDirStore(dir); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		if err := os.WriteFile(StoreBase(dir)+MarkerSuffix+"1-1", nil, 0o600); err != nil {
			t.Fatalf("plant marker: %v", err)
		}
		if _, _, err := Open(dir, DefaultPolicy(), newDirStore); err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
	}
	if got := len(QuarantinedCopies(dir)); got > MaxQuarantinedCopies {
		t.Errorf("quarantined copies = %d, want <= %d (unbounded evidence fills the volume)", got, MaxQuarantinedCopies)
	}
}

// ── the invariant that is easiest to refactor away ───────────────────────────

// rename(2) does not consult flocks, so probing the lock and releasing it before
// the rename leaves a window in which another process starts its own open and
// has its live directory renamed underneath it. The invariant is carried by the
// TYPE — a released handle is refused — so the window cannot be reintroduced by
// reordering two statements.
func TestQuarantineDir_RefusesWithoutAHeldLock(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := QuarantineDir(nil, dir); !errors.Is(err, ErrStoreLockNotHeld) {
		t.Errorf("QuarantineDir(nil) = %v, want ErrStoreLockNotHeld", err)
	}
	lock, err := LockStore(dir)
	if err != nil || lock == nil {
		t.Fatalf("LockStore = (%v, %v)", lock, err)
	}
	lock.Release()
	if _, err := QuarantineDir(lock, dir); !errors.Is(err, ErrStoreLockNotHeld) {
		t.Errorf("QuarantineDir(released) = %v, want ErrStoreLockNotHeld", err)
	}
}

// A marker whose owner is still alive is not a poison signal. Acting on one
// would destroy the breadcrumb of an open still in progress.
func TestAbandonedMarkers_LiveAttemptIsNotAbandoned(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	live := BeginAttempt(dir)
	if live.MarkerPath() == "" {
		t.Fatal("attempt was not armed")
	}
	if got := AbandonedMarkers(dir); len(got) != 0 {
		t.Errorf("a LIVE attempt's marker read as abandoned: %v", got)
	}
	// Dropping the lock without removing the marker is exactly what the kernel
	// does when a process dies inside the open.
	live.ReleaseLock()
	if got := AbandonedMarkers(dir); len(got) != 1 {
		t.Errorf("abandoned markers after the owner died = %v, want 1", got)
	}
}

// End removes the marker BEFORE releasing the lock. Releasing first would leave
// a window in which our own still-present marker reads as abandoned.
func TestOpenAttempt_EndRemovesTheMarker(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	a := BeginAttempt(dir)
	p := a.MarkerPath()
	a.End()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("marker %q survived End(); a later open would read it as poison", p)
	}
}

// ── policy composition ───────────────────────────────────────────────────────

func TestPolicy_WithoutNarrowsOnlyTheCorruptionList(t *testing.T) {
	base := DefaultPolicy()
	narrowed := base.Without("encryption key mismatch")

	if len(narrowed.Corruption) != len(base.Corruption)-1 {
		t.Errorf("Without removed %d signals, want exactly 1", len(base.Corruption)-len(narrowed.Corruption))
	}
	if len(narrowed.Environmental) != len(base.Environmental) {
		t.Error("Without touched the environmental deny-list; it must only ever narrow corruption")
	}
	for _, s := range narrowed.Corruption {
		if strings.EqualFold(s, "encryption key mismatch") {
			t.Error("the named signal is still present")
		}
	}
	// The caller's base must not be mutated — two stores share DefaultPolicy().
	for _, s := range base.Corruption {
		if strings.EqualFold(s, "encryption key mismatch") {
			return
		}
	}
	t.Error("Without mutated the policy it was called on; another store's posture would change with it")
}

func TestPolicy_WithoutIsCaseInsensitiveAndToleratesUnknownNames(t *testing.T) {
	base := DefaultPolicy()
	if got := base.Without("ENCRYPTION KEY MISMATCH"); len(got.Corruption) != len(base.Corruption)-1 {
		t.Error("Without is case-sensitive; a caller matching badger's own casing would silently remove nothing")
	}
	if got := base.Without("not a signal"); len(got.Corruption) != len(base.Corruption) {
		t.Error("Without dropped something for an unknown name")
	}
}

// Environmental faults are matched FIRST, structurally where the error chain
// allows it. A full or read-only volume is never a reason to rename a store.
func TestClassify_EnvironmentalWinsAndSyscallsAreStructural(t *testing.T) {
	p := DefaultPolicy()
	if got := Classify(errors.New("checksum mismatch: no space left on device"), p); got != ClassEnvironment {
		t.Errorf("Classify(full disk) = %v, want ClassEnvironment", got)
	}
	if got := Classify(syscall.EROFS, p); got != ClassEnvironment {
		t.Errorf("Classify(EROFS) = %v, want ClassEnvironment", got)
	}
	if got := Classify(nil, p); got != ClassUnknown {
		t.Errorf("Classify(nil) = %v, want ClassUnknown", got)
	}
	if got := Classify(errors.New("MANIFEST has bad magic"), p); got != ClassCorrupt {
		t.Errorf("Classify(bad magic) = %v, want ClassCorrupt", got)
	}
}

// An empty corruption list must disable recovery entirely rather than fall back
// to some default: a store that opts out of quarantine must really get none.
func TestClassify_EmptyCorruptionListNeverQuarantines(t *testing.T) {
	p := Policy{Environmental: EnvironmentalSignals()}
	if got := Classify(errors.New("MANIFEST has bad magic"), p); got == ClassCorrupt {
		t.Error("an empty corruption list still classified corruption")
	}
}

// StoreBase must be insensitive to a trailing separator: markers and
// quarantined copies are siblings, so "dir" and "dir/" have to land on the same
// names or a caller's marker becomes invisible to the next open.
func TestStoreBase_TrailingSeparatorIsIgnored(t *testing.T) {
	if StoreBase("/data/store"+string(os.PathSeparator)) != "/data/store" {
		t.Error("StoreBase did not trim the trailing separator")
	}
	if StoreBase("/data/store") != "/data/store" {
		t.Error("StoreBase altered a path with no trailing separator")
	}
}

// A store another process holds must never be renamed away, even when a poison
// marker is present — that is the one case where the rename would destroy a
// perfectly live store.
func TestApplyQuarantine_RefusesWhileAnotherProcessHoldsTheStore(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	holder, err := LockStore(dir)
	if err != nil || holder == nil {
		t.Fatalf("LockStore = (%v, %v)", holder, err)
	}
	defer holder.Release()

	var rec Recovery
	ApplyQuarantine(dir, &rec)
	if rec.Quarantined {
		t.Fatal("a store held by another opener was renamed out from under it")
	}
	if rec.Skipped == "" {
		t.Error("the refusal was not recorded; an operator cannot tell recovery was declined")
	}
}

func TestApplyQuarantine_MissingDirectoryIsRecordedNotAnError(t *testing.T) {
	var rec Recovery
	ApplyQuarantine(filepath.Join(t.TempDir(), "absent"), &rec)
	if rec.Quarantined {
		t.Error("quarantined a directory that does not exist")
	}
	if !strings.Contains(rec.Skipped, "no store directory") {
		t.Errorf("Skipped = %q, want the missing-directory reason", rec.Skipped)
	}
}

// ── the marker must not outlive the incident it describes ────────────────────

// Codex review, PR #1242 (P2). A process killed after BeginAttempt but BEFORE
// the store directory exists leaves a marker describing a store that was never
// created. The quarantine is then correctly skipped — there is nothing to move
// aside — but gating the marker cleanup solely on Quarantined left the marker
// behind, so:
//
//	open 1 — creates a healthy store beside the stale marker
//	open 2 — reads that same marker as poison and quarantines the HEALTHY store
//
// i.e. the mechanism manufactured exactly the data loss it exists to prevent,
// one open later. This shape is inherited from the original catdb implementation,
// so it was latent in the shipped Layer-2 store too.
func TestOpen_StaleMarkerOnAnAbsentStoreDoesNotQuarantineTheNextStore(t *testing.T) {
	dir := tempStore(t)
	// The store directory deliberately does NOT exist: the dead process never
	// got far enough to create it.
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	marker := StoreBase(dir) + MarkerSuffix + "777-1"
	if err := os.WriteFile(marker, []byte("pid=777\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}

	// Open 1: nothing to quarantine, store gets created.
	s1, rec1, err := Open(dir, DefaultPolicy(), newDirStore)
	if err != nil || s1 == nil {
		t.Fatalf("open 1 = (%v, %v)", s1, err)
	}
	if rec1.Quarantined {
		t.Fatalf("open 1 quarantined a store that did not exist: %+v", rec1)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("the stale marker survived an open that settled it — open 2 will quarantine a healthy store")
	}

	// Open 2: the store is healthy and must be left completely alone.
	canary := filepath.Join(dir, "canary")
	if err := os.WriteFile(canary, []byte("healthy"), 0o600); err != nil {
		t.Fatalf("seed canary: %v", err)
	}
	s2, rec2, err := Open(dir, DefaultPolicy(), newDirStore)
	if err != nil || s2 == nil {
		t.Fatalf("open 2 = (%v, %v)", s2, err)
	}
	if rec2.Quarantined {
		t.Errorf("open 2 quarantined a HEALTHY store (moved to %s)", rec2.QuarantinePath)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("the healthy store's contents were moved aside: %v", err)
	}
	if n := len(QuarantinedCopies(dir)); n != 0 {
		t.Errorf("quarantined copies = %d, want 0 — a healthy store was reset", n)
	}
}

// The control for the fix above: a marker must still be KEPT when the
// quarantine was blocked rather than unnecessary. A live lock holder means the
// condition is genuinely unresolved, so the breadcrumb has to survive for the
// next attempt — clearing it there would silently disarm the recovery.
func TestOpen_BlockedQuarantineKeepsTheMarkerForTheNextAttempt(t *testing.T) {
	dir := tempStore(t)
	if _, err := newDirStore(dir); err != nil {
		t.Fatalf("seed: %v", err)
	}
	holder, err := LockStore(dir)
	if err != nil || holder == nil {
		t.Fatalf("LockStore = (%v, %v)", holder, err)
	}
	defer holder.Release()

	marker := StoreBase(dir) + MarkerSuffix + "888-1"
	if err := os.WriteFile(marker, []byte("pid=888\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}

	_, rec, _ := Open(dir, DefaultPolicy(), newDirStore)
	if rec.Quarantined {
		t.Fatal("quarantined a store held by another opener")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("a marker was discarded while the condition was still unresolved; the next attempt cannot recover")
	}
}
