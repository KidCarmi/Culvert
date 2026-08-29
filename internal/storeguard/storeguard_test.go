package storeguard

// storeguard_test.go — gates for the shared recovery engine.
//
// These exercise the state machine with a SYNTHETIC opener, which reaches
// decisions the badger-backed consumer suites cannot construct on demand: the
// "already quarantined once, never loop" rule, the exact retry count, and the
// full classification matrix including the per-store policy subtraction.
//
// The engine's behaviour against a REAL corrupt BadgerDB — including the
// uncatchable panic that is its whole reason for existing — is pinned by its
// two consumers: internal/catdb/resilient_test.go (CHAOS-50) and
// internal/logstore/resilient_chaos_test.go (CHAOS-57).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeStore stands in for a *badger.DB.
type fakeStore struct{}

// opener returns an open func that fails with errs[i] on call i, then succeeds.
// A nil element means success.
type opener struct {
	errs  []error
	calls int
}

func (o *opener) open(string) (*fakeStore, error) {
	i := o.calls
	o.calls++
	if i < len(o.errs) && o.errs[i] != nil {
		return nil, o.errs[i]
	}
	return &fakeStore{}, nil
}

// seedDir creates a non-empty directory at path, standing in for a store that
// exists on disk.
func seedDir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(filepath.Join(path, "MANIFEST"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
}

var errCorrupt = errors.New("manifest has bad magic")

// ── classification ───────────────────────────────────────────────────────────

// The fault → class table. Environmental signals must be checked FIRST: each is
// a fault renaming cannot fix, and on the lock case renaming would move a LIVE
// store out from under its owner.
func TestClassifyOpenError_Table(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want OpenErrClass
	}{
		{"nil", nil, ClassUnknown},
		{"torn manifest", errors.New("manifest has bad magic"), ClassCorrupt},
		{"corrupt manifest", errors.New("Manifest file might be corrupted"), ClassCorrupt},
		{"checksum", errors.New("checksum mismatch"), ClassCorrupt},
		{"missing table", errors.New("file does not exist for table 1"), ClassCorrupt},
		{"keyregistry", errors.New("Encryption key mismatch"), ClassCorrupt},
		{"truncate", errors.New("log truncate required"), ClassCorrupt},
		{"invalid magic", errors.New("invalid magic"), ClassCorrupt},
		{"live owner", errors.New("Another process is using this Badger database"), ClassEnvironment},
		{"not a dir", errors.New("... not a directory"), ClassEnvironment},
		{"permission", errors.New("permission denied"), ClassEnvironment},
		{"read-only", errors.New("read-only file system"), ClassEnvironment},
		{"no space", errors.New("no space left on device"), ClassEnvironment},
		{"emfile", errors.New("too many open files"), ClassEnvironment},
		{"eio", errors.New("input/output error"), ClassEnvironment},
		{"unrecognised", errors.New("something nobody predicted"), ClassUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyOpenError(tc.err, Policy{}); got != tc.want {
				t.Errorf("ClassifyOpenError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// Syscall-level faults are reached structurally, not by text — the exact-and-
// cheap path for the errors whose chain survives.
func TestClassifyOpenError_StructuralEnvironmentalFaults(t *testing.T) {
	for _, target := range []error{os.ErrPermission, os.ErrNotExist} {
		if got := ClassifyOpenError(target, Policy{}); got != ClassEnvironment {
			t.Errorf("ClassifyOpenError(%v) = %v, want ClassEnvironment", target, got)
		}
		// The chain, not the text: a badger wrapper around the same fault must
		// reach the same verdict.
		if got := ClassifyOpenError(fmt.Errorf("badger open: %w", target), Policy{}); got != ClassEnvironment {
			t.Errorf("ClassifyOpenError(wrapped %v) = %v, want ClassEnvironment", target, got)
		}
	}
}

// A Policy may only ever SUBTRACT. This is the invariant that keeps a shared
// destructive mechanism safe to hand to a new caller.
func TestPolicy_OnlySubtracts(t *testing.T) {
	sentinel := errors.New("store-specific benign condition")
	p := Policy{
		NeverCorrupt:     []error{sentinel},
		NeverCorruptText: []string{"encryption key mismatch"},
	}

	if got := ClassifyOpenError(errors.New("Encryption key mismatch"), p); got == ClassCorrupt {
		t.Error("text exemption did not hold")
	}
	if got := ClassifyOpenError(sentinel, p); got == ClassCorrupt {
		t.Error("sentinel exemption did not hold")
	}
	// Wrapping must not defeat the structural exemption.
	if got := ClassifyOpenError(errors.Join(errors.New("ctx"), sentinel), p); got == ClassCorrupt {
		t.Error("sentinel exemption did not survive wrapping")
	}
	// Everything else keeps its meaning: exemptions never reclassify unrelated
	// corruption, and never turn an environmental fault into corruption.
	if got := ClassifyOpenError(errCorrupt, p); got != ClassCorrupt {
		t.Errorf("unrelated corruption signal = %v, want ClassCorrupt", got)
	}
	if got := ClassifyOpenError(errors.New("no space left on device"), p); got != ClassEnvironment {
		t.Errorf("environmental fault = %v, want ClassEnvironment", got)
	}
}

// An environmental fault outranks an exemption, and an exemption outranks the
// corruption table. Order is the whole safety argument.
func TestClassifyOpenError_EnvironmentalOutranksEverything(t *testing.T) {
	p := Policy{NeverCorruptText: []string{"read-only file system"}}
	if got := ClassifyOpenError(errors.New("read-only file system"), p); got != ClassEnvironment {
		t.Errorf("= %v, want ClassEnvironment (an exemption must not demote an environmental fault to unknown)", got)
	}
}

// ── the open state machine ───────────────────────────────────────────────────

func TestOpen_HealthyStoreTouchesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	o := &opener{}

	st, rec, err := Open(dir, Policy{}, o.open)
	if err != nil || st == nil {
		t.Fatalf("Open = (%v, %v)", st, err)
	}
	if o.calls != 1 {
		t.Errorf("open calls = %d, want 1", o.calls)
	}
	if rec.Quarantined || rec.Trigger != TriggerNone || rec.Skipped != "" {
		t.Errorf("healthy open reported a recovery: %+v", rec)
	}
	if got := QuarantinedCopies(dir); len(got) != 0 {
		t.Errorf("quarantined copies = %v, want none", got)
	}
}

// Identified corruption: quarantine, then EXACTLY ONE retry. No loop — if the
// retry fails the fault is environmental and retrying cannot help.
func TestOpen_CorruptionQuarantinesAndRetriesExactlyOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	o := &opener{errs: []error{errCorrupt}}

	st, rec, err := Open(dir, Policy{}, o.open)
	if err != nil || st == nil {
		t.Fatalf("Open = (%v, %v), want a recovered store", st, err)
	}
	if o.calls != 2 {
		t.Errorf("open calls = %d, want exactly 2 (one failure, one retry)", o.calls)
	}
	if !rec.Quarantined || rec.Trigger != TriggerOpenError {
		t.Errorf("recovery = %+v, want a quarantine triggered by the open error", rec)
	}
	if rec.Cause != errCorrupt.Error() {
		t.Errorf("cause = %q, want the open error", rec.Cause)
	}
	if got := QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies = %v, want exactly 1", got)
	}
	if len(rec.ResidualQuarantines) != 1 {
		t.Errorf("residual quarantines = %v, want 1", rec.ResidualQuarantines)
	}
}

// The retry is bounded even when the replacement store also fails: two opens,
// one quarantine, a returned error. A store that fails forever must not spin.
func TestOpen_ReplacementFailureIsReportedNotRetried(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	o := &opener{errs: []error{errCorrupt, errCorrupt}}

	st, rec, err := Open(dir, Policy{}, o.open)
	if err == nil {
		t.Fatal("Open succeeded despite both attempts failing")
	}
	if st != nil {
		t.Error("a store was returned alongside the error")
	}
	if o.calls != 2 {
		t.Errorf("open calls = %d, want exactly 2 — no loop", o.calls)
	}
	if !rec.Quarantined {
		t.Errorf("recovery = %+v, want the first quarantine still reported", rec)
	}
}

// An environmental fault must degrade with the disk untouched.
func TestOpen_EnvironmentalFaultNeverQuarantines(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	o := &opener{errs: []error{errors.New("no space left on device")}}

	_, rec, err := Open(dir, Policy{}, o.open)
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if o.calls != 1 {
		t.Errorf("open calls = %d, want 1 (no retry for an environmental fault)", o.calls)
	}
	if rec.Quarantined {
		t.Fatalf("quarantined on an environmental fault: %+v", rec)
	}
	if _, serr := os.Stat(dir); serr != nil {
		t.Fatalf("store directory was moved: %v", serr)
	}
}

// An unrecognised error degrades: the fail-safe default is to leave the disk
// alone rather than guess.
func TestOpen_UnknownErrorDegrades(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	o := &opener{errs: []error{errors.New("a message from a future badger")}}

	_, rec, err := Open(dir, Policy{}, o.open)
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if rec.Quarantined {
		t.Fatalf("quarantined on an unclassified error: %+v", rec)
	}
}

// An exempted error must not be quarantined even though the shared table would
// classify it as corruption — the CHAOS-57 case, at engine level.
func TestOpen_ExemptedErrorIsNeverQuarantined(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	benign := errors.New("saved logs use a different encryption key")
	o := &opener{errs: []error{errors.New("Encryption key mismatch")}}
	p := Policy{NeverCorrupt: []error{benign}, NeverCorruptText: []string{"encryption key mismatch"}}

	_, rec, err := Open(dir, p, o.open)
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if rec.Quarantined {
		t.Fatalf("an exempted condition was quarantined: %+v", rec)
	}
	if o.calls != 1 {
		t.Errorf("open calls = %d, want 1", o.calls)
	}
}

// The poison-marker path: a marker with no live owner means a previous process
// entered the open and never returned. The store is quarantined BEFORE the
// opener is called, and the marker is cleared once it has been acted on.
func TestOpen_AbandonedMarkerQuarantinesBeforeOpening(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	marker := dir + MarkerSuffix + "1234-5678"
	if err := os.WriteFile(marker, []byte("pid=1234\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}
	o := &opener{}

	st, rec, err := Open(dir, Policy{}, o.open)
	if err != nil || st == nil {
		t.Fatalf("Open = (%v, %v)", st, err)
	}
	if rec.Trigger != TriggerPoisonMarker || !rec.Quarantined {
		t.Fatalf("recovery = %+v, want a poison-marker quarantine", rec)
	}
	if o.calls != 1 {
		t.Errorf("open calls = %d, want 1 — the quarantine happens BEFORE the opener runs", o.calls)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Error("the acted-on marker was not cleared; the next start would quarantine again")
	}
}

// A marker whose owner is STILL RUNNING is not a poison signal. Acting on it
// would destroy the breadcrumb of an attempt still in progress.
func TestAbandonedMarkers_LiveAttemptIsNotAbandoned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)

	live := BeginAttempt(dir)
	if live.Path == "" {
		t.Fatal("could not arm a marker")
	}
	if got := AbandonedMarkers(dir); len(got) != 0 {
		t.Errorf("a LIVE attempt's marker was reported abandoned: %v", got)
	}
	// Releasing the flock while the file stays is exactly what the kernel does
	// when the owner dies.
	live.Lock.Release()
	if got := AbandonedMarkers(dir); len(got) != 1 {
		t.Errorf("abandoned markers after the owner released = %v, want 1", got)
	}
	_ = os.Remove(live.Path)
}

// The marker is a SIBLING of the store, so a quarantine cannot carry it into
// the moved-aside directory and lose the breadcrumb.
func TestBeginAttempt_MarkerIsASibling(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	a := BeginAttempt(dir)
	defer a.End()
	if a.Path == "" {
		t.Fatal("marker could not be armed")
	}
	if filepath.Dir(a.Path) != filepath.Dir(dir) {
		t.Errorf("marker %q is not a sibling of %q", a.Path, dir)
	}
	if strings.HasPrefix(a.Path, dir+string(filepath.Separator)) {
		t.Errorf("marker %q lives INSIDE the store", a.Path)
	}
	// A trailing separator must not produce a nested marker either.
	b := BeginAttempt(dir + string(filepath.Separator))
	defer b.End()
	if filepath.Dir(b.Path) != filepath.Dir(dir) {
		t.Errorf("marker %q for a trailing-separator path is not a sibling", b.Path)
	}
}

// End removes the marker and releases the lock; a zero-value attempt is safe.
func TestOpenAttempt_EndIsSafeOnAZeroValue(t *testing.T) {
	var a *OpenAttempt
	a.End() // must not panic
	(&OpenAttempt{}).End()
}

// ── the quarantine rename ────────────────────────────────────────────────────

// The invariant carried by the TYPE: no lock, no rename. Probing the lock and
// letting go before the rename leaves a window in which another process starts
// opening a store that is about to be renamed out from under it.
func TestQuarantineDir_RefusesWithoutAHeldLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)

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
	if _, serr := os.Stat(dir); serr != nil {
		t.Fatalf("the store was renamed without a held lock: %v", serr)
	}
}

// Evidence is bounded: a host that keeps producing corruption must not fill the
// volume, and the newest copy is the diagnostically useful one.
func TestQuarantineDir_PrunesToTheCap(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	for i := 0; i < MaxQuarantinedCopies+3; i++ {
		seedDir(t, dir)
		lock, err := LockStore(dir)
		if err != nil || lock == nil {
			t.Fatalf("LockStore: (%v, %v)", lock, err)
		}
		if _, err := QuarantineDir(lock, dir); err != nil {
			t.Fatalf("QuarantineDir: %v", err)
		}
		lock.Release()
	}
	if got := QuarantinedCopies(dir); len(got) > MaxQuarantinedCopies {
		t.Errorf("quarantined copies = %d, want <= %d", len(got), MaxQuarantinedCopies)
	}
}

// ApplyQuarantine refuses, with a reason, when there is nothing to move.
func TestApplyQuarantine_MissingDirectoryIsSkippedWithAReason(t *testing.T) {
	var rec Recovery
	ApplyQuarantine(filepath.Join(t.TempDir(), "absent"), &rec)
	if rec.Quarantined {
		t.Error("quarantined a directory that does not exist")
	}
	if rec.Skipped == "" {
		t.Error("no skip reason recorded")
	}
}

// QuarantinedCopies is ordered oldest-first so "newest last" holds for callers
// that report the most recent incident.
func TestQuarantinedCopies_IsChronological(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	for i := 0; i < 3; i++ {
		if err := os.MkdirAll(dir+QuarantineSuffix+string(rune('1'+i))+"00000000000000000", 0o700); err != nil {
			t.Fatalf("plant: %v", err)
		}
	}
	got := QuarantinedCopies(dir)
	if len(got) != 3 {
		t.Fatalf("copies = %v, want 3", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("copies are not in ascending order: %v", got)
		}
	}
}

// An empty path must never be interpreted as a store to act on.
func TestEmptyPathIsInert(t *testing.T) {
	if got := AbandonedMarkers(""); got != nil {
		t.Errorf("AbandonedMarkers(\"\") = %v, want nil", got)
	}
	if got := QuarantinedCopies(""); got != nil {
		t.Errorf("QuarantinedCopies(\"\") = %v, want nil", got)
	}
	if a := BeginAttempt(""); a.Path != "" {
		t.Errorf("BeginAttempt(\"\") armed a marker at %q", a.Path)
	}
}

// ── glob metacharacters in the store path ────────────────────────────────────

// A store path is operator-configurable, and discovery must not interpret it as
// a pattern. Raised by Codex review on PR #1257 and verified in both directions
// before the fix: with filepath.Glob, `hist[1]` found NOTHING (its own poison
// marker undiscoverable — the crash loop survives its own remedy) and `hist?`
// matched a NEIGHBOUR's marker (a healthy store quarantined on someone else's
// evidence).
func TestDiscovery_IsNotFooledByGlobMetacharactersInThePath(t *testing.T) {
	for _, name := range []string{"hist[1]", "hist?", "hist*", `hist\x`} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, name)
			seedDir(t, base)

			// This store's own abandoned marker must be found.
			marker := base + MarkerSuffix + "1234-5678"
			if err := os.WriteFile(marker, []byte("pid=1234\n"), 0o600); err != nil {
				t.Fatalf("plant marker: %v", err)
			}
			got := AbandonedMarkers(base)
			if len(got) != 1 || got[0] != marker {
				t.Fatalf("AbandonedMarkers = %v, want exactly [%s] — a missed poison marker means the next start panics again", got, marker)
			}

			// And its own quarantined copy must be found.
			q := base + QuarantineSuffix + "1700000000000000000"
			if err := os.MkdirAll(q, 0o700); err != nil {
				t.Fatalf("plant quarantine: %v", err)
			}
			if c := QuarantinedCopies(base); len(c) != 1 || c[0] != q {
				t.Fatalf("QuarantinedCopies = %v, want exactly [%s]", c, q)
			}
		})
	}
}

// The other direction: a neighbouring store's marker must never be attributed to
// this one, or a healthy store gets quarantined on someone else's evidence.
func TestDiscovery_DoesNotClaimANeighboursMarker(t *testing.T) {
	root := t.TempDir()
	mine := filepath.Join(root, "hist?")
	seedDir(t, mine)

	neighbour := filepath.Join(root, "histX")
	seedDir(t, neighbour)
	if err := os.WriteFile(neighbour+MarkerSuffix+"999-1", []byte("pid=999\n"), 0o600); err != nil {
		t.Fatalf("plant neighbour marker: %v", err)
	}
	if err := os.MkdirAll(neighbour+QuarantineSuffix+"1700000000000000000", 0o700); err != nil {
		t.Fatalf("plant neighbour quarantine: %v", err)
	}

	if got := AbandonedMarkers(mine); len(got) != 0 {
		t.Errorf("AbandonedMarkers(%q) claimed a neighbour's marker: %v", mine, got)
	}
	if got := QuarantinedCopies(mine); len(got) != 0 {
		t.Errorf("QuarantinedCopies(%q) claimed a neighbour's copy: %v", mine, got)
	}
}

// The temp-marker form must stay outside the final form's prefix, or arming a
// marker would read as an abandoned one.
func TestDiscovery_TempMarkerIsNotSeenAsAFinalMarker(t *testing.T) {
	if strings.HasPrefix(MarkerTempSuffix, MarkerSuffix) {
		t.Fatalf("MarkerTempSuffix %q starts with MarkerSuffix %q — a marker being armed reads as abandoned", MarkerTempSuffix, MarkerSuffix)
	}
	root := t.TempDir()
	base := filepath.Join(root, "store")
	seedDir(t, base)
	if err := os.WriteFile(base+MarkerTempSuffix+"1-2", []byte("x"), 0o600); err != nil {
		t.Fatalf("plant temp marker: %v", err)
	}
	// AbandonedMarkers reaps the temp marker as litter but must not report it.
	if got := AbandonedMarkers(base); len(got) != 0 {
		t.Errorf("a temp marker was reported as a poison signal: %v", got)
	}
}
