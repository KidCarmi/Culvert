package urlcat

// urlcat_durable_test.go — 2D-B.0a: the fenced durable mutation domain for the
// URL-category taxonomy. Confirmed success == restart-durable; pre-replacement
// persistence failure == rollback in memory AND on reload; the optimistic
// fence is the restart-stable ContentFingerprint (2D-B §7 — no new on-disk
// envelope); MaxHostsPerCategory is enforced at the store boundary on every
// supported mutation; publication ordering and the commit boundary follow the
// 2D-A doctrine. Every truth assertion reloads a FRESH store (the restart
// oracle) — no memory-only tests.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// newDurableStore returns an EMPTY store persisting into a fresh temp dir.
func newDurableStore(t *testing.T) (*Store, string) {
	t.Helper()
	s := New(nil)
	path := filepath.Join(t.TempDir(), "url_categories.json")
	s.SetPathForTest(path)
	return s, path
}

// reloadStore loads the on-disk state into a FRESH store — the restart oracle.
func reloadStore(t *testing.T, path string) *Store {
	t.Helper()
	s := New(nil)
	if err := s.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	return s
}

func catNames(s *Store) string {
	all := s.All()
	names := make([]string, 0, len(all))
	for _, e := range all {
		names = append(names, e.Name)
	}
	return strings.Join(names, "|")
}

func TestCreateDurable_SuccessIsRestartDurable(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Social", []string{"example.com"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	fresh := reloadStore(t, path)
	e := fresh.GetByName("Social")
	if e == nil || len(e.Hosts) != 1 || e.Hosts[0] != "example.com" || e.BuiltIn {
		t.Fatalf("reload = %+v, want admin category Social with example.com", e)
	}
	if fresh.ContentFingerprint() != s.ContentFingerprint() {
		t.Fatal("restart must reproduce the same semantic revision (ContentFingerprint is restart-stable)")
	}
}

func TestMutateDurable_PersistFailureRollsBackMemoryAndDisk(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Keep", []string{"keep.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	preFP := s.ContentFingerprint()

	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		if p == path {
			return errors.New("injected persistence failure")
		}
		return fileutil.AtomicWrite(p, data, mode)
	}
	t.Cleanup(func() { writeFile = prev })

	err := s.CreateDurable(nil, "Doomed", []string{"doomed.example"})
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("persist failure = %v, want ErrPersist", err)
	}
	// Memory rolled back to the old semantic taxonomy.
	if s.GetByName("Doomed") != nil || s.ContentFingerprint() != preFP {
		t.Fatalf("memory must return to the pre-mutation taxonomy (fp %q vs %q)", s.ContentFingerprint(), preFP)
	}
	writeFile = prev
	// Restart sees the old taxonomy.
	fresh := reloadStore(t, path)
	if fresh.GetByName("Doomed") != nil || fresh.ContentFingerprint() != preFP {
		t.Fatalf("reload must show the pre-mutation taxonomy, got %q", catNames(fresh))
	}
}

func TestMutateDurable_LandedContentDoctrine(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Keep", []string{"keep.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		if p == path {
			if err := fileutil.AtomicWrite(p, data, mode); err != nil {
				return err
			}
			return fmt.Errorf("wrapped: %w", fileutil.ErrReplacedNotSynced)
		}
		return fileutil.AtomicWrite(p, data, mode)
	}
	t.Cleanup(func() { writeFile = prev })

	if err := s.CreateDurable(nil, "Landed", []string{"landed.example"}); err != nil {
		t.Fatalf("ErrReplacedNotSynced must be a landed-content SUCCESS, got %v", err)
	}
	writeFile = prev
	fresh := reloadStore(t, path)
	if fresh.GetByName("Landed") == nil {
		t.Fatal("landed content missing after reload")
	}
	if fresh.ContentFingerprint() != s.ContentFingerprint() {
		t.Fatal("landed content must carry the landed semantic revision")
	}
}

func TestRevisionFence_StaleConflictsAndIsRestartStable(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Seed", []string{"seed.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	loaded := s.ContentFingerprint() // the revision a client loaded

	// A fenced mutation with the current revision succeeds.
	if err := s.AddHostDurable(&loaded, "Seed", "added.example"); err != nil {
		t.Fatalf("current-revision mutation: %v", err)
	}
	// The SAME token is now stale — structured conflict, mutation not applied.
	err := s.AddHostDurable(&loaded, "Seed", "never.example")
	var conflict *RevisionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("stale fence = %v, want RevisionConflictError", err)
	}
	if conflict.Asserted != loaded || conflict.Current != s.ContentFingerprint() {
		t.Fatalf("conflict payload = %+v", conflict)
	}
	if e := s.GetByName("Seed"); len(e.Hosts) != 2 {
		t.Fatalf("stale mutation must not apply, hosts = %v", e.Hosts)
	}

	// Restart stability: a fresh store over the same file serves the SAME
	// revision, and the stale token still conflicts.
	fresh := reloadStore(t, path)
	if fresh.ContentFingerprint() != s.ContentFingerprint() {
		t.Fatal("revision must be restart-stable")
	}
	if err := fresh.AddHostDurable(&loaded, "Seed", "never.example"); !errors.As(err, &conflict) {
		t.Fatalf("stale token after restart = %v, want RevisionConflictError", err)
	}
}

func TestCreateDurable_StrictCreateNeverUpserts(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Media", []string{"a.example"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	err := s.CreateDurable(nil, "media", []string{"b.example"}) // case-insensitive collision
	if !errors.Is(err, ErrNameExists) {
		t.Fatalf("duplicate create = %v, want ErrNameExists", err)
	}
	fresh := reloadStore(t, path)
	if e := fresh.GetByName("Media"); e == nil || len(e.Hosts) != 1 || e.Hosts[0] != "a.example" {
		t.Fatalf("existing category must be untouched, got %+v", e)
	}
}

func TestReplaceHostsDurable_PreservesBuiltInAndRequiresExistence(t *testing.T) {
	s, path := newDurableStore(t)
	// Seed a BuiltIn entry through the legacy upsert (the baseline shape).
	if err := s.Set("Baseline", []string{"old.example"}, true); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.ReplaceHostsDurable(nil, "Baseline", []string{"new.example"}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	fresh := reloadStore(t, path)
	e := fresh.GetByName("Baseline")
	if e == nil || !e.BuiltIn || len(e.Hosts) != 1 || e.Hosts[0] != "new.example" {
		t.Fatalf("BuiltIn flag must survive a fenced host replacement, got %+v", e)
	}
	if err := s.ReplaceHostsDurable(nil, "Ghost", []string{"x.example"}); err == nil {
		t.Fatal("replace on a missing category must error, never create")
	}
}

func TestMaxHostsPerCategory_EnforcedOnEveryWritePath(t *testing.T) {
	over := make([]string, MaxHostsPerCategory+1)
	atCap := make([]string, MaxHostsPerCategory)
	for i := range over {
		over[i] = fmt.Sprintf("h%05d.example", i)
	}
	copy(atCap, over[:MaxHostsPerCategory])

	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Big", over); !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("CreateDurable over cap = %v, want ErrTooManyHosts", err)
	}
	if err := s.CreateDurable(nil, "Big", atCap); err != nil {
		t.Fatalf("CreateDurable at cap must succeed: %v", err)
	}
	if err := s.ReplaceHostsDurable(nil, "Big", over); !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("ReplaceHostsDurable over cap = %v, want ErrTooManyHosts", err)
	}
	if err := s.AddHostDurable(nil, "Big", "one-more.example"); !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("AddHostDurable past cap = %v, want ErrTooManyHosts", err)
	}
	// The LEGACY paths are bounded at the same store boundary (the old PUT
	// had no cap; a bypass path must not evade it — 2D-B §11).
	if err := s.Set("Big", over, false); !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("legacy Set over cap = %v, want ErrTooManyHosts", err)
	}
	if err := s.AddHost("Big", "one-more.example"); !errors.Is(err, ErrTooManyHosts) {
		t.Fatalf("legacy AddHost past cap = %v, want ErrTooManyHosts", err)
	}
	fresh := reloadStore(t, path)
	if e := fresh.GetByName("Big"); e == nil || len(e.Hosts) != MaxHostsPerCategory {
		t.Fatalf("durable state must hold exactly the cap, got %d", len(e.Hosts))
	}
}

func TestRemoveHostDurable_SuccessAndRollback(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Seed", []string{"a.example", "b.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.RemoveHostDurable(nil, "Seed", "a.example"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	fresh := reloadStore(t, path)
	if e := fresh.GetByName("Seed"); len(e.Hosts) != 1 || e.Hosts[0] != "b.example" {
		t.Fatalf("remove not durable: %v", e.Hosts)
	}
	preFP := s.ContentFingerprint()
	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		return errors.New("injected persistence failure")
	}
	t.Cleanup(func() { writeFile = prev })
	if err := s.RemoveHostDurable(nil, "Seed", "b.example"); !errors.Is(err, ErrPersist) {
		t.Fatalf("failed remove = %v, want ErrPersist", err)
	}
	writeFile = prev
	if s.ContentFingerprint() != preFP {
		t.Fatal("failed remove must roll memory back")
	}
	fresh2 := reloadStore(t, path)
	if e := fresh2.GetByName("Seed"); len(e.Hosts) != 1 || e.Hosts[0] != "b.example" {
		t.Fatalf("failed remove must not be durable: %v", e.Hosts)
	}
}

// ─── Publication ordering + commit boundary (the 2D-A doctrine) ────────

// TestPublication_StaleBulkSaveCannotClobberDurableMutation: the production
// bulk shape (ReplaceAll + Save — cluster apply / import / rollback) parks at
// the publication seam post-snapshot; a fenced durable mutation lands and is
// acknowledged; the stale publication resumes LAST. The acknowledged
// mutation must survive on disk.
func TestPublication_StaleBulkSaveCannotClobberDurableMutation(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Seed", []string{"seed.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	prev := writeFile
	t.Cleanup(func() { writeFile = prev })
	var stubMu sync.Mutex
	calls := 0
	bulkInWrite := make(chan struct{})
	releaseBulk := make(chan struct{})
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		stubMu.Lock()
		calls++
		n := calls
		stubMu.Unlock()
		if n == 1 {
			close(bulkInWrite)
			<-releaseBulk
		}
		return fileutil.AtomicWrite(p, data, mode)
	}

	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		s.ReplaceAll([]Entry{{Name: "Bulk", Hosts: []string{"bulk.example"}}})
		s.Save()
	}()
	<-bulkInWrite

	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.CreateDurable(nil, "AdminAdd", []string{"admin.example"})
	}()
	adminFinishedFirst := false
	for i := 0; i < 200000 && !adminFinishedFirst; i++ {
		select {
		case <-adminDone:
			adminFinishedFirst = true
		default:
			runtime.Gosched()
		}
	}
	close(releaseBulk)
	<-bulkDone
	<-adminDone
	if adminErr != nil {
		t.Fatalf("durable mutation must succeed, got %v", adminErr)
	}
	writeFile = prev

	fresh := reloadStore(t, path)
	if fresh.GetByName("AdminAdd") == nil {
		t.Fatalf("acknowledged durable mutation missing after reload (adminFinishedFirst=%v)", adminFinishedFirst)
	}
	if fresh.ContentFingerprint() != s.ContentFingerprint() {
		t.Fatalf("reload %q must equal memory %q", catNames(fresh), catNames(s))
	}
}

// TestCommitBoundary_SaveWaitsForInFlightDurableMutation: while a durable
// mutation's fn is mid-transaction (memory mutated, not yet committed), a
// standalone Save must NOT complete — no external publication may observe an
// unfinished mutation (whitebox: drives the unexported mutateDurable core
// directly to hold the transaction open).
func TestCommitBoundary_SaveWaitsForInFlightDurableMutation(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Seed", []string{"seed.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fnMutated := make(chan struct{})
	fnRelease := make(chan struct{})
	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.mutateDurable(nil, func() error {
			if err := s.addHostMem("Seed", "inflight.example"); err != nil {
				return err
			}
			close(fnMutated)
			<-fnRelease
			return nil
		})
	}()
	<-fnMutated

	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		s.Save()
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case <-saveDone:
		t.Fatal("standalone Save completed while a durable mutation was open — published an unfinished mutation")
	default:
	}
	close(fnRelease)
	<-adminDone
	<-saveDone
	if adminErr != nil {
		t.Fatalf("mutation must succeed, got %v", adminErr)
	}
	fresh := reloadStore(t, path)
	if fresh.ContentFingerprint() != s.ContentFingerprint() {
		t.Fatal("committed state not durable after boundary closed")
	}
}

// TestCommitBoundary_FailedMutationNeverVisibleOnDisk: an in-flight mutation
// observed by a pending standalone Save, whose own publication then fails,
// must not exist on disk at any revision (the 2D-A rollback-reload proof
// transposed).
func TestCommitBoundary_FailedMutationNeverVisibleOnDisk(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.CreateDurable(nil, "Seed", []string{"seed.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	preFP := s.ContentFingerprint()

	prevW := writeFile
	t.Cleanup(func() { writeFile = prevW })
	var stubMu sync.Mutex
	failArmed := false
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		stubMu.Lock()
		if failArmed && p == path {
			failArmed = false
			stubMu.Unlock()
			return errors.New("injected publication failure")
		}
		stubMu.Unlock()
		return fileutil.AtomicWrite(p, data, mode)
	}

	fnMutated := make(chan struct{})
	fnRelease := make(chan struct{})
	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.mutateDurable(nil, func() error {
			if err := s.addHostMem("Seed", "doomed.example"); err != nil {
				return err
			}
			close(fnMutated)
			<-fnRelease
			return nil
		})
	}()
	<-fnMutated

	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		s.Save()
	}()
	saveCompletedInFlight := false
	for i := 0; i < 200000 && !saveCompletedInFlight; i++ {
		select {
		case <-saveDone:
			saveCompletedInFlight = true
		default:
			runtime.Gosched()
		}
	}
	if saveCompletedInFlight {
		t.Error("standalone Save completed while the mutation transaction was open")
	}
	stubMu.Lock()
	failArmed = true
	stubMu.Unlock()
	close(fnRelease)
	<-adminDone
	<-saveDone
	if !errors.Is(adminErr, ErrPersist) {
		t.Fatalf("failed publication = %v, want ErrPersist", adminErr)
	}
	writeFile = prevW

	if s.ContentFingerprint() != preFP {
		t.Fatal("memory must roll back to the pre-mutation taxonomy")
	}
	fresh := reloadStore(t, path)
	if e := fresh.GetByName("Seed"); len(e.Hosts) != 1 {
		t.Fatalf("failed mutation visible on disk: %v", e.Hosts)
	}
	if fresh.ContentFingerprint() != preFP {
		t.Fatal("reload must equal the rollback truth")
	}
}

// TestReplaceAll_SerializesAgainstDurableMutation (§12): a bulk install
// cannot interleave between a durable mutation's fence comparison and its
// protected mutation. Deterministic channel barrier + bounded yields.
func TestReplaceAll_SerializesAgainstDurableMutation(t *testing.T) {
	s, _ := newDurableStore(t)
	if err := s.CreateDurable(nil, "Seed", []string{"seed.example"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.mutateDurable(nil, func() error {
			close(entered)
			<-release
			return s.addHostMem("Seed", "added.example")
		})
	}()
	<-entered
	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		s.ReplaceAll([]Entry{{Name: "Bulk", Hosts: []string{"bulk.example"}}})
	}()
	for i := 0; i < 10000; i++ {
		runtime.Gosched()
	}
	select {
	case <-bulkDone:
		t.Fatal("ReplaceAll interleaved into an open durable mutation")
	default:
	}
	close(release)
	<-adminDone
	<-bulkDone
	if adminErr != nil {
		t.Fatalf("mutation: %v", adminErr)
	}
	// Serial order: the bulk install ran after the mutation committed.
	if s.GetByName("Bulk") == nil || s.GetByName("Seed") != nil {
		t.Fatalf("final memory must be the later bulk state, got %q", catNames(s))
	}
}
