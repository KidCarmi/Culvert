package catgroup

import (
	"encoding/json"
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

// newDurableStore returns a store persisting into a fresh temp dir.
func newDurableStore(t *testing.T) (*Store, string) {
	t.Helper()
	s := New()
	path := filepath.Join(t.TempDir(), "category_groups.json")
	s.SetPathForTest(path)
	return s, path
}

// reload loads the on-disk state into a FRESH store — the restart oracle. No
// test may inspect memory only (2D-A §26).
func reload(t *testing.T, path string) *Store {
	t.Helper()
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	return s
}

// TestMutateDurable_SuccessIsRestartDurable: a confirmed nil error means a
// fresh store loading the same path sees the mutation, and the generation
// sidecar survives the restart (monotonic fence).
func TestMutateDurable_SuccessIsRestartDurable(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Prod Allowed", []string{"ai", "news"})
		return err
	}); err != nil {
		t.Fatalf("MutateDurable: %v", err)
	}
	if got := s.Version(); got != 1 {
		t.Fatalf("version after first mutation = %d, want 1", got)
	}
	fresh := reload(t, path)
	if g := fresh.GetByName("Prod Allowed"); g == nil || len(g.Categories) != 2 {
		t.Fatalf("reloaded group = %+v, want 2 categories", fresh.GetByName("Prod Allowed"))
	}
	if got := fresh.Version(); got != 1 {
		t.Fatalf("reloaded version = %d, want 1 (sidecar survives restart)", got)
	}
}

// TestMutateDurable_PersistFailureRollsBackMemoryAndDisk: a pre-replacement
// write failure must fail the request, restore the in-memory state (objects
// AND generation), and leave the previously persisted file the durable truth.
func TestMutateDurable_PersistFailureRollsBack(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Keep", []string{"news"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Break persistence with a REAL filesystem fault: the parent of the new
	// path is a regular file, so AtomicWrite's temp-file create fails with
	// ENOTDIR even for root.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SetPathForTest(filepath.Join(blocker, "category_groups.json"))

	err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Doomed", []string{"ai"})
		return err
	})
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("persist failure = %v, want ErrPersist", err)
	}
	if s.GetByName("Doomed") != nil {
		t.Fatal("failed mutation must be rolled back in memory")
	}
	if s.GetByName("Keep") == nil {
		t.Fatal("rollback lost the pre-existing group")
	}
	if got := s.Version(); got != 1 {
		t.Fatalf("version after rollback = %d, want 1 (failed mutation never happened)", got)
	}
	// The durable truth at the ORIGINAL path is untouched.
	fresh := reload(t, path)
	if fresh.GetByName("Doomed") != nil || fresh.GetByName("Keep") == nil {
		t.Fatalf("durable truth changed: %+v", fresh.List())
	}
}

// TestMutateDurable_VersionFence: a stale assertion returns the typed conflict
// and the mutation NEVER runs; a matching assertion proceeds.
func TestMutateDurable_VersionFence(t *testing.T) {
	s, _ := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("A", nil)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stale := int64(0) // pre-mutation token
	ran := false
	err := s.MutateDurable(&stale, func() error { ran = true; return nil })
	var vc *VersionConflictError
	if !errors.As(err, &vc) {
		t.Fatalf("stale fence = %v, want *VersionConflictError", err)
	}
	if vc.Current != 1 || vc.Asserted != 0 {
		t.Fatalf("conflict payload = %+v, want current=1 asserted=0", vc)
	}
	if ran {
		t.Fatal("fenced-out mutation must never run")
	}
	cur := s.Version()
	if err := s.MutateDurable(&cur, func() error {
		_, err := s.Add("B", nil)
		return err
	}); err != nil {
		t.Fatalf("matching fence: %v", err)
	}
	if s.Version() != cur+1 {
		t.Fatalf("version = %d, want %d", s.Version(), cur+1)
	}
}

// TestMutateDurable_FnErrorMutatesNothingDurable: a validation error from fn
// (name collision) leaves version and disk untouched.
func TestMutateDurable_FnErrorMutatesNothing(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("A", nil)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := s.MutateDurable(nil, func() error {
		_, aerr := s.Add("a", nil) // case-insensitive collision
		return aerr
	})
	if !errors.Is(err, ErrNameTaken) {
		t.Fatalf("collision = %v, want ErrNameTaken", err)
	}
	if s.Version() != 1 {
		t.Fatalf("version moved on a failed mutation: %d", s.Version())
	}
	if got := len(reload(t, path).List()); got != 1 {
		t.Fatalf("disk groups = %d, want 1", got)
	}
}

// TestMutateDurable_LandedContentDoctrine (2D-A fence correction, Blocker A —
// the §10 gap-closer): ErrReplacedNotSynced means the replacement already
// carries the new objects — memory must NOT roll back and the call reports
// success. Because content and epoch are ONE atomic envelope, the landed
// write ALSO carries the new generation: after restart the effective epoch is
// NOT the pre-mutation token, and that stale token conflicts. (Against the
// separate-sidecar implementation this test fails: the sidecar write was
// never reached, so a restart re-exposed the pre-mutation token.)
func TestMutateDurable_LandedContentDoctrine(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Keep", nil)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	staleToken := s.Version() // the pre-mutation epoch a slow client holds

	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		if err := fileutil.AtomicWrite(p, data, mode); err != nil {
			return err
		}
		if p == path {
			return fmt.Errorf("parent dir fsync: injected: %w", fileutil.ErrReplacedNotSynced)
		}
		return nil
	}
	t.Cleanup(func() { writeFile = prev })

	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Landed", []string{"ai"})
		return err
	}); err != nil {
		t.Fatalf("landed-content write must report success, got %v", err)
	}
	if s.GetByName("Landed") == nil {
		t.Fatal("landed-content success must keep the in-memory mutation")
	}
	writeFile = prev // restart path uses the real reader/writer

	fresh := reload(t, path)
	if fresh.GetByName("Landed") == nil {
		t.Fatal("the file the doctrine trusts must actually carry the object")
	}
	if got := fresh.Version(); got != staleToken+1 {
		t.Fatalf("reloaded epoch = %d, want %d — landed content must carry the landed epoch", got, staleToken+1)
	}
	ran := false
	err := fresh.MutateDurable(&staleToken, func() error { ran = true; return nil })
	var vc *VersionConflictError
	if !errors.As(err, &vc) || ran {
		t.Fatalf("stale pre-mutation token must conflict after restart, got err=%v ran=%v", err, ran)
	}
}

// TestEnvelope_NoStaleTokenReuseAfterMetadataLoss (2D-A fence correction §2 —
// the explicit version-0 ABA case): a client may legitimately hold token 0
// from a fresh store. After an ACKNOWLEDGED content change, no restart state
// may revalidate that token — the epoch travels inside the content envelope,
// so losing a separate metadata file (removed here to simulate the retired
// sidecar being lost) cannot resurrect it. (Against the separate-sidecar
// implementation this test fails: content reloaded with version 0 and the
// stale token false-passed.)
func TestEnvelope_NoStaleTokenReuseAfterMetadataLoss(t *testing.T) {
	s, path := newDurableStore(t)
	tokenZero := s.Version()
	if tokenZero != 0 {
		t.Fatalf("fresh store version = %d, want 0", tokenZero)
	}
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("First", []string{"news"})
		return err
	}); err != nil {
		t.Fatalf("mutation: %v", err)
	}
	// Any sibling metadata is gone (lost volume file, retired-sidecar cleanup —
	// the envelope must not depend on it).
	_ = os.Remove(path + ".meta")

	fresh := reload(t, path)
	if fresh.GetByName("First") == nil {
		t.Fatal("acknowledged content missing after restart")
	}
	if got := fresh.Version(); got < 1 {
		t.Fatalf("reloaded epoch = %d, want >= 1 after an acknowledged change", got)
	}
	err := fresh.MutateDurable(&tokenZero, func() error { return nil })
	var vc *VersionConflictError
	if !errors.As(err, &vc) {
		t.Fatalf("token 0 from the pre-change epoch must conflict after restart, got %v", err)
	}
}

// TestEnvelope_FailedWriteLeavesEpochAndContentCoupled: a hard persistence
// failure rolls the mutation back, and the durable truth keeps OLD content
// with the OLD epoch — one file, structurally incapable of diverging.
func TestEnvelope_FailedWriteLeavesEpochAndContentCoupled(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("A", nil)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		if p == path {
			return errors.New("injected objects-file failure")
		}
		return fileutil.AtomicWrite(p, data, mode)
	}
	t.Cleanup(func() { writeFile = prev })
	err := s.MutateDurable(nil, func() error {
		_, aerr := s.Add("B", nil)
		return aerr
	})
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("objects failure = %v, want ErrPersist", err)
	}
	writeFile = prev
	fresh := reload(t, path)
	if fresh.GetByName("B") != nil {
		t.Fatal("failed mutation's content must not be durable")
	}
	if got := fresh.Version(); got != 1 {
		t.Fatalf("durable epoch = %d, want 1 (coupled to the durable content)", got)
	}
}

// TestLegacyArrayFileMigration: a pre-envelope bare-array file with the
// retired sidecar loads with its recorded version; the first durable mutation
// migrates the format (envelope carries content + epoch) and removes the
// superseded sidecar so a stale epoch can never be resurrected from it.
func TestLegacyArrayFileMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "category_groups.json")
	legacy, err := json.MarshalIndent([]Group{{ID: "legacy-id-001", Name: "Legacy", Categories: []string{"news"}}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".meta", []byte(`{"version":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("legacy load: %v", err)
	}
	if s.GetByName("Legacy") == nil || s.Version() != 5 {
		t.Fatalf("legacy load = version %d (want 5), group present %v", s.Version(), s.GetByName("Legacy") != nil)
	}
	if err := s.MutateDurable(nil, func() error {
		_, aerr := s.Add("Migrated", nil)
		return aerr
	}); err != nil {
		t.Fatalf("migrating mutation: %v", err)
	}
	if _, err := os.Stat(path + ".meta"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded legacy sidecar must be removed, stat err = %v", err)
	}
	fresh := reload(t, path)
	if fresh.Version() != 6 || fresh.GetByName("Migrated") == nil || fresh.GetByName("Legacy") == nil {
		t.Fatalf("post-migration reload = version %d (want 6), groups %v", fresh.Version(), fresh.List())
	}
}

// TestReplaceAll_SerializesAgainstMutateDurable (2D-A fence correction,
// Blocker B — §8D): a bulk install must NOT interleave between the fence
// comparison and the protected mutation. Deterministic barriers: the client
// mutation parks INSIDE fn (holding the serialization domain); ReplaceAll is
// then started and must not complete until the client finishes. (Against the
// unserialized implementation, ReplaceAll completes during the pause and the
// stale-asserted client mutates the bulk-installed content — this test fails
// at the interleaving check.)
func TestReplaceAll_SerializesAgainstMutateDurable(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Seed", nil)
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	token := s.Version() // == 1

	entered := make(chan struct{})
	release := make(chan struct{})
	aDone := make(chan error, 1)
	go func() {
		aDone <- s.MutateDurable(&token, func() error {
			close(entered)
			<-release
			_, err := s.Add("AdminAdd", nil)
			return err
		})
	}()
	<-entered // the client holds the serialization domain, fence already checked

	bDone := make(chan struct{})
	go func() {
		s.ReplaceAll([]Group{{ID: "bulk-id-01", Name: "Bulk", Categories: []string{"ai"}}})
		close(bDone)
	}()
	// Give the scheduler ample opportunity to run the bulk install; with the
	// serialization fix it is BLOCKED on the shared mutation domain, so it can
	// never complete while the client is parked inside fn. (Bounded yields, not
	// wall-clock sleeps: the property is a mutex, not a timing window.)
	for i := 0; i < 10000; i++ {
		runtime.Gosched()
	}
	select {
	case <-bDone:
		t.Fatal("ReplaceAll interleaved between the fence comparison and the protected mutation")
	default:
	}

	close(release)
	if err := <-aDone; err != nil {
		t.Fatalf("serialized client mutation must succeed, got %v", err)
	}
	<-bDone

	// Exactly one serial order: client (v2, persisted) then bulk (v3, memory).
	if got := s.Version(); got != 3 {
		t.Fatalf("final version = %d, want 3 (client v2, then bulk v3)", got)
	}
	if s.GetByName("Bulk") == nil || s.GetByName("AdminAdd") != nil {
		t.Fatalf("final content must be the bulk install (wholesale replace ran last): %v", s.List())
	}
	// The durable envelope holds the CLIENT's committed state (ReplaceAll does
	// not persist) — proving the client ran first.
	fresh := reload(t, path)
	if fresh.Version() != 2 || fresh.GetByName("AdminAdd") == nil {
		t.Fatalf("durable state = version %d (want 2 with AdminAdd) — client must have committed before the bulk install", fresh.Version())
	}
}

// TestVersionEpoch_AdminReplaceAllAdmin (§8E): interleaved writer classes keep
// the fence strictly monotonic — no token issued against an earlier state can
// alias a later one, in-process or across restart.
func TestVersionEpoch_AdminReplaceAllAdmin(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("A1", nil)
		return err
	}); err != nil {
		t.Fatalf("admin 1: %v", err)
	}
	t1 := s.Version() // 1
	s.ReplaceAll([]Group{{ID: "bulk-id-02", Name: "Bulk", Categories: nil}})
	if got := s.Version(); got != t1+1 {
		t.Fatalf("bulk install version = %d, want %d", got, t1+1)
	}
	// The stale admin token from before the bulk install must conflict.
	if err := s.MutateDurable(&t1, func() error { return nil }); err == nil {
		t.Fatal("stale token across a bulk install must conflict")
	}
	cur := s.Version()
	if err := s.MutateDurable(&cur, func() error {
		_, err := s.Add("A2", nil)
		return err
	}); err != nil {
		t.Fatalf("admin 2: %v", err)
	}
	if got := s.Version(); got != 3 {
		t.Fatalf("final version = %d, want 3", got)
	}
	fresh := reload(t, path)
	for _, stale := range []int64{0, 1, 2} {
		staleTok := stale
		if err := fresh.MutateDurable(&staleTok, func() error { return nil }); err == nil {
			t.Fatalf("stale token %d must conflict after restart (current %d)", stale, fresh.Version())
		}
	}
}

// ─── Publication ordering (2D-A publication-ordering correction) ───────

// namesOf joins a store's group names for order-sensitive content comparison.
func namesOf(s *Store) string { return strings.Join(s.Names(), "|") }

// TestPublication_StaleBulkSaveCannotClobberAcknowledgedMutation pins the
// durable-publication ordering invariant against the PRODUCTION bulk shape
// (ReplaceAll + Save — cluster snapshot apply / config import / rollback)
// racing an admin MutateDurable:
//
//	seed v1 → bulk installs v2 and its Save parks at the publication seam
//	(post-snapshot, pre-write) → an admin mutation lands v3 → the parked
//	stale publication resumes LAST.
//
// An unserialized SaveErr lets the admin persist v3, return a confirmed 2xx,
// and then be overwritten by the resumed v2 snapshot — the acknowledged
// mutation silently vanishes from disk. The corrected SaveErr holds the
// publication serializer across snapshot→write, so the admin publication
// waits, then snapshots the CURRENT state; either way the final durable
// state carries the acknowledged mutation and its epoch. Bounded yields +
// channels only — no wall-clock sleeps.
func TestPublication_StaleBulkSaveCannotClobberAcknowledgedMutation(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Seed", []string{"news"})
		return err
	}); err != nil {
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
			close(bulkInWrite) // parked at the publication seam, snapshot taken
			<-releaseBulk
		}
		return fileutil.AtomicWrite(p, data, mode)
	}

	bulkDone := make(chan struct{})
	go func() {
		defer close(bulkDone)
		s.ReplaceAll([]Group{{ID: "bulk-id-01", Name: "Bulk", Categories: []string{"ai"}}})
		s.Save()
	}()
	<-bulkInWrite

	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.MutateDurable(nil, func() error {
			_, err := s.Add("AdminAdd", []string{"marketing"})
			return err
		})
	}()

	// Give the admin mutation every opportunity to complete AROUND the parked
	// stale save (possible only on an unserialized implementation; a
	// serialized one parks it on the publication lock until the release).
	adminFinishedFirst := false
	for i := 0; i < 200000 && !adminFinishedFirst; i++ {
		select {
		case <-adminDone:
			adminFinishedFirst = true
		default:
			runtime.Gosched()
		}
	}
	close(releaseBulk) // the stale publication resumes LAST
	<-bulkDone
	<-adminDone
	if adminErr != nil {
		t.Fatalf("admin mutation must succeed, got %v", adminErr)
	}
	writeFile = prev

	memVersion := s.Version()
	fresh := reload(t, path)
	if fresh.GetByName("AdminAdd") == nil {
		t.Fatalf("acknowledged admin mutation missing after reload — a stale publication clobbered it (adminFinishedFirst=%v)", adminFinishedFirst)
	}
	if fresh.GetByName("Bulk") == nil {
		t.Fatal("bulk install missing after reload")
	}
	if got := fresh.Version(); got != 3 || got != memVersion {
		t.Fatalf("reloaded epoch = %d, want 3 (memory %d) — durable publication went backwards", got, memVersion)
	}
}

// TestPublication_AdminThenBulkSerialOrder proves the property is SERIAL
// ORDER, not "admin always wins": when the admin mutation completes first and
// the bulk ReplaceAll+Save follows, the final durable state is the LATER bulk
// state (wholesale replace), at the later epoch.
func TestPublication_AdminThenBulkSerialOrder(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Seed", []string{"news"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("AdminAdd", []string{"marketing"})
		return err
	}); err != nil {
		t.Fatalf("admin: %v", err)
	}
	s.ReplaceAll([]Group{{ID: "bulk-id-01", Name: "Bulk", Categories: []string{"ai"}}})
	s.Save()

	fresh := reload(t, path)
	if fresh.GetByName("Bulk") == nil || fresh.GetByName("AdminAdd") != nil || fresh.GetByName("Seed") != nil {
		t.Fatalf("final durable state must be the later BULK install, got %q", namesOf(fresh))
	}
	if got := fresh.Version(); got != 3 || got != s.Version() {
		t.Fatalf("reloaded epoch = %d, want 3 (memory %d)", got, s.Version())
	}
}

// TestPublication_AlternatingWritersConvergeOnReload (§7): repeated
// ReplaceAll+Save ↔ MutateDurable alternation; after EVERY completed
// publication a fresh reload must describe the same latest ordered durable
// state as memory — same epoch, same content, no acknowledged mutation lost,
// no epoch regression.
func TestPublication_AlternatingWritersConvergeOnReload(t *testing.T) {
	s, path := newDurableStore(t)
	lastVersion := int64(0)
	for i := 0; i < 8; i++ {
		if i%2 == 0 {
			s.ReplaceAll([]Group{{Name: fmt.Sprintf("Bulk%d", i), Categories: []string{"ai"}}})
			s.Save()
		} else {
			name := fmt.Sprintf("Admin%d", i)
			if err := s.MutateDurable(nil, func() error {
				_, err := s.Add(name, []string{"news"})
				return err
			}); err != nil {
				t.Fatalf("round %d admin: %v", i, err)
			}
		}
		fresh := reload(t, path)
		if fresh.Version() != s.Version() {
			t.Fatalf("round %d: reloaded epoch %d != memory %d", i, fresh.Version(), s.Version())
		}
		if namesOf(fresh) != namesOf(s) {
			t.Fatalf("round %d: reloaded content %q != memory %q", i, namesOf(fresh), namesOf(s))
		}
		if fresh.Version() <= lastVersion {
			t.Fatalf("round %d: epoch did not advance (%d -> %d)", i, lastVersion, fresh.Version())
		}
		lastVersion = fresh.Version()
	}
}

// TestPublication_ConcurrentWritersConverge (§7, bounded concurrency under
// -race): admin MutateDurable and bulk ReplaceAll+Save writers run
// concurrently; after ALL complete, the final durable state must equal the
// final memory state exactly (the last publication in serializer order
// snapshots a state at least as new as every completed mutation, so disk
// converges on memory).
func TestPublication_ConcurrentWritersConverge(t *testing.T) {
	s, path := newDurableStore(t)
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				name := fmt.Sprintf("Admin-%d-%d", w, i)
				if err := s.MutateDurable(nil, func() error {
					_, err := s.Add(name, []string{"news"})
					return err
				}); err != nil {
					t.Errorf("admin %s: %v", name, err)
				}
			}
		}(w)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				s.ReplaceAll([]Group{{Name: fmt.Sprintf("Bulk-%d-%d", w, i), Categories: []string{"ai"}}})
				s.Save()
			}
		}(w)
	}
	wg.Wait()

	fresh := reload(t, path)
	if fresh.Version() != s.Version() {
		t.Fatalf("reloaded epoch %d != final memory epoch %d", fresh.Version(), s.Version())
	}
	if namesOf(fresh) != namesOf(s) {
		t.Fatalf("reloaded content %q != final memory content %q", namesOf(fresh), namesOf(s))
	}
}

// ─── Envelope schema discriminator (fail-closed format validation) ─────

// TestEnvelopeLoad_SchemaDiscriminator: for non-legacy-array input, exactly
// schema_version 1 is accepted. {} (missing discriminator), explicit 0, an
// unknown/future version, and a negative persisted fence generation are
// refused with an explicit load error — never silently parsed with today's
// struct. A legitimate empty schema-1 envelope stays valid.
func TestEnvelopeLoad_SchemaDiscriminator(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"missing schema_version", `{}`, true},
		{"explicit schema_version 0", `{"schema_version":0,"version":3,"groups":[]}`, true},
		{"future schema_version 2", `{"schema_version":2,"version":3,"groups":[{"id":"x1","name":"G","categories":["ai"]}]}`, true},
		{"negative version", `{"schema_version":1,"version":-5,"groups":[]}`, true},
		{"valid empty envelope", `{"schema_version":1,"version":7,"groups":[]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "category_groups.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			s := New()
			err := s.Load(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load must refuse %s (fail-closed format validation), got nil", tc.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid envelope refused: %v", err)
			}
			if got := s.Version(); got != 7 {
				t.Fatalf("valid empty envelope version = %d, want 7", got)
			}
			if len(s.List()) != 0 {
				t.Fatalf("valid empty envelope must load zero groups, got %v", s.Names())
			}
		})
	}
}

// ─── Commit boundary (2D-A commit-boundary correction) ─────────────────

// TestCommitBoundary_FailedMutationNeverVisibleOnDisk (§7): a standalone
// Save (the production ReplaceAll+Save bulk shape) racing an admin
// MutateDurable whose fn has mutated memory but NOT yet returned must not be
// able to publish that in-flight state. Sequence: durable seed → ReplaceAll
// installs BULK (its following Save still pending) → admin fn mutates and
// blocks pre-return → the standalone Save runs → admin fn released → the
// admin's OWN publication is failed hard → MutateDurable rolls back and
// returns ErrPersist. Required final truth: a fresh reload equals the
// rollback state — the failed, unacknowledged admin mutation must NOT exist
// on disk at any epoch. On an implementation whose Save does not enter the
// mutation domain, the standalone Save publishes uncommitted-new-content +
// old-epoch and the failed mutation survives on disk. Channels + bounded
// yields only — no sleeps.
func TestCommitBoundary_FailedMutationNeverVisibleOnDisk(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Keep", []string{"news"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.ReplaceAll([]Group{{ID: "bulk-id-01", Name: "Bulk", Categories: []string{"ai"}}}) // v2, Save pending

	prev := writeFile
	t.Cleanup(func() { writeFile = prev })
	var stubMu sync.Mutex
	failArmed := false
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		stubMu.Lock()
		if failArmed && p == path {
			failArmed = false
			stubMu.Unlock()
			return errors.New("injected admin publication failure")
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
		adminErr = s.MutateDurable(nil, func() error {
			_, err := s.Add("AdminAdd", []string{"marketing"})
			if err != nil {
				return err
			}
			close(fnMutated) // memory now carries the in-flight mutation
			<-fnRelease      // blocked BEFORE fn returns
			return nil
		})
	}()
	<-fnMutated

	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		s.Save() // the bulk caller's pending standalone Save
	}()

	// Give the standalone Save every opportunity to complete while the
	// mutation transaction is still open (possible only when Save does not
	// enter the mutation domain).
	saveCompletedWhileFnBlocked := false
	for i := 0; i < 200000 && !saveCompletedWhileFnBlocked; i++ {
		select {
		case <-saveDone:
			saveCompletedWhileFnBlocked = true
		default:
			runtime.Gosched()
		}
	}
	if saveCompletedWhileFnBlocked {
		t.Error("standalone Save completed while the mutation transaction was open — it published an unfinished mutation")
	}

	// Fail the admin's OWN durable publication (the next store-path write).
	stubMu.Lock()
	failArmed = true
	stubMu.Unlock()
	close(fnRelease)
	<-adminDone
	<-saveDone
	if !errors.Is(adminErr, ErrPersist) {
		t.Fatalf("admin publication failure = %v, want ErrPersist", adminErr)
	}
	writeFile = prev

	// Memory rolled back to the pre-admin truth.
	if s.GetByName("AdminAdd") != nil || s.Version() != 2 {
		t.Fatalf("memory rollback truth violated: version %d, names %q", s.Version(), namesOf(s))
	}
	// Disk must equal the rollback truth — the failed mutation must not be
	// durable at ANY epoch.
	fresh := reload(t, path)
	if fresh.GetByName("AdminAdd") != nil {
		t.Fatalf("failed, unacknowledged admin mutation exists on disk (names %q, epoch %d)", namesOf(fresh), fresh.Version())
	}
	if fresh.Version() != 2 || namesOf(fresh) != namesOf(s) {
		t.Fatalf("reload = epoch %d names %q, want rollback truth epoch 2 names %q", fresh.Version(), namesOf(fresh), namesOf(s))
	}
}

// TestCommitBoundary_SaveWaitsForMutationBoundary (§8, the crash-window pin
// independent of any forced write error): while a MutateDurable fn is blocked
// after its memory mutation, a standalone Save must NOT complete — an
// external publication observing an unfinished transaction is forbidden even
// when the transaction later succeeds. After the boundary closes, the Save
// publishes the committed state.
func TestCommitBoundary_SaveWaitsForMutationBoundary(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add("Keep", []string{"news"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	fnMutated := make(chan struct{})
	fnRelease := make(chan struct{})
	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.MutateDurable(nil, func() error {
			_, err := s.Add("AdminAdd", []string{"marketing"})
			if err != nil {
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
		t.Fatal("standalone Save completed while the mutation transaction was open — published an unfinished mutation")
	default:
	}

	close(fnRelease)
	<-adminDone
	<-saveDone
	if adminErr != nil {
		t.Fatalf("admin mutation must succeed, got %v", adminErr)
	}
	fresh := reload(t, path)
	if fresh.GetByName("AdminAdd") == nil || fresh.Version() != s.Version() || namesOf(fresh) != namesOf(s) {
		t.Fatalf("committed state not durable after boundary closed: epoch %d names %q (memory %d %q)", fresh.Version(), namesOf(fresh), s.Version(), namesOf(s))
	}
}
