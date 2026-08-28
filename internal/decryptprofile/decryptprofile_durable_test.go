package decryptprofile

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
	path := filepath.Join(t.TempDir(), "decryption_profiles.json")
	s.SetPathForTest(path)
	return s, path
}

// reloadStore loads the on-disk state into a FRESH store — the restart oracle
// (2D-A §26: no test may inspect memory only).
func reloadStore(t *testing.T, path string) *Store {
	t.Helper()
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	return s
}

// TestMutateDurable_SuccessIsRestartDurable mirrors the catgroup proof: a
// confirmed nil error means a fresh store sees the mutation and the generation
// sidecar survives restart.
func TestMutateDurable_SuccessIsRestartDurable(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "strict-verify", CertVerification: "strict"})
		return err
	}); err != nil {
		t.Fatalf("MutateDurable: %v", err)
	}
	if got := s.Version(); got != 1 {
		t.Fatalf("version = %d, want 1", got)
	}
	fresh := reloadStore(t, path)
	if p := fresh.GetByName("strict-verify"); p == nil || p.CertVerification != "strict" {
		t.Fatalf("reloaded profile = %+v", fresh.GetByName("strict-verify"))
	}
	if got := fresh.Version(); got != 1 {
		t.Fatalf("reloaded version = %d, want 1", got)
	}
}

// TestMutateDurable_PersistFailureRollsBack: pre-replacement failure fails the
// request, restores memory (objects + generation + the InspectHTTP2 tri-state),
// and the previously persisted file stays the durable truth.
func TestMutateDurable_PersistFailureRollsBack(t *testing.T) {
	s, path := newDurableStore(t)
	inherit := (*bool)(nil)
	on := true
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "keep", InspectHTTP2: inherit, OnInspectError: "fail-close"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SetPathForTest(filepath.Join(blocker, "decryption_profiles.json"))
	err := s.MutateDurable(nil, func() error {
		_, aerr := s.Add(Profile{Name: "doomed", InspectHTTP2: &on})
		return aerr
	})
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("persist failure = %v, want ErrPersist", err)
	}
	if s.GetByName("doomed") != nil {
		t.Fatal("failed mutation must be rolled back in memory")
	}
	kept := s.GetByName("keep")
	if kept == nil || kept.InspectHTTP2 != nil || kept.OnInspectError != "fail-close" {
		t.Fatalf("rollback altered the surviving profile: %+v (InspectHTTP2 tri-state must stay inherit)", kept)
	}
	if s.Version() != 1 {
		t.Fatalf("version after rollback = %d, want 1", s.Version())
	}
	fresh := reloadStore(t, path)
	if fresh.GetByName("doomed") != nil || fresh.GetByName("keep") == nil {
		t.Fatalf("durable truth changed: %+v", fresh.List())
	}
}

// TestMutateDurable_VersionFence mirrors catgroup: stale token → typed
// conflict, mutation never runs.
func TestMutateDurable_VersionFence(t *testing.T) {
	s, _ := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "a"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stale := int64(0)
	ran := false
	err := s.MutateDurable(&stale, func() error { ran = true; return nil })
	var vc *VersionConflictError
	if !errors.As(err, &vc) || vc.Current != 1 || vc.Asserted != 0 {
		t.Fatalf("stale fence = %v (%+v)", err, vc)
	}
	if ran {
		t.Fatal("fenced-out mutation must never run")
	}
}

// TestMutateDurable_RenamePreservesSecurityGen: a cosmetic rename through the
// durable path must not move the profile's security generation (adaptive
// decryption-exclusion scope stays valid across rename — 2D-A §17).
func TestMutateDurable_RenamePreservesSecurityGen(t *testing.T) {
	s, path := newDurableStore(t)
	var id string
	if err := s.MutateDurable(nil, func() error {
		p, err := s.Add(Profile{Name: "fail-open-prof", OnInspectError: "fail-open", CertVerification: "strict"})
		if err != nil {
			return err
		}
		id = p.ID
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	genBefore := s.GetByID(id).SecurityGen()
	scopeBefore, sgBefore, ok := s.FailOpenScopeByID(id)
	if !ok || scopeBefore != id || sgBefore != genBefore {
		t.Fatalf("pre-rename scope = (%q,%q,%v)", scopeBefore, sgBefore, ok)
	}
	if err := s.MutateDurable(nil, func() error {
		_, rerr := s.Rename(id, "renamed-prof")
		return rerr
	}); err != nil {
		t.Fatalf("rename: %v", err)
	}
	after := s.GetByID(id)
	if after == nil || after.Name != "renamed-prof" {
		t.Fatalf("rename lost the profile: %+v", after)
	}
	if after.SecurityGen() != genBefore {
		t.Fatalf("SecurityGen moved on a cosmetic rename: %q → %q", genBefore, after.SecurityGen())
	}
	// And across restart.
	if got := reloadStore(t, path).GetByID(id).SecurityGen(); got != genBefore {
		t.Fatalf("reloaded SecurityGen = %q, want %q", got, genBefore)
	}
}

// TestMutateDurable_LandedContentDoctrine (2D-A fence correction, Blocker A —
// the §10 gap-closer, proven independently of the catgroup twin):
// ErrReplacedNotSynced keeps the in-memory mutation and reports success, and
// because content + epoch are ONE atomic envelope the landed write carries
// the new generation — after restart the pre-mutation token conflicts.
// (Against the separate-sidecar implementation this test fails: the sidecar
// write was never reached, so a restart re-exposed the pre-mutation token.)
func TestMutateDurable_LandedContentDoctrine(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "keep"})
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
		_, err := s.Add(Profile{Name: "landed"})
		return err
	}); err != nil {
		t.Fatalf("landed-content write must report success, got %v", err)
	}
	if s.GetByName("landed") == nil {
		t.Fatal("landed-content success must keep the in-memory mutation")
	}
	writeFile = prev

	fresh := reloadStore(t, path)
	if fresh.GetByName("landed") == nil {
		t.Fatal("the file the doctrine trusts must carry the profile")
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

// TestEnvelope_NoStaleTokenReuseAfterMetadataLoss (§2 — the explicit
// version-0 ABA case, decryptprofile edition): after an acknowledged content
// change, losing any sibling metadata cannot let a token from the earlier
// epoch revalidate across restart — the epoch travels inside the envelope.
func TestEnvelope_NoStaleTokenReuseAfterMetadataLoss(t *testing.T) {
	s, path := newDurableStore(t)
	tokenZero := s.Version()
	if tokenZero != 0 {
		t.Fatalf("fresh store version = %d, want 0", tokenZero)
	}
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "first", CertVerification: "strict"})
		return err
	}); err != nil {
		t.Fatalf("mutation: %v", err)
	}
	_ = os.Remove(path + ".meta")

	fresh := reloadStore(t, path)
	if fresh.GetByName("first") == nil {
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

// TestEnvelope_FailedWriteLeavesEpochAndContentCoupled mirrors the catgroup
// proof: a hard persistence failure rolls back, and the durable truth keeps
// OLD content with the OLD epoch — one file, structurally coupled.
func TestEnvelope_FailedWriteLeavesEpochAndContentCoupled(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "a"})
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
		_, aerr := s.Add(Profile{Name: "b"})
		return aerr
	})
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("objects failure = %v, want ErrPersist", err)
	}
	writeFile = prev
	fresh := reloadStore(t, path)
	if fresh.GetByName("b") != nil {
		t.Fatal("failed mutation's content must not be durable")
	}
	if got := fresh.Version(); got != 1 {
		t.Fatalf("durable epoch = %d, want 1 (coupled to the durable content)", got)
	}
}

// TestLegacyArrayFileMigration (decryptprofile edition): a pre-envelope
// bare-array file + retired sidecar loads with its recorded version; the
// first durable mutation migrates to the envelope and removes the sidecar.
func TestLegacyArrayFileMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decryption_profiles.json")
	legacy, err := json.MarshalIndent([]Profile{{ID: "legacy-id-001", Name: "legacy", CertVerification: "strict"}}, "", "  ")
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
	if s.GetByName("legacy") == nil || s.Version() != 5 {
		t.Fatalf("legacy load = version %d (want 5), profile present %v", s.Version(), s.GetByName("legacy") != nil)
	}
	if err := s.MutateDurable(nil, func() error {
		_, aerr := s.Add(Profile{Name: "migrated"})
		return aerr
	}); err != nil {
		t.Fatalf("migrating mutation: %v", err)
	}
	if _, err := os.Stat(path + ".meta"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("superseded legacy sidecar must be removed, stat err = %v", err)
	}
	fresh := reloadStore(t, path)
	if fresh.Version() != 6 || fresh.GetByName("migrated") == nil || fresh.GetByName("legacy") == nil {
		t.Fatalf("post-migration reload = version %d (want 6)", fresh.Version())
	}
}

// TestReplaceAll_SerializesAgainstMutateDurable (Blocker B, §8D/§9 —
// decryptprofile edition, proven independently): a bulk install must not
// interleave between the fence comparison and the protected mutation.
func TestReplaceAll_SerializesAgainstMutateDurable(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "seed"})
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
			_, err := s.Add(Profile{Name: "adminadd"})
			return err
		})
	}()
	<-entered

	bDone := make(chan struct{})
	go func() {
		s.ReplaceAll([]Profile{{ID: "bulk-id-01", Name: "bulk", CertVerification: "strict"}})
		close(bDone)
	}()
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

	if got := s.Version(); got != 3 {
		t.Fatalf("final version = %d, want 3 (client v2, then bulk v3)", got)
	}
	if s.GetByName("bulk") == nil || s.GetByName("adminadd") != nil {
		t.Fatal("final content must be the bulk install (wholesale replace ran last)")
	}
	fresh := reloadStore(t, path)
	if fresh.Version() != 2 || fresh.GetByName("adminadd") == nil {
		t.Fatalf("durable state = version %d (want 2 with adminadd) — client must have committed before the bulk install", fresh.Version())
	}
}

// TestVersionEpoch_AdminReplaceAllAdmin (§8E/§9): interleaved writer classes
// keep the fence strictly monotonic, in-process and across restart.
func TestVersionEpoch_AdminReplaceAllAdmin(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "a1"})
		return err
	}); err != nil {
		t.Fatalf("admin 1: %v", err)
	}
	t1 := s.Version() // 1
	s.ReplaceAll([]Profile{{ID: "bulk-id-02", Name: "bulk"}})
	if got := s.Version(); got != t1+1 {
		t.Fatalf("bulk install version = %d, want %d", got, t1+1)
	}
	if err := s.MutateDurable(&t1, func() error { return nil }); err == nil {
		t.Fatal("stale token across a bulk install must conflict")
	}
	cur := s.Version()
	if err := s.MutateDurable(&cur, func() error {
		_, err := s.Add(Profile{Name: "a2"})
		return err
	}); err != nil {
		t.Fatalf("admin 2: %v", err)
	}
	if got := s.Version(); got != 3 {
		t.Fatalf("final version = %d, want 3", got)
	}
	fresh := reloadStore(t, path)
	for _, stale := range []int64{0, 1, 2} {
		staleTok := stale
		if err := fresh.MutateDurable(&staleTok, func() error { return nil }); err == nil {
			t.Fatalf("stale token %d must conflict after restart (current %d)", stale, fresh.Version())
		}
	}
}

// ─── Publication ordering (2D-A publication-ordering correction) ───────

// namesOf joins a store's profile names for order-sensitive content
// comparison.
func namesOf(s *Store) string { return strings.Join(s.Names(), "|") }

// TestPublication_StaleBulkSaveCannotClobberAcknowledgedMutation mirrors the
// catgroup proof (symmetry proven, not assumed): the PRODUCTION bulk shape
// (ReplaceAll + Save) parks at the publication seam post-snapshot, an admin
// MutateDurable lands and is acknowledged, then the stale publication resumes
// LAST. The acknowledged mutation and its epoch must survive on disk.
func TestPublication_StaleBulkSaveCannotClobberAcknowledgedMutation(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "seed", CertVerification: "strict"})
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
		s.ReplaceAll([]Profile{{ID: "bulk-id-01", Name: "bulk", CertVerification: "strict"}})
		s.Save()
	}()
	<-bulkInWrite

	adminDone := make(chan struct{})
	var adminErr error
	go func() {
		defer close(adminDone)
		adminErr = s.MutateDurable(nil, func() error {
			_, err := s.Add(Profile{Name: "adminadd", CertVerification: "strict"})
			return err
		})
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
	close(releaseBulk) // the stale publication resumes LAST
	<-bulkDone
	<-adminDone
	if adminErr != nil {
		t.Fatalf("admin mutation must succeed, got %v", adminErr)
	}
	writeFile = prev

	memVersion := s.Version()
	fresh := reloadStore(t, path)
	if fresh.GetByName("adminadd") == nil {
		t.Fatalf("acknowledged admin mutation missing after reload — a stale publication clobbered it (adminFinishedFirst=%v)", adminFinishedFirst)
	}
	if fresh.GetByName("bulk") == nil {
		t.Fatal("bulk install missing after reload")
	}
	if got := fresh.Version(); got != 3 || got != memVersion {
		t.Fatalf("reloaded epoch = %d, want 3 (memory %d) — durable publication went backwards", got, memVersion)
	}
}

// TestPublication_AdminThenBulkSerialOrder proves the property is SERIAL
// ORDER, not "admin always wins": admin first, bulk ReplaceAll+Save second ⇒
// the final durable state is the LATER bulk state at the later epoch.
func TestPublication_AdminThenBulkSerialOrder(t *testing.T) {
	s, path := newDurableStore(t)
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "seed", CertVerification: "strict"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.MutateDurable(nil, func() error {
		_, err := s.Add(Profile{Name: "adminadd", CertVerification: "strict"})
		return err
	}); err != nil {
		t.Fatalf("admin: %v", err)
	}
	s.ReplaceAll([]Profile{{ID: "bulk-id-01", Name: "bulk", CertVerification: "strict"}})
	s.Save()

	fresh := reloadStore(t, path)
	if fresh.GetByName("bulk") == nil || fresh.GetByName("adminadd") != nil || fresh.GetByName("seed") != nil {
		t.Fatalf("final durable state must be the later BULK install, got %q", namesOf(fresh))
	}
	if got := fresh.Version(); got != 3 || got != s.Version() {
		t.Fatalf("reloaded epoch = %d, want 3 (memory %d)", got, s.Version())
	}
}

// TestPublication_AlternatingWritersConvergeOnReload (§7): repeated
// ReplaceAll+Save ↔ MutateDurable alternation; after EVERY completed
// publication a fresh reload must describe the same latest ordered durable
// state as memory — same epoch, same content, no epoch regression.
func TestPublication_AlternatingWritersConvergeOnReload(t *testing.T) {
	s, path := newDurableStore(t)
	lastVersion := int64(0)
	for i := 0; i < 8; i++ {
		if i%2 == 0 {
			s.ReplaceAll([]Profile{{Name: fmt.Sprintf("bulk%d", i), CertVerification: "strict"}})
			s.Save()
		} else {
			name := fmt.Sprintf("admin%d", i)
			if err := s.MutateDurable(nil, func() error {
				_, err := s.Add(Profile{Name: name, CertVerification: "strict"})
				return err
			}); err != nil {
				t.Fatalf("round %d admin: %v", i, err)
			}
		}
		fresh := reloadStore(t, path)
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
// concurrently; after ALL complete, disk must equal final memory exactly.
func TestPublication_ConcurrentWritersConverge(t *testing.T) {
	s, path := newDurableStore(t)
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(2)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				name := fmt.Sprintf("admin-%d-%d", w, i)
				if err := s.MutateDurable(nil, func() error {
					_, err := s.Add(Profile{Name: name, CertVerification: "strict"})
					return err
				}); err != nil {
					t.Errorf("admin %s: %v", name, err)
				}
			}
		}(w)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				s.ReplaceAll([]Profile{{Name: fmt.Sprintf("bulk-%d-%d", w, i), CertVerification: "strict"}})
				s.Save()
			}
		}(w)
	}
	wg.Wait()

	fresh := reloadStore(t, path)
	if fresh.Version() != s.Version() {
		t.Fatalf("reloaded epoch %d != final memory epoch %d", fresh.Version(), s.Version())
	}
	if namesOf(fresh) != namesOf(s) {
		t.Fatalf("reloaded content %q != final memory content %q", namesOf(fresh), namesOf(s))
	}
}

// ─── Envelope schema discriminator (fail-closed format validation) ─────

// TestEnvelopeLoad_SchemaDiscriminator mirrors the catgroup proof: for
// non-legacy-array input, exactly schema_version 1 is accepted; {}, explicit
// 0, unknown/future versions, and a negative persisted fence generation are
// refused with an explicit load error. A valid empty schema-1 envelope loads.
func TestEnvelopeLoad_SchemaDiscriminator(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"missing schema_version", `{}`, true},
		{"explicit schema_version 0", `{"schema_version":0,"version":3,"profiles":[]}`, true},
		{"future schema_version 2", `{"schema_version":2,"version":3,"profiles":[{"id":"x1","name":"p","certVerification":"strict"}]}`, true},
		{"negative version", `{"schema_version":1,"version":-5,"profiles":[]}`, true},
		{"valid empty envelope", `{"schema_version":1,"version":7,"profiles":[]}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "decryption_profiles.json")
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
				t.Fatalf("valid empty envelope must load zero profiles, got %v", s.Names())
			}
		})
	}
}
