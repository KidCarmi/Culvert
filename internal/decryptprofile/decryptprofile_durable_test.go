package decryptprofile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// TestMutateDurable_LandedContentDoctrine: ErrReplacedNotSynced keeps the
// in-memory mutation and reports success.
func TestMutateDurable_LandedContentDoctrine(t *testing.T) {
	s, path := newDurableStore(t)
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
	if reloadStore(t, path).GetByName("landed") == nil {
		t.Fatal("the file the doctrine trusts must carry the profile")
	}
}

// TestMetaSidecar_NeverNewerThanObjects mirrors catgroup.
func TestMetaSidecar_NeverNewerThanObjects(t *testing.T) {
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
	var meta storeMeta
	mdata, rerr := os.ReadFile(path + ".meta")
	if rerr != nil {
		t.Fatalf("meta sidecar missing: %v", rerr)
	}
	if err := json.Unmarshal(mdata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != 1 {
		t.Fatalf("meta version = %d, want 1", meta.Version)
	}
}
