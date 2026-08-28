package catgroup

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

// TestMutateDurable_LandedContentDoctrine: ErrReplacedNotSynced means the
// renamed file already carries the new objects — memory must NOT roll back and
// the call reports success (repository landed-content doctrine, §5).
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
		_, err := s.Add("Landed", []string{"ai"})
		return err
	}); err != nil {
		t.Fatalf("landed-content write must report success, got %v", err)
	}
	if s.GetByName("Landed") == nil {
		t.Fatal("landed-content success must keep the in-memory mutation")
	}
	writeFile = prev // reload uses the real reader anyway
	if reload(t, path).GetByName("Landed") == nil {
		t.Fatal("the file the doctrine trusts must actually carry the object")
	}
}

// TestMetaSidecar_NeverNewerThanObjects: an objects-file failure skips the meta
// write, so a recorded generation can never describe objects that are not on
// disk.
func TestMetaSidecar_NeverNewerThanObjects(t *testing.T) {
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
	var meta storeMeta
	mdata, rerr := os.ReadFile(path + ".meta")
	if rerr != nil {
		t.Fatalf("meta sidecar missing: %v", rerr)
	}
	if err := json.Unmarshal(mdata, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Version != 1 {
		t.Fatalf("meta version = %d, want 1 (never newer than the objects file)", meta.Version)
	}
}
