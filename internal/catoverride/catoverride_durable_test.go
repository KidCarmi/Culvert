package catoverride

// catoverride_durable_test.go — 2D-B.0b: the fenced durable FULL-SET
// override replacement. Stale overwrite protection (revision fence in the
// same serialization domain as replace + durable save), rollback on
// persistence failure (memory AND reload), landed-content doctrine, and the
// 2D-A publication/commit-boundary ordering against ReplaceAll/Save. Every
// truth assertion reloads a fresh store — no memory-only tests.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// testRevOf mirrors the production saasFeedOverridesFingerprint shape:
// sentinel for an empty set, else sha-256 hex of the canonical normalized
// JSON. (The production function lives in package main; the fence contract
// only requires a deterministic content function.)
func testRevOf(o Overrides) string {
	norm, err := Normalize(o)
	if err != nil {
		norm = Overrides{}
	}
	if len(norm.Added) == 0 && len(norm.Recategorized) == 0 && len(norm.Tombstones) == 0 {
		return "none"
	}
	b, _ := json.Marshal(norm)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func newDurableOverrideStore(t *testing.T) (*Store, string) {
	t.Helper()
	s := New()
	path := filepath.Join(t.TempDir(), "overrides.json")
	s.SetPathForTest(path)
	return s, path
}

func reloadOverrides(t *testing.T, path string) *Store {
	t.Helper()
	s := New()
	if err := s.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	return s
}

func TestReplaceAllDurable_SuccessIsRestartDurable(t *testing.T) {
	s, path := newDurableOverrideStore(t)
	next := Overrides{Added: map[string]string{"example.com": "SaaS Storage"}}
	stored, err := s.ReplaceAllDurable(nil, next, testRevOf)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	if len(stored.Added) != 1 {
		t.Fatalf("stored = %+v", stored)
	}
	fresh := reloadOverrides(t, path)
	if got := fresh.Get(); len(got.Added) != 1 || got.Added["example.com"] == "" {
		t.Fatalf("reload = %+v", got)
	}
	if testRevOf(fresh.Get()) != testRevOf(s.Get()) {
		t.Fatal("revision must be restart-stable")
	}
}

func TestReplaceAllDurable_StaleFenceIsStructuredConflict(t *testing.T) {
	s, _ := newDurableOverrideStore(t)
	empty := testRevOf(s.Get()) // "none"
	if _, err := s.ReplaceAllDurable(&empty, Overrides{Tombstones: []string{"gone.example"}}, testRevOf); err != nil {
		t.Fatalf("first replace: %v", err)
	}
	// The consumed token is stale; the replacement must NOT run.
	_, err := s.ReplaceAllDurable(&empty, Overrides{}, testRevOf)
	var conflict *RevisionConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("stale fence = %v, want RevisionConflictError", err)
	}
	if conflict.Asserted != empty || conflict.Current != testRevOf(s.Get()) {
		t.Fatalf("conflict payload = %+v", conflict)
	}
	if got := s.Get(); len(got.Tombstones) != 1 {
		t.Fatal("stale full-set replacement must not clear the current set (no last-write-wins)")
	}
}

func TestReplaceAllDurable_PersistFailureRollsBackMemoryAndDisk(t *testing.T) {
	s, path := newDurableOverrideStore(t)
	if _, err := s.ReplaceAllDurable(nil, Overrides{Added: map[string]string{"keep.example": "CRM"}}, testRevOf); err != nil {
		t.Fatalf("seed: %v", err)
	}
	preRev := testRevOf(s.Get())

	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		return errors.New("injected persistence failure")
	}
	t.Cleanup(func() { writeFile = prev })
	_, err := s.ReplaceAllDurable(nil, Overrides{Tombstones: []string{"doomed.example"}}, testRevOf)
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("persist failure = %v, want ErrPersist", err)
	}
	writeFile = prev
	if testRevOf(s.Get()) != preRev {
		t.Fatal("memory must return to the previous override set")
	}
	fresh := reloadOverrides(t, path)
	if got := fresh.Get(); len(got.Tombstones) != 0 || len(got.Added) != 1 {
		t.Fatalf("failed full-set replacement present after restart: %+v", got)
	}
}

func TestReplaceAllDurable_LandedContentDoctrine(t *testing.T) {
	s, path := newDurableOverrideStore(t)
	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		if err := fileutil.AtomicWrite(p, data, mode); err != nil {
			return err
		}
		return fileutil.ErrReplacedNotSynced
	}
	t.Cleanup(func() { writeFile = prev })
	if _, err := s.ReplaceAllDurable(nil, Overrides{Added: map[string]string{"landed.example": "CRM"}}, testRevOf); err != nil {
		t.Fatalf("ErrReplacedNotSynced must be a landed-content success, got %v", err)
	}
	writeFile = prev
	fresh := reloadOverrides(t, path)
	if got := fresh.Get(); len(got.Added) != 1 {
		t.Fatalf("landed content missing after reload: %+v", got)
	}
}

func TestReplaceAllDurable_EmptySetIsClearAll(t *testing.T) {
	s, path := newDurableOverrideStore(t)
	if _, err := s.ReplaceAllDurable(nil, Overrides{Added: map[string]string{"a.example": "CRM"}, Tombstones: []string{"b.example"}}, testRevOf); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cur := testRevOf(s.Get())
	if _, err := s.ReplaceAllDurable(&cur, Overrides{}, testRevOf); err != nil {
		t.Fatalf("clear-all: %v", err)
	}
	fresh := reloadOverrides(t, path)
	got := fresh.Get()
	if len(got.Added) != 0 || len(got.Recategorized) != 0 || len(got.Tombstones) != 0 {
		t.Fatalf("clear-all not durable: %+v", got)
	}
	if testRevOf(got) != "none" {
		t.Fatal("cleared set must serve the empty-set revision")
	}
}

func TestReplaceAllDurable_InvalidTargetLeavesCurrentSet(t *testing.T) {
	s, path := newDurableOverrideStore(t)
	if _, err := s.ReplaceAllDurable(nil, Overrides{Added: map[string]string{"keep.example": "CRM"}}, testRevOf); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Duplicate host across roles is invalid (ErrDuplicateHost class).
	bad := Overrides{
		Added:         map[string]string{"x.example": "CRM"},
		Recategorized: map[string]string{"x.example": "Storage"},
	}
	if _, err := s.ReplaceAllDurable(nil, bad, testRevOf); err == nil {
		t.Fatal("invalid target must be rejected")
	}
	fresh := reloadOverrides(t, path)
	if got := fresh.Get(); len(got.Added) != 1 || got.Added["keep.example"] == "" {
		t.Fatalf("current set must be untouched: %+v", got)
	}
}

// TestCommitBoundary_SaveWaitsForInFlightReplacement: a standalone Save must
// not observe (or publish) an in-flight durable replacement. The replacement
// is held open at the publication seam; the standalone Save must park on the
// mutation domain until it completes.
func TestCommitBoundary_SaveWaitsForInFlightReplacement(t *testing.T) {
	s, path := newDurableOverrideStore(t)
	prev := writeFile
	t.Cleanup(func() { writeFile = prev })
	var stubMu sync.Mutex
	calls := 0
	inWrite := make(chan struct{})
	release := make(chan struct{})
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		stubMu.Lock()
		calls++
		n := calls
		stubMu.Unlock()
		if n == 1 {
			close(inWrite)
			<-release
		}
		return fileutil.AtomicWrite(p, data, mode)
	}

	replDone := make(chan struct{})
	var replErr error
	go func() {
		defer close(replDone)
		_, replErr = s.ReplaceAllDurable(nil, Overrides{Added: map[string]string{"a.example": "CRM"}}, testRevOf)
	}()
	<-inWrite // replacement is mid-transaction (inside its publication)

	saveDone := make(chan struct{})
	go func() {
		defer close(saveDone)
		_ = s.Save()
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	select {
	case <-saveDone:
		t.Fatal("standalone Save completed while a durable replacement was open")
	default:
	}
	close(release)
	<-replDone
	<-saveDone
	if replErr != nil {
		t.Fatalf("replacement: %v", replErr)
	}
	fresh := reloadOverrides(t, path)
	if got := fresh.Get(); len(got.Added) != 1 {
		t.Fatalf("committed replacement missing after reload: %+v", got)
	}
}
