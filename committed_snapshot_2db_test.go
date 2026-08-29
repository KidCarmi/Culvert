package main

// committed_snapshot_2db_test.go — transactional-read correction, Blocker A
// (§§1–5): a management GET that returns a mutation fence must describe
// COMMITTED truth only. MutateDurable's fn mutates the store under the inner
// lock and releases it BEFORE the version bump and the durable publication,
// and a persist failure rolls everything back to the pre-mutation state at
// the SAME version — so at the prior candidate a GET landing inside that
// window returned mutated rows paired with the UNBUMPED version, and after
// the rollback an edit derived from those phantom rows PASSED the ifVersion
// fence against the restored tree (the §2 false-pass).
//
// Corrected contract: SnapshotView acquires mutMu, so the REAL GET cannot
// complete until the open transaction reaches success or rollback; after a
// hard-failed publication it returns S0 rows at version N.
//
// Deterministic — fn-seam pause + channels + the established Gosched/select
// technique; the persistence fault is a real filesystem fault (parent of the
// store path is a regular file). Both tests fail against e221106d.

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/decryptprofile"
)

// csBreakPersistence points the store's path into a regular file so the next
// AtomicWrite fails with ENOTDIR — the real fault the rollback path handles.
func csBreakPersistence(t *testing.T, setPath func(string)) {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setPath(filepath.Join(blocker, "store.json"))
}

func TestCommittedSnapshot_CategoryGroupGETNeverExposesFailedTransaction(t *testing.T) {
	orig := globalCategoryGroups
	fresh := catgroup.New()
	fresh.SetPathForTest(filepath.Join(t.TempDir(), "groups.json"))
	globalCategoryGroups = fresh
	t.Cleanup(func() { globalCategoryGroups = orig })

	// S0 / version N, durably committed.
	if err := fresh.MutateDurable(nil, func() error {
		_, err := fresh.Add("alpha", []string{"news"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	baseVersion := fresh.Version()
	csBreakPersistence(t, fresh.SetPathForTest)

	// Open a durable transaction: content mutated to S1, paused BEFORE fn
	// returns (so before the version bump and the doomed publication).
	mutated := make(chan struct{})
	release := make(chan struct{})
	mutDone := make(chan struct{})
	var mutErr error
	go func() {
		defer close(mutDone)
		mutErr = fresh.MutateDurable(nil, func() error {
			if _, err := fresh.Add("phantom", []string{"social"}); err != nil {
				return err
			}
			close(mutated)
			<-release
			return nil
		})
	}()
	<-mutated

	// The REAL management GET.
	w := httptest.NewRecorder()
	getDone := make(chan struct{})
	go func() {
		defer close(getDone)
		apiCategoryGroups(w, getReq("/api/category-groups"))
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-getDone:
		escaped = true
	default:
	}
	close(release)
	<-mutDone
	<-getDone

	if !errors.Is(mutErr, catgroup.ErrPersist) {
		t.Fatalf("induced publication failure expected, got %v", mutErr)
	}
	var resp struct {
		Names   []string `json:"names"`
		Version int64    `json:"version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	phantomSeen := false
	for _, n := range resp.Names {
		if n == "phantom" {
			phantomSeen = true
		}
	}
	if escaped {
		// Candidate defect evidence (§2/§5 H+I): the GET completed inside the
		// open transaction. Show the captured S1/N pair and that a mutation
		// derived from it passes the fence against the rolled-back tree.
		fresh.SetPathForTest(filepath.Join(t.TempDir(), "groups.json")) // repair persistence
		v := resp.Version
		fenceErr := fresh.MutateDurable(&v, func() error {
			_, err := fresh.Add("derived-from-phantom", []string{"ai"})
			return err
		})
		t.Fatalf("management GET completed while a durable transaction was open: captured rows-with-phantom=%t at version %d (base %d); a follow-up edit asserting ifVersion=%d against the ROLLED-BACK tree returned err=%v — stale/phantom intent passes a supposedly coherent fence", phantomSeen, resp.Version, baseVersion, v, fenceErr)
	}
	// Corrected truth: the GET waited and returned committed S0/N.
	if phantomSeen {
		t.Fatalf("GET exposed the rolled-back mutation: %v", resp.Names)
	}
	if resp.Version != baseVersion {
		t.Fatalf("GET version = %d, want committed %d", resp.Version, baseVersion)
	}
}

func TestCommittedSnapshot_DecryptionProfileGETNeverExposesFailedTransaction(t *testing.T) {
	orig := globalDecryptionProfiles
	fresh := decryptprofile.New()
	fresh.SetPathForTest(filepath.Join(t.TempDir(), "profiles.json"))
	globalDecryptionProfiles = fresh
	t.Cleanup(func() { globalDecryptionProfiles = orig })

	if err := fresh.MutateDurable(nil, func() error {
		_, err := fresh.Add(DecryptionProfile{Name: "alpha"})
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	baseVersion := fresh.Version()
	csBreakPersistence(t, fresh.SetPathForTest)

	mutated := make(chan struct{})
	release := make(chan struct{})
	mutDone := make(chan struct{})
	var mutErr error
	go func() {
		defer close(mutDone)
		mutErr = fresh.MutateDurable(nil, func() error {
			if _, err := fresh.Add(DecryptionProfile{Name: "phantom"}); err != nil {
				return err
			}
			close(mutated)
			<-release
			return nil
		})
	}()
	<-mutated

	w := httptest.NewRecorder()
	getDone := make(chan struct{})
	go func() {
		defer close(getDone)
		apiDecryptionProfiles(w, getReq("/api/decryption-profiles"))
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-getDone:
		escaped = true
	default:
	}
	close(release)
	<-mutDone
	<-getDone

	if !errors.Is(mutErr, decryptprofile.ErrPersist) {
		t.Fatalf("induced publication failure expected, got %v", mutErr)
	}
	var resp struct {
		Names   []string `json:"names"`
		Version int64    `json:"version"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	phantomSeen := false
	for _, n := range resp.Names {
		if n == "phantom" {
			phantomSeen = true
		}
	}
	if escaped {
		fresh.SetPathForTest(filepath.Join(t.TempDir(), "profiles.json"))
		v := resp.Version
		fenceErr := fresh.MutateDurable(&v, func() error {
			_, err := fresh.Add(DecryptionProfile{Name: "derived-from-phantom"})
			return err
		})
		t.Fatalf("management GET completed while a durable transaction was open: captured rows-with-phantom=%t at version %d (base %d); a follow-up edit asserting ifVersion=%d against the ROLLED-BACK tree returned err=%v — stale/phantom intent passes a supposedly coherent fence", phantomSeen, resp.Version, baseVersion, v, fenceErr)
	}
	if phantomSeen {
		t.Fatalf("GET exposed the rolled-back mutation: %v", resp.Names)
	}
	if resp.Version != baseVersion {
		t.Fatalf("GET version = %d, want committed %d", resp.Version, baseVersion)
	}
}
