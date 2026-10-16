package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// Guards the enterprise-operator visibility fix: an in-memory-only policy
// store (no -policy / policy_file configured) must never look identical to a
// persisted one on GET /api/policy — every prior mutation reported 200 OK
// with no signal that a restart discards the whole rulebase. Mirrors the
// IdPRegistry.Persisted() contract (auth_idp.go) that already ships this for
// identity providers.

func TestPolicyStore_Persisted_FalseWhenInMemory(t *testing.T) {
	ps := &PolicyStore{}
	if ps.Persisted() {
		t.Error("Persisted() = true for a store with no path configured")
	}
}

func TestPolicyStore_Persisted_TrueWhenPathSet(t *testing.T) {
	dir := t.TempDir()
	ps := &PolicyStore{}
	if err := ps.Load(filepath.Join(dir, "policy.json")); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ps.Persisted() {
		t.Error("Persisted() = false after Load with a real path")
	}
}

func TestAPIPolicy_GET_ReportsPersistedState(t *testing.T) {
	withFreshPolicyStore(t)

	// Force the in-memory posture regardless of what earlier tests left on
	// the shared global (withFreshPolicyStore only swaps the rule slice).
	savedPath := policyStore.path
	policyStore.path = ""
	t.Cleanup(func() { policyStore.path = savedPath })

	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("GET", "/api/policy", nil))
	if w.Code != 200 {
		t.Fatalf("GET /api/policy = %d, want 200", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	persisted, ok := resp["persisted"]
	if !ok {
		t.Fatal("GET /api/policy response has no \"persisted\" field")
	}
	if persisted != false {
		t.Errorf("persisted = %v, want false for an in-memory store", persisted)
	}

	// Now point the store at a real file and confirm the flag flips.
	f, err := os.CreateTemp(t.TempDir(), "policy-*.json")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	f.Close()
	policyStore.path = f.Name()

	w2 := httptest.NewRecorder()
	apiPolicy(w2, jsonReq("GET", "/api/policy", nil))
	var resp2 map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp2["persisted"] != true {
		t.Errorf("persisted = %v, want true once a policy file path is set", resp2["persisted"])
	}
}

// TestPolicyStore_Load_AdoptingPathPersistsExistingRules guards the review
// finding (Codex, PR #1445): applyHotReload can call Load with a path that
// does not exist yet while the store already holds in-memory-only rules —
// e.g. an admin edits rules with no -policy configured, then a SIGHUP config
// reload turns persistence on. Load must not leave Persisted() claiming
// durability while those rules exist nowhere on disk; a crash before the
// next mutation would silently discard them exactly as if the warning had
// never fired.
func TestPolicyStore_Load_AdoptingPathPersistsExistingRules(t *testing.T) {
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "pre-existing", Action: ActionAllow}})

	dir := t.TempDir()
	path := filepath.Join(dir, "newly-adopted.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("test setup: %s already exists", path)
	}

	if err := ps.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ps.Persisted() {
		t.Fatal("Persisted() = false immediately after adopting a path")
	}

	// The claim must be true, not just the flag: the file must actually now
	// hold the pre-existing in-memory rule.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("adopting a path did not persist the in-memory rules: %v", err)
	}
	fresh := &PolicyStore{}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("reload from the adopted path: %v", err)
	}
	got := fresh.List()
	if len(got) != 1 || got[0].Name != "pre-existing" {
		t.Fatalf("reload after adoption = %+v, want the pre-existing rule recovered", got)
	}
}

// TestPolicyStore_Load_AdoptFailureNeverFailsLoad pins the fail-safe half:
// a failed best-effort persist on adoption (e.g. the target directory does
// not exist) must not turn Load into a fatal error — initPolicy calls
// logFatalf on any Load error, so that would convert a graceful in-memory
// boot into a crash loop, which is exactly the class of regression the
// CHAOS-50 boot-path conventions in this codebase exist to prevent. It also
// pins the visibility half: while no rules exist on disk, Persisted() is
// false (the GUI warning stays up) until a later write succeeds.
func TestPolicyStore_Load_AdoptFailureNeverFailsLoad(t *testing.T) {
	// This test deliberately provokes a real AtomicWrite failure, which
	// updates the process-global storage-health record (storage_health.go).
	// Reset on both edges so it cannot leak into another test's assertions
	// about a clean/undegraded baseline — the exact hazard documented on
	// resetStorageWriteHealthForTest's other callers (diagnostics_test.go).
	resetStorageWriteHealthForTest()
	t.Cleanup(resetStorageWriteHealthForTest)

	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "unsaved", Action: ActionAllow}})

	dir := filepath.Join(t.TempDir(), "no-such-dir")
	path := filepath.Join(dir, "policy.json")
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load must not fail when the best-effort adopt-persist fails, got: %v", err)
	}
	// The path is configured but no rules exist on disk: Persisted() must
	// keep reporting false so the GUI warning stays visible.
	if ps.Persisted() {
		t.Fatal("Persisted() = true after a failed adopt-write, but no rules are on disk")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no policy file on disk after failed adopt-write, stat err = %v", err)
	}

	// Once the target becomes writable, the next successful save clears the
	// flag and Persisted() reports true again.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ps.SaveErr(); err != nil {
		t.Fatalf("SaveErr after making the directory: %v", err)
	}
	if !ps.Persisted() {
		t.Error("Persisted() = false after a later successful save")
	}
}

// TestPolicyStore_Load_ConcurrentWithPersisted_NoRace guards a Codex finding
// (PR #1445): Load assigned ps.path without holding ps.mu, while Persisted()
// (called on every GET /api/policy) reads it under ps.mu.RLock() — a real
// data race between the SIGHUP goroutine (applyHotReload -> Load) and any
// concurrent HTTP handler. `go test -race` only catches a race it actually
// observes, so this drives both sides concurrently rather than relying on
// the ordinary sequential tests above to happen to trip it.
func TestPolicyStore_Load_ConcurrentWithPersisted_NoRace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	ps := &PolicyStore{}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				ps.Persisted()
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				ps.SaveErr() //nolint:errcheck // exercising concurrent access, not asserting outcomes
			}
		}
	}()

	for i := 0; i < 200; i++ {
		if err := ps.Load(path); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Load: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// TestPolicyStore_Load_MalformedFileDoesNotAdoptPath guards the other half
// of the same Codex finding: a hot reload (applyHotReload) survives a Load
// error and keeps running, so a SIGHUP pointed at a malformed policy file
// must not make the store silently claim that path — Persisted() would then
// report true for a location that does not actually hold the live rules,
// and initPolicy's own reload of that same file at the next restart would
// hard-fail to boot with no warning ever having been shown.
func TestPolicyStore_Load_MalformedFileDoesNotAdoptPath(t *testing.T) {
	dir := t.TempDir()
	goodPath := filepath.Join(dir, "good.json")
	if err := os.WriteFile(goodPath, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := &PolicyStore{}
	if err := ps.Load(goodPath); err != nil {
		t.Fatalf("Load good: %v", err)
	}
	if !ps.Persisted() {
		t.Fatal("Persisted() = false after a successful Load")
	}

	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ps.Load(badPath); err == nil {
		t.Fatal("Load of malformed JSON should return an error")
	}

	ps.mu.RLock()
	got := ps.path
	ps.mu.RUnlock()
	if got != goodPath {
		t.Errorf("path = %q after a failed Load, want unchanged %q", got, goodPath)
	}
	if !ps.Persisted() {
		t.Error("Persisted() = false after a failed reload, but the OLD path is still valid and unchanged")
	}
}

// TestAPIPolicy_GET_DraftPersistedReflectsCandidateNotRunning guards a
// second Codex finding: GET /api/policy always reported the RUNNING store's
// persisted flag, even while rendering the draft candidate (draft:true).
// The candidate's own persistence path is wired up only at startup
// (initPolicyDraft), so a SIGHUP that turns persistence on for the running
// store never rewires the draft — a staged edit can still be lost on
// restart while the response claimed persisted:true for the exact rulebase
// the admin was looking at.
func TestAPIPolicy_GET_DraftPersistedReflectsCandidateNotRunning(t *testing.T) {
	draftTestSetup(t)

	// Running store IS persisted (as if a hot reload had turned persistence
	// on) — the candidate's own path (reset to "" by draftTestSetup) is not.
	f, err := os.CreateTemp(t.TempDir(), "policy-*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	savedPath := policyStore.path
	policyStore.path = f.Name()
	t.Cleanup(func() { policyStore.path = savedPath })

	setRequireCommit(true)
	if w := createRuleViaAPI(t, "candidate-only", ""); w.Code != http.StatusOK {
		t.Fatalf("stage candidate = %d (%s)", w.Code, w.Body.String())
	}
	if !policyDraftEngaged() {
		t.Fatal("draft not engaged after staging")
	}

	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("GET", "/api/policy", nil))
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["draft"] != true {
		t.Fatalf("draft = %v, want true", resp["draft"])
	}
	if resp["persisted"] != false {
		t.Errorf("persisted = %v, want false — the draft candidate has no persistence path even though the running store does", resp["persisted"])
	}
}

// TestPolicyStore_StalePathSaveDoesNotClearAdoptionFailure pins a Codex
// finding (PR #1445): a save that snapshotted the OLD path before a SIGHUP
// adopted a new, unwritable one must not clear the adoption-failure flag when
// it later succeeds — it wrote a superseded path, and the current one still
// holds nothing.
func TestPolicyStore_StalePathSaveDoesNotClearAdoptionFailure(t *testing.T) {
	resetStorageWriteHealthForTest()
	t.Cleanup(resetStorageWriteHealthForTest)

	oldPath := filepath.Join(t.TempDir(), "old-policy.json")
	ps := &PolicyStore{}
	ps.ReplaceAll([]PolicyRule{{Priority: 1, Name: "r", Action: ActionAllow}})

	newPath := filepath.Join(t.TempDir(), "no-such-dir", "policy.json")
	if err := ps.Load(newPath); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if ps.Persisted() {
		t.Fatal("precondition: adoption of an unwritable path must report Persisted()=false")
	}
	// The in-flight mutation's save, which snapshotted oldPath earlier,
	// now completes successfully.
	if err := ps.saveTo(oldPath); err != nil {
		t.Fatalf("saveTo(oldPath): %v", err)
	}
	if ps.Persisted() {
		t.Fatal("a successful save to a SUPERSEDED path cleared the adoption failure — the warning is hidden while the current path holds no policy file")
	}
}

// TestAPIPolicy_GET_DraftPersistedFalseAfterPolicyDirMoves pins the Codex
// finding (PR #1445): a SIGHUP moving proxy.policy_file to another directory
// leaves policyDraft.path at the OLD sibling, which the next boot's
// initPolicyDraft never reloads — the draft must report persisted:false
// until its file is where the next boot will look.
func TestAPIPolicy_GET_DraftPersistedFalseAfterPolicyDirMoves(t *testing.T) {
	draftTestSetup(t)

	oldDir, newDir := t.TempDir(), t.TempDir()
	savedPath := policyStore.path
	policyStore.path = filepath.Join(oldDir, "policy.json")
	t.Cleanup(func() { policyStore.path = savedPath })
	policyDraft.mu.Lock()
	policyDraft.path = policyDraftPathFor(policyStore.path)
	policyDraft.mu.Unlock()
	t.Cleanup(func() {
		policyDraft.mu.Lock()
		policyDraft.path = ""
		policyDraft.mu.Unlock()
	})

	setRequireCommit(true)
	if w := createRuleViaAPI(t, "candidate-moved", ""); w.Code != http.StatusOK {
		t.Fatalf("stage candidate = %d (%s)", w.Code, w.Body.String())
	}
	get := func() any {
		w := httptest.NewRecorder()
		apiPolicy(w, jsonReq("GET", "/api/policy", nil))
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp["draft"] != true {
			t.Fatalf("draft = %v, want true", resp["draft"])
		}
		return resp["persisted"]
	}
	if p := get(); p != true {
		t.Fatalf("control: draft sibling of the live policy file must report persisted:true, got %v", p)
	}
	policyStore.mu.Lock()
	policyStore.path = filepath.Join(newDir, "policy.json")
	policyStore.mu.Unlock()
	if p := get(); p != false {
		t.Errorf("persisted = %v, want false — the draft file is not where the next boot will reload it", p)
	}
}

// TestPolicyStore_Load_AdoptionNeverClaimsPersistedBeforeWrite guards a
// Codex finding (PR #1445): Load's adopt-missing-file branch used to clear
// adoptUnsaved to false BEFORE calling SaveErr, opening a window — between
// that unlock and the atomic write actually landing — in which a concurrent
// Persisted() call read path != "" && !adoptUnsaved (i.e. persisted:true)
// for a path that had no file on disk yet. adoptUnsaved is now set to true
// in the SAME critical section that publishes ps.path, and only SaveErr's
// own successful write (via saveTo) clears it, so Persisted() can never
// read true ahead of the write it describes. Runs Load and Persisted
// concurrently on a writable directory (so every adopt-write succeeds) and
// asserts persisted-implies-file-exists holds throughout, not just at the
// end.
func TestPolicyStore_Load_AdoptionNeverClaimsPersistedBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	ps := &PolicyStore{}

	stop := make(chan struct{})
	var violation atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Read path and the persisted verdict in the SAME critical
			// section Persisted() itself uses — a separate re-read of
			// ps.path after calling Persisted() would race the writer
			// loop's next Load() advancing ps.path to a newer, not-yet-
			// written path, which is a bug in this test, not in Load().
			ps.mu.RLock()
			path := ps.path
			persisted := path != "" && !ps.adoptUnsaved.Load()
			ps.mu.RUnlock()
			if !persisted {
				continue
			}
			if _, err := os.Stat(path); err != nil {
				violation.Store(true)
			}
		}
	}()

	for i := 0; i < 500; i++ {
		path := filepath.Join(dir, fmt.Sprintf("policy-%d.json", i))
		if err := ps.Load(path); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Load: %v", err)
		}
	}
	close(stop)
	wg.Wait()

	if violation.Load() {
		t.Fatal("Persisted() reported true for a path whose file was not yet on disk")
	}
}
