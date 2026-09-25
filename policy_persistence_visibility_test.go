package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
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
