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
