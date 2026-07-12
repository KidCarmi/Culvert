package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// policy_optlock_test.go — optimistic concurrency for policy mutations (P2
// rule-set generation counter; authority docs/design/POLICY-ARCHITECTURE-
// FUTURE.md §6). A write carrying ?ifVersion=N is rejected (409) when the
// rule-set has advanced past N, so a stale multi-admin edit cannot silently
// overwrite another admin's change. Absent ifVersion = no check (back-compat).

func currentPolicyVersion(t *testing.T) int64 {
	t.Helper()
	v, _ := policyStore.policyVersion()
	return v
}

func TestPolicyOptLock_MatchingVersionSucceeds(t *testing.T) {
	withFreshPolicyStore(t)
	v := currentPolicyVersion(t)
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", fmt.Sprintf("/api/policy?ifVersion=%d", v), map[string]any{
		"name": "optlock-ok", "action": "Allow", "priority": 300,
	}))
	if w.Code != 200 {
		t.Fatalf("create with matching ifVersion = %d (%s), want 200", w.Code, w.Body.String())
	}
}

func TestPolicyOptLock_StaleVersionConflicts(t *testing.T) {
	withFreshPolicyStore(t)
	// Admin A and B both load version v.
	v := currentPolicyVersion(t)
	// Admin A commits first — bumps the version.
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", fmt.Sprintf("/api/policy?ifVersion=%d", v), map[string]any{
		"name": "admin-a", "action": "Allow", "priority": 301,
	}))
	if w.Code != 200 {
		t.Fatalf("admin A create = %d (%s), want 200", w.Code, w.Body.String())
	}
	// Admin B commits against the now-stale version v → 409.
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", fmt.Sprintf("/api/policy?ifVersion=%d", v), map[string]any{
		"name": "admin-b", "action": "Allow", "priority": 302,
	}))
	if w.Code != 409 {
		t.Fatalf("admin B stale create = %d (%s), want 409", w.Code, w.Body.String())
	}
	var body struct {
		CurrentVersion int64 `json:"currentVersion"`
		YourVersion    int64 `json:"yourVersion"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("409 body not JSON: %v (%s)", err, w.Body.String())
	}
	if body.YourVersion != v || body.CurrentVersion <= v {
		t.Errorf("409 body versions = your %d / current %d; want your %d / current > %d",
			body.YourVersion, body.CurrentVersion, v, v)
	}
	// Admin B's rule must NOT have been created.
	for _, r := range policyStore.List() {
		if r.Name == "admin-b" {
			t.Error("stale create was applied despite the 409")
		}
	}
}

func TestPolicyOptLock_AbsentVersionSkipsCheck(t *testing.T) {
	withFreshPolicyStore(t)
	// Bump the version so any stale check would fire…
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{"name": "seed", "action": "Allow", "priority": 303}))
	if w.Code != 200 {
		t.Fatalf("seed = %d", w.Code)
	}
	// …a write WITHOUT ifVersion is unaffected (backward compatible).
	w = httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy", map[string]any{"name": "no-version", "action": "Allow", "priority": 304}))
	if w.Code != 200 {
		t.Fatalf("create without ifVersion = %d (%s), want 200 (no check)", w.Code, w.Body.String())
	}
}

func TestPolicyOptLock_InvalidVersionRejected(t *testing.T) {
	withFreshPolicyStore(t)
	w := httptest.NewRecorder()
	apiPolicy(w, jsonReq("POST", "/api/policy?ifVersion=notanumber", map[string]any{
		"name": "bad", "action": "Allow", "priority": 305,
	}))
	if w.Code != 400 {
		t.Fatalf("create with non-numeric ifVersion = %d; want 400", w.Code)
	}
}
