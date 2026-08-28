package main

// defaultauthoutcome_durability_test.go — 2C.0c: PUT
// /api/settings/default-auth-outcome is durable-or-nothing.
//
// The pre-2C.0c handler called the unchecked SetDefaultAuthOutcome (persist
// failure only logged) and returned 200 regardless — so a global
// authentication-default change could report success and silently revert on
// the next restart (the exact hazard setDefaultAuthOutcomeChecked was built
// to close for the setup path). The handler now uses the checked setter: a
// pre-replacement persist failure rolls the in-memory value back and fails
// the request 500; ErrReplacedNotSynced counts as landed (commit doctrine).

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
)

// defaultAuthOutcomeTestSetup points cfg's users file at a temp path and
// restores the previous path + in-memory outcome afterward.
func defaultAuthOutcomeTestSetup(t *testing.T) (usersPath string) {
	t.Helper()
	usersPath = t.TempDir() + "/ui_users.json"
	cfg.mu.Lock()
	prevPath := cfg.uiUsersFile
	prevOutcome := cfg.defaultAuthOutcome
	cfg.uiUsersFile = usersPath
	cfg.mu.Unlock()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.uiUsersFile = prevPath
		cfg.defaultAuthOutcome = prevOutcome
		cfg.mu.Unlock()
	})
	return usersPath
}

func putDefaultAuthOutcome(outcome string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	apiDefaultAuthOutcome(w, jsonReq("PUT", "/api/settings/default-auth-outcome",
		map[string]any{"defaultAuthOutcome": outcome}))
	return w
}

func persistedDefaultAuthOutcome(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read users file: %v", err)
	}
	var env struct {
		DefaultAuthOutcome *string `json:"default_auth_outcome"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse users file: %v", err)
	}
	if env.DefaultAuthOutcome == nil {
		t.Fatal("users file carries no default_auth_outcome")
	}
	return *env.DefaultAuthOutcome
}

func TestDefaultAuthOutcome_SuccessIsDurable(t *testing.T) {
	usersPath := defaultAuthOutcomeTestSetup(t)

	w := putDefaultAuthOutcome("Exempt")
	assertStatus(t, w, 200)
	if cfg.DefaultAuthOutcome() != OutcomeExempt {
		t.Fatal("in-memory outcome not Exempt after 200")
	}
	if got := persistedDefaultAuthOutcome(t, usersPath); got != "Exempt" {
		t.Fatalf("persisted outcome = %q, want Exempt", got)
	}

	w = putDefaultAuthOutcome("Default")
	assertStatus(t, w, 200)
	if got := persistedDefaultAuthOutcome(t, usersPath); got != "Default" {
		t.Fatalf("persisted outcome = %q, want Default", got)
	}
}

func TestDefaultAuthOutcome_PersistFailureRollsBackAnd500s(t *testing.T) {
	usersPath := defaultAuthOutcomeTestSetup(t)

	// Establish a durable Exempt baseline.
	assertStatus(t, putDefaultAuthOutcome("Exempt"), 200)

	// Fault: displace the users file with a non-empty directory so
	// AtomicWrite's rename fails pre-replacement (2B.0b harness technique).
	prev := blockPath(t, usersPath)

	w := putDefaultAuthOutcome("Default")
	if w.Code != 500 {
		t.Fatalf("persist failure must fail the request, got %d (%s)", w.Code, w.Body.String())
	}
	// In-memory value rolled back: the endpoint never 2xx'd, so runtime truth
	// must still be the durably persisted Exempt.
	if cfg.DefaultAuthOutcome() != OutcomeExempt {
		t.Fatal("failed persist mutated the in-memory outcome (would silently revert on restart)")
	}
	unblockPath(t, usersPath, prev)
	if got := persistedDefaultAuthOutcome(t, usersPath); got != "Exempt" {
		t.Fatalf("durable outcome = %q, want the pre-failure Exempt", got)
	}
}

func TestDefaultAuthOutcome_RejectsInvalidValues(t *testing.T) {
	defaultAuthOutcomeTestSetup(t)
	for _, bad := range []string{"", "exempt", "CredentialRequired", "garbage"} {
		if w := putDefaultAuthOutcome(bad); w.Code != 400 {
			t.Fatalf("outcome %q: want 400, got %d", bad, w.Code)
		}
	}
}
