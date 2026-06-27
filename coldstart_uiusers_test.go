package main

// D1.2a cold-start tests for ui_users.json (admin RBAC roster).
//
// LoadUIUsersFile pins the documented behavior, including a D1.2-flag
// finding worth surfacing for future hardening:
//
//   D1.2-flag: missing-file silently returns nil (no error, no users
//   loaded). The audit (D1.0 inventory) called this out as HIGH risk
//   because it permits silent default-admin bootstrap at higher levels
//   of main.go startup, which can mask attacker deletion of the file.
//   This test pins the loader-level behavior so any future change to
//   "fail closed on missing file" is intentional and reviewable.
//
// Other cases pinned: empty file, empty JSON object, empty JSON array,
// empty envelope, corrupted JSON, legacy bare-array, new envelope.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestUIUsersConfig(t *testing.T, dir string) (*Config, string) {
	t.Helper()
	path := filepath.Join(dir, "ui_users.json")
	c := &Config{}
	c.SetUIUsersFile(path)
	return c, path
}

// TestColdStart_UIUsers_MissingFile pins the silent-success behavior on
// missing file. See the D1.2-flag note at the top of this file.
func TestColdStart_UIUsers_MissingFile(t *testing.T) {
	dir := t.TempDir()
	c, _ := newTestUIUsersConfig(t, dir)

	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile (missing): %v", err)
	}
	if len(c.uiUsers) != 0 {
		t.Errorf("expected empty user roster on missing file, got %d users", len(c.uiUsers))
	}
}

func TestColdStart_UIUsers_EmptyFile(t *testing.T) {
	// Empty bytes — neither envelope nor bare-array unmarshal succeeds.
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	err := c.LoadUIUsersFile()
	if err == nil {
		t.Fatal("expected error on empty file")
	}
	if !strings.Contains(err.Error(), "unexpected end of JSON") &&
		!strings.Contains(err.Error(), "EOF") {
		t.Errorf("error should mention JSON parse failure, got: %v", err)
	}
}

func TestColdStart_UIUsers_EmptyJSONObject(t *testing.T) {
	// `{}` — envelope unmarshal succeeds with env.Users == nil. The
	// loader then falls through to bare-array unmarshal of `{}`, which
	// fails because you can't unmarshal a JSON object into []slice.
	// Net: returns error.
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write empty object: %v", err)
	}

	if err := c.LoadUIUsersFile(); err == nil {
		t.Fatal("expected error on empty JSON object (envelope path absent + bare-array fails)")
	}
}

func TestColdStart_UIUsers_EmptyJSONArray(t *testing.T) {
	// `[]` — legacy bare-array empty roster. Loader succeeds with no
	// users. This is the documented backward-compat path.
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write empty array: %v", err)
	}

	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile (empty array): %v", err)
	}
	if len(c.uiUsers) != 0 {
		t.Errorf("expected 0 users from empty bare array, got %d", len(c.uiUsers))
	}
}

func TestColdStart_UIUsers_EmptyEnvelope(t *testing.T) {
	// `{"users": []}` — envelope path with explicit empty user list.
	// Should load cleanly with no users.
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	if err := os.WriteFile(path, []byte(`{"users":[]}`), 0o600); err != nil {
		t.Fatalf("write empty envelope: %v", err)
	}

	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile (empty envelope): %v", err)
	}
	if len(c.uiUsers) != 0 {
		t.Errorf("expected 0 users from empty envelope, got %d", len(c.uiUsers))
	}
}

func TestColdStart_UIUsers_CorruptedJSON(t *testing.T) {
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	if err := os.WriteFile(path, []byte(`{this is not json`), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	if err := c.LoadUIUsersFile(); err == nil {
		t.Fatal("expected error on corrupted JSON")
	}
}

func TestColdStart_UIUsers_LegacyBareArrayWithUser(t *testing.T) {
	// Backward-compat path: file is a bare array of records, no envelope.
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	body := `[{"username":"admin","pass_hash_hex":"deadbeefdeadbeef","role":"admin"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile (legacy bare array): %v", err)
	}
	if _, ok := c.uiUsers["admin"]; !ok {
		t.Error("expected admin user from legacy bare array")
	}
}

func TestColdStart_UIUsers_NewEnvelopeWithUser(t *testing.T) {
	dir := t.TempDir()
	c, path := newTestUIUsersConfig(t, dir)
	body := `{"unauth_mode":false,"users":[{"username":"admin","pass_hash_hex":"deadbeefdeadbeef","role":"admin"}]}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write envelope: %v", err)
	}

	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile (envelope with user): %v", err)
	}
	if _, ok := c.uiUsers["admin"]; !ok {
		t.Error("expected admin user from envelope")
	}
	if c.UnauthMode() {
		t.Error("expected unauthMode=false")
	}
}
