package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// withRosterOnDisk points the global cfg at a fresh Config whose roster path
// holds body, WITHOUT loading it. That is the state the finding is about: a
// process whose in-memory roster is empty while the file on disk is not.
func withRosterOnDisk(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ui_users.json")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("seed roster: %v", err)
		}
	}
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	orig := cfg
	cfg = c
	resetDurableSetupAnchorForTest()
	t.Cleanup(func() {
		cfg = orig
		resetDurableSetupAnchorForTest()
	})
	return path
}

// adminRoster builds a roster envelope whose single record carries a real
// bcrypt hash, so the hex term the loader applies is satisfied honestly rather
// than by a hand-written string that happens to be hex.
func adminRoster(t *testing.T, role UIRole) string {
	t.Helper()
	seeder := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := seeder.SetUIUser("alice", "Sup3rSecret!x", role); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	path := filepath.Join(t.TempDir(), "seed.json")
	seeder.SetUIUsersFile(path)
	if err := seeder.SaveUIUsersFile(); err != nil {
		t.Fatalf("seed save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	return string(raw)
}

// TestBootstrapWindow_ClosedByDurableRoster is the CHAOS-103 security gate. A
// process whose in-memory roster is empty but whose configured roster FILE
// records a completed setup must not be in the bootstrap window — that window
// grants unauthenticated RoleAdmin, and before the fix a second process on a
// shared /data held it open for its whole life.
func TestBootstrapWindow_ClosedByDurableRoster(t *testing.T) {
	withRosterOnDisk(t, adminRoster(t, RoleAdmin))

	if cfg.IsConfigured() {
		t.Fatal("premise broken: this Config must NOT have loaded the roster, or the test proves nothing")
	}
	if bootstrapWindowOpen() {
		t.Fatal("a durable roster with an admin must close the bootstrap window")
	}
}

// TestBootstrapWindow_OpenOnAGenuineFreshInstall is the negative control the
// whole fix lives or dies on: closing the window on a real first run would make
// a new install unconfigurable.
func TestBootstrapWindow_OpenOnAGenuineFreshInstall(t *testing.T) {
	withRosterOnDisk(t, "") // configured path, no file yet
	if !bootstrapWindowOpen() {
		t.Fatal("a fresh install with no roster file must leave the bootstrap window open")
	}

	// And with no roster path configured at all (in-memory-only roster).
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	orig := cfg
	cfg = c
	t.Cleanup(func() { cfg = orig })
	resetDurableSetupAnchorForTest()
	if !bootstrapWindowOpen() {
		t.Fatal("an unconfigured roster path must leave the bootstrap window open")
	}
}

// TestBootstrapWindow_AgreesWithTheLoader is the differential oracle. The
// derivation in rosterBytesConfigure mirrors loadUIUsersFile's acceptance, and
// the property that has to hold is ONE-DIRECTIONAL:
//
//	rosterBytesConfigure(bytes) ⇒ a Config that loaded those bytes IsConfigured()
//
// Over-claiming locks an operator out of a legitimate wizard; under-claiming
// only leaves the window open where it is open today. So the implication is
// asserted in the unsafe direction only, and the cases where the two
// deliberately differ are recorded as such rather than asserted equal.
func TestBootstrapWindow_AgreesWithTheLoader(t *testing.T) {
	adminEnvelope := adminRoster(t, RoleAdmin)
	viewerEnvelope := adminRoster(t, RoleViewer)

	var bare []uiUserRecord
	var env uiUsersFileEnvelope
	if err := json.Unmarshal([]byte(adminEnvelope), &env); err != nil {
		t.Fatalf("decode seed envelope: %v", err)
	}
	bare = env.Users
	bareJSON, err := json.Marshal(bare)
	if err != nil {
		t.Fatalf("marshal bare roster: %v", err)
	}

	badHash := env
	badHash.Users = []uiUserRecord{{Username: "alice", PassHash: "not-hex!!", Role: RoleAdmin}}
	badHashJSON, err := json.Marshal(badHash)
	if err != nil {
		t.Fatalf("marshal bad-hash roster: %v", err)
	}

	unknownRole := env
	unknownRole.Users = []uiUserRecord{{Username: "alice", PassHash: hex.EncodeToString([]byte("x")), Role: UIRole("superuser")}}
	unknownRoleJSON, err := json.Marshal(unknownRole)
	if err != nil {
		t.Fatalf("marshal unknown-role roster: %v", err)
	}

	exempt := "Exempt"
	openMode := uiUsersFileEnvelope{DefaultAuthOutcome: &exempt, Users: []uiUserRecord{}}
	openModeJSON, err := json.Marshal(openMode)
	if err != nil {
		t.Fatalf("marshal open-mode roster: %v", err)
	}

	blank := ""
	blankOutcome := uiUsersFileEnvelope{DefaultAuthOutcome: &blank, Users: []uiUserRecord{}}
	blankOutcomeJSON, err := json.Marshal(blankOutcome)
	if err != nil {
		t.Fatalf("marshal blank-outcome roster: %v", err)
	}

	cases := []struct {
		name string
		body string
	}{
		{"envelope with an admin", adminEnvelope},
		{"envelope with only a viewer", viewerEnvelope},
		{"legacy bare array", string(bareJSON)},
		{"admin whose hash is not hex", string(badHashJSON)},
		{"role this build does not enroll", string(unknownRoleJSON)},
		{"open mode via default_auth_outcome", string(openModeJSON)},
		{"present-but-empty default_auth_outcome", string(blankOutcomeJSON)},
		{"legacy unauth_mode mirror", `{"unauth_mode":true,"users":[]}`},
		{"empty envelope", `{"users":[]}`},
		{"envelope with no users key", `{"default_auth_outcome":"Default"}`},
		{"corrupt JSON", `{"users":[`},
		{"empty file", ``},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			anchor := rosterBytesConfigure([]byte(tc.body))

			// What a process that LOADED these bytes would believe. The loader
			// is the authority; the anchor is only allowed to agree or be more
			// conservative.
			path := filepath.Join(t.TempDir(), "ui_users.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			probe := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
			probe.SetUIUsersFile(path)
			_ = probe.LoadUIUsersFile() // a corrupt roster returns an error AND quarantines; both are "not configured"
			loaded := probe.IsConfigured()

			if anchor && !loaded {
				t.Fatalf("anchor claims a completed setup the loader does not: anchor=%v loader=%v body=%q",
					anchor, loaded, tc.body)
			}
			if loaded && !anchor {
				t.Logf("KNOWN CONSERVATIVE: the loader configures this roster but the anchor does not (body=%q) — "+
					"safe direction, the window stays as open as it is today", tc.body)
			}
		})
	}
}

// TestSetupComplete_RefusesWhenTheDurableRosterIsAlreadySet is the end-to-end
// half: the reproduced takeover was an UNAUTHENTICATED POST to this endpoint on
// a second process, which replaced the live gateway's roster file wholesale.
func TestSetupComplete_RefusesWhenTheDurableRosterIsAlreadySet(t *testing.T) {
	body := adminRoster(t, RoleAdmin)
	path := withRosterOnDisk(t, body)

	resetSetupLockout()
	t.Cleanup(resetSetupLockout)
	w := httptest.NewRecorder()
	apiSetupComplete(w, jsonReq(http.MethodPost, "/api/setup/complete", map[string]any{
		"user": "attacker", "pass": "Attacker-Pw0rd!xy",
	}))

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%q)", w.Code, w.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read roster: %v", err)
	}
	if string(after) != body {
		t.Fatalf("the durable roster was rewritten by a refused setup:\nbefore=%s\nafter=%s", body, after)
	}
}

// TestSetupStatus_ReportsCompleteFromTheDurableRoster pins the signal an
// operator (and the shipped wizard) reads. Before the fix the second process
// answered needsSetup:true forever and rendered the wizard to anyone.
func TestSetupStatus_ReportsCompleteFromTheDurableRoster(t *testing.T) {
	withRosterOnDisk(t, adminRoster(t, RoleAdmin))

	w := httptest.NewRecorder()
	apiSetupStatus(w, getReq("/api/setup/status"))

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["needsSetup"] != false {
		t.Fatalf("needsSetup = %v, want false", got["needsSetup"])
	}
}

// TestDurableSetupAnchor_LatchesSoTheAdminPathStopsReadingTheFile pins the cost
// control: the file read must not stay on every admin request once setup is
// durably complete.
func TestDurableSetupAnchor_LatchesSoTheAdminPathStopsReadingTheFile(t *testing.T) {
	path := withRosterOnDisk(t, adminRoster(t, RoleAdmin))

	if !durableSetupComplete() {
		t.Fatal("first observation must see the durable roster")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !durableSetupComplete() {
		t.Fatal("the latch must hold once a completed setup has been observed — removing the file must not reopen the window")
	}
}
