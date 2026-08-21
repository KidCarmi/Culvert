package main

// auth_idp_registry_txn_test.go — P1-3 wall: IdPRegistry mutations are
// TRANSACTIONAL. Persistence runs BEFORE the candidate is published, so a
// persist failure leaves the old profiles, old live providers, and old
// credentials fully authoritative — for Upsert (create + update), Delete,
// and ReplaceAll (the CP→DP application path) — and the API reports 500
// without emitting an audit-success entry.
//
// Failure injection is deterministic and filesystem-level: the registry path
// is pointed UNDER A REGULAR FILE, so atomicWriteFile's temp-file create
// fails on every platform without mocking.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// brokenRegistryPath returns a path whose parent is a regular file, so any
// write attempt fails deterministically.
func brokenRegistryPath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(blocker, "idp_profiles.json")
}

// setRegistryPath swaps the registry's persistence target (test seam).
func setRegistryPath(t *testing.T, r *IdPRegistry, path string) {
	t.Helper()
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
}

// seedWritableLDAPRegistry installs a PERSISTED registry holding one enabled,
// working LDAP profile, and returns the live provider that must survive every
// failed mutation.
func seedWritableLDAPRegistry(t *testing.T) (reg *IdPRegistry, liveBefore IdentityProvider) {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	reg = &IdPRegistry{live: make(map[string]IdentityProvider)}
	idpRegistry = reg
	if err := reg.Load(filepath.Join(t.TempDir(), "idp_profiles.json")); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := reg.Upsert(ldapTestProfile("ldap-live", "Working AD")); err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}
	prov, ok := reg.LiveProvider("ldap-live")
	if !ok {
		t.Fatal("seed profile did not compile")
	}
	return reg, prov
}

// assertOldStateAuthoritative proves the pre-mutation state survived: same
// stored profile bytes, same live provider INSTANCE (pointer identity — not
// a recompiled lookalike), no phantom profiles.
func assertOldStateAuthoritative(t *testing.T, reg *IdPRegistry, liveBefore IdentityProvider, wantProfiles int) {
	t.Helper()
	got := reg.Get("ldap-live")
	if got == nil || got.LDAP == nil || got.LDAP.URL != "ldaps://dc01.corp.example:636" || got.Name != "Working AD" {
		t.Fatalf("stored profile changed after failed persistence: %+v", got)
	}
	liveAfter, ok := reg.LiveProvider("ldap-live")
	if !ok {
		t.Fatal("live provider lost after failed persistence")
	}
	if liveAfter != liveBefore {
		t.Fatal("live provider was replaced despite the failed persistence")
	}
	if n := len(reg.All()); n != wantProfiles {
		t.Fatalf("profile count = %d, want %d (no phantom entries)", n, wantProfiles)
	}
}

func TestIdPRegistryTxn_CreatePersistFailurePublishesNothing(t *testing.T) {
	reg, liveBefore := seedWritableLDAPRegistry(t)
	setRegistryPath(t, reg, brokenRegistryPath(t))

	err := reg.Upsert(ldapTestProfile("ldap-new", "New AD"))
	if err == nil {
		t.Fatal("Upsert must fail when persistence fails")
	}
	if !strings.Contains(err.Error(), "persisting the profile registry failed") {
		t.Fatalf("error must carry the persist-failure sentinel, got %v", err)
	}
	if reg.Get("ldap-new") != nil {
		t.Fatal("failed create leaked the new profile into the published set")
	}
	if _, ok := reg.LiveProvider("ldap-new"); ok {
		t.Fatal("failed create leaked a live provider")
	}
	assertOldStateAuthoritative(t, reg, liveBefore, 1)
}

func TestIdPRegistryTxn_UpdatePersistFailureKeepsOldProviderLive(t *testing.T) {
	reg, liveBefore := seedWritableLDAPRegistry(t)
	setRegistryPath(t, reg, brokenRegistryPath(t))

	edited := ldapTestProfile("ldap-live", "Hijacked AD")
	edited.LDAP.URL = "ldaps://evil.example:636"
	if err := reg.Upsert(edited); err == nil {
		t.Fatal("Upsert must fail when persistence fails")
	}
	assertOldStateAuthoritative(t, reg, liveBefore, 1)
}

func TestIdPRegistryTxn_DeletePersistFailureKeepsProfileAndProvider(t *testing.T) {
	reg, liveBefore := seedWritableLDAPRegistry(t)
	setRegistryPath(t, reg, brokenRegistryPath(t))

	if err := reg.Delete("ldap-live"); err == nil {
		t.Fatal("Delete must fail when persistence fails")
	}
	assertOldStateAuthoritative(t, reg, liveBefore, 1)
}

func TestIdPRegistryTxn_ReplaceAllPersistFailureKeepsOldSet(t *testing.T) {
	reg, liveBefore := seedWritableLDAPRegistry(t)
	setRegistryPath(t, reg, brokenRegistryPath(t))

	// The CP→DP application path: a fully VALID candidate that cannot be
	// persisted must reject the snapshot and keep the previous set live.
	snap := ConfigSnapshot{Version: 12, IdPProfiles: []*IdPProfile{ldapTestProfile("ldap-synced", "Synced AD")}}
	if err := syncSnapshotIdPProfiles(snap); err == nil {
		t.Fatal("snapshot IdP sync must be rejected when persistence fails")
	}
	if reg.Get("ldap-synced") != nil {
		t.Fatal("rejected snapshot leaked its profiles into the published set")
	}
	assertOldStateAuthoritative(t, reg, liveBefore, 1)
}

func TestIdPRegistryTxn_APIMutationsReport500AndAuditNothing(t *testing.T) {
	reg, liveBefore := seedWritableLDAPRegistry(t)
	setRegistryPath(t, reg, brokenRegistryPath(t))
	baseline := time.Now().UnixMilli()

	// PUT update → 500, old provider authoritative.
	w := httptest.NewRecorder()
	apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/ldap-live", ldapProfileBodyForPut("Renamed", nil)), "ldap-live")
	assertStatus(t, w, http.StatusInternalServerError)
	assertOldStateAuthoritative(t, reg, liveBefore, 1)

	// POST create → 500.
	w = httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", ldapProfileBodyForPut("Another AD", nil)))
	assertStatus(t, w, http.StatusInternalServerError)

	// DELETE → 500 (NOT 404 — the profile exists; the appliance failed).
	w = httptest.NewRecorder()
	r := jsonReq(http.MethodDelete, "/api/idp/ldap-live", nil)
	apiIdPItem(w, r, "ldap-live")
	assertStatus(t, w, http.StatusInternalServerError)
	assertOldStateAuthoritative(t, reg, liveBefore, 1)

	// No successful-mutation audit entry was emitted for any failed call.
	for _, e := range auditGet() {
		if e.TS < baseline {
			continue
		}
		if e.Action == "idp.create" || e.Action == "idp.update" || e.Action == "idp.delete" {
			t.Fatalf("failed mutation emitted a success audit entry: %+v", e)
		}
	}

	// A validation failure still reports 400 (the caller's input was bad).
	w = httptest.NewRecorder()
	bad := ldapProfileBodyForPut("Bad AD", nil)
	bad["ldap"].(map[string]any)["url"] = "https://not-ldap"
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", bad))
	assertStatus(t, w, http.StatusBadRequest)
}

func TestIdPRegistryTxn_InMemoryModeStillPublishesWithWarning(t *testing.T) {
	// Deliberate in-memory registry (path == ""): mutations publish without
	// persistence — the explicit pre-existing contract, warning retained.
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	idpRegistry = reg
	if err := reg.Upsert(ldapTestProfile("ldap-mem", "In-memory AD")); err != nil {
		t.Fatalf("in-memory Upsert: %v", err)
	}
	if _, ok := reg.LiveProvider("ldap-mem"); !ok {
		t.Fatal("in-memory mutation must publish")
	}
}
