package main

// auth_idp_ldap_persistence_test.go — Slice 2 wall (ADR-0025):
//   - write-only bind-credential API semantics (redact / preserve / replace /
//     explicit clear / no audit leak),
//   - registry persistence round-trip,
//   - legacy-YAML authority shadowing (startup + runtime, guarded),
//   - CP→DP snapshot parity for LDAP profiles (sync, reject-preserves-last-good,
//     unenrolled redaction).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Redaction / write-only semantics ─────────────────────────────────────────

func TestPublicIdPProfile_RedactsLDAPBindPassword(t *testing.T) {
	p := ldapTestProfile("ldap-redact", "LDAP Redact")
	got := publicIdPProfile(p)
	if got.LDAP == nil {
		t.Fatal("LDAP config missing from public profile")
	}
	if got.LDAP.BindPassword != "" {
		t.Fatalf("public bindPassword = %q, want empty", got.LDAP.BindPassword)
	}
	if !got.LDAP.BindCredentialConfigured {
		t.Error("bindCredentialConfigured must be true when a credential is stored")
	}
	if p.LDAP.BindPassword != "svc-secret" {
		t.Fatal("source profile was mutated by redaction")
	}
	// No credential stored → metadata bit false.
	p2 := ldapTestProfile("ldap-none", "None")
	p2.LDAP.BindPassword = ""
	if publicIdPProfile(p2).LDAP.BindCredentialConfigured {
		t.Error("bindCredentialConfigured must be false without a stored credential")
	}
}

func ldapProfileBodyForPut(name string, extra map[string]any) map[string]any {
	ldap := map[string]any{
		"url":    "ldaps://dc01.corp.example:636",
		"bindDn": "CN=svc-proxy,OU=Service,DC=corp,DC=example",
		"baseDn": "DC=corp,DC=example",
	}
	for k, v := range extra {
		ldap[k] = v
	}
	return map[string]any{
		"name":    name,
		"type":    "ldap",
		"enabled": false,
		"ldap":    ldap,
	}
}

func seedLDAPProfile(t *testing.T, id string) {
	t.Helper()
	p := ldapTestProfile(id, "Corporate AD")
	p.Enabled = false
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
}

func TestAPIIdPItem_PutPreservesLDAPBindPasswordWhenOmitted(t *testing.T) {
	withTestIdPRegistry(t)
	seedLDAPProfile(t, "ldap-preserve")

	w := httptest.NewRecorder()
	// Edit an unrelated field; bindPassword field entirely absent from body.
	r := jsonReq(http.MethodPut, "/api/idp/ldap-preserve", ldapProfileBodyForPut("Renamed AD", nil))
	apiIdPItem(w, r, "ldap-preserve")
	assertStatus(t, w, http.StatusOK)

	if strings.Contains(w.Body.String(), "svc-secret") {
		t.Fatalf("response leaked the preserved bind credential: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"bindCredentialConfigured":true`) {
		t.Errorf("response must report the credential as configured: %s", w.Body.String())
	}
	got := idpRegistry.Get("ldap-preserve")
	if got.LDAP.BindPassword != "svc-secret" {
		t.Fatalf("stored bindPassword = %q, want preserved", got.LDAP.BindPassword)
	}
	if got.Name != "Renamed AD" {
		t.Fatalf("unrelated edit was not applied: %q", got.Name)
	}
}

func TestAPIIdPItem_PutReplacesLDAPBindPassword(t *testing.T) {
	withTestIdPRegistry(t)
	seedLDAPProfile(t, "ldap-replace")

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/ldap-replace",
		ldapProfileBodyForPut("Corporate AD", map[string]any{"bindPassword": "new-secret"}))
	apiIdPItem(w, r, "ldap-replace")
	assertStatus(t, w, http.StatusOK)

	if strings.Contains(w.Body.String(), "new-secret") {
		t.Fatalf("response leaked the replaced bind credential: %s", w.Body.String())
	}
	if got := idpRegistry.Get("ldap-replace"); got.LDAP.BindPassword != "new-secret" {
		t.Fatalf("stored bindPassword = %q, want replaced", got.LDAP.BindPassword)
	}
}

func TestAPIIdPItem_PutExplicitEmptyClearsLDAPBindPassword(t *testing.T) {
	withTestIdPRegistry(t)
	seedLDAPProfile(t, "ldap-clear")

	w := httptest.NewRecorder()
	// Field PRESENT and empty = deliberate clear (distinguishable from omission).
	r := jsonReq(http.MethodPut, "/api/idp/ldap-clear",
		ldapProfileBodyForPut("Corporate AD", map[string]any{"bindPassword": ""}))
	apiIdPItem(w, r, "ldap-clear")
	assertStatus(t, w, http.StatusOK)

	if got := idpRegistry.Get("ldap-clear"); got.LDAP.BindPassword != "" {
		t.Fatalf("stored bindPassword = %q, want cleared", got.LDAP.BindPassword)
	}
	if strings.Contains(w.Body.String(), `"bindCredentialConfigured":true`) {
		t.Errorf("cleared credential must not report as configured: %s", w.Body.String())
	}
}

func TestAPIIdPList_GetNeverReturnsLDAPBindPassword(t *testing.T) {
	withTestIdPRegistry(t)
	seedLDAPProfile(t, "ldap-list")

	w := httptest.NewRecorder()
	apiIdPList(w, getReq("/api/idp"))
	assertStatus(t, w, http.StatusOK)
	if strings.Contains(w.Body.String(), "svc-secret") {
		t.Fatalf("GET /api/idp leaked a bind credential: %s", w.Body.String())
	}
}

func TestAuditIdPProfile_OmitsLDAPBindPassword(t *testing.T) {
	p := ldapTestProfile("ldap-audit", "Audit")
	if got := auditIdPProfile(p); got.LDAP == nil || got.LDAP.BindPassword != "" {
		t.Fatal("audit projection must blank the bind credential")
	}
}

func TestNormalizeIdPProfileWriteInput_StripsEchoedMetadata(t *testing.T) {
	p := ldapTestProfile("ldap-echo", "Echo")
	p.LDAP.BindCredentialConfigured = true // client echoed the GET projection
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	t.Cleanup(func() { _ = idpRegistry.Delete("ldap-echo") })
	if got := idpRegistry.Get("ldap-echo"); got.LDAP.BindCredentialConfigured {
		t.Error("stored profile carries the derived bindCredentialConfigured bit — must be recomputed on read only")
	}
}

// ── Persistence round-trip ───────────────────────────────────────────────────

func TestIdPRegistry_LDAPProfilePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "idp_profiles.json")

	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := idpRegistry.Load(path); err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	if err := idpRegistry.Upsert(ldapTestProfile("ldap-persist", "Persist AD")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// File must be 0600 and carry the raw credential (DP-local auth needs it).
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("idp_profiles.json mode = %v, want 0600", fi.Mode().Perm())
	}

	fresh := &IdPRegistry{live: make(map[string]IdentityProvider)}
	if err := fresh.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := fresh.Get("ldap-persist")
	if got == nil || got.Type != IdPTypeLDAP || got.LDAP == nil {
		t.Fatalf("reloaded profile = %+v", got)
	}
	if got.LDAP.BindPassword != "svc-secret" {
		t.Errorf("reloaded bindPassword = %q, want stored credential", got.LDAP.BindPassword)
	}
	if _, ok := fresh.LiveProvider("ldap-persist"); !ok {
		t.Error("enabled LDAP profile must compile on load")
	}
}

// ── Legacy YAML authority shadowing ──────────────────────────────────────────

// withLocalAdminUser gives cfg a local admin account (the canShadowLegacyLDAP
// anchor) and restores the prior auth state afterwards.
func withLocalAdminUser(t *testing.T) {
	t.Helper()
	prevUser := cfg.GetUser()
	if err := cfg.SetAuth("shadow-admin", "Shadow-admin-1!"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() {
		if prevUser == "" {
			_ = cfg.SetAuth("", "")
		}
	})
}

func TestLegacyLDAP_StartupShadowedByRegistryProfile(t *testing.T) {
	withTestIdPRegistry(t)
	withLocalAdminUser(t)
	if err := idpRegistry.Upsert(ldapTestProfile("ldap-authority", "Registry AD")); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	cfg.SetProvider(nil)

	err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{
		LDAP: LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"},
	})
	if err != nil {
		t.Fatalf("loadLegacyAuthProviders: %v", err)
	}
	if got := cfg.snapshotAuthBackend().provider; got != nil {
		t.Fatalf("legacy YAML LDAP was wired (%T) despite an enabled registry LDAP profile — two authorities", got)
	}
}

func TestLegacyLDAP_StartupWiresWithoutRegistryProfile(t *testing.T) {
	withTestIdPRegistry(t)
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	cfg.SetProvider(nil)

	err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{
		LDAP: LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"},
	})
	if err != nil {
		t.Fatalf("loadLegacyAuthProviders: %v", err)
	}
	if _, ok := cfg.snapshotAuthBackend().provider.(*LDAPAuth); !ok {
		t.Fatal("legacy YAML LDAP must keep working when no registry LDAP profile exists")
	}
}

func TestLegacyLDAP_RuntimeDeactivatedOnRegistryCreate(t *testing.T) {
	withTestIdPRegistry(t)
	withLocalAdminUser(t)
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetProvider(legacy)

	// Admin creates an enabled registry LDAP profile via the API.
	w := httptest.NewRecorder()
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = true
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", body))
	assertStatus(t, w, http.StatusOK)

	if got := cfg.snapshotAuthBackend().provider; got != nil {
		t.Fatalf("legacy YAML LDAP provider still active (%T) after registry LDAP creation", got)
	}
}

func TestLegacyLDAP_RuntimeShadowingGuardedWhenSetupWouldFailOpen(t *testing.T) {
	withTestIdPRegistry(t)
	// NO local admin user and Default outcome: deactivation would flip
	// cfg.IsConfigured() false and the admin UI would fail open. The legacy
	// provider must stay wired (registry still wins in the Basic chain).
	if cfg.GetUser() != "" {
		t.Skip("test requires no local user in cfg")
	}
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetProvider(legacy)
	if err := idpRegistry.Upsert(ldapTestProfile("ldap-guard", "Guard AD")); err != nil {
		t.Fatal(err)
	}

	enforceLegacyLDAPShadowing()
	if _, ok := cfg.snapshotAuthBackend().provider.(*LDAPAuth); !ok {
		t.Fatal("guarded shadowing removed the setup-gate anchor — admin UI would fail open")
	}
	if !cfg.IsConfigured() {
		t.Fatal("IsConfigured flipped false")
	}
}

// ── CP→DP snapshot parity ────────────────────────────────────────────────────

func TestSnapshotSync_LDAPProfileAppliesAtomically(t *testing.T) {
	withTestIdPRegistry(t)
	snap := ConfigSnapshot{Version: 7, IdPProfiles: []*IdPProfile{ldapTestProfile("ldap-sync", "Synced AD")}}
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		t.Fatalf("sync: %v", err)
	}
	prov, ok := idpRegistry.LiveProvider("ldap-sync")
	if !ok || prov.Name() != "ldap:ldap-sync" {
		t.Fatalf("synced LDAP profile not live: %v %v", prov, ok)
	}
}

func TestSnapshotSync_InvalidLDAPProfileRejectsCandidatePreservingLastGood(t *testing.T) {
	withTestIdPRegistry(t)
	// Establish a working registry (last-known-good).
	if err := idpRegistry.ReplaceAll([]*IdPProfile{ldapTestProfile("ldap-good", "Good AD")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bad := ldapTestProfile("ldap-bad", "Bad AD")
	bad.LDAP.URL = "https://not-ldap.example" // invalid scheme → compile/validation failure
	err := syncSnapshotIdPProfiles(ConfigSnapshot{Version: 8, IdPProfiles: []*IdPProfile{bad}})
	if err == nil {
		t.Fatal("malformed LDAP profile must reject the whole IdP candidate")
	}
	// Old registry state must remain fully live — no half-applied set.
	if _, ok := idpRegistry.LiveProvider("ldap-good"); !ok {
		t.Fatal("rejected candidate wiped the previously working provider set")
	}
	if idpRegistry.Get("ldap-bad") != nil {
		t.Fatal("rejected profile leaked into the registry")
	}
}

func TestRedactUnenrolledSnapshot_CoversLDAPProfiles(t *testing.T) {
	snap := ConfigSnapshot{IdPProfiles: []*IdPProfile{ldapTestProfile("ldap-x", "X")}, SessionHMAC: "aa"}
	redactUnenrolledSnapshot(&snap)
	if snap.IdPProfiles != nil {
		t.Fatal("unenrolled snapshot redaction must drop IdP profiles (bind credentials)")
	}
}

func TestCloneIdPProfiles_DeepCopiesLDAPConfig(t *testing.T) {
	src := []*IdPProfile{ldapTestProfile("ldap-clone", "Clone")}
	out := cloneIdPProfiles(src)
	if out[0].LDAP == src[0].LDAP {
		t.Fatal("LDAP config pointer shared between clone and source")
	}
	out[0].LDAP.BindPassword = "tampered"
	if src[0].LDAP.BindPassword != "svc-secret" {
		t.Fatal("mutating the clone reached the source profile")
	}
}

// TestConfigSnapshot_LDAPProfileJSONRoundTrip pins the wire shape: an LDAP
// profile survives ConfigSnapshot marshal/unmarshal with its credential (for
// enrolled DPs) and its config intact.
func TestConfigSnapshot_LDAPProfileJSONRoundTrip(t *testing.T) {
	snap := ConfigSnapshot{Version: 3, IdPProfiles: []*IdPProfile{ldapTestProfile("ldap-wire", "Wire AD")}}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var got ConfigSnapshot
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.IdPProfiles) != 1 || got.IdPProfiles[0].LDAP == nil {
		t.Fatalf("round-trip lost the LDAP config: %+v", got.IdPProfiles)
	}
	if got.IdPProfiles[0].LDAP.BindPassword != "svc-secret" {
		t.Error("round-trip lost the bind credential (enrolled DP sync would break)")
	}
	if got.IdPProfiles[0].LDAP.BaseDN != "DC=corp,DC=example" {
		t.Error("round-trip lost the base DN")
	}
}
