package main

// auth_idp_ldap_persistence_test.go — Slice 2 wall (ADR-0025):
//   - write-only bind-credential API semantics (redact / preserve / replace /
//     explicit clear / no audit leak),
//   - registry persistence round-trip,
//   - legacy-YAML authority shadowing (startup + runtime, guarded),
//   - CP→DP snapshot parity for LDAP profiles (sync, reject-preserves-last-good,
//     unenrolled redaction).

import (
	"encoding/base64"
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

// ── Legacy YAML authority + durable cutover (ADR-0025 / P1-2) ────────────────
//
// SINGLE-AUTHORITY WALL: one operational LDAP authenticator, no hidden legacy
// fallback, durable cutover across registry disable/delete and restarts, and
// an admin console that stays gated with NO local admin account.

// withLegacyLDAPAuthorityReset isolates the process-global cutover sentinel
// and the retained YAML block, and points the admin-settings file at a temp
// path so the cutover's best-effort persist cannot touch other tests' state.
func withLegacyLDAPAuthorityReset(t *testing.T) {
	t.Helper()
	prev := legacyLDAPRetiredFlag.Load()
	legacyLDAPRetiredFlag.Store(false)
	t.Cleanup(func() { legacyLDAPRetiredFlag.Store(prev) })

	adminSettingsMu.Lock()
	prevPath := adminSettingsPath
	adminSettingsPath = filepath.Join(t.TempDir(), "admin_settings.json")
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsMu.Lock()
		adminSettingsPath = prevPath
		adminSettingsMu.Unlock()
	})

	withLegacyLDAPYAML(t, &LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
}

// withNoLocalAdminAuth clears the legacy single-user credential so the test
// runs in the "no local admin account" deployment shape, restoring afterwards.
func withNoLocalAdminAuth(t *testing.T) {
	t.Helper()
	cfg.mu.Lock()
	prevUser, prevHash := cfg.user, cfg.passHash
	prevOutcome := cfg.defaultAuthOutcome
	cfg.user, cfg.passHash = "", nil
	cfg.defaultAuthOutcome = OutcomeDefault
	cfg.authRevision++
	cfg.mu.Unlock()
	cfg.cache.clear()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.user, cfg.passHash, cfg.defaultAuthOutcome = prevUser, prevHash, prevOutcome
		cfg.authRevision++
		cfg.mu.Unlock()
		cfg.cache.clear()
	})
}

func TestLegacyLDAP_StartupShadowedByRegistryProfile(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPAuthorityReset(t)
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
	if !legacyLDAPRetired() {
		t.Fatal("startup cutover observation must set the durable retirement sentinel")
	}
}

func TestLegacyLDAP_StartupWiresWithoutRegistryProfileOrSentinel(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPAuthorityReset(t)
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
		t.Fatal("legacy YAML LDAP must keep working before cutover (no registry profile, no sentinel)")
	}
	if legacyLDAPRetired() {
		t.Fatal("no cutover happened — the sentinel must not be set")
	}
}

// The core P1-2 wall: legacy YAML + registry LDAP + NO local admin account.
// Cutover must be unconditional — only registry LDAP can authenticate proxy
// traffic afterwards, and the admin console stays safely gated.
func TestLegacyLDAP_NoLocalAdmin_UnconditionalCutoverKeepsConsoleGated(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPAuthorityReset(t)
	withNoLocalAdminAuth(t)

	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetProvider(legacy)
	if !cfg.IsConfigured() {
		t.Fatal("precondition: the wired legacy provider anchors IsConfigured")
	}

	// Admin creates an enabled registry LDAP profile via the API.
	w := httptest.NewRecorder()
	body := ldapProfileBodyForPut("Registry AD", map[string]any{"bindPassword": "s"})
	body["enabled"] = true
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", body))
	assertStatus(t, w, http.StatusOK)

	if got := cfg.snapshotAuthBackend().provider; got != nil {
		t.Fatalf("legacy YAML LDAP provider still active (%T) after registry LDAP creation — dual authority", got)
	}
	if !legacyLDAPRetired() {
		t.Fatal("cutover must set the durable retirement sentinel")
	}
	if !cfg.IsConfigured() {
		t.Fatal("IsConfigured flipped false after cutover — the admin console would fail OPEN (RoleAdmin for all)")
	}
}

// Registry rejects a credential the legacy provider would have accepted:
// after cutover the answer is DENY — never a legacy fallback.
func TestLegacyLDAP_RegistryRejects_NeverLegacyFallback(t *testing.T) {
	setupAuthGateTest(t)
	withLegacyLDAPAuthorityReset(t)
	withNoLocalAdminAuth(t)

	// A legacy provider that WOULD accept eve's credential (pre-seeded
	// authoritative cache — no directory needed).
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	legacy.cacheSet(cacheKey("eve", "eve-pass"), true, nil)
	cfg.SetProvider(legacy)

	// Registry LDAP that REJECTS eve.
	installLDAPRegistry(t, "corp-ad", aliceStub())
	withLegacyLDAPYAML(t, &LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	enforceLegacyLDAPShadowing()
	if cfg.snapshotAuthBackend().provider != nil {
		t.Fatal("cutover did not deactivate the legacy provider")
	}

	r := makeRequest("http://fallback.example.test/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("eve:eve-pass")))
	w := httptest.NewRecorder()
	if _, proceed := resolveRequestAuth(w, r, "127.0.0.1", "no-fallback-test"); proceed {
		t.Fatal("credential rejected by registry LDAP was accepted — hidden legacy fallback")
	}
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407 deny", w.Code)
	}
}

// Cutover is durable: registry disable and delete followed by a restart must
// NOT reactivate the legacy YAML block.
func TestLegacyLDAP_CutoverSurvivesDisableDeleteAndRestart(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPAuthorityReset(t)
	prof := ldapTestProfile("ldap-cutover", "Registry AD")
	if err := idpRegistry.Upsert(prof); err != nil {
		t.Fatal(err)
	}
	enforceLegacyLDAPShadowing()
	if !legacyLDAPRetired() {
		t.Fatal("cutover sentinel not set")
	}

	restartKeepsLegacyShadowed := func(step string) {
		prevProvider := cfg.snapshotAuthBackend().provider
		defer cfg.SetProvider(prevProvider)
		cfg.SetProvider(nil)
		if err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{
			LDAP: LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"},
		}); err != nil {
			t.Fatalf("%s: loadLegacyAuthProviders: %v", step, err)
		}
		if cfg.snapshotAuthBackend().provider != nil {
			t.Fatalf("%s: restart re-wired the retired legacy YAML LDAP provider", step)
		}
		if !cfg.IsConfigured() {
			t.Fatalf("%s: IsConfigured false after restart — setup gate would fail open", step)
		}
	}

	// Disable the registry profile, then "restart".
	disabled := ldapTestProfile("ldap-cutover", "Registry AD")
	disabled.Enabled = false
	if err := idpRegistry.Upsert(disabled); err != nil {
		t.Fatal(err)
	}
	restartKeepsLegacyShadowed("after disable")

	// Delete the registry profile, then "restart".
	if err := idpRegistry.Delete("ldap-cutover"); err != nil {
		t.Fatal(err)
	}
	restartKeepsLegacyShadowed("after delete")
}

// The sentinel round-trips through admin_settings.json, and loading a settings
// file that carries it deactivates a still-wired legacy provider (the real
// boot order: legacy providers wire before LoadAdminSettings runs).
func TestLegacyLDAP_RetirementSentinelDurableRoundTrip(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPAuthorityReset(t)

	adminSettingsMu.Lock()
	path := adminSettingsPath
	adminSettingsMu.Unlock()

	markLegacyLDAPRetired("test cutover")
	if err := SaveAdminSettings(); err != nil {
		t.Fatalf("SaveAdminSettings: %v", err)
	}

	// Simulate the next boot: flag cleared, legacy provider wired (as the
	// startup shim would have done before it could know about the sentinel
	// in a pre-P1-2 world)… The file bytes are pinned and rewritten so a
	// stale best-effort save goroutine from an unrelated test can never
	// clobber the fixture between the flag reset and the load.
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved settings: %v", err)
	}
	var savedSettings AdminSettings
	if err := json.Unmarshal(saved, &savedSettings); err != nil {
		t.Fatalf("parse saved settings: %v", err)
	}
	if !savedSettings.LegacyLDAPRetired {
		t.Fatal("saved settings do not carry the legacy_ldap_retired sentinel")
	}
	legacyLDAPRetiredFlag.Store(false)
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatalf("rewrite settings fixture: %v", err)
	}
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetProvider(legacy)

	// …then the settings load applies the sentinel and unwires it.
	LoadAdminSettings(path)
	if !legacyLDAPRetired() {
		t.Fatal("sentinel did not survive the admin_settings.json round trip")
	}
	if cfg.snapshotAuthBackend().provider != nil {
		t.Fatal("settings load must deactivate a wired legacy provider on a retired node")
	}
}

// CP→DP: a synced snapshot carrying an enabled LDAP profile performs the same
// durable cutover on the DP (and last-known-good replay goes through the same
// syncSnapshotIdPProfiles path, preserving the authority state).
func TestLegacyLDAP_DPSnapshotSyncCutsOver(t *testing.T) {
	withTestIdPRegistry(t)
	withLegacyLDAPAuthorityReset(t)
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	legacy, err := NewLDAPAuth(LDAPConfig{URL: "ldap://legacy.corp.example:389", BaseDN: "DC=legacy"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetProvider(legacy)

	snap := ConfigSnapshot{Version: 9, IdPProfiles: []*IdPProfile{ldapTestProfile("ldap-dp", "Synced AD")}}
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if cfg.snapshotAuthBackend().provider != nil {
		t.Fatal("DP sync left the legacy YAML provider active alongside the synced registry LDAP")
	}
	if !legacyLDAPRetired() {
		t.Fatal("DP sync cutover must set the durable sentinel")
	}
}

// IsConfigured semantics around the sentinel.
func TestIsConfigured_LegacyLDAPRetiredCountsAsConfigured(t *testing.T) {
	withNoLocalAdminAuth(t)
	prevProvider := cfg.snapshotAuthBackend().provider
	t.Cleanup(func() { cfg.SetProvider(prevProvider) })
	cfg.SetProvider(nil)

	prev := legacyLDAPRetiredFlag.Load()
	t.Cleanup(func() { legacyLDAPRetiredFlag.Store(prev) })

	legacyLDAPRetiredFlag.Store(false)
	if cfg.IsConfigured() {
		t.Fatal("no anchors at all: IsConfigured must be false (fresh-install setup gate)")
	}
	legacyLDAPRetiredFlag.Store(true)
	if !cfg.IsConfigured() {
		t.Fatal("the durable retirement sentinel must count as configured")
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
