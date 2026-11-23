package main

// proxy_auth_posture_test.go — owner decision "Durable Authentication
// Posture" (2026-11-23; ADR-0063; contract AUTH-006).
//
// "Once authentication protection is established, it cannot disappear
// silently. Only an explicit authorized policy decision may permit
// unauthenticated access."
//
// What these gates pin, and why each is here:
//   - a fresh installation (never had a provider) keeps its first-setup
//     behaviour: Stage 1 inert, SOCKS5 NO-AUTH;
//   - every activation path sets the durable marker (admin API create and
//     enable, CP→DP snapshot, startup registry load, startup legacy provider);
//     a disabled profile (the legacy-LDAP import shape) and config import do
//     not;
//   - once established, removing, disabling or failing to load the last
//     provider refuses authentication-required traffic on HTTP (407) and
//     SOCKS5 (USER/PASS only, RFC 1929 failure, reason + metric), across a
//     restart, a backup restore, a config-version rollback and later CP→DP
//     snapshots;
//   - explicit Exempt (global default, scoped rule) admits exactly what it
//     did; nothing else becomes exempt;
//   - corrupt / unreadable markers fail closed; a missing marker migrates
//     from evidence;
//   - activation and removal racing request authentication never admits a
//     credential-free request after the posture is established (-race).
//
// Global-state hygiene: postureNode replaces cfg (the ratchet lives on it) and
// the IdP registry and restores both on cleanup.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/authposture"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// postureNode resets the proxy/auth state to a node with no account and an
// empty, file-backed IdP registry, opens the posture marker in a temp dir and
// restores cfg and the registry on cleanup. It returns the marker path and
// the registry file path.
func postureNode(t *testing.T) (markerPath, registryPath string) {
	t.Helper()
	prevCfg := cfg
	t.Cleanup(func() { cfg = prevCfg })
	setupProxyTest(t)
	withFreshPolicyStore(t)
	captureLoggerForTest(t)
	t.Cleanup(reqlog.SwapRingForTest())
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
	// Legacy-LDAP evidence is process-global: start from none, restore after.
	resetLegacyAuthGlobals(t)
	legacyLDAPYAMLState.mu.Lock()
	legacyLDAPYAMLState.cfg = nil
	legacyLDAPYAMLState.mu.Unlock()
	legacyLDAPRetiredFlag.Store(false)
	dir := t.TempDir()
	registryPath = filepath.Join(dir, "idp_profiles.json")
	orig := idpRegistry
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}, path: registryPath}
	t.Cleanup(func() { idpRegistry = orig })
	markerPath = filepath.Join(dir, proxyAuthPostureFileName)
	if got, err := cfg.proxyAuthPosture().Open(markerPath, atomicWriteFile, nil); err != nil || got != authposture.OutcomeMissing {
		t.Fatalf("open marker: outcome %d err %v", got, err)
	}
	return markerPath, registryPath
}

// resetProxyAuthPostureForTest gives the global cfg a fresh, in-memory, not
// established posture. The production ratchet has no way down (by design), so
// test isolation swaps the whole ratchet. Every IdP activation a test performs
// against the global cfg (swapIdPRegistry's ReplaceAll, an Upsert through the
// admin API, a CP→DP snapshot, a registry Load) establishes it for the REST of
// the binary otherwise, and the proxy_auth_posture row then fails every later
// aggregate-verdict assertion (registered in resetDiagVerdictGlobals, the
// CHAOS-45/47/57/68 precedent).
func resetProxyAuthPostureForTest() {
	if cfg != nil {
		cfg.authPosture.Store(new(authposture.Ratchet))
	}
}

// restartNode simulates a process restart on the same data: a new Config (the
// in-memory posture is gone), the registry reloaded from its file and the
// marker reopened, then the migration step startup runs.
func restartNode(t *testing.T, markerPath, registryPath string) {
	t.Helper()
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	initProxyAuthPosture(markerPath)
	if err := idpRegistry.Load(registryPath); err != nil {
		t.Fatalf("registry reload: %v", err)
	}
	completeProxyAuthPostureMigration()
}

// markerOnDisk decodes the marker file, failing the test if it is absent.
func markerOnDisk(t *testing.T, path string) authposture.Record {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("marker not on disk: %v", err)
	}
	rec, err := authposture.Decode(data)
	if err != nil {
		t.Fatalf("marker on disk is invalid: %v", err)
	}
	return rec
}

// assertEstablishedOnDisk requires the in-memory flag and the durable marker,
// with an origin naming the activation path.
func assertEstablishedOnDisk(t *testing.T, markerPath, byContains string) {
	t.Helper()
	if !cfg.ProxyAuthEstablished() {
		t.Fatal("posture not established in memory")
	}
	rec := markerOnDisk(t, markerPath)
	if !rec.Established || !strings.Contains(rec.By, byContains) || rec.Since == "" {
		t.Fatalf("marker on disk = %+v, want established by %q", rec, byContains)
	}
}

// socks5NoAuthMethod offers ONLY NO-AUTH and returns the selected method
// (0x00 accepted, 0xFF no acceptable method).
func socks5NoAuthMethod(t *testing.T, addr string) byte {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		t.Fatalf("greeting read: %v", err)
	}
	return resp[1]
}

// assertBothChannelsRefuse is the HTTP + SOCKS5 parity assertion for an
// established node with no usable provider: HTTP 407 with and without a
// credential (browser and CONNECT too), SOCKS5 never offers NO-AUTH and
// refuses USER/PASS with the posture reason.
func assertBothChannelsRefuse(t *testing.T, wantReason string) {
	t.Helper()
	for _, tc := range []struct {
		name, method, target, user, pass string
		browser                          bool
	}{
		{"no credential", http.MethodGet, "http://posture.example.test/", "", "", false},
		{"credential", http.MethodGet, "http://posture.example.test/", "alice", "ldap-pass", false},
		{"browser", http.MethodGet, "http://posture.example.test/", "", "", true},
		{"CONNECT", http.MethodConnect, "http://posture.example.test:443", "", "", false},
	} {
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, tc.method, tc.target, tc.user, tc.pass, tc.browser))
		if proceed {
			t.Fatalf("HTTP %s: proceeded as %q/%q on an established node with no provider", tc.name, out.source, out.identity)
		}
		if w.Code != http.StatusProxyAuthRequired {
			t.Errorf("HTTP %s: status %d, want 407", tc.name, w.Code)
		}
	}
	// Through the full request path too.
	w := httptest.NewRecorder()
	handleRequest(w, httpProxyRequest(t, http.MethodGet, "http://posture-e2e.example.test/", "", "", false))
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("handleRequest: status %d, want 407", w.Code)
	}

	if !socks5AuthRequired() {
		t.Fatal("SOCKS5 would offer NO-AUTH on an established node")
	}
	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	if m := socks5NoAuthMethod(t, addr); m != 0xFF {
		t.Errorf("SOCKS5 NO-AUTH-only client: method 0x%02x, want 0xFF (no acceptable method)", m)
	}
	posture0 := socks5AuthFailures[2].Load()
	status, reason := socks5AuthOutcome(t, addr, "alice", "ldap-pass")
	if status != 0x01 {
		t.Errorf("SOCKS5 USER/PASS: status 0x%02x, want 0x01 (RFC 1929 failure)", status)
	}
	if wantReason == socks5AuthReasonPostureNoProvider {
		if socks5AuthFailures[2].Load() == posture0 {
			t.Errorf("SOCKS5 refusal was not counted under %q", socks5AuthReasonPostureNoProvider)
		}
	} else if reason != wantReason {
		t.Errorf("SOCKS5 refusal reason %q, want %q", reason, wantReason)
	}
}

// assertFreshInert is the fresh-installation behaviour: Stage 1 inert, SOCKS5
// NO-AUTH accepted as unauth.
func assertFreshInert(t *testing.T) {
	t.Helper()
	_, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://fresh.example.test/", "", "", false))
	if !proceed || out.source != "unauth" {
		t.Fatalf("fresh node: Stage 1 must stay inert (unauth), got proceed=%v source=%q", proceed, out.source)
	}
	if socks5AuthRequired() {
		t.Fatal("fresh node: SOCKS5 must offer NO-AUTH")
	}
	ln := startSOCKS5Listener(t)
	if m := socks5NoAuthMethod(t, ln.Addr().String()); m != 0x00 {
		t.Errorf("fresh node: SOCKS5 NO-AUTH method 0x%02x, want 0x00", m)
	}
}

func enabledLDAPBody(name string) map[string]any {
	b := ldapProfileBodyForPut(name, map[string]any{"bindPassword": "svc-secret"})
	b["enabled"] = true
	return b
}

// TestProxyAuthPosture_FreshInstallUnchanged: a node that never had a provider
// keeps the first-setup behaviour, and the migration records it as fresh.
func TestProxyAuthPosture_FreshInstallUnchanged(t *testing.T) {
	marker, _ := postureNode(t)
	completeProxyAuthPostureMigration()
	if cfg.ProxyAuthEstablished() {
		t.Fatal("a node with no evidence must stay fresh")
	}
	if rec := markerOnDisk(t, marker); rec.Established || rec.EvaluatedAt == "" {
		t.Fatalf("want a fresh record on disk, got %+v", rec)
	}
	assertFreshInert(t)
	if row := checkProxyAuthPosture(); row.Status != diagOK || !strings.Contains(row.Message, "not been established") {
		t.Errorf("diagnostics row: %+v", row)
	}
}

// TestProxyAuthPosture_ActivationPathsEstablish: every activation path sets
// the durable marker; then removing the provider refuses on both channels.
func TestProxyAuthPosture_ActivationPathsEstablish(t *testing.T) {
	for _, tc := range []struct {
		name     string
		activate func(t *testing.T, registryPath string)
		by       string
		remove   func(t *testing.T)
	}{
		{
			name: "admin_api_create",
			activate: func(t *testing.T, _ string) {
				w := httptest.NewRecorder()
				apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", enabledLDAPBody("Posture AD")))
				assertStatus(t, w, http.StatusOK)
			},
			by:     "identity provider activation",
			remove: deleteAllProfilesViaAPI,
		},
		{
			name: "admin_api_enable",
			activate: func(t *testing.T, _ string) {
				p := ldapTestProfile("posture-ldap", "Posture AD")
				p.Enabled = false
				if err := idpRegistry.Upsert(p); err != nil {
					t.Fatal(err)
				}
				if cfg.ProxyAuthEstablished() {
					t.Fatal("storing a DISABLED profile (the legacy-import shape) must not establish")
				}
				w := httptest.NewRecorder()
				apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/posture-ldap", enabledLDAPBody("Posture AD")), "posture-ldap")
				assertStatus(t, w, http.StatusOK)
			},
			by: "identity provider activation",
			remove: func(t *testing.T) { // disable rather than delete
				w := httptest.NewRecorder()
				apiIdPItem(w, jsonReq(http.MethodPut, "/api/idp/posture-ldap", ldapProfileBodyForPut("Posture AD", nil)), "posture-ldap")
				assertStatus(t, w, http.StatusOK)
			},
		},
		{
			name: "cluster_snapshot",
			activate: func(t *testing.T, _ string) {
				if err := syncSnapshotIdPProfiles(ConfigSnapshot{IdPProfiles: []*IdPProfile{ldapTestProfile("dp-ldap", "DP AD")}}); err != nil {
					t.Fatal(err)
				}
			},
			by: "control-plane snapshot",
			remove: func(t *testing.T) { // a later snapshot that wipes every profile
				if err := syncSnapshotIdPProfiles(ConfigSnapshot{IdPProfiles: []*IdPProfile{}}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "startup_registry_load",
			activate: func(t *testing.T, registryPath string) {
				data, _ := json.Marshal([]*IdPProfile{ldapTestProfile("boot-ldap", "Boot AD")})
				if err := os.WriteFile(registryPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := idpRegistry.Load(registryPath); err != nil {
					t.Fatal(err)
				}
			},
			by:     "startup",
			remove: deleteAllProfilesViaAPI,
		},
		{
			name: "startup_legacy_ldap",
			activate: func(t *testing.T, _ string) {
				resetLegacyAuthGlobals(t)
				if err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{LDAP: LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=example"}}); err != nil {
					t.Fatal(err)
				}
			},
			by:     "legacy ldap",
			remove: func(*testing.T) { cfg.SetProvider(nil) }, // unwired, e.g. a failed load next boot
		},
		{
			name: "startup_legacy_oidc",
			activate: func(t *testing.T, _ string) {
				resetLegacyAuthGlobals(t)
				if err := loadLegacyAuthProviders(legacyAuthProvidersStartupConfig{OIDC: OIDCConfig{IntrospectionURL: "https://idp.example/introspect", ClientID: "cid"}}); err != nil {
					t.Fatal(err)
				}
			},
			by:     "legacy oidc",
			remove: func(*testing.T) { cfg.SetProvider(nil) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker, registryPath := postureNode(t)
			tc.activate(t, registryPath)
			assertEstablishedOnDisk(t, marker, tc.by)
			if row := checkProxyAuthPosture(); row.Status != diagOK || !strings.Contains(row.Message, "is usable") {
				t.Errorf("diagnostics with a provider: %+v", row)
			}
			tc.remove(t)
			if hasCredentialCapableProvider() || idpRegistry.HasEnabledInteractiveProvider() {
				t.Fatal("premise: the provider is gone")
			}
			assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
			if row := checkProxyAuthPosture(); row.Status != diagFail {
				t.Errorf("diagnostics with no provider: want fail, got %+v", row)
			}
		})
	}
}

func deleteAllProfilesViaAPI(t *testing.T) {
	t.Helper()
	for _, p := range idpRegistry.All() {
		w := httptest.NewRecorder()
		apiIdPItem(w, jsonReq(http.MethodDelete, "/api/idp/"+p.ID, nil), p.ID)
		if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
			t.Fatalf("DELETE /api/idp/%s: status %d", p.ID, w.Code)
		}
	}
}

// TestProxyAuthPosture_ActivationRefusedWhenMarkerCannotBeWritten: write-ahead.
// The admin API and a CP→DP snapshot refuse the activation (500 / snapshot
// rejected) and nothing changes when the marker cannot be persisted.
func TestProxyAuthPosture_ActivationRefusedWhenMarkerCannotBeWritten(t *testing.T) {
	marker, _ := postureNode(t)
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	failWrite := func(string, []byte, fs.FileMode) error { return errors.New("injected: disk full") }
	if _, err := cfg.proxyAuthPosture().Open(marker, failWrite, nil); err != nil {
		t.Fatalf("open: %v", err)
	}
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", enabledLDAPBody("Unrecordable AD")))
	assertStatus(t, w, http.StatusInternalServerError)
	if len(idpRegistry.All()) != 0 || cfg.ProxyAuthEstablished() {
		t.Fatalf("a refused activation changed state: profiles=%d established=%v", len(idpRegistry.All()), cfg.ProxyAuthEstablished())
	}
	if err := syncSnapshotIdPProfiles(ConfigSnapshot{IdPProfiles: []*IdPProfile{ldapTestProfile("dp-ldap", "DP AD")}}); err == nil {
		t.Fatal("a snapshot whose activation cannot be recorded must be rejected")
	}
	if len(idpRegistry.All()) != 0 || cfg.ProxyAuthEstablished() {
		t.Fatal("a rejected snapshot changed state")
	}
}

// TestProxyAuthPosture_ConfiguredProviderFailsToLoad: established, then the
// only profile is enabled but not loaded (a compile failure at the next boot):
// both channels refuse.
func TestProxyAuthPosture_ConfiguredProviderFailsToLoad(t *testing.T) {
	marker, _ := postureNode(t)
	if err := idpRegistry.Upsert(ldapTestProfile("dark-ldap", "Dark AD")); err != nil {
		t.Fatal(err)
	}
	assertEstablishedOnDisk(t, marker, "identity provider activation")
	idpRegistry.mu.Lock()
	delete(idpRegistry.live, "dark-ldap")
	idpRegistry.mu.Unlock()
	if !hasCredentialCapableProvider() {
		t.Fatal("premise: an enabled LDAP profile counts as credential-capable even when not loaded")
	}
	// The SOCKS5 reason here is the existing classification for an enabled
	// but unloaded password provider (invalid_credentials), not the posture one.
	assertBothChannelsRefuse(t, socks5AuthReasonInvalid)
	if row := checkProxyAuthPosture(); row.Status != diagFail {
		t.Errorf("an established node whose only provider failed to load must report fail, got %+v", row)
	}
}

// TestProxyAuthPosture_RemovalThenRestartStillRefuses: the marker, not the
// in-memory flag, carries the posture across a restart.
func TestProxyAuthPosture_RemovalThenRestartStillRefuses(t *testing.T) {
	marker, registryPath := postureNode(t)
	w := httptest.NewRecorder()
	apiIdPList(w, jsonReq(http.MethodPost, "/api/idp", enabledLDAPBody("Restart AD")))
	assertStatus(t, w, http.StatusOK)
	deleteAllProfilesViaAPI(t)
	restartNode(t, marker, registryPath)
	if len(idpRegistry.All()) != 0 {
		t.Fatal("premise: the deletion is durable")
	}
	assertEstablishedOnDisk(t, marker, "identity provider activation")
	assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
}

// TestProxyAuthPosture_ConfigImportAndRollbackNeverClear: config import and
// config-version rollback carry no provider and no posture: they neither
// establish a fresh node nor clear an established one, and establishing the
// posture creates no config version.
func TestProxyAuthPosture_ConfigImportAndRollbackNeverClear(t *testing.T) {
	marker, _ := postureNode(t)
	versionsDir := snapshotConfigVersionsDir(t)
	preProvider := captureConfigBackup() // the rollback target predates the provider

	importPlainRule := func() {
		t.Helper()
		body, err := json.Marshal(configBackup{Version: 1, PolicyRules: []PolicyRule{{Priority: 9, Name: "posture-import", Action: ActionAllow}}})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		apiConfigImport(w, adminRequest("POST", "/api/config/import", string(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("import: %d %s", w.Code, w.Body.String())
		}
	}
	importPlainRule()
	if cfg.ProxyAuthEstablished() {
		t.Fatal("config import must not establish the posture")
	}

	before, err := os.ReadDir(versionsDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := idpRegistry.Upsert(ldapTestProfile("rb-ldap", "Rollback AD")); err != nil {
		t.Fatal(err)
	}
	assertEstablishedOnDisk(t, marker, "identity provider activation")
	after, err := os.ReadDir(versionsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("establishing the posture created %d config version(s); it is not a versioned configuration mutation", len(after)-len(before))
	}
	if b, _ := json.Marshal(captureConfigBackup()); strings.Contains(strings.ToLower(string(b)), "auth_posture") || strings.Contains(string(b), "identity provider activation") {
		t.Fatal("the posture leaked into the rollback/export surface")
	}

	if err := idpRegistry.Delete("rb-ldap"); err != nil {
		t.Fatal(err)
	}
	if err := applyConfigBackup(preProvider); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	importPlainRule()
	assertEstablishedOnDisk(t, marker, "identity provider activation")
	assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
}

// TestProxyAuthPosture_ClusterSnapshotsNeverClear: a DP that applied a
// snapshot with a provider stays established through a later snapshot with no
// provider, one that omits the field, and a JSON snapshot missing it.
func TestProxyAuthPosture_ClusterSnapshotsNeverClear(t *testing.T) {
	marker, _ := postureNode(t)
	if err := syncSnapshotIdPProfiles(ConfigSnapshot{IdPProfiles: []*IdPProfile{ldapTestProfile("dp-ldap", "DP AD")}}); err != nil {
		t.Fatal(err)
	}
	var missing ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":7}`), &missing); err != nil {
		t.Fatal(err)
	}
	for _, snap := range []ConfigSnapshot{{IdPProfiles: []*IdPProfile{}}, {}, missing} {
		if err := syncSnapshotIdPProfiles(snap); err != nil {
			t.Fatal(err)
		}
		assertEstablishedOnDisk(t, marker, "control-plane snapshot")
	}
	assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
}

// TestProxyAuthPosture_ExplicitExemptUnchanged proves both directions. An
// established node whose provider went away answers EXACTLY like the same node
// with its provider still configured (the "today" of a configured node): the
// Exempt default and a scoped Exempt rule admit the same credential-free
// requests, with the same auth source; and provider disappearance never
// creates an exemption — an uncovered request, a presented credential and the
// kill switch all refuse. The fresh column records the unchanged first-setup
// behaviour (no backend: Stage 1 inert) for contrast.
func TestProxyAuthPosture_ExplicitExemptUnchanged(t *testing.T) {
	type outcome struct {
		proceed bool
		source  string
		code    int
	}
	const (
		fresh = iota
		withProvider
		establishedNoProvider
	)
	run := func(t *testing.T, node int, setup func(t *testing.T), host, user, pass string) outcome {
		t.Helper()
		postureNode(t)
		switch node {
		case withProvider:
			installCredentialRegistry(t, aliceStub(), false)
			establishProxyAuthPostureFailClosed("test")
		case establishedNoProvider:
			establishProxyAuthPostureFailClosed("test")
		}
		setup(t)
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://"+host+"/", user, pass, false))
		return outcome{proceed, out.source, w.Code}
	}
	exemptDefault := func(*testing.T) { cfg.SetDefaultAuthOutcome(OutcomeExempt) }
	const covered = "posture-exempt.example.test"
	scopedRule := func(*testing.T) { policyStore.Add(slice7ExemptRule(covered)) }
	killSwitched := func(t *testing.T) {
		cfg.SetDefaultAuthOutcome(OutcomeExempt)
		policyStore.Add(slice7ExemptRule(covered))
		setAuthExemptDisabled(true)
	}
	admitted := func(source string) outcome { return outcome{true, source, http.StatusOK} }
	refused := outcome{false, "", http.StatusProxyAuthRequired}
	for _, tc := range []struct {
		name             string
		setup            func(*testing.T)
		host, user, pass string
		fresh, closed    outcome // closed: with a provider AND established without one
	}{
		{"exempt default, no credential", exemptDefault, "any.example.test", "", "", admitted("unauth"), admitted("unauth")},
		{"scoped exempt, covered", scopedRule, covered, "", "", admitted("unauth"), admitted(authSourceExempt)},
		{"scoped exempt, uncovered", scopedRule, "uncovered.example.test", "", "", admitted("unauth"), refused},
		{"no exemption at all", func(*testing.T) {}, "plain.example.test", "", "", admitted("unauth"), refused},
		{"exempt default, credential presented", exemptDefault, "any.example.test", "alice", "wrong", admitted("unauth"), refused},
		{"kill switch engaged", killSwitched, covered, "", "", admitted("unauth"), refused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(t, fresh, tc.setup, tc.host, tc.user, tc.pass); got != tc.fresh {
				t.Errorf("fresh node: %+v, want %+v", got, tc.fresh)
			}
			if got := run(t, withProvider, tc.setup, tc.host, tc.user, tc.pass); got != tc.closed {
				t.Errorf("node with its provider: %+v, want %+v", got, tc.closed)
			}
			if got := run(t, establishedNoProvider, tc.setup, tc.host, tc.user, tc.pass); got != tc.closed {
				t.Errorf("established node whose provider went away: %+v, want %+v (identical to the node with its provider)", got, tc.closed)
			}
		})
	}
}

// TestProxyAuthPosture_MarkerFailClosedAndMigration: corrupt and unreadable
// markers establish; a missing marker migrates from evidence, and only a node
// with none is fresh.
func TestProxyAuthPosture_MarkerFailClosedAndMigration(t *testing.T) {
	for _, tc := range []struct {
		name        string
		prepare     func(t *testing.T, marker, registryPath string)
		read        authposture.ReadFunc
		established bool
		problem     authposture.Problem
		by          string
	}{
		{name: "corrupt", prepare: func(t *testing.T, marker, _ string) { writeFileT(t, marker, []byte(`{"version":1,"establ`)) }, established: true, problem: authposture.ProblemCorrupt},
		{name: "empty", prepare: func(t *testing.T, marker, _ string) { writeFileT(t, marker, nil) }, established: true, problem: authposture.ProblemCorrupt},
		{name: "unreadable (directory)", prepare: func(t *testing.T, marker, _ string) {
			if err := os.Mkdir(marker, 0o700); err != nil {
				t.Fatal(err)
			}
		}, established: true, problem: authposture.ProblemUnreadable},
		{name: "unreadable (permission)", read: func(string) ([]byte, error) { return nil, fs.ErrPermission }, established: true, problem: authposture.ProblemUnreadable},
		{name: "missing with a disabled registry profile", prepare: func(t *testing.T, _, registryPath string) {
			p := ldapTestProfile("old-ldap", "Old AD")
			p.Enabled = false
			data, _ := json.Marshal([]*IdPProfile{p})
			writeFileT(t, registryPath, data)
		}, established: true, by: "migration: 1 identity provider profile(s)"},
		{name: "missing with a live registry profile", prepare: func(t *testing.T, _, registryPath string) {
			data, _ := json.Marshal([]*IdPProfile{ldapTestProfile("live-ldap", "Live AD")})
			writeFileT(t, registryPath, data)
		}, established: true, by: "startup: identity provider profile"},
		{name: "missing with a legacy ldap block", prepare: func(t *testing.T, _, _ string) {
			resetLegacyAuthGlobals(t)
			setLegacyLDAPYAMLConfig(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=example"})
		}, established: true, by: "migration: a legacy ldap block"},
		{name: "missing with the legacy retirement sentinel", prepare: func(t *testing.T, _, _ string) {
			resetLegacyAuthGlobals(t)
			legacyLDAPRetiredFlag.Store(true)
		}, established: true, by: "migration: the legacy LDAP retirement sentinel"},
		{name: "missing with no evidence", prepare: func(*testing.T, string, string) {}, established: false},
	} {
		t.Run(tc.name, func(t *testing.T) { runMarkerCase(t, tc.prepare, tc.read, tc.established, tc.problem, tc.by) })
	}
}

// runMarkerCase is one TestProxyAuthPosture_MarkerFailClosedAndMigration case:
// prepare the data, "restart" (new Config and registry, marker opened, registry
// loaded, migration run), then check the posture, the marker and both channels.
func runMarkerCase(t *testing.T, prepare func(t *testing.T, marker, registryPath string), read authposture.ReadFunc,
	established bool, problem authposture.Problem, by string) {
	t.Helper()
	marker, registryPath := postureNode(t)
	if prepare != nil {
		prepare(t, marker, registryPath)
	}
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	if read != nil {
		_, _ = cfg.proxyAuthPosture().Open(marker, atomicWriteFile, read)
	} else {
		initProxyAuthPosture(marker)
	}
	if err := idpRegistry.Load(registryPath); err != nil {
		t.Fatal(err)
	}
	completeProxyAuthPostureMigration()
	if cfg.ProxyAuthEstablished() != established {
		t.Fatalf("established = %v, want %v", cfg.ProxyAuthEstablished(), established)
	}
	if st := cfg.proxyAuthPosture().Status(); st.Problem != problem {
		t.Errorf("problem %q, want %q", st.Problem, problem)
	}
	if by != "" {
		assertEstablishedOnDisk(t, marker, by)
	}
	if !established {
		assertFreshInert(t)
		return
	}
	if row := checkProxyAuthPosture(); problem != "" && (row.Status != diagFail || !strings.Contains(row.Message, string(problem))) {
		t.Errorf("diagnostics: %+v", row)
	}
	// The live-profile case still has its provider; every other case has
	// none, and refuses on both channels.
	if !proxyAuthProviderUsable() {
		assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
	}
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestProxyAuthPosture_FreshRecordIsNotReMigrated: after the first start
// records a fresh node, a later DISABLED profile (never activated) does not
// establish the posture at the next restart.
func TestProxyAuthPosture_FreshRecordIsNotReMigrated(t *testing.T) {
	marker, registryPath := postureNode(t)
	completeProxyAuthPostureMigration()
	p := ldapTestProfile("later-ldap", "Later AD")
	p.Enabled = false
	if err := idpRegistry.Upsert(p); err != nil {
		t.Fatal(err)
	}
	restartNode(t, marker, registryPath)
	if cfg.ProxyAuthEstablished() {
		t.Fatal("a never-activated profile established the posture through a re-run migration")
	}
}

// TestProxyAuthPosture_BackupRestoreSetsNeverClears drives the real offline
// restore: restoring an archive that predates the posture onto an established
// node keeps it; restoring an established archive onto a fresh node sets it;
// a fresh record is never carried over.
func TestProxyAuthPosture_BackupRestoreSetsNeverClears(t *testing.T) {
	established, err := authposture.Encode(authposture.Record{Version: 1, Established: true, Since: "2026-11-23T10:00:00Z", By: "identity provider activation"})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := authposture.Encode(authposture.Record{Version: 1, EvaluatedAt: "2026-11-23T10:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	backupWith := func(t *testing.T, marker []byte) string {
		t.Helper()
		dir := t.TempDir()
		seedFile(t, dir, "ui_users.json", []byte(`{"users":[{"username":"admin","role":"admin"}]}`), 0o600)
		seedFile(t, dir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
		if marker != nil {
			seedFile(t, dir, proxyAuthPostureFileName, marker, 0o600)
		}
		out := filepath.Join(t.TempDir(), "backup.tar.gz")
		if err := runBackup(out, dir); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name             string
		current, archive []byte
		mode             restoreMode
		want             []byte // nil: no marker after the restore
	}{
		{"older archive onto an established node", established, nil, modeFull, established},
		{"fresh archive onto an established node", established, fresh, modeFull, established},
		{"established archive onto a fresh node", fresh, established, modeFull, established},
		{"established archive onto a node without a marker", nil, established, modeStateOnly, established},
		{"trust-root-only keeps the established node", established, fresh, modeTrustRootOnly, established},
		{"fresh is never carried over", fresh, fresh, modeFull, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := backupWith(t, tc.archive)
			current := t.TempDir()
			seedFile(t, current, "ui_users.json", []byte(`{"users":[{"username":"admin","role":"admin"}]}`), 0o600)
			if tc.current != nil {
				seedFile(t, current, proxyAuthPostureFileName, tc.current, 0o600)
			}
			if _, err := captureStdout(t, func() error { return runRestoreCommit(src, current, "", restoreOpts{Mode: tc.mode}) }); err != nil {
				t.Fatalf("restore: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(current, proxyAuthPostureFileName))
			if tc.want == nil {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("a fresh record was carried over: %q (%v)", got, err)
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("marker after restore = %q (%v), want %q", got, err, tc.want)
			}
		})
	}

	// And the restored node starts established and refusing.
	t.Run("restored node refuses after start", func(t *testing.T) {
		src := backupWith(t, nil)
		current := t.TempDir()
		seedFile(t, current, "ui_users.json", []byte(`{"users":[{"username":"admin","role":"admin"}]}`), 0o600)
		seedFile(t, current, proxyAuthPostureFileName, established, 0o600)
		if _, err := captureStdout(t, func() error { return runRestoreCommit(src, current, "", commitOptsFull()) }); err != nil {
			t.Fatal(err)
		}
		marker, registryPath := postureNode(t)
		writeFileT(t, marker, established)
		restartNode(t, marker, registryPath)
		assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
	})
}

// TestProxyAuthPosture_UnreadableCurrentMarkerAbortsRestore: a restore never
// drops a marker it cannot read.
func TestProxyAuthPosture_UnreadableCurrentMarkerAbortsRestore(t *testing.T) {
	src := makeValidBackup(t)
	current := t.TempDir()
	seedFile(t, current, "ui_users.json", []byte(`{"users":[{"username":"admin","role":"admin"}]}`), 0o600)
	if err := os.Mkdir(filepath.Join(current, proxyAuthPostureFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error { return runRestoreCommit(src, current, "", commitOptsFull()) }); err == nil ||
		!strings.Contains(err.Error(), "proxy auth posture") {
		t.Fatalf("restore over an unreadable marker: err %v, want a posture refusal", err)
	}
}

// TestProxyAuthPosture_KillSwitchAndDiagnosticsRows: the kill-switch row names
// the posture state instead of claiming Stage 2 decides, and the posture row
// renders identically for every role (it carries no roster fact or path).
func TestProxyAuthPosture_KillSwitchAndDiagnosticsRows(t *testing.T) {
	postureNode(t)
	if got := currentKillSwitchBackend(); got != killSwitchBackendNone {
		t.Fatalf("fresh node: %d, want killSwitchBackendNone", got)
	}
	establishProxyAuthPostureFailClosed("test")
	if got := currentKillSwitchBackend(); got != killSwitchBackendPostureNoProvider {
		t.Fatalf("established node with no provider: %d, want killSwitchBackendPostureNoProvider", got)
	}
	admin, viewer := authExemptKillSwitchContractRows(false, true)
	if admin != viewer || !strings.Contains(admin.Message, "established") || strings.Contains(admin.Message, "decided by the remaining") {
		t.Errorf("kill-switch row: admin %+v viewer %+v", admin, viewer)
	}
	// The roster states keep precedence (SEC-KSROSTER-1 unchanged).
	if err := cfg.SetAuth("admin", "Adm1n-Console-pass"); err != nil {
		t.Fatal(err)
	}
	if got := currentKillSwitchBackend(); got != killSwitchBackendAdminOnly {
		t.Errorf("admin-only + established: %d, want killSwitchBackendAdminOnly", got)
	}
	contractFor := func(ctx func(*http.Request) *http.Request) *OperatorContractCheck {
		w := httptest.NewRecorder()
		apiDiagnostics(w, ctx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/diagnostics", http.NoBody)))
		return findDiagnosticCheck(decodeContract(t, w), proxyAuthPostureCode)
	}
	adminRow, viewerRow := contractFor(adminCtx), contractFor(viewerCtx)
	if adminRow == nil || viewerRow == nil || *adminRow != *viewerRow {
		t.Fatalf("posture row admin %+v viewer %+v", adminRow, viewerRow)
	}
	if adminRow.Status != diagFail || !strings.Contains(adminRow.Message, "since ") || !strings.Contains(adminRow.Message, "by test") {
		t.Errorf("posture row must state established/since/by and fail with no provider: %+v", adminRow)
	}
	if strings.Contains(adminRow.Message+adminRow.OperatorAction, os.TempDir()) {
		t.Errorf("the posture row must name no path: %+v", adminRow)
	}
}

// TestProxyAuthPosture_SOCKS5MetricLabel: the refusal reason is exported.
func TestProxyAuthPosture_SOCKS5MetricLabel(t *testing.T) {
	var b strings.Builder
	writeSOCKS5AuthMetrics(&b)
	if !strings.Contains(b.String(), `culvert_socks5_auth_failures_total{reason="auth_established_no_provider"}`) {
		t.Fatalf("metrics missing the posture reason:\n%s", b.String())
	}
}

// TestProxyAuthPosture_ConcurrentActivationAndRequests races provider
// activation and removal against HTTP Stage 1 and SOCKS5 method selection.
// Once the first activation has returned, no credential-free request may
// proceed and SOCKS5 may never select NO-AUTH. Run with -race.
func TestProxyAuthPosture_ConcurrentActivationAndRequests(t *testing.T) {
	postureNode(t)
	idpRegistry.path = "" // in-memory registry: the race is about the posture, not registry I/O
	var activated atomic.Bool
	var violations atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			if err := idpRegistry.Upsert(ldapTestProfile("race-ldap", "Race AD")); err != nil {
				t.Error(err)
				return
			}
			activated.Store(true)
			if err := idpRegistry.Delete("race-ldap"); err != nil {
				t.Error(err)
				return
			}
		}
		close(stop)
	}()
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				after := activated.Load()
				w := httptest.NewRecorder()
				_, proceed := resolveRequestAuth(w, httpProxyRequest(t, http.MethodGet, "http://race.example.test/", "", "", false), "127.0.0.1", "posture-race")
				if after && (proceed || !socks5AuthRequired()) {
					violations.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := violations.Load(); n != 0 {
		t.Fatalf("%d request(s) were admitted without credentials after the posture was established", n)
	}
	if !cfg.ProxyAuthEstablished() {
		t.Fatal("the posture must be established after the race")
	}
}

// TestProxyAuthPosture_GateReadAllocFree: the posture is read on every proxied
// request (resolveRequestAuth) and every SOCKS5 greeting (socks5AuthRequired):
// an atomic load, no allocation, no file I/O. Matched by the benchgate filter.
func TestProxyAuthPosture_GateReadAllocFree(t *testing.T) {
	marker, _ := postureNode(t)
	establishProxyAuthPostureFailClosed("alloc-test")
	if err := os.Remove(marker); err != nil { // no file I/O per request: the read must not need it
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = cfg.ProxyAuthEstablished() }); n != 0 {
		t.Errorf("ProxyAuthEstablished allocates %.1f per call", n)
	}
	if n := testing.AllocsPerRun(1000, func() { _ = socks5AuthRequired() }); n != 0 {
		t.Errorf("socks5AuthRequired allocates %.1f per call", n)
	}
	if !cfg.ProxyAuthEstablished() || !socks5AuthRequired() {
		t.Fatal("the in-memory posture must not depend on the marker file after startup")
	}
}

// BenchmarkProxyAuthEstablished is the hot-path read.
func BenchmarkProxyAuthEstablished(b *testing.B) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if _, err := c.proxyAuthPosture().Establish("bench", time.Now()); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = c.ProxyAuthEstablished()
	}
}

// TestProxyAuthPosture_ControlPlanePostureReachesFreshDP closes the CP→DP gap:
// a CP that is established with ZERO providers left publishes the posture, and
// a DP that never had a provider (it enrols after the last one was deleted)
// establishes on apply, durably, and refuses on both channels — instead of
// starting fresh with NO-AUTH and an inert Stage 1.
func TestProxyAuthPosture_ControlPlanePostureReachesFreshDP(t *testing.T) {
	// Control Plane: established earlier, every provider since removed.
	postureNode(t)
	if err := idpRegistry.Upsert(ldapTestProfile("cp-ldap", "CP AD")); err != nil {
		t.Fatal(err)
	}
	if err := idpRegistry.Delete("cp-ldap"); err != nil {
		t.Fatal(err)
	}
	snap := CurrentConfigSnapshot()
	if !snap.ProxyAuthEstablished || len(snap.IdPProfiles) != 0 {
		t.Fatalf("CP snapshot: established=%v profiles=%d, want true/0", snap.ProxyAuthEstablished, len(snap.IdPProfiles))
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte(`"proxy_auth_established":true`)) {
		t.Fatal("the posture is not on the wire")
	}

	// Data Plane: a fresh node with no provider, applying what the CP sent.
	marker, registryPath := postureNode(t)
	var got ConfigSnapshot
	if err := json.Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	assertFreshInert(t) // the premise: fresh before the snapshot
	if err := syncSnapshotIdPProfiles(got); err != nil {
		t.Fatalf("DP apply: %v", err)
	}
	assertEstablishedOnDisk(t, marker, "control-plane snapshot")
	assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
	restartNode(t, marker, registryPath) // durable on the DP itself
	assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
}

// TestProxyAuthPosture_SnapshotPostureFalseOrAbsentNeverLowers: the field is
// merge-only. A false value, an absent field (omitempty on the wire, or an
// older CP that does not know it) never clears an established DP.
func TestProxyAuthPosture_SnapshotPostureFalseOrAbsentNeverLowers(t *testing.T) {
	marker, _ := postureNode(t)
	if err := syncSnapshotIdPProfiles(ConfigSnapshot{ProxyAuthEstablished: true}); err != nil {
		t.Fatal(err)
	}
	var explicitFalse, absent ConfigSnapshot
	if err := json.Unmarshal([]byte(`{"version":9,"proxy_auth_established":false,"idp_profiles":[]}`), &explicitFalse); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"version":10}`), &absent); err != nil {
		t.Fatal(err)
	}
	if wire, _ := json.Marshal(ConfigSnapshot{}); bytes.Contains(wire, []byte("proxy_auth_established")) {
		t.Fatal("a false posture must be omitted from the wire (omitempty), so an older DP sees nothing new")
	}
	for _, snap := range []ConfigSnapshot{{ProxyAuthEstablished: false}, explicitFalse, absent} {
		if err := syncSnapshotIdPProfiles(snap); err != nil {
			t.Fatal(err)
		}
		assertEstablishedOnDisk(t, marker, "control-plane snapshot")
	}
	assertBothChannelsRefuse(t, socks5AuthReasonPostureNoProvider)
}

// TestProxyAuthPosture_SnapshotPostureWriteFailureRejects: write-ahead on the
// DP. A snapshot carrying the CP posture that the DP cannot record is
// rejected before anything it carries is applied.
func TestProxyAuthPosture_SnapshotPostureWriteFailureRejects(t *testing.T) {
	marker, _ := postureNode(t)
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	failWrite := func(string, []byte, fs.FileMode) error { return errors.New("injected: disk full") }
	if _, err := cfg.proxyAuthPosture().Open(marker, failWrite, nil); err != nil {
		t.Fatal(err)
	}
	err := syncSnapshotIdPProfiles(ConfigSnapshot{ProxyAuthEstablished: true, IdPProfiles: []*IdPProfile{ldapTestProfile("dp-ldap", "DP AD")}})
	if err == nil {
		t.Fatal("a snapshot whose posture cannot be recorded must be rejected")
	}
	if cfg.ProxyAuthEstablished() || len(idpRegistry.All()) != 0 {
		t.Fatalf("a rejected snapshot changed state: established=%v profiles=%d", cfg.ProxyAuthEstablished(), len(idpRegistry.All()))
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("no marker may exist after a rejected snapshot: %v", statErr)
	}
}
