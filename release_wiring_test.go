package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveReleaseStartupConfig_Defaults(t *testing.T) {
	// Empty env (fake getenv) ⇒ documented defaults. No process-env mutation.
	cfg := resolveReleaseStartupConfigFrom(func(string) string { return "" })
	if cfg.proxyRepo != defaultReleaseProxyRepo {
		t.Errorf("proxyRepo = %q; want default %q", cfg.proxyRepo, defaultReleaseProxyRepo)
	}
	if cfg.maintURL != defaultMaintAgentSocket {
		t.Errorf("maintURL = %q; want default socket %q", cfg.maintURL, defaultMaintAgentSocket)
	}
	if cfg.catalogDir == "" {
		t.Error("catalogDir should be derived from dataDir, got empty")
	}
}

func TestResolveReleaseStartupConfig_EnvOverride(t *testing.T) {
	env := map[string]string{
		envReleaseProxyRepo: "registry.local/culvert",
		envMaintAgentURL:    "http://127.0.0.1:9999",
	}
	cfg := resolveReleaseStartupConfigFrom(func(k string) string { return env[k] })
	if cfg.proxyRepo != "registry.local/culvert" || cfg.maintURL != "http://127.0.0.1:9999" {
		t.Fatalf("env override not honored: %+v", cfg)
	}
}

func TestResolveReleaseStartupConfig_TrustKeysEnv(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		envReleaseCatalogTrustKeys: `[{"key_id":"catalog-prod","alg":"ed25519","public_key":"` +
			base64.StdEncoding.EncodeToString(pub) + `"}]`,
	}
	cfg := resolveReleaseStartupConfigFrom(func(k string) string { return env[k] })
	if cfg.trustKeysErr != nil {
		t.Fatalf("trustKeysErr = %v", cfg.trustKeysErr)
	}
	if len(cfg.trustKeys) != 1 {
		t.Fatalf("trustKeys len = %d; want 1", len(cfg.trustKeys))
	}
	if cfg.trustKeys[0].KeyID != "catalog-prod" || cfg.trustKeys[0].Alg != catalogSigAlg {
		t.Fatalf("trust key = %+v; want catalog-prod/%s", cfg.trustKeys[0], catalogSigAlg)
	}
	if string(cfg.trustKeys[0].PublicKey) != string(pub) {
		t.Fatal("trust key public key did not round-trip from env")
	}
}

// resolveCatalogVerifyMode is the central Phase 1 decision: roots ⇒ enforce,
// permissive/disabled are explicit break-glass only, unrecognized ⇒ enforce.
func TestResolveCatalogVerifyMode(t *testing.T) {
	cases := []struct {
		name     string
		override string
		nRoots   int
		want     VerifyMode
		wantWarn bool
	}{
		{"unset with roots ⇒ enforce, no warn", "", 1, VerifyEnforce, false},
		{"unset no roots ⇒ enforce + disabled warn", "", 0, VerifyEnforce, true},
		{"explicit enforce with roots", "enforce", 2, VerifyEnforce, false},
		{"break-glass permissive warns", "permissive", 0, VerifyPermissive, true},
		{"break-glass disabled warns", "disabled", 0, VerifyDisabled, true},
		{"case-insensitive permissive", "PERMISSIVE", 1, VerifyPermissive, true},
		{"unrecognized ⇒ enforce + warn", "yolo", 1, VerifyEnforce, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, warn := resolveCatalogVerifyMode(tc.override, tc.nRoots)
			if mode != tc.want {
				t.Errorf("mode = %v; want %v", mode, tc.want)
			}
			if (warn != "") != tc.wantWarn {
				t.Errorf("warn = %q; wantWarn=%v", warn, tc.wantWarn)
			}
		})
	}
}

// Baked roots and operator-configured (env) roots are merged into one ring.
func TestCombinedReleaseTrustKeys_MergesBakedAndEnv(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := bakedReleaseTrustKeysJSON
	t.Cleanup(func() { bakedReleaseTrustKeysJSON = saved })
	bakedReleaseTrustKeysJSON = `[{"key_id":"baked-1","alg":"ed25519","public_key":"` +
		base64.StdEncoding.EncodeToString(pub) + `"}]`

	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	envRaw := `[{"key_id":"env-1","alg":"ed25519","public_key":"` +
		base64.StdEncoding.EncodeToString(pub2) + `"}]`

	keys, err := combinedReleaseTrustKeys(envRaw)
	if err != nil {
		t.Fatalf("combinedReleaseTrustKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len(keys) = %d; want 2 (baked ∪ env)", len(keys))
	}
	ids := map[string]bool{keys[0].KeyID: true, keys[1].KeyID: true}
	if !ids["baked-1"] || !ids["env-1"] {
		t.Fatalf("merged key_ids = %v; want baked-1 and env-1", ids)
	}
}

// A malformed baked root set fails closed (Release Management disabled), never a
// half-parsed ring.
func TestCombinedReleaseTrustKeys_MalformedBakedFailsClosed(t *testing.T) {
	saved := bakedReleaseTrustKeysJSON
	t.Cleanup(func() { bakedReleaseTrustKeysJSON = saved })
	bakedReleaseTrustKeysJSON = `[{"key_id":"baked-1",` // truncated JSON
	if _, err := combinedReleaseTrustKeys(""); err == nil {
		t.Fatal("malformed baked trust keys must error (fail closed)")
	}
}

func TestLocalAgentEndpoint(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantOK  bool
		wantURL string
	}{
		{"empty", "", false, ""},
		{"bare socket", "/run/culvert-maint/culvert-maint.sock", true, "http://unix"},
		{"unix scheme", "unix:///run/culvert-maint/culvert-maint.sock", true, "http://unix"},
		{"http url", "http://127.0.0.1:8888", true, "http://127.0.0.1:8888"},
		{"https url", "https://maint.local:443", true, "https://maint.local:443"},
		{"bad scheme", "ftp://maint", false, ""},
		{"no scheme non-abs", "maint:8888", false, ""},
		{"unix empty", "unix:", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep, ok := localAgentEndpoint(tc.raw)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v; want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if ep.Key != localAgentKey {
				t.Errorf("key = %q; want %q", ep.Key, localAgentKey)
			}
			if ep.BaseURL != tc.wantURL {
				t.Errorf("baseURL = %q; want %q", ep.BaseURL, tc.wantURL)
			}
			if ep.Client == nil {
				t.Error("client must be non-nil")
			}
		})
	}
}

func TestReleaseAgentResolver(t *testing.T) {
	// Configured local agent resolves only the "local" key.
	resolve, note := releaseAgentResolver("/run/culvert-maint/culvert-maint.sock")
	if note == "none" {
		t.Fatal("note should describe the configured endpoint")
	}
	if _, ok := resolve(localAgentKey); !ok {
		t.Fatal("local key should resolve")
	}
	if _, ok := resolve("other"); ok {
		t.Fatal("non-local key must not resolve")
	}
	// Blank endpoint ⇒ resolver knows no agents.
	resolveNone, noteNone := releaseAgentResolver("")
	if noteNone != "none" {
		t.Fatalf("note = %q; want none", noteNone)
	}
	if _, ok := resolveNone(localAgentKey); ok {
		t.Fatal("blank endpoint must resolve no agents")
	}
}

// An UNSIGNED seeded catalog loads at startup ONLY under the explicit break-glass
// permissive mode — never under the secure default. (The secure-default refusal is
// covered by TestLoadReleaseManagement_UnsignedNotAutoTrusted.)
func TestLoadReleaseManagement_LoadsSeededCatalog_BreakGlassPermissive(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	dir := t.TempDir()
	writeUnsignedCatalogDir(t, dir, validSource())

	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo: defaultReleaseProxyRepo, catalogDir: dir, maintURL: "",
		verifyMode: VerifyPermissive, // BREAK-GLASS: unsigned accepted
	})
	if currentReleaseManager() == nil {
		t.Fatal("manager not published")
	}
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	body := decodeBody(t, rec)
	if body["available"] != true {
		t.Fatalf("available = %v; want true (unsigned seeded catalog loads under break-glass permissive)", body["available"])
	}
	if body["verify_mode"] != "permissive" {
		t.Errorf("verify_mode = %v; want permissive", body["verify_mode"])
	}
	if rels, ok := body["releases"].([]any); !ok || len(rels) != 2 {
		t.Fatalf("releases = %v; want the 2 seeded releases", body["releases"])
	}
}

// The center of Phase 1: an UNSIGNED catalog on disk is NEVER auto-trusted under
// the secure default. With no trust roots and no break-glass override the trust
// ring is empty in enforce mode, so Release Management is disabled (manager nil,
// routes report 503) — the unsigned catalog is never published.
func TestLoadReleaseManagement_UnsignedNotAutoTrusted(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	dir := t.TempDir()
	writeUnsignedCatalogDir(t, dir, validSource())

	setReleaseManager(nil)
	// Resolve through the REAL resolver with empty env. The baked official
	// Sigstore root (P2b-2a) now ACTIVATES the keyless scheme ⇒ enforce mode, so
	// Release Management is ENABLED. The security property is unchanged and tested
	// here at the catalog level: an UNSIGNED on-disk catalog must NOT be trusted —
	// scheme selection finds no .sigstore and no ed25519 sig ⇒ enforce reject ⇒
	// the catalog is never published (available:false), no dispatch.
	cfg := resolveReleaseStartupConfigFrom(func(string) string { return "" })
	cfg.catalogDir = dir
	cfg.statePath = filepath.Join(t.TempDir(), "state.json")
	loadReleaseManagement(cfg)
	if currentReleaseManager() == nil {
		t.Fatal("manager should be enabled (baked Sigstore root ⇒ enforce mode)")
	}
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	body := decodeBody(t, rec)
	if body["available"] == true {
		t.Fatalf("an unsigned catalog must NOT be auto-trusted: available must be false; body=%s", rec.Body.String())
	}
}

// writeUnsignedCatalogDir materializes a memSource's index + manifests on disk
// WITHOUT a signature — loadable under permissive trust (no keys).
func TestLoadReleaseManagement_LoadsSignedSeededCatalogWithConfiguredTrust(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Enforce mode now also requires a future expires_at + catalog_version ≥ 1.
	writeSignedCatalogDir(t, dir, priv, freshValidSource("2099-01-01T00:00:00Z", 7))

	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:  defaultReleaseProxyRepo,
		catalogDir: dir,
		statePath:  filepath.Join(t.TempDir(), "state.json"),
		maintURL:   "",
		verifyMode: VerifyEnforce,
		trustKeys: []TrustKey{{
			KeyID:     holderTestKeyID,
			Alg:       catalogSigAlg,
			PublicKey: pub,
		}},
	})
	if currentReleaseManager() == nil {
		t.Fatal("manager not published")
	}
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	body := decodeBody(t, rec)
	if body["available"] != true {
		t.Fatalf("available = %v; want true for signed catalog trusted at startup; body=%s", body["available"], rec.Body.String())
	}
	if body["verify_mode"] != "enforce" {
		t.Errorf("verify_mode = %v; want enforce", body["verify_mode"])
	}
	if body["catalog_version"] != float64(7) {
		t.Errorf("catalog_version = %v; want 7", body["catalog_version"])
	}
	if body["expires_at"] != "2099-01-01T00:00:00Z" {
		t.Errorf("expires_at = %v; want 2099-01-01T00:00:00Z", body["expires_at"])
	}
}

func writeUnsignedCatalogDir(t *testing.T, dir string, ms *memSource) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), ms.index, 0o600); err != nil {
		t.Fatal(err)
	}
	for ref, b := range ms.manifests {
		if err := os.WriteFile(filepath.Join(dir, "manifests", ref), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadReleaseManagement_PublishesAndGraceful(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })

	// A valid config publishes a usable backend (routes leave the 503 state).
	// Break-glass permissive lets the manager publish with an empty catalog dir
	// without configuring roots (the secure-default no-roots path is covered by
	// TestLoadReleaseManagement_UnsignedNotAutoTrusted).
	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo: defaultReleaseProxyRepo, catalogDir: "/tmp/nonexistent-catalog", maintURL: "",
		verifyMode: VerifyPermissive,
	})
	if currentReleaseManager() == nil {
		t.Fatal("valid config must publish a release manager")
	}
	// With an empty holder the read route is live and reports available:false.
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	if rec.Code != http.StatusOK || decodeBody(t, rec)["available"] != false {
		t.Fatalf("GET /api/releases after wiring = %d %s; want 200 available:false", rec.Code, rec.Body.String())
	}

	// An invalid proxy_repo fails construction gracefully: manager stays nil
	// (routes report 503), never a panic. Permissive so it reaches the dispatch
	// service (the proxy_repo validator) rather than failing earlier at trust.
	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{proxyRepo: "", catalogDir: "/tmp/x", maintURL: "", verifyMode: VerifyPermissive})
	if currentReleaseManager() != nil {
		t.Fatal("invalid proxy_repo must leave the manager unpublished (503), not panic")
	}
}
