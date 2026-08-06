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
	// Hermetic (M1-2): the baked default origin would otherwise make
	// loadReleaseManagement auto-seed from catalog.culvertlabs.com in enforce mode,
	// fetching the REAL signed catalog and overwriting the unsigned dir under test
	// (an available:true false-pass that flakes on runner egress). This test is
	// about on-disk trust, not auto-seed, so disable the fetch.
	cfg.catalogURL = ""
	cfg.catalogURLSource = catalogURLSourceDisabled
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

// TestLoadReleaseManagement_SigstoreWarnSurfacedOnAPI proves a Sigstore trust
// misconfiguration (identity override set without a trusted root) reaches
// GET /api/releases instead of only the startup log — previously an operator
// who believed they'd pinned a custom Sigstore identity had no way to
// discover from the GUI/API that it silently didn't take effect.
func TestLoadReleaseManagement_SigstoreWarnSurfacedOnAPI(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	setReleaseManager(nil)

	const wantWarn = "release catalog: test sigstore misconfiguration"
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo: defaultReleaseProxyRepo, catalogDir: "/tmp/nonexistent-catalog", maintURL: "",
		verifyMode:   VerifyPermissive,
		sigstoreWarn: wantWarn,
	})
	rm := currentReleaseManager()
	if rm == nil {
		t.Fatal("valid config must publish a release manager")
	}
	if rm.sigstoreWarn != wantWarn {
		t.Fatalf("releaseManager.sigstoreWarn = %q, want %q", rm.sigstoreWarn, wantWarn)
	}

	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/releases = %d %s; want 200", rec.Code, rec.Body.String())
	}
	if got := decodeBody(t, rec)["sigstore_warn"]; got != wantWarn {
		t.Fatalf("GET /api/releases sigstore_warn = %v, want %q", got, wantWarn)
	}
}

// TestLoadReleaseManagement_SigstoreWarnSurfacedWhenTrustFails covers the case
// the warning actually exists for: enforce mode with no ed25519 roots and an
// inactive Sigstore scheme (a custom identity set without a trusted root). The
// trust store then fails to build with an empty enforce ring, so the normal
// wiring returns before publishing a manager and GET /api/releases would 503 —
// leaving the operator no way to see WHY. A warning-only manager must be
// published so the reason surfaces. The sibling test above uses VerifyPermissive,
// where trust construction succeeds and never exercises this path.
func TestLoadReleaseManagement_SigstoreWarnSurfacedWhenTrustFails(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	setReleaseManager(nil)

	const wantWarn = "release catalog: sigstore identity override set without a trusted root"
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo: defaultReleaseProxyRepo, catalogDir: "/tmp/nonexistent-catalog", maintURL: "",
		verifyMode:   VerifyEnforce, // enforce + empty ring → NewTrustStoreWithSigstore fails
		trustKeys:    nil,
		sigstore:     nil,
		sigstoreWarn: wantWarn,
	})

	rm := currentReleaseManager()
	if rm == nil {
		t.Fatal("a warning-only manager must be published when trust construction fails with a sigstore warning, else the operator gets a blank 503")
	}
	if rm.svc != nil {
		t.Fatal("warning-only manager must carry no dispatch service (release management is disabled)")
	}

	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/releases = %d %s; want 200 (available:false + warning, not 503)", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if body["available"] != false {
		t.Errorf("available = %v, want false", body["available"])
	}
	if got := body["sigstore_warn"]; got != wantWarn {
		t.Fatalf("GET /api/releases sigstore_warn = %v, want %q", got, wantWarn)
	}
}

// ─── M1-2 product revision: baked default catalog origin ──────────────────────
// Owner-required behaviors: default resolution, override precedence, empty
// fallback, mirror URLs verbatim, the trust-safe disable sentinel, and origin
// never affecting trust.

func TestResolveCatalogURL_DefaultWhenUnset(t *testing.T) {
	cfg := resolveReleaseStartupConfigFrom(func(string) string { return "" })
	if cfg.catalogURL != defaultReleaseCatalogURL || cfg.catalogURLSource != catalogURLSourceDefault {
		t.Fatalf("unset env must resolve the baked default; got %q (source=%q)",
			cfg.catalogURL, cfg.catalogURLSource)
	}
}

func TestResolveCatalogURL_OverridePrecedence(t *testing.T) {
	cfg := resolveReleaseStartupConfigFrom(func(k string) string {
		if k == envReleaseCatalogURL {
			return "https://staging.example.com/catalog"
		}
		return ""
	})
	if cfg.catalogURL != "https://staging.example.com/catalog" || cfg.catalogURLSource != catalogURLSourceOverride {
		t.Fatalf("explicit override must win; got %q (source=%q)", cfg.catalogURL, cfg.catalogURLSource)
	}
}

func TestResolveCatalogURL_EmptyOverrideFallsBack(t *testing.T) {
	for _, v := range []string{"", "   ", "\t"} {
		url, source := resolveCatalogURL(v)
		if url != defaultReleaseCatalogURL || source != catalogURLSourceDefault {
			t.Fatalf("empty/whitespace override %q must fall back to the default; got %q (source=%q)", v, url, source)
		}
	}
}

func TestResolveCatalogURL_MirrorURLVerbatim(t *testing.T) {
	// Air-gap/internal-mirror override is used VERBATIM at resolution time (the
	// SSRF guard applies at provider construction, by design — see the
	// defaultReleaseCatalogURL doc comment for the recorded private-IP constraint).
	mirror := "https://catalog-mirror.corp.example.com/releases"
	url, source := resolveCatalogURL(mirror)
	if url != mirror || source != catalogURLSourceOverride {
		t.Fatalf("mirror override must be used verbatim; got %q (source=%q)", url, source)
	}
}

// The trust-SAFE opt-out (M1-2 review HIGH): a disable sentinel stops outbound
// fetch (empty URL ⇒ wantSeed false) WITHOUT touching trust — the only prior way
// to silence the fetch was CULVERT_RELEASE_CATALOG_VERIFY=permissive/disabled,
// which weakens the trust channel. Verify mode/roots stay identical to the default.
func TestResolveCatalogURL_DisableSentinel(t *testing.T) {
	for _, v := range []string{"off", "none", "disabled", "OFF", " Disabled "} {
		url, source := resolveCatalogURL(v)
		if url != "" || source != catalogURLSourceDisabled {
			t.Fatalf("disable sentinel %q must yield no fetch; got url=%q source=%q", v, url, source)
		}
	}
	// Trust is untouched by disabling the fetch: mode + roots match the default.
	base := resolveReleaseStartupConfigFrom(func(string) string { return "" })
	off := resolveReleaseStartupConfigFrom(func(k string) string {
		if k == envReleaseCatalogURL {
			return "off"
		}
		return ""
	})
	if off.catalogURL != "" || off.catalogURLSource != catalogURLSourceDisabled {
		t.Fatalf("disabled config must carry no origin; got url=%q source=%q", off.catalogURL, off.catalogURLSource)
	}
	if off.verifyMode != base.verifyMode || len(off.trustKeys) != len(base.trustKeys) || off.sigstoreActive != base.sigstoreActive {
		t.Fatal("disabling the fetch must NOT change the trust posture (mode/roots/sigstore)")
	}
}

// Changing the origin must NEVER change trust: verify mode and the trust
// material are identical whether the origin is the default or an override, and
// enforce mode stays enforced on overridden origins. (Byte-level proof that a
// served origin cannot bypass verification is the TestServedVerify_* suite,
// which drives the same trust store against arbitrary origins.)
func TestCatalogURLSource_DoesNotAffectTrust(t *testing.T) {
	base := func(k string) string { return "" }
	withOverride := func(k string) string {
		if k == envReleaseCatalogURL {
			return "https://mirror.example.net/catalog"
		}
		return ""
	}
	a := resolveReleaseStartupConfigFrom(base)
	b := resolveReleaseStartupConfigFrom(withOverride)
	if a.verifyMode != b.verifyMode {
		t.Fatalf("verify mode changed with origin: %v vs %v", a.verifyMode, b.verifyMode)
	}
	if len(a.trustKeys) != len(b.trustKeys) || a.sigstoreActive != b.sigstoreActive {
		t.Fatal("trust material changed with origin — the origin must never affect trusted roots/identities")
	}
	// With the baked Sigstore root present, the default build is enforce mode: an
	// overridden origin therefore still requires full verification.
	if b.sigstoreActive && b.verifyMode != VerifyEnforce {
		t.Fatalf("override origin must remain enforce with the baked root; got %v", b.verifyMode)
	}
}

// M1-2 review HIGH (UX): a boot-time seed failure on a default/enforce appliance
// must be visible on /api/releases IMMEDIATELY (trigger "startup"), not only after
// the first periodic tick ~one interval later. Here the origin is SSRF-rejected
// (a private host), so the startup seed fails with NO network, and the failure
// must appear in refreshStatus/last_refresh right after wiring.
func TestLoadReleaseManagement_StartupSeedFailureRecorded(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:  defaultReleaseProxyRepo,
		catalogDir: filepath.Join(base, "release_catalog"),
		statePath:  filepath.Join(base, "state.json"),
		maintURL:   "",
		verifyMode: VerifyEnforce,
		trustKeys:  []TrustKey{{KeyID: "startup-test", Alg: catalogSigAlg, PublicKey: pub}},
		// Private host ⇒ the SSRF guard rejects the seed before any dial: a
		// deterministic, network-free startup-seed failure.
		catalogURL:       "https://127.0.0.1/release-catalog",
		catalogURLSource: catalogURLSourceOverride,
	})
	rm := currentReleaseManager()
	if rm == nil {
		t.Fatal("enforce wiring with roots must still publish a manager (seed failure is non-fatal)")
	}
	st := rm.refreshStatusSnapshot()
	if st.LastAt.IsZero() || st.LastTrigger != "startup" || st.LastOK {
		t.Fatalf("startup seed failure not recorded as an immediate failure: %+v", st)
	}
	if st.ConsecutiveFailures != 1 {
		t.Fatalf("startup failure must count once; got %d", st.ConsecutiveFailures)
	}
	// The immediate failure is visible on the read API (no ~6h blind window), and
	// the redacted error must not leak the origin path.
	rec := httptest.NewRecorder()
	apiReleases(rec, releaseReq(http.MethodGet, "/api/releases", nil, RoleViewer))
	body := decodeBody(t, rec)
	lr, ok := body["last_refresh"].(map[string]any)
	if !ok {
		t.Fatalf("last_refresh missing from /api/releases: %s", rec.Body.String())
	}
	if lr["last_trigger"] != "startup" || lr["last_ok"] != false {
		t.Fatalf("last_refresh does not show the startup failure: %v", lr)
	}
	if src := body["catalog_url_source"]; src != catalogURLSourceOverride {
		t.Fatalf("catalog_url_source = %v; want override", src)
	}
}
