package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeStager returns a pre-built staged dir (or an error) for autoSeedCatalog.
type fakeStager struct {
	dir string
	err error
}

func (f *fakeStager) Stage(context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.dir, nil
}

// seedFixture builds an enforce trust store (trusting a fresh key under
// holderTestKeyID) and a shared base dir; the returned private key signs the
// staged fixtures.
func seedFixture(t *testing.T) (priv ed25519.PrivateKey, trust TrustStore, base string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err = NewTrustStore([]TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	return priv, trust, t.TempDir()
}

// stageSignedDir materializes a signed+fresh catalog into base/<name> (same FS as
// the destination so the swap rename is atomic).
func stageSignedDir(t *testing.T, base, name string, priv ed25519.PrivateKey, expiresAt string, version int) string {
	t.Helper()
	dir := filepath.Join(base, name)
	writeSignedCatalogDir(t, dir, priv, freshValidSource(expiresAt, version))
	return dir
}

func autoSeedCfg(t *testing.T, base string, trust TrustStore) (autoSeedConfig, string) {
	t.Helper()
	catalogDir := filepath.Join(base, "release_catalog")
	now := mustTime(t, "2026-05-01T00:00:00Z")
	return autoSeedConfig{
		catalogDir: catalogDir,
		statePath:  filepath.Join(base, "state.json"),
		trust:      trust,
		now:        func() time.Time { return now },
		skew:       catalogClockSkew,
	}, catalogDir
}

func TestAutoSeed_HappyPath(t *testing.T) {
	priv, trust, base := seedFixture(t)
	cfg, catalogDir := autoSeedCfg(t, base, trust)
	stage := stageSignedDir(t, base, "stage", priv, "2099-01-01T00:00:00Z", 3)

	if err := autoSeedCatalog(context.Background(), &fakeStager{dir: stage}, cfg); err != nil {
		t.Fatalf("happy path: %v", err)
	}
	// release_catalog/ now holds the verified catalog and loads cleanly.
	if _, err := os.Stat(filepath.Join(catalogDir, "index.json")); err != nil {
		t.Fatalf("catalog not installed: %v", err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: catalogDir}, trust)
	if err != nil || cat.Version() != 3 {
		t.Fatalf("installed catalog not loadable/version wrong: cat=%v err=%v", cat, err)
	}
	// The staged dir was consumed (moved), not left behind.
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Errorf("staged dir should have been moved, still present: %v", err)
	}
}

func TestAutoSeed_UnchangedIsNoop(t *testing.T) {
	_, trust, base := seedFixture(t)
	cfg, catalogDir := autoSeedCfg(t, base, trust)
	if err := autoSeedCatalog(context.Background(), &fakeStager{err: errCatalogUnchanged}, cfg); err != nil {
		t.Fatalf("304 must be a no-op, got %v", err)
	}
	if _, err := os.Stat(catalogDir); !os.IsNotExist(err) {
		t.Error("304 must not create release_catalog/")
	}
}

func TestAutoSeed_FailClosedMatrix(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, base string, priv ed25519.PrivateKey) string
	}{
		{"forged: untrusted signing key", func(t *testing.T, base string, _ ed25519.PrivateKey) string {
			_, other, _ := ed25519.GenerateKey(nil)
			return stageSignedDir(t, base, "stage", other, "2099-01-01T00:00:00Z", 3)
		}},
		{"expired", func(t *testing.T, base string, priv ed25519.PrivateKey) string {
			return stageSignedDir(t, base, "stage", priv, "2026-04-19T00:00:00Z", 3) // before now
		}},
		{"missing expires_at", func(t *testing.T, base string, priv ed25519.PrivateKey) string {
			return stageSignedDir(t, base, "stage", priv, "", 3)
		}},
		{"missing catalog_version", func(t *testing.T, base string, priv ed25519.PrivateKey) string {
			return stageSignedDir(t, base, "stage", priv, "2099-01-01T00:00:00Z", 0)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, trust, base := seedFixture(t)
			cfg, catalogDir := autoSeedCfg(t, base, trust)
			stage := tc.build(t, base, priv)
			err := autoSeedCatalog(context.Background(), &fakeStager{dir: stage}, cfg)
			if err == nil {
				t.Fatalf("%s: expected fail-closed error", tc.name)
			}
			if _, serr := os.Stat(catalogDir); !os.IsNotExist(serr) {
				t.Fatalf("%s: a failed seed must not install a catalog", tc.name)
			}
			// staged dir cleaned up on failure
			if _, serr := os.Stat(stage); !os.IsNotExist(serr) {
				t.Errorf("%s: staged dir must be removed on failure", tc.name)
			}
		})
	}
}

func TestAutoSeed_RollbackRefused(t *testing.T) {
	priv, trust, base := seedFixture(t)
	cfg, catalogDir := autoSeedCfg(t, base, trust)
	// Persisted floor is 5; the served catalog is version 4 (a downgrade).
	if err := (freshnessPolicy{enabled: true, statePath: cfg.statePath}).writeVersionFloor(5); err != nil {
		t.Fatal(err)
	}
	stage := stageSignedDir(t, base, "stage", priv, "2099-01-01T00:00:00Z", 4)
	err := autoSeedCatalog(context.Background(), &fakeStager{dir: stage}, cfg)
	if !errors.Is(err, errCatalogRollback) {
		t.Fatalf("downgrade must be refused with errCatalogRollback, got %v", err)
	}
	if _, serr := os.Stat(catalogDir); !os.IsNotExist(serr) {
		t.Fatal("a refused rollback must not install a catalog")
	}
}

// A pre-existing good on-disk catalog is NOT clobbered by a failing seed.
func TestAutoSeed_FailedSeedPreservesExisting(t *testing.T) {
	priv, trust, base := seedFixture(t)
	cfg, catalogDir := autoSeedCfg(t, base, trust)
	// Install a good v5 catalog first (simulate prior good state).
	good := stageSignedDir(t, base, "good", priv, "2099-01-01T00:00:00Z", 5)
	if err := os.Rename(good, catalogDir); err != nil {
		t.Fatal(err)
	}
	// Now a forged seed arrives.
	_, other, _ := ed25519.GenerateKey(nil)
	forged := stageSignedDir(t, base, "forged", other, "2099-01-01T00:00:00Z", 6)
	if err := autoSeedCatalog(context.Background(), &fakeStager{dir: forged}, cfg); err == nil {
		t.Fatal("forged seed must fail")
	}
	// The good v5 catalog must still be intact and loadable.
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: catalogDir}, trust)
	if err != nil || cat.Version() != 5 {
		t.Fatalf("existing good catalog was clobbered by a failed seed: cat=%v err=%v", cat, err)
	}
}

// swapCatalogDir replaces an existing dir and cleans up its backup.
func TestSwapCatalogDir_ReplacesAndCleansBackup(t *testing.T) {
	base := t.TempDir()
	dst := filepath.Join(base, "release_catalog")
	if err := os.MkdirAll(filepath.Join(dst, "old"), 0o750); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(base, "stage")
	if err := os.MkdirAll(filepath.Join(stage, "new"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := swapCatalogDir(stage, dst); err != nil {
		t.Fatalf("swap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "new")); err != nil {
		t.Error("destination should contain the staged content")
	}
	if _, err := os.Stat(dst + ".bak"); !os.IsNotExist(err) {
		t.Error("backup must be cleaned up after a successful swap")
	}
}

// ─── runStartupAutoSeed SSRF / scheme guard (no network needed) ──────────────

func TestRunStartupAutoSeed_RejectsPrivateAndBadScheme(t *testing.T) {
	_, trust, base := seedFixture(t)
	cfg := releaseStartupConfig{
		catalogDir: filepath.Join(base, "release_catalog"),
		statePath:  filepath.Join(base, "state.json"),
	}
	for _, tc := range []struct{ name, url string }{
		{"private ip", "http://127.0.0.1:9999/catalog"},
		{"loopback host", "http://localhost:8080/catalog"},
		{"bad scheme", "ftp://example.com/catalog"},
		{"no host", "https:///catalog"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg.catalogURL = tc.url
			if err := runStartupAutoSeed(cfg, trust); err == nil {
				t.Fatalf("%s: expected rejection before any outbound request", tc.url)
			}
			if _, err := os.Stat(cfg.catalogDir); !os.IsNotExist(err) {
				t.Error("a rejected seed must not create release_catalog/")
			}
		})
	}
}

func TestSeedHost(t *testing.T) {
	if got := seedHost("https://user:pass@cdn.example.com:8443/releases/index.json?t=1"); got != "cdn.example.com:8443" {
		t.Errorf("seedHost leaked more than host: %q", got)
	}
	if got := seedHost("://broken"); got != "configured-url" {
		t.Errorf("malformed URL host = %q; want placeholder", got)
	}
}

// In break-glass permissive mode the auto-seed is SKIPPED entirely (never
// fetches), so even a private/bogus URL is safe: the manager still publishes and
// reports available:false, with no network attempt. Guards the enforce-only gate.
func TestLoadReleaseManagement_AutoSeedSkippedInPermissive(t *testing.T) {
	t.Cleanup(func() { setReleaseManager(nil) })
	setReleaseManager(nil)
	loadReleaseManagement(releaseStartupConfig{
		proxyRepo:  defaultReleaseProxyRepo,
		catalogDir: filepath.Join(t.TempDir(), "release_catalog"),
		maintURL:   "",
		verifyMode: VerifyPermissive,
		// A private URL would be SSRF-rejected if a fetch were attempted; skip path
		// means it is never touched.
		catalogURL: "http://127.0.0.1:9/should-never-be-fetched",
	})
	if currentReleaseManager() == nil {
		t.Fatal("permissive wiring must still publish a manager")
	}
}

func TestResolveReleaseStartupConfig_CatalogURL(t *testing.T) {
	cfg := resolveReleaseStartupConfigFrom(func(k string) string {
		if k == envReleaseCatalogURL {
			return "  https://cdn.example.com/releases  "
		}
		return ""
	})
	if cfg.catalogURL != "https://cdn.example.com/releases" {
		t.Errorf("catalogURL = %q; want trimmed URL", cfg.catalogURL)
	}
}
