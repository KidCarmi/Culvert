package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestE2ESeedSignedCatalog is the seed step of the real-binary / real-image
// catalog E2E (.github/workflows/catalog-e2e.yml). It is NOT a unit assertion —
// it is a CI helper that generates a deterministic catalog, ed25519-signs
// index.json, writes the full bundle (index.json + index.json.sig + manifests/)
// into the seed dir, and writes the matching trust-keys JSON, so the workflow can
// start a real Control Plane in enforce mode and assert the catalog loads +
// verifies + serves. Skipped unless CULVERT_E2E_SEED_OUT (+ _KEYS) are set.
//
// Env knobs (all optional except OUT/KEYS) — these let one helper drive a whole
// upgrade + anti-rollback sequence by re-seeding with the SAME key:
//
//	CULVERT_E2E_SEED_OUT        catalog dir to populate (required)
//	CULVERT_E2E_SEED_KEYS       file to write the trust-keys JSON (pubkey) to (required)
//	CULVERT_E2E_SEED_PRIV       file to persist/REUSE the ed25519 private seed; if it
//	                            exists it is reused so successive seeds share ONE key
//	                            (the CP is started once with that key as its root)
//	CULVERT_E2E_SEED_VERSION    catalog_version (default 1) — raise it to test upgrade,
//	                            lower it (below the persisted floor) to test rollback
//	CULVERT_E2E_SEED_VERSION_ID release version_id (default 9.9.9)
//	CULVERT_E2E_SEED_EXPIRES    expires_at RFC3339 (default 2099-01-01T00:00:00Z)
func TestE2ESeedSignedCatalog(t *testing.T) {
	outDir := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_OUT"))
	keysFile := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_KEYS"))
	if outDir == "" || keysFile == "" {
		t.Skip("set CULVERT_E2E_SEED_OUT and CULVERT_E2E_SEED_KEYS to seed a real E2E catalog")
	}

	version := envIntOr(t, "CULVERT_E2E_SEED_VERSION", 1)
	versionID := envOr("CULVERT_E2E_SEED_VERSION_ID", "9.9.9")
	expires := envOr("CULVERT_E2E_SEED_EXPIRES", "2099-01-01T00:00:00Z")

	spec := releaseCatalogSpec{
		GeneratedAt:    "2026-01-01T00:00:00Z",
		ExpiresAt:      expires,
		CatalogVersion: version,
		Entries: []releaseEntrySpec{{
			ReleaseID:  "culvert-" + versionID,
			VersionID:  versionID,
			Severity:   "normal",
			Repo:       "ghcr.io/kidcarmi/culvert",
			ListDigest: "sha256:" + strings.Repeat("a", 64),
			Platforms:  []string{"linux/amd64", "linux/arm64"},
			CreatedAt:  "2026-01-01T00:00:00Z",
			Channels:   []Channel{ChannelRecommended},
		}},
	}
	bundle, err := generateReleaseCatalog(spec)
	if err != nil {
		t.Fatalf("generateReleaseCatalog: %v", err)
	}

	// Stable key across re-seeds: the CP is started ONCE with this key's pubkey as
	// its trust root, so an upgrade (v2) signed by a different key would be
	// rejected. Persist the private seed and reuse it on later seeds.
	priv := e2eLoadOrCreateKey(t, strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_PRIV")))
	pub := priv.Public().(ed25519.PublicKey)

	const keyID = "e2e-catalog"
	sigEnv := sigEnvelopeBytes(t, catalogSigAlg, keyID, ed25519.Sign(priv, bundle.Index))
	if err := writeReleaseBundle(outDir, bundle, sigEnv); err != nil {
		t.Fatalf("writeReleaseBundle: %v", err)
	}

	keysJSON := fmt.Sprintf(`[{"key_id":%q,"alg":%q,"public_key":%q}]`,
		keyID, catalogSigAlg, base64.StdEncoding.EncodeToString(pub))
	if err := os.WriteFile(keysFile, []byte(keysJSON), 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
	t.Logf("seeded signed catalog into %s (catalog_version=%d, version_id=%s, expires=%s)",
		outDir, version, versionID, expires)
}

// e2eLoadOrCreateKey reuses a persisted ed25519 seed (so a re-seed keeps the same
// key the CP already trusts) or mints + persists a fresh one. With no path it
// just mints an ephemeral key (single-seed callers).
func e2eLoadOrCreateKey(t *testing.T, privPath string) ed25519.PrivateKey {
	t.Helper()
	if privPath != "" {
		if seed, err := os.ReadFile(privPath); err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed)
		}
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_ = pub
	if privPath != "" {
		if err := os.WriteFile(privPath, priv.Seed(), 0o600); err != nil {
			t.Fatalf("persist priv seed: %v", err)
		}
	}
	return priv
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envIntOr(t *testing.T, key string, def int) int {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("%s must be an int: %v", key, err)
	}
	return n
}
