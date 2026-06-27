package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestE2ESeedSignedCatalog is the seed step of the real-binary catalog E2E
// (.github/workflows/catalog-e2e.yml). It is NOT a unit assertion — it is a CI
// helper that, when CULVERT_E2E_SEED_OUT (+ CULVERT_E2E_SEED_KEYS) are set,
// generates a deterministic catalog, ed25519-signs index.json with a FRESH key,
// writes the full bundle (index.json + index.json.sig + manifests/) into the seed
// dir, and writes the matching trust-keys JSON so the workflow can start a real
// Control Plane in enforce mode and assert the catalog loads + verifies + serves
// available:true. Skipped unless the env is set, so it never runs in the normal
// unit suite.
func TestE2ESeedSignedCatalog(t *testing.T) {
	outDir := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_OUT"))
	keysFile := strings.TrimSpace(os.Getenv("CULVERT_E2E_SEED_KEYS"))
	if outDir == "" || keysFile == "" {
		t.Skip("set CULVERT_E2E_SEED_OUT and CULVERT_E2E_SEED_KEYS to seed a real-binary E2E catalog")
	}

	// Far-future expires_at so the enforce-mode freshness gate passes; a fixed
	// past generated_at (not future-dated); catalog_version ≥ 1.
	spec := releaseCatalogSpec{
		GeneratedAt:    "2026-01-01T00:00:00Z",
		ExpiresAt:      "2099-01-01T00:00:00Z",
		CatalogVersion: 1,
		Entries: []releaseEntrySpec{{
			ReleaseID:  "culvert-9.9.9",
			VersionID:  "9.9.9",
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

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
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
	t.Logf("seeded signed catalog into %s (catalog_version=1, version_id=9.9.9); trust keys → %s", outDir, keysFile)
}
