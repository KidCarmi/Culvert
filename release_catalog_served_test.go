package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// ─── M0-PR2: served-catalog verification ─────────────────────────────────────
//
// Objective: prove catalog bytes served over HTTP are validated through the REAL
// production verification path before promotion.
//
// These tests drive the real production orchestrator autoSeedCatalog
// (Stage → LoadVerifiedCatalog → checkCatalogFreshness → readVersionFloor →
// checkCatalogRollback → swapCatalogDir) backed by a real HTTPCatalogProvider served
// over httptest — the ONE dimension release_autoseed_test.go (which uses a fake
// stager returning a local dir) does not cover: bytes that actually traversed HTTP.
// The leaf verify/freshness/rollback negatives are already proven there; here we
// assert the transport-driven path reaches the same fail-closed outcomes and that a
// failed seed leaves the destination untouched.

// servedHTTP starts a fake origin serving `files` and returns a real provider wired
// to it, staged on the SAME filesystem as the auto-seed destination (base) so
// swapCatalogDir's os.Rename is atomic (no EXDEV).
func servedHTTP(t *testing.T, base string, trust TrustStore, files map[string][]byte) *HTTPCatalogProvider {
	t.Helper()
	f := &fakeCatalogServer{files: files}
	p, _ := newHTTPProvider(t, f, trust)
	p.stageBase = base
	return p
}

func assertServedInstalled(t *testing.T, catalogDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(catalogDir, "index.json")); err != nil {
		t.Fatalf("catalog was not promoted into the destination: %v", err)
	}
}

func assertServedRejectedUntouched(t *testing.T, p *HTTPCatalogProvider, cfg autoSeedConfig, catalogDir string) {
	t.Helper()
	if err := autoSeedCatalog(context.Background(), p, cfg); err == nil {
		t.Fatal("autoSeedCatalog accepted served bytes that must be rejected")
	}
	if _, err := os.Stat(filepath.Join(catalogDir, "index.json")); !os.IsNotExist(err) {
		t.Fatalf("destination catalog must be untouched on a failed seed; stat err=%v", err)
	}
}

// TestServedVerify_Contract drives the real autoSeedCatalog orchestrator over real
// HTTP: a valid served catalog installs; tamper/expired/rollback/malformed reject
// with the destination untouched. The freshness (expired) and rollback (persisted
// floor) negatives are the ones NOT previously exercised on the served path.
func TestServedVerify_Contract(t *testing.T) {
	t.Run("valid served catalog installs", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust) // injected now = 2026-05-01
		p := servedHTTP(t, base, trust, signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3)))
		if err := autoSeedCatalog(context.Background(), p, cfg); err != nil {
			t.Fatalf("valid served catalog should install: %v", err)
		}
		assertServedInstalled(t, catalogDir)
	})

	t.Run("tampered index rejected", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust)
		files := signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3))
		files["/index.json"] = append([]byte("tamper"), files["/index.json"]...) // corrupt AFTER signing
		assertServedRejectedUntouched(t, servedHTTP(t, base, trust, files), cfg, catalogDir)
	})

	t.Run("expired catalog rejected (freshness over transport)", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust) // now = 2026-05-01
		// expires_at (2026-04-20) is after generated_at (2026-04-18) but before now
		// → validly signed, structurally fine, rejected by the freshness gate.
		p := servedHTTP(t, base, trust, signedCatalogFiles(t, priv, freshValidSource("2026-04-20T00:00:00Z", 3)))
		assertServedRejectedUntouched(t, p, cfg, catalogDir)
	})

	t.Run("rollback rejected (persisted floor over transport)", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust)
		if err := (freshnessPolicy{enabled: true, statePath: cfg.statePath}).writeVersionFloor(5); err != nil {
			t.Fatal(err)
		}
		// served catalog_version 4 < persisted floor 5 → rollback refused. This
		// exercises the PERSISTED floor read (readVersionFloor), not a hand-passed int.
		p := servedHTTP(t, base, trust, signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 4)))
		assertServedRejectedUntouched(t, p, cfg, catalogDir)
	})

	t.Run("malformed index rejected", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust)
		bad := []byte("{ not valid json")
		files := map[string][]byte{
			"/index.json":     bad,
			"/index.json.sig": sigEnvelopeBytes(t, catalogSigAlg, holderTestKeyID, ed25519.Sign(priv, bad)),
		}
		assertServedRejectedUntouched(t, servedHTTP(t, base, trust, files), cfg, catalogDir)
	})
}

// TestServedVerify_BakedRootFailClosed proves the REAL baked-root Sigstore trust
// store is consulted on the served path and FAILS CLOSED — the locally-provable half
// of must-prove #8. A validly ed25519-signed served catalog is rejected because the
// baked-root (sigstore-only, enforce) store has no valid Fulcio bundle to accept.
// The baked-root POSITIVE over real Fulcio-signed bytes needs CI signing and is PR3
// (TestServedVerify_BakedRootGate).
func TestServedVerify_BakedRootFailClosed(t *testing.T) {
	sv, err := newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())
	if err != nil {
		t.Fatalf("baked-root verifier: %v", err)
	}
	bakedTrust, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)
	if err != nil {
		t.Fatalf("baked-root trust store: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	cfg, catalogDir := autoSeedCfg(t, base, bakedTrust)
	p := servedHTTP(t, base, bakedTrust, signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3)))
	assertServedRejectedUntouched(t, p, cfg, catalogDir)
}

// TestServedVerify_ArtifactOwnsOutcome proves the anti-downgrade property OVER HTTP:
// with BOTH schemes configured (a valid ed25519 key + a virtual Sigstore verifier),
// a present-but-invalid .sigstore sidecar REJECTS and does NOT fall through to the
// valid ed25519 signature (the strip-one-of-two downgrade vector). The existing
// memDualSource test proves this at the unit level; this proves it through the
// transport (the provider's dual-sidecar fetch + compose).
func TestServedVerify_ArtifactOwnsOutcome(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	sv, err := newSigstoreVerifierFromMaterial(vs, officialSigstoreIdentity())
	if err != nil {
		t.Fatalf("virtual sigstore verifier: %v", err)
	}
	dualTrust, err := NewTrustStoreWithSigstore(
		[]TrustKey{{KeyID: holderTestKeyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce, sv)
	if err != nil {
		t.Fatalf("dual trust store: %v", err)
	}
	base := t.TempDir()
	cfg, catalogDir := autoSeedCfg(t, base, dualTrust)

	files := signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3)) // valid ed25519 .sig
	files["/index.json.sigstore"] = []byte("garbage-not-a-sigstore-bundle")           // present but invalid
	assertServedRejectedUntouched(t, servedHTTP(t, base, dualTrust, files), cfg, catalogDir)
}

// TestServedVerify_BakedRootGate is the baked-root POSITIVE over HTTP against REAL
// Fulcio-signed bytes. That requires a CI keyless-signed published catalog, so it is
// env-gated on CULVERT_RELEASE_SERVED_URL and exercised by PR3's dormant job against
// a freshly-staged published catalog — it is a skip locally. It keeps the PRODUCTION
// SSRF guard (NewHTTPCatalogProvider's default isPrivateHost) and drives the full
// autoSeedCatalog path. Named here to keep the served-verify surface in one place.
func TestServedVerify_BakedRootGate(t *testing.T) {
	url := os.Getenv("CULVERT_RELEASE_SERVED_URL")
	if url == "" {
		t.Skip("served baked-root positive: set CULVERT_RELEASE_SERVED_URL to a published catalog origin (PR3/owner)")
	}
	sv, err := newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())
	if err != nil {
		t.Fatalf("baked-root verifier: %v", err)
	}
	trust, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewHTTPCatalogProvider(url, trust) // production guard (isPrivateHost) retained
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	p.stageBase = base
	cfg := autoSeedConfig{
		catalogDir: filepath.Join(base, "release_catalog"),
		statePath:  filepath.Join(base, "state.json"),
		trust:      trust,
		skew:       catalogClockSkew,
	}
	if err := autoSeedCatalog(context.Background(), p, cfg); err != nil {
		t.Fatalf("baked-root served positive failed: %v", err)
	}
	assertServedInstalled(t, cfg.catalogDir)
}
