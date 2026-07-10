package main

import (
	"context"
	"crypto/ed25519"
	"errors"
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
// to it (plus the origin, for request-count assertions), staged on the SAME
// filesystem as the auto-seed destination (base) so swapCatalogDir's os.Rename is
// atomic (no EXDEV).
func servedHTTP(t *testing.T, base string, trust TrustStore, files map[string][]byte) (*HTTPCatalogProvider, *fakeCatalogServer) {
	t.Helper()
	f := &fakeCatalogServer{files: files}
	p, _ := newHTTPProvider(t, f, trust)
	p.stageBase = base
	return p, f
}

func assertServedInstalled(t *testing.T, catalogDir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(catalogDir, "index.json")); err != nil {
		t.Fatalf("catalog was not promoted into the destination: %v", err)
	}
}

// runFailedSeed runs autoSeedCatalog expecting failure, returns the error, and
// asserts the destination catalog was left untouched (never created).
func runFailedSeed(t *testing.T, p *HTTPCatalogProvider, cfg autoSeedConfig, catalogDir string) error {
	t.Helper()
	err := autoSeedCatalog(context.Background(), p, cfg)
	if err == nil {
		t.Fatal("autoSeedCatalog accepted served bytes that must be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(catalogDir, "index.json")); !os.IsNotExist(statErr) {
		t.Fatalf("destination catalog must be untouched on a failed seed; stat err=%v", statErr)
	}
	return err
}

func assertServedRejectedUntouched(t *testing.T, p *HTTPCatalogProvider, cfg autoSeedConfig, catalogDir string) {
	t.Helper()
	runFailedSeed(t, p, cfg, catalogDir)
}

// assertServedRejectedKind is the stronger form: reject with the EXPECTED error
// kind (not merely non-nil) AND destination untouched. Matching the freshness/
// rollback error identities proves the served bytes were refused by the SPECIFIC
// gate under test, not by some incidental upstream failure.
func assertServedRejectedKind(t *testing.T, p *HTTPCatalogProvider, cfg autoSeedConfig, catalogDir string, want error) {
	t.Helper()
	if err := runFailedSeed(t, p, cfg, catalogDir); !errors.Is(err, want) {
		t.Fatalf("served reject: err = %v; want errors.Is(_, %v)", err, want)
	}
}

// TestServedVerify_Contract drives the real autoSeedCatalog orchestrator over real
// HTTP: a valid served catalog installs; tamper/expired/rollback/malformed reject
// with the destination untouched. The freshness (expired) and rollback (persisted
// floor) negatives are the ones NOT previously exercised on the served path, and
// they assert the SPECIFIC error identity (errCatalogExpired / errCatalogRollback).
func TestServedVerify_Contract(t *testing.T) {
	t.Run("valid served catalog installs", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust) // injected clock: 2026-05-01
		p, _ := servedHTTP(t, base, trust, signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3)))
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
		p, f := servedHTTP(t, base, trust, files)
		assertServedRejectedUntouched(t, p, cfg, catalogDir)
		// Two-phase proof: the index signature is verified BEFORE any manifest is
		// fetched, so a tampered index must be refused without a single manifest GET.
		if n := f.manifestGET.Load(); n != 0 {
			t.Fatalf("tampered index must reject before manifest fetch; manifestGET=%d", n)
		}
	})

	t.Run("expired catalog rejected (freshness over transport)", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust) // injected clock: 2026-05-01
		// expires_at (2026-04-20) is after generated_at (2026-04-18) but before the clock
		// → validly signed, structurally fine, rejected by the freshness gate.
		p, _ := servedHTTP(t, base, trust, signedCatalogFiles(t, priv, freshValidSource("2026-04-20T00:00:00Z", 3)))
		assertServedRejectedKind(t, p, cfg, catalogDir, errCatalogExpired)
	})

	t.Run("rollback rejected (persisted floor over transport)", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust)
		if err := (freshnessPolicy{enabled: true, statePath: cfg.statePath}).writeVersionFloor(5); err != nil {
			t.Fatal(err)
		}
		// served catalog_version 4 < persisted floor 5 → rollback refused. This
		// exercises the PERSISTED floor read (readVersionFloor), not a hand-passed int.
		p, _ := servedHTTP(t, base, trust, signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 4)))
		assertServedRejectedKind(t, p, cfg, catalogDir, errCatalogRollback)
	})

	t.Run("malformed index rejected", func(t *testing.T) {
		priv, trust, base := seedFixture(t)
		cfg, catalogDir := autoSeedCfg(t, base, trust)
		bad := []byte("{ not valid json")
		files := map[string][]byte{
			"/index.json":     bad,
			"/index.json.sig": sigEnvelopeBytes(t, catalogSigAlg, holderTestKeyID, ed25519.Sign(priv, bad)),
		}
		p, _ := servedHTTP(t, base, trust, files)
		assertServedRejectedUntouched(t, p, cfg, catalogDir)
	})
}

// TestServedVerify_NoClobberExisting proves "destination untouched" is a REAL
// no-clobber guarantee, not a trivial consequence of the dest never pre-existing:
// a good catalog (v5) is pre-installed, then a tampered v6 is served. The seed must
// fail and the pre-existing v5 must survive AND still verify.
func TestServedVerify_NoClobberExisting(t *testing.T) {
	priv, trust, base := seedFixture(t)
	cfg, catalogDir := autoSeedCfg(t, base, trust)

	// Pre-install a good catalog (v5) into the live destination.
	writeSignedCatalogDir(t, catalogDir, priv, freshValidSource("2099-01-01T00:00:00Z", 5))
	if good, err := LoadVerifiedCatalog(&dirCatalogSource{dir: catalogDir}, trust); err != nil || good.Version() != 5 {
		t.Fatalf("precondition: good v5 must load; cat=%v err=%v", good, err)
	}

	// Serve a tampered v6 (corrupted after signing) — must be rejected.
	files := signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 6))
	files["/index.json"] = append([]byte("tamper"), files["/index.json"]...)
	p, _ := servedHTTP(t, base, trust, files)
	if err := autoSeedCatalog(context.Background(), p, cfg); err == nil {
		t.Fatal("tampered served catalog must be rejected")
	}

	// The pre-existing good v5 survives untouched and still verifies.
	after, err := LoadVerifiedCatalog(&dirCatalogSource{dir: catalogDir}, trust)
	if err != nil || after.Version() != 5 {
		t.Fatalf("existing good catalog must survive a failed seed; cat=%v err=%v", after, err)
	}
}

// TestServedVerify_BakedRootFailClosed proves the REAL baked-root Sigstore trust
// store is CONSULTED on the served path and FAILS CLOSED — the locally-provable half
// of must-prove #8. A present-but-invalid /index.json.sigstore is served against the
// baked-root (sigstore-only, enforce) store so verifySigstoreScheme → sv.verifyIndexBundle
// actually runs and REJECTS (artifact-owns-outcome: a present-but-unparseable bundle
// never falls through). Serving a bundle-ABSENT catalog would reject via errSigMissing
// WITHOUT invoking the baked-root verifier, which is why a garbage sidecar is served
// here. The baked-root POSITIVE over real Fulcio-signed bytes needs CI signing and is
// PR3 (TestServedVerify_BakedRootGate).
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
	files := signedCatalogFiles(t, priv, freshValidSource("2099-01-01T00:00:00Z", 3))
	files["/index.json.sigstore"] = []byte("garbage-not-a-sigstore-bundle") // present but invalid → baked-root verify runs and rejects
	p, _ := servedHTTP(t, base, bakedTrust, files)
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
	p, _ := servedHTTP(t, base, dualTrust, files)
	assertServedRejectedUntouched(t, p, cfg, catalogDir)
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
