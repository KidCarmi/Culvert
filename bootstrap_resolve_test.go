package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The bootstrap resolver is the installer-side security kernel. These tests
// exercise it end-to-end against a REAL served catalog fixture (httptest origin +
// ed25519-signed index), never a mock of the verifier — so a regression in the
// shared trust path (signature, freshness, rollback, repo allowlist) fails here.

const (
	digModern = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digLegacy = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// bootstrapNow is a fixed clock inside the fixtures' freshness window.
func bootstrapNow() time.Time { return time.Date(2026, 4, 18, 1, 0, 0, 0, time.UTC) }

// modernCatalogSource builds a fresh, enforce-gate-passing catalog whose
// `recommended`/`stable` channel points at a MODERN release (2.0.0 @ digModern),
// while ALSO carrying a legacy 0.0.238 @ digLegacy release in the index — pointed
// at by NO channel (yanked). This is the exact shape of the EC2 regression: the
// legacy image still exists, but the channel is the sole authority.
func modernCatalogSource(expiresAt string, catalogVersion int) *memSource {
	return buildCatalogSourceFull(
		map[string]string{"recommended": "rel_modern", "lts": "rel_modern", "critical": "rel_modern"},
		1, "2026-04-18T00:00:00Z", expiresAt, catalogVersion,
		[]relSpec{
			{ref: "modern.json", releaseID: "rel_modern", versionID: "2.0.0", raw: manifestJSON("rel_modern", "2.0.0", "normal", repo, digModern)},
			{ref: "legacy.json", releaseID: "rel_legacy", versionID: "0.0.238", raw: manifestJSON("rel_legacy", "0.0.238", "normal", repo, digLegacy)},
		})
}

// serveCatalog starts a signed-catalog origin and returns (url, trust, pub).
func serveCatalog(t *testing.T, ms *memSource) (string, TrustStore, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCatalogServer{files: signedCatalogFiles(t, priv, ms)}
	ts := httptest.NewServer(f.handler())
	t.Cleanup(ts.Close)
	return ts.URL, holderTrust(t, pub), pub
}

// resolveOpts returns baseline opts wired to a loopback origin (guard disabled).
func resolveOpts(url string, trust TrustStore) bootstrapResolveOpts {
	return bootstrapResolveOpts{
		catalogURL:     url,
		originSource:   catalogURLSourceOverride,
		trust:          trust,
		channel:        ChannelRecommended,
		installChannel: "stable",
		proxyRepo:      repo,
		trustSchemes:   "ed25519",
		now:            bootstrapNow,
		insecureGuard:  true,
	}
}

func TestBootstrapResolve_HappyPath_ServedCatalog(t *testing.T) {
	url, trust, _ := serveCatalog(t, modernCatalogSource("2030-01-01T00:00:00Z", 5))

	dec, err := bootstrapResolve(context.Background(), resolveOpts(url, trust))
	if err != nil {
		t.Fatalf("bootstrapResolve: %v", err)
	}
	if dec.ImageRef != repo+"@"+digModern {
		t.Fatalf("image_ref = %q; want the modern digest %q", dec.ImageRef, repo+"@"+digModern)
	}
	if dec.Digest != digModern {
		t.Fatalf("digest = %q; want %q", dec.Digest, digModern)
	}
	if dec.VersionID != "2.0.0" || dec.CatalogChannel != "recommended" || dec.InstallChannel != "stable" {
		t.Fatalf("unexpected decision fields: %+v", dec)
	}
	if dec.CatalogVersion != 5 || dec.Repo != repo {
		t.Fatalf("unexpected decision fields: %+v", dec)
	}
	if dec.SchemaVersion != bootstrapDecisionSchema {
		t.Fatalf("schema_version = %d; want %d", dec.SchemaVersion, bootstrapDecisionSchema)
	}
}

// The historical regression: GHCR contains legacy 0.0.238 + modern tags. Prove
// the trusted decision comes ONLY from the catalog channel and NEVER selects the
// legacy 0.0.238 digest — there is no tag enumeration anywhere in the resolver.
func TestBootstrapResolve_NeverSelectsLegacy(t *testing.T) {
	url, trust, _ := serveCatalog(t, modernCatalogSource("2030-01-01T00:00:00Z", 5))

	dec, err := bootstrapResolve(context.Background(), resolveOpts(url, trust))
	if err != nil {
		t.Fatalf("bootstrapResolve: %v", err)
	}
	if dec.Digest == digLegacy || dec.VersionID == "0.0.238" {
		t.Fatalf("resolver selected the legacy 0.0.238 release: %+v", dec)
	}
	if dec.Digest != digModern {
		t.Fatalf("expected the channel-authoritative modern digest, got %q", dec.Digest)
	}
	// Serialize + re-parse the decision the way the installer consumes it, and
	// assert the legacy digest never appears anywhere in the wire output.
	b, _ := json.Marshal(dec)
	if strings.Contains(string(b), digLegacy) || strings.Contains(string(b), "0.0.238") {
		t.Fatalf("legacy reference leaked into the install decision: %s", b)
	}
}

func TestBootstrapResolve_TamperedIndexRejected(t *testing.T) {
	ms := modernCatalogSource("2030-01-01T00:00:00Z", 5)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	files := signedCatalogFiles(t, priv, ms)
	// Flip a byte of the index AFTER signing → signature no longer matches.
	idx := files["/index.json"]
	idx[len(idx)/2] ^= 0xFF
	f := &fakeCatalogServer{files: files}
	ts := httptest.NewServer(f.handler())
	t.Cleanup(ts.Close)

	_, err = bootstrapResolve(context.Background(), resolveOpts(ts.URL, holderTrust(t, pub)))
	if err == nil {
		t.Fatal("tampered index must be rejected")
	}
}

func TestBootstrapResolve_UntrustedSignerRejected(t *testing.T) {
	ms := modernCatalogSource("2030-01-01T00:00:00Z", 5)
	trustedPub, _, _ := ed25519.GenerateKey(nil)
	_, attackerPriv, _ := ed25519.GenerateKey(nil) // signs with an untrusted key
	f := &fakeCatalogServer{files: signedCatalogFiles(t, attackerPriv, ms)}
	ts := httptest.NewServer(f.handler())
	t.Cleanup(ts.Close)

	_, err := bootstrapResolve(context.Background(), resolveOpts(ts.URL, holderTrust(t, trustedPub)))
	if err == nil {
		t.Fatal("catalog signed by an untrusted key must be rejected")
	}
}

func TestBootstrapResolve_MissingManifestRejected(t *testing.T) {
	ms := modernCatalogSource("2030-01-01T00:00:00Z", 5)
	pub, priv, _ := ed25519.GenerateKey(nil)
	files := signedCatalogFiles(t, priv, ms)
	delete(files, "/manifests/modern.json") // origin 404s a referenced manifest
	f := &fakeCatalogServer{files: files}
	ts := httptest.NewServer(f.handler())
	t.Cleanup(ts.Close)

	_, err := bootstrapResolve(context.Background(), resolveOpts(ts.URL, holderTrust(t, pub)))
	if err == nil {
		t.Fatal("a missing referenced manifest must fail the resolve")
	}
}

func TestBootstrapResolve_ExpiredCatalogRejected(t *testing.T) {
	// expires_at in the past relative to bootstrapNow.
	url, trust, _ := serveCatalog(t, modernCatalogSource("2026-01-01T00:00:00Z", 5))

	_, err := bootstrapResolve(context.Background(), resolveOpts(url, trust))
	if err == nil || !strings.Contains(err.Error(), "freshness") {
		t.Fatalf("expired catalog must fail freshness; got %v", err)
	}
}

func TestBootstrapResolve_MissingExpiryRejected(t *testing.T) {
	// No expires_at at all → enforce-mode freshness refuses it (replay-forever guard).
	url, trust, _ := serveCatalog(t, modernCatalogSource("", 5))

	_, err := bootstrapResolve(context.Background(), resolveOpts(url, trust))
	if err == nil || !strings.Contains(err.Error(), "freshness") {
		t.Fatalf("catalog with no expiry must fail freshness; got %v", err)
	}
}

func TestBootstrapResolve_RollbackFloorRejected(t *testing.T) {
	url, trust, _ := serveCatalog(t, modernCatalogSource("2030-01-01T00:00:00Z", 5))

	// Persist a floor HIGHER than the served catalog_version → rollback refusal.
	dir := t.TempDir()
	statePath := filepath.Join(dir, "release_catalog_state.json")
	if err := os.WriteFile(statePath, []byte(`{"highest_accepted_version":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := resolveOpts(url, trust)
	opts.statePath = statePath

	_, err := bootstrapResolve(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("catalog below the rollback floor must be refused; got %v", err)
	}
}

func TestBootstrapResolve_ReplayRejected(t *testing.T) {
	// Same version as the floor but an OLDER generated_at than the floor's → SEC-F4 replay.
	url, trust, _ := serveCatalog(t, modernCatalogSource("2030-01-01T00:00:00Z", 5))
	dir := t.TempDir()
	statePath := filepath.Join(dir, "release_catalog_state.json")
	if err := os.WriteFile(statePath, []byte(`{"highest_accepted_version":5,"highest_accepted_generated_at":"2026-04-19T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := resolveOpts(url, trust)
	opts.statePath = statePath

	_, err := bootstrapResolve(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("an older re-sign of the same version must be refused as replay; got %v", err)
	}
}

func TestBootstrapResolve_RepoOutsideAllowlistRejected(t *testing.T) {
	url, trust, _ := serveCatalog(t, modernCatalogSource("2030-01-01T00:00:00Z", 5))
	opts := resolveOpts(url, trust)
	opts.proxyRepo = "ghcr.io/attacker/culvert" // catalog resolves to ghcr.io/kidcarmi/culvert

	_, err := bootstrapResolve(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("a repo outside the allowlist must be refused; got %v", err)
	}
}

// The SSRF guard must be wired: with the guard ENABLED, a private/loopback origin
// (the httptest server) is rejected before any catalog bytes are trusted.
func TestBootstrapResolve_SSRFGuardRejectsPrivateOrigin(t *testing.T) {
	url, trust, _ := serveCatalog(t, modernCatalogSource("2030-01-01T00:00:00Z", 5))
	opts := resolveOpts(url, trust)
	opts.insecureGuard = false // enable the real SSRF guard

	_, err := bootstrapResolve(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "SSRF") {
		t.Fatalf("a private/loopback origin must be rejected by the SSRF guard; got %v", err)
	}
}

func TestMapInstallChannel(t *testing.T) {
	cases := map[string]Channel{
		"":            ChannelRecommended,
		"stable":      ChannelRecommended,
		"STABLE":      ChannelRecommended,
		"recommended": ChannelRecommended,
		"lts":         ChannelLTS,
		"critical":    ChannelCritical,
	}
	for in, want := range cases {
		got, err := mapInstallChannel(in)
		if err != nil || got != want {
			t.Errorf("mapInstallChannel(%q) = %q,%v; want %q", in, got, err, want)
		}
	}
	if _, err := mapInstallChannel("edge"); err == nil {
		t.Error("unknown channel must error")
	}
}

// ─── trust-scheme description ──────────────────────────────────────────────────

func TestTrustSchemesOf(t *testing.T) {
	if got := trustSchemesOf(nil, false); got != "none" {
		t.Errorf("no schemes = %q; want none", got)
	}
	if got := trustSchemesOf([]TrustKey{{}}, false); got != catalogSigAlg {
		t.Errorf("ed25519 only = %q", got)
	}
	if got := trustSchemesOf([]TrustKey{{}}, true); got != catalogSigAlg+"+"+sigstoreSigAlg {
		t.Errorf("both = %q", got)
	}
}

// ─── CLI wrapper (argument + fail-closed behavior; crypto covered above) ───────

func TestRunBootstrapResolve_DisabledSentinelFailsClosed(t *testing.T) {
	var out, errBuf strings.Builder
	code := runBootstrapResolve([]string{"--catalog-url", "off"}, &out, &errBuf)
	if code == 0 {
		t.Fatal("a disabled catalog URL must fail closed (non-zero exit)")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty on failure; got %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "disable sentinel") {
		t.Fatalf("expected a disable-sentinel diagnostic; got %q", errBuf.String())
	}
}

func TestRunBootstrapResolve_BadChannelFailsClosed(t *testing.T) {
	var out, errBuf strings.Builder
	// A real-looking public origin so trust config resolves; the channel is the
	// first hard failure. (No network is reached — channel mapping happens first.)
	code := runBootstrapResolve([]string{"--channel", "edge", "--catalog-url", "https://catalog.example.com/x"}, &out, &errBuf)
	if code == 0 {
		t.Fatal("an unknown channel must fail closed")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must be empty on failure; got %q", out.String())
	}
}

func TestMaybeRunBootstrapResolve_NonMatchReturns(t *testing.T) {
	// A non-matching argv must return without exiting the process.
	maybeRunBootstrapResolve([]string{"culvert", "--port", "8080"})
	maybeRunBootstrapResolve([]string{"culvert"})
}
