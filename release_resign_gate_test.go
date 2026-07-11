package main

// M1-4 (design §4 Slice D) — the re-sign gate. SEC-F1 (§10, BLOCKING): the
// resign path signs content sourced from a MUTABLE GitHub release asset, so an
// attacker with contents:write could swap the bundle and turn the weekly cron
// into a keyless signing oracle. The §10 enforcement lives HERE, in the gate
// binary, not in CI shell:
//
//  1. verify-before-read: the source bundle's index.json.sigstore MUST verify
//     against the trust store (CI: the baked Sigstore root + pinned identity)
//     BEFORE any field is read. Verification is signature + structure only —
//     deliberately EXPIRY-TOLERANT (LoadVerifiedCatalog without the freshness
//     gate): re-signing an already-lapsed catalog is exactly the recovery case.
//  2. the version binding: CULVERT_RELEASE_SPEC_VERSION (derived from the
//     dispatch ref tag in CI) must equal the verified bundle's release identity.
//  3. every entry fact — created_at, catalog_version, repo, digest, platforms,
//     channels, severity — comes ONLY from the signature-verified bundle (never
//     an env side-channel, never the served R2 index: origin is untrusted
//     transport). The design's provisional CULVERT_RELEASE_SPEC_RESIGN_CREATED_AT
//     env input is deliberately NOT accepted (it would be a spoofable bypass of
//     verify-before-read); recorded in design §4.1.
//
// The output is byte-new ONLY in generated_at/expires_at: same catalog_version,
// same created_at, byte-identical manifests. buildResignSpecFromVerified is the
// testable core; TestReleaseResignGate is the env-driven CI entrypoint that
// wires the REAL baked-root trust around it (mirroring TestReleaseCatalogGate).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// resignSource is what buildResignSpecFromVerified extracts from a VERIFIED
// bundle: the full generator spec for the re-sign plus the source facts the
// gate asserts against after generation.
type resignSource struct {
	spec          releaseCatalogSpec
	srcIndexRaw   []byte
	srcManifests  map[string][]byte // "<release_id>.json" → raw bytes
	srcCreatedAt  string
	srcCatVersion int
}

// buildResignSpecFromVerified implements SEC-F1's verify-before-read: it
// verifies the source bundle dir against trust (signature + structure, no
// freshness — expiry-tolerant by design), asserts the version binding, and
// reconstructs the SINGLE-entry generator spec with generated_at slid to
// resignNow and everything else carried from the verified bytes.
func buildResignSpecFromVerified(src string, trust TrustStore, version, resignNow string) (*resignSource, error) {
	// (1) VERIFY FIRST. Nothing below runs on unverified bytes.
	if _, err := LoadVerifiedCatalog(&dirCatalogSource{dir: src}, trust); err != nil {
		return nil, fmt.Errorf("resign source bundle failed verification (SEC-F1 refuses to sign it): %w", err)
	}
	// (2) The bytes are now signature-verified (index) and hash-bound to it
	// (manifests) — parse them for the facts the spec needs.
	idxRaw, err := os.ReadFile(filepath.Join(src, "index.json")) // #nosec G304 -- CI-provided bundle dir
	if err != nil {
		return nil, err
	}
	var idx catalogIndexFile
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		return nil, fmt.Errorf("verified index unparsable: %w", err)
	}
	if len(idx.Releases) != 1 {
		return nil, fmt.Errorf("resign supports exactly one release entry, source has %d (fail closed)", len(idx.Releases))
	}
	ref := idx.Releases[0].ManifestRef
	manRaw, err := os.ReadFile(filepath.Join(src, "manifests", filepath.Base(ref))) // #nosec G304 -- ref is hash-bound to the verified index
	if err != nil {
		return nil, err
	}
	var man struct {
		ReleaseID string `json:"release_id"`
		VersionID string `json:"version_id"`
		Severity  string `json:"severity"`
		CreatedAt string `json:"created_at"`
		Image     struct {
			Repo       string   `json:"repo"`
			ListDigest string   `json:"list_digest"`
			Platforms  []string `json:"platforms"`
		} `json:"image"`
		MinUpgradeFrom string `json:"min_upgrade_from"`
		ChangelogURL   string `json:"changelog_url"`
		Notes          string `json:"notes"`
	}
	if err := json.Unmarshal(manRaw, &man); err != nil {
		return nil, fmt.Errorf("verified manifest unparsable: %w", err)
	}
	// (3) Version binding: the dispatch tag must name the release this verified
	// bundle actually describes — an attacker cannot point the resign at a
	// bundle for a different (e.g. older, weaker) release.
	if version == "" || man.VersionID != version {
		return nil, fmt.Errorf("version binding failed: dispatch tag version %q != verified bundle version %q (SEC-F1)", version, man.VersionID)
	}
	// Channels for this entry from the verified index's channel map.
	var channels []Channel
	for ch, rid := range idx.Channels {
		if rid == man.ReleaseID {
			channels = append(channels, Channel(ch))
		}
	}
	spec := releaseCatalogSpec{
		GeneratedAt:    resignNow,
		CatalogVersion: idx.CatalogVersion,
		Entries: []releaseEntrySpec{{
			ReleaseID:      man.ReleaseID,
			VersionID:      man.VersionID,
			Severity:       man.Severity,
			Repo:           man.Image.Repo,
			ListDigest:     man.Image.ListDigest,
			Platforms:      man.Image.Platforms,
			CreatedAt:      man.CreatedAt,
			MinUpgradeFrom: man.MinUpgradeFrom,
			ChangelogURL:   man.ChangelogURL,
			Notes:          man.Notes,
			Channels:       channels,
		}},
	}
	// Fresh window: expires_at = resignNow + 180d, derived by the SAME tested
	// helper the release path uses.
	exp, err := deriveExpiry(resignNow, defaultExpiryDays)
	if err != nil {
		return nil, err
	}
	spec.ExpiresAt = exp
	// Normalize generated_at exactly like buildReleaseSpec's resign mode.
	if spec.GeneratedAt, err = normalizeUTC(resignNow); err != nil {
		return nil, fmt.Errorf("resign now: %w", err)
	}
	manifests := map[string][]byte{filepath.Base(ref): manRaw}
	return &resignSource{
		spec:          spec,
		srcIndexRaw:   idxRaw,
		srcManifests:  manifests,
		srcCreatedAt:  man.CreatedAt,
		srcCatVersion: idx.CatalogVersion,
	}, nil
}

// assertResignInvariants pins what a re-sign may and may not change: SAME
// catalog_version, SAME created_at, byte-identical manifests, and an index that
// differs ONLY in generated_at + expires_at.
func assertResignInvariants(t *testing.T, src *resignSource, bundle *releaseBundle) {
	t.Helper()
	var oldIdx, newIdx catalogIndexFile
	if err := json.Unmarshal(src.srcIndexRaw, &oldIdx); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bundle.Index, &newIdx); err != nil {
		t.Fatal(err)
	}
	if newIdx.CatalogVersion != src.srcCatVersion {
		t.Fatalf("resign must NOT change catalog_version: %d → %d", src.srcCatVersion, newIdx.CatalogVersion)
	}
	if newIdx.GeneratedAt == oldIdx.GeneratedAt {
		t.Fatal("resign must slide generated_at")
	}
	if newIdx.ExpiresAt == oldIdx.ExpiresAt {
		t.Fatal("resign must slide expires_at")
	}
	// Everything else in the index is byte-equal once the two slid fields are
	// normalized out.
	oldIdx.GeneratedAt, newIdx.GeneratedAt = "", ""
	oldIdx.ExpiresAt, newIdx.ExpiresAt = "", ""
	ob, _ := json.Marshal(oldIdx)
	nb, _ := json.Marshal(newIdx)
	if !bytes.Equal(ob, nb) {
		t.Fatalf("resign changed index fields beyond generated_at/expires_at:\n old=%s\n new=%s", ob, nb)
	}
	for name, oldRaw := range src.srcManifests {
		if !bytes.Equal(bundle.Manifests[name], oldRaw) {
			t.Fatalf("resign must keep manifest %s byte-identical (created_at/release identity are immutable)", name)
		}
	}
}

// TestReleaseResignGate is the CI entrypoint (env-driven, like
// TestReleaseCatalogGate): verify the downloaded release bundle through the
// REAL baked root + pinned identity, rebuild the spec, generate, assert the
// resign invariants, round-trip the result through the real verifier, and emit
// the bundle for cosign to sign. Skipped without the resign envs.
func TestReleaseResignGate(t *testing.T) {
	if os.Getenv("CULVERT_RELEASE_SPEC_RESIGN") != "1" {
		t.Skip("resign gate: set CULVERT_RELEASE_SPEC_RESIGN=1 (+_RESIGN_SRC/_VERSION/_RESIGN_NOW/GEN_OUT) to run (CI only)")
	}
	src := os.Getenv("CULVERT_RELEASE_RESIGN_SRC")
	version := os.Getenv("CULVERT_RELEASE_SPEC_VERSION")
	now := os.Getenv("CULVERT_RELEASE_SPEC_RESIGN_NOW")
	if src == "" || version == "" || now == "" {
		t.Fatal("resign gate requires CULVERT_RELEASE_RESIGN_SRC, CULVERT_RELEASE_SPEC_VERSION, CULVERT_RELEASE_SPEC_RESIGN_NOW")
	}
	// REAL trust: baked Sigstore root + pinned official identity, Sigstore-only
	// enforce (the original bundle MUST carry a valid keyless signature — an
	// unsigned or stripped bundle is refused, per SEC-F1).
	sv, err := newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())
	if err != nil {
		t.Fatalf("build verifier from baked root: %v", err)
	}
	trust, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := buildResignSpecFromVerified(src, trust, version, now)
	if err != nil {
		t.Fatalf("resign spec: %v", err)
	}
	bundle, err := generateReleaseCatalog(rs.spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	assertResignInvariants(t, rs, bundle)
	// Round-trip through the real loader with an ephemeral test signature (the
	// official keyless signature is applied by cosign AFTER this gate emits).
	sig, ts := ephemeralSign(t, bundle.Index)
	tmp := t.TempDir()
	if err := writeReleaseBundle(tmp, bundle, sig); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: tmp}, ts)
	if err != nil {
		t.Fatalf("resigned bundle failed real verification: %v", err)
	}
	if err := checkCatalogFreshness(cat, time.Now(), catalogClockSkew); err != nil {
		t.Fatalf("resigned catalog must be fresh: %v", err)
	}
	emitGateBundle(t, bundle)
}

// ─── Always-on unit enforcement (SEC-F1, mutation-proven) ─────────────────────
// The CI gate above only runs on the resign path; these run in every suite.

// resignFixture builds a signed single-entry source bundle on disk + its trust
// (ephemeralSign produces the loader's JSON signature envelope).
func resignFixture(t *testing.T) (dir string, trust TrustStore) {
	t.Helper()
	spec, err := buildReleaseSpec(SpecInputs{
		Version:    "1.4.3",
		Repo:       "ghcr.io/kidcarmi/culvert",
		ListDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Mode:       specModeRelease,
		CommitISO:  "2026-01-05T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := generateReleaseCatalog(spec)
	if err != nil {
		t.Fatal(err)
	}
	sig, ts := ephemeralSign(t, bundle.Index)
	dir = t.TempDir()
	if err := writeReleaseBundle(dir, bundle, sig); err != nil {
		t.Fatal(err)
	}
	return dir, ts
}

// SEC-F1: verify-before-read. A tampered source bundle (one flipped byte after
// signing) must be REFUSED before any field is read; an untrusted key likewise.
func TestResignGate_RefusesUnverifiedSource(t *testing.T) {
	dir, trust := resignFixture(t)

	// Happy path first: the verified bundle yields a spec.
	rs, err := buildResignSpecFromVerified(dir, trust, "1.4.3", "2026-07-10T00:00:00Z")
	if err != nil {
		t.Fatalf("verified source must build: %v", err)
	}
	if rs.srcCreatedAt == "" || rs.srcCatVersion < 1 {
		t.Fatalf("source facts not extracted: %+v", rs)
	}

	// Tamper AFTER signing: append a byte to the index.
	idxPath := filepath.Join(dir, "index.json")
	raw, err := os.ReadFile(idxPath) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idxPath, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildResignSpecFromVerified(dir, trust, "1.4.3", "2026-07-10T00:00:00Z"); err == nil {
		t.Fatal("SEC-F1 violated: a tampered source bundle was accepted for re-signing")
	}

	// Untrusted signer: a bundle signed by a DIFFERENT key must be refused.
	dir2, _ := resignFixture(t)
	_, otherTrust := resignFixture(t)
	if _, err := buildResignSpecFromVerified(dir2, otherTrust, "1.4.3", "2026-07-10T00:00:00Z"); err == nil {
		t.Fatal("SEC-F1 violated: a bundle signed by an untrusted key was accepted")
	}
}

// SEC-F1 (3): the version binding — a dispatch tag that does not match the
// verified bundle's release identity is refused (an attacker cannot re-sign an
// old/other release under the latest tag's identity).
func TestResignGate_VersionBinding(t *testing.T) {
	dir, trust := resignFixture(t)
	if _, err := buildResignSpecFromVerified(dir, trust, "9.9.9", "2026-07-10T00:00:00Z"); err == nil {
		t.Fatal("version binding violated: mismatched tag version accepted")
	}
	if _, err := buildResignSpecFromVerified(dir, trust, "", "2026-07-10T00:00:00Z"); err == nil {
		t.Fatal("version binding violated: empty version accepted")
	}
}

// The re-sign result: same catalog_version + created_at + byte-identical
// manifests, slid generated_at/expires_at (+180d), and the invariant assertion
// itself catches a mutated generator.
func TestResignGate_InvariantsHold(t *testing.T) {
	dir, trust := resignFixture(t)
	rs, err := buildResignSpecFromVerified(dir, trust, "1.4.3", "2026-07-10T09:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := generateReleaseCatalog(rs.spec)
	if err != nil {
		t.Fatal(err)
	}
	assertResignInvariants(t, rs, bundle)

	var newIdx catalogIndexFile
	if err := json.Unmarshal(bundle.Index, &newIdx); err != nil {
		t.Fatal(err)
	}
	if newIdx.GeneratedAt != "2026-07-10T09:30:00Z" {
		t.Fatalf("generated_at = %s; want the resign now", newIdx.GeneratedAt)
	}
	if newIdx.ExpiresAt != "2027-01-06T09:30:00Z" { // +180d
		t.Fatalf("expires_at = %s; want generated_at+180d", newIdx.ExpiresAt)
	}
	// Determinism: the same resign inputs yield identical bytes (idempotent re-runs).
	bundle2, err := generateReleaseCatalog(rs.spec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bundle.Index, bundle2.Index) {
		t.Fatal("resign generation is not deterministic")
	}
}
