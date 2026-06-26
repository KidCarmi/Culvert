package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

// genFixtureNow is the fixed generated_at/created_at used across the generator
// fixtures (kept as one constant rather than repeating the literal).
const genFixtureNow = "2026-05-01T00:00:00Z"

func validGenSpec() releaseCatalogSpec {
	return releaseCatalogSpec{
		GeneratedAt:    genFixtureNow,
		ExpiresAt:      "2026-07-30T00:00:00Z", // ~90d later
		CatalogVersion: 7,
		Entries: []releaseEntrySpec{
			{
				ReleaseID: "rel_b", VersionID: "1.9.0", Severity: "normal",
				Repo: repo, ListDigest: digB, Platforms: []string{"linux/arm64", "linux/amd64"},
				CreatedAt: genFixtureNow, Channels: []Channel{ChannelLTS},
			},
			{
				ReleaseID: "rel_a", VersionID: "1.10.0", Severity: "critical",
				Repo: repo, ListDigest: digA, Platforms: []string{"linux/amd64", "linux/arm64"},
				CreatedAt: genFixtureNow, Channels: []Channel{ChannelRecommended, ChannelCritical},
			},
		},
	}
}

// ephemeralSign signs idxBytes with a throwaway ed25519 key (the CI gate's
// round-trip key) and returns the detached sig envelope + a TrustStore trusting
// it. The private key never leaves this function.
func ephemeralSign(t *testing.T, idxBytes []byte) ([]byte, TrustStore) {
	t.Helper()
	const keyID = "ci-ephemeral"
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := catalogSigEnvelope{SchemaVersion: catalogSchemaMajor, Alg: catalogSigAlg, KeyID: keyID,
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, idxBytes))}
	sig, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := NewTrustStore([]TrustKey{{KeyID: keyID, Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	return sig, ts
}

// ─── determinism (merge gate) ────────────────────────────────────────────────

func TestGenerateReleaseCatalog_Deterministic(t *testing.T) {
	b1, err := generateReleaseCatalog(validGenSpec())
	if err != nil {
		t.Fatal(err)
	}
	b2, err := generateReleaseCatalog(validGenSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Index, b2.Index) {
		t.Fatalf("non-deterministic index:\n%s\n---\n%s", b1.Index, b2.Index)
	}
	if len(b1.Manifests) != len(b2.Manifests) {
		t.Fatalf("manifest count differs: %d vs %d", len(b1.Manifests), len(b2.Manifests))
	}
	for ref, data := range b1.Manifests {
		if !bytes.Equal(data, b2.Manifests[ref]) {
			t.Errorf("non-deterministic manifest %q", ref)
		}
	}
}

// ─── round-trip through the REAL loader (no gate/runtime drift) ──────────────

func TestGenerateReleaseCatalog_RoundTripsThroughLoader(t *testing.T) {
	bundle, err := generateReleaseCatalog(validGenSpec())
	if err != nil {
		t.Fatal(err)
	}
	sig, ts := ephemeralSign(t, bundle.Index)
	dir := t.TempDir()
	if err := writeReleaseBundle(dir, bundle, sig); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, ts)
	if err != nil {
		t.Fatalf("generated bundle must load through the real verifier: %v", err)
	}
	// Enforce-mode freshness + rollback the runtime would apply.
	now := mustTime(t, "2026-05-15T00:00:00Z")
	if err := checkCatalogFreshness(cat, now, catalogClockSkew); err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if err := checkCatalogRollback(cat, 0); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if cat.Version() != 7 {
		t.Errorf("catalog_version = %d; want 7", cat.Version())
	}
	// Channel pointers and digest-bound refs resolve.
	got, err := cat.Resolve(ChannelRecommended)
	if err != nil || got.PinnedRef != repo+"@"+digA {
		t.Fatalf("recommended resolve = %+v err=%v; want %s", got, err, repo+"@"+digA)
	}
	if lts, err := cat.Resolve(ChannelLTS); err != nil || lts.PinnedRef != repo+"@"+digB {
		t.Fatalf("lts resolve = %+v err=%v", lts, err)
	}
}

// ─── fail-closed generation ──────────────────────────────────────────────────

func TestGenerateReleaseCatalog_FailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *releaseCatalogSpec)
	}{
		{"tag in repo", func(s *releaseCatalogSpec) { s.Entries[0].Repo = repo + ":latest" }},
		{"digest in repo", func(s *releaseCatalogSpec) { s.Entries[0].Repo = repo + "@" + digA }},
		{"bad list_digest", func(s *releaseCatalogSpec) { s.Entries[0].ListDigest = "sha256:nothex" }},
		{"non-semver version", func(s *releaseCatalogSpec) { s.Entries[0].VersionID = "1.0" }},
		{"empty severity", func(s *releaseCatalogSpec) { s.Entries[0].Severity = "" }},
		{"missing created_at", func(s *releaseCatalogSpec) { s.Entries[0].CreatedAt = "" }},
		{"catalog_version 0", func(s *releaseCatalogSpec) { s.CatalogVersion = 0 }},
		{"expires before generated", func(s *releaseCatalogSpec) { s.ExpiresAt = "2026-04-01T00:00:00Z" }},
		{"unknown channel", func(s *releaseCatalogSpec) { s.Entries[0].Channels = []Channel{"beta"} }},
		{"duplicate channel", func(s *releaseCatalogSpec) {
			s.Entries[0].Channels = []Channel{ChannelLTS}
			s.Entries[1].Channels = []Channel{ChannelLTS}
		}},
		{"release_id with slash", func(s *releaseCatalogSpec) { s.Entries[0].ReleaseID = "a/b" }},
		{"no entries", func(s *releaseCatalogSpec) { s.Entries = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validGenSpec()
			tc.mutate(&s)
			if _, err := generateReleaseCatalog(s); err == nil {
				t.Fatalf("%s: expected generation to fail closed", tc.name)
			}
		})
	}
}

// The generated catalog binds the manifest-LIST digest into the agent-facing
// repo@sha256 pinned ref — never a tag.
func TestGenerateReleaseCatalog_DigestPinnedNeverTag(t *testing.T) {
	bundle, err := generateReleaseCatalog(validGenSpec())
	if err != nil {
		t.Fatal(err)
	}
	sig, ts := ephemeralSign(t, bundle.Index)
	dir := t.TempDir()
	if err := writeReleaseBundle(dir, bundle, sig); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, ts)
	if err != nil {
		t.Fatal(err)
	}
	// Every channel pointer is a repo@sha256 digest, never a tag.
	pinned := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	for _, ch := range []Channel{ChannelRecommended, ChannelLTS, ChannelCritical} {
		r, err := cat.Resolve(ch)
		if err != nil {
			continue
		}
		if !pinned.MatchString(r.PinnedRef) {
			t.Errorf("channel %s pinned ref %q is not repo@sha256:<64hex>", ch, r.PinnedRef)
		}
	}
}

// ─── env-driven CI gate ──────────────────────────────────────────────────────
//
// In CI the release workflow sets CULVERT_RELEASE_GEN_SPEC (a JSON
// releaseCatalogSpec built from the pushed image digest + release metadata) and
// optionally CULVERT_RELEASE_GEN_OUT (where to write the UNSIGNED official bundle
// for attachment) and CULVERT_RELEASE_EXPECT_DIGEST (the digest the workflow
// actually pushed). The gate generates, round-trips through the REAL verifier
// with an EPHEMERAL test key (in a temp dir; the ephemeral signature is NEVER the
// shipped artifact), and asserts every release's list_digest equals the pushed
// digest. Outside CI (env unset) it is skipped.
func TestReleaseCatalogGate(t *testing.T) {
	specPath := os.Getenv("CULVERT_RELEASE_GEN_SPEC")
	if specPath == "" {
		t.Skip("release gate: set CULVERT_RELEASE_GEN_SPEC to run (CI only)")
	}
	raw, err := os.ReadFile(specPath) // #nosec G304 -- CI-provided spec path, not attacker input
	if err != nil {
		t.Fatal(err)
	}
	var spec releaseCatalogSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	bundle, err := generateReleaseCatalog(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Round-trip verify with an ephemeral key in a temp dir (test-only signature).
	sig, ts := ephemeralSign(t, bundle.Index)
	tmp := t.TempDir()
	if err := writeReleaseBundle(tmp, bundle, sig); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: tmp}, ts)
	if err != nil {
		t.Fatalf("generated bundle failed real verification: %v", err)
	}
	if err := checkCatalogFreshness(cat, time.Now(), catalogClockSkew); err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if err := checkCatalogRollback(cat, 0); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// The pushed manifest-list digest must equal every catalog list_digest.
	if want := os.Getenv("CULVERT_RELEASE_EXPECT_DIGEST"); want != "" {
		for i := range spec.Entries {
			if spec.Entries[i].ListDigest != want {
				t.Fatalf("release %q list_digest %q != pushed digest %q",
					spec.Entries[i].ReleaseID, spec.Entries[i].ListDigest, want)
			}
		}
	}

	// Emit the UNSIGNED official bundle for attachment (P2b adds the real sig).
	if out := os.Getenv("CULVERT_RELEASE_GEN_OUT"); out != "" {
		if err := writeReleaseBundle(out, bundle, nil); err != nil {
			t.Fatalf("write output bundle: %v", err)
		}
		t.Logf("release gate: wrote unsigned bundle to %s", filepath.Clean(out))
	}
}
