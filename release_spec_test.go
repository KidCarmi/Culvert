package main

import (
	"bytes"
	"testing"
)

const (
	testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testRepo   = "ghcr.io/kidcarmi/culvert"
)

func releaseInputs(version, commitISO string) SpecInputs {
	return SpecInputs{
		Version:    version,
		Repo:       testRepo,
		ListDigest: testDigest,
		Platforms:  []string{"linux/amd64", "linux/arm64"},
		Mode:       specModeRelease,
		CommitISO:  commitISO,
	}
}

// TestCatalogVersionFromSemver pins the pure, monotonic, collision-free encoding
// that replaces the racy shell tag-count (M0 design v2 §4.2 / BLOCKING-1).
func TestCatalogVersionFromSemver(t *testing.T) {
	must := func(v string) int {
		t.Helper()
		n, err := catalogVersionFromSemver(v)
		if err != nil {
			t.Fatalf("catalogVersionFromSemver(%q): unexpected error %v", v, err)
		}
		return n
	}

	// Deterministic exact encodings.
	if got := must("1.4.3"); got != 1_004_003 {
		t.Errorf("v1.4.3 encoded %d, want 1004003", got)
	}
	if got := must("0.0.1"); got != 1 {
		t.Errorf("v0.0.1 encoded %d, want 1 (must be ≥1)", got)
	}
	if got := must("0.0.16"); got != 16 {
		t.Errorf("v0.0.16 encoded %d, want 16", got)
	}

	// Monotonic in release order.
	order := []string{"0.0.1", "0.0.16", "1.2.9", "1.2.10", "1.4.3", "1.4.4", "1.5.0", "2.0.0"}
	prev := -1
	for _, v := range order {
		n := must(v)
		if n <= prev {
			t.Errorf("non-monotonic: %s encoded %d, not > previous %d", v, n, prev)
		}
		prev = n
	}

	// A backport (v1.2.10 published after v1.5.0) encodes LOWER than v1.5.0 — the
	// appliance floor then refuses the downgrade for v1.5.0 appliances (correct).
	if must("1.2.10") >= must("1.5.0") {
		t.Errorf("backport v1.2.10 (%d) must encode lower than v1.5.0 (%d)", must("1.2.10"), must("1.5.0"))
	}

	// Collision-free: distinct semver ⇒ distinct integer.
	seen := map[int]string{}
	for _, v := range order {
		n := must(v)
		if other, dup := seen[n]; dup {
			t.Errorf("collision: %s and %s both encode %d", v, other, n)
		}
		seen[n] = v
	}

	// Fail-closed cases.
	for _, bad := range []string{"1.4", "1.4.3.2", "1.4.3-rc.1", "v1.4.3", "1.4.1000", "1.1000.0", "1000.0.0", "", "x.y.z"} {
		if _, err := catalogVersionFromSemver(bad); err == nil {
			t.Errorf("catalogVersionFromSemver(%q): expected error, got nil", bad)
		}
	}
}

// TestReleaseSpec_Idempotent proves re-running the SAME release yields byte-identical
// catalog bytes (must-prove #2). Because catalog_version is semver-derived and the
// timestamps come from the fixed commit date, no external mutable state (tag count,
// wall clock) can perturb the output — so two independent builds are identical.
func TestReleaseSpec_Idempotent(t *testing.T) {
	in := releaseInputs("1.4.3", "2026-07-08T12:00:00+02:00")

	build := func() []byte {
		t.Helper()
		spec, err := buildReleaseSpec(in)
		if err != nil {
			t.Fatalf("buildReleaseSpec: %v", err)
		}
		b, err := generateReleaseCatalog(spec)
		if err != nil {
			t.Fatalf("generateReleaseCatalog: %v", err)
		}
		return b.Index
	}

	a, bts := build(), build()
	if !bytes.Equal(a, bts) {
		t.Fatalf("non-idempotent: two identical-input builds differ\n a=%s\n b=%s", a, bts)
	}
}

// TestReleaseSpec_UTCNormalize proves a non-Zulu committer date is normalized to UTC
// "Z" (unanimous review finding: git %cI emits +NN:NN, which would drift bytes and
// break manifest_sha256).
func TestReleaseSpec_UTCNormalize(t *testing.T) {
	spec, err := buildReleaseSpec(releaseInputs("1.4.3", "2026-07-08T14:30:00+02:00"))
	if err != nil {
		t.Fatalf("buildReleaseSpec: %v", err)
	}
	// +02:00 14:30 == 12:30Z
	if spec.GeneratedAt != "2026-07-08T12:30:00Z" {
		t.Errorf("generated_at not UTC-Z normalized: got %q, want 2026-07-08T12:30:00Z", spec.GeneratedAt)
	}
	if spec.Entries[0].CreatedAt != "2026-07-08T12:30:00Z" {
		t.Errorf("created_at not UTC-Z normalized: got %q", spec.Entries[0].CreatedAt)
	}
	// +180d
	if spec.ExpiresAt != "2027-01-04T12:30:00Z" {
		t.Errorf("expires_at wrong: got %q, want 2027-01-04T12:30:00Z (generated_at + 180d)", spec.ExpiresAt)
	}
}

// TestReleaseSpec_DefaultExpiry180 pins the D9 90→180 change as an explicit assertion.
func TestReleaseSpec_DefaultExpiry180(t *testing.T) {
	spec, err := buildReleaseSpec(releaseInputs("1.0.0", "2026-01-01T00:00:00Z"))
	if err != nil {
		t.Fatalf("buildReleaseSpec: %v", err)
	}
	if spec.ExpiresAt != "2026-06-30T00:00:00Z" {
		t.Errorf("default expiry not 180d: got %q, want 2026-06-30T00:00:00Z", spec.ExpiresAt)
	}
}

// TestReleaseSpec_ResignPreservesIdentity proves a freshness re-sign reuses the same
// catalog_version (no allocation, must-prove #3), preserves created_at and the
// manifest bytes (release identity immutable), and changes ONLY generated_at/expires_at.
func TestReleaseSpec_ResignPreservesIdentity(t *testing.T) {
	rel, err := buildReleaseSpec(releaseInputs("1.4.3", "2026-07-08T12:00:00Z"))
	if err != nil {
		t.Fatalf("release build: %v", err)
	}
	relBundle, err := generateReleaseCatalog(rel)
	if err != nil {
		t.Fatalf("release generate: %v", err)
	}

	resign, err := buildReleaseSpec(SpecInputs{
		Version:         "1.4.3",
		Repo:            testRepo,
		ListDigest:      testDigest,
		Platforms:       []string{"linux/amd64", "linux/arm64"},
		Mode:            specModeResign,
		ResignNow:       "2026-10-01T09:00:00Z",   // freshness window slid forward
		ResignCreatedAt: rel.Entries[0].CreatedAt, // original created_at carried forward
	})
	if err != nil {
		t.Fatalf("resign build: %v", err)
	}
	resignBundle, err := generateReleaseCatalog(resign)
	if err != nil {
		t.Fatalf("resign generate: %v", err)
	}

	if resign.CatalogVersion != rel.CatalogVersion {
		t.Errorf("re-sign allocated a new catalog_version: %d != %d (must be equal by construction)", resign.CatalogVersion, rel.CatalogVersion)
	}
	if resign.Entries[0].CreatedAt != rel.Entries[0].CreatedAt {
		t.Errorf("re-sign changed created_at: %q != %q", resign.Entries[0].CreatedAt, rel.Entries[0].CreatedAt)
	}
	// Manifest bytes (which carry created_at but NOT generated_at/expires_at) must be
	// byte-identical ⇒ manifest_sha256 unchanged ⇒ release identity preserved.
	for ref, mb := range relBundle.Manifests {
		if !bytes.Equal(resignBundle.Manifests[ref], mb) {
			t.Errorf("re-sign changed manifest %s bytes; release identity mutated", ref)
		}
	}
	// The index MUST differ, and only in the freshness timestamps.
	if resign.GeneratedAt == rel.GeneratedAt {
		t.Errorf("re-sign did not move generated_at")
	}
	if resign.ExpiresAt == rel.ExpiresAt {
		t.Errorf("re-sign did not move expires_at")
	}
}

// TestReleaseSpec_OldTagExpiredGuard proves the optional dead-on-arrival guard rejects
// an old-tag re-run whose expires_at is already past (REL-H3). Now is not written to
// any byte, so determinism is unaffected.
func TestReleaseSpec_OldTagExpiredGuard(t *testing.T) {
	in := releaseInputs("0.1.0", "2020-01-01T00:00:00Z") // +180d = 2020-06-29, long past
	in.Now = "2026-07-08T00:00:00Z"
	if _, err := buildReleaseSpec(in); err == nil {
		t.Fatalf("expected expired-guard rejection for an old tag, got nil")
	}

	// A fresh tag with the same guard passes.
	fresh := releaseInputs("0.1.0", "2026-07-08T00:00:00Z")
	fresh.Now = "2026-07-08T00:00:00Z"
	if _, err := buildReleaseSpec(fresh); err != nil {
		t.Fatalf("fresh tag rejected by guard: %v", err)
	}
}

// TestReleaseSpec_RejectsBadInputs covers required-field + mode fail-closed paths.
func TestReleaseSpec_RejectsBadInputs(t *testing.T) {
	cases := map[string]SpecInputs{
		"no version":        {Repo: testRepo, ListDigest: testDigest, Mode: specModeRelease, CommitISO: "2026-01-01T00:00:00Z"},
		"no repo":           {Version: "1.0.0", ListDigest: testDigest, Mode: specModeRelease, CommitISO: "2026-01-01T00:00:00Z"},
		"no digest":         {Version: "1.0.0", Repo: testRepo, Mode: specModeRelease, CommitISO: "2026-01-01T00:00:00Z"},
		"release no commit": {Version: "1.0.0", Repo: testRepo, ListDigest: testDigest, Mode: specModeRelease},
		"resign no fields":  {Version: "1.0.0", Repo: testRepo, ListDigest: testDigest, Mode: specModeResign},
		"bad commit iso":    {Version: "1.0.0", Repo: testRepo, ListDigest: testDigest, Mode: specModeRelease, CommitISO: "not-a-time"},
	}
	for name, in := range cases {
		if _, err := buildReleaseSpec(in); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
