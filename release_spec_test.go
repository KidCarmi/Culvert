package main

import (
	"bytes"
	"reflect"
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

	// Deterministic exact encodings (base offset + major*1e6 + minor*1e3 + patch).
	if got := must("1.4.3"); got != catalogVersionSchemeEpoch+1_004_003 {
		t.Errorf("v1.4.3 encoded %d, want %d", got, catalogVersionSchemeEpoch+1_004_003)
	}
	if got := must("0.0.1"); got != catalogVersionSchemeEpoch+1 {
		t.Errorf("v0.0.1 encoded %d, want %d", got, catalogVersionSchemeEpoch+1)
	}
	if got := must("0.0.16"); got != catalogVersionSchemeEpoch+16 {
		t.Errorf("v0.0.16 encoded %d, want %d", got, catalogVersionSchemeEpoch+16)
	}
	// Component boundary: 999 passes (only ≥1000 is rejected).
	if got := must("0.0.999"); got != catalogVersionSchemeEpoch+999 {
		t.Errorf("v0.0.999 encoded %d, want %d", got, catalogVersionSchemeEpoch+999)
	}

	// Migration-safety: every semver encoding dwarfs any legacy count-based floor
	// (retired scheme was (count of v* tags)+1, realistically < 1e5), so the
	// count→semver transition only ever moves the floor UP, never a false rollback.
	if must("0.0.1") <= 100_000 {
		t.Errorf("smallest semver encoding %d must exceed any plausible count-based floor", must("0.0.1"))
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

	// Fail-closed cases — leading zeros (must match the generator's strict core),
	// 0.0.0 (not a real release), pre-release/build (GA-only stable ring), component
	// ≥1000, and an overflowing component (strconv.Atoi ErrRange must be rejected,
	// not silently mis-encoded).
	for _, bad := range []string{
		"1.4", "1.4.3.2", "1.4.3-rc.1", "1.4.3+build.5", "v1.4.3", "1.4.1000", "1.1000.0", "1000.0.0",
		"", "x.y.z", "01.4.3", "1.04.3", "1.4.03", "0.0.0",
		"99999999999999999999.0.0", "1.99999999999999999999.0", "1.0.99999999999999999999",
	} {
		if _, err := catalogVersionFromSemver(bad); err == nil {
			t.Errorf("catalogVersionFromSemver(%q): expected error, got nil", bad)
		}
	}
}

// TestCatalogVersionFromSemver_BoundaryOrdering proves the base-B positional encoding
// has NO cross-component carry: a maxed lower component never reaches the next value
// of the higher component. This is the precise ordering guarantee (major dominates
// minor dominates patch) the appliance rollback floor relies on.
func TestCatalogVersionFromSemver_BoundaryOrdering(t *testing.T) {
	enc := func(v string) int {
		t.Helper()
		n, err := catalogVersionFromSemver(v)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		return n
	}
	// Each pair: max-out the lower component(s), then increment the next-higher one.
	pairs := [][2]string{
		{"0.0.999", "0.1.0"},    // patch maxed < next minor
		{"0.999.999", "1.0.0"},  // minor+patch maxed < next major
		{"1.0.999", "1.1.0"},    // patch maxed < next minor (nonzero major)
		{"1.999.999", "2.0.0"},  // minor+patch maxed < next major
		{"9.999.999", "10.0.0"}, // two-digit major boundary
	}
	for _, p := range pairs {
		lo, hi := enc(p[0]), enc(p[1])
		if lo >= hi {
			t.Errorf("cross-component carry: %s (%d) must be < %s (%d)", p[0], lo, p[1], hi)
		}
	}
	// Exact packed value pins the formula EPOCH + major*1e6 + minor*1e3 + patch.
	if enc("2.3.4") != catalogVersionSchemeEpoch+2_003_004 {
		t.Errorf("v2.3.4 = %d, want %d", enc("2.3.4"), catalogVersionSchemeEpoch+2_003_004)
	}
}

// TestReleaseSpec_Idempotent proves re-running the SAME release yields byte-identical
// catalog bytes (must-prove #2). Because catalog_version is semver-derived and the
// timestamps come from the fixed commit date, no external mutable state (tag count,
// wall clock) can perturb the output — so two independent builds are identical.
func TestReleaseSpec_Idempotent(t *testing.T) {
	in := releaseInputs("1.4.3", "2026-07-08T12:00:00+02:00")

	build := func() (releaseCatalogSpec, []byte) {
		t.Helper()
		spec, err := buildReleaseSpec(in)
		if err != nil {
			t.Fatalf("buildReleaseSpec: %v", err)
		}
		b, err := generateReleaseCatalog(spec)
		if err != nil {
			t.Fatalf("generateReleaseCatalog: %v", err)
		}
		return spec, b.Index
	}

	spec1, idx1 := build()
	spec2, idx2 := build()
	// Byte-identical specification INPUTS (the assembled spec, incl. derived
	// timestamps + catalog_version), not just the generated output.
	if !reflect.DeepEqual(spec1, spec2) {
		t.Fatalf("non-idempotent spec inputs:\n %+v\n %+v", spec1, spec2)
	}
	if !bytes.Equal(idx1, idx2) {
		t.Fatalf("non-idempotent output bytes:\n a=%s\n b=%s", idx1, idx2)
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

// TestReleaseSpec_NowGuardBoundary proves the dead-on-arrival guard rejects at the
// exact boundary (expires_at == now ⇒ !After ⇒ reject) and admits one second later.
func TestReleaseSpec_NowGuardBoundary(t *testing.T) {
	in := releaseInputs("0.1.0", "2026-01-01T00:00:00Z") // +180d = 2026-06-30T00:00:00Z
	in.Now = "2026-06-30T00:00:00Z"                      // exactly expiry
	if _, err := buildReleaseSpec(in); err == nil {
		t.Errorf("expected rejection when expires_at == now (boundary)")
	}
	in.Now = "2026-06-29T23:59:59Z" // one second before expiry
	if _, err := buildReleaseSpec(in); err != nil {
		t.Errorf("one second before expiry should pass: %v", err)
	}
}

// TestReleaseSpec_ResignNormalizesCreatedAt proves a non-Zulu original created_at is
// normalized to UTC "Z" on the resign path (the resign-side normalizeUTC).
func TestReleaseSpec_ResignNormalizesCreatedAt(t *testing.T) {
	spec, err := buildReleaseSpec(SpecInputs{
		Version:         "1.4.3",
		Repo:            testRepo,
		ListDigest:      testDigest,
		Platforms:       []string{"linux/amd64"},
		Mode:            specModeResign,
		ResignNow:       "2026-10-01T09:00:00+02:00", // 07:00Z
		ResignCreatedAt: "2026-07-08T14:30:00+02:00", // 12:30Z
	})
	if err != nil {
		t.Fatalf("resign build: %v", err)
	}
	if spec.GeneratedAt != "2026-10-01T07:00:00Z" {
		t.Errorf("resign generated_at not UTC-Z: %q", spec.GeneratedAt)
	}
	if spec.Entries[0].CreatedAt != "2026-07-08T12:30:00Z" {
		t.Errorf("resign created_at not UTC-Z: %q", spec.Entries[0].CreatedAt)
	}
}

// TestReleaseSpec_OverridesAndExpiry exercises the caller-supplied severity/channels
// branch and the ExpiryDays override (+ negative fail-closed).
func TestReleaseSpec_OverridesAndExpiry(t *testing.T) {
	in := releaseInputs("2.1.0", "2026-01-01T00:00:00Z")
	in.Severity = string(SeverityCritical)
	in.Channels = []Channel{ChannelCritical}
	in.ExpiryDays = 30
	spec, err := buildReleaseSpec(in)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.Entries[0].Severity != string(SeverityCritical) {
		t.Errorf("severity override ignored: %q", spec.Entries[0].Severity)
	}
	if len(spec.Entries[0].Channels) != 1 || spec.Entries[0].Channels[0] != ChannelCritical {
		t.Errorf("channels override ignored: %v", spec.Entries[0].Channels)
	}
	if spec.ExpiresAt != "2026-01-31T00:00:00Z" {
		t.Errorf("ExpiryDays=30 override wrong: %q", spec.ExpiresAt)
	}

	in.ExpiryDays = -5
	if _, err := buildReleaseSpec(in); err == nil {
		t.Errorf("negative ExpiryDays must fail closed")
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
