// Release Catalog Spec Construction — M0 / E1 + E2 (correctness core).
//
// buildReleaseSpec assembles a *deterministic* releaseCatalogSpec from immutable
// inputs (a release version, the pushed image digest, and the tagged commit's
// date) so that re-running the same release produces byte-identical catalog
// bytes. It is PURE: no wall-clock, no git, no network. All timestamp and version
// derivation that used to live in CI shell (`date -u`, `git tag | wc -l`) moves
// here where it is unit-tested.
//
// The two load-bearing correctness properties (M0 design v2):
//
//  1. Deterministic timestamps — generated_at/created_at come from the tagged
//     commit's committer date (a fixed input per tag), normalized to UTC "Z".
//     expires_at = generated_at + ExpiryDays. Re-running a tag yields identical
//     bytes; the loader authenticates each manifest by hashing its RAW bytes
//     (release_catalog.go), so a one-byte timestamp drift would break the digest
//     binding.
//
//  2. Race-free monotonic version — catalog_version is a pure function of the
//     release semver (catalogVersionFromSemver), NOT a live count of git tags.
//     This makes allocation idempotent (re-running any tag, before or after other
//     tags exist, yields the same version), monotonic (a later GA release encodes
//     higher), and collision-free (distinct semver ⇒ distinct integer) — with no
//     shared mutable source to race on. Re-signing the same release trivially
//     reuses its version (same semver), so "re-sign does not allocate" holds by
//     construction.
//
// generateReleaseCatalog (release_gen.go) remains the SOLE validator; this file
// only assembles + normalizes the spec the generator consumes.
package main

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// specMode distinguishes a first-time release build from a freshness re-sign of an
// already-published release. Re-sign is wired by a later milestone (E8); the mode
// exists now so the version/created_at invariants are expressed and tested up front.
type specMode int

const (
	specModeRelease specMode = iota // first publish of a tag: timestamps from the commit
	specModeResign                  // freshness re-sign: caller supplies now + original created_at
)

// catalogVersionComponentMax bounds each semver component in the version encoding
// (major*1_000_000 + minor*1_000 + patch). A component ≥ this would collide with
// the next-higher component's range, so it is rejected fail-closed. The bound is
// revisited when pre-release/ring semantics are added (deferred).
const catalogVersionComponentMax = 1000

// catalogVersionCoreRE captures the numeric major.minor.patch core of a version.
// Stable-ring releases are GA (no pre-release/build metadata); a pre-release suffix
// is rejected by catalogVersionFromSemver (fail-closed) — the encoding for
// pre-releases lands with the ring work.
var catalogVersionCoreRE = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)

// SpecInputs are the immutable, deterministic inputs to buildReleaseSpec.
type SpecInputs struct {
	Version    string    // "1.4.3" — the release semver (from the tag ref / version_bare)
	Repo       string    // "ghcr.io/kidcarmi/culvert"
	ListDigest string    // "sha256:<64hex>" — the pushed manifest-list digest
	Platforms  []string  // e.g. ["linux/amd64","linux/arm64"]
	Channels   []Channel // channel pointers at this release (default: recommended)
	Severity   string    // "normal" | "critical" (default: normal)

	Mode       specMode
	CommitISO  string // release mode: the tagged commit's committer date (RFC3339, any offset)
	ExpiryDays int    // days added to generated_at for expires_at (0 ⇒ default 180)

	// Optional safety guard: when non-empty (RFC3339), buildReleaseSpec rejects a
	// spec whose expires_at is already at/before Now. Used to stop an old-tag
	// re-run from shipping a dead-on-arrival catalog. Now is NOT written into any
	// catalog byte, so it does not affect determinism.
	Now string

	// Re-sign mode only:
	ResignNow       string // RFC3339 "now" — becomes generated_at (freshness window slides)
	ResignCreatedAt string // the release's ORIGINAL created_at, carried forward unchanged
}

// defaultExpiryDays is the stable-ring freshness window (master design D9: raised
// from 90 to 180 so a low-cadence security product's auto-seed does not brick).
const defaultExpiryDays = 180

// buildReleaseSpec assembles a deterministic, normalized releaseCatalogSpec.
// It is pure. generateReleaseCatalog validates the result.
func buildReleaseSpec(in SpecInputs) (releaseCatalogSpec, error) {
	if in.Version == "" {
		return releaseCatalogSpec{}, fmt.Errorf("release spec: version is required")
	}
	if in.Repo == "" {
		return releaseCatalogSpec{}, fmt.Errorf("release spec: repo is required")
	}
	if in.ListDigest == "" {
		return releaseCatalogSpec{}, fmt.Errorf("release spec: list_digest is required")
	}

	catVer, err := catalogVersionFromSemver(in.Version)
	if err != nil {
		return releaseCatalogSpec{}, err
	}

	genAt, createdAt, err := specTimestamps(in)
	if err != nil {
		return releaseCatalogSpec{}, err
	}

	days := in.ExpiryDays
	if days == 0 {
		days = defaultExpiryDays
	}
	expAt, err := deriveExpiry(genAt, days)
	if err != nil {
		return releaseCatalogSpec{}, err
	}

	// Optional dead-on-arrival guard (does not touch bytes; see SpecInputs.Now).
	if in.Now != "" {
		now, perr := time.Parse(time.RFC3339, in.Now)
		if perr != nil {
			return releaseCatalogSpec{}, fmt.Errorf("release spec: now: %w", perr)
		}
		exp, _ := time.Parse(time.RFC3339, expAt) // expAt is well-formed (deriveExpiry)
		if !exp.After(now) {
			return releaseCatalogSpec{}, fmt.Errorf("release spec: expires_at %s is not after now %s (refusing to publish an already-expired catalog)", expAt, in.Now)
		}
	}

	severity := in.Severity
	if severity == "" {
		severity = string(SeverityNormal)
	}
	channels := in.Channels
	if len(channels) == 0 {
		channels = []Channel{ChannelRecommended}
	}

	return releaseCatalogSpec{
		GeneratedAt:    genAt,
		ExpiresAt:      expAt,
		CatalogVersion: catVer,
		Entries: []releaseEntrySpec{{
			ReleaseID:  "culvert-" + in.Version,
			VersionID:  in.Version,
			Severity:   severity,
			Repo:       in.Repo,
			ListDigest: in.ListDigest,
			Platforms:  in.Platforms,
			CreatedAt:  createdAt,
			Channels:   channels,
		}},
	}, nil
}

// specTimestamps derives (generated_at, created_at) per mode, normalized to UTC "Z".
//   - release: both = the tagged commit's committer date (deterministic per tag).
//   - resign:  generated_at = ResignNow (slides the freshness window); created_at =
//     the release's ORIGINAL created_at, carried forward unchanged (a re-sign must
//     not mutate release identity).
func specTimestamps(in SpecInputs) (generatedAt, createdAt string, err error) {
	switch in.Mode {
	case specModeResign:
		if in.ResignNow == "" || in.ResignCreatedAt == "" {
			return "", "", fmt.Errorf("release spec: resign mode requires resign_now and resign_created_at")
		}
		g, e := normalizeUTC(in.ResignNow)
		if e != nil {
			return "", "", fmt.Errorf("release spec: resign_now: %w", e)
		}
		c, e := normalizeUTC(in.ResignCreatedAt)
		if e != nil {
			return "", "", fmt.Errorf("release spec: resign_created_at: %w", e)
		}
		return g, c, nil
	default: // specModeRelease
		if in.CommitISO == "" {
			return "", "", fmt.Errorf("release spec: release mode requires commit_iso")
		}
		g, e := normalizeUTC(in.CommitISO)
		if e != nil {
			return "", "", fmt.Errorf("release spec: commit_iso: %w", e)
		}
		return g, g, nil // created_at == generated_at for a first release build
	}
}

// catalogVersionFromSemver encodes a GA semver into a monotonic, collision-free
// catalog_version. major*1_000_000 + minor*1_000 + patch. Each component must be
// < catalogVersionComponentMax; a pre-release/build suffix is rejected (fail
// closed — stable ring is GA only).
func catalogVersionFromSemver(version string) (int, error) {
	m := catalogVersionCoreRE.FindStringSubmatch(version)
	if m == nil {
		return 0, fmt.Errorf("release spec: version %q is not a plain GA semver X.Y.Z (pre-release/build not allowed on the stable ring)", version)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	for _, c := range [][2]interface{}{{"major", major}, {"minor", minor}, {"patch", patch}} {
		if c[1].(int) >= catalogVersionComponentMax {
			return 0, fmt.Errorf("release spec: version %q %s component %d exceeds encoding bound %d", version, c[0], c[1].(int), catalogVersionComponentMax)
		}
	}
	v := major*catalogVersionComponentMax*catalogVersionComponentMax + minor*catalogVersionComponentMax + patch
	if v < 1 {
		return 0, fmt.Errorf("release spec: version %q encodes to catalog_version %d (< 1)", version, v)
	}
	return v, nil
}

// deriveExpiry returns generatedAt + days, formatted as UTC "Z". generatedAt must
// already be normalized RFC3339.
func deriveExpiry(generatedAt string, days int) (string, error) {
	if days <= 0 {
		return "", fmt.Errorf("release spec: expiry days must be > 0, got %d", days)
	}
	g, err := time.Parse(time.RFC3339, generatedAt)
	if err != nil {
		return "", fmt.Errorf("release spec: generated_at: %w", err)
	}
	return g.UTC().AddDate(0, 0, days).Format(time.RFC3339), nil
}

// normalizeUTC parses an RFC3339 timestamp (any offset) and re-emits it as UTC "Z".
// git's `%cI` emits the committer's numeric offset (e.g. +00:00), which would drift
// byte-for-byte from the retired `date -u …Z` form and change manifest_sha256.
func normalizeUTC(rfc3339 string) (string, error) {
	t, err := time.Parse(time.RFC3339, rfc3339)
	if err != nil {
		return "", err
	}
	return t.UTC().Format(time.RFC3339), nil
}
