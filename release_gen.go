// Release Catalog Generator — P2a.
//
// Deterministically generates a release catalog (index.json + per-release
// manifests) from release metadata, so an official catalog is produced by CI
// from the digest the workflow actually pushed — never hand-edited. The output
// is the EXACT on-disk shape the P1.2 loader (release_catalog.go) consumes, and
// the P2a CI gate (release_gen_test.go) round-trips the generated bundle back
// through LoadVerifiedCatalog so the generator can never drift from runtime
// verification.
//
// Determinism is load-bearing: the loader authenticates each manifest by hashing
// its RAW bytes, so generation MUST be byte-stable — compact json.Marshal (no
// indent; encoding/json already emits map keys in sorted order), RFC3339-UTC
// timestamps supplied by the caller, and releases emitted in sorted release_id
// order. TestGenerateReleaseCatalog_Deterministic is the merge gate.
//
// Scope (roadmap/D1.6d-P2-release-pipeline-signing-plan.md — P2a): generation +
// validation only. NO signing trust decision (the CI gate signs with an
// EPHEMERAL key for round-trip proof only), NO Control-Plane trust-model change
// (that is P2b), NO network.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// releaseEntrySpec is one release's input to the generator. It mirrors the fields
// the manifest needs; the generator validates each against the same rules the
// loader enforces (defense-in-depth) before emitting.
type releaseEntrySpec struct {
	ReleaseID      string    `json:"release_id"`
	VersionID      string    `json:"version_id"`
	Severity       string    `json:"severity"`
	Repo           string    `json:"repo"`
	ListDigest     string    `json:"list_digest"` // sha256:<64hex> (manifest-LIST digest)
	Platforms      []string  `json:"platforms"`
	CreatedAt      string    `json:"created_at"` // RFC3339
	MinUpgradeFrom string    `json:"min_upgrade_from,omitempty"`
	ChangelogURL   string    `json:"changelog_url,omitempty"`
	Notes          string    `json:"notes,omitempty"`
	Channels       []Channel `json:"channels,omitempty"` // channels pointing AT this release
}

// releaseCatalogSpec is the full generator input.
type releaseCatalogSpec struct {
	GeneratedAt    string             `json:"generated_at"` // RFC3339
	ExpiresAt      string             `json:"expires_at"`   // RFC3339 (P2a: created_at + 90d default)
	CatalogVersion int                `json:"catalog_version"`
	Entries        []releaseEntrySpec `json:"entries"`
}

// releaseBundle is the generated, byte-stable output: the raw index.json bytes
// and each manifest file's raw bytes (keyed by its bare filename).
type releaseBundle struct {
	Index     []byte
	Manifests map[string][]byte // "<release_id>.json" → raw bytes
}

// generateReleaseCatalog validates the spec and produces a deterministic bundle.
// It fails closed on anything the loader would reject (so a bad release can never
// be published), and additionally requires the P2a freshness/rollback fields
// (expires_at, catalog_version) the enforce-mode runtime needs.
func generateReleaseCatalog(spec releaseCatalogSpec) (*releaseBundle, error) {
	if err := validateGenTimestamps(spec); err != nil {
		return nil, err
	}
	if spec.CatalogVersion < 1 {
		return nil, fmt.Errorf("release gen: catalog_version must be ≥ 1, got %d", spec.CatalogVersion)
	}
	if len(spec.Entries) == 0 {
		return nil, fmt.Errorf("release gen: no release entries")
	}

	// Emit releases in sorted release_id order for byte-stability.
	entries := append([]releaseEntrySpec(nil), spec.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ReleaseID < entries[j].ReleaseID })

	manifests := make(map[string][]byte, len(entries))
	idxEntries := make([]catalogIndexEntry, 0, len(entries))
	channels := map[string]string{}
	seenID := map[string]bool{}

	for i := range entries {
		e := entries[i]
		ref := e.ReleaseID + ".json"
		manBytes, err := genManifest(e)
		if err != nil {
			return nil, err
		}
		// The ref must be a bare filename the loader will accept (no separators);
		// this rejects a release_id containing path separators at generation time.
		if err := catalogValidateManifestRef(ref); err != nil {
			return nil, fmt.Errorf("release gen: release %q: %w", e.ReleaseID, err)
		}
		if seenID[e.ReleaseID] {
			return nil, fmt.Errorf("release gen: duplicate release_id %q", e.ReleaseID)
		}
		seenID[e.ReleaseID] = true
		manifests[ref] = manBytes

		sum := sha256.Sum256(manBytes)
		idxEntries = append(idxEntries, catalogIndexEntry{
			ReleaseID:      e.ReleaseID,
			VersionID:      e.VersionID,
			ManifestRef:    ref,
			ManifestSHA256: hex.EncodeToString(sum[:]),
		})

		if err := collectChannels(channels, e.ReleaseID, e.Channels); err != nil {
			return nil, err
		}
	}

	idx := catalogIndexFile{
		SchemaVersion:  catalogSchemaMajor,
		GeneratedAt:    spec.GeneratedAt,
		ExpiresAt:      spec.ExpiresAt,
		CatalogVersion: spec.CatalogVersion,
		Channels:       channels,
		Releases:       idxEntries,
	}
	idxBytes, err := json.Marshal(idx) // compact; encoding/json sorts map keys
	if err != nil {
		return nil, fmt.Errorf("release gen: marshal index: %w", err)
	}
	return &releaseBundle{Index: idxBytes, Manifests: manifests}, nil
}

// collectChannels records each of a release's channel pointers into the shared
// channels map, rejecting unknown channel keys and any channel that would point
// at two different releases. Extracted from generateReleaseCatalog to keep that
// function's nesting (and cognitive complexity) low.
func collectChannels(channels map[string]string, relID string, chs []Channel) error {
	for _, ch := range chs {
		if _, known := catalogKnownChannel(string(ch)); !known {
			return fmt.Errorf("release gen: release %q: unknown channel %q", relID, ch)
		}
		if prev, dup := channels[string(ch)]; dup {
			return fmt.Errorf("release gen: channel %q points at both %q and %q", ch, prev, relID)
		}
		channels[string(ch)] = relID
	}
	return nil
}

// genManifest validates one entry and returns its raw, byte-stable manifest bytes.
func genManifest(e releaseEntrySpec) ([]byte, error) {
	if err := catalogValidateID("release_id", e.ReleaseID); err != nil {
		return nil, err
	}
	if !catalogSemverRE.MatchString(e.VersionID) {
		return nil, fmt.Errorf("release gen: release %q: version_id %q is not semver", e.ReleaseID, e.VersionID)
	}
	if e.Severity == "" {
		return nil, fmt.Errorf("release gen: release %q: severity is required", e.ReleaseID)
	}
	if err := catalogValidateRepo(e.Repo); err != nil { // rejects tags/@digest
		return nil, fmt.Errorf("release gen: release %q: %w", e.ReleaseID, err)
	}
	if !catalogListDigestRE.MatchString(e.ListDigest) {
		return nil, fmt.Errorf("release gen: release %q: list_digest must be sha256:<64 lowercase hex>", e.ReleaseID)
	}
	if e.CreatedAt == "" {
		return nil, fmt.Errorf("release gen: release %q: created_at is required", e.ReleaseID)
	}
	if _, err := time.Parse(time.RFC3339, e.CreatedAt); err != nil {
		return nil, fmt.Errorf("release gen: release %q: created_at: %w", e.ReleaseID, err)
	}
	if e.MinUpgradeFrom != "" && !catalogSemverRE.MatchString(e.MinUpgradeFrom) {
		return nil, fmt.Errorf("release gen: release %q: min_upgrade_from %q is not semver", e.ReleaseID, e.MinUpgradeFrom)
	}

	platforms := append([]string(nil), e.Platforms...)
	sort.Strings(platforms) // byte-stability

	var man catalogManifestFile
	man.SchemaVersion = catalogSchemaMajor
	man.ReleaseID = e.ReleaseID
	man.VersionID = e.VersionID
	man.Severity = e.Severity
	man.CreatedAt = e.CreatedAt
	man.Image.Repo = e.Repo
	man.Image.ListDigest = e.ListDigest
	man.Image.Platforms = platforms
	man.MinUpgradeFrom = e.MinUpgradeFrom
	man.ChangelogURL = e.ChangelogURL
	man.Notes = e.Notes

	b, err := json.Marshal(man) // compact, deterministic
	if err != nil {
		return nil, fmt.Errorf("release gen: release %q: marshal manifest: %w", e.ReleaseID, err)
	}
	return b, nil
}

// validateGenTimestamps requires well-formed RFC3339 generated_at/expires_at and
// expires_at strictly after generated_at (a degenerate window is a generator bug).
func validateGenTimestamps(spec releaseCatalogSpec) error {
	gen, err := time.Parse(time.RFC3339, spec.GeneratedAt)
	if err != nil {
		return fmt.Errorf("release gen: generated_at: %w", err)
	}
	exp, err := time.Parse(time.RFC3339, spec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("release gen: expires_at: %w", err)
	}
	if !exp.After(gen) {
		return fmt.Errorf("release gen: expires_at %s must be after generated_at %s", spec.ExpiresAt, spec.GeneratedAt)
	}
	return nil
}

// writeReleaseBundle materializes the bundle into dir as index.json,
// manifests/<ref>, an optional index.json.sig (when sig != nil), and an
// audit-only checksums.txt. Files are written with restrictive modes; dir is
// created if absent. Manifest refs are re-validated as bare filenames before
// any write (defense-in-depth, even though the generator already validated them).
func writeReleaseBundle(dir string, b *releaseBundle, sig []byte) error {
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), b.Index, 0o600); err != nil {
		return err
	}
	if sig != nil {
		if err := os.WriteFile(filepath.Join(dir, "index.json.sig"), sig, 0o600); err != nil {
			return err
		}
	}
	for ref, data := range b.Manifests {
		if err := catalogValidateManifestRef(ref); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "manifests", ref), data, 0o600); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, "checksums.txt"), checksumsFile(b), 0o600)
}

// checksumsFile renders an audit-only SHA-256 listing of the bundle files (the
// Control Plane never reads this — authenticated integrity is the per-manifest
// manifest_sha256 + the index signature). Deterministic (sorted by name).
func checksumsFile(b *releaseBundle) []byte {
	lines := make([]string, 0, len(b.Manifests)+1)
	sum := sha256.Sum256(b.Index)
	lines = append(lines, fmt.Sprintf("%s  index.json", hex.EncodeToString(sum[:])))
	names := make([]string, 0, len(b.Manifests))
	for name := range b.Manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := sha256.Sum256(b.Manifests[name])
		lines = append(lines, fmt.Sprintf("%s  manifests/%s", hex.EncodeToString(s[:]), name))
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return []byte(out)
}
