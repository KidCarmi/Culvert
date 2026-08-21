// Feed Publisher Generator — F5 (dormant).
//
// Deterministically produces the exact signed-feed bytes the dedicated CI signing
// workflow (.github/workflows/publish-feeds.yml) signs and the dedicated publisher
// publishes, plus the offline re-verification that both jobs run through the SAME
// production trust kernel (internal/urlcatfeed). This file holds ONLY the pure,
// network-free, credential-free generation + assembly + verify glue; all signing
// (keyless cosign) and all publishing (R2 CAS) live in the privilege-separated
// workflow, gated dormant by FEEDS_PUBLISH_ENABLED (F0 §11).
//
// Determinism is load-bearing: the workflow hashes and keyless-signs these RAW
// bytes, so identical semantic input MUST yield byte-identical output. All
// normalization, category, manifest, envelope, and verification logic is REUSED
// from internal/urlcatfeed — this file never re-implements any of it.
//
// Version strategy (F0 §4.3 "monotonic integer ≥ 1"; F5 stateless, no R2 creds in
// the sign job): feed_version = whole-second UTC Unix seconds of a single
// generated_at instant captured once at the start of the signing job. It is
// strictly increasing over wall-clock, needs no published-state read to derive,
// and the publisher's CAS (§11.3) is the authority that rejects it unless it is
// strictly greater than the currently-published version. A no-content-change
// weekly re-sign therefore still produces a strictly greater feed_version (a new
// immutable artifact), never a same-version renewal.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// feedNormalValidity is the NORMAL publisher validity window (F5). It is distinct
// from urlcatfeed.MaxValidity (the 30-day hard producer/verify ceiling) and from
// the client's current-time freshness enforcement (F3b).
const feedNormalValidity = 14 * 24 * time.Hour

// feedEnvelopeKey is the single mutable envelope object key (F0 §4.1, B6).
const feedEnvelopeKey = "manifest.sigstore.json"

var (
	errFeedDatasetDecode = errors.New("feed gen: source dataset is not strict-decodable")
	errFeedDatasetDup    = errors.New("feed gen: duplicate category name in source dataset")
	errFeedDatasetEmpty  = errors.New("feed gen: source dataset has no categories")
	errFeedNotReady      = errors.New("feed gen: source dataset failed readiness (EvaluateReadiness.Ready == false)")
	errFeedValidity      = errors.New("feed gen: validity window invalid")
)

// deriveFeedVersion maps a generated_at instant to the F5 feed_version: whole-second
// UTC Unix seconds. Pure; the caller captures the instant ONCE and reuses it for
// generation and signing so every artifact/manifest field is consistent.
func deriveFeedVersion(generatedAt time.Time) int64 {
	return generatedAt.UTC().Truncate(time.Second).Unix()
}

// feedSourceCategoryJSON is the on-disk shape of ONE entry in the approved source
// dataset (internal/urlcat/default_categories.json): a bare array of {name, hosts}.
// The loader decodes this and wraps it into urlcatfeed.SourceDataset — it does NOT
// duplicate normalization/category logic (that stays in internal/urlcatfeed).
type feedSourceCategoryJSON struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

// loadFeedSourceDataset STRICTLY decodes the approved source dataset file into a
// urlcatfeed.SourceDataset. Strictness (F5 loader contract): unknown fields, a
// non-array/non-canonical top level, and any trailing bytes after the array are
// rejected; duplicate category names (case-insensitive) are rejected; an empty set
// is rejected. Semantic readiness (host conflicts, suffix pairs, name bounds) is
// left to EvaluateReadiness so there is exactly one source of truth for it.
func loadFeedSourceDataset(path string) (urlcatfeed.SourceDataset, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- CI-configured dataset path
	if err != nil {
		return urlcatfeed.SourceDataset{}, fmt.Errorf("feed gen: read dataset: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw []feedSourceCategoryJSON
	if err := dec.Decode(&raw); err != nil {
		return urlcatfeed.SourceDataset{}, fmt.Errorf("%w: %v", errFeedDatasetDecode, err)
	}
	// Reject trailing tokens after the single JSON array (no concatenated documents).
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return urlcatfeed.SourceDataset{}, fmt.Errorf("%w: trailing data after array", errFeedDatasetDecode)
	}
	if len(raw) == 0 {
		return urlcatfeed.SourceDataset{}, errFeedDatasetEmpty
	}
	seen := make(map[string]bool, len(raw))
	cats := make([]urlcatfeed.SourceCategory, 0, len(raw))
	for _, c := range raw {
		key := strings.ToLower(strings.TrimSpace(c.Name))
		if seen[key] {
			return urlcatfeed.SourceDataset{}, fmt.Errorf("%w: %q", errFeedDatasetDup, c.Name)
		}
		seen[key] = true
		cats = append(cats, urlcatfeed.SourceCategory{Name: c.Name, Hosts: c.Hosts})
	}
	return urlcatfeed.SourceDataset{Categories: cats}, nil
}

// feedGenSpec is the full, explicit input to generateFeed (no clock read here).
type feedGenSpec struct {
	DatasetPath     string
	GeneratedAt     time.Time     // captured once by the caller (job start)
	Validity        time.Duration // 0 ⇒ feedNormalValidity (14d); hard-capped at urlcatfeed.MaxValidity
	PrevFeedVersion int64         // 0 in the sign job; the publisher CAS enforces strictly-greater-than-published
}

// feedInventory is the machine-readable digest/inventory report (F5 handoff
// metadata.json). Producer-side fields are filled here; the workflow adds source
// commit / workflow ref / run identity before handoff to the publish job.
type feedInventory struct {
	SchemaVersion   int    `json:"schema_version"`
	Protocol        string `json:"protocol"`
	Feed            string `json:"feed"`
	FeedVersion     int64  `json:"feed_version"`
	GeneratedAt     string `json:"generated_at"`
	ExpiresAt       string `json:"expires_at"`
	ArtifactPath    string `json:"artifact_path"`
	ArtifactSigPath string `json:"artifact_sig_path"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	ArtifactSize    int64  `json:"artifact_size"`
	ManifestSHA256  string `json:"manifest_sha256"` // digest of the RAW manifest-payload bytes (what the envelope bundle signs)
	EnvelopeKey     string `json:"envelope_key"`
	CategoryCount   int    `json:"category_count"`
	HostCount       int    `json:"host_count"`
}

// feedBundle is the produced, byte-stable output.
type feedBundle struct {
	ArtifactBytes []byte // canonical artifact JSON — signed by its own bundle, published immutable
	ManifestBytes []byte // canonical manifest-payload JSON — signed by the envelope bundle
	Result        *urlcatfeed.GenerateResult
	Inventory     feedInventory
}

// generateFeed loads + strictly validates the dataset, REQUIRES readiness, derives
// the Unix-second feed_version, and deterministically produces the artifact +
// manifest-payload bytes via internal/urlcatfeed. It never signs, publishes, or
// reads the clock.
func generateFeed(spec feedGenSpec) (*feedBundle, error) {
	ds, err := loadFeedSourceDataset(spec.DatasetPath)
	if err != nil {
		return nil, err
	}
	if rep := urlcatfeed.EvaluateReadiness(ds); !rep.Ready {
		return nil, fmt.Errorf("%w: %s", errFeedNotReady, summarizeReadiness(rep))
	}

	genAt := spec.GeneratedAt.UTC().Truncate(time.Second)
	if genAt.IsZero() {
		return nil, fmt.Errorf("%w: generated_at is zero", errFeedValidity)
	}
	validity := spec.Validity
	if validity == 0 {
		validity = feedNormalValidity
	}
	if validity <= 0 {
		return nil, fmt.Errorf("%w: non-positive validity %s", errFeedValidity, validity)
	}
	if validity > urlcatfeed.MaxValidity {
		return nil, fmt.Errorf("%w: %s exceeds the %s ceiling", errFeedValidity, validity, urlcatfeed.MaxValidity)
	}
	expiresAt := genAt.Add(validity)
	feedVersion := deriveFeedVersion(genAt)

	res, err := urlcatfeed.Generate(urlcatfeed.GenerateInput{
		Source:          ds,
		FeedVersion:     feedVersion,
		PrevFeedVersion: spec.PrevFeedVersion,
		GeneratedAt:     genAt,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("feed gen: generate: %w", err)
	}

	manSum := sha256.Sum256(res.ManifestBytes)
	inv := feedInventory{
		SchemaVersion:   res.Manifest.SchemaVersion,
		Protocol:        res.Manifest.Protocol,
		Feed:            res.Manifest.Feed,
		FeedVersion:     res.Manifest.FeedVersion,
		GeneratedAt:     res.Manifest.GeneratedAt,
		ExpiresAt:       res.Manifest.ExpiresAt,
		ArtifactPath:    res.ArtifactPath,
		ArtifactSigPath: res.ArtifactSigPath,
		ArtifactSHA256:  res.ArtifactSHA256,
		ArtifactSize:    res.Manifest.ArtifactSize,
		ManifestSHA256:  hex.EncodeToString(manSum[:]),
		EnvelopeKey:     feedEnvelopeKey,
		CategoryCount:   res.CategoryCount,
		HostCount:       res.HostCount,
	}
	return &feedBundle{
		ArtifactBytes: res.ArtifactBytes,
		ManifestBytes: res.ManifestBytes,
		Result:        res,
		Inventory:     inv,
	}, nil
}

// summarizeReadiness renders a bounded, deterministic one-line reason for a
// not-ready dataset (counts of each conflict class) — never raw host dumps.
func summarizeReadiness(r *urlcatfeed.ReadinessReport) string {
	return fmt.Sprintf("invalid_hosts=%d multi_category=%d suffix_conflicts=%d category_name=%d structural=%d",
		len(r.InvalidHosts), len(r.MultiCategory), len(r.SuffixConflict), len(r.CategoryName), len(r.StructuralIssues))
}

// writeFeedGenOutput materializes the generate-phase output into dir: the immutable
// artifact JSON (under its verified artifact_path key), the RAW manifest-payload
// bytes (the bytes cosign signs to build the envelope), and the inventory. Files
// use restrictive modes; the key is re-validated as a bare filename.
func writeFeedGenOutput(dir string, b *feedBundle) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if strings.ContainsAny(b.Result.ArtifactPath, "/\\") || b.Result.ArtifactPath == "" {
		return fmt.Errorf("feed gen: refusing unsafe artifact_path %q", b.Result.ArtifactPath)
	}
	if err := os.WriteFile(dir+"/"+b.Result.ArtifactPath, b.ArtifactBytes, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(dir+"/manifest-payload.json", b.ManifestBytes, 0o600); err != nil {
		return err
	}
	invBytes, err := json.MarshalIndent(b.Inventory, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dir+"/metadata.json", append(invBytes, '\n'), 0o600)
}

// assembleAndVerifyFeedEnvelope builds the single self-contained manifest envelope
// from the RAW manifest-payload bytes + the cosign bundle over those bytes, then
// runs the FULL production offline verification (the SAME trust kernel + baked root
// + pinned feed identity the client uses) over the envelope AND the artifact +
// artifact bundle. It cross-checks that the verified manifest binds the exact
// artifact the generator produced. Any failure returns an error and NO envelope —
// the publisher must never promote an envelope that did not pass this gate.
func assembleAndVerifyFeedEnvelope(b *feedBundle, manifestBundleJSON, artifactBundleJSON []byte) ([]byte, error) {
	envelope, err := urlcatfeed.AssembleEnvelope(b.ManifestBytes, manifestBundleJSON)
	if err != nil {
		return nil, fmt.Errorf("feed gen: assemble envelope: %w", err)
	}
	if err := verifyFeedEnvelopeOffline(envelope, b.ArtifactBytes, artifactBundleJSON, b.Result); err != nil {
		return nil, err
	}
	return envelope, nil
}

// verifyFeedEnvelopeOffline runs the production verifier (baked shared root + pinned
// feed identity) over the envelope + artifact, offline. It is the exact
// verify-before-parse path the client executes, reused so producer and client can
// never drift. It additionally asserts the verified manifest points at the artifact
// bytes we hold (digest + counts) — the PRODUCER-side (Job A) anti-substitution
// binding against the just-generated result.
func verifyFeedEnvelopeOffline(envelope, artifactBytes, artifactBundleJSON []byte, res *urlcatfeed.GenerateResult) error {
	manifest, err := verifyFeedArtifactAndEnvelope(envelope, artifactBytes, artifactBundleJSON)
	if err != nil {
		return err
	}
	return crossCheckVerifiedManifest(manifest, res)
}

// verifyFeedArtifactAndEnvelope is the single production trust chokepoint: it builds
// the production verifier (baked shared root + pinned feed identity), verifies the
// signed manifest envelope, verifies the artifact bundle AGAINST that verified
// manifest, and recomputes host/category counts from the verified artifact —
// requiring them to equal the signed manifest. Offline; no regeneration. Producer
// (Job A), publisher (Job B), and client all route through this so none can drift.
func verifyFeedArtifactAndEnvelope(envelope, artifactBytes, artifactBundleJSON []byte) (*urlcatfeed.ManifestPayload, error) {
	verifier, err := urlcatfeed.NewVerifierFromJSON(bakedSigstoreTrustedRootJSON, urlcatfeed.OfficialIdentity())
	if err != nil {
		return nil, fmt.Errorf("feed gen: build verifier: %w", err)
	}
	manifest, err := verifier.VerifyEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("feed gen: verify envelope: %w", err)
	}
	artifact, err := verifier.VerifyArtifact(artifactBytes, artifactBundleJSON, manifest)
	if err != nil {
		return nil, fmt.Errorf("feed gen: verify artifact: %w", err)
	}
	if got := countArtifactHosts(artifact); got != manifest.HostCount {
		return nil, fmt.Errorf("feed gen: verified host_count %d != manifest %d", got, manifest.HostCount)
	}
	if len(artifact.Categories) != manifest.CategoryCount {
		return nil, fmt.Errorf("feed gen: verified category_count %d != manifest %d", len(artifact.Categories), manifest.CategoryCount)
	}
	return manifest, nil
}

// verifyFeedBundleDir re-verifies an ALREADY-ASSEMBLED feed bundle on disk — the
// envelope (feedEnvelopeKey), the artifact it names, and the artifact bundle —
// WITHOUT regenerating. This is the PUBLISHER's (Job B) re-verify seam, used against
// (1) Job A's downloaded workflow artifact (§11.2 step 3), (2) the artifact fetched
// through the public origin (steps 5–6), and (3) the public envelope after promotion
// (step 9). The envelope is verified FIRST so a forged/unsigned envelope can never
// steer which artifact file we read; artifact_path/sig_path are re-checked as bare
// keys (defense-in-depth over the verifier's own safeRelKey gate). Returns the
// verified manifest so the publisher can drive the §11.3 CAS on its signed
// feed_version.
func verifyFeedBundleDir(dir string) (*urlcatfeed.ManifestPayload, error) {
	envelope, err := os.ReadFile(filepath.Join(dir, feedEnvelopeKey)) // #nosec G304 -- CI-controlled bundle dir
	if err != nil {
		return nil, fmt.Errorf("feed gen: read envelope: %w", err)
	}
	verifier, err := urlcatfeed.NewVerifierFromJSON(bakedSigstoreTrustedRootJSON, urlcatfeed.OfficialIdentity())
	if err != nil {
		return nil, fmt.Errorf("feed gen: build verifier: %w", err)
	}
	manifest, err := verifier.VerifyEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("feed gen: verify envelope: %w", err)
	}
	if strings.ContainsAny(manifest.ArtifactPath, "/\\") || manifest.ArtifactPath == "" ||
		strings.ContainsAny(manifest.ArtifactSigPath, "/\\") || manifest.ArtifactSigPath == "" {
		return nil, fmt.Errorf("feed gen: refusing unsafe artifact key(s) %q / %q", manifest.ArtifactPath, manifest.ArtifactSigPath)
	}
	artBytes, err := os.ReadFile(filepath.Join(dir, manifest.ArtifactPath)) // #nosec G304 -- verified bare key
	if err != nil {
		return nil, fmt.Errorf("feed gen: read artifact: %w", err)
	}
	artBundle, err := os.ReadFile(filepath.Join(dir, manifest.ArtifactSigPath)) // #nosec G304 -- verified bare key
	if err != nil {
		return nil, fmt.Errorf("feed gen: read artifact bundle: %w", err)
	}
	// Full trust chain (re-verifies the envelope + verifies the artifact + counts).
	return verifyFeedArtifactAndEnvelope(envelope, artBytes, artBundle)
}

// crossCheckVerifiedManifest asserts a VERIFIED manifest binds the exact artifact the
// generator produced (digest match). This is the anti-substitution binding: even a
// correctly-signed manifest for a DIFFERENT artifact is rejected before the artifact
// is trusted.
func crossCheckVerifiedManifest(manifest *urlcatfeed.ManifestPayload, res *urlcatfeed.GenerateResult) error {
	if manifest.ArtifactSHA256 != res.ArtifactSHA256 {
		return fmt.Errorf("feed gen: verified manifest artifact_sha256 %q != generated %q", manifest.ArtifactSHA256, res.ArtifactSHA256)
	}
	return nil
}

// countArtifactHosts counts the unique normalized hosts in a verified artifact
// (host keys are already normalized + deduped + single-category by the generator).
func countArtifactHosts(a *urlcatfeed.ArtifactPayload) int {
	n := 0
	for i := range a.Categories {
		n += len(a.Categories[i].Hosts)
	}
	return n
}

// buildFeedGateSpec builds the generation spec from the CI environment (injected
// getenv for testability). CULVERT_FEED_GEN_GENERATED_AT (canonical RFC3339 UTC) is
// required and is the SINGLE captured instant that drives both feed_version and the
// timestamps. Dataset defaults to the approved embedded source; validity defaults to
// the normal 14-day window. There is NO force-version or downgrade input.
func buildFeedGateSpec(getenv func(string) string) (feedGenSpec, error) {
	dataset := getenv("CULVERT_FEED_GEN_DATASET")
	if dataset == "" {
		dataset = "internal/urlcat/default_categories.json"
	}
	genRaw := getenv("CULVERT_FEED_GEN_GENERATED_AT")
	if genRaw == "" {
		return feedGenSpec{}, fmt.Errorf("feed gen: CULVERT_FEED_GEN_GENERATED_AT is required")
	}
	genAt, err := time.Parse(time.RFC3339, genRaw)
	if err != nil {
		return feedGenSpec{}, fmt.Errorf("feed gen: CULVERT_FEED_GEN_GENERATED_AT %q: %w", genRaw, err)
	}
	spec := feedGenSpec{DatasetPath: dataset, GeneratedAt: genAt.UTC()}
	if hrs := getenv("CULVERT_FEED_GEN_VALIDITY_HRS"); hrs != "" {
		n, err := strconv.Atoi(hrs)
		if err != nil || n <= 0 {
			return feedGenSpec{}, fmt.Errorf("feed gen: CULVERT_FEED_GEN_VALIDITY_HRS %q invalid", hrs)
		}
		spec.Validity = time.Duration(n) * time.Hour
	}
	if pv := getenv("CULVERT_FEED_GEN_PREV_VERSION"); pv != "" {
		n, err := strconv.ParseInt(pv, 10, 64)
		if err != nil || n < 0 {
			return feedGenSpec{}, fmt.Errorf("feed gen: CULVERT_FEED_GEN_PREV_VERSION %q invalid", pv)
		}
		spec.PrevFeedVersion = n
	}
	return spec, nil
}

var _ = sort.Strings // reserved for future dataset-order normalization helpers
