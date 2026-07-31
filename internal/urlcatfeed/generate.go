package urlcatfeed

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// F1 — deterministic generator. Produces the exact canonical bytes the F2
// verifier and the (later) client consume. Determinism is load-bearing: the CI
// signer hashes and signs these RAW bytes, so identical semantic input MUST
// yield identical output regardless of input ordering, map iteration order,
// locale, or timezone.

var (
	ErrVersion     = errors.New("urlcatfeed: feed_version must be >= 1 and strictly greater than the previous version")
	ErrExpiry      = errors.New("urlcatfeed: expires_at must be after generated_at (whole-second UTC)")
	ErrNoCats      = errors.New("urlcatfeed: dataset has no categories with hosts")
	ErrEnvelope    = errors.New("urlcatfeed: envelope assembly failed")
	ErrZeroTime    = errors.New("urlcatfeed: generated_at/expires_at must be non-zero")
	ErrMaxValidity = errors.New("urlcatfeed: validity window exceeds the protocol maximum (30d)")
)

// GenerateInput is the full, explicit input to Generate. Timestamps are supplied
// by the caller (never read from the clock here) so generation stays pure and
// deterministic.
type GenerateInput struct {
	Source          SourceDataset
	FeedVersion     int64     // monotonic; must be >= 1
	PrevFeedVersion int64     // 0 = none; FeedVersion must be strictly greater
	GeneratedAt     time.Time // formatted RFC3339 UTC
	ExpiresAt       time.Time // must be after GeneratedAt
}

// GenerateResult carries the produced bytes and their bindings.
type GenerateResult struct {
	ArtifactPath    string
	ArtifactSigPath string
	ArtifactBytes   []byte // canonical artifact JSON (signed by its own bundle)
	ArtifactSHA256  string // hex digest of ArtifactBytes
	ManifestBytes   []byte // canonical manifest-payload JSON (signed by the envelope bundle)
	Manifest        ManifestPayload
	HostCount       int
	CategoryCount   int
}

// Generate deterministically builds the normalized artifact and the manifest
// payload from an approved source dataset. It rejects the WHOLE input on any
// normalization or integrity violation (§7.4/§7.5) — it never emits a partial
// or ambiguous feed.
func Generate(in GenerateInput) (*GenerateResult, error) {
	if in.FeedVersion < 1 || in.FeedVersion <= in.PrevFeedVersion {
		return nil, fmt.Errorf("%w: got %d (prev %d)", ErrVersion, in.FeedVersion, in.PrevFeedVersion)
	}
	if in.GeneratedAt.IsZero() || in.ExpiresAt.IsZero() {
		return nil, ErrZeroTime
	}
	// Canonical timestamps: UTC, whole seconds. Truncate BEFORE the ordering and
	// window checks so validation runs on the EXACT values that will be serialized
	// — a sub-second-only gap that would collapse to a single RFC3339 second (and
	// make the emitted manifest fail its own parse) is rejected here (Finding 2).
	genT := in.GeneratedAt.UTC().Truncate(time.Second)
	expT := in.ExpiresAt.UTC().Truncate(time.Second)
	if !expT.After(genT) {
		return nil, fmt.Errorf("%w: generated=%s expires=%s", ErrExpiry,
			genT.Format(time.RFC3339), expT.Format(time.RFC3339))
	}
	if expT.Sub(genT) > MaxValidity {
		return nil, fmt.Errorf("%w: window=%s", ErrMaxValidity, expT.Sub(genT))
	}

	ha, err := assignHosts(in.Source.Categories)
	if err != nil {
		return nil, err
	}
	if len(ha.catOf) == 0 {
		return nil, ErrNoCats
	}

	genAt := genT.Format(time.RFC3339)
	cats := groupSorted(ha)

	artifact := ArtifactPayload{
		SchemaVersion: SchemaVersion,
		Protocol:      Protocol,
		Feed:          FeedID,
		FeedVersion:   in.FeedVersion,
		GeneratedAt:   genAt,
		Categories:    cats,
	}
	artBytes, err := canonicalJSON(artifact)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(artBytes)
	digest := hex.EncodeToString(sum[:])

	artPath := fmt.Sprintf("saas-%08d-%s.json", in.FeedVersion, genT.Format("20060102"))
	sigPath := artPath + ".sigstore"

	manifest := ManifestPayload{
		SchemaVersion:   SchemaVersion,
		Protocol:        Protocol,
		Feed:            FeedID,
		FeedVersion:     in.FeedVersion,
		GeneratedAt:     genAt,
		ExpiresAt:       expT.Format(time.RFC3339),
		ArtifactPath:    artPath,
		ArtifactSHA256:  digest,
		ArtifactSize:    int64(len(artBytes)),
		ArtifactSigPath: sigPath,
		CategoryCount:   len(cats),
		HostCount:       len(ha.catOf),
	}
	manBytes, err := canonicalJSON(manifest)
	if err != nil {
		return nil, err
	}

	return &GenerateResult{
		ArtifactPath:    artPath,
		ArtifactSigPath: sigPath,
		ArtifactBytes:   artBytes,
		ArtifactSHA256:  digest,
		ManifestBytes:   manBytes,
		Manifest:        manifest,
		HostCount:       len(ha.catOf),
		CategoryCount:   len(cats),
	}, nil
}

// groupSorted turns the host→category assignment into sorted categories with
// sorted, deduplicated hosts. Deterministic: categories sorted by display name,
// hosts sorted lexicographically.
func groupSorted(ha *hostAssignments) []ArtifactCategory {
	byCat := make(map[string][]string)
	for host, cat := range ha.catOf {
		byCat[cat] = append(byCat[cat], host)
	}
	names := make([]string, 0, len(byCat))
	for name := range byCat {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ArtifactCategory, 0, len(names))
	for _, name := range names {
		hosts := byCat[name]
		sort.Strings(hosts)
		out = append(out, ArtifactCategory{Name: name, Hosts: hosts})
	}
	return out
}

// AssembleEnvelope builds the single self-contained manifest envelope object
// from the EXACT manifest-payload bytes and the cosign bundle produced over those
// same bytes (F0 §4.2). payload_b64 is standard base64 of manifestBytes, so the
// verifier decodes back to the exact bytes the bundle signed.
//
// Hardening: the payload must be a CANONICAL, structurally-valid manifest (not
// merely non-empty), and the bundle must parse as a real cosign bundle (not any
// valid JSON) — so a producer defect can never wrap a malformed manifest or a
// non-bundle blob into a shippable envelope.
func AssembleEnvelope(manifestBytes, bundleJSON []byte) ([]byte, error) {
	if _, err := parseManifestPayload(manifestBytes); err != nil {
		return nil, fmt.Errorf("%w: payload is not a canonical manifest: %v", ErrEnvelope, err)
	}
	if len(bundleJSON) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: bundle exceeds %d bytes", ErrEnvelope, MaxBundleBytes)
	}
	if _, err := bundleEntity(bundleJSON); err != nil {
		return nil, fmt.Errorf("%w: bundle is not a valid cosign bundle: %v", ErrEnvelope, err)
	}
	env := Envelope{
		PayloadB64: base64.StdEncoding.EncodeToString(manifestBytes),
		Bundle:     json.RawMessage(bundleJSON),
	}
	out, err := canonicalJSON(&env)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelope, err)
	}
	return out, nil
}
