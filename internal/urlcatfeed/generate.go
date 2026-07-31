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
	ErrVersion  = errors.New("urlcatfeed: feed_version must be >= 1 and strictly greater than the previous version")
	ErrExpiry   = errors.New("urlcatfeed: expires_at must be after generated_at")
	ErrNoCats   = errors.New("urlcatfeed: dataset has no categories with hosts")
	ErrEnvelope = errors.New("urlcatfeed: envelope assembly failed")
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
	if !in.ExpiresAt.After(in.GeneratedAt) {
		return nil, fmt.Errorf("%w: generated=%s expires=%s", ErrExpiry,
			in.GeneratedAt.UTC().Format(time.RFC3339), in.ExpiresAt.UTC().Format(time.RFC3339))
	}

	ha, err := assignHosts(in.Source.Categories)
	if err != nil {
		return nil, err
	}
	if len(ha.catOf) == 0 {
		return nil, ErrNoCats
	}

	genAt := in.GeneratedAt.UTC().Format(time.RFC3339)
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

	artPath := fmt.Sprintf("saas-%08d-%s.json", in.FeedVersion, in.GeneratedAt.UTC().Format("20060102"))
	sigPath := artPath + ".sigstore"

	manifest := ManifestPayload{
		SchemaVersion:   SchemaVersion,
		Protocol:        Protocol,
		Feed:            FeedID,
		FeedVersion:     in.FeedVersion,
		GeneratedAt:     genAt,
		ExpiresAt:       in.ExpiresAt.UTC().Format(time.RFC3339),
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

// canonicalJSON marshals with a deterministic, HTML-escape-free encoder. The
// input types use structs with pre-sorted slices and NO maps, so field and
// element order are fixed — the bytes are stable across runs and platforms.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("urlcatfeed: marshal: %w", err)
	}
	return b, nil
}

// AssembleEnvelope builds the single self-contained manifest envelope object
// from the EXACT manifest-payload bytes and the cosign bundle produced over those
// same bytes (F0 §4.2). payload_b64 is standard base64 of manifestBytes, so the
// verifier decodes back to the exact bytes the bundle signed.
func AssembleEnvelope(manifestBytes, bundleJSON []byte) ([]byte, error) {
	if len(manifestBytes) == 0 {
		return nil, fmt.Errorf("%w: empty manifest payload", ErrEnvelope)
	}
	if !json.Valid(bundleJSON) {
		return nil, fmt.Errorf("%w: bundle is not valid JSON", ErrEnvelope)
	}
	env := Envelope{
		PayloadB64: base64.StdEncoding.EncodeToString(manifestBytes),
		Bundle:     json.RawMessage(bundleJSON),
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEnvelope, err)
	}
	return out, nil
}
