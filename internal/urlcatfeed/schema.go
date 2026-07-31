// Package urlcatfeed is the producer + trust kernel for the public, signed
// SaaS URL-category feed distributed from feeds.culvertlabs.com
// (roadmap/FEEDS-DISTRIBUTION-F0-DESIGN.md). It ships two topology-independent
// halves:
//
//   - F1 — a DETERMINISTIC generator: it takes an approved source dataset and
//     emits the exact, canonical, normalized signed-artifact bytes and the
//     signed-manifest payload bytes. Given semantically identical input it emits
//     byte-identical output regardless of map order, source ordering, locale,
//     timezone, or repeated execution (generate.go, normalize.go).
//   - F2 — a Sigstore KEYLESS trust kernel: it verifies a self-contained signed
//     manifest ENVELOPE and the immutable artifact bundle OFFLINE against a
//     shared Sigstore trusted root plus a PINNED, feed-specific workflow identity
//     (verify.go, identity.go). Verify-before-parse: no manifest field is ever
//     returned before the signature over its exact bytes has passed.
//
// This package holds NO private key, embeds NO trusted root (the root is supplied
// by the caller so the SAME baked public-good root the release catalog uses can
// be reused by value), reaches NO network, and is independent of the CP/DP
// topology, the on-disk activation model, migration, and the client downloader —
// all of which are later, separately-gated slices (F3+). It NEVER imports or
// alters the release-catalog trust path; the feed identity is its own pin.
package urlcatfeed

import (
	"encoding/json"
	"time"
)

// Wire constants. These are bound INSIDE the signed bytes and re-checked on
// verify, so a manifest/artifact for a different schema, protocol, or feed is
// rejected even if correctly signed.
const (
	// SchemaVersion is the only supported major schema. An unknown value is
	// rejected (fail-closed), never coerced.
	SchemaVersion = 1

	// Protocol is the ONLY supported feed protocol. There is no unsigned mode
	// and no fallback (F0 §13) — this string is asserted on both sides.
	Protocol = "signed_manifest_v1"

	// FeedID is the canonical identifier for this feed. A manifest/artifact
	// whose "feed" differs is rejected (cross-feed substitution guard).
	FeedID = "url-categories/saas"
)

// Protocol ceilings (Finding 3 / additional hardening). MaxValidity is the HARD
// producer + structural-verify ceiling on a signed manifest's validity window
// (expires_at - generated_at). It is defense-in-depth, distinct from the normal
// 14-day publisher value (F5) and from the client's current-time freshness /
// checkpoint enforcement (F3b). MaxArtifactBytes / MaxBundleBytes bound the
// in-memory inputs the verifier will accept; the F3 downloader MUST enforce the
// same read bounds on the wire as a precondition.
const (
	MaxValidity     = 30 * 24 * time.Hour // 30 days
	MaxArtifactSize = 8 << 20             // 8 MiB — manifest.artifact_size ceiling
	MaxBundleBytes  = 1 << 20             // 1 MiB — cosign bundle ceiling
)

// Category-name contract bounds (Finding 4).
const (
	MaxCategoryNameCodePoints = 64
	MaxCategoryNameBytes      = 255
)

// SourceCategory is one category of the APPROVED input dataset: a display name
// and its raw (un-normalized) host list.
type SourceCategory struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

// SourceDataset is the approved input to the generator.
type SourceDataset struct {
	Categories []SourceCategory `json:"categories"`
}

// ArtifactCategory is one category in the generated, normalized artifact: hosts
// are normalized, deduplicated, and sorted.
type ArtifactCategory struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

// ArtifactPayload is the immutable, deterministically-generated artifact. Its
// bytes are digest-bound by the manifest and signed by their own bundle.
type ArtifactPayload struct {
	SchemaVersion int                `json:"schema_version"`
	Protocol      string             `json:"protocol"`
	Feed          string             `json:"feed"`
	FeedVersion   int64              `json:"feed_version"`
	GeneratedAt   string             `json:"generated_at"`
	Categories    []ArtifactCategory `json:"categories"`
}

// ManifestPayload is the small pointer document. Its exact bytes are what the
// manifest envelope's Sigstore bundle signs; it binds the artifact by digest.
type ManifestPayload struct {
	SchemaVersion   int    `json:"schema_version"`
	Protocol        string `json:"protocol"`
	Feed            string `json:"feed"`
	FeedVersion     int64  `json:"feed_version"`
	GeneratedAt     string `json:"generated_at"`
	ExpiresAt       string `json:"expires_at"`
	ArtifactPath    string `json:"artifact_path"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	ArtifactSize    int64  `json:"artifact_size"`
	ArtifactSigPath string `json:"artifact_sig_path"`
	CategoryCount   int    `json:"category_count"`
	HostCount       int    `json:"host_count"`
}

// Envelope is the SINGLE self-contained mutable object served at
// manifest.sigstore.json (F0 §4.2, B6): the exact manifest-payload bytes
// (base64) plus the cosign keyless bundle over those exact bytes. The client
// fetches ONE object, so there is no manifest/bundle observation race. The
// outer wrapper is UNTRUSTED — only PayloadB64's decoded bytes, once their
// bundle verifies, become trusted.
type Envelope struct {
	PayloadB64 string          `json:"payload_b64"`
	Bundle     json.RawMessage `json:"bundle"`
}
