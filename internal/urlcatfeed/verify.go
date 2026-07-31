package urlcatfeed

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// F2 — Sigstore keyless trust kernel.
//
// There is exactly ONE scheme (keyless Sigstore) and NO fallback: a missing or
// invalid signature is a rejection, never a downgrade to unsigned data. The
// verifier accepts RAW bytes and returns a COMPLETE verified object or no object
// — verify-before-parse means no manifest/artifact field is exposed before the
// signature over its exact bytes has passed. The verification pattern mirrors the
// release catalog's (offline: transparency-log + integrated timestamps, no
// wall-clock, no network) but this kernel is independent of the catalog and
// carries its OWN pinned identity.

const (
	// maxEnvelopeBytes bounds the single manifest envelope object; the manifest
	// payload it carries is tiny. The client downloader (F3) enforces read bounds
	// on the wire; this is a defensive in-memory cap.
	maxEnvelopeBytes = 1 << 20 // 1 MiB
)

// Distinct error kinds so callers/tests/alerting can tell a config error apart
// from a malformed artifact apart from an authenticity failure.
var (
	ErrConfig    = errors.New("urlcatfeed: verifier config")
	ErrMalformed = errors.New("urlcatfeed: malformed envelope/bundle")
	ErrOversize  = errors.New("urlcatfeed: input exceeds size bound")
	ErrVerify    = errors.New("urlcatfeed: signature verification failed")
	ErrPayload   = errors.New("urlcatfeed: payload failed validation")
	ErrBinding   = errors.New("urlcatfeed: artifact does not match manifest binding")
)

// Verifier verifies feed signatures against fixed trust material and a pinned
// identity. Immutable after construction; safe for concurrent use.
type Verifier struct {
	v  *verify.Verifier
	id verify.CertificateIdentity
}

// NewVerifierFromJSON builds a verifier from a Sigstore trusted-root JSON snapshot
// (the shared public-good root, supplied by value) and a pinned identity.
func NewVerifierFromJSON(trustedRootJSON []byte, id Identity) (*Verifier, error) {
	if len(bytes.TrimSpace(trustedRootJSON)) == 0 {
		return nil, fmt.Errorf("%w: empty trusted root", ErrConfig)
	}
	tm, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: trusted root: %v", ErrConfig, err)
	}
	return NewVerifierFromMaterial(tm, id)
}

// NewVerifierFromMaterial is the test-friendly core: production passes a parsed
// trusted root; tests pass a VirtualSigstore. Configured for OFFLINE keyless
// verification (transparency log + integrated timestamps, never wall-clock).
func NewVerifierFromMaterial(tm root.TrustedMaterial, id Identity) (*Verifier, error) {
	if strings.TrimSpace(id.Issuer) == "" || strings.TrimSpace(id.SANRegex) == "" {
		return nil, fmt.Errorf("%w: identity requires both issuer and san_regex", ErrConfig)
	}
	v, err := verify.NewVerifier(tm,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: build verifier: %v", ErrConfig, err)
	}
	// Exact issuer (issuerRegex empty), anchored SAN regex (sanValue empty).
	certID, err := verify.NewShortCertificateIdentity(id.Issuer, "", "", id.SANRegex)
	if err != nil {
		return nil, fmt.Errorf("%w: identity policy: %v", ErrConfig, err)
	}
	return &Verifier{v: v, id: certID}, nil
}

// verifyEntity is the crypto core: it proves the signed entity's Fulcio cert
// chains to the trusted root, matches the pinned issuer+SAN, carries a valid
// Rekor proof, and signs EXACTLY the given bytes. A different identity is
// rejected even if otherwise valid.
func (v *Verifier) verifyEntity(signed []byte, entity verify.SignedEntity) error {
	_, err := v.v.Verify(entity, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(signed)),
		verify.WithCertificateIdentity(v.id),
	))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrVerify, err)
	}
	return nil
}

// bundleEntity parses an UNTRUSTED cosign bundle JSON into a signed entity. The
// input is size-bounded; protojson.Unmarshal rejects unknown fields by default,
// so a non-bundle blob (even valid JSON) fails here rather than being accepted.
func bundleEntity(bundleJSON []byte) (verify.SignedEntity, error) {
	if len(bundleJSON) > MaxBundleBytes {
		return nil, fmt.Errorf("%w: bundle %d bytes", ErrOversize, len(bundleJSON))
	}
	pb := new(protobundle.Bundle)
	if err := protojson.Unmarshal(bundleJSON, pb); err != nil {
		return nil, fmt.Errorf("%w: bundle: %v", ErrMalformed, err)
	}
	b, err := sgbundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("%w: bundle: %v", ErrMalformed, err)
	}
	return b, nil
}

// VerifyEnvelope verifies the single self-contained manifest envelope and returns
// the trusted manifest payload. Verify-before-parse: it extracts only the two
// UNTRUSTED wrapper fields, verifies the bundle over the exact decoded payload
// bytes, and ONLY THEN parses/validates the manifest. A forged or unsigned
// envelope yields no manifest object (and, for the caller, drives zero artifact
// fetches).
func (v *Verifier) VerifyEnvelope(envelopeBytes []byte) (*ManifestPayload, error) {
	if len(envelopeBytes) > maxEnvelopeBytes {
		return nil, fmt.Errorf("%w: envelope %d bytes", ErrOversize, len(envelopeBytes))
	}
	// Untrusted outer wrapper: ONLY payload_b64 + bundle. No manifest field is
	// touched here. Strict decode = unknown fields, duplicate keys, and trailing
	// data all rejected (single value + EOF).
	var env Envelope
	if err := strictUnmarshal(envelopeBytes, &env); err != nil {
		return nil, fmt.Errorf("%w: envelope: %v", ErrMalformed, err)
	}
	if env.PayloadB64 == "" || len(env.Bundle) == 0 {
		return nil, fmt.Errorf("%w: envelope missing payload or bundle", ErrMalformed)
	}
	payload, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64: %v", ErrMalformed, err)
	}
	entity, err := bundleEntity(env.Bundle)
	if err != nil {
		return nil, err
	}
	return v.verifyManifest(payload, entity)
}

// verifyManifest verifies the signature over the raw payload bytes and, only on
// success, parses + validates the manifest. Exposed to tests so the crypto core
// can be driven with a VirtualSigstore entity.
func (v *Verifier) verifyManifest(payload []byte, entity verify.SignedEntity) (*ManifestPayload, error) {
	if err := v.verifyEntity(payload, entity); err != nil {
		return nil, err
	}
	return parseManifestPayload(payload)
}

// VerifyArtifact verifies the immutable artifact against its own bundle AND binds
// it to an already-verified manifest (size + digest + feed_version + counts). It
// independently re-runs the integrity rejection rules (§7.4) so a signed-but-
// colliding artifact is rejected as a whole candidate. Returns the trusted
// artifact payload or no object.
func (v *Verifier) VerifyArtifact(artifactBytes, bundleJSON []byte, manifest *ManifestPayload) (*ArtifactPayload, error) {
	entity, err := bundleEntity(bundleJSON)
	if err != nil {
		return nil, err
	}
	return v.verifyArtifactWithEntity(artifactBytes, entity, manifest)
}

// verifyArtifactWithEntity is the entity-path core for VerifyArtifact (tests pass
// a VirtualSigstore entity). Order: bind to the trusted manifest (size+digest),
// verify the signature, THEN parse (verify-before-parse), THEN integrity + cross-
// check.
func (v *Verifier) verifyArtifactWithEntity(artifactBytes []byte, entity verify.SignedEntity, manifest *ManifestPayload) (*ArtifactPayload, error) {
	if manifest == nil {
		return nil, fmt.Errorf("%w: nil manifest", ErrBinding)
	}
	if int64(len(artifactBytes)) != manifest.ArtifactSize {
		return nil, fmt.Errorf("%w: size %d != manifest %d", ErrBinding, len(artifactBytes), manifest.ArtifactSize)
	}
	sum := sha256.Sum256(artifactBytes)
	if hex.EncodeToString(sum[:]) != manifest.ArtifactSHA256 {
		return nil, fmt.Errorf("%w: sha256 mismatch", ErrBinding)
	}
	if err := v.verifyEntity(artifactBytes, entity); err != nil {
		return nil, err
	}
	art, hostCount, catCount, err := parseArtifactPayload(artifactBytes)
	if err != nil {
		return nil, err
	}
	if art.FeedVersion != manifest.FeedVersion {
		return nil, fmt.Errorf("%w: artifact feed_version %d != manifest %d", ErrBinding, art.FeedVersion, manifest.FeedVersion)
	}
	if art.GeneratedAt != manifest.GeneratedAt {
		return nil, fmt.Errorf("%w: artifact generated_at %q != manifest %q", ErrBinding, art.GeneratedAt, manifest.GeneratedAt)
	}
	if hostCount != manifest.HostCount || catCount != manifest.CategoryCount {
		return nil, fmt.Errorf("%w: counts artifact(%d hosts,%d cats) != manifest(%d,%d)",
			ErrBinding, hostCount, catCount, manifest.HostCount, manifest.CategoryCount)
	}
	return art, nil
}

// parseManifestPayload validates the manifest: strict decode (no unknown fields,
// no duplicate keys, no trailing data), CANONICAL byte-equality, canonical
// timestamps, the 30-day validity ceiling, and the producer's cross-field
// invariants (sig-path and artifact-path shape). It runs on
// signature-verified bytes; current-time freshness enforcement is the client
// slice (F0 §10), deliberately not done here.
func parseManifestPayload(b []byte) (*ManifestPayload, error) {
	var m ManifestPayload
	if err := strictUnmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrPayload, err)
	}
	if err := requireCanonical(b, &m); err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrPayload, err)
	}
	if m.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: schema_version %d", ErrPayload, m.SchemaVersion)
	}
	if m.Protocol != Protocol {
		return nil, fmt.Errorf("%w: protocol %q", ErrPayload, m.Protocol)
	}
	if m.Feed != FeedID {
		return nil, fmt.Errorf("%w: feed %q", ErrPayload, m.Feed)
	}
	if m.FeedVersion < 1 {
		return nil, fmt.Errorf("%w: feed_version %d", ErrPayload, m.FeedVersion)
	}
	if !safeRelKey(m.ArtifactPath) {
		return nil, fmt.Errorf("%w: artifact_path %q", ErrPayload, m.ArtifactPath)
	}
	if m.ArtifactSigPath != m.ArtifactPath+".sigstore" {
		return nil, fmt.Errorf("%w: artifact_sig_path %q != %q", ErrPayload, m.ArtifactSigPath, m.ArtifactPath+".sigstore")
	}
	if !isSHA256Hex(m.ArtifactSHA256) {
		return nil, fmt.Errorf("%w: artifact_sha256 %q", ErrPayload, m.ArtifactSHA256)
	}
	if m.ArtifactSize <= 0 || m.ArtifactSize > MaxArtifactSize {
		return nil, fmt.Errorf("%w: artifact_size %d", ErrPayload, m.ArtifactSize)
	}
	if m.CategoryCount < 0 || m.HostCount < 0 {
		return nil, fmt.Errorf("%w: negative counts", ErrPayload)
	}
	gen, err := parseCanonicalRFC3339(m.GeneratedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: generated_at %q: %v", ErrPayload, m.GeneratedAt, err)
	}
	exp, err := parseCanonicalRFC3339(m.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: expires_at %q: %v", ErrPayload, m.ExpiresAt, err)
	}
	if !exp.After(gen) {
		return nil, fmt.Errorf("%w: expires_at not after generated_at", ErrPayload)
	}
	if exp.Sub(gen) > MaxValidity {
		return nil, fmt.Errorf("%w: validity window %s exceeds %s", ErrPayload, exp.Sub(gen), MaxValidity)
	}
	// Artifact-path shape is a producer invariant: saas-<8-pad version>-<UTC date>.json.
	wantPath := fmt.Sprintf("saas-%08d-%s.json", m.FeedVersion, gen.Format("20060102"))
	if m.ArtifactPath != wantPath {
		return nil, fmt.Errorf("%w: artifact_path %q != expected %q", ErrPayload, m.ArtifactPath, wantPath)
	}
	return &m, nil
}

// parseCanonicalRFC3339 parses s and requires it to already be in the canonical
// form the producer emits: UTC, whole seconds, "Z" offset. A same-instant string
// with a numeric offset or fractional seconds re-formats differently and is
// rejected, so a signed payload cannot smuggle a non-canonical timestamp.
func parseCanonicalRFC3339(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	if t.UTC().Format(time.RFC3339) != s {
		return time.Time{}, fmt.Errorf("non-canonical timestamp %q", s)
	}
	return t.UTC(), nil
}

// parseArtifactPayload validates the artifact and returns recomputed counts. It
// accepts the artifact ONLY if it is already in the EXACT canonical form the
// producer emits: strict + canonical bytes, canonical UTC timestamp, canonical
// category names, strictly-ascending (deduplicated) category rows and host rows,
// already-normalized hosts, no empty-host category, and no multi-category or
// ancestor/descendant suffix collision. A signed-but-non-canonical or colliding
// artifact is rejected as a WHOLE candidate (§7.4) — no winner is picked.
func parseArtifactPayload(b []byte) (art *ArtifactPayload, hostCount, catCount int, err error) {
	var a ArtifactPayload
	if e := strictUnmarshal(b, &a); e != nil {
		return nil, 0, 0, fmt.Errorf("%w: artifact: %v", ErrPayload, e)
	}
	if e := requireCanonical(b, &a); e != nil {
		return nil, 0, 0, fmt.Errorf("%w: artifact: %v", ErrPayload, e)
	}
	if a.SchemaVersion != SchemaVersion {
		return nil, 0, 0, fmt.Errorf("%w: schema_version %d", ErrPayload, a.SchemaVersion)
	}
	if a.Protocol != Protocol {
		return nil, 0, 0, fmt.Errorf("%w: protocol %q", ErrPayload, a.Protocol)
	}
	if a.Feed != FeedID {
		return nil, 0, 0, fmt.Errorf("%w: feed %q", ErrPayload, a.Feed)
	}
	if a.FeedVersion < 1 {
		return nil, 0, 0, fmt.Errorf("%w: feed_version %d", ErrPayload, a.FeedVersion)
	}
	if _, e := parseCanonicalRFC3339(a.GeneratedAt); e != nil {
		return nil, 0, 0, fmt.Errorf("%w: generated_at %q: %v", ErrPayload, a.GeneratedAt, e)
	}
	if len(a.Categories) == 0 {
		return nil, 0, 0, fmt.Errorf("%w: no categories", ErrPayload)
	}
	// Structural canonicality: rows and hosts must be strictly ascending (which
	// also rejects duplicate rows / duplicate hosts), names canonical, hosts
	// already-normalized, no empty-host category.
	src := make([]SourceCategory, 0, len(a.Categories))
	prevCat := ""
	for ci := range a.Categories {
		c := a.Categories[ci]
		name, e := CanonicalCategoryName(c.Name)
		if e != nil {
			return nil, 0, 0, fmt.Errorf("%w: category: %v", ErrPayload, e)
		}
		if name != c.Name {
			return nil, 0, 0, fmt.Errorf("%w: non-canonical category name %q", ErrPayload, c.Name)
		}
		if ci > 0 && !(prevCat < name) {
			return nil, 0, 0, fmt.Errorf("%w: category rows not strictly sorted at %q", ErrPayload, name)
		}
		prevCat = name
		if len(c.Hosts) == 0 {
			return nil, 0, 0, fmt.Errorf("%w: %v: %q", ErrPayload, ErrEmptyCategoryHost, name)
		}
		prevHost := ""
		for hi, h := range c.Hosts {
			canonHost, e := NormalizeHost(h)
			if e != nil {
				return nil, 0, 0, fmt.Errorf("%w: %v", ErrPayload, e)
			}
			if canonHost != h {
				return nil, 0, 0, fmt.Errorf("%w: non-canonical host %q (want %q)", ErrPayload, h, canonHost)
			}
			if hi > 0 && !(prevHost < h) {
				return nil, 0, 0, fmt.Errorf("%w: hosts not strictly sorted in %q at %q", ErrPayload, name, h)
			}
			prevHost = h
		}
		src = append(src, SourceCategory{Name: c.Name, Hosts: c.Hosts})
	}
	ha, e := assignHosts(src)
	if e != nil {
		return nil, 0, 0, fmt.Errorf("%w: %v", ErrPayload, e)
	}
	return &a, len(ha.catOf), len(a.Categories), nil
}

// safeRelKey accepts a single safe relative object key: one path segment,
// [A-Za-z0-9._-] only, no "..", no separators.
func safeRelKey(k string) bool {
	if k == "" || len(k) > 255 || strings.Contains(k, "..") {
		return false
	}
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// isSHA256Hex reports whether s is exactly 64 lowercase hex digits.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
