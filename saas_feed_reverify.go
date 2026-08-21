package main

// saas_feed_reverify.go — F3b-3: OFFLINE full re-verification of a committed immutable
// generation from its signed durable bytes (§B.9 Option 1).
//
// Both the activation coordinator (before committing) and startup/crash recovery
// re-verify the exact generation they are about to serve — never trusting a filename,
// directory order, mtime, or a bare version number. Verification is entirely offline
// (no network request): it reads the five immutable files F3b-2 committed, runs the full
// F0 §6 signature verification via the pinned trust kernel, re-derives every digest, and
// re-asserts the metadata + normalized-snapshot bindings. Any mismatch rejects the WHOLE
// generation (no partial trust). The caller supplies the generation id from a durable
// record (activation record or a valid floor record) — this file locates only
// generations/<id>/ and nothing else.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// maxGenerationMetaBytes bounds the generation.json read (the record is ~400 bytes).
const maxGenerationMetaBytes = 64 << 10

var (
	errReverifyRead     = errors.New("saas feed reverify: cannot read generation file")
	errReverifyVerify   = errors.New("saas feed reverify: signature verification failed")
	errReverifyMeta     = errors.New("saas feed reverify: generation metadata invalid or inconsistent")
	errReverifySnapshot = errors.New("saas feed reverify: normalized snapshot is not the canonical projection of the verified artifact")
	errReverifyBinding  = errors.New("saas feed reverify: candidate does not match the requested identity binding")
	errReverifyID       = errors.New("saas feed reverify: invalid generation id")
)

// reverifiedGeneration is the trusted result of an offline re-verification: the verified
// payloads, the on-disk digests, and the feed-owned host→category snapshot map ready for
// override composition. It carries NO freshness verdict — the caller applies current-time
// freshness against an injected clock (recovery/activation), never this function.
type reverifiedGeneration struct {
	Version        int64
	GenerationID   string
	Dir            string
	ManifestSHA256 string
	ArtifactSHA256 string
	SnapshotSHA256 string
	GeneratedAt    string
	ExpiresAt      string
	Manifest       *urlcatfeed.ManifestPayload
	Artifact       *urlcatfeed.ArtifactPayload
	// SnapshotEntries is the feed-owned normalized host→category view (from the verified
	// artifact) that catoverride.ComposeView folds the admin overrides onto.
	SnapshotEntries map[string]string
	EnvelopeBytes   []byte // retained so a resume can re-derive/rebind without a second read
}

// reverifyReader is the injectable read seam (production: os.ReadFile; tests inject
// per-file failures for the crash matrix).
type reverifyReader func(path string) ([]byte, error)

// reverifyGeneration fully re-verifies generations/<generationID>/ offline. `bind`, when
// non-nil, additionally requires the re-derived (generation_id, manifest_sha256,
// artifact_sha256) to equal the durable record's binding — so a floor-ahead resume
// accepts ONLY the exact generation the record names (§B.9), never a same-numbered
// impostor.
func reverifyGeneration(read reverifyReader, v feedVerifier, root, generationID string, bind *generationBinding) (*reverifiedGeneration, error) {
	if !validGenerationID(generationID) {
		return nil, fmt.Errorf("%w: %q", errReverifyID, generationID)
	}
	dir := filepath.Join(root, generationID)

	files, err := readGenerationFiles(read, dir)
	if err != nil {
		return nil, err
	}

	// Verify-before-parse: the signatures over the exact stored bytes, then bind.
	manifest, err := v.VerifyEnvelope(files.envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: envelope: %v", errReverifyVerify, err)
	}
	if manifest == nil {
		return nil, fmt.Errorf("%w: nil manifest", errReverifyVerify)
	}
	artifact, err := v.VerifyArtifact(files.artifact, files.bundle, manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact: %v", errReverifyVerify, err)
	}
	if artifact == nil {
		return nil, fmt.Errorf("%w: nil artifact", errReverifyVerify)
	}

	manifestDigest := sha256Hex(files.envelope)
	snapshotDigest := sha256Hex(files.snapshot)

	// The generation directory name must equal the verified feed version.
	if generationID != strconv.FormatInt(manifest.FeedVersion, 10) {
		return nil, fmt.Errorf("%w: dir %q != feed_version %d", errReverifyMeta, generationID, manifest.FeedVersion)
	}
	// Re-derive + re-assert the metadata record and the normalized snapshot.
	if err := checkGenerationMeta(files.meta, manifest, manifestDigest, snapshotDigest, generationID); err != nil {
		return nil, err
	}
	if err := checkNormalizedSnapshot(files.snapshot, artifact); err != nil {
		return nil, err
	}
	// Optional exact-identity binding (floor-ahead resume): the record's bound digests.
	if err := checkBinding(bind, generationID, manifestDigest, manifest.ArtifactSHA256); err != nil {
		return nil, err
	}

	return &reverifiedGeneration{
		Version:         manifest.FeedVersion,
		GenerationID:    generationID,
		Dir:             dir,
		ManifestSHA256:  manifestDigest,
		ArtifactSHA256:  manifest.ArtifactSHA256,
		SnapshotSHA256:  snapshotDigest,
		GeneratedAt:     manifest.GeneratedAt,
		ExpiresAt:       manifest.ExpiresAt,
		Manifest:        manifest,
		Artifact:        artifact,
		SnapshotEntries: artifactToHostCategoryMap(artifact),
		EnvelopeBytes:   files.envelope,
	}, nil
}

// generationFiles holds the five immutable payloads F3b-2 committed for a generation.
type generationFiles struct {
	envelope []byte
	artifact []byte
	bundle   []byte
	snapshot []byte
	meta     []byte
}

// readGenerationFiles bounded-reads the five immutable files of generations/<id>/ (any
// read/empty/over-limit failure rejects the whole generation).
func readGenerationFiles(read reverifyReader, dir string) (generationFiles, error) {
	var f generationFiles
	var err error
	if f.envelope, err = readGenFileBounded(read, dir, genFileManifestEnvelope, urlcatfeed.MaxBundleBytes); err != nil {
		return generationFiles{}, err
	}
	if f.artifact, err = readGenFileBounded(read, dir, genFileArtifact, urlcatfeed.MaxArtifactSize); err != nil {
		return generationFiles{}, err
	}
	if f.bundle, err = readGenFileBounded(read, dir, genFileArtifactBundle, urlcatfeed.MaxBundleBytes); err != nil {
		return generationFiles{}, err
	}
	if f.snapshot, err = readGenFileBounded(read, dir, genFileSnapshotNormalized, urlcatfeed.MaxArtifactSize); err != nil {
		return generationFiles{}, err
	}
	if f.meta, err = readGenFileBounded(read, dir, genFileMeta, maxGenerationMetaBytes); err != nil {
		return generationFiles{}, err
	}
	return f, nil
}

// checkBinding enforces the optional exact-identity binding (floor-ahead resume): the
// re-derived (generation_id, manifest_sha256, artifact_sha256) must equal the durable
// record's binding, so a same-numbered impostor is rejected (§B.9). nil bind ⇒ no-op.
func checkBinding(bind *generationBinding, generationID, manifestDigest, artifactDigest string) error {
	if bind == nil {
		return nil
	}
	if generationID != bind.GenerationID || manifestDigest != bind.ManifestSHA256 || artifactDigest != bind.ArtifactSHA256 {
		return fmt.Errorf("%w: id/digest mismatch", errReverifyBinding)
	}
	return nil
}

// generationBinding is the exact-identity binding a durable record carries (used by a
// floor-ahead resume to demand the precise generation, not just its version).
type generationBinding struct {
	GenerationID   string
	ManifestSHA256 string
	ArtifactSHA256 string
}

// checkGenerationMeta strictly decodes generation.json and asserts it binds the same
// version, digests, counts, and constants the verified manifest carries.
func checkGenerationMeta(metaBytes []byte, m *urlcatfeed.ManifestPayload, manifestDigest, snapshotDigest, generationID string) error {
	var meta generationMeta
	if err := strictDecodeGenerationMeta(metaBytes, &meta); err != nil {
		return fmt.Errorf("%w: decode: %v", errReverifyMeta, err)
	}
	// Canonical byte-equality: the stored record must be exactly the canonical encoding
	// (rejects reordering / whitespace / duplicate keys / alternate encodings).
	canon, err := floorCanonicalBytes(meta)
	if err != nil {
		return err
	}
	if !bytes.Equal(canon, metaBytes) {
		return fmt.Errorf("%w: non-canonical", errReverifyMeta)
	}
	if !metaBindsManifest(meta, m, manifestDigest, generationID) {
		return fmt.Errorf("%w: metadata does not bind the verified generation", errReverifyMeta)
	}
	_ = snapshotDigest // snapshot digest is bound by checkNormalizedSnapshot (byte-exact), not by the meta record
	return nil
}

// metaBindsManifest reports whether the stored generation.json binds exactly the same
// schema/protocol/feed constants, version, digests, counts, and timestamps the verified
// manifest carries.
func metaBindsManifest(meta generationMeta, m *urlcatfeed.ManifestPayload, manifestDigest, generationID string) bool {
	return meta.SchemaVersion == genMetaSchemaVersion &&
		meta.Protocol == urlcatfeed.Protocol && meta.Feed == urlcatfeed.FeedID &&
		meta.FeedVersion == m.FeedVersion && meta.GenerationID == generationID &&
		meta.ManifestSHA256 == manifestDigest && meta.ArtifactSHA256 == m.ArtifactSHA256 &&
		meta.ArtifactSize == m.ArtifactSize &&
		meta.CategoryCount == m.CategoryCount && meta.HostCount == m.HostCount &&
		meta.GeneratedAt == m.GeneratedAt && meta.ExpiresAt == m.ExpiresAt
}

// checkNormalizedSnapshot asserts snapshot.normalized.json is EXACTLY the canonical
// projection of the verified artifact (the same derivation F3b-2 persisted), so a tampered
// or stale snapshot cannot ride along inside an otherwise-valid generation.
func checkNormalizedSnapshot(snapshot []byte, a *urlcatfeed.ArtifactPayload) error {
	want, err := normalizedSnapshotBytes(a)
	if err != nil {
		return err
	}
	if !bytes.Equal(want, snapshot) {
		return fmt.Errorf("%w", errReverifySnapshot)
	}
	return nil
}

// artifactToHostCategoryMap flattens a verified artifact's categories into a normalized
// host→category map (the feed-owned layer catoverride.ComposeView consumes). The artifact
// hosts are already normalized + de-duplicated + within a single category (kernel-enforced),
// so there is no ambiguity.
func artifactToHostCategoryMap(a *urlcatfeed.ArtifactPayload) map[string]string {
	out := make(map[string]string)
	for i := range a.Categories {
		for _, h := range a.Categories[i].Hosts {
			out[h] = a.Categories[i].Name
		}
	}
	return out
}

// strictDecodeGenerationMeta decodes generation.json with unknown fields disallowed and
// no trailing data (defense-in-depth over the canonical byte-equality check).
func strictDecodeGenerationMeta(data []byte, meta *generationMeta) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(meta); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// readGenFileBounded reads dir/name and rejects an empty or over-limit file.
func readGenFileBounded(read reverifyReader, dir, name string, limit int64) ([]byte, error) {
	b, err := read(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errReverifyRead, name, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: %s empty", errReverifyRead, name)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s %d > %d", errReverifyRead, name, len(b), limit)
	}
	return b, nil
}

// osReverifyReader is the production reader.
func osReverifyReader(path string) ([]byte, error) {
	return os.ReadFile(path) // #nosec G304 -- fixed constructed paths under the generations root
}
