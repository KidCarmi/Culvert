package main

// saas_feed_activation.go — F3b-3: the durable ACTIVE-GENERATION authority record
// (activation-state.json) + its canonical codec and single-record store.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §B.4 (on-disk contract —
// "activation-state.json ← ACTIVE-GENERATION authority (points at one generation) + a
// copy of the floor record"), §B.5 S4 (the active-gen commit), §B.7 (record-driven
// content selection — the activation record selects served content only after the
// referenced generation fully re-verifies), §B.12 (invariants). This file owns ONLY
// the record schema/codec/store; re-verification, recovery precedence, the live
// cutover, and GC live in their own F3b-3 files.
//
// The record mirrors the F3b-1 floor record's hardening EXACTLY (canonical byte-stable
// encoding, CRC-32/Castagnoli corruption detection — NOT authenticity, strict bounded
// decode, atomic write + read-back). Authenticity of the served feed content comes
// solely from the Sigstore signatures over the stored generation bytes, which
// activation/recovery re-verify (§B.9) — the CRC only tells honest recovery "this
// record is intact vs. bit-rotted".
//
// It binds a COPY of the rollback floor (concern 1) alongside the active generation
// (concern 2), so the floor survives even if both floor.a/floor.b are lost — the
// activation-record floor copy is a THIRD max input to selectFloor (§B.4/§B.6).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// ─── constants ──────────────────────────────────────────────────────────────────

const (
	// activationSchemaVersion is the only supported activation-record schema.
	activationSchemaVersion = 1

	// activationFile is the FIXED record filename (§B.4). Recovery reads ONLY this
	// path — never a directory scan, never mtime.
	activationFile = "activation-state.json"

	// maxActivationRecordBytes bounds decoder input. The record is ~600 bytes; 8 KiB is
	// generous headroom while capping a corrupt/hostile file.
	maxActivationRecordBytes = 8192

	activationFilePerm os.FileMode = 0o600
)

// activationProvenance labels HOW a generation became active (surfaced read-only for
// F3b-4; not a trust input). "embedded" is never written to an activation record — it
// is the recovery fallback when NO generation activates.
const (
	activationProvenanceDownloaded = "downloaded" // fresh network activation (F3b-2 acquire → activate)
	activationProvenanceResumed    = "resumed"    // floor-ahead crash-recovery completion (§B.9)
	activationProvenanceCached     = "cached"     // restart re-activation of the committed active generation (LKG)
)

func validActivationProvenance(p string) bool {
	switch p {
	case activationProvenanceDownloaded, activationProvenanceResumed, activationProvenanceCached:
		return true
	default:
		return false
	}
}

// ─── structured errors ───────────────────────────────────────────────────────────

var (
	errActEmpty        = errors.New("saas feed activation: empty record")
	errActOversize     = errors.New("saas feed activation: record exceeds max size")
	errActTrailing     = errors.New("saas feed activation: trailing data after record")
	errActNoncanonical = errors.New("saas feed activation: record is not in canonical form")
	errActSchema       = errors.New("saas feed activation: unsupported schema_version")
	errActProtocol     = errors.New("saas feed activation: protocol mismatch")
	errActFeed         = errors.New("saas feed activation: feed mismatch")
	errActVersion      = errors.New("saas feed activation: invalid active_feed_version")
	errActGenerationID = errors.New("saas feed activation: unsafe or inconsistent generation_id")
	errActTime         = errors.New("saas feed activation: non-canonical timestamp")
	errActDigest       = errors.New("saas feed activation: invalid sha-256 digest")
	errActETag         = errors.New("saas feed activation: malformed etag")
	errActFloor        = errors.New("saas feed activation: invalid floor copy")
	errActProvenance   = errors.New("saas feed activation: invalid provenance")
	errActConfigRev    = errors.New("saas feed activation: invalid config revision")
	errActCRC          = errors.New("saas feed activation: crc32c corruption")
	errActNoDir        = errors.New("saas feed activation: empty data directory")
	errActWrite        = errors.New("saas feed activation: durable write failed")
	errActVerifyBack   = errors.New("saas feed activation: read-back verification failed")
)

// ─── the record + codec ───────────────────────────────────────────────────────────

// activationRecord is the canonical ACTIVE-GENERATION authority (§B.4). The JSON field
// order below is FIXED and load-bearing: the canonical bytes must be byte-stable across
// writers/platforms (golden-bytes test pins this).
type activationRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Protocol      string `json:"protocol"` // urlcatfeed.Protocol
	Feed          string `json:"feed"`     // urlcatfeed.FeedID

	// Active generation (concern 2).
	ActiveVersion  int64  `json:"active_feed_version"` // ≥ 1
	GenerationID   string `json:"generation_id"`       // == decimal active_feed_version
	ManifestSHA256 string `json:"manifest_sha256"`     // digest of generations/<id>/manifest.envelope.json
	ArtifactSHA256 string `json:"artifact_sha256"`     // digest of generations/<id>/artifact.json
	SnapshotSHA256 string `json:"snapshot_sha256"`     // digest of generations/<id>/snapshot.normalized.json
	GeneratedAt    string `json:"generated_at"`        // canonical whole-second UTC RFC3339
	ExpiresAt      string `json:"expires_at"`
	ETag           string `json:"etag,omitempty"` // opaque, bounded; the manifest ETag when known

	// Rollback floor copy (concern 1) — a THIRD max input to selectFloor.
	FloorVersion     int64  `json:"floor_version"`
	FloorGeneratedAt string `json:"floor_generated_at"`

	// Commit / config revision (the approved state machine's revision binding) +
	// provenance (how it became active).
	ConfigRevision string `json:"config_revision"`
	Provenance     string `json:"provenance"`

	CRC32C string `json:"crc32c"` // EXACTLY 8 lowercase hex (fmt %08x)
}

// activationRecordSansCRC is the CRC-omitted canonical VIEW (identical field order,
// crc32c ABSENT). The CRC is computed over THIS view's canonical bytes.
type activationRecordSansCRC struct {
	SchemaVersion    int    `json:"schema_version"`
	Protocol         string `json:"protocol"`
	Feed             string `json:"feed"`
	ActiveVersion    int64  `json:"active_feed_version"`
	GenerationID     string `json:"generation_id"`
	ManifestSHA256   string `json:"manifest_sha256"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	SnapshotSHA256   string `json:"snapshot_sha256"`
	GeneratedAt      string `json:"generated_at"`
	ExpiresAt        string `json:"expires_at"`
	ETag             string `json:"etag,omitempty"`
	FloorVersion     int64  `json:"floor_version"`
	FloorGeneratedAt string `json:"floor_generated_at"`
	ConfigRevision   string `json:"config_revision"`
	Provenance       string `json:"provenance"`
}

func (r activationRecord) sansCRC() activationRecordSansCRC {
	return activationRecordSansCRC{
		SchemaVersion: r.SchemaVersion, Protocol: r.Protocol, Feed: r.Feed,
		ActiveVersion: r.ActiveVersion, GenerationID: r.GenerationID,
		ManifestSHA256: r.ManifestSHA256, ArtifactSHA256: r.ArtifactSHA256, SnapshotSHA256: r.SnapshotSHA256,
		GeneratedAt: r.GeneratedAt, ExpiresAt: r.ExpiresAt, ETag: r.ETag,
		FloorVersion: r.FloorVersion, FloorGeneratedAt: r.FloorGeneratedAt,
		ConfigRevision: r.ConfigRevision, Provenance: r.Provenance,
	}
}

// activationComputeCRC derives the crc32c string (8 lowercase hex) over the crc-omitted
// canonical bytes (reuses the F3b-1 canonical encoder + Castagnoli table).
func activationComputeCRC(r activationRecord) (string, error) {
	b, err := floorCanonicalBytes(r.sansCRC())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x", crc32.Checksum(b, floorCRCTable)), nil
}

// encodeActivationRecord (re)computes crc32c and returns the full canonical bytes.
func encodeActivationRecord(r activationRecord) ([]byte, error) {
	crc, err := activationComputeCRC(r)
	if err != nil {
		return nil, err
	}
	r.CRC32C = crc
	return floorCanonicalBytes(r)
}

// decodeActivationRecord strictly decodes + fully validates one canonical record.
func decodeActivationRecord(data []byte) (activationRecord, error) {
	if len(data) == 0 {
		return activationRecord{}, errActEmpty
	}
	if len(data) > maxActivationRecordBytes {
		return activationRecord{}, fmt.Errorf("%w: %d > %d", errActOversize, len(data), maxActivationRecordBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r activationRecord
	if err := dec.Decode(&r); err != nil {
		return activationRecord{}, fmt.Errorf("saas feed activation: decode: %w", err)
	}
	if dec.More() {
		return activationRecord{}, errActTrailing
	}
	canon, err := floorCanonicalBytes(r)
	if err != nil {
		return activationRecord{}, err
	}
	if !bytes.Equal(canon, data) {
		return activationRecord{}, errActNoncanonical
	}
	if err := validateActivationRecord(r); err != nil {
		return activationRecord{}, err
	}
	return r, nil
}

// validateActivationFields checks every semantic field EXCEPT the crc32c value.
func validateActivationFields(r activationRecord) error {
	if r.SchemaVersion != activationSchemaVersion {
		return fmt.Errorf("%w: %d", errActSchema, r.SchemaVersion)
	}
	if r.Protocol != urlcatfeed.Protocol {
		return errActProtocol
	}
	if r.Feed != urlcatfeed.FeedID {
		return errActFeed
	}
	if r.ActiveVersion < 1 {
		return fmt.Errorf("%w: %d", errActVersion, r.ActiveVersion)
	}
	if !validGenerationID(r.GenerationID) || r.GenerationID != strconv.FormatInt(r.ActiveVersion, 10) {
		return fmt.Errorf("%w: %q != active_feed_version %d", errActGenerationID, r.GenerationID, r.ActiveVersion)
	}
	if !validSHA256Hex(r.ManifestSHA256) || !validSHA256Hex(r.ArtifactSHA256) || !validSHA256Hex(r.SnapshotSHA256) {
		return errActDigest
	}
	if err := validateActivationTiming(r); err != nil {
		return err
	}
	if !validActivationETag(r.ETag) {
		return fmt.Errorf("%w: %q", errActETag, r.ETag)
	}
	if err := validateActivationFloor(r); err != nil {
		return err
	}
	if !validActivationProvenance(r.Provenance) {
		return fmt.Errorf("%w: %q", errActProvenance, r.Provenance)
	}
	if !validConfigRevision(r.ConfigRevision) {
		return fmt.Errorf("%w: %q", errActConfigRev, r.ConfigRevision)
	}
	return nil
}

// validateActivationTiming checks the generated/expires timestamps are canonical
// whole-second UTC and ordered (expires after generated).
func validateActivationTiming(r activationRecord) error {
	gen, ok := canonicalUTCSecond(r.GeneratedAt)
	if !ok {
		return fmt.Errorf("%w: generated_at %q", errActTime, r.GeneratedAt)
	}
	exp, ok := canonicalUTCSecond(r.ExpiresAt)
	if !ok {
		return fmt.Errorf("%w: expires_at %q", errActTime, r.ExpiresAt)
	}
	if !exp.After(gen) {
		return fmt.Errorf("%w: expires_at not after generated_at", errActTime)
	}
	return nil
}

// validateActivationFloor checks the embedded floor copy: version ≥ compiled checkpoint
// floor (0) and a canonical generated_at (or the zero sentinel at the fresh checkpoint).
func validateActivationFloor(r activationRecord) error {
	if r.FloorVersion < 0 || r.FloorVersion > r.ActiveVersion {
		return fmt.Errorf("%w: floor v%d vs active v%d", errActFloor, r.FloorVersion, r.ActiveVersion)
	}
	if r.FloorGeneratedAt != "" {
		if _, ok := canonicalUTCSecond(r.FloorGeneratedAt); !ok {
			return fmt.Errorf("%w: floor generated_at %q", errActFloor, r.FloorGeneratedAt)
		}
	}
	return nil
}

// validateActivationRecord is the read-path check: all fields PLUS crc format + value.
func validateActivationRecord(r activationRecord) error {
	if err := validateActivationFields(r); err != nil {
		return err
	}
	if !validCRC32Hex(r.CRC32C) {
		return fmt.Errorf("%w: format %q", errActCRC, r.CRC32C)
	}
	want, err := activationComputeCRC(r)
	if err != nil {
		return err
	}
	if r.CRC32C != want {
		return fmt.Errorf("%w: stored %s recomputed %s", errActCRC, r.CRC32C, want)
	}
	return nil
}

// validActivationETag bounds an opaque validator: empty (unknown) or a short,
// control-char-free token.
func validActivationETag(v string) bool {
	if v == "" {
		return true
	}
	if len(v) > 256 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return false
		}
	}
	return true
}

// validConfigRevision bounds the opaque config/override revision identity: non-empty,
// short, printable (a fingerprint, epoch string, or "compiled" for no overrides).
func validConfigRevision(v string) bool {
	if v == "" || len(v) > 256 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return false
		}
	}
	return true
}

// floorWatermark returns the activation record's DURABLE floor copy as an ordering key.
// §B.4/§B.6: this copy is a THIRD max input to floor selection alongside floor.a/floor.b,
// so a valid activation record restores the rollback floor even if both floor replicas are
// lost (see raiseFloorFromActivation, saas_feed_recover.go).
func (r activationRecord) floorWatermark() floorWatermark {
	t, _ := canonicalUTCSecond(r.FloorGeneratedAt) // zero time when unset — the fresh checkpoint
	return floorWatermark{Version: r.FloorVersion, GeneratedAt: t}
}

// ─── single-record store (§B.5 S4) ────────────────────────────────────────────────

// activationStore owns the fixed activation-state.json path + the durability seam
// (reusing the F3b-1 floorFS: AtomicWrite + os.ReadFile). It writes exactly one record
// atomically and read-back-verifies it before reporting success (§B.5 S4 requires the
// activation record durable BEFORE the live cutover).
type activationStore struct {
	fs   floorFS
	path string
}

func newActivationStore(dir string) (*activationStore, error) {
	return newActivationStoreFS(osFloorFS(), dir)
}

func newActivationStoreFS(fs floorFS, dir string) (*activationStore, error) {
	if dir == "" {
		return nil, errActNoDir
	}
	return &activationStore{fs: fs, path: filepath.Join(dir, activationFile)}, nil
}

// activationReadStatus mirrors floorReadStatus for the recovery classifier.
type activationReadStatus int

const (
	activationAbsent     activationReadStatus = iota // no record — fresh install / pre-activation
	activationValid                                  // decoded + validated + crc ok
	activationCorrupt                                // present but failed decode/validate/crc → excluded
	activationUnreadable                             // I/O error other than NotExist → excluded
)

func (s activationReadStatus) String() string {
	switch s {
	case activationAbsent:
		return "absent"
	case activationValid:
		return "valid"
	case activationCorrupt:
		return "corrupt"
	case activationUnreadable:
		return "unreadable"
	default:
		return "unknown"
	}
}

// Read is fail-closed like the floor read: missing ⇒ absent; unreadable /
// structurally-invalid / crc-mismatch ⇒ excluded (never a silent zero).
func (s *activationStore) Read() (activationRecord, activationReadStatus, error) {
	b, err := s.fs.readFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return activationRecord{}, activationAbsent, nil
		}
		return activationRecord{}, activationUnreadable, err
	}
	r, err := decodeActivationRecord(b)
	if err != nil {
		return activationRecord{}, activationCorrupt, err
	}
	return r, activationValid, nil
}

// Commit validates, (re)computes the crc, writes the canonical bytes atomically, and
// read-back-verifies. It returns an error (never partial success) on any write/verify
// failure — the caller (activation coordinator) MUST NOT perform the live cutover unless
// Commit succeeded (§B.5 S4 → S5; §B.12 invariant "incomplete durability never silently
// activates").
func (s *activationStore) Commit(r activationRecord) error {
	if err := validateActivationFields(r); err != nil {
		return err
	}
	b, err := encodeActivationRecord(r)
	if err != nil {
		return err
	}
	if err := s.fs.atomicWrite(s.path, b, activationFilePerm); err != nil {
		return fmt.Errorf("%w: %v", errActWrite, err)
	}
	got, st, err := s.Read()
	if st != activationValid {
		if err != nil {
			return fmt.Errorf("%w: %v", errActVerifyBack, err)
		}
		return fmt.Errorf("%w: status %s", errActVerifyBack, st)
	}
	if !sameActivationIdentity(got, r) {
		return fmt.Errorf("%w: identity mismatch", errActVerifyBack)
	}
	return nil
}

// sameActivationIdentity compares the identity-bearing fields (everything but the crc,
// which encode recomputes) for read-back exactness.
func sameActivationIdentity(a, b activationRecord) bool {
	return a.sansCRC() == b.sansCRC()
}
