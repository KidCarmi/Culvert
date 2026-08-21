package main

// saas_feed_authority.go — F3b-4: the managed-DP durable AUTHORITY mirror.
//
// Closes the F3a-2 deferred managed-DP persistence finding. F3a-2 deliberately kept
// CP-provided feed configuration as an IN-MEMORY mirror (applySnapshotSaaSFeed,
// controlplane_snapshot.go) because there was no runtime consumer — the durable-DP
// persistence was explicitly deferred "to the F3b consumer". F3b-4 introduces that
// consumer (the runtime lifecycle + scheduler), so a managed data-plane node must be
// able to recover the LAST AUTHORITATIVE control-plane feed configuration across a
// restart WITHOUT a live CP — never falling back to node-local/default settings, and
// never silently dropping CP-provided category overrides.
//
// This record is node-local DURABLE AUTHORITY (the activation-state.json / floor.*
// class): it is OFF every configuration surface (export/import, config-version
// rollback, ConfigSnapshot, configBackup — no binding by construction), and it is never
// writable through a managed-DP local API (only the fenced snapshot-apply path writes
// it). It is:
//
//   - written ONLY after an authenticated, fenced (dpObserveEpoch), fully validated
//     (validateConfigSnapshot) CP snapshot has been accepted and applied;
//   - atomic (fileutil.AtomicWrite: temp + fsync + rename + parent fsync), read-back
//     verified, CRC-32/Castagnoli corruption-detected, strictly decoded, schema-versioned;
//   - an operational CACHE of CP authority, NOT locally-editable policy;
//   - replaced only by a newer valid authoritative snapshot;
//   - rejected on a CP identity / fencing-epoch conflict per the existing HA ratchet.
//
// Why a NEW record and not the F3b-3 activation record: the activation record
// (saas_feed_activation.go) binds the ACTIVE GENERATION content (version, digests, floor
// copy) plus an opaque config-revision fingerprint — it does NOT bind the authoritative
// feed CONFIGURATION (managed/enabled, the resolved URL, the refresh interval), the
// controlling CP identity, or the fencing epoch. Proven from code at review time
// (activationRecord has no url/enabled/interval/cp-identity/epoch fields). Reusing it is
// therefore impossible; this mirror is the minimal, distinct, non-redundant closure.
//
// Overrides: the actual override DATA continues to live in the already-durable
// overrides.json (internal/catoverride; persisted by applySnapshotSaaSFeed today). The
// mirror binds only an override FINGERPRINT so a managed DP can (a) bind the overrides'
// identity to the authoritative epoch and (b) detect a mirror/overrides inconsistency on
// restart (ambiguous ⇒ wait for authority) rather than silently composing without them.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// ─── constants ──────────────────────────────────────────────────────────────────

const (
	// saasFeedAuthoritySchemaVersion is the only supported authority-mirror schema.
	saasFeedAuthoritySchemaVersion = 1

	// saasFeedAuthorityFile is the FIXED record filename (node-local, beside the floor
	// and activation records). Recovery reads ONLY this path — never a directory scan.
	saasFeedAuthorityFile = "authority-state.json"

	// maxSaaSFeedAuthorityRecordBytes bounds decoder input against a corrupt/hostile
	// file. The record is a few hundred bytes; 8 KiB is generous headroom.
	maxSaaSFeedAuthorityRecordBytes = 8192

	saasFeedAuthorityFilePerm os.FileMode = 0o600

	// saasFeedOverridesFingerprintNone is the fingerprint of an empty override set (the
	// sha-256 of the canonical "{}" normalized form) — precomputed as a stable sentinel
	// so an empty authoritative override set has a definite, comparable identity.
	saasFeedNoOverridesSentinel = "none"
)

// ─── structured errors ───────────────────────────────────────────────────────────

var (
	errAuthEmpty        = errors.New("saas feed authority: empty record")
	errAuthOversize     = errors.New("saas feed authority: record exceeds max size")
	errAuthTrailing     = errors.New("saas feed authority: trailing data after record")
	errAuthNoncanonical = errors.New("saas feed authority: record is not in canonical form")
	errAuthSchema       = errors.New("saas feed authority: unsupported schema_version")
	errAuthProtocol     = errors.New("saas feed authority: protocol mismatch")
	errAuthURL          = errors.New("saas feed authority: url is not the official manifest origin")
	errAuthRefresh      = errors.New("saas feed authority: invalid refresh_seconds")
	errAuthFingerprint  = errors.New("saas feed authority: invalid overrides_fingerprint")
	errAuthEpoch        = errors.New("saas feed authority: invalid epoch")
	errAuthConfigVer    = errors.New("saas feed authority: invalid config_version")
	errAuthCPIdent      = errors.New("saas feed authority: invalid cp_fingerprint")
	errAuthCRC          = errors.New("saas feed authority: crc32c corruption")
	errAuthNoDir        = errors.New("saas feed authority: empty data directory")
	errAuthWrite        = errors.New("saas feed authority: durable write failed")
	errAuthVerifyBack   = errors.New("saas feed authority: read-back verification failed")
)

// ─── the record + codec ───────────────────────────────────────────────────────────

// saasFeedAuthorityRecord is the canonical last-authoritative-CP-config mirror. The JSON
// field order is FIXED and load-bearing (the canonical bytes must be byte-stable across
// writers/platforms; a golden-bytes test pins it). No wall-clock field appears here on
// purpose — ordering is by fencing epoch + config version, both clock-independent.
type saasFeedAuthorityRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Protocol      string `json:"protocol"` // saasFeedProtocolV1

	// Authoritative feed configuration (the exact policy a managed DP recovers).
	URL            string `json:"url"`             // resolved official manifest URL
	Managed        bool   `json:"managed"`         // CP always sends explicit management
	Enabled        bool   `json:"enabled"`         // effective enable
	RefreshSeconds int64  `json:"refresh_seconds"` // 0 ⇒ resolve-time default

	// Override identity (the DATA lives in overrides.json; this binds it to the epoch).
	OverridesFingerprint string `json:"overrides_fingerprint"`

	// Controlling CP identity + fencing (the existing cluster model).
	Epoch         int64  `json:"epoch"`          // ConfigSnapshot.Epoch (fencing; 0 = legacy)
	ConfigVersion int64  `json:"config_version"` // ConfigSnapshot.Version (monotonic)
	CPFingerprint string `json:"cp_fingerprint"` // ConfigSnapshot.CAFingerprint (cluster identity; "" = legacy)

	CRC32C string `json:"crc32c"` // EXACTLY 8 lowercase hex (fmt %08x)
}

// saasFeedAuthorityRecordSansCRC is the CRC-omitted canonical VIEW (identical field
// order, crc32c ABSENT). The CRC is computed over THIS view's canonical bytes.
type saasFeedAuthorityRecordSansCRC struct {
	SchemaVersion        int    `json:"schema_version"`
	Protocol             string `json:"protocol"`
	URL                  string `json:"url"`
	Managed              bool   `json:"managed"`
	Enabled              bool   `json:"enabled"`
	RefreshSeconds       int64  `json:"refresh_seconds"`
	OverridesFingerprint string `json:"overrides_fingerprint"`
	Epoch                int64  `json:"epoch"`
	ConfigVersion        int64  `json:"config_version"`
	CPFingerprint        string `json:"cp_fingerprint"`
}

func (r saasFeedAuthorityRecord) sansCRC() saasFeedAuthorityRecordSansCRC {
	return saasFeedAuthorityRecordSansCRC{
		SchemaVersion: r.SchemaVersion, Protocol: r.Protocol, URL: r.URL,
		Managed: r.Managed, Enabled: r.Enabled, RefreshSeconds: r.RefreshSeconds,
		OverridesFingerprint: r.OverridesFingerprint, Epoch: r.Epoch,
		ConfigVersion: r.ConfigVersion, CPFingerprint: r.CPFingerprint,
	}
}

// saasFeedAuthorityComputeCRC derives the crc32c string (8 lowercase hex) over the
// crc-omitted canonical bytes (reuses the F3b-1 canonical encoder + Castagnoli table).
func saasFeedAuthorityComputeCRC(r saasFeedAuthorityRecord) (string, error) {
	b, err := floorCanonicalBytes(r.sansCRC())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x", crc32.Checksum(b, floorCRCTable)), nil
}

// encodeSaaSFeedAuthorityRecord (re)computes crc32c and returns the full canonical bytes.
func encodeSaaSFeedAuthorityRecord(r saasFeedAuthorityRecord) ([]byte, error) {
	crc, err := saasFeedAuthorityComputeCRC(r)
	if err != nil {
		return nil, err
	}
	r.CRC32C = crc
	return floorCanonicalBytes(r)
}

// decodeSaaSFeedAuthorityRecord strictly decodes + fully validates one canonical record.
func decodeSaaSFeedAuthorityRecord(data []byte) (saasFeedAuthorityRecord, error) {
	if len(data) == 0 {
		return saasFeedAuthorityRecord{}, errAuthEmpty
	}
	if len(data) > maxSaaSFeedAuthorityRecordBytes {
		return saasFeedAuthorityRecord{}, fmt.Errorf("%w: %d > %d", errAuthOversize, len(data), maxSaaSFeedAuthorityRecordBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r saasFeedAuthorityRecord
	if err := dec.Decode(&r); err != nil {
		return saasFeedAuthorityRecord{}, fmt.Errorf("saas feed authority: decode: %w", err)
	}
	if dec.More() {
		return saasFeedAuthorityRecord{}, errAuthTrailing
	}
	canon, err := floorCanonicalBytes(r)
	if err != nil {
		return saasFeedAuthorityRecord{}, err
	}
	if !bytes.Equal(canon, data) {
		return saasFeedAuthorityRecord{}, errAuthNoncanonical
	}
	if err := validateSaaSFeedAuthorityRecord(r); err != nil {
		return saasFeedAuthorityRecord{}, err
	}
	return r, nil
}

// validateSaaSFeedAuthorityFields checks every semantic field EXCEPT the crc32c value.
func validateSaaSFeedAuthorityFields(r saasFeedAuthorityRecord) error {
	if r.SchemaVersion != saasFeedAuthoritySchemaVersion {
		return fmt.Errorf("%w: %d", errAuthSchema, r.SchemaVersion)
	}
	if r.Protocol != saasFeedProtocolV1 {
		return errAuthProtocol
	}
	// The URL must be the official manifest origin (the only accepted destination —
	// there is no generic mirror; an empty stored URL is invalid: the writer stores the
	// resolved URL, never the empty sentinel).
	if err := validateOfficialManifestURL(r.URL); err != nil {
		return fmt.Errorf("%w: %v", errAuthURL, err)
	}
	if r.RefreshSeconds < 0 {
		return fmt.Errorf("%w: %d", errAuthRefresh, r.RefreshSeconds)
	}
	if !validSaaSFeedOverridesFingerprint(r.OverridesFingerprint) {
		return fmt.Errorf("%w: %q", errAuthFingerprint, r.OverridesFingerprint)
	}
	if r.Epoch < 0 {
		return fmt.Errorf("%w: %d", errAuthEpoch, r.Epoch)
	}
	if r.ConfigVersion < 0 {
		return fmt.Errorf("%w: %d", errAuthConfigVer, r.ConfigVersion)
	}
	if !validSaaSFeedCPFingerprint(r.CPFingerprint) {
		return fmt.Errorf("%w: %q", errAuthCPIdent, r.CPFingerprint)
	}
	return nil
}

// validateSaaSFeedAuthorityRecord is the read-path check: all fields PLUS crc format + value.
func validateSaaSFeedAuthorityRecord(r saasFeedAuthorityRecord) error {
	if err := validateSaaSFeedAuthorityFields(r); err != nil {
		return err
	}
	if !validCRC32Hex(r.CRC32C) {
		return fmt.Errorf("%w: format %q", errAuthCRC, r.CRC32C)
	}
	want, err := saasFeedAuthorityComputeCRC(r)
	if err != nil {
		return err
	}
	if r.CRC32C != want {
		return fmt.Errorf("%w: stored %s recomputed %s", errAuthCRC, r.CRC32C, want)
	}
	return nil
}

// validSaaSFeedOverridesFingerprint accepts the empty-set sentinel or a 64-hex sha-256.
func validSaaSFeedOverridesFingerprint(v string) bool {
	return v == saasFeedNoOverridesSentinel || validSHA256Hex(v)
}

// validSaaSFeedCPFingerprint bounds the controlling-CP identity: empty (legacy cluster
// with no CA fingerprint) or a short printable token (the CA SHA-256 hex in practice).
func validSaaSFeedCPFingerprint(v string) bool {
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

// saasFeedOverridesFingerprint returns a stable identity for an override set: the
// sha-256 (hex) of its canonical normalized JSON, or the sentinel for an empty set.
// Deterministic across nodes/restarts (Normalize canonicalizes; json.Marshal sorts map
// keys), so producer and every consumer compute the same value.
func saasFeedOverridesFingerprint(o catoverride.Overrides) string {
	norm, err := catoverride.Normalize(o)
	if err != nil {
		// An invalid override set cannot be fingerprinted meaningfully; the caller has
		// already validated on the write path, so this is defensive. Treat as empty.
		norm = catoverride.Overrides{}
	}
	if len(norm.Added) == 0 && len(norm.Recategorized) == 0 && len(norm.Tombstones) == 0 {
		return saasFeedNoOverridesSentinel
	}
	b, err := json.Marshal(norm)
	if err != nil {
		return saasFeedNoOverridesSentinel
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ─── single-record store ───────────────────────────────────────────────────────────

// saasFeedAuthorityStore owns the fixed authority-state.json path + the durability seam
// (reusing the F3b-1 floorFS: AtomicWrite + os.ReadFile). It writes exactly one record
// atomically and read-back-verifies it before reporting success.
type saasFeedAuthorityStore struct {
	fs   floorFS
	path string
}

func newSaaSFeedAuthorityStore(dir string) (*saasFeedAuthorityStore, error) {
	return newSaaSFeedAuthorityStoreFS(osFloorFS(), dir)
}

func newSaaSFeedAuthorityStoreFS(fs floorFS, dir string) (*saasFeedAuthorityStore, error) {
	if dir == "" {
		return nil, errAuthNoDir
	}
	return &saasFeedAuthorityStore{fs: fs, path: filepath.Join(dir, saasFeedAuthorityFile)}, nil
}

// saasFeedAuthorityReadStatus mirrors the floor/activation read classifiers.
type saasFeedAuthorityReadStatus int

const (
	saasFeedAuthorityAbsent     saasFeedAuthorityReadStatus = iota // no record — never synced from a CP
	saasFeedAuthorityValid                                         // decoded + validated + crc ok
	saasFeedAuthorityCorrupt                                       // present but failed decode/validate/crc → excluded
	saasFeedAuthorityUnreadable                                    // I/O error other than NotExist → excluded
)

func (s saasFeedAuthorityReadStatus) String() string {
	switch s {
	case saasFeedAuthorityAbsent:
		return "absent"
	case saasFeedAuthorityValid:
		return "valid"
	case saasFeedAuthorityCorrupt:
		return "corrupt"
	case saasFeedAuthorityUnreadable:
		return "unreadable"
	default:
		return "unknown"
	}
}

// Read is fail-closed like the floor/activation read: missing ⇒ absent; unreadable /
// structurally-invalid / crc-mismatch ⇒ excluded (never a silent zero-value config).
func (s *saasFeedAuthorityStore) Read() (saasFeedAuthorityRecord, saasFeedAuthorityReadStatus, error) {
	b, err := s.fs.readFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return saasFeedAuthorityRecord{}, saasFeedAuthorityAbsent, nil
		}
		return saasFeedAuthorityRecord{}, saasFeedAuthorityUnreadable, err
	}
	r, err := decodeSaaSFeedAuthorityRecord(b)
	if err != nil {
		return saasFeedAuthorityRecord{}, saasFeedAuthorityCorrupt, err
	}
	return r, saasFeedAuthorityValid, nil
}

// Commit validates, (re)computes the crc, writes the canonical bytes atomically, and
// read-back-verifies. It returns an error (never partial success) on any write/verify
// failure. The parent directory is created if missing (the saas_feed dir may not exist
// on a DP that has never activated a generation).
func (s *saasFeedAuthorityStore) Commit(r saasFeedAuthorityRecord) error {
	if err := validateSaaSFeedAuthorityFields(r); err != nil {
		return err
	}
	if err := s.fs.mkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("%w: mkdir: %v", errAuthWrite, err)
	}
	b, err := encodeSaaSFeedAuthorityRecord(r)
	if err != nil {
		return err
	}
	if err := s.fs.atomicWrite(s.path, b, saasFeedAuthorityFilePerm); err != nil {
		return fmt.Errorf("%w: %v", errAuthWrite, err)
	}
	got, st, err := s.Read()
	if st != saasFeedAuthorityValid {
		if err != nil {
			return fmt.Errorf("%w: %v", errAuthVerifyBack, err)
		}
		return fmt.Errorf("%w: status %s", errAuthVerifyBack, st)
	}
	if got.sansCRC() != r.sansCRC() {
		return fmt.Errorf("%w: identity mismatch", errAuthVerifyBack)
	}
	return nil
}
