package cpdp

import (
	"encoding/hex"
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// SourceMeta records a snapshot's provenance. For a rollback-produced snapshot it
// keeps the original target hash and rollback lineage explicit, so a reverted
// snapshot is never mistaken for a fresh forward publication.
type SourceMeta struct {
	// Kind is "publish" or "rollback".
	Kind string `json:"kind"`
	// RollbackOfHash is the retained target content hash when Kind == "rollback".
	RollbackOfHash string `json:"rollback_of_hash,omitempty"`
}

// Manifest is the immutable, signed header of an MCP snapshot. Every field is
// part of the content hash.
type Manifest struct {
	SchemaVersion   int           `json:"schema_version"`
	Capability      Capability    `json:"capability"`
	Epoch           int64         `json:"epoch"`
	Revisions       Revisions     `json:"revisions"`
	MinDPVersion    CompatVersion `json:"minimum_dp_version"`
	PayloadType     string        `json:"payload_type"`
	PayloadVersion  int           `json:"payload_version"`
	CreatedUnixNano int64         `json:"created_unix_nano"`
	Source          SourceMeta    `json:"source"`
}

// Envelope is one versioned, immutable, signed MCP snapshot. The signature
// authenticates the content hash; the content hash covers the complete unsigned
// manifest + algorithm + key id + payload (everything EXCEPT the content_hash and
// signature themselves, which would create a circular dependency).
type Envelope struct {
	Manifest    Manifest `json:"manifest"`
	Payload     Payload  `json:"payload"`
	ContentHash string   `json:"content_hash"` // hex sha256 of the canonical signable form
	SigAlg      string   `json:"sig_alg"`      // MUST be "ed25519"
	KeyID       string   `json:"key_id"`
	Signature   string   `json:"signature"` // std-base64 of the raw 64-byte ed25519 signature
}

// signable is the exact byte-defined representation the content hash is computed
// over. It deliberately includes the algorithm and key id (so a signature can
// never be transplanted onto a different alg/key), every revision, the epoch, the
// minimum version, the payload type/version, provenance, and the payload — and
// deliberately EXCLUDES content_hash and signature. Struct field order is fixed;
// the payload is map-free (sorted slices), so json.Marshal is deterministic and
// canonical.Hash then normalizes it to an arch-independent, duplicate-key-free,
// UTF-8-strict canonical digest.
type signable struct {
	SchemaVersion   int           `json:"schema_version"`
	Capability      string        `json:"capability"`
	Epoch           int64         `json:"epoch"`
	Revisions       Revisions     `json:"revisions"`
	MinDPVersion    CompatVersion `json:"minimum_dp_version"`
	Alg             string        `json:"alg"`
	KeyID           string        `json:"key_id"`
	PayloadType     string        `json:"payload_type"`
	PayloadVersion  int           `json:"payload_version"`
	CreatedUnixNano int64         `json:"created_unix_nano"`
	Source          SourceMeta    `json:"source"`
	Payload         Payload       `json:"payload"`
}

// buildSignable projects an envelope's signed fields into the canonical signable
// view.
func buildSignable(m Manifest, p Payload, alg, keyID string) signable {
	return signable{
		SchemaVersion:   m.SchemaVersion,
		Capability:      m.Capability.String(),
		Epoch:           m.Epoch,
		Revisions:       m.Revisions,
		MinDPVersion:    m.MinDPVersion,
		Alg:             alg,
		KeyID:           keyID,
		PayloadType:     m.PayloadType,
		PayloadVersion:  m.PayloadVersion,
		CreatedUnixNano: m.CreatedUnixNano,
		Source:          m.Source,
		Payload:         p,
	}
}

// ContentHash computes the hex SHA-256 content hash over the canonical signable
// representation of (manifest, payload, alg, keyID). It is the single hashing
// primitive used by both the signer (to produce content_hash) and the verifier
// (to recompute and compare). Any mutation of any signed field — including a
// payload section, the algorithm, the key id, or any revision — changes the hash.
func ContentHash(m Manifest, p Payload, alg, keyID string, b canonical.Bounds) (string, error) {
	raw, err := json.Marshal(buildSignable(m, p, alg, keyID))
	if err != nil {
		return "", mcperr.Wrap(mcperr.ReasonSnapshotMalformed, "cpdp.hash", "marshal signable", err)
	}
	h, err := canonical.Hash(raw, b)
	if err != nil {
		return "", mcperr.Wrap(mcperr.ReasonSnapshotMalformed, "cpdp.hash", "canonicalize signable", err)
	}
	return hex.EncodeToString(h[:]), nil
}
