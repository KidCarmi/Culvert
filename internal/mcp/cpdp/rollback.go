package cpdp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// rollbackDomainPrefix is the distinct domain-separation context for a rollback
// directive, so a rollback signature can never be confused with a snapshot
// signature (which uses domainPrefix).
const rollbackDomainPrefix = "culvert-mcp-rollback-v1"

// RollbackDirective is an operator-authorized, signed, hash-bound command to
// atomically revert a capability's active pointer to an EXACT retained signed
// snapshot (identified by TargetHash). It never republishes an unsigned document —
// it selects a snapshot the DP already holds and has re-verified. It is signed by
// the same CP signing key boundary as a snapshot.
type RollbackDirective struct {
	SchemaVersion     int           `json:"schema_version"`
	Capability        Capability    `json:"capability"`
	Epoch             int64         `json:"epoch"`
	CurrentActiveHash string        `json:"current_active_hash"`
	TargetHash        string        `json:"target_hash"`
	CommandID         string        `json:"command_id"`
	MinDPVersion      CompatVersion `json:"minimum_dp_version"`
	ExpiryUnixNano    int64         `json:"expiry_unix_nano"`
	SigAlg            string        `json:"sig_alg"`
	KeyID             string        `json:"key_id"`
	Signature         string        `json:"signature"`
}

// rollbackSignable is the exact representation the rollback signature covers
// (everything except the signature itself). alg and key_id are included so a
// signature can never be transplanted onto a different alg/key.
type rollbackSignable struct {
	SchemaVersion     int           `json:"schema_version"`
	Capability        string        `json:"capability"`
	Epoch             int64         `json:"epoch"`
	CurrentActiveHash string        `json:"current_active_hash"`
	TargetHash        string        `json:"target_hash"`
	CommandID         string        `json:"command_id"`
	MinDPVersion      CompatVersion `json:"minimum_dp_version"`
	ExpiryUnixNano    int64         `json:"expiry_unix_nano"`
	Alg               string        `json:"alg"`
	KeyID             string        `json:"key_id"`
}

func (d RollbackDirective) signable(alg, keyID string) rollbackSignable {
	return rollbackSignable{
		SchemaVersion:     d.SchemaVersion,
		Capability:        d.Capability.String(),
		Epoch:             d.Epoch,
		CurrentActiveHash: d.CurrentActiveHash,
		TargetHash:        d.TargetHash,
		CommandID:         d.CommandID,
		MinDPVersion:      d.MinDPVersion,
		ExpiryUnixNano:    d.ExpiryUnixNano,
		Alg:               alg,
		KeyID:             keyID,
	}
}

func rollbackSigningInput(s rollbackSignable) ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "marshal directive", err)
	}
	sum := sha256.Sum256(raw)
	msg := make([]byte, 0, len(rollbackDomainPrefix)+1+len(sum))
	msg = append(msg, rollbackDomainPrefix...)
	msg = append(msg, 0x00)
	msg = append(msg, sum[:]...)
	return msg, nil
}

// SignRollback produces a signed rollback directive. The caller has already
// validated the target and current hashes and holds write authority; signing does
// not itself verify those.
func SignRollback(d RollbackDirective, s Signer) (*RollbackDirective, error) {
	if s == nil {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.rollback", "nil signer")
	}
	if s.Algorithm() != SigAlgEd25519 {
		return nil, mcperr.New(mcperr.ReasonSnapshotAlgUnknown, "cpdp.rollback", "signer algorithm not ed25519")
	}
	if !d.Capability.Valid() || d.TargetHash == "" || d.CommandID == "" {
		return nil, mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "incomplete directive")
	}
	d.SchemaVersion = SchemaVersion
	msg, err := rollbackSigningInput(d.signable(s.Algorithm(), s.KeyID()))
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(msg)
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.rollback", "sign", err)
	}
	d.SigAlg = s.Algorithm()
	d.KeyID = s.KeyID()
	d.Signature = base64.StdEncoding.EncodeToString(sig)
	return &d, nil
}

// verifyRollbackSignature checks a directive's structural fields (schema,
// capability, algorithm, completeness), trusted key, and ed25519 signature. Split
// out to keep VerifyRollback under the cyclomatic-complexity bound.
func verifyRollbackSignature(d *RollbackDirective, trust *TrustStore, expectCap Capability) error {
	if !schemaSupported(d.SchemaVersion) {
		return mcperr.New(mcperr.ReasonSnapshotSchemaUnknown, "cpdp.rollback", "unsupported directive schema")
	}
	if !d.Capability.Valid() || d.Capability != expectCap {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.rollback", "directive capability mismatch")
	}
	if d.SigAlg != SigAlgEd25519 {
		return mcperr.New(mcperr.ReasonSnapshotAlgUnknown, "cpdp.rollback", "unsupported algorithm")
	}
	if d.TargetHash == "" || d.CommandID == "" {
		return mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "incomplete directive")
	}
	pub, ok := trust.lookup(d.KeyID)
	if !ok {
		return mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.rollback", "directive key id not trusted")
	}
	sig, err := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "malformed signature")
	}
	msg, err := rollbackSigningInput(d.signable(d.SigAlg, d.KeyID))
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "signature did not verify")
	}
	return nil
}

// VerifyRollback verifies a rollback directive's signature and structural
// validity against the trust store, then checks it is not expired and binds to
// the expected current active hash. A directive that is malformed, signed by an
// untrusted key, expired, or bound to a different current hash is rejected.
func VerifyRollback(d *RollbackDirective, trust *TrustStore, expectCap Capability, currentActiveHash string, nowUnixNano int64, dpVersion CompatVersion) error {
	if d == nil || trust == nil {
		return mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "nil directive or trust store")
	}
	if err := verifyRollbackSignature(d, trust, expectCap); err != nil {
		return err
	}
	// Expiry.
	if d.ExpiryUnixNano != 0 && nowUnixNano > d.ExpiryUnixNano {
		return mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "directive expired")
	}
	// Minimum version gate applies to rollback too.
	if err := CheckMinVersion(d.MinDPVersion, dpVersion); err != nil {
		return err
	}
	// Bind to the current active hash so a directive cannot be replayed against a
	// different active state.
	if d.CurrentActiveHash != "" && d.CurrentActiveHash != currentActiveHash {
		return mcperr.New(mcperr.ReasonRollbackDirectiveInvalid, "cpdp.rollback", "directive current-hash does not match active")
	}
	return nil
}
