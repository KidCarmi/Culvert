package cpdp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// domainPrefix is the domain-separation context string prepended to the content
// hash before signing. It ensures an MCP snapshot signature can never be confused
// with a release-catalog signature (which signs raw bytes with no prefix) or any
// other ed25519 signature in the codebase. The signed message is:
//
//	domainPrefix || 0x00 || <raw 32-byte content hash>
//
// The 0x00 separator makes the prefix unambiguously terminated so no crafted
// content hash can shift the boundary.
const domainPrefix = "culvert-mcp-snapshot-v1"

// signingInput builds the domain-separated message that is actually signed and
// verified, from the hex content hash. It returns an error if the content hash is
// not a well-formed 32-byte hex SHA-256.
func signingInput(contentHashHex string) ([]byte, error) {
	hb, err := hex.DecodeString(contentHashHex)
	if err != nil || len(hb) != 32 {
		return nil, mcperr.New(mcperr.ReasonSnapshotHashMismatch, "cpdp.sign", "content hash is not a 32-byte hex digest")
	}
	msg := make([]byte, 0, len(domainPrefix)+1+len(hb))
	msg = append(msg, domainPrefix...)
	msg = append(msg, 0x00)
	msg = append(msg, hb...)
	return msg, nil
}

// Signer is the scoped CP-side signing interface. The private key NEVER leaves
// the implementation: there is no raw-private-bytes accessor. A Signer performs
// the signing operation and exposes only its public key, key id and algorithm —
// mirroring the ca.KeyProvider boundary, so an HSM/KMS-backed signer can satisfy
// it without ever surfacing key material.
type Signer interface {
	// KeyID returns the stable identifier of the signing key.
	KeyID() string
	// Algorithm returns the signature algorithm identifier ("ed25519").
	Algorithm() string
	// Public returns the ed25519 public key (safe to distribute as a trust root).
	Public() ed25519.PublicKey
	// Sign signs msg and returns the raw signature bytes. It never exposes the
	// private key.
	Sign(msg []byte) ([]byte, error)
}

// localSigner is the default in-process ed25519 Signer. The private key is
// unexported and never returned.
type localSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewLocalSigner wraps an ed25519 private key as a Signer with the given key id.
// It fails closed on a malformed key or empty id — a signer that cannot sign is
// never silently returned.
func NewLocalSigner(keyID string, priv ed25519.PrivateKey) (Signer, error) {
	if keyID == "" {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "empty key id")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "malformed ed25519 private key")
	}
	return &localSigner{keyID: keyID, priv: priv}, nil
}

// GenerateLocalSigner generates a fresh ed25519 key pair and returns a Signer.
// This is intended for tests and one-time key provisioning through a trusted
// boundary — a production build must NOT generate an ephemeral signing key on
// every restart.
func GenerateLocalSigner(keyID string) (Signer, error) {
	if keyID == "" {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "empty key id")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "generate key", err)
	}
	return &localSigner{keyID: keyID, priv: priv}, nil
}

// KeyID returns the signing key id.
func (s *localSigner) KeyID() string { return s.keyID }

// Algorithm returns the signature algorithm identifier ("ed25519").
func (s *localSigner) Algorithm() string { return SigAlgEd25519 }

// Public returns the ed25519 public key (safe to distribute as a trust root).
func (s *localSigner) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Sign signs msg with the ed25519 private key; it never exposes the private key.
func (s *localSigner) Sign(msg []byte) ([]byte, error) {
	if len(s.priv) != ed25519.PrivateKeySize {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "signer unavailable")
	}
	return ed25519.Sign(s.priv, msg), nil
}

// TrustRoot is a public ed25519 trust root the DP verifies against. It carries
// PUBLIC material only; a private signing key is never distributed to a DP.
type TrustRoot struct {
	KeyID  string
	Alg    string
	Public ed25519.PublicKey
}

// TrustStore is an immutable, fail-closed set of trusted public keys, keyed by
// key id. It supports overlapping old/new roots during rotation (multiple roots)
// and removal (build a new store without the key). A key carried inside a snapshot
// is NEVER consulted — only keys provisioned through this trusted boundary are.
type TrustStore struct {
	keys map[string]ed25519.PublicKey
}

// NewTrustStore builds an immutable trust store from a bounded set of ed25519
// roots. It fails closed on: an empty set (an empty allowlist trusts nothing), a
// non-ed25519 algorithm, a wrong-length key (ed25519.Verify panics on a bad
// length, so the check is load-bearing), an empty or duplicate key id, or a root
// count over the hard cap. Each public key is defensively copied so the store is
// unaliased from caller memory.
func NewTrustStore(roots []TrustRoot) (*TrustStore, error) {
	if len(roots) == 0 {
		return nil, mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.trust", "empty trust store")
	}
	if len(roots) > capTrustRoots {
		return nil, mcperr.New(mcperr.ReasonSnapshotTooLarge, "cpdp.trust", "too many trust roots")
	}
	keys := make(map[string]ed25519.PublicKey, len(roots))
	for _, r := range roots {
		if r.Alg != SigAlgEd25519 {
			return nil, mcperr.New(mcperr.ReasonSnapshotAlgUnknown, "cpdp.trust", "trust root algorithm not ed25519")
		}
		if r.KeyID == "" || len(r.KeyID) > capKeyIDBytes {
			return nil, mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.trust", "invalid trust-root key id")
		}
		if len(r.Public) != ed25519.PublicKeySize {
			return nil, mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.trust", "trust root is not a 32-byte ed25519 public key")
		}
		if _, dup := keys[r.KeyID]; dup {
			return nil, mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.trust", "duplicate trust-root key id")
		}
		cp := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(cp, r.Public)
		keys[r.KeyID] = cp
	}
	return &TrustStore{keys: keys}, nil
}

// lookup returns the trusted public key for a key id, or false if the key id is
// not trusted.
func (t *TrustStore) lookup(keyID string) (ed25519.PublicKey, bool) {
	k, ok := t.keys[keyID]
	return k, ok
}

// Len returns the number of trusted keys (for status/diagnostics). It never
// returns key material.
func (t *TrustStore) Len() int { return len(t.keys) }

// Sign produces a signed Envelope from a manifest + payload using the signer. It
// computes the content hash over the canonical signable form, then signs the
// domain-separated content hash. The manifest's schema version, capability, and
// the signer's algorithm/key id are stamped into the envelope. Signing does NOT
// perform semantic validation — the caller validates the candidate BEFORE signing
// (validate-then-sign).
func Sign(m Manifest, p Payload, s Signer, l Limits) (*Envelope, error) {
	if s == nil {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "nil signer")
	}
	if s.Algorithm() != SigAlgEd25519 {
		return nil, mcperr.New(mcperr.ReasonSnapshotAlgUnknown, "cpdp.sign", "signer algorithm not ed25519")
	}
	hash, err := ContentHash(m, p, s.Algorithm(), s.KeyID(), l.canonicalBounds())
	if err != nil {
		return nil, err
	}
	msg, err := signingInput(hash)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(msg)
	if err != nil {
		return nil, mcperr.Wrap(mcperr.ReasonSnapshotSignerUnavailable, "cpdp.sign", "sign", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, mcperr.New(mcperr.ReasonSnapshotSignatureInvalid, "cpdp.sign", "signer produced a wrong-length signature")
	}
	return &Envelope{
		Manifest:    m,
		Payload:     p,
		ContentHash: hash,
		SigAlg:      s.Algorithm(),
		KeyID:       s.KeyID(),
		Signature:   base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// verifyEnvelopeHeader checks the bounded structural header fields of an envelope
// (schema version, capability, key id, signature length, algorithm) without
// consulting the trust store or recomputing the hash. Split out to keep
// VerifySignature under the cyclomatic-complexity bound.
func verifyEnvelopeHeader(env *Envelope, l Limits) error {
	if !schemaSupported(env.Manifest.SchemaVersion) {
		// A present-but-unknown schema is a schema rejection, not a generic malform.
		return mcperr.New(mcperr.ReasonSnapshotSchemaUnknown, "cpdp.verify", "unsupported envelope schema version")
	}
	if !env.Manifest.Capability.Valid() {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "cpdp.verify", "invalid capability")
	}
	if env.KeyID == "" || len(env.KeyID) > l.MaxKeyIDBytes() {
		return mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.verify", "missing or oversized key id")
	}
	if env.Signature == "" || len(env.Signature) > l.MaxSignatureBytes() {
		return mcperr.New(mcperr.ReasonSnapshotSignatureInvalid, "cpdp.verify", "missing or oversized signature")
	}
	// An unknown alg is NEVER treated as ed25519.
	if env.SigAlg != SigAlgEd25519 {
		return mcperr.New(mcperr.ReasonSnapshotAlgUnknown, "cpdp.verify", "unsupported signature algorithm")
	}
	return nil
}

// VerifySignature performs the cryptographic verification of an envelope in the
// mandated order, WITHOUT the semantic validation (which is a separate step so
// the ordering "authenticate before ratchet, validate before mutate" is explicit
// in the caller):
//
//  1. structural: bounded header fields are present;
//  2. known schema version;
//  3. known algorithm (ed25519);
//  4. trusted key id;
//  5. recomputed content hash equals the declared content hash;
//  6. ed25519 signature verifies over the domain-separated content hash.
//
// An unknown algorithm, unknown key, malformed hash, or malformed/oversized
// signature rejects the whole snapshot. A key carried inside the snapshot never
// authorizes itself — only the trust store is consulted.
func VerifySignature(env *Envelope, trust *TrustStore, l Limits) error {
	if env == nil || trust == nil {
		return mcperr.New(mcperr.ReasonSnapshotMalformed, "cpdp.verify", "nil envelope or trust store")
	}
	// 1-3. structural header presence + bounds + known algorithm.
	if err := verifyEnvelopeHeader(env, l); err != nil {
		return err
	}
	// 4. trusted key.
	pub, ok := trust.lookup(env.KeyID)
	if !ok {
		return mcperr.New(mcperr.ReasonSnapshotKeyUntrusted, "cpdp.verify", "signing key id is not trusted")
	}
	// 5. recompute content hash and compare.
	want, err := ContentHash(env.Manifest, env.Payload, env.SigAlg, env.KeyID, l.canonicalBounds())
	if err != nil {
		return err
	}
	if want != env.ContentHash {
		return mcperr.New(mcperr.ReasonSnapshotHashMismatch, "cpdp.verify", "recomputed content hash does not match declared")
	}
	// 6. ed25519 verify over the domain-separated content hash.
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return mcperr.New(mcperr.ReasonSnapshotSignatureInvalid, "cpdp.verify", "malformed signature encoding")
	}
	msg, err := signingInput(env.ContentHash)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return mcperr.New(mcperr.ReasonSnapshotSignatureInvalid, "cpdp.verify", "signature did not verify")
	}
	return nil
}
