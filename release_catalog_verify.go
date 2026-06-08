// Release Catalog Authenticity — P1.3 Slice 1 (index signature verification).
//
// Adds a Control-Plane-side authenticity gate on TOP of the P1.2 catalog runtime
// (release_catalog.go): an ed25519 detached signature over the RAW index.json
// bytes, verified against a baked/operator TrustStore BEFORE the index is parsed
// or any manifest_sha256 entry is trusted (plan §5/§5.0). Signing the index
// transitively authenticates every manifest (the index binds each by sha256), so
// one signature over one document is the whole authenticity kernel.
//
// Scope (roadmap/D1.6d-P1.3-catalog-authenticity-plan.md — Slice 1): TrustStore
// + envelope parse + LoadVerifiedCatalog + the three enforcement modes. NO GUI,
// NO agent/dispatch, NO air-gap bundle, NO network/refresh, NO CP→DP propagation,
// NO metrics wiring. The verifier is release-agnostic and verifies fully offline.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// catalogSigAlg is the ONLY signature algorithm P1.3 accepts (downgrade guard).
const catalogSigAlg = "ed25519"

// Distinct error kinds (plan §8) so callers/tests/alerting can tell an
// authenticity failure apart from P1.2's structural "malformed" errors.
var (
	errSigMissing   = errors.New("release catalog: signature missing")
	errSigOversize  = errors.New("release catalog: signature exceeds size bound")
	errSigMalformed = errors.New("release catalog: signature envelope malformed")
	errSigAlg       = errors.New("release catalog: unsupported signature alg")
	errSigUntrusted = errors.New("release catalog: untrusted key_id")
	errSigVerify    = errors.New("release catalog: signature verification failed")
)

// VerifyMode is the catalog-signature enforcement mode (plan §6).
type VerifyMode int

const (
	// VerifyEnforce rejects a MISSING or INVALID signature (production target).
	VerifyEnforce VerifyMode = iota
	// VerifyPermissive loads an UNSIGNED catalog with a warning but still rejects
	// a present-but-INVALID signature (migration window — never a tamper bypass).
	VerifyPermissive
	// VerifyDisabled loads without verifying (break-glass / local dev only).
	VerifyDisabled
)

func (m VerifyMode) String() string {
	switch m {
	case VerifyEnforce:
		return "enforce"
	case VerifyPermissive:
		return "permissive"
	case VerifyDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

// ─── source extensions (signature reading kept OFF CatalogSource, plan §5.2) ──

// SignatureSource yields the detached index signature bytes. It is kept OUT of
// CatalogSource so unsigned/test-only sources stay valid for the bare
// LoadCatalog (and the P1.2 tests keep compiling unchanged).
type SignatureSource interface {
	// ReadSignature returns the raw index.json.sig bytes (bounded). A MISSING
	// signature MUST surface as an error satisfying errors.Is(err, fs.ErrNotExist)
	// so permissive mode can tell "unsigned" apart from "present-but-unreadable".
	ReadSignature() ([]byte, error)
}

// SignedCatalogSource is a source that can do both the catalog and signature
// reads. The dir source satisfies it; unsigned CatalogSources do not.
type SignedCatalogSource interface {
	CatalogSource
	SignatureSource
}

// ReadSignature reads <dir>/index.json.sig with the same symlink-refusing,
// size-bounded discipline as every other dir-source read (catalogReadBounded).
func (s *dirCatalogSource) ReadSignature() ([]byte, error) {
	return catalogReadBounded(filepath.Join(s.dir, "index.json.sig"))
}

// ─── trust store (key ring + mode, plan §4) ──────────────────────────────────

// TrustKey is a parsed, not-yet-validated trust-ring entry. (The base64 key-file
// loader / baked-literal wiring is a later integration slice; this slice takes
// already-decoded keys.)
type TrustKey struct {
	KeyID     string
	Alg       string
	PublicKey ed25519.PublicKey
}

// TrustStore is an immutable key ring (key_id → ed25519 public key) plus the
// active enforcement mode. Built once at startup; lookups are pure.
type TrustStore struct {
	keys map[string]ed25519.PublicKey
	mode VerifyMode
}

// NewTrustStore builds a TrustStore, enforcing the §4.1.1 construction
// invariants fail-closed: every key is ed25519 and EXACTLY ed25519.PublicKeySize
// bytes, every key_id is bounded and unique, and the ring is non-empty in
// enforce mode. The length check is load-bearing: ed25519.Verify PANICS on a
// wrong-length key, so an invalid key must be rejected here and can NEVER reach
// Verify. Any violation returns a non-nil error (the caller refuses to boot).
func NewTrustStore(keys []TrustKey, mode VerifyMode) (TrustStore, error) {
	ring := make(map[string]ed25519.PublicKey, len(keys))
	for i := range keys {
		k := keys[i]
		if err := catalogValidateID("trust key_id", k.KeyID); err != nil {
			return TrustStore{}, err
		}
		if k.Alg != catalogSigAlg {
			return TrustStore{}, fmt.Errorf("release catalog: trust key %q: unsupported alg %q (only %q)", k.KeyID, k.Alg, catalogSigAlg)
		}
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return TrustStore{}, fmt.Errorf("release catalog: trust key %q: public key is %d bytes, want %d", k.KeyID, len(k.PublicKey), ed25519.PublicKeySize)
		}
		if _, dup := ring[k.KeyID]; dup {
			return TrustStore{}, fmt.Errorf("release catalog: duplicate trust key_id %q", k.KeyID)
		}
		// Defensive copy: keep the ring immutable and unaliased from caller
		// memory. A future key-file loader may decode many keys through a
		// reusable buffer; storing the slice directly would let a later in-place
		// mutation silently swap which key verifies, bypassing the checks above.
		pub := make(ed25519.PublicKey, len(k.PublicKey))
		copy(pub, k.PublicKey)
		ring[k.KeyID] = pub
	}
	if mode == VerifyEnforce && len(ring) == 0 {
		return TrustStore{}, errors.New("release catalog: trust ring is empty in enforce mode (an empty allowlist trusts nothing)")
	}
	return TrustStore{keys: ring, mode: mode}, nil
}

// Mode returns the store's enforcement mode.
func (t TrustStore) Mode() VerifyMode { return t.mode }

func (t TrustStore) lookup(keyID string) (ed25519.PublicKey, bool) {
	k, ok := t.keys[keyID]
	return k, ok
}

// ─── signature envelope (detached sidecar, plan §3.1) ────────────────────────

type catalogSigEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Alg           string `json:"alg"`
	KeyID         string `json:"key_id"`
	Sig           string `json:"sig"`
}

// parseSigEnvelope validates the UNTRUSTED envelope shape and returns the
// selected key_id and the decoded 64-byte signature. It performs NO verification
// (it only selects the key and extracts the signature bytes). Unknown additive
// fields are ignored (forward-compat); the major is gated like the index.
func parseSigEnvelope(sigBytes []byte) (keyID string, sig []byte, err error) {
	var env catalogSigEnvelope
	if e := json.Unmarshal(sigBytes, &env); e != nil {
		return "", nil, fmt.Errorf("%w: %v", errSigMalformed, e)
	}
	if e := catalogCheckSchemaMajor("signature envelope", env.SchemaVersion); e != nil {
		return "", nil, e
	}
	if env.Alg != catalogSigAlg {
		return "", nil, fmt.Errorf("%w: %q", errSigAlg, env.Alg)
	}
	if e := catalogValidateID("signature key_id", env.KeyID); e != nil {
		return "", nil, fmt.Errorf("%w: %v", errSigMalformed, e)
	}
	raw, e := base64.StdEncoding.DecodeString(env.Sig)
	if e != nil {
		return "", nil, fmt.Errorf("%w: sig is not std-base64: %v", errSigMalformed, e)
	}
	if len(raw) != ed25519.SignatureSize {
		return "", nil, fmt.Errorf("%w: sig is %d bytes, want %d", errSigMalformed, len(raw), ed25519.SignatureSize)
	}
	return env.KeyID, raw, nil
}

// ─── verifying loader ────────────────────────────────────────────────────────

// LoadVerifiedCatalog reads the index ONCE, verifies those exact bytes against
// the TrustStore per its mode (plan §5/§5.0), then hands the SAME buffer to the
// shared loadCatalogFromIndexBytes builder. There is no re-read after
// verification — the verified buffer is the parsed buffer.
func LoadVerifiedCatalog(src SignedCatalogSource, trust TrustStore) (*Catalog, error) {
	idxBytes, err := src.ReadIndex()
	if err != nil {
		return nil, fmt.Errorf("release catalog: read index: %w", err)
	}
	if err := verifyIndexSignature(idxBytes, src, trust); err != nil {
		return nil, err
	}
	return loadCatalogFromIndexBytes(idxBytes, src)
}

// handleSignatureReadError maps a failed ReadSignature into the mode-correct
// outcome (plan §6): a MISSING signature loads under permissive (returns nil to
// proceed) but rejects under enforce; a present-but-unreadable signature
// (permission/oversize from a non-dir source) is never permissive-degradable and
// fails closed in all modes. Flattened (early returns) to keep nesting shallow.
func handleSignatureReadError(err error, mode VerifyMode) error {
	if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("release catalog: read signature: %w", err)
	}
	if mode != VerifyPermissive {
		return fmt.Errorf("%w (enforce mode)", errSigMissing)
	}
	if logger != nil {
		logger.Printf("release catalog: UNSIGNED catalog loaded (permissive mode); no index signature present")
	}
	return nil
}

// verifyIndexSignature applies the trust gate to the already-read index bytes.
// It returns nil to PROCEED (verified, or intentionally skipped) and a non-nil
// error to REJECT fail-closed. Mode semantics (plan §6):
//   - disabled:   skip verification (break-glass).
//   - enforce:    a MISSING or INVALID signature → reject.
//   - permissive: a MISSING signature → load with a warning; INVALID → reject.
func verifyIndexSignature(idxBytes []byte, src SignatureSource, trust TrustStore) error {
	if trust.mode == VerifyDisabled {
		if logger != nil {
			logger.Printf("release catalog: signature verification DISABLED (break-glass); loading without verifying")
		}
		return nil
	}

	sigBytes, err := src.ReadSignature()
	if err != nil {
		// nil ⇒ proceed (permissive + missing); non-nil ⇒ reject fail-closed.
		return handleSignatureReadError(err, trust.mode)
	}

	// Bound the signature bytes in the loader too — not only in the dir source —
	// so every SignatureSource is covered (plan §5.2 / FA13).
	if len(sigBytes) > catalogMaxReadBytes {
		return fmt.Errorf("%w (%d > %d)", errSigOversize, len(sigBytes), catalogMaxReadBytes)
	}

	keyID, sig, err := parseSigEnvelope(sigBytes)
	if err != nil {
		return err
	}
	// keyID is already validated to bounded printable ASCII by parseSigEnvelope,
	// so it is safe to embed in errors/logs (no CWE-117 vector).
	pub, ok := trust.lookup(keyID)
	if !ok {
		return fmt.Errorf("%w: %q", errSigUntrusted, keyID)
	}
	// pub is guaranteed ed25519.PublicKeySize by NewTrustStore — Verify cannot panic.
	if !ed25519.Verify(pub, idxBytes, sig) {
		return fmt.Errorf("%w: key_id %q", errSigVerify, keyID)
	}
	if logger != nil {
		logger.Printf("release catalog: signature VERIFIED (key_id=%q)", sanitizeLog(keyID))
	}
	return nil
}
