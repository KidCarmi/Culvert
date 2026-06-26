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

// TrustStore is an immutable key ring (key_id → ed25519 public key) plus an
// OPTIONAL Sigstore-identity verifier (P2b) and the active enforcement mode. Built
// once at startup; lookups are pure. A catalog is accepted iff it verifies under at
// least one CONFIGURED scheme (ed25519 ring non-empty OR sigstore != nil).
type TrustStore struct {
	keys     map[string]ed25519.PublicKey
	sigstore *sigstoreVerifier // nil ⇒ Sigstore scheme not configured
	mode     VerifyMode
}

// NewTrustStore builds an ed25519-only TrustStore (the P1.3 surface). It is a thin
// wrapper over NewTrustStoreWithSigstore(keys, mode, nil) so every existing caller
// keeps the same fail-closed semantics (empty ring in enforce mode is rejected).
func NewTrustStore(keys []TrustKey, mode VerifyMode) (TrustStore, error) {
	return NewTrustStoreWithSigstore(keys, mode, nil)
}

// NewTrustStoreWithSigstore builds a TrustStore that may carry BOTH schemes. It
// enforces the §4.1.1 ed25519 construction invariants fail-closed: every key is
// ed25519 and EXACTLY ed25519.PublicKeySize bytes, every key_id is bounded and
// unique. The length check is load-bearing: ed25519.Verify PANICS on a
// wrong-length key, so an invalid key must be rejected here and can NEVER reach
// Verify.
//
// Enforce-mode non-emptiness is satisfied by EITHER scheme: in enforce mode at
// least one trusted scheme must be configured (a non-empty ed25519 ring OR a
// Sigstore verifier), otherwise the store trusts nothing and boot is refused.
func NewTrustStoreWithSigstore(keys []TrustKey, mode VerifyMode, ss *sigstoreVerifier) (TrustStore, error) {
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
	if mode == VerifyEnforce && len(ring) == 0 && ss == nil {
		return TrustStore{}, errors.New("release catalog: no trusted scheme configured in enforce mode (an empty allowlist trusts nothing)")
	}
	return TrustStore{keys: ring, sigstore: ss, mode: mode}, nil
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

// schemeOutcome is the tri-state result of consulting one configured trust scheme
// for its sidecar artifact. It is the heart of the downgrade-safe composition rule
// (plan §"Scheme selection & precedence"):
//
//   - schemeAbsent: the artifact read returned fs.ErrNotExist ONLY. The other
//     scheme MAY be consulted (fall-through). This is the single permitted bypass.
//   - schemeAccept: the artifact was present AND verified. Accept the catalog.
//   - schemeReject: the artifact was present (readable OR unreadable) but did not
//     verify. The catalog is rejected — the other scheme is NEVER consulted as a
//     fallback (artifact-owns-outcome). Closes the strip-one-sig downgrade vector.
type schemeOutcome int

const (
	schemeAbsent schemeOutcome = iota
	schemeAccept
	schemeReject
)

// verifyIndexSignature applies the trust gate to the already-read index bytes,
// composing the configured schemes per the exact precedence rule. It returns nil
// to PROCEED (verified, or intentionally skipped) and a non-nil error to REJECT
// fail-closed. Mode semantics (plan §6):
//   - disabled:   skip verification (break-glass).
//   - enforce:    a MISSING-for-all-schemes or INVALID signature → reject.
//   - permissive: MISSING for all schemes → load with a warning; INVALID → reject.
//
// Precedence: Sigstore identity (if configured) is consulted first; only a true
// fs.ErrNotExist on its sidecar falls through to ed25519; only a true fs.ErrNotExist
// there falls through to the mode-based no-artifact decision.
func verifyIndexSignature(idxBytes []byte, src SignatureSource, trust TrustStore) error {
	if trust.mode == VerifyDisabled {
		if logger != nil {
			logger.Printf("release catalog: signature verification DISABLED (break-glass); loading without verifying")
		}
		return nil
	}

	// Scheme 1: Sigstore identity (keyless), when configured.
	if trust.sigstore != nil {
		ss, _ := src.(sigstoreSource) // nil if the source can't supply a .sigstore
		switch outcome, err := verifySigstoreScheme(idxBytes, ss, trust.sigstore); outcome {
		case schemeAccept:
			return nil
		case schemeReject:
			return err
		case schemeAbsent:
			// fall through to ed25519
		}
	}

	// Scheme 2: ed25519 detached signature, when configured.
	if len(trust.keys) > 0 {
		switch outcome, err := verifyEd25519Scheme(idxBytes, src, trust); outcome {
		case schemeAccept:
			return nil
		case schemeReject:
			return err
		case schemeAbsent:
			// fall through to the no-artifact decision
		}
	}

	// Scheme 3: no artifact present for any configured scheme.
	return noArtifactOutcome(trust.mode)
}

// verifySigstoreScheme consults the .sigstore sidecar. A source that cannot supply
// one (src == nil) is treated as absent (fall-through), never a bypass: with no
// other scheme satisfied, the no-artifact decision still fails closed in enforce.
func verifySigstoreScheme(idxBytes []byte, src sigstoreSource, sv *sigstoreVerifier) (schemeOutcome, error) {
	if src == nil {
		return schemeAbsent, nil
	}
	bundleBytes, err := src.ReadSigstoreBundle()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return schemeAbsent, nil
		}
		return schemeReject, fmt.Errorf("release catalog: read sigstore bundle: %w", err)
	}
	if len(bundleBytes) > catalogMaxReadBytes {
		return schemeReject, fmt.Errorf("%w (%d > %d)", errSigstoreOversize, len(bundleBytes), catalogMaxReadBytes)
	}
	if err := sv.verifyIndexBundle(idxBytes, bundleBytes); err != nil {
		return schemeReject, err
	}
	if logger != nil {
		logger.Printf("release catalog: Sigstore identity signature VERIFIED")
	}
	return schemeAccept, nil
}

// verifyEd25519Scheme consults the index.json.sig detached-signature sidecar.
func verifyEd25519Scheme(idxBytes []byte, src SignatureSource, trust TrustStore) (schemeOutcome, error) {
	sigBytes, err := src.ReadSignature()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return schemeAbsent, nil
		}
		return schemeReject, fmt.Errorf("release catalog: read signature: %w", err)
	}
	// Bound the signature bytes in the loader too — not only in the dir source —
	// so every SignatureSource is covered (plan §5.2 / FA13).
	if len(sigBytes) > catalogMaxReadBytes {
		return schemeReject, fmt.Errorf("%w (%d > %d)", errSigOversize, len(sigBytes), catalogMaxReadBytes)
	}
	keyID, sig, err := parseSigEnvelope(sigBytes)
	if err != nil {
		return schemeReject, err
	}
	// keyID is already validated to bounded printable ASCII by parseSigEnvelope,
	// so it is safe to embed in errors/logs (no CWE-117 vector).
	pub, ok := trust.lookup(keyID)
	if !ok {
		return schemeReject, fmt.Errorf("%w: %q", errSigUntrusted, keyID)
	}
	// pub is guaranteed ed25519.PublicKeySize by NewTrustStore — Verify cannot panic.
	if !ed25519.Verify(pub, idxBytes, sig) {
		return schemeReject, fmt.Errorf("%w: key_id %q", errSigVerify, keyID)
	}
	if logger != nil {
		logger.Printf("release catalog: signature VERIFIED (key_id=%q)", sanitizeLog(keyID))
	}
	return schemeAccept, nil
}

// noArtifactOutcome is the mode-based decision when NO configured scheme found its
// sidecar (every present scheme returned fs.ErrNotExist). Permissive loads with a
// warning; enforce rejects. (Disabled is handled earlier in verifyIndexSignature.)
func noArtifactOutcome(mode VerifyMode) error {
	if mode == VerifyPermissive {
		if logger != nil {
			logger.Printf("release catalog: UNSIGNED catalog loaded (permissive mode); no signature present for any configured scheme")
		}
		return nil
	}
	return fmt.Errorf("%w (enforce mode)", errSigMissing)
}
