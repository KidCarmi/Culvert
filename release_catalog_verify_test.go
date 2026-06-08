package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

// ─── signed in-memory source ─────────────────────────────────────────────────

// memSignedSource is an in-memory SignedCatalogSource. It counts ReadIndex calls
// so the single-read contract (P1.3 §5.0) can be asserted, and lets a test force
// a missing signature via sigErr (fs.ErrNotExist).
type memSignedSource struct {
	index      []byte
	manifests  map[string][]byte
	sig        []byte
	sigErr     error
	indexReads int
}

func (m *memSignedSource) ReadIndex() ([]byte, error) {
	m.indexReads++
	return m.index, nil
}

func (m *memSignedSource) ReadManifest(ref string) ([]byte, error) {
	b, ok := m.manifests[ref]
	if !ok {
		return nil, fmt.Errorf("memSignedSource: no manifest %q", ref)
	}
	return b, nil
}

func (m *memSignedSource) ReadSignature() ([]byte, error) {
	if m.sigErr != nil {
		return nil, m.sigErr
	}
	return m.sig, nil
}

func sigEnvelopeBytes(t *testing.T, alg, keyID string, sig []byte) []byte {
	t.Helper()
	b, err := json.Marshal(catalogSigEnvelope{
		SchemaVersion: 1,
		Alg:           alg,
		KeyID:         keyID,
		Sig:           base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signedSource wires a valid 2-release catalog (reusing the P1.2 validSource
// fixture), signs its exact index bytes with a fresh ed25519 key, and returns a
// matching single-key TrustStore (key_id "k1") in the requested mode.
func signedSource(t *testing.T, mode VerifyMode) (*memSignedSource, TrustStore) {
	t.Helper()
	const keyID = "k1"
	pub, priv, err := ed25519.GenerateKey(nil) // nil ⇒ crypto/rand
	if err != nil {
		t.Fatal(err)
	}
	base := validSource()
	idx := append([]byte(nil), base.index...)
	sig := ed25519.Sign(priv, idx)
	src := &memSignedSource{
		index:     idx,
		manifests: base.manifests,
		sig:       sigEnvelopeBytes(t, catalogSigAlg, keyID, sig),
	}
	ts, err := NewTrustStore([]TrustKey{{KeyID: keyID, Alg: catalogSigAlg, PublicKey: pub}}, mode)
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	return src, ts
}

// ─── happy path ──────────────────────────────────────────────────────────────

func TestVerify_HappyPath(t *testing.T) {
	src, ts := signedSource(t, VerifyEnforce)
	c, err := LoadVerifiedCatalog(src, ts)
	if err != nil {
		t.Fatalf("LoadVerifiedCatalog: unexpected error: %v", err)
	}
	if len(c.byReleaseID) != 2 || len(c.byPinnedRef) != 2 {
		t.Fatalf("verified catalog not fully built: byReleaseID=%d byPinnedRef=%d", len(c.byReleaseID), len(c.byPinnedRef))
	}
}

// The verified path reads the index exactly once — the verified buffer is the
// parsed buffer, no TOCTOU re-read (B1 / §5.0).
func TestVerify_SingleReadIndexCall(t *testing.T) {
	src, ts := signedSource(t, VerifyEnforce)
	if _, err := LoadVerifiedCatalog(src, ts); err != nil {
		t.Fatalf("LoadVerifiedCatalog: %v", err)
	}
	if src.indexReads != 1 {
		t.Fatalf("ReadIndex called %d times; want exactly 1 (single-read contract)", src.indexReads)
	}
}

// ─── tamper / raw-byte ───────────────────────────────────────────────────────

func TestVerify_TamperedIndexRejects(t *testing.T) {
	src, ts := signedSource(t, VerifyEnforce)
	src.index = append(src.index, ' ') // mutate AFTER signing
	if _, err := LoadVerifiedCatalog(src, ts); !errors.Is(err, errSigVerify) {
		t.Fatalf("tampered index: err = %v; want errSigVerify", err)
	}
}

// Re-serializing the index to semantically-identical-but-different bytes breaks
// the signature — proves verification is over the RAW bytes (no canonicalization).
func TestVerify_RawByteReindentRejects(t *testing.T) {
	src, ts := signedSource(t, VerifyEnforce)
	var obj map[string]any
	if err := json.Unmarshal(src.index, &obj); err != nil {
		t.Fatal(err)
	}
	reindented, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(reindented) == string(src.index) {
		t.Skip("reindent produced identical bytes; nothing to prove")
	}
	src.index = reindented
	if _, err := LoadVerifiedCatalog(src, ts); !errors.Is(err, errSigVerify) {
		t.Fatalf("reindented index: err = %v; want errSigVerify", err)
	}
}

// ─── trust store / key validation ────────────────────────────────────────────

// A wrong-length public key is rejected at construction — it must NEVER reach
// ed25519.Verify (which panics on a bad length). B2.
func TestTrustStore_BadKeyLengthDoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewTrustStore panicked on a short key: %v", r)
		}
	}()
	short := make([]byte, ed25519.PublicKeySize-1)
	if _, err := NewTrustStore([]TrustKey{{KeyID: "k", Alg: catalogSigAlg, PublicKey: short}}, VerifyEnforce); err == nil {
		t.Fatal("expected error for a public key shorter than ed25519.PublicKeySize")
	}
}

func TestTrustStore_RejectsDuplicateKeyID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewTrustStore([]TrustKey{
		{KeyID: "k1", Alg: catalogSigAlg, PublicKey: pub},
		{KeyID: "k1", Alg: catalogSigAlg, PublicKey: pub},
	}, VerifyPermissive)
	if err == nil {
		t.Fatal("expected duplicate key_id to be rejected")
	}
}

func TestTrustStore_EmptyRing(t *testing.T) {
	// Empty ring is fail-closed in enforce …
	if _, err := NewTrustStore(nil, VerifyEnforce); err == nil {
		t.Fatal("empty ring must be rejected in enforce mode")
	}
	// … but allowed in permissive/disabled (an unsigned catalog still loads).
	if _, err := NewTrustStore(nil, VerifyPermissive); err != nil {
		t.Fatalf("empty ring should be allowed in permissive: %v", err)
	}
	if _, err := NewTrustStore(nil, VerifyDisabled); err != nil {
		t.Fatalf("empty ring should be allowed in disabled: %v", err)
	}
}

// The trust ring must own its key material — mutating the caller's slice after
// construction must not affect verification (defensive copy).
func TestTrustStore_CopiesKeyMaterial(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	callerBuf := append(ed25519.PublicKey(nil), pub...) // a caller-owned buffer
	ts, err := NewTrustStore([]TrustKey{{KeyID: "k1", Alg: catalogSigAlg, PublicKey: callerBuf}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	for i := range callerBuf { // corrupt the caller's buffer AFTER construction
		callerBuf[i] ^= 0xff
	}
	base := validSource()
	sig := ed25519.Sign(priv, base.index)
	src := &memSignedSource{index: base.index, manifests: base.manifests, sig: sigEnvelopeBytes(t, catalogSigAlg, "k1", sig)}
	if _, err := LoadVerifiedCatalog(src, ts); err != nil {
		t.Fatalf("ring aliased caller memory: verification broke after the caller mutated its buffer: %v", err)
	}
}

func TestTrustStore_RejectsBadAlg(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTrustStore([]TrustKey{{KeyID: "k", Alg: "rsa", PublicKey: pub}}, VerifyEnforce); err == nil {
		t.Fatal("expected a non-ed25519 alg to be rejected")
	}
}

// ─── envelope / key selection ────────────────────────────────────────────────

func TestVerify_UnknownKeyIDRejects(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := validSource()
	sig := ed25519.Sign(priv, base.index)
	src := &memSignedSource{
		index:     base.index,
		manifests: base.manifests,
		sig:       sigEnvelopeBytes(t, catalogSigAlg, "not-in-ring", sig),
	}
	ts, err := NewTrustStore([]TrustKey{{KeyID: "k1", Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedCatalog(src, ts); !errors.Is(err, errSigUntrusted) {
		t.Fatalf("unknown key_id: err = %v; want errSigUntrusted", err)
	}
}

func TestVerify_BadAlgRejects(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	base := validSource()
	sig := ed25519.Sign(priv, base.index)
	src := &memSignedSource{
		index:     base.index,
		manifests: base.manifests,
		sig:       sigEnvelopeBytes(t, "rsa", "k1", sig), // wrong alg in the envelope
	}
	ts, err := NewTrustStore([]TrustKey{{KeyID: "k1", Alg: catalogSigAlg, PublicKey: pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedCatalog(src, ts); !errors.Is(err, errSigAlg) {
		t.Fatalf("bad alg: err = %v; want errSigAlg", err)
	}
}

// ─── modes: missing / bad signature ──────────────────────────────────────────

func TestVerify_MissingSigEnforceRejects(t *testing.T) {
	src, ts := signedSource(t, VerifyEnforce)
	src.sig, src.sigErr = nil, fs.ErrNotExist
	if _, err := LoadVerifiedCatalog(src, ts); !errors.Is(err, errSigMissing) {
		t.Fatalf("missing sig (enforce): err = %v; want errSigMissing", err)
	}
}

func TestVerify_MissingSigPermissiveLoads(t *testing.T) {
	src, ts := signedSource(t, VerifyPermissive)
	src.sig, src.sigErr = nil, fs.ErrNotExist
	c, err := LoadVerifiedCatalog(src, ts)
	if err != nil {
		t.Fatalf("missing sig (permissive) should load: %v", err)
	}
	if c == nil || len(c.byReleaseID) != 2 {
		t.Fatalf("permissive unsigned load produced an unexpected catalog: %+v", c)
	}
}

// permissive tolerates a MISSING signature, never a present-but-INVALID one.
func TestVerify_BadSigPermissiveRejects(t *testing.T) {
	src, ts := signedSource(t, VerifyPermissive)
	src.index = append(src.index, ' ') // valid envelope, but signature no longer matches
	if _, err := LoadVerifiedCatalog(src, ts); !errors.Is(err, errSigVerify) {
		t.Fatalf("bad sig (permissive) must reject: err = %v; want errSigVerify", err)
	}
}

// disabled loads without verifying — even a signature that would fail.
func TestVerify_DisabledLoadsWithoutVerify(t *testing.T) {
	src, _ := signedSource(t, VerifyEnforce)
	src.index = append(src.index, ' ') // would fail verification (trailing ws still parses)
	ts, err := NewTrustStore(nil, VerifyDisabled)
	if err != nil {
		t.Fatal(err)
	}
	c, err := LoadVerifiedCatalog(src, ts)
	if err != nil {
		t.Fatalf("disabled mode should load without verifying: %v", err)
	}
	if c == nil || len(c.byReleaseID) != 2 {
		t.Fatalf("disabled load produced an unexpected catalog: %+v", c)
	}
}
