package spool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/KidCarmi/Culvert/internal/secret"
)

// The spool encrypts every record at rest with authenticated encryption
// (AES-256-GCM), the same primitive the repository's audited codecs use
// (internal/ca, internal/backupcrypt). The data-encryption key (DEK) is derived
// ONCE per spool open and never leaves this package: it is sealed under the KEK
// via internal/secret (the opaque ADR-0007 boundary) and, on open, unsealed
// inside secret.Sealed.WithPlaintext just long enough to build the cipher.AEAD —
// after which the raw DEK bytes are zeroized and only the AEAD's internal key
// schedule survives, exactly as internal/alerts caches its GCM handle. There is
// NO exported accessor that yields KEK bytes, DEK bytes, a raw nonce, or a
// plaintext buffer. There is NO plaintext fallback: a missing/unopenable key is a
// commit FAILURE, never a cleartext write.

const (
	dekLen        = 32 // AES-256
	spoolNonceLen = 12 // GCM standard nonce
	keyIDLen      = 8  // bytes of the DEK fingerprint recorded in a segment header
	dekFileName   = "dek.sealed"
)

var (
	// errEncryptionUnavailable — the KEK is absent, or a sealed DEK cannot be
	// opened. Mapped to ReasonEventEncryptionUnavailable; never a plaintext write.
	errEncryptionUnavailable = errors.New("spool: encryption key unavailable")
	// errDecryptOpaque — any record decrypt failure (wrong key OR tamper). A
	// single opaque error, no oracle. Mapped to ReasonEventSpoolCorrupt.
	errDecryptOpaque = errors.New("spool: record integrity check failed")
)

// cryptor performs per-record authenticated encryption under a DEK bound to the
// configured KEK. It is safe for concurrent use (cipher.AEAD is stateless across
// Seal/Open once constructed and each call carries its own nonce).
type cryptor struct {
	aead  cipher.AEAD
	keyID [keyIDLen]byte
}

// openCryptor loads or creates the sealed DEK under keyDir and returns a cryptor.
// With a nil KEK provider it fails closed (errEncryptionUnavailable) — the spool
// never falls back to plaintext. A DEK file that exists is opened; otherwise a
// fresh random DEK is generated, sealed under the KEK, and durably written.
func openCryptor(be Backend, keyPath string, kek *secret.Provider) (*cryptor, error) {
	if kek == nil {
		return nil, errEncryptionUnavailable
	}
	if err := secret.ValidateProvider(kek); err != nil {
		return nil, errEncryptionUnavailable
	}
	sealed, err := be.ReadFile(keyPath)
	if err == nil && len(sealed) > 0 {
		return cryptorFromSealed(sealed, kek)
	}
	// No existing DEK: generate, seal, persist, then build.
	dek := make([]byte, dekLen)
	if _, rerr := rand.Read(dek); rerr != nil {
		return nil, errEncryptionUnavailable
	}
	env, serr := secret.Seal(dek, kek)
	if serr != nil {
		zero(dek)
		return nil, errEncryptionUnavailable
	}
	if werr := be.AtomicReplace(keyPath, env, 0o600); werr != nil {
		zero(dek)
		return nil, werr
	}
	c, cerr := cryptorFromDEK(dek)
	zero(dek)
	return c, cerr
}

// cryptorFromSealed opens a sealed DEK envelope under the KEK and builds a cryptor
// inside the scoped-plaintext window so the raw DEK is zeroized on return.
func cryptorFromSealed(env []byte, kek *secret.Provider) (*cryptor, error) {
	s, err := secret.Open(env, kek)
	if err != nil {
		return nil, errEncryptionUnavailable
	}
	var out *cryptor
	perr := s.WithPlaintext(func(dek []byte) error {
		c, cerr := cryptorFromDEK(dek)
		if cerr != nil {
			return cerr
		}
		out = c
		return nil
	})
	if perr != nil {
		return nil, errEncryptionUnavailable
	}
	return out, nil
}

// cryptorFromDEK builds the AEAD and the stable key id from raw DEK bytes. The
// caller retains ownership of dek and zeroizes it; the AEAD keeps only its
// internal (unexported) key schedule.
func cryptorFromDEK(dek []byte) (*cryptor, error) {
	if len(dek) != dekLen {
		return nil, errEncryptionUnavailable
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, errEncryptionUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errEncryptionUnavailable
	}
	c := &cryptor{aead: aead}
	// keyID is a one-way fingerprint of the DEK (domain-separated), used to tie a
	// segment to the key that wrote it. It never reveals the DEK.
	sum := sha256.Sum256(append([]byte("mcp-spool-keyid\x00"), dek...))
	copy(c.keyID[:], sum[:keyIDLen])
	return c, nil
}

// seal encrypts plaintext, authenticating aad, and returns the fresh random nonce
// and the ciphertext (which includes the GCM tag). The nonce is generated here so
// no caller can reuse one.
func (c *cryptor) seal(aad, plaintext []byte) (nonce, ciphertext []byte, err error) {
	nonce = make([]byte, spoolNonceLen)
	if _, rerr := rand.Read(nonce); rerr != nil {
		return nil, nil, errEncryptionUnavailable
	}
	ciphertext = c.aead.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// open decrypts ciphertext, verifying aad and the GCM tag. Any failure — wrong
// key, tampered header (aad), tampered ciphertext, truncated tag — returns the
// single opaque error with no distinguishing detail.
func (c *cryptor) open(aad, nonce, ciphertext []byte) ([]byte, error) {
	if len(nonce) != spoolNonceLen {
		return nil, errDecryptOpaque
	}
	pt, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errDecryptOpaque
	}
	return pt, nil
}

// zero wipes a byte slice (best-effort DEK hygiene at the call sites that own raw
// key bytes; secret.Sealed already zeroizes its own buffer).
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
