// Package backupcrypt is the D1.4 backup-envelope cryptography leaf: optional
// AES-256-GCM encryption of the compressed tar.gz backup blob, with the fixed
// 43-byte header bound to the ciphertext via AAD so any header tampering —
// including a KDF iteration-count downgrade — fails authentication. It is a
// self-contained leaf (stdlib + golang.org/x/crypto/pbkdf2 only) extracted from
// package main per ADR-0002.
//
// On-disk format:
//
//	offset  size  field          notes
//	------  ----  -------------  ---------------------------------
//	  0       8   magic          "CVRTBK01" (ASCII)
//	  8       1   version        0x01
//	  9       1   kdf_id         0x01 = PBKDF2-SHA256
//	 10       4   kdf_iters      uint32 BE; 600000 for v1
//	 14      16   salt           random
//	 30       1   cipher_id      0x01 = AES-256-GCM
//	 31      12   nonce          random
//	 43      ..   ciphertext     compressed tar.gz, AES-GCM-sealed
//	end-16   16   tag            GCM auth tag (last 16 bytes)
//
// Restore detection: the magic bytes "CV" (0x43 0x56) cannot collide with
// gzip's magic (0x1F 0x8B), so the restore reader can sniff the first eight
// bytes to choose between the encrypted path and the existing D1.3a
// unencrypted tar.gz path.
//
// Wrong-passphrase vs. tamper: AES-GCM's Open returns the same error class for
// both. We surface a single opaque error (ErrDecryptOpaque) so a malicious
// caller cannot distinguish the two via the response. Header-level errors (bad
// magic, unknown version, KDF/cipher id) report specifically because they
// cannot leak passphrase information.
package backupcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// Exported envelope/policy constants consumed by package main (the backup,
// restore, list-backups, and CLI flag paths).
const (
	// Magic is the 8-byte ASCII envelope magic ("CVRTBK01").
	Magic = "CVRTBK01"
	// MagicLen is len(Magic) — the prefix length the restore/list readers peek.
	MagicLen = 8
	// HdrLen is the fixed serialized header length (magic+version+kdf+iters+salt+cipher+nonce).
	HdrLen = 8 + 1 + 1 + 4 + 16 + 1 + 12 // = 43
	// KDFIters is the PBKDF2-SHA256 iteration count for v1 envelopes.
	KDFIters = 600_000
	// PassphraseEnv names the env var the CLI reads the backup passphrase from.
	PassphraseEnv = "CULVERT_BACKUP_PASSPHRASE" // #nosec G101 -- env-var NAME, not a credential (NOSONAR)
	// PassphraseMinLen is the soft floor below which the CLI warns (does not enforce).
	PassphraseMinLen = 12
)

const (
	encVersion      = byte(0x01)
	encKDFPBKDF2    = byte(0x01)
	encCipherAESGCM = byte(0x01)
	encSaltLen      = 16
	encNonceLen     = 12
	encMinIters     = 100_000 // refuse weakened headers
	encTagLen       = 16
)

// ErrDecryptOpaque is the single error surfaced for wrong-passphrase AND
// tampered ciphertext. AES-GCM's Open cannot distinguish the two; we present
// them identically so an attacker has no oracle.
var ErrDecryptOpaque = errors.New("backup decrypt failed (invalid passphrase or tampered backup)")

// IsEncryptedBlob returns true iff prefix begins with the D1.4 magic. Used by
// the restore reader to decide between the encrypted path and the D1.3a
// unencrypted tar.gz path.
func IsEncryptedBlob(prefix []byte) bool {
	if len(prefix) < MagicLen {
		return false
	}
	return string(prefix[:MagicLen]) == Magic
}

// EncryptBlob seals plaintext (a compressed D1.3a tar.gz) under the given
// passphrase. Generates a fresh salt and nonce, derives the AES-256 key via
// PBKDF2-SHA256, and seals with the header as AAD. Returns the on-disk blob
// (header || ciphertext+tag).
//
// Memory: peak usage is ~plaintext+ciphertext (≈ 2× compressed-tarball size).
// Acceptable for one-shot admin operations on the backup sizes CLAUDE.md
// documents (well under 100 MB). Future v2 may switch to chunked AEAD for
// streaming.
func EncryptBlob(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, encSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("backup encrypt: salt gen: %w", err)
	}
	nonce := make([]byte, encNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("backup encrypt: nonce gen: %w", err)
	}

	key := pbkdf2.Key([]byte(passphrase), salt, KDFIters, 32, sha256.New)
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup encrypt: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup encrypt: gcm init: %w", err)
	}

	hdr := buildEncHeader(salt, nonce, KDFIters)
	ciphertext := gcm.Seal(nil, nonce, plaintext, hdr)

	out := make([]byte, 0, len(hdr)+len(ciphertext))
	out = append(out, hdr...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptBlob parses the header, derives the key, and opens the ciphertext
// using the header as AAD. Returns plaintext or ErrDecryptOpaque on any
// wrong-key or authentication failure. Header-level validation errors (bad
// magic, version, ids, length, iter floor) are returned as their own non-opaque
// errors because they cannot leak passphrase information.
func DecryptBlob(blob []byte, passphrase string) ([]byte, error) {
	hdr, ciphertext, err := parseEncHeader(blob)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < encTagLen {
		return nil, ErrDecryptOpaque
	}

	iters := int(binary.BigEndian.Uint32(hdr[10:14]))
	salt := hdr[14 : 14+encSaltLen]
	nonce := hdr[31 : 31+encNonceLen]

	key := pbkdf2.Key([]byte(passphrase), salt, iters, 32, sha256.New)
	defer ZeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptOpaque
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptOpaque
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return nil, ErrDecryptOpaque
	}
	return plaintext, nil
}

// buildEncHeader serializes the 43-byte fixed header. Used as AAD during seal
// and as the AAD-input again during open. iters is uint32 so the
// binary.PutUint32 call needs no conversion — passing a signed int and
// converting trips gosec G115.
func buildEncHeader(salt, nonce []byte, iters uint32) []byte {
	hdr := make([]byte, 0, HdrLen)
	hdr = append(hdr, []byte(Magic)...)
	hdr = append(hdr, encVersion, encKDFPBKDF2)
	var iterBuf [4]byte
	binary.BigEndian.PutUint32(iterBuf[:], iters)
	hdr = append(hdr, iterBuf[:]...)
	hdr = append(hdr, salt...)
	hdr = append(hdr, encCipherAESGCM)
	hdr = append(hdr, nonce...)
	return hdr
}

// parseEncHeader validates the magic / version / KDF id / cipher id / iter
// floor and returns (header, ciphertext, error). Header-level errors are
// non-opaque (they cannot leak passphrase information).
func parseEncHeader(blob []byte) (hdr, ciphertext []byte, err error) {
	if len(blob) < HdrLen {
		return nil, nil, fmt.Errorf("backup decrypt: blob too short for header (%d < %d)", len(blob), HdrLen)
	}
	if string(blob[:MagicLen]) != Magic {
		return nil, nil, fmt.Errorf("backup decrypt: bad magic (not a Culvert encrypted backup)")
	}
	if blob[8] != encVersion {
		return nil, nil, fmt.Errorf("backup decrypt: unsupported version %d (expected %d)", blob[8], encVersion)
	}
	if blob[9] != encKDFPBKDF2 {
		return nil, nil, fmt.Errorf("backup decrypt: unsupported KDF id %d", blob[9])
	}
	iters := int(binary.BigEndian.Uint32(blob[10:14]))
	if iters < encMinIters {
		return nil, nil, fmt.Errorf("backup decrypt: KDF iterations %d below minimum %d", iters, encMinIters)
	}
	if blob[30] != encCipherAESGCM {
		return nil, nil, fmt.Errorf("backup decrypt: unsupported cipher id %d", blob[30])
	}
	hdr = blob[:HdrLen]
	ciphertext = blob[HdrLen:]
	return hdr, ciphertext, nil
}

// ZeroBytes best-effort wipes a byte slice. Go's GC offers no real guarantee
// that this memory isn't already mirrored elsewhere, but we do the right thing
// within stdlib semantics.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
