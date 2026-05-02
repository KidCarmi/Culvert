package main

// D1.4 — backup encryption.
//
// Optional AES-256-GCM encryption of the D1.3a tar.gz backup envelope.
// Compress first (existing path), then encrypt the whole compressed blob
// with a single GCM seal. The 43-byte header is bound to the ciphertext
// via AAD so any header tampering — including an iteration-count
// downgrade — fails authentication.
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
// Restore detection: the magic bytes "CV" (0x43 0x56) cannot collide
// with gzip's magic (0x1F 0x8B), so the restore reader can sniff the
// first eight bytes to choose between the encrypted path and the
// existing D1.3a unencrypted tar.gz path.
//
// Wrong-passphrase vs. tamper: AES-GCM's Open returns the same error
// class for both. We surface a single opaque error so a malicious
// caller cannot distinguish the two via the response. Header-level
// errors (bad magic, unknown version, KDF/cipher id) report
// specifically because they cannot leak passphrase information.

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

const (
	backupEncMagic        = "CVRTBK01"
	backupEncVersion      = byte(0x01)
	backupEncKDFPBKDF2    = byte(0x01)
	backupEncCipherAESGCM = byte(0x01)
	backupEncKDFIters     = 600_000
	backupEncSaltLen      = 16
	backupEncNonceLen     = 12
	backupEncMagicLen     = 8
	backupEncHdrLen       = 8 + 1 + 1 + 4 + 16 + 1 + 12 // = 43
	backupEncMinIters     = 100_000                     // refuse weakened headers
	backupEncTagLen       = 16

	backupPassphraseEnv    = "CULVERT_BACKUP_PASSPHRASE"
	backupPassphraseMinLen = 12 // warn (do not enforce) below this
)

// errBackupDecryptOpaque is the single error surfaced for wrong-passphrase
// AND tampered ciphertext. AES-GCM's Open cannot distinguish the two; we
// present them identically so an attacker has no oracle.
var errBackupDecryptOpaque = errors.New("backup decrypt failed (invalid passphrase or tampered backup)")

// isEncryptedBackupBlob returns true iff prefix begins with the D1.4
// magic. Used by the restore reader to decide between the encrypted
// path and the D1.3a unencrypted tar.gz path.
func isEncryptedBackupBlob(prefix []byte) bool {
	if len(prefix) < backupEncMagicLen {
		return false
	}
	return string(prefix[:backupEncMagicLen]) == backupEncMagic
}

// encryptBackupBlob seals plaintext (a compressed D1.3a tar.gz) under
// the given passphrase. Generates a fresh salt and nonce, derives the
// AES-256 key via PBKDF2-SHA256, and seals with the header as AAD.
// Returns the on-disk blob (header || ciphertext+tag).
//
// Memory: peak usage is ~plaintext+ciphertext (≈ 2× compressed-tarball
// size). Acceptable for one-shot admin operations on the backup sizes
// CLAUDE.md documents (well under 100 MB). Future v2 may switch to
// chunked AEAD for streaming.
func encryptBackupBlob(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, backupEncSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("backup encrypt: salt gen: %w", err)
	}
	nonce := make([]byte, backupEncNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("backup encrypt: nonce gen: %w", err)
	}

	key := pbkdf2.Key([]byte(passphrase), salt, backupEncKDFIters, 32, sha256.New)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup encrypt: cipher init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup encrypt: gcm init: %w", err)
	}

	hdr := buildBackupEncHeader(salt, nonce, backupEncKDFIters)
	ciphertext := gcm.Seal(nil, nonce, plaintext, hdr)

	out := make([]byte, 0, len(hdr)+len(ciphertext))
	out = append(out, hdr...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptBackupBlob parses the header, derives the key, and opens the
// ciphertext using the header as AAD. Returns plaintext or
// errBackupDecryptOpaque on any wrong-key or authentication failure.
// Header-level validation errors (bad magic, version, ids, length,
// iter floor) are returned as their own non-opaque errors because they
// cannot leak passphrase information.
func decryptBackupBlob(blob []byte, passphrase string) ([]byte, error) {
	hdr, ciphertext, err := parseBackupEncHeader(blob)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < backupEncTagLen {
		return nil, errBackupDecryptOpaque
	}

	iters := int(binary.BigEndian.Uint32(hdr[10:14]))
	salt := hdr[14 : 14+backupEncSaltLen]
	nonce := hdr[31 : 31+backupEncNonceLen]

	key := pbkdf2.Key([]byte(passphrase), salt, iters, 32, sha256.New)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errBackupDecryptOpaque
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errBackupDecryptOpaque
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, hdr)
	if err != nil {
		return nil, errBackupDecryptOpaque
	}
	return plaintext, nil
}

// buildBackupEncHeader serializes the 43-byte fixed header. Used as
// AAD during seal and as the AAD-input again during open. iters is
// uint32 so the binary.PutUint32 call needs no conversion — passing a
// signed int and converting trips gosec G115.
func buildBackupEncHeader(salt, nonce []byte, iters uint32) []byte {
	hdr := make([]byte, 0, backupEncHdrLen)
	hdr = append(hdr, []byte(backupEncMagic)...)
	hdr = append(hdr, backupEncVersion, backupEncKDFPBKDF2)
	var iterBuf [4]byte
	binary.BigEndian.PutUint32(iterBuf[:], iters)
	hdr = append(hdr, iterBuf[:]...)
	hdr = append(hdr, salt...)
	hdr = append(hdr, backupEncCipherAESGCM)
	hdr = append(hdr, nonce...)
	return hdr
}

// parseBackupEncHeader validates the magic / version / KDF id / cipher
// id / iter floor and returns (header, ciphertext, error). Header-level
// errors are non-opaque (they cannot leak passphrase information).
func parseBackupEncHeader(blob []byte) (hdr, ciphertext []byte, err error) {
	if len(blob) < backupEncHdrLen {
		return nil, nil, fmt.Errorf("backup decrypt: blob too short for header (%d < %d)", len(blob), backupEncHdrLen)
	}
	if string(blob[:backupEncMagicLen]) != backupEncMagic {
		return nil, nil, fmt.Errorf("backup decrypt: bad magic (not a Culvert encrypted backup)")
	}
	if blob[8] != backupEncVersion {
		return nil, nil, fmt.Errorf("backup decrypt: unsupported version %d (expected %d)", blob[8], backupEncVersion)
	}
	if blob[9] != backupEncKDFPBKDF2 {
		return nil, nil, fmt.Errorf("backup decrypt: unsupported KDF id %d", blob[9])
	}
	iters := int(binary.BigEndian.Uint32(blob[10:14]))
	if iters < backupEncMinIters {
		return nil, nil, fmt.Errorf("backup decrypt: KDF iterations %d below minimum %d", iters, backupEncMinIters)
	}
	if blob[30] != backupEncCipherAESGCM {
		return nil, nil, fmt.Errorf("backup decrypt: unsupported cipher id %d", blob[30])
	}
	hdr = blob[:backupEncHdrLen]
	ciphertext = blob[backupEncHdrLen:]
	return hdr, ciphertext, nil
}

// zeroBytes best-effort wipes a byte slice. Go's GC offers no real
// guarantee that this memory isn't already mirrored elsewhere, but we
// do the right thing within stdlib semantics.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
