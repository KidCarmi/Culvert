// Package sealbox is the recipient-public-key sealing leaf for support-bundle
// export (M4 E2E). It wraps NaCl anonymous sealed boxes (X25519 key agreement +
// XSalsa20-Poly1305 AEAD via golang.org/x/crypto/nacl/box) in a fixed, versioned
// envelope so a bundle can be sealed to a recipient's PUBLIC key on the appliance
// and opened ONLY by the holder of the matching private key. The appliance never
// holds a decryption capability — true end-to-end confidentiality to (e.g.) TAC.
//
// On-disk format:
//
//	offset  size  field       notes
//	------  ----  ----------  ---------------------------------
//	  0       8   magic       "CVRTSB01" (ASCII)
//	  8       1   version     0x01
//	  9      ..   sealed box  box.SealAnonymous output (ephemeral pub || ciphertext || tag)
//
// The magic distinguishes a sealed export from the passphrase envelope
// ("CVRTBK01") and from a plain gzip tar, so a recipient tool can sniff the first
// bytes. Anonymous boxes carry no sender identity by design (the operator chooses
// the recipient key out-of-band); integrity/authenticity of the CONTENTS still
// comes from the bundle manifest's own hashes.
package sealbox

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const (
	// Magic is the 8-byte ASCII envelope magic.
	Magic = "CVRTSB01"
	// MagicLen is the prefix length a reader peeks to classify a blob.
	MagicLen = 8
	// Version is the current envelope version byte.
	Version = byte(0x01)
	// KeyLen is the X25519 public/private key length.
	KeyLen = 32
	// hdrLen is magic + version.
	hdrLen = MagicLen + 1
	// sealOverhead is box.AnonymousOverhead (ephemeral pubkey + Poly1305 tag).
	sealOverhead = box.AnonymousOverhead
)

// ErrOpenFailed is the single opaque error for a decrypt/auth failure (wrong key
// or tampered ciphertext) — it never distinguishes the two, so a caller gets no
// oracle. Header-level problems (bad magic/version/length) report specifically
// because they leak no key information.
var ErrOpenFailed = errors.New("sealed bundle open failed (wrong key or tampered)")

// IsSealed reports whether prefix begins with the sealbox magic.
func IsSealed(prefix []byte) bool {
	return len(prefix) >= MagicLen && string(prefix[:MagicLen]) == Magic
}

// Seal wraps plaintext for recipientPub. randSource defaults to crypto/rand when
// nil (tests may inject a deterministic reader).
func Seal(plaintext []byte, recipientPub *[KeyLen]byte, randSource io.Reader) ([]byte, error) {
	if recipientPub == nil {
		return nil, errors.New("sealbox: nil recipient key")
	}
	if randSource == nil {
		randSource = rand.Reader
	}
	out := make([]byte, 0, hdrLen+len(plaintext)+sealOverhead)
	out = append(out, Magic...)
	out = append(out, Version)
	sealed, err := box.SealAnonymous(nil, plaintext, recipientPub, randSource)
	if err != nil {
		return nil, err
	}
	return append(out, sealed...), nil
}

// Open reverses Seal using the recipient's key pair. It validates the header, then
// opens the anonymous box; any auth/key failure returns ErrOpenFailed.
func Open(blob []byte, recipientPub, recipientPriv *[KeyLen]byte) ([]byte, error) {
	if recipientPub == nil || recipientPriv == nil {
		return nil, errors.New("sealbox: nil key")
	}
	if len(blob) < hdrLen {
		return nil, errors.New("sealbox: short blob")
	}
	if string(blob[:MagicLen]) != Magic {
		return nil, errors.New("sealbox: bad magic")
	}
	if blob[MagicLen] != Version {
		return nil, errors.New("sealbox: unsupported version")
	}
	pt, ok := box.OpenAnonymous(nil, blob[hdrLen:], recipientPub, recipientPriv)
	if !ok {
		return nil, ErrOpenFailed
	}
	return pt, nil
}

// GenerateKey returns a fresh X25519 key pair (public, private). Recipients use it
// to publish a public key and keep the private key; tests use it end-to-end.
func GenerateKey() (pub, priv *[KeyLen]byte, err error) {
	return box.GenerateKey(rand.Reader)
}
