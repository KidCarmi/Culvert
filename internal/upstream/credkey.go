package upstream

// credkey.go — the node-local credential key (`.upstream_cred_key`, 0600,
// never archived) and the AES-GCM sealing of parent-proxy passwords bound to
// their immutable entry id AND authority hash (2F contract C4/C10; RISK-003
// webhook pattern).
//
// Rules: a failed key READ never mints a key; a key is created only when the
// caller proves no v2 state and no ciphertext exist anywhere (the boot
// migration / first credential); the plaintext exists only inside the
// caller that unseals it and is discarded immediately.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFileName is the node-local credential key file, beside admin_settings.
const KeyFileName = ".upstream_cred_key"

// ErrKeyMissing reports that no key file exists.
var ErrKeyMissing = errors.New("upstream credential key: not found")

// Keyring holds the loaded node-local key.
type Keyring struct {
	key []byte
	id  string
}

// KeyID is the public identifier of the loaded key (first 16 hex of its
// SHA-256), recorded on every sealed credential.
func (k *Keyring) KeyID() string {
	if k == nil {
		return ""
	}
	return k.id
}

// OpenKey loads the key from dir. create=false is the READ path: a missing
// key is ErrKeyMissing and nothing is written. create=true mints a fresh key
// ONLY when none exists (the caller has proven no ciphertext exists).
func OpenKey(dir string, create bool) (*Keyring, error) {
	path := filepath.Join(dir, KeyFileName)
	data, err := os.ReadFile(path) // #nosec G304 -- derived from the operator-configured data dir
	switch {
	case err == nil:
		if len(data) != 32 {
			return nil, fmt.Errorf("upstream credential key: unexpected length %d (want 32)", len(data))
		}
		return newKeyring(data), nil
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("upstream credential key: read failed: %w", err)
	case !create:
		return nil, ErrKeyMissing
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("upstream credential key: generate: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil { // #nosec G306 -- 0600 is intentional for a secret key
		return nil, fmt.Errorf("upstream credential key: write failed: %w", err)
	}
	return newKeyring(key), nil
}

func newKeyring(key []byte) *Keyring {
	sum := sha256.Sum256(key)
	return &Keyring{key: append([]byte(nil), key...), id: hex.EncodeToString(sum[:8])}
}

func (k *Keyring) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealAAD is the additional authenticated data binding a credential to the
// immutable entry ID AND the canonical authority hash (length-framed by
// the NUL separator neither component can contain).
func sealAAD(entryID, authorityHash string) []byte {
	return []byte(entryID + "\x00" + authorityHash)
}

// Seal encrypts plaintext for exactly one (entryID, authorityHash) pair:
// both are AEAD additional data AND recorded on the Sealed record, so the
// ciphertext can never be re-attached to another entry or authority.
func (k *Keyring) Seal(plaintext, entryID, authorityHash, setAt, setBy string) (*Sealed, error) {
	if k == nil {
		return nil, ErrKeyMissing
	}
	g, err := k.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if entryID == "" {
		return nil, errors.New("upstream credential: entry id required")
	}
	ct := g.Seal(nonce, nonce, []byte(plaintext), sealAAD(entryID, authorityHash))
	return &Sealed{
		EntryID: entryID, AuthorityHash: authorityHash, Ciphertext: base64.StdEncoding.EncodeToString(ct),
		KeyID: k.id, SetAt: setAt, SetBy: setBy,
	}, nil
}

// ErrCredentialMismatch is the bounded reason a sealed credential does not
// belong to the (entry, authority) it is attached to.
var ErrCredentialMismatch = errors.New("upstream credential: bound to a different entry or authority")

// Unseal decrypts a sealed credential for exactly the given entry ID and
// authority hash. Any failure is reported as a bounded error (never the
// ciphertext).
func (k *Keyring) Unseal(s *Sealed, entryID, authorityHash string) (string, error) {
	if k == nil {
		return "", ErrKeyMissing
	}
	if s == nil {
		return "", errors.New("no credential")
	}
	if s.KeyID != k.id {
		return "", errors.New("upstream credential: sealed under a different key")
	}
	if s.EntryID != entryID || s.AuthorityHash != authorityHash {
		return "", ErrCredentialMismatch
	}
	raw, err := base64.StdEncoding.DecodeString(s.Ciphertext)
	if err != nil {
		return "", errors.New("upstream credential: ciphertext malformed")
	}
	g, err := k.gcm()
	if err != nil {
		return "", err
	}
	if len(raw) < g.NonceSize() {
		return "", errors.New("upstream credential: ciphertext too short")
	}
	pt, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], sealAAD(entryID, authorityHash))
	if err != nil {
		return "", errors.New("upstream credential: cannot unwrap")
	}
	return string(pt), nil
}
