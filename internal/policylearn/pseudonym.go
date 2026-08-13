package policylearn

// M3 — durable subject pseudonymization. Aggregation state never stores a raw
// subject: distinct-subject evidence is keyed by a stable pseudonymous token
// derived from the authoritative tuple (AuthSource, Subject) under a node-local
// cryptographically random HMAC key.
//
// Key contract:
//   - 32 random bytes (crypto/rand), generated on first use;
//   - node-local and durable (AtomicWrite 0600), stored SEPARATELY from the
//     session/aggregate document (SubjectKeyPath vs StorePath) so backup or
//     inspection of aggregates never carries the key;
//   - never derived from admin credentials or any config string;
//   - never logged (nothing in this package logs the key or a raw subject).
//
// Key loss/rotation is HONEST, never silent: the key's identity (KeyID = first
// 8 bytes of SHA-256(key), hex) is pinned on every session at start. A restart
// that produces a different KeyID (deleted/rotated/unreadable key) breaks
// distinct-subject continuity — the recovered active session records a
// subject_key_changed gap and the aggregate is flagged, so tokens from before
// and after are never presented as one population.
//
// Token framing is unambiguous: HMAC-SHA256(key,
// uint32be(len(authSource)) || authSource || uint32be(len(subject)) || subject),
// truncated to 16 bytes, hex-encoded (32 chars). Length-prefixed framing means
// ("ab","c") and ("a","bc") can never collide, and AuthSource participates
// verbatim (never normalized), so the same Subject under two providers yields
// two distinct tokens — matching the (authSource, Sub) aggregation identity.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const subjectKeyLen = 32

// subjectKey holds the loaded key and its stable identity.
type subjectKey struct {
	key   []byte
	keyID string // hex(sha256(key)[:8]) — safe to persist/log; reveals nothing of the key
}

// loadOrCreateSubjectKey loads the durable key, creating it on first use.
// Empty path ⇒ ephemeral in-memory key (memory-only test engines) — tokens are
// still internally consistent but not restart-stable, which such engines never
// promise. An unreadable or wrong-length key file is an ERROR (fail honestly:
// silently regenerating would silently reset distinct-subject identity).
func loadOrCreateSubjectKey(path string) (*subjectKey, error) {
	if path == "" {
		k := make([]byte, subjectKeyLen)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("policylearn: generate ephemeral subject key: %w", err)
		}
		return newSubjectKey(k), nil
	}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		k := make([]byte, subjectKeyLen)
		if _, err := rand.Read(k); err != nil {
			return nil, fmt.Errorf("policylearn: generate subject key: %w", err)
		}
		if err := fileutil.AtomicWrite(path, k, 0o600); err != nil {
			return nil, fmt.Errorf("policylearn: persist subject key: %w", err)
		}
		return newSubjectKey(k), nil
	case err != nil:
		return nil, fmt.Errorf("policylearn: read subject key: %w", err)
	case len(raw) != subjectKeyLen:
		return nil, fmt.Errorf("policylearn: subject key at %q has invalid length %d (want %d) — refusing to silently regenerate (it would reset distinct-subject identity); move the file aside to mint a new key", path, len(raw), subjectKeyLen)
	default:
		return newSubjectKey(raw), nil
	}
}

func newSubjectKey(k []byte) *subjectKey {
	sum := sha256.Sum256(k)
	return &subjectKey{key: k, keyID: hex.EncodeToString(sum[:8])}
}

// token derives the stable pseudonymous subject token for (authSource,
// subject). Empty subject ⇒ empty token (unauthenticated traffic is never
// tokenized). AuthSource is used VERBATIM — opaque provenance, no
// normalization.
func (sk *subjectKey) token(authSource, subject string) string {
	if subject == "" {
		return ""
	}
	mac := hmac.New(sha256.New, sk.key)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(authSource)))
	mac.Write(l[:])
	mac.Write([]byte(authSource))
	binary.BigEndian.PutUint32(l[:], uint32(len(subject)))
	mac.Write(l[:])
	mac.Write([]byte(subject))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
