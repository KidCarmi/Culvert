package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

// support_tac_trust.go — M6 Secure Upload, PR-4: the TAC recipient trust store +
// the encrypt-to-TAC seal seam.
//
// The upload path (PR-5) encrypts a bundle END-TO-END to TAC's PUBLIC X25519 key
// BEFORE the outbound HTTPS POST (SECURE-UPLOAD-ARCHITECTURE.md §3): only TAC's
// cloud-KMS-held private key decrypts, so the appliance holds no decryption
// capability and a MITM or a compromised transit hop can never read the bundle.
// This slice ships the trust store and the seal function ONLY — it does NO
// network I/O (the no-egress wall + TestNoAutoUpload stay green); PR-5 wires it
// into the queue's uploadFunc.
//
// Trust model (mirrors the release-catalog trust roots exactly):
//   - TAC recipient public keys are PUBLIC material — never a secret. They are
//     BAKED into an official build (bakedTACTrustKeysJSON, linker-injected) and
//     OPERATOR-OVERRIDABLE via CULVERT_TAC_TRUST_KEYS for private/regional/staging
//     TAC. Configured keys EXTEND the baked set (they never silently replace a
//     baked pin — a same-id collision keeps the baked key and logs a warning).
//   - Rotation is ADDITIVE with an overlap window: multiple keys are trusted at
//     once; new bundles seal to the ACTIVE key (CULVERT_TAC_ACTIVE_KEY_ID, else
//     the first resolved key), and the key id is recorded so the upload manifest
//     carries {key_id}. TAC keeps the retired private key through the overlap so
//     bundles queued against the old public key still decrypt.
//   - Every key is validated against the sealbox low-order guard at resolve time
//     (a low-order point derives an all-zero shared secret, which would let anyone
//     open the "sealed" bundle), so a tampered env value can only ever REMOVE a
//     sealing target, never widen exposure.
//
// GUI parity: the resolved set is surfaced READ-ONLY on GET /api/support/tac-trust
// (key id + alg + fingerprint + source + active flag — no secrets). Configuration
// stays env-only, a recorded GUI-parity deferral in the same class as the other
// CULVERT_RELEASE_*/trust-root vars (baked + pinned material an operator verifies
// out-of-band, not day-to-day GUI state).

const (
	envTACTrustKeys   = "CULVERT_TAC_TRUST_KEYS"
	envTACActiveKeyID = "CULVERT_TAC_ACTIVE_KEY_ID"
	// tacAlgX25519 is the only supported recipient key algorithm (sealbox/NaCl
	// anonymous box over X25519). An unknown alg is rejected at resolve.
	tacAlgX25519 = "x25519"
	// maxTACTrustKeys bounds the resolved set so a malformed/hostile env value
	// cannot blow up memory; far more than any real rotation overlap needs.
	maxTACTrustKeys = 64
)

// bakedTACTrustKeysJSON is the BAKED-IN public TAC recipient set, in the same JSON
// shape as CULVERT_TAC_TRUST_KEYS. It is EMPTY in the open-source tree (so the
// encrypt-to-TAC scheme is DORMANT until an official build bakes a key) and is
// injected at official-build time via the linker
// (`-ldflags "-X main.bakedTACTrustKeysJSON=[...]"`). Public keys ONLY — never
// private signing/decryption material.
var bakedTACTrustKeysJSON = ""

// tacTrustKey is one resolved, validated TAC recipient key. PublicKey is std-base64
// of the raw 32-byte X25519 point; Fingerprint is the lowercase-hex SHA-256 of the
// raw key (the trust anchor an operator verifies out-of-band). Source is "baked" or
// "configured"; Active marks the current sealing target.
type tacTrustKey struct {
	KeyID       string `json:"key_id"`
	Alg         string `json:"alg"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Source      string `json:"source"`
	Active      bool   `json:"active"`
}

type tacTrustKeyJSON struct {
	KeyID     string `json:"key_id"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

var errNoTACTrustKey = errors.New("no TAC recipient trust key configured (encrypt-to-TAC unavailable)")

// parseTACTrustKeys parses one JSON array of trust keys, tagging each with source,
// validating the algorithm and the X25519 point (low-order guard, via
// decodeX25519PubKey), and computing the fingerprint. A blank input yields no keys.
func parseTACTrustKeys(raw, source string) ([]tacTrustKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var in []tacTrustKeyJSON
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, fmt.Errorf("must be a JSON array of trust keys: %w", err)
	}
	out := make([]tacTrustKey, 0, len(in))
	seen := make(map[string]string, len(in)) // key_id → fingerprint, within THIS source
	for i := range in {
		k := in[i]
		id := strings.TrimSpace(k.KeyID)
		if !supportRecipientNameRe.MatchString(id) {
			return nil, fmt.Errorf("trust key #%d: invalid key_id (alphanumeric start; letters/digits/._- ; ≤64)", i)
		}
		if strings.ToLower(strings.TrimSpace(k.Alg)) != tacAlgX25519 {
			return nil, fmt.Errorf("trust key %q: alg must be %q", sanitizeLog(id), tacAlgX25519)
		}
		pub, err := decodeX25519PubKey(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("trust key %q: %v", sanitizeLog(id), err)
		}
		fp := tacKeyFingerprint(pub)
		if prev, dup := seen[id]; dup {
			// A same-source key_id repeated with a DIFFERENT key is malformed: the
			// upload manifest records only key_id, so a bundle could seal to one key
			// while TAC selects the other private key for that id (undecryptable).
			// Fail closed. An EXACT repeat (same fingerprint) is a harmless dup — drop
			// it. (A cross-source baked↔configured collision is handled in resolve,
			// where baked deliberately wins.)
			if prev != fp {
				return nil, fmt.Errorf("duplicate key_id %q with a different public key", sanitizeLog(id))
			}
			continue
		}
		seen[id] = fp
		out = append(out, tacTrustKey{
			KeyID:       id,
			Alg:         tacAlgX25519,
			PublicKey:   k.PublicKey,
			Fingerprint: fp,
			Source:      source,
		})
	}
	return out, nil
}

// tacKeyFingerprint is the lowercase-hex SHA-256 of the raw key bytes (matches
// recipientFingerprint; kept distinct so the TAC trust store carries no coupling
// to the M5 recipient registry).
func tacKeyFingerprint(pub *[sealbox.KeyLen]byte) string {
	sum := sha256.Sum256(pub[:])
	return hex.EncodeToString(sum[:])
}

// resolveTACTrustKeys returns the trusted TAC recipient set: baked keys first, then
// configured keys that EXTEND them. Deduplicated by key id (baked wins a collision;
// a configured key that reuses a baked id with a DIFFERENT fingerprint is dropped
// with a logged warning — an operator override never silently rebinds a baked pin).
// The active sealing target (CULVERT_TAC_ACTIVE_KEY_ID, else the first resolved key)
// is flagged. Fail-closed: a malformed env value returns an error and no keys.
func resolveTACTrustKeys() ([]tacTrustKey, error) {
	baked, err := parseTACTrustKeys(bakedTACTrustKeysJSON, "baked")
	if err != nil {
		return nil, fmt.Errorf("baked TAC trust keys: %w", err)
	}
	configured, err := parseTACTrustKeys(os.Getenv(envTACTrustKeys), "configured")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envTACTrustKeys, err)
	}

	seen := make(map[string]string, len(baked)+len(configured)) // key_id → fingerprint
	out := make([]tacTrustKey, 0, len(baked)+len(configured))
	add := func(keys []tacTrustKey) {
		for i := range keys {
			k := keys[i]
			if fp, dup := seen[k.KeyID]; dup {
				if fp != k.Fingerprint {
					logger.Printf("support: TAC trust key_id %q from %s ignored — collides with an already-trusted key of a different fingerprint",
						sanitizeLog(k.KeyID), sanitizeLog(k.Source))
				}
				continue
			}
			seen[k.KeyID] = k.Fingerprint
			out = append(out, k)
		}
	}
	add(baked)
	add(configured)

	if len(out) > maxTACTrustKeys {
		return nil, fmt.Errorf("too many TAC trust keys (%d > %d)", len(out), maxTACTrustKeys)
	}
	markActiveTACKey(out)
	return out, nil
}

// markActiveTACKey flags the sealing target in place: the key whose id matches
// CULVERT_TAC_ACTIVE_KEY_ID, else the first key. An active-id that names no
// resolved key flags nothing (activeTACTrustKey then fails closed) and logs — a
// typo must never silently seal to the wrong recipient.
func markActiveTACKey(keys []tacTrustKey) {
	if len(keys) == 0 {
		return
	}
	wantID := strings.TrimSpace(os.Getenv(envTACActiveKeyID))
	if wantID == "" {
		keys[0].Active = true
		return
	}
	for i := range keys {
		if keys[i].KeyID == wantID {
			keys[i].Active = true
			return
		}
	}
	logger.Printf("support: %s=%q names no resolved TAC trust key — encrypt-to-TAC will fail closed",
		envTACActiveKeyID, sanitizeLog(wantID))
}

// activeTACTrustKey resolves the current sealing target and its validated X25519
// public key. Returns errNoTACTrustKey when no key is trusted or the configured
// active id names none — the caller (PR-5) must then queue/offline-export rather
// than upload, never seal to an unverified key.
func activeTACTrustKey() (tacTrustKey, *[sealbox.KeyLen]byte, error) {
	keys, err := resolveTACTrustKeys()
	if err != nil {
		return tacTrustKey{}, nil, err
	}
	for i := range keys {
		if keys[i].Active {
			pub, err := decodeX25519PubKey(keys[i].PublicKey)
			if err != nil {
				// Resolve already validated this; a failure here means the set was
				// mutated concurrently — fail closed rather than seal to a bad key.
				return tacTrustKey{}, nil, err
			}
			return keys[i], pub, nil
		}
	}
	return tacTrustKey{}, nil, errNoTACTrustKey
}

// sealBundleToTAC encrypts plaintext to the active TAC recipient key and returns
// the sealed blob plus the key id to record in the upload manifest ({key_id}).
// Pure in-memory crypto — NO network I/O. The appliance holds no matching private
// key, so it cannot decrypt what it seals (true E2E to TAC). PR-5 calls this from
// the queue's uploadFunc, before the PR-2 client POSTs the ciphertext.
func sealBundleToTAC(plaintext []byte) (sealed []byte, keyID string, err error) {
	key, pub, err := activeTACTrustKey()
	if err != nil {
		return nil, "", err
	}
	blob, err := sealbox.Seal(plaintext, pub, nil)
	if err != nil {
		return nil, "", fmt.Errorf("seal to TAC key %q: %w", sanitizeLog(key.KeyID), err)
	}
	return blob, key.KeyID, nil
}

// tacTrustConfigured reports whether encrypt-to-TAC has a usable active key. Used
// by the health/status surface and PR-5's consent gate to distinguish "not
// enabled" (no key ⇒ offline-export only) from "ready". A resolve error counts as
// not-configured (fail-closed) — the detail is logged, not surfaced to the gate.
func tacTrustConfigured() bool {
	_, _, err := activeTACTrustKey()
	return err == nil
}

// ── admin API (read-only; config is env-only, GUI-parity deferral) ─────────────

// apiSupportTACTrust surfaces the resolved TAC recipient trust set (GET, viewer).
// Public keys + fingerprints only — nothing secret. Read-only: the set is baked +
// env-configured pinned material, not runtime-mutable state, so there is no write
// verb (mirrors the release-catalog trust-root surface).
func apiSupportTACTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	keys, err := resolveTACTrustKeys()
	if err != nil {
		// A malformed env value is an operator misconfiguration, not a server
		// fault; report it (already sanitized by the resolver) without leaking
		// key material.
		jsonOK(w, map[string]any{
			"configured": false,
			"error":      err.Error(),
			"keys":       []tacTrustKey{},
		})
		return
	}
	activeID := ""
	for i := range keys {
		if keys[i].Active {
			activeID = keys[i].KeyID
			break
		}
	}
	jsonOK(w, map[string]any{
		"configured": len(keys) > 0 && activeID != "",
		"active_key": activeID,
		"keys":       keys,
		"max":        maxTACTrustKeys,
		"alg":        tacAlgX25519,
	})
}
