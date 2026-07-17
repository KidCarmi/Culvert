package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/KidCarmi/Culvert/internal/backupcrypt"
	"github.com/KidCarmi/Culvert/internal/sealbox"
	"github.com/KidCarmi/Culvert/internal/support"
)

// Encrypted support-bundle export (M4). An operator can download a support bundle
// wrapped in the DOCUMENTED support/backup envelope (backupcrypt.EncryptBlob —
// "CVRTBK01": PBKDF2-SHA256 → AES-256-GCM with the fixed header AAD-bound to the
// ciphertext, so header tampering incl. a KDF-iteration downgrade fails auth) under
// a passphrase they choose, so the redacted diagnostics can be handed to TAC over
// an untrusted channel without ever sharing a stored key. This is the same envelope
// the backup/restore path uses, so a TAC/CLI validator recognises the blob
// (backupcrypt.IsEncryptedBlob). The passphrase is used once to derive the key and
// is NEVER logged, persisted, or echoed. Recipient public-key (E2E) encryption is a
// later slice; this is the symmetric, air-gap-friendly path.

const (
	// supportPassphraseMin defends against trivially brute-forceable passphrases.
	supportPassphraseMin = 12
	// supportPassphraseMax bounds the input so a giant body can't be abused.
	supportPassphraseMax = 512
)

type encryptedExportReq struct {
	Passphrase string `json:"passphrase"`
}

// apiSupportBundleExportEncrypted streams a passphrase-encrypted copy of a READY
// bundle (POST, operator+). It shares the mandatory-preview gate with plain
// download: only an approved bundle can leave the appliance, encrypted or not.
func apiSupportBundleExportEncrypted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	// Mandatory-preview gate: an encrypted export is still an exfiltration of the
	// bundle, so it requires admin approval exactly like a plain download.
	if readBundleState(id).State != bundleStateReady {
		http.Error(w, "bundle pending approval — an admin must review the redaction report and approve before download", http.StatusConflict)
		return
	}

	var req encryptedExportReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Validate BY LENGTH only — the passphrase itself is never inspected, logged,
	// or included in any error string.
	if n := len(req.Passphrase); n < supportPassphraseMin || n > supportPassphraseMax {
		http.Error(w, fmt.Sprintf("passphrase must be %d..%d characters", supportPassphraseMin, supportPassphraseMax), http.StatusBadRequest)
		return
	}

	tgz, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	enc, err := backupcrypt.EncryptBlob(tgz, req.Passphrase)
	if err != nil {
		// The error from the codec never contains key material, but keep the client
		// message generic regardless.
		logger.Printf("support: encrypt bundle %q failed: %v", sanitizeLog(id), err)
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	// Audit the exfiltration at grant time — the passphrase is NOT recorded.
	auditEvent(r, "support.bundle.download_encrypted", id, support.BundleFormat)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".csb.enc"))
	// #nosec G705 -- enc is opaque AES-256-GCM ciphertext (backupcrypt.EncryptBlob)
	// served as application/octet-stream, not reflected HTML/script; gosec's taint
	// tracker only sees that it transitively derives from request input (the
	// passphrase), not that it is encrypted binary data, so this is a false positive.
	_, _ = w.Write(enc)
}

// ── recipient public-key (E2E) sealed export ──────────────────────────────────

// supportSealedPubKeyMax bounds the base64 public-key field so a giant body can't
// be abused; an X25519 key is 32 bytes (~44 base64 chars).
const supportSealedPubKeyMax = 128

type sealedExportReq struct {
	// RecipientPublicKey is the recipient's base64 (std or url, padded or not)
	// X25519 public key — obtained out-of-band (e.g. TAC publishes it).
	RecipientPublicKey string `json:"recipient_public_key"`
	// RecipientName references a registered recipient (support_recipients.go) whose
	// key was validated + fingerprinted at registration — the safe, routine path.
	RecipientName string `json:"recipient_name"`
}

// resolveSealRecipient picks the recipient key from EITHER a registered name OR a
// raw public key. EXACTLY one must be supplied — both-present is rejected (rather
// than silently preferring one, which could seal to a stale default instead of the
// key the operator just pasted) and both-empty is rejected. Both paths run the same
// low-order validation (lookup re-validates the stored key; decode validates the
// raw key).
func resolveSealRecipient(req sealedExportReq) (*[sealbox.KeyLen]byte, error) {
	name := strings.TrimSpace(req.RecipientName)
	rawKey := strings.TrimSpace(req.RecipientPublicKey)
	switch {
	case name != "" && rawKey != "":
		return nil, errors.New("supply exactly one of recipient_name or recipient_public_key, not both")
	case name != "":
		return lookupSupportRecipientKey(name)
	case rawKey != "":
		return decodeX25519PubKey(rawKey)
	default:
		return nil, errors.New("supply recipient_name (registered) or recipient_public_key (raw base64 X25519)")
	}
}

// decodeX25519PubKey accepts standard or URL base64, padded or raw, and requires
// exactly 32 decoded bytes.
func decodeX25519PubKey(s string) (*[sealbox.KeyLen]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > supportSealedPubKeyMax {
		return nil, errors.New("empty or oversized key")
	}
	for _, dec := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		b, err := dec.DecodeString(s)
		if err != nil {
			continue
		}
		if len(b) != sealbox.KeyLen {
			return nil, errors.New("key must decode to 32 bytes")
		}
		var k [sealbox.KeyLen]byte
		copy(k[:], b)
		// Reject low-order/invalid X25519 points: sealing to one derives an
		// all-zero shared secret, so the blob would be openable without the
		// recipient's private key — defeating the E2E guarantee.
		if err := sealbox.ValidateRecipientPublicKey(&k); err != nil {
			return nil, errors.New("key is not a valid X25519 point")
		}
		return &k, nil
	}
	return nil, errors.New("not valid base64")
}

// apiSupportBundleExportSealed streams a READY bundle sealed to a recipient's
// PUBLIC key (POST, operator+). The appliance holds no private key, so it cannot
// decrypt what it seals — true end-to-end confidentiality to the recipient. Shares
// the mandatory-preview gate with plain download.
func apiSupportBundleExportSealed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	if readBundleState(id).State != bundleStateReady {
		http.Error(w, "bundle pending approval — an admin must review the redaction report and approve before download", http.StatusConflict)
		return
	}

	var req sealedExportReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	pub, err := resolveSealRecipient(req)
	if err != nil {
		if errors.Is(err, errRecipientNotFound) {
			http.Error(w, "registered recipient not found", http.StatusNotFound)
			return
		}
		http.Error(w, "invalid recipient: "+err.Error(), http.StatusBadRequest)
		return
	}

	tgz, err := os.ReadFile(filepath.Join(supportBundlesDir(), id, "bundle.csb.tgz"))
	if err != nil {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	sealed, err := sealbox.Seal(tgz, pub, nil)
	if err != nil {
		logger.Printf("support: seal bundle %q failed: %v", sanitizeLog(id), err)
		http.Error(w, "seal failed", http.StatusInternalServerError)
		return
	}

	auditEvent(r, "support.bundle.download_sealed", id, support.BundleFormat)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".csb.sealed"))
	// #nosec G705 -- sealed is opaque NaCl sealed-box ciphertext (sealbox.Seal)
	// served as application/octet-stream, not reflected HTML/script; gosec's taint
	// tracker only sees that it transitively derives from request input (the
	// recipient public key), not that it is sealed binary data, so this is a false positive.
	_, _ = w.Write(sealed)
}
