package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/support"
)

// Encrypted support-bundle export (M4). An operator can download a support bundle
// wrapped in the FROZEN PSCA envelope (ca.EncryptBundle — PBKDF2-SHA256 → AES-256-GCM,
// random salt+nonce, versioned magic) under a passphrase they choose, so the
// redacted diagnostics can be handed to TAC over an untrusted channel without ever
// sharing a stored key. The passphrase is used once to derive the key and is NEVER
// logged, persisted, or echoed. Recipient public-key (E2E) encryption is a later
// slice; this is the symmetric, air-gap-friendly path.

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
	enc, err := ca.EncryptBundle(tgz, []byte(req.Passphrase))
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
	_, _ = w.Write(enc)
}
