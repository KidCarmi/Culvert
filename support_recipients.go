package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

// Recipient-key registry (M5). The sealed-export path (#794) seals a bundle to a
// recipient's PUBLIC X25519 key handed in per request. Pasting a raw base64 key
// each time is error-prone AND dangerous — a low-order point silently defeats the
// E2E guarantee (the #794 P1) — so this registry lets an admin register a NAMED
// recipient (e.g. "tac-prod") ONCE, with its key validated against the same
// low-order guard at registration and a SHA-256 fingerprint surfaced for
// out-of-band verification. Sealed export can then reference the recipient by name
// (support_export.go), so the routine, safe path never re-enters a raw key.
//
// A recipient's public key is NOT a secret — it is stored and displayed openly;
// the fingerprint is the trust anchor an operator verifies out-of-band (phone,
// signed message) once, at registration. The registry is node-local operational
// state (like debug_level.json): OFF export/import, config-version rollback, and
// CP→DP sync. A corrupt/absent file fails closed to an empty registry — it can
// only ever REMOVE a convenience path, never widen exposure.

// maxSupportRecipients bounds the on-disk registry so it cannot grow unbounded.
const maxSupportRecipients = 256

// supportRecipientNameRe is the recipient-name grammar: starts alphanumeric, then
// letters/digits/`._-`, ≤64 (1 + 63) — safe for display, filenames, and logs.
var supportRecipientNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

var errRecipientNotFound = errors.New("recipient not found")

// supportRecipient is one registered sealing target. PublicKey is base64 (std);
// Fingerprint is the lowercase hex SHA-256 of the RAW 32-byte key.
type supportRecipient struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by,omitempty"`
	RotatedAt   string `json:"rotated_at,omitempty"` // last key-rotation time (in-place PUT)
	RotatedBy   string `json:"rotated_by,omitempty"`
}

var supportRecipientMu sync.Mutex

func supportRecipientsPath() string { return filepath.Join(dataDir, "support", "recipients.json") }

// loadSupportRecipientsLocked reads the registry (sorted by name). Absent or
// corrupt ⇒ empty list — fail-closed: an unreadable registry grants no recipients.
// Caller holds supportRecipientMu.
func loadSupportRecipientsLocked() []supportRecipient {
	b, err := os.ReadFile(supportRecipientsPath())
	if err != nil {
		return nil
	}
	var list []supportRecipient
	if err := json.Unmarshal(b, &list); err != nil {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// saveSupportRecipientsLocked atomically persists the registry at 0600. Caller
// holds supportRecipientMu.
func saveSupportRecipientsLocked(list []supportRecipient) error {
	if err := os.MkdirAll(filepath.Dir(supportRecipientsPath()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := supportRecipientsPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, supportRecipientsPath())
}

// listSupportRecipients returns the registry sorted by name (public keys included —
// they are not secret).
func listSupportRecipients() []supportRecipient {
	supportRecipientMu.Lock()
	defer supportRecipientMu.Unlock()
	return loadSupportRecipientsLocked()
}

// recipientFingerprint is the lowercase-hex SHA-256 of the raw key bytes.
func recipientFingerprint(pub *[sealbox.KeyLen]byte) string {
	sum := sha256.Sum256(pub[:])
	return hex.EncodeToString(sum[:])
}

// addSupportRecipient validates the name and PUBLIC key (reusing decodeX25519PubKey,
// so a low-order point is rejected exactly as in the seal path), computes the
// fingerprint, and persists. Duplicate names and a full registry are refused.
func addSupportRecipient(name, pubB64, actor string) (supportRecipient, error) {
	name = strings.TrimSpace(name)
	if !supportRecipientNameRe.MatchString(name) {
		return supportRecipient{}, errors.New("invalid name (alphanumeric start; letters/digits/._- ; ≤64)")
	}
	pub, err := decodeX25519PubKey(pubB64)
	if err != nil {
		return supportRecipient{}, errors.New("invalid public key: " + err.Error())
	}

	supportRecipientMu.Lock()
	defer supportRecipientMu.Unlock()
	list := loadSupportRecipientsLocked()
	for i := range list {
		if list[i].Name == name {
			return supportRecipient{}, errors.New("a recipient with that name already exists")
		}
	}
	if len(list) >= maxSupportRecipients {
		return supportRecipient{}, errors.New("recipient registry is full")
	}
	rec := supportRecipient{
		Name:        name,
		PublicKey:   pubB64,
		Fingerprint: recipientFingerprint(pub),
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		CreatedBy:   actor,
	}
	list = append(list, rec)
	if err := saveSupportRecipientsLocked(list); err != nil {
		return supportRecipient{}, err
	}
	return rec, nil
}

// updateSupportRecipientKey rotates an EXISTING recipient's public key in place —
// the name binding (and thus every reference to it) is preserved while the key and
// fingerprint change. The new key is validated with the same low-order guard as
// registration. Returns errRecipientNotFound if the name is absent.
func updateSupportRecipientKey(name, pubB64, actor string) (supportRecipient, error) {
	name = strings.TrimSpace(name)
	pub, err := decodeX25519PubKey(pubB64)
	if err != nil {
		return supportRecipient{}, errors.New("invalid public key: " + err.Error())
	}

	supportRecipientMu.Lock()
	defer supportRecipientMu.Unlock()
	list := loadSupportRecipientsLocked()
	for i := range list {
		if list[i].Name != name {
			continue
		}
		list[i].PublicKey = pubB64
		list[i].Fingerprint = recipientFingerprint(pub)
		list[i].RotatedAt = time.Now().UTC().Format(time.RFC3339)
		list[i].RotatedBy = actor
		if err := saveSupportRecipientsLocked(list); err != nil {
			return supportRecipient{}, err
		}
		return list[i], nil
	}
	return supportRecipient{}, errRecipientNotFound
}

// deleteSupportRecipient removes one recipient by name. Returns errRecipientNotFound
// if absent.
func deleteSupportRecipient(name string) error {
	supportRecipientMu.Lock()
	defer supportRecipientMu.Unlock()
	list := loadSupportRecipientsLocked()
	out := list[:0:0]
	found := false
	for i := range list {
		if list[i].Name == name {
			found = true
			continue
		}
		out = append(out, list[i])
	}
	if !found {
		return errRecipientNotFound
	}
	return saveSupportRecipientsLocked(out)
}

// lookupSupportRecipientKey resolves a registered recipient's name to its validated
// X25519 public key for seal-by-name. The stored key is re-validated on read so a
// tampered on-disk file can never yield a low-order key.
func lookupSupportRecipientKey(name string) (*[sealbox.KeyLen]byte, error) {
	supportRecipientMu.Lock()
	list := loadSupportRecipientsLocked()
	supportRecipientMu.Unlock()
	for i := range list {
		if list[i].Name == name {
			return decodeX25519PubKey(list[i].PublicKey)
		}
	}
	return nil, errRecipientNotFound
}

// ── admin API ─────────────────────────────────────────────────────────────────

type addRecipientReq struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"` // base64 X25519 (std or url, padded or not)
}

// apiSupportRecipients lists (GET, viewer) or registers (POST, admin) sealing
// recipients. The list includes public keys + fingerprints — none are secret.
func apiSupportRecipients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, map[string]any{"recipients": listSupportRecipients(), "max": maxSupportRecipients})
	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var req addRecipientReq
		if err := decodeJSON(r, &req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		rec, err := addSupportRecipient(req.Name, req.PublicKey, auditActor(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		auditEvent(r, "support.recipient.add", rec.Name, rec.Fingerprint)
		jsonOK(w, rec)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiSupportRecipientItem rotates (PUT, admin) or removes (DELETE, operator) a
// registered recipient.
func apiSupportRecipientItem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		handleRecipientRotate(w, r)
	case http.MethodDelete:
		handleRecipientDelete(w, r)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRecipientRotate replaces an existing recipient's key in place (admin).
func handleRecipientRotate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	name := r.PathValue("name")
	if !supportRecipientNameRe.MatchString(name) {
		http.Error(w, "invalid recipient name", http.StatusBadRequest)
		return
	}
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// Capture the fingerprint being replaced BEFORE the rotate so the audit
	// records old→new. In-place rotation preserves the name binding while the key
	// silently changes underneath every future seal-by-name, so this entry is the
	// only control on a compromised-admin key-swap — it must state what was replaced.
	oldFP := ""
	for _, rc := range listSupportRecipients() {
		if rc.Name == strings.TrimSpace(name) {
			oldFP = rc.Fingerprint
			break
		}
	}
	rec, err := updateSupportRecipientKey(name, req.PublicKey, auditActor(r))
	if err != nil {
		if errors.Is(err, errRecipientNotFound) {
			http.Error(w, "recipient not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	auditEventDiff(r, "support.recipient.rotate", rec.Name,
		fmt.Sprintf("fp %s -> %s", oldFP, rec.Fingerprint), oldFP, rec.Fingerprint)
	jsonOK(w, rec)
}

// handleRecipientDelete removes a registered recipient (operator).
func handleRecipientDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleOperator) {
		return
	}
	name := r.PathValue("name")
	if !supportRecipientNameRe.MatchString(name) {
		http.Error(w, "invalid recipient name", http.StatusBadRequest)
		return
	}
	if err := deleteSupportRecipient(name); err != nil {
		if errors.Is(err, errRecipientNotFound) {
			http.Error(w, "recipient not found", http.StatusNotFound)
			return
		}
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	auditEvent(r, "support.recipient.delete", name, "")
	jsonOK(w, map[string]any{"deleted": name})
}
