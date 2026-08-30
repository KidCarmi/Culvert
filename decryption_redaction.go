package main

// decryption_redaction.go — the admin surface for the destination-privacy posture
// (ADR-0011 §4 → PR3 Option B). A single node-local toggle that, when ON, pseudonymizes
// the destination with a keyed HMAC (traffic_redaction.go) at the persistLogEntry
// chokepoint — the top-level Host/URI, the nested dec.host/dec.sni, AND the top-hosts
// ranking, across every sink — instead of recording the plaintext. OFF by default (the
// historical behavior), so upgrading changes nothing until an operator opts in.
//
// The flag is read at PROJECTION time (toBlock) on the decision/close path and at the
// persistLogEntry chokepoint, so it is a lock-free atomic read. It is DURABLE in
// admin_settings.json but node-local — off export/import, version-rollback, and CP→DP
// sync (AdminDurable-only config_surfaces rows for the flag AND the pseudonym key, like
// the auto-exclusion tunables): destination privacy is a per-appliance choice, not fleet
// policy (fleet-wide pseudonym correlation via a synced key is the deferred B3 follow-up).

import (
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
)

// decRedactHostsFlag is the live redaction toggle. Default (false) = record plaintext host/SNI.
var decRedactHostsFlag atomic.Bool

// decRedactHosts reports whether host/SNI redaction is enabled. Called at every dec-block
// projection (toBlock) — a plain atomic load, safe on the proxy hot path.
func decRedactHosts() bool { return decRedactHostsFlag.Load() }

// setDecRedactHosts sets the redaction toggle (load-time restore + the admin PUT).
func setDecRedactHosts(v bool) { decRedactHostsFlag.Store(v) }

// decRedactionTarget is the TARGET destination-privacy state a redaction PUT
// hands to saveAdminSettingsWithOverrides (2E-B persist-before-apply): the
// durable file records these values FIRST; only a successful write applies
// them to the live posture/key.
type decRedactionTarget struct {
	RedactHosts bool
	Key         []byte
	KeyID       string
}

// decRedactionSnapshot reads the committed destination-privacy state as ONE
// coherent pair under adminSettingsMu — the surface's writer domain (the PUT
// installs posture and key inside that mutex, so a lock-free two-atomic read
// could pair a new posture with an old generation id; 2E-A §1 doctrine).
func decRedactionSnapshot() (redact bool, keyID string, keyProvisioned bool) {
	adminSettingsMu.Lock()
	defer adminSettingsMu.Unlock()
	return decRedactHosts(), getTrafficPseudonymKeyID(), len(getTrafficPseudonymKey()) == trafficKeyLen
}

// decRedactionRevisionOf derives the destination-privacy revision from one
// committed snapshot — a pure function of (posture, generation id), so the
// fence covers BOTH the privacy toggle and the pseudonym-key rotation: any
// landed rotation changes the id, so a write (or retried rotation) asserting
// pre-rotation truth is a structured 409, never a silent overwrite or a
// silent second rotation.
func decRedactionRevisionOf(redact bool, keyID string) string {
	return contentSecRevision("dec-redaction", fmt.Sprintf("%t", redact), keyID)
}

// errPseudonymKeyMint marks an entropy failure while minting a key inside the
// redaction save's precondition (distinguishes a 500 from a fence 409).
var errPseudonymKeyMint = errors.New("pseudonym key mint failed")

// apiDecryptionRedaction is the ADR-0011 §4 admin surface for the host/SNI redaction
// posture. GET (viewer) reports the current setting; PUT (admin) sets it. The flag apply
// is an infallible atomic store, so it is set first and rolled back only if the durable
// write fails (the setting is node-local — off export/import, rollback, and CP→DP).
func apiDecryptionRedaction(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		// PR3 Option B (supersedes the B0 metadata-only interim): the posture is now a
		// GLOBAL destination-privacy posture. When on, the destination is pseudonymized
		// with a keyed HMAC at the persistLogEntry chokepoint across EVERY sink (feed,
		// JSONL/history, SIEM, drill-down) AND the nested dec.host/dec.sni. Node-local
		// key; fail-closed to a sentinel if the key is missing. key_provisioned reports
		// whether the node holds a pseudonym key (the value is NEVER exposed); key_id is
		// the NON-SECRET pseudonym generation (2E-B §B — changes iff a rotation landed).
		// One coherent snapshot under the writer domain; the revision fingerprints
		// exactly the returned state (2E-B §A).
		redact, keyID, provisioned := decRedactionSnapshot()
		jsonOK(w, map[string]any{
			"redact_hosts":    redact,
			"scope":           "traffic_destination",
			"scope_fields":    []string{"host", "uri", "dec.host", "dec.sni", "top_hosts"},
			"key_provisioned": provisioned,
			"key_id":          keyID,
			"revision":        decRedactionRevisionOf(redact, keyID),
			"note":            "Global destination privacy: host, URI, dec.host/dec.sni, and the top-hosts ranking are pseudonymized with a node-local keyed HMAC across every sink (feed, JSONL/history, SIEM, drill-down, top-hosts). Fail-closed: a node with the posture on but no key emits a constant sentinel, never plaintext. Node-local (not exported/rolled-back/synced); fleet-wide correlation is a separate follow-up. Limitation: log search by host (?filter=) matches the stored token, not the plaintext, so plaintext host search does not resolve while the posture is on. Rotate the key via PUT {\"rotate_key\":true} — this breaks correlation with older records; key_id is the non-secret generation that changes with each rotation.",
		})

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			RedactHosts bool `json:"redact_hosts"`
			// RotateKey, when true, mints a NEW node-local pseudonym key. All future
			// tokens change, so correlation with pre-rotation records breaks (the
			// mission's defined rotation behavior). Admin-only, audited.
			RotateKey bool `json:"rotate_key,omitempty"`
			// IfRevision is the OPTIONAL stale-writer fence (2E-B §A): when present
			// it must equal the committed revision or the write is the ONE
			// structured 409 with no mutation. Because the revision covers the
			// pseudonym generation id, a fenced rotation retried after a lost
			// response is refused instead of silently rotating twice (§B). Absent
			// keeps the legacy last-writer-wins contract; the v2 client always
			// asserts it.
			IfRevision string `json:"ifRevision,omitempty"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		// 2E-B §A/§B/§C: fence comparison, target construction (incl. any key
		// mint), durable write, and runtime apply all share ONE serialized
		// AdminSettings save domain — persist-before-apply, so a persist failure
		// leaves the RUNNING privacy posture untouched and a rotation is durable
		// before its success response. The target is built INSIDE the lock so a
		// concurrent PUT can never interleave between read-current and persist.
		var target decRedactionTarget
		err := saveAdminSettingsWithOverrides(adminSaveOverrides{
			decRedaction: &target,
			precondition: func() error {
				curRedact := decRedactHosts()
				curKey := getTrafficPseudonymKey()
				curID := getTrafficPseudonymKeyID()
				if body.IfRevision != "" {
					if cur := decRedactionRevisionOf(curRedact, curID); cur != body.IfRevision {
						return errContentSecRevisionConflict{current: cur, asserted: body.IfRevision}
					}
				}
				// Rotation is ORTHOGONAL to the posture. The advertised rotate call
				// is PUT {"rotate_key":true}, which omits redact_hosts — so it
				// decodes as false. Honoring that false would SILENTLY DISABLE the
				// posture (and turn plaintext logging back on) on a node whose
				// operator only meant to roll the key. Preserve the current posture
				// across a rotation; a posture change is a separate PUT.
				target.RedactHosts = body.RedactHosts
				if body.RotateKey {
					target.RedactHosts = curRedact
				}
				switch {
				case body.RotateKey:
					// Explicit rotation mints a fresh (key, generation) pair.
					k, id, mintErr := mintTrafficPseudonymKeyPair()
					if mintErr != nil {
						return fmt.Errorf("%w: %v", errPseudonymKeyMint, mintErr)
					}
					target.Key, target.KeyID = k, id
				case target.RedactHosts && len(curKey) != trafficKeyLen:
					// Enabling with no key: provision one in the SAME durable
					// transaction (no window where the posture is on but no key
					// exists ⇒ no accidental fail-closed sentinel run).
					k, id, mintErr := mintTrafficPseudonymKeyPair()
					if mintErr != nil {
						return fmt.Errorf("%w: %v", errPseudonymKeyMint, mintErr)
					}
					target.Key, target.KeyID = k, id
				default:
					// Posture-only change: the key (and its generation) is kept —
					// disabling never destroys the pseudonym key.
					target.Key, target.KeyID = curKey, curID
				}
				return nil
			},
			applyOnSuccess: func() {
				setDecRedactHosts(target.RedactHosts)
				setTrafficPseudonymKeyPair(target.Key, target.KeyID)
			},
		})
		var conflict errContentSecRevisionConflict
		switch {
		case errors.As(err, &conflict):
			writeContentSecRevisionConflict(w, "destination privacy", conflict.current, conflict.asserted)
			return
		case errors.Is(err, errPseudonymKeyMint):
			logger.Printf("decryption redaction: %v", err)
			http.Error(w, "failed to provision pseudonym key", http.StatusInternalServerError)
			return
		case err != nil:
			logger.Printf("decryption redaction: persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist redaction setting", http.StatusInternalServerError)
			return
		}
		state := "disabled"
		if target.RedactHosts {
			state = "enabled"
		}
		if body.RotateKey {
			auditEvent(r, "decryption.redaction.key-rotated", state, "traffic-log destination pseudonym key rotated (breaks correlation with older records)")
		} else {
			auditEvent(r, "decryption.redaction", state, "traffic-log destination pseudonymization (host/URI/dec.*)")
		}
		// The response is the state THIS PUT installed (coherent by
		// construction), including the non-secret generation and its revision.
		jsonOK(w, map[string]any{
			"redact_hosts": target.RedactHosts,
			"key_rotated":  body.RotateKey,
			"key_id":       target.KeyID,
			"revision":     decRedactionRevisionOf(target.RedactHosts, target.KeyID),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
