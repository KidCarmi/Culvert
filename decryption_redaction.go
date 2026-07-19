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
		// whether the node holds a pseudonym key (the value is NEVER exposed).
		jsonOK(w, map[string]any{
			"redact_hosts":    decRedactHosts(),
			"scope":           "traffic_destination",
			"scope_fields":    []string{"host", "uri", "dec.host", "dec.sni", "top_hosts"},
			"key_provisioned": len(getTrafficPseudonymKey()) == trafficKeyLen,
			"note":            "Global destination privacy: host, URI, dec.host/dec.sni, and the top-hosts ranking are pseudonymized with a node-local keyed HMAC across every sink (feed, JSONL/history, SIEM, drill-down, top-hosts). Fail-closed: a node with the posture on but no key emits a constant sentinel, never plaintext. Node-local (not exported/rolled-back/synced); fleet-wide correlation is a separate follow-up. Limitation: log search by host (?filter=) matches the stored token, not the plaintext, so plaintext host search does not resolve while the posture is on. Rotate the key via PUT {\"rotate_key\":true} — this breaks correlation with older records.",
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
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		old := decRedactHosts()
		oldKey := getTrafficPseudonymKey()
		// Rotation is ORTHOGONAL to the posture. The advertised rotate call is
		// PUT {"rotate_key":true}, which omits redact_hosts — so it decodes as false.
		// Honoring that false would SILENTLY DISABLE the posture (and turn plaintext
		// logging back on) on a node whose operator only meant to roll the key. Preserve
		// the current posture across a rotation; a posture change is a separate PUT.
		targetRedact := body.RedactHosts
		if body.RotateKey {
			targetRedact = old
		}
		switch {
		case body.RotateKey:
			// Explicit rotation regenerates unconditionally.
			if err := rotateTrafficPseudonymKey(); err != nil {
				logger.Printf("decryption redaction: pseudonym key rotation failed: %v", err)
				http.Error(w, "failed to rotate pseudonym key", http.StatusInternalServerError)
				return
			}
		case targetRedact:
			// Provision the key BEFORE persisting, so enabling the posture and the key's
			// durability are one transaction (no window where the posture is on but no
			// key exists ⇒ no accidental fail-closed sentinel run).
			if err := ensureTrafficPseudonymKey(); err != nil {
				logger.Printf("decryption redaction: pseudonym key provisioning failed: %v", err)
				http.Error(w, "failed to provision pseudonym key", http.StatusInternalServerError)
				return
			}
		}
		setDecRedactHosts(targetRedact)
		if err := SaveAdminSettings(); err != nil {
			setDecRedactHosts(old)         // durable write failed — leave runtime unchanged
			setTrafficPseudonymKey(oldKey) // ...including the key (roll back a rotation)
			logger.Printf("decryption redaction: persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist redaction setting", http.StatusInternalServerError)
			return
		}
		state := "disabled"
		if targetRedact {
			state = "enabled"
		}
		if body.RotateKey {
			auditEvent(r, "decryption.redaction.key-rotated", state, "traffic-log destination pseudonym key rotated (breaks correlation with older records)")
		} else {
			auditEvent(r, "decryption.redaction", state, "traffic-log destination pseudonymization (host/URI/dec.*)")
		}
		jsonOK(w, map[string]any{"redact_hosts": targetRedact, "key_rotated": body.RotateKey})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
