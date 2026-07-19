package main

// decryption_redaction.go — ADR-0011 §4 host/SNI privacy posture. A single node-local
// toggle that, when ON, hashes the host and SNI in every projected decryption block
// (redactHost → "h_"+12hex) instead of recording the plaintext. OFF by default (the
// historical behavior), so upgrading changes nothing until an operator opts in.
//
// SCOPE (PR3 B0 honesty fix — the contract is METADATA-ONLY, not full traffic privacy):
// this posture pseudonymizes ONLY the nested dec.host/dec.sni sub-fields. The SAME log
// record still carries the plaintext destination in the top-level Entry.Host / Entry.URI,
// which are emitted to the request feed, the JSONL/history logs, the SIEM/syslog export,
// and the dashboard drill-down unchanged. The API GET surfaces this scope + warning and
// the SPA panel shows it, so the toggle no longer advertises privacy it does not deliver.
// Full traffic-log destination privacy across every sink (opt-in, keyed HMAC, node-local
// key, fail-closed) is the recommended follow-up in
// roadmap/PR3-privacy-posture-v2-DECISION.md (Option B).
//
// The flag is read at PROJECTION time (toBlock) on the decision/close path, so it must be
// a lock-free atomic read. It is DURABLE in admin_settings.json but node-local — off
// export/import, version-rollback, and CP→DP sync (an AdminDurable-only config_surfaces
// row, like the auto-exclusion tunables): host redaction is a per-appliance privacy choice,
// not fleet policy.

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
		// Surface the TRUTHFUL scope alongside the flag (PR3 B0 honesty fix): this
		// posture pseudonymizes ONLY the nested dec.host/dec.sni sub-fields. The same
		// records still carry the plaintext destination in the top-level Host/URI
		// across the feed, JSONL/history, SIEM, and drill-down. Full traffic-log
		// destination privacy (opt-in keyed-HMAC across every sink) is the recommended
		// follow-up recorded in roadmap/PR3-privacy-posture-v2-DECISION.md.
		jsonOK(w, map[string]any{
			"redact_hosts": decRedactHosts(),
			"scope":        "decryption_metadata_only",
			"scope_fields": []string{"dec.host", "dec.sni"},
			"warning":      "Top-level request-log host and URI remain plaintext across the feed, JSONL/history logs, SIEM export, and dashboard drill-down. This is not full traffic-log destination privacy.",
		})

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var body struct {
			RedactHosts bool `json:"redact_hosts"`
		}
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		old := decRedactHosts()
		setDecRedactHosts(body.RedactHosts)
		if err := SaveAdminSettings(); err != nil {
			setDecRedactHosts(old) // durable write failed — leave the runtime flag unchanged
			logger.Printf("decryption redaction: persist failed, runtime unchanged: %v", err)
			http.Error(w, "failed to persist redaction setting", http.StatusInternalServerError)
			return
		}
		state := "disabled"
		if body.RedactHosts {
			state = "enabled"
		}
		auditEvent(r, "decryption.redaction", state, "host/SNI redaction in decryption records")
		jsonOK(w, map[string]any{"redact_hosts": body.RedactHosts})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
