package main

import (
	"net/http"
	"strings"
)

// Per-bundle export (exfiltration) history (M5). Every way a bundle leaves the
// appliance is audited with the bundle id as the audit Object and an action under
// "support.bundle.download" (plain / _encrypted / _sealed). This read-only view
// answers "who took this bundle off the box, and how?" for a support/security
// review WITHOUT re-exposing anything: it surfaces only the already-audited
// actor/time/action, never bundle content. It reads the in-memory audit ring, so
// it is RECENT history only (the ring is bounded and evicts oldest-first) — a
// durable per-bundle export log is out of scope for this slice.

// bundleExportActionPrefix matches every bundle-exfiltration audit action
// (support.bundle.download, .download_encrypted, .download_sealed) and nothing
// else on a bundle (create/approve/delete do not start with "…download").
const bundleExportActionPrefix = "support.bundle.download"

type bundleExportEvent struct {
	Actor  string `json:"actor"`
	Time   string `json:"time"`
	TS     int64  `json:"ts"`
	Action string `json:"action"` // support.bundle.download{,_encrypted,_sealed}
}

// bundleExportEvents scans the audit ring for the export events of one bundle,
// newest-first (auditGet already returns newest-first).
func bundleExportEvents(id string) []bundleExportEvent {
	var out []bundleExportEvent
	entries := auditGet()
	for i := range entries { // index-based: audit.Entry is 136 bytes (rangeValCopy)
		e := &entries[i]
		if e.Object != id || !strings.HasPrefix(e.Action, bundleExportActionPrefix) {
			continue
		}
		out = append(out, bundleExportEvent{Actor: e.Actor, Time: e.Time, TS: e.TS, Action: e.Action})
	}
	return out
}

// apiSupportBundleExports lists the recent export history for one bundle (GET,
// viewer). Read-only over the audit ring — no bundle content, no network.
func apiSupportBundleExports(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]any{
		"bundle_id": id,
		"exports":   bundleExportEvents(id),
		"note":      "recent history from the bounded audit ring (oldest events are evicted)",
	})
}
