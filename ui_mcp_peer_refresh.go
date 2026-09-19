package main

import (
	"net/http"
	"strconv"
)

// apiMCPServerRefresh is the governed operator entry point for an authenticated peer observation
// (blocker 11, §7): POST /api/mcp/servers/refresh with {"server_id": "..."}.
//
// It is ADMIN-ONLY and treated as a security-significant control-plane mutation, because a
// refresh can move a tool's catalog drift/eligibility projection — a peer that now advertises a
// changed schema lands Quarantined, which withdraws an approval's projection. It grants nothing:
// see mcp_peer_refresh.go for why observation and authority are kept apart.
//
// The body carries a ServerID and NOTHING ELSE. There is deliberately no endpoint, pinned
// identity, tenant, expected fingerprint, tool list, provenance or timestamp field: every one of
// those is resolved from authoritative state or from the authenticated peer, so no operator input
// can make the catalog assert something the peer did not say. There is also no wildcard and no
// "refresh all" — an amplifier pointed at a fleet is not an operator control.
func apiMCPServerRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		ServerID string `json:"server_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	out, reason, err := mcpRefreshPeerObservation(r.Context(), req.ServerID)
	if reason != "" {
		// Audited on the failure path too: an operator repeatedly failing to observe a peer is
		// exactly the kind of control-plane activity a reviewer wants to see, and the reason is
		// drawn from a closed vocabulary so the record can never carry an upstream string, an
		// endpoint or a peer payload. err itself is deliberately NOT audited or returned.
		auditEvent(r, "mcp.server.refresh.failed", sanitizeLog(req.ServerID), reason)
		mcpRefreshRefusal(w, reason)
		return
	}
	_ = err // success path: err is nil by construction
	auditEvent(r, "mcp.server.refresh", sanitizeLog(out.ServerID),
		"revision="+strconv.FormatUint(out.Revision, 10)+" observations="+strconv.Itoa(out.Observations))
	jsonOK(w, map[string]any{
		"server_id":    out.ServerID,
		"revision":     out.Revision,
		"observations": out.Observations,
	})
}

// mcpRefreshRefusal maps a bounded reason onto its status. The mapping is explicit rather than a
// default-500 so an operator can tell "you asked for something that cannot work" (400) from "this
// node is not configured for it" (409) from "try again shortly" (429) from "the peer did not
// answer" (502) — four different next actions.
func mcpRefreshRefusal(w http.ResponseWriter, reason string) {
	switch reason {
	case mcpPeerRefreshReasonNoServerID:
		http.Error(w, reason, http.StatusBadRequest)
	case mcpPeerRefreshReasonNotConfigured:
		http.Error(w, reason, http.StatusConflict)
	case mcpPeerRefreshReasonInProgress, mcpPeerRefreshReasonBusy:
		http.Error(w, reason, http.StatusTooManyRequests)
	case mcpPeerRefreshReasonUnregistered, mcpPeerRefreshReasonUnusable:
		http.Error(w, reason, http.StatusBadRequest)
	default:
		http.Error(w, reason, http.StatusBadGateway)
	}
}
