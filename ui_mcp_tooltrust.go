package main

// MCP tool-trust admin API (ADR-0034). Thin HTTP handlers over the package-main
// tool-trust coordinator (mcp_tooltrust.go), which owns the durable ToolApproval
// store and the catalog Usable projection. These handlers only parse input, enforce
// RBAC + tenant scope, marshal the safe (secret-free) approval view, and write the
// admin audit ring. Nothing here executes a tool, dials a server, materializes a
// credential, or arms any live-execution tier.
//
// Durability of a trust decision is the durable AtomicWrite store (the recovery
// authority) plus the admin audit ring written here (`mcp.tooltrust.<verb>`). A
// supplementary MCP-events-spool tamper record is a documented follow-up, not shipped in
// this slice — see ADR-0034 D3 (the events API is decision-point specific and a
// governance action needs its own event type); it changes no authoritative guarantee.
//
// Trust ≠ availability ≠ authorization: an approval only ever promotes a tool to
// catalog.Usable (a supply-chain trust decision reviewed by a privileged human for a
// declared purpose); it never authorizes a call. Runtime policy stays authoritative
// for every invocation.

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

// mcpToolViewEnriched is the inventory ToolView (ADR-0024) plus the ADR-0034 tool-
// trust overlay: the governing approval's status/purpose/id/expiry. The trust fields
// are omitempty, so a tool with no approval — and a node with the tool-trust
// coordinator not composed — serializes byte-identically to the bare ToolView. The
// overlay is informational: the authoritative usability is still ToolView.Disposition
// (catalog.Usable), which the coordinator's reconcile keeps consistent.
type mcpToolViewEnriched struct {
	adminapi.ToolView
	ApprovalStatus    string     `json:"approval_status,omitempty"`
	ApprovalPurpose   string     `json:"approval_purpose,omitempty"`
	ApprovalID        string     `json:"approval_id,omitempty"`
	ApprovalExpiresAt *time.Time `json:"approval_expires_at,omitempty"`
}

// mcpToolTrustStatusView is the safe, read-only tool-trust subsystem status for the
// MCP overview: whether the coordinator is composed and a bounded reason when not.
type mcpToolTrustStatusView struct {
	Composed bool   `json:"composed"`
	Reason   string `json:"reason,omitempty"`
}

// mcpToolTrustStatus builds the read-only status view from the coordinator.
func mcpToolTrustStatus() mcpToolTrustStatusView {
	composed, reason := mcpToolTrust.composedStatus()
	return mcpToolTrustStatusView{Composed: composed, Reason: reason}
}

// enrichToolView overlays the tool-trust annotation onto an inventory ToolView.
func enrichToolView(tenant string, v adminapi.ToolView) mcpToolViewEnriched {
	out := mcpToolViewEnriched{ToolView: v}
	if ann, ok := mcpToolTrust.annotateTool(tenant, v.ServerID, v.Name, v.Fingerprint); ok {
		out.ApprovalStatus = ann.Status
		out.ApprovalPurpose = ann.Purpose
		out.ApprovalID = ann.ID
		out.ApprovalExpiresAt = ann.ExpiresAt
	}
	return out
}

// mcpToolApprovalView is the safe, secret-free wire view of a ToolApproval. It
// carries only bounded references, the fingerprint digest (a hash of PUBLIC
// capability facts), and lifecycle metadata — never a token, credential, or raw
// schema/body.
type mcpToolApprovalView struct {
	ApprovalID               string     `json:"approval_id"`
	Tenant                   string     `json:"tenant"`
	ServerID                 string     `json:"server_id"`
	ToolName                 string     `json:"tool_name"`
	Fingerprint              string     `json:"fingerprint"`
	FingerprintFormatVersion uint16     `json:"fingerprint_format_version"`
	Purpose                  string     `json:"purpose"`
	Status                   string     `json:"status"`
	CatalogRevision          uint64     `json:"catalog_revision"`
	ServerRevision           uint64     `json:"server_revision,omitempty"`
	RequestedBy              string     `json:"requested_by"`
	RequestedAt              time.Time  `json:"requested_at"`
	ApprovedBy               string     `json:"approved_by,omitempty"`
	ApprovedAt               *time.Time `json:"approved_at,omitempty"`
	Reason                   string     `json:"reason,omitempty"`
	TicketRef                string     `json:"ticket_ref,omitempty"`
	ExpiresAt                *time.Time `json:"expires_at,omitempty"`
	RevokedBy                string     `json:"revoked_by,omitempty"`
	RevokedAt                *time.Time `json:"revoked_at,omitempty"`
	RevocationReason         string     `json:"revocation_reason,omitempty"`
	RejectedReason           string     `json:"rejected_reason,omitempty"`
}

func mcpToolApprovalViewOf(a *tooltrust.ToolApproval) mcpToolApprovalView {
	v := mcpToolApprovalView{
		ApprovalID:               a.ApprovalID,
		Tenant:                   a.Tenant,
		ServerID:                 a.ServerID,
		ToolName:                 a.ToolName,
		Fingerprint:              hex.EncodeToString(a.Fingerprint[:]),
		FingerprintFormatVersion: a.FingerprintFormatVersion,
		Purpose:                  a.Purpose.String(),
		Status:                   a.Status.String(),
		CatalogRevision:          a.CatalogRevision,
		ServerRevision:           a.ServerRevision,
		RequestedBy:              a.RequestedBy,
		RequestedAt:              a.RequestedAt,
		ApprovedBy:               a.ApprovedBy,
		Reason:                   a.Reason,
		TicketRef:                a.TicketRef,
		ExpiresAt:                a.ExpiresAt,
		RevokedBy:                a.RevokedBy,
		RevokedAt:                a.RevokedAt,
		RevocationReason:         a.RevocationReason,
		RejectedReason:           a.RejectedReason,
	}
	if !a.ApprovedAt.IsZero() {
		t := a.ApprovedAt
		v.ApprovedAt = &t
	}
	return v
}

// mcpToolApprovalRequestBody is the create-request body. The client submits only the
// tool coordinates, the EXPECTED (reviewed) fingerprint hex, the expected catalog
// revision (optimistic-concurrency evidence), a declared purpose, and free-text
// reason/ticket. The tenant is taken from the ?tenant= scope (validated against the
// server's ownership), never trusted as a server fact.
type mcpToolApprovalRequestBody struct {
	ServerID         string `json:"server_id"`
	ToolName         string `json:"tool_name"`
	Fingerprint      string `json:"fingerprint"`      // 64-char hex of the reviewed digest
	CatalogRevision  uint64 `json:"catalog_revision"` // 0 ⇒ not asserted
	Purpose          string `json:"purpose"`          // shadow_evaluation (default; only issuable)
	Reason           string `json:"reason"`
	TicketRef        string `json:"ticket_ref"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"` // 0 ⇒ no expiry
}

// mcpToolApprovalDecisionBody is the approve/reject/revoke body.
type mcpToolApprovalDecisionBody struct {
	ApprovalID string `json:"approval_id"`
	Action     string `json:"action"` // approve | reject | revoke
	Reason     string `json:"reason"`
}

// apiMCPToolApprovals lists/gets tenant-scoped tool-trust approvals (GET, viewer) and
// creates a pending trust request (POST, operator). Creating a request is NOT a
// grant — it never changes catalog eligibility.
func apiMCPToolApprovals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		tenant, ok := mcpTenant(r)
		if !ok {
			mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
			return
		}
		if id := r.URL.Query().Get("id"); id != "" {
			a, err := mcpToolTrust.Get(id, tenant)
			if err != nil {
				mcpErr(w, err)
				return
			}
			jsonOK(w, mcpToolApprovalViewOf(a))
			return
		}
		list, err := mcpToolTrust.List(tenant, mcpToolApprovalLimit(r))
		if err != nil {
			mcpErr(w, err)
			return
		}
		views := make([]mcpToolApprovalView, 0, len(list))
		for _, a := range list {
			views = append(views, mcpToolApprovalViewOf(a))
		}
		jsonOK(w, views)
	case http.MethodPost:
		if !requireRole(w, r, RoleOperator) {
			return
		}
		tenant, ok := mcpTenant(r)
		if !ok {
			mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
			return
		}
		var body mcpToolApprovalRequestBody
		if err := decodeJSON(r, &body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		purpose, ok := parseToolApprovalPurpose(body.Purpose)
		if !ok {
			mcpErr(w, mcperr.New(mcperr.ReasonApprovalPurposeUnsupported, "mcp", "unsupported approval purpose"))
			return
		}
		in := toolTrustRequestInput{
			Tenant:              tenant,
			ServerID:            body.ServerID,
			ToolName:            body.ToolName,
			ExpectedFingerprint: body.Fingerprint,
			ExpectedCatalogRev:  body.CatalogRevision,
			Purpose:             purpose,
			RequestedBy:         auditActor(r),
			Reason:              body.Reason,
			TicketRef:           body.TicketRef,
			ExpiresAt:           expiryFromSeconds(body.ExpiresInSeconds),
		}
		a, err := mcpToolTrust.RequestApproval(in)
		if err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.tooltrust.request", a.ApprovalID, a.ServerID+"/"+a.ToolName)
		jsonOK(w, mcpToolApprovalViewOf(a))
	default:
		mcpMethodNotAllowed(w)
	}
}

// apiMCPToolApprovalDecision approves (shadow), rejects, or revokes a tool-trust
// approval (POST, admin). Approve materializes catalog.Usable for the exact reviewed
// fingerprint; revoke immediately withdraws it. Every decision is audited.
func apiMCPToolApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	tenant, ok := mcpTenant(r)
	if !ok {
		mcpErr(w, mcperr.New(mcperr.ReasonAdminTenantScope, "mcp", "tenant required"))
		return
	}
	var body mcpToolApprovalDecisionBody
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	actor := auditActor(r)
	switch body.Action {
	case "approve":
		a, err := mcpToolTrust.ApproveShadow(body.ApprovalID, actor, tenant)
		// A non-nil grant means the durable active grant was committed even if the catalog
		// projection (promotion) failed afterward (a stale CAS). That IS a real trust
		// decision — it becomes effective on the next reconcile — so audit it regardless of
		// the projection error, then surface any error.
		if a != nil {
			auditEvent(r, "mcp.tooltrust.approve", a.ApprovalID, a.ServerID+"/"+a.ToolName)
		}
		if err != nil {
			mcpErr(w, err)
			return
		}
		jsonOK(w, mcpToolApprovalViewOf(a))
	case "reject":
		if err := mcpToolTrust.Reject(body.ApprovalID, actor, tenant, body.Reason); err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.tooltrust.reject", body.ApprovalID, "")
		jsonOK(w, map[string]any{"rejected": true})
	case "revoke":
		a, err := mcpToolTrust.Revoke(body.ApprovalID, actor, tenant, body.Reason)
		if err != nil {
			mcpErr(w, err)
			return
		}
		auditEvent(r, "mcp.tooltrust.revoke", a.ApprovalID, a.ServerID+"/"+a.ToolName)
		jsonOK(w, mcpToolApprovalViewOf(a))
	default:
		http.Error(w, "admin_request_invalid", http.StatusBadRequest)
	}
}

// parseToolApprovalPurpose resolves the request purpose, defaulting an empty value to
// shadow_evaluation (the only issuable purpose). live_execution parses successfully
// so the store refuses it with the precise purpose-unsupported reason (the firewall's
// negative half); an unknown label is rejected here.
func parseToolApprovalPurpose(s string) (tooltrust.Purpose, bool) {
	if s == "" {
		return tooltrust.PurposeShadowEvaluation, true
	}
	return tooltrust.ParsePurpose(s)
}

// expiryFromSeconds converts a positive relative expiry to an absolute timestamp; a
// non-positive value means no expiry.
func expiryFromSeconds(sec int64) *time.Time {
	if sec <= 0 {
		return nil
	}
	t := time.Now().Add(time.Duration(sec) * time.Second)
	return &t
}

// mcpToolApprovalLimit clamps the list page size to a safe bound.
func mcpToolApprovalLimit(r *http.Request) int {
	n := mcpQueryLimit(r)
	const defLimit, maxLimit = 100, 500
	if n <= 0 {
		return defLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}
