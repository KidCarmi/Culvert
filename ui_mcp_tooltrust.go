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

// enrichToolView overlays the tool-trust annotation onto a SINGLE inventory ToolView. For a
// whole inventory response use enrichToolViewWith with one shared annotator (below).
func enrichToolView(tenant string, v adminapi.ToolView) mcpToolViewEnriched {
	return enrichToolViewWith(mcpToolTrust.newToolTrustAnnotator(tenant), v)
}

// enrichToolViewWith overlays the tool-trust annotation using a PRE-BUILT annotator, so a
// list of tools shares one approval snapshot instead of re-listing per tool (the O(tools ×
// approvals) amplification a viewer could otherwise trigger on GET /api/mcp/tools). A nil
// annotator (trust not composed) leaves the bare ToolView unchanged.
func enrichToolViewWith(ann *toolTrustAnnotator, v adminapi.ToolView) mcpToolViewEnriched {
	out := mcpToolViewEnriched{ToolView: v}
	if a, ok := ann.annotate(v.ServerID, v.Name, v.Fingerprint); ok {
		out.ApprovalStatus = a.Status
		out.ApprovalPurpose = a.Purpose
		out.ApprovalID = a.ID
		out.ApprovalExpiresAt = a.ExpiresAt
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
	RejectedBy               string     `json:"rejected_by,omitempty"`
	RejectedAt               *time.Time `json:"rejected_at,omitempty"`
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
		RejectedBy:               a.RejectedBy,
		RejectedAt:               a.RejectedAt,
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
	CatalogRevision  uint64 `json:"catalog_revision"` // REQUIRED: the reviewed per-record revision (ToolView.Revision); 0/omitted is rejected
	Purpose          string `json:"purpose"`          // shadow_evaluation (default) | live_execution (requires expiry, four-eyes)
	Reason           string `json:"reason"`
	TicketRef        string `json:"ticket_ref"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"` // shadow: 0 ⇒ no expiry; live: REQUIRED, 1..≤24h; negative or > ~10y is rejected
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
		apiMCPToolApprovalsList(w, r)
	case http.MethodPost:
		apiMCPToolApprovalCreate(w, r)
	default:
		mcpMethodNotAllowed(w)
	}
}

// apiMCPToolApprovalsList serves the viewer GET: one approval by ?id= or a bounded,
// tenant-scoped list.
func apiMCPToolApprovalsList(w http.ResponseWriter, r *http.Request) {
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
}

// apiMCPToolApprovalCreate serves the operator POST: create a pending trust request bound to
// the reviewed fingerprint. It validates purpose and TTL before constructing the request.
func apiMCPToolApprovalCreate(w http.ResponseWriter, r *http.Request) {
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
	expiresAt, err := expiryFromSeconds(body.ExpiresInSeconds)
	if err != nil {
		mcpErr(w, err)
		return
	}
	live := purpose == tooltrust.PurposeLiveExecution
	// A live_execution request is bound to the CANONICAL authenticated principal (session subject),
	// not auditActor's username@IP string, so the four-eyes check at approval compares stable
	// identities. It fails closed for an unauthenticated (IP-only) caller: a live-execution trust
	// request may never be attributed to an anonymous actor (§5). shadow_evaluation keeps auditActor.
	requestedBy := auditActor(r)
	if live {
		principal, perr := mcpLivePrincipal(r)
		if perr != nil {
			mcpErr(w, perr)
			return
		}
		requestedBy = principal
	}
	in := toolTrustRequestInput{
		Tenant:              tenant,
		ServerID:            body.ServerID,
		ToolName:            body.ToolName,
		ExpectedFingerprint: body.Fingerprint,
		ExpectedCatalogRev:  body.CatalogRevision,
		Purpose:             purpose,
		RequestedBy:         requestedBy,
		Reason:              body.Reason,
		TicketRef:           body.TicketRef,
		ExpiresAt:           expiresAt,
	}
	// Route through the dedicated live path (§3) so a live request can never be created with shadow
	// semantics; the store enforces the mandatory ≤24h expiry either way.
	var a *tooltrust.ToolApproval
	if live {
		a, err = mcpToolTrust.RequestLiveApproval(in)
	} else {
		a, err = mcpToolTrust.RequestApproval(in)
	}
	if err != nil {
		mcpErr(w, err)
		return
	}
	auditEvent(r, "mcp.tooltrust.request", a.ApprovalID, a.ServerID+"/"+a.ToolName)
	jsonOK(w, mcpToolApprovalViewOf(a))
}

// mcpLivePrincipal returns the CANONICAL authenticated principal for a live-execution trust
// decision — the stable subject of the admin UI session, which four-eyes is compared on. It fails
// CLOSED when the request carries no authenticated admin session or an empty subject: a
// live-execution trust decision (request OR approval) may never be attributed to an anonymous,
// IP-only actor, because four-eyes over bare IPs is not a real separation of duties (§5). It reads
// the same ps_ui_session cookie auditActor does, but returns ONLY the canonical subject — never
// the IP-enriched display string.
func mcpLivePrincipal(r *http.Request) (string, error) {
	sess, err := readUISessionCookie(r)
	if err != nil || sess == nil || sess.Sub == "" {
		return "", mcperr.New(mcperr.ReasonApprovalNotAuthorized, "mcp", "live_execution trust requires an authenticated principal")
	}
	return sess.Sub, nil
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
		apiMCPToolApprovalApprove(w, r, body.ApprovalID, tenant, actor)
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

// apiMCPToolApprovalApprove decides a pending approval, ROUTING by the stored purpose (§3/§15). A
// live_execution approval is approved via the dedicated ApproveLive path — four-eyes on the
// canonical authenticated principal (a distinct requester and approver), and NO catalog promotion
// (live trust never materializes catalog.Usable). A shadow_evaluation approval keeps its existing
// path (approve + promote), attributed to the auditActor string. Routing on the stored purpose (not
// a request field) means the caller can never pick which governance applies.
func apiMCPToolApprovalApprove(w http.ResponseWriter, r *http.Request, id, tenant, shadowActor string) {
	existing, err := mcpToolTrust.Get(id, tenant)
	if err != nil {
		mcpErr(w, err)
		return
	}
	if existing.Purpose == tooltrust.PurposeLiveExecution {
		approver, perr := mcpLivePrincipal(r)
		if perr != nil {
			mcpErr(w, perr)
			return
		}
		a, aerr := mcpToolTrust.ApproveLive(id, approver, tenant)
		if a != nil {
			auditEvent(r, "mcp.tooltrust.approve-live", a.ApprovalID, a.ServerID+"/"+a.ToolName)
		}
		if aerr != nil {
			mcpErr(w, aerr)
			return
		}
		jsonOK(w, mcpToolApprovalViewOf(a))
		return
	}
	a, aerr := mcpToolTrust.ApproveShadow(id, shadowActor, tenant)
	// A non-nil grant means the durable active grant was committed even if the catalog projection
	// (promotion) failed afterward (a stale CAS). That IS a real trust decision — it becomes
	// effective on the next reconcile — so audit it regardless of the projection error.
	if a != nil {
		auditEvent(r, "mcp.tooltrust.approve", a.ApprovalID, a.ServerID+"/"+a.ToolName)
	}
	if aerr != nil {
		mcpErr(w, aerr)
		return
	}
	jsonOK(w, mcpToolApprovalViewOf(a))
}

// parseToolApprovalPurpose resolves the request purpose, defaulting an empty value to
// shadow_evaluation. Both shadow_evaluation and live_execution parse successfully and are now
// issuable — live_execution under the stronger governance the issue path enforces (mandatory
// ≤24h expiry, four-eyes, exact-state). An unknown label is rejected here.
func parseToolApprovalPurpose(s string) (tooltrust.Purpose, bool) {
	if s == "" {
		return tooltrust.PurposeShadowEvaluation, true
	}
	return tooltrust.ParsePurpose(s)
}

// maxApprovalTTLSeconds bounds a relative approval expiry. It is generous for any real
// shadow-evaluation approval yet far below the point where a seconds→time.Duration
// (nanoseconds) conversion overflows int64 (~9.2e9 s), so the multiply is always defined.
const maxApprovalTTLSeconds = 10 * 365 * 24 * 3600 // ~10 years

// expiryFromSeconds converts a relative expiry (seconds) to an absolute timestamp. Zero is
// the documented "no expiry" sentinel. A NEGATIVE value is rejected as invalid input rather
// than silently treated as no-expiry (which would turn an intended short/invalid TTL into a
// never-expiring grant), and a value above maxApprovalTTLSeconds is rejected before the
// time.Duration nanosecond conversion can overflow into an already-expired timestamp.
func expiryFromSeconds(sec int64) (*time.Time, error) {
	if sec == 0 {
		return nil, nil // no expiry
	}
	if sec < 0 || sec > maxApprovalTTLSeconds {
		return nil, mcperr.New(mcperr.ReasonAdminRequestInvalid, "mcp", "expires_in_seconds out of range")
	}
	t := time.Now().Add(time.Duration(sec) * time.Second)
	return &t, nil
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
