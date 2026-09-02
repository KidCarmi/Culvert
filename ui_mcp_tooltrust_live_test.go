package main

// Admin-surface tests for the governed live_execution tool-trust path (§16 RBAC, §21 read-only
// review surface, §25 red-team on the canonical-principal four-eyes). These drive the real HTTP
// handlers through the MCP mux, so they exercise mcpLivePrincipal (canonical session subject) and
// the create/approve routing end to end.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mcpReqLive is mcpReq plus a signed admin-UI session whose subject is `sub`, so mcpLivePrincipal
// resolves a canonical authenticated principal. role is still injected via context (the RBAC gate),
// so a test can set the request role independently of the four-eyes subject.
func mcpReqLive(method, target string, role UIRole, body, sub string) *httptest.ResponseRecorder {
	initSessionSecret() // encodeSession needs the HMAC key
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if role != "" {
		r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	}
	if sub != "" {
		tok, err := encodeSession(&Session{Sub: sub, Role: string(role), Provider: "local", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()})
		if err == nil {
			r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: tok})
		}
	}
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerMCPRoutes(mux)
	mux.ServeHTTP(w, r)
	return w
}

// liveCreateBody builds a live_execution create request body for the seeded controlled/t tool.
func liveCreateBody(fpHex string, catRev uint64) string {
	b, _ := json.Marshal(mcpToolApprovalRequestBody{
		ServerID: "controlled", ToolName: "t", Fingerprint: fpHex, CatalogRevision: catRev,
		Purpose: "live_execution", Reason: "reviewed for live", ExpiresInSeconds: 3600,
	})
	return string(b)
}

const liveApprovalsPath = "/api/mcp/tool-approvals?tenant=" + ttTenant
const liveDecisionPath = "/api/mcp/tool-approval-decision?tenant=" + ttTenant

// §5/§25: a live_execution request without an authenticated session is refused fail-closed — a live
// trust decision may never be attributed to an anonymous, IP-only actor. (No session cookie here.)
func TestLiveTrustHTTP_UnauthenticatedRequestFailsClosed(t *testing.T) {
	resetInventory(t)
	_, cat, _, _, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	// RoleOperator via context, but NO session cookie ⇒ mcpLivePrincipal fails closed.
	rec := mcpReq(http.MethodPost, liveApprovalsPath, RoleOperator, liveCreateBody(fpHex, cat.Current().Revision()))
	if rec.Code == http.StatusOK {
		t.Fatalf("an unauthenticated live request must be refused, got 200: %s", rec.Body.String())
	}
	if rec.Code < 400 {
		t.Fatalf("want a client error, got %d", rec.Code)
	}
}

// §16/§25: four-eyes on the CANONICAL principal. A request and approval by the SAME session subject
// (even from different requests/IPs) is refused; two DISTINCT subjects succeed. RBAC roles gate who
// may request vs approve.
func TestLiveTrustHTTP_FourEyesAndRBAC(t *testing.T) {
	resetInventory(t)
	_, cat, _, _, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	rev := cat.Current().Revision()

	// A viewer may NOT create (create is operator+).
	if rec := mcpReqLive(http.MethodPost, liveApprovalsPath, RoleViewer, liveCreateBody(fpHex, rev), "carol"); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer create must be 403, got %d", rec.Code)
	}

	// alice (operator) creates the live request.
	rec := mcpReqLive(http.MethodPost, liveApprovalsPath, RoleOperator, liveCreateBody(fpHex, rev), "alice")
	if rec.Code != http.StatusOK {
		t.Fatalf("operator live create must be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var created mcpToolApprovalView
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.Purpose != "live_execution" || created.RequestedBy != "alice" || created.Status != "pending" {
		t.Fatalf("unexpected created view: %+v", created)
	}

	decide := func(action, sub string, role UIRole) *httptest.ResponseRecorder {
		b, _ := json.Marshal(mcpToolApprovalDecisionBody{ApprovalID: created.ApprovalID, Action: action})
		return mcpReqLive(http.MethodPost, liveDecisionPath, role, string(b), sub)
	}

	// An operator may NOT approve (decision is admin+).
	if rec := decide("approve", "dave", RoleOperator); rec.Code != http.StatusForbidden {
		t.Fatalf("operator approve must be 403, got %d", rec.Code)
	}
	// alice (now acting as admin) approving her OWN request is refused: four-eyes on the canonical
	// subject catches it regardless of the IP/role the second request carries.
	if rec := decide("approve", "alice", RoleAdmin); rec.Code == http.StatusOK {
		t.Fatalf("self-approval by the same subject must be refused, got 200: %s", rec.Body.String())
	}
	// bob (a DISTINCT admin principal) approves — four-eyes satisfied.
	rec = decide("approve", "bob", RoleAdmin)
	if rec.Code != http.StatusOK {
		t.Fatalf("distinct-principal approve must be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var approved mcpToolApprovalView
	if err := json.Unmarshal(rec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if approved.Status != "active" || approved.ApprovedBy != "bob" || approved.RequestedBy != "alice" {
		t.Fatalf("want an active four-eyes grant, got %+v", approved)
	}

	// §21: a viewer can READ the approval and see the review-relevant fields (purpose, requester,
	// approver, fingerprint, status, expiry) — never a secret.
	rd := mcpReqLive(http.MethodGet, "/api/mcp/tool-approvals?tenant="+ttTenant+"&id="+approved.ApprovalID, RoleViewer, "", "carol")
	if rd.Code != http.StatusOK {
		t.Fatalf("viewer read must be 200, got %d", rd.Code)
	}
	var view mcpToolApprovalView
	if err := json.Unmarshal(rd.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode read: %v", err)
	}
	if view.Purpose != "live_execution" || view.RequestedBy != "alice" || view.ApprovedBy != "bob" || view.ExpiresAt == nil || view.Fingerprint == "" {
		t.Fatalf("viewer review surface incomplete: %+v", view)
	}
}
