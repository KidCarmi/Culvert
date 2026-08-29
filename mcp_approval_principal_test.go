package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// SEC-MCP-4E-1 / SEC-MCP-4E-2 — the MCP four-eyes principal is an IDENTITY, and the
// tool-trust plane enforces separation of duties.
//
// Before this change every MCP approval PrincipalID was built from auditActor(r), an
// attribution string that is realClientIP(r) prefixed with "<sub>@" only when a UI session
// cookie is present. That made four-eyes key on network location: the same human passed it
// from a second address, and on the HTTP Basic (programmatic) path — which carries no
// session cookie — the username never appeared in the principal at all. The ADR-0034
// tool-trust plane, added on top, had no separation-of-duties check whatsoever.

// mcpReqAs is mcpReq with an authenticated identity: it attaches an admin UI session
// cookie for sub, and optionally overrides the client address, so a test can drive two
// DISTINCT humans (or one human from two addresses) through the real handlers.
func mcpReqAs(t *testing.T, method, target string, role UIRole, body, sub, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	if sub != "" {
		r.AddCookie(uiSessionCookieForTest(t, sub))
	}
	if remoteAddr != "" {
		r.RemoteAddr = remoteAddr
	}
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerMCPRoutes(mux)
	mux.ServeHTTP(w, r)
	return w
}

// TestMCPApprovalPrincipal_IsIdentityNotClientAddress is the core REGRESSION test: the
// four-eyes principal for one authenticated human must be IDENTICAL from two different
// client addresses, where auditActor — correctly, for attribution — differs.
func TestMCPApprovalPrincipal_IsIdentityNotClientAddress(t *testing.T) {
	mk := func(addr string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/tool-approval-decision", nil)
		r.RemoteAddr = addr
		r.AddCookie(uiSessionCookieForTest(t, "alice"))
		return r
	}
	a, b := mk("198.51.100.7:1111"), mk("203.0.113.9:2222")
	pa, pb := mcpApprovalPrincipal(a), mcpApprovalPrincipal(b)
	if pa != "alice" || pb != "alice" {
		t.Fatalf("principal = %q / %q, want alice from both addresses", pa, pb)
	}
	if auditActor(a) == auditActor(b) {
		t.Fatal("precondition: auditActor must still differ by address (attribution keeps the IP)")
	}
	if strings.Contains(pa, "198.51.100.7") || strings.Contains(pb, "203.0.113.9") {
		t.Fatalf("the four-eyes principal must never carry the client address: %q / %q", pa, pb)
	}
}

// TestMCPApprovalPrincipal_DistinctHumansStayDistinct is the POSITIVE control: two
// different subjects from the SAME address must remain two principals, so a legitimate
// four-eyes approval is never refused. This is the half the pre-change code got wrong on
// the Basic path, where both collapsed onto the shared address.
func TestMCPApprovalPrincipal_DistinctHumansStayDistinct(t *testing.T) {
	mk := func(sub string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/approval-decision", nil)
		r.RemoteAddr = "198.51.100.7:1111" // one shared bastion / NAT egress
		r.AddCookie(uiSessionCookieForTest(t, sub))
		return r
	}
	if mcpApprovalPrincipal(mk("alice")) == mcpApprovalPrincipal(mk("bob")) {
		t.Fatal("two humans behind ONE address must be two principals")
	}
}

// TestMCPApprovalPrincipal_NoIdentityFallsBackToAuditActor pins the documented degenerate
// case: with no session and no trusted Basic identity (the pre-setup bootstrap path, where
// the admin API has no authentication at all), the principal falls back to auditActor —
// byte-identical to the previous behaviour, never worse.
func TestMCPApprovalPrincipal_NoIdentityFallsBackToAuditActor(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/approval-decision", nil)
	r.RemoteAddr = "198.51.100.7:1111"
	if got, want := mcpApprovalPrincipal(r), auditActor(r); got != want {
		t.Fatalf("fallback principal = %q, want auditActor %q", got, want)
	}
}

// TestMCPApprovalPrincipal_UnverifiedBasicHeaderIsNotAnIdentity pins the trust boundary on
// the Basic path: uiAuthMiddleware only reaches its VerifyUIUser branch once the deployment
// is configured, and its pre-setup bootstrap branch admits an UNVERIFIED Basic header. An
// unverified username must therefore never become a principal — otherwise a caller could
// mint two principals from one request stream during bootstrap.
func TestMCPApprovalPrincipal_UnverifiedBasicHeaderIsNotAnIdentity(t *testing.T) {
	if cfg.IsConfigured() {
		t.Skip("this test pins the NOT-configured (pre-setup) branch")
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/approval-decision", nil)
	r.RemoteAddr = "198.51.100.7:1111"
	r.SetBasicAuth("attacker-chosen", "x")
	if got := mcpApprovalPrincipal(r); got != auditActor(r) {
		t.Fatalf("unverified Basic username became a principal: %q", got)
	}
}

// toolApprovalReqBody builds the create-request body for the seeded tool.
func toolApprovalReqBody(t *testing.T, cat *catalog.Catalog, serverID, toolName, fpHex string) string {
	t.Helper()
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(serverID), Name: toolName})
	if !ok {
		t.Fatalf("tool %s/%s missing", serverID, toolName)
	}
	return `{"server_id":"` + serverID + `","tool_name":"` + toolName + `","fingerprint":"` + fpHex +
		`","catalog_revision":` + strconv.FormatUint(rec.Revision, 10) + `,"purpose":"shadow_evaluation","reason":"reviewed"}`
}

// TestToolTrust_HTTP_SelfApprovalRefusedAcrossAddresses is the end-to-end SEC-MCP-4E-2
// test over the real admin handlers: one human who requests a tool-trust grant cannot
// approve it — not from the same address, and not from a different one (which is exactly
// how the address-keyed principal used to be evaded). A second human then succeeds, and
// only then does the tool become catalog.Usable.
func TestToolTrust_HTTP_SelfApprovalRefusedAcrossAddresses(t *testing.T) {
	resetInventory(t)
	_, cat, serverID, toolName, fpHex := seedToolTrustInventory(t)
	composeToolTrust(t, nil)
	tenantQ := "?tenant=" + ttTenant

	w := mcpReqAs(t, http.MethodPost, "/api/mcp/tool-approvals"+tenantQ, RoleOperator,
		toolApprovalReqBody(t, cat, serverID, toolName, fpHex), "alice", "198.51.100.7:1111")
	if w.Code != http.StatusOK {
		t.Fatalf("create request = %d (%s)", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	id, _ := created["approval_id"].(string)
	if id == "" {
		t.Fatalf("missing approval_id in %v", created)
	}
	if got, _ := created["requested_by"].(string); got != "alice" {
		t.Fatalf("requested_by = %q, want the identity principal alice (never an address)", got)
	}

	decBody := `{"approval_id":"` + id + `","action":"approve","reason":"reviewed"}`
	// Same human, same address.
	if w := mcpReqAs(t, http.MethodPost, "/api/mcp/tool-approval-decision"+tenantQ, RoleAdmin,
		decBody, "alice", "198.51.100.7:1111"); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "approval_self_approval") {
		t.Fatalf("self-approve = %d (%s), want 403 approval_self_approval", w.Code, strings.TrimSpace(w.Body.String()))
	}
	// Same human, DIFFERENT address — the bypass this change closes.
	if w := mcpReqAs(t, http.MethodPost, "/api/mcp/tool-approval-decision"+tenantQ, RoleAdmin,
		decBody, "alice", "203.0.113.9:2222"); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Body.String(), "approval_self_approval") {
		t.Fatalf("self-approve from a second address = %d (%s), want 403 approval_self_approval",
			w.Code, strings.TrimSpace(w.Body.String()))
	}
	// The refusals must not have granted anything.
	if got := eligibility(t, cat, serverID, toolName); got == catalog.Usable {
		t.Fatal("a refused self-approval must never promote the tool to Usable")
	}

	// A second human approves: the grant lands and the tool becomes Usable.
	w = mcpReqAs(t, http.MethodPost, "/api/mcp/tool-approval-decision"+tenantQ, RoleAdmin,
		decBody, "bob", "198.51.100.7:1111")
	if w.Code != http.StatusOK {
		t.Fatalf("approve by a second human = %d (%s)", w.Code, strings.TrimSpace(w.Body.String()))
	}
	var decided map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &decided); err != nil {
		t.Fatalf("decode decision response: %v", err)
	}
	if decided["status"] != "active" || decided["approved_by"] != "bob" {
		t.Fatalf("decision = %v, want status active approved_by bob", decided)
	}
	if got := eligibility(t, cat, serverID, toolName); got != catalog.Usable {
		t.Fatalf("eligibility after a valid four-eyes approval = %v, want Usable", got)
	}
}

// TestToolTrust_HTTP_SelfApprovalStillAuditsNetworkLocation proves the change did NOT cost
// attribution: audit still records the IP-bearing actor even though the four-eyes
// comparison no longer uses it. The two concerns are deliberately separate.
func TestToolTrust_HTTP_SelfApprovalStillAuditsNetworkLocation(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/tool-approvals", nil)
	r.RemoteAddr = "198.51.100.7:1111"
	r.AddCookie(uiSessionCookieForTest(t, "alice"))
	if actor := auditActor(r); !strings.Contains(actor, "198.51.100.7") || !strings.HasPrefix(actor, "alice@") {
		t.Fatalf("auditActor = %q, want the identity AND the client address for attribution", actor)
	}
}
