package main

// auditActor is a PRINCIPAL, not only a rendered audit string. Non-audit
// consumers compare it for identity: apiMCPPublications records it as the
// publication requester and apiMCPPublicationDecision / apiMCPApprovalDecision
// pass it as the approver, so the approval store's four-eyes check
// (approver == requester ⇒ approval_self_approval) is an equality test on this
// value. Bounding it lossily (a 64-byte prefix plus the original length) made
// two DISTINCT configured administrators whose names share that prefix and
// length, connecting from the same client address, compare equal: the second
// admin's legitimate approval was refused as self-approval (Codex review,
// PR #1532). The length bound belongs only to the rendered AuditEntry fields.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mcpReqAs drives the MCP admin mux as an authenticated Basic-auth identity
// (uiUserKey, which auditActor falls back to without a session cookie) from a
// fixed client address, so two calls differ ONLY in the username.
func mcpReqAs(t *testing.T, method, target, user, clientIP, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	r.RemoteAddr = clientIP + ":9999"
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin)
	ctx = context.WithValue(ctx, uiUserKey{}, user)
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	registerMCPRoutes(mux)
	mux.ServeHTTP(w, r)
	return w
}

// collidingAdminNames returns two distinct names that share the first
// loginAuditActorMax bytes AND the total byte length — exactly the pair a
// prefix-plus-length bound cannot tell apart.
func collidingAdminNames() (requester, approver string) {
	prefix := strings.Repeat("a", loginAuditActorMax)
	return prefix + "-requester-0001", prefix + "-approver-00002"
}

// activeMCPPolicyRevision reads the capability's CURRENT active revision through
// GET /api/mcp/policy, the same store the publication handler compares
// expected_base against. The policy stores are process-wide and other tests
// (shadow, rollout) publish to them, so a hard-coded base of 0 is stale under
// -shuffle; a unique tenant isolates pending requests, not the base revision.
func activeMCPPolicyRevision(t *testing.T, capability, user, clientIP string) uint64 {
	t.Helper()
	w := mcpReqAs(t, http.MethodGet, "/api/mcp/policy?capability="+capability, user, clientIP, "")
	if w.Code != http.StatusOK {
		t.Fatalf("read active %s policy: %d %s", capability, w.Code, w.Body.String())
	}
	var got struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode active %s policy: %v %s", capability, err, w.Body.String())
	}
	return got.Revision
}

func TestAuditActor_PrincipalKeepsDistinctLongAdminsDistinct(t *testing.T) {
	a, b := collidingAdminNames()
	if a == b || len(a) != len(b) || a[:loginAuditActorMax] != b[:loginAuditActorMax] {
		t.Fatal("fixture must be two distinct names sharing the bounded prefix and length")
	}
	ra := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", http.NoBody)
	ra.RemoteAddr = "198.51.100.120:9999"
	ra = ra.WithContext(context.WithValue(ra.Context(), uiUserKey{}, a))
	rb := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", http.NoBody)
	rb.RemoteAddr = "198.51.100.120:9999"
	rb = rb.WithContext(context.WithValue(rb.Context(), uiUserKey{}, b))

	if got, want := auditActor(ra), a+"@198.51.100.120"; got != want {
		t.Errorf("auditActor must return the full, untruncated principal: got %d bytes, want %q", len(got), want)
	}
	if auditActor(ra) == auditActor(rb) {
		t.Error("two distinct administrators produced the SAME auditActor principal: every identity " +
			"comparison on it (MCP four-eyes, tool-trust four-eyes) treats them as one person")
	}
	// The rendered audit Actor is bounded, but must still tell the two apart.
	ea, eb := auditEntryActor(ra), auditEntryActor(rb)
	if ea == eb {
		t.Errorf("bounded audit Actors are indistinguishable for distinct administrators: %q", ea)
	}
	for _, e := range []string{ea, eb} {
		if strings.Contains(e, a) || strings.Contains(e, b) {
			t.Errorf("bounded audit Actor still carries a full oversize name: %d bytes", len(e))
		}
	}
}

func TestMCPPublication_DistinctLongAdminApprovalIsNotSelfApproval(t *testing.T) {
	const clientIP = "198.51.100.121"
	requester, approver := collidingAdminNames()
	// A unique tenant keeps this request apart from any other test's pending
	// publications in the process-wide MCP admin singleton.
	tenant := "tenant-auditactor-" + time.Now().Format("150405.000000000")
	// The candidate names the revision AFTER the active one, against the base the
	// store holds now (both are process-wide; see activeMCPPolicyRevision).
	base := activeMCPPolicyRevision(t, "gateway", requester, clientIP)
	candidate := `{"schema_version":1,"capability":"gateway","policy_revision":` + strconv.FormatUint(base+1, 10) +
		`,"default_action":"DENY","rules":[]}`
	create := mcpReqAs(t, http.MethodPost, "/api/mcp/publications", requester, clientIP,
		`{"capability":"gateway","tenant":"`+tenant+`","candidate":`+candidate+`,"expected_base":`+strconv.FormatUint(base, 10)+`}`)
	if create.Code != http.StatusOK {
		t.Fatalf("create publication: %d %s", create.Code, create.Body.String())
	}
	var created struct {
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil || created.RequestID == "" {
		t.Fatalf("create publication returned no request_id: %v %s", err, create.Body.String())
	}

	decide := func(user string) *httptest.ResponseRecorder {
		return mcpReqAs(t, http.MethodPost, "/api/mcp/publication-decision", user, clientIP,
			`{"request_id":"`+created.RequestID+`","tenant":"`+tenant+`","action":"approve"}`)
	}

	// The DISTINCT second administrator must pass four-eyes. In the disabled
	// default posture the decision then fails closed on durability, which is
	// the expected, unrelated refusal; what must never appear is self-approval.
	if got := decide(approver); strings.Contains(got.Body.String(), "approval_self_approval") {
		t.Fatalf("a DISTINCT administrator's approval was refused as self-approval (%d %s): the "+
			"principal compared by four-eyes was truncated to a prefix the two names share",
			got.Code, got.Body.String())
	}
	// CONTROL: the requester approving their own publication is still refused.
	if got := decide(requester); !strings.Contains(got.Body.String(), "approval_self_approval") {
		t.Fatalf("the requester approving their own publication was not refused as self-approval: %d %s",
			got.Code, got.Body.String())
	}
}
