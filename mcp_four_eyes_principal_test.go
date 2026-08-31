package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Four-eyes principal identity (SEC-FE-1).
//
// Every separation-of-duty gate in the MCP subsystem is a string equality on the
// principal recorded for the request — approval.Store.Approve's `approver == requester`
// and canary.EvaluateTrust's `RequestedBy == ApprovedBy`. Those principals used to come
// from auditActor(r), which is deliberately "<identity>@<clientIP>" for AUDIT purposes.
// The appended half is a network coordinate the acting principal controls (X-Forwarded-For
// through a configured trusted proxy; otherwise the peer address), so one authenticated
// human produced two different principals and defeated every four-eyes gate at once.
//
// These tests pin the split: approvalPrincipal is the STABLE authenticated subject and
// nothing else, auditActor keeps its coordinate, and an unattributable caller is refused.

// mkAuthedReq builds a request carrying a real admin session cookie for `user`, arriving
// through a trusted proxy with the given X-Forwarded-For.
func mkAuthedReq(t *testing.T, user, xff string) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	seed := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := setUISessionCookie(rec, seed, user, RoleAdmin); err != nil {
		t.Fatalf("setUISessionCookie: %v", err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie minted")
	}
	r := httptest.NewRequest(http.MethodPost, "/api/mcp/publication?tenant=acme", nil)
	r.RemoteAddr = "10.0.0.9:1234" // inside the trusted-proxy set below
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	r.AddCookie(cookies[0])
	return r
}

func withTrustedProxy(t *testing.T) {
	t.Helper()
	prev := ListTrustedProxyCIDRs()
	if err := SetTrustedProxyCIDRs([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs: %v", err)
	}
	t.Cleanup(func() { _ = SetTrustedProxyCIDRs(prev) })
}

// --- REGRESSION: the proven bypass ----------------------------------------
//
// This is the exact shape that defeated four-eyes: ONE admin, ONE session cookie, two
// requests differing only in X-Forwarded-For. It must now yield ONE principal.
func TestApprovalPrincipal_IsStableAcrossClientCoordinate(t *testing.T) {
	withTrustedProxy(t)

	a := approvalPrincipal(mkAuthedReq(t, "alice", "198.51.100.1"))
	b := approvalPrincipal(mkAuthedReq(t, "alice", "198.51.100.2"))
	c := approvalPrincipal(mkAuthedReq(t, "alice", "")) // no XFF at all: peer address

	if a == "" {
		t.Fatal("an authenticated admin must resolve to a principal")
	}
	if a != b || a != c {
		t.Fatalf("one admin produced several four-eyes principals: %q / %q / %q — "+
			"a client-controlled coordinate is still in the principal", a, b, c)
	}
	if a != "alice" {
		t.Fatalf("principal = %q, want the authenticated subject %q", a, "alice")
	}
	if strings.ContainsAny(a, "@:") {
		t.Fatalf("principal %q still embeds a network coordinate", a)
	}
}

// Two DIFFERENT humans must still be two principals — the fix must not collapse
// distinct subjects into one, which would make four-eyes unsatisfiable.
func TestApprovalPrincipal_DistinctSubjectsStayDistinct(t *testing.T) {
	withTrustedProxy(t)
	alice := approvalPrincipal(mkAuthedReq(t, "alice", "198.51.100.1"))
	bob := approvalPrincipal(mkAuthedReq(t, "bob", "198.51.100.1")) // SAME coordinate
	if alice == bob || alice == "" || bob == "" {
		t.Fatalf("distinct admins must be distinct principals: %q vs %q", alice, bob)
	}
}

// The audit ring keeps the coordinate. The fix changes the four-eyes principal ONLY;
// auditActor must still say who acted AND from where (RISK-019).
func TestAuditActor_StillCarriesTheClientCoordinate(t *testing.T) {
	withTrustedProxy(t)
	got := auditActor(mkAuthedReq(t, "alice", "198.51.100.1"))
	if got != "alice@198.51.100.1" {
		t.Fatalf("auditActor = %q, want %q — audit attribution must be unchanged", got, "alice@198.51.100.1")
	}
}

// --- AUTHENTICATION: unattributable callers fail closed --------------------
//
// Before setup completes, uiAuthMiddleware grants RoleAdmin with NO identity. Mapping
// that to a principal literally named "unknown" would make every anonymous caller the
// SAME principal — and a four-eyes gate between two anonymous callers would read as
// satisfied by two DIFFERENT anonymous callers while refusing one honest retry. Absent
// is the only correct answer, and the handler must refuse.
func TestApprovalPrincipal_UnauthenticatedIsAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/mcp/publication?tenant=acme", nil)
	r.RemoteAddr = "198.51.100.7:1111"
	if got := approvalPrincipal(r); got != "" {
		t.Fatalf("principal = %q, want \"\" for an unauthenticated caller", got)
	}
	if got := sessionAdmin(r); got != "unknown" {
		t.Fatalf("sessionAdmin = %q, want \"unknown\" (its own contract is unchanged)", got)
	}
}

func TestMCPFourEyesPrincipal_RefusesUnattributableCaller(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/mcp/publication?tenant=acme", nil)
	r.RemoteAddr = "198.51.100.7:1111"

	got, ok := mcpFourEyesPrincipal(w, r)
	if ok {
		t.Fatalf("an unattributable caller must be refused; got principal %q", got)
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if !strings.Contains(w.Body.String(), "approval_not_authorized") {
		t.Fatalf("body = %q, want the approval_not_authorized reason code", w.Body.String())
	}
}

func TestMCPFourEyesPrincipal_AdmitsAuthenticatedCaller(t *testing.T) {
	withTrustedProxy(t)
	w := httptest.NewRecorder()
	got, ok := mcpFourEyesPrincipal(w, mkAuthedReq(t, "alice", "198.51.100.1"))
	if !ok {
		t.Fatalf("an authenticated admin must be admitted; body=%q", w.Body.String())
	}
	if string(got) != "alice" {
		t.Fatalf("principal = %q, want %q", got, "alice")
	}
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("the admit path must write nothing: code=%d body=%q", w.Code, w.Body.String())
	}
}

// --- Basic-auth path -------------------------------------------------------
//
// Programmatic/CLI access carries no session cookie; uiAuthMiddleware puts the verified
// Basic username in the request context. That identity is equally stable and must be
// used, so a CLI-driven approval is attributable — and so a CLI request and a browser
// request by the SAME human do not read as two principals.
func TestApprovalPrincipal_UsesBasicAuthIdentity(t *testing.T) {
	withTrustedProxy(t)
	r := httptest.NewRequest(http.MethodPost, "/api/mcp/publication?tenant=acme", nil)
	r.RemoteAddr = "10.0.0.9:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.42")
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "alice"))

	if got := approvalPrincipal(r); got != "alice" {
		t.Fatalf("principal = %q, want %q from the Basic-auth identity", got, "alice")
	}
	// Same human, two transports, one principal — the property four-eyes depends on.
	browser := approvalPrincipal(mkAuthedReq(t, "alice", "198.51.100.1"))
	if browser != "alice" {
		t.Fatalf("browser principal = %q, want %q", browser, "alice")
	}
}

// --- ANTI-DRIFT ------------------------------------------------------------
//
// The four-eyes principal must never be re-derived from auditActor. This is a source
// wall, not a behavioural one: a future edit that "simplifies" mcpFourEyesPrincipal back
// to auditActor would silently reopen the bypass with every test above still passing,
// because the tests fix the trusted-proxy set and could be satisfied by a constant IP.
func TestFourEyesPrincipal_NeverDerivedFromAuditActor(t *testing.T) {
	for _, f := range []string{"ui_mcp.go", "ui_mcp_tooltrust.go", "ui_rbac.go"} {
		src := readSourceForTest(t, f)
		for _, banned := range []string{
			"approval.PrincipalID(auditActor(",
			"RequestedBy:         auditActor(",
			"actor := auditActor(r)\n\tswitch body.Action",
		} {
			if strings.Contains(src, banned) {
				t.Errorf("%s: a four-eyes principal is derived from auditActor (%q). "+
					"auditActor embeds a client-controlled network coordinate; use "+
					"mcpFourEyesPrincipal / approvalPrincipal instead.", f, banned)
			}
		}
	}
}

// readSourceForTest reads a repository source file for the anti-drift wall above.
func readSourceForTest(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}
