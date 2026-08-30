package main

// Security-regression gate: the AUDIT RING must name the Basic-auth admin, not just an IP.
//
// This branch taught sessionAdmin to resolve the HTTP Basic username uiAuthMiddleware stores in
// the request context, so a programmatic admin action is attributed to the real actor rather than
// "unknown". auditActor — which feeds Actor on EVERY audit entry (auditEvent → auditEventDiffID)
// and is therefore the compliance record — did not get the same fallback, so the same request
// wrote a durable record naming the operator while the audit line named only an IP.
//
// That gap matters exactly where this branch adds privileged endpoints: a tool-trust approval
// (mcp.tooltrust.approve) and a Shadow Exit Review attestation
// (mcp.canary.shadow-exit-review.attest) are both audited through auditEvent. On an appliance
// where several admins reach the API through one bastion or NAT egress, an IP alone does not
// answer "who approved this".
//
// The fix only ever ADDS the authenticated name to the IP; it never substitutes for it, and the
// name comes solely from the context value the middleware sets after VerifyUIUser succeeded — so
// there is no header or request field an attacker can set to forge attribution.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// auditActorFor builds a request carrying the given identities and returns the resolved actor.
// cookieSub == "" ⇒ no admin UI session cookie; basicUser == "" ⇒ no authenticated Basic identity.
func auditActorFor(t *testing.T, cookieSub, basicUser, remoteAddr string) string {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/tool-approval-decision", nil)
	r.RemoteAddr = remoteAddr
	if cookieSub != "" {
		r.AddCookie(uiSessionCookieForTest(t, cookieSub))
	}
	if basicUser != "" {
		r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, basicUser))
	}
	return auditActor(r)
}

// TestAuditActor_BasicAuthUsernameIsAttributed is the defect gate: pre-fix this returned the bare
// IP, so a Basic-auth admin action was unattributable in the audit ring.
func TestAuditActor_BasicAuthUsernameIsAttributed(t *testing.T) {
	// TEST-NET-2 discriminator so the assertion cannot collide with other suite traffic.
	got := auditActorFor(t, "", "basic-admin", "198.51.100.91:5150")
	const want = "basic-admin@198.51.100.91"
	if got != want {
		t.Fatalf("SECURITY: auditActor = %q, want %q — a Basic-auth admin action must name the "+
			"authenticated operator in the audit ring, not just the source IP", got, want)
	}
}

// TestAuditActor_CookieIdentityStillWins pins the precedence: the interactive admin UI session is
// the primary identity and must not be displaced by a context username.
func TestAuditActor_CookieIdentityStillWins(t *testing.T) {
	got := auditActorFor(t, "cookie-admin", "basic-admin", "198.51.100.92:5150")
	const want = "cookie-admin@198.51.100.92"
	if got != want {
		t.Fatalf("auditActor = %q, want %q — the admin UI session identity must win over the "+
			"Basic username", got, want)
	}
}

// TestAuditActor_UnauthenticatedKeepsBareIP is the control: with no authenticated identity the
// actor is unchanged from before this fix — the IP alone, never a fabricated name.
func TestAuditActor_UnauthenticatedKeepsBareIP(t *testing.T) {
	got := auditActorFor(t, "", "", "198.51.100.93:5150")
	const want = "198.51.100.93"
	if got != want {
		t.Fatalf("auditActor = %q, want %q — an unauthenticated request must still attribute to "+
			"the client IP only", got, want)
	}
}

// TestAuditActor_IPIsAlwaysRetained pins the accountability half: the name is ADDED to the IP, so
// enriching attribution can never lose the network origin an investigation needs.
func TestAuditActor_IPIsAlwaysRetained(t *testing.T) {
	for _, tc := range []struct{ cookie, basic string }{
		{"cookie-admin", ""},
		{"", "basic-admin"},
		{"cookie-admin", "basic-admin"},
	} {
		got := auditActorFor(t, tc.cookie, tc.basic, "198.51.100.94:5150")
		if !endsWithIP(got, "198.51.100.94") {
			t.Fatalf("auditActor = %q must retain the client IP (cookie=%q basic=%q)", got, tc.cookie, tc.basic)
		}
	}
}

// endsWithIP reports whether actor ends with "@"+ip or equals ip (the unauthenticated shape).
func endsWithIP(actor, ip string) bool {
	if actor == ip {
		return true
	}
	suffix := "@" + ip
	return len(actor) > len(suffix) && actor[len(actor)-len(suffix):] == suffix
}

// TestAuditEvent_BasicAuthActorReachesTheRing proves the fix end-to-end through the real
// auditEvent path a privileged MCP handler uses — the entry the compliance record keeps.
//
// It asserts on entry CONTENT (a unique TEST-NET-2 actor plus the action, above a baseline
// timestamp), never on len(auditGet()) deltas: the ring is bounded at maxAuditLogs and saturates
// under -count=2 -shuffle=on, which is exactly how a length-delta assertion becomes a flake.
func TestAuditEvent_BasicAuthActorReachesTheRing(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/tool-approval-decision", nil)
	r.RemoteAddr = "198.51.100.95:5150"
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-approver"))

	baseline := time.Now().UnixMilli()
	auditEvent(r, "test.basic_auth_actor", "approval-1", "approve")

	const want = "basic-approver@198.51.100.95"
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "test.basic_auth_actor" && e.Actor == want {
			return
		}
	}
	t.Fatalf("SECURITY: no audit entry with actor %q found — a Basic-auth privileged action must "+
		"be attributable to the operator in the audit ring", want)
}
