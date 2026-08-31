package main

import "net/http"

// uiRoleKey is the context key used to propagate the authenticated UI role.
type uiRoleKey struct{}

// uiUserKey is the context key used to propagate the authenticated UI username on auth paths that
// carry no session cookie (HTTP Basic fallback), so admin-action attribution (sessionAdmin) resolves
// the real actor instead of "unknown".
type uiUserKey struct{}

// uiUser extracts the authenticated username injected by uiAuthMiddleware (empty when none is set,
// e.g. the cookie path, where sessionAdmin reads the cookie directly).
func uiUser(r *http.Request) string {
	if u, ok := r.Context().Value(uiUserKey{}).(string); ok {
		return u
	}
	return ""
}

// uiRole extracts the UI role injected by uiAuthMiddleware.
// Returns RoleViewer when no role is in context (safe default).
func uiRole(r *http.Request) UIRole {
	if role, ok := r.Context().Value(uiRoleKey{}).(UIRole); ok && role != "" {
		return role
	}
	return RoleViewer
}

// sessionAdmin returns the authenticated admin username from the session cookie.
// Falls back to "unknown" if no session is found.
// Reads the admin UI cookie (ps_ui_session), NOT the proxy-user cookie
// (ps_session) — cookies are host-scoped, so a browser holding a
// captive-portal session would otherwise attribute admin actions to the
// proxy-user identity.
func sessionAdmin(r *http.Request) string {
	sess, err := readUISessionCookie(r)
	if err == nil && sess != nil {
		if sess.Sub != "" {
			return sess.Sub
		}
		if sess.Email != "" {
			return sess.Email
		}
	}
	// Basic-auth fallback: programmatic/CLI access carries no session cookie, but uiAuthMiddleware
	// stores the authenticated Basic username in context, so an admin action taken that way is still
	// attributed to the real actor rather than "unknown" (Codex P2).
	if u := uiUser(r); u != "" {
		return u
	}
	return "unknown"
}

// approvalPrincipal returns the STABLE authenticated identity of the caller, for use as
// a separation-of-duty (four-eyes) principal. It returns "" when no authenticated
// identity can be resolved, and every caller MUST treat that as fail-closed: a decision
// that cannot be attributed to a named human can never satisfy four-eyes.
//
// ── Why this is NOT auditActor ────────────────────────────────────────────────
//
// auditActor(r) is the AUDIT attribution string and is deliberately
// "<identity>@<clientIP>" (RISK-019) — it names WHO acted and FROM WHERE, which is what
// an audit line wants. It is the wrong value for a four-eyes comparison, because the
// half it appends is a NETWORK COORDINATE the acting principal controls:
//
//   - realClientIP honours X-Forwarded-For whenever the request arrives through a
//     CONFIGURED trusted proxy — the ordinary enterprise shape for an admin UI behind a
//     reverse proxy. One admin, one session cookie, two requests differing only in the
//     XFF header therefore yields two different strings.
//   - With no trusted proxy configured it is still the peer address, so the same human
//     moving between office/VPN/home, or holding a new DHCP lease, is a different
//     "principal" — and two DIFFERENT humans behind one NAT egress can collapse into
//     the same one when neither is logged in (both "unknown@<nat-ip>").
//
// Every four-eyes gate in the MCP subsystem is a string equality on this value —
// approval.Store.Approve's `approver == r.requester`, and canary.EvaluateTrust's
// `RequestedBy == ApprovedBy` — so an IP-bearing principal makes the control both
// bypassable (one human reads as two) and, in the NAT case, wrongly restrictive.
// Separation of duties must compare the AUTHENTICATED SUBJECT and nothing else.
//
// Resolution order matches sessionAdmin (session Sub → session Email → the Basic-auth
// username uiAuthMiddleware placed in context), minus its "unknown" sentinel: an
// unresolvable identity is reported as absent rather than as a principal literally
// named "unknown", which would make every unauthenticated actor the SAME principal and
// let a four-eyes gate read as satisfied between two anonymous callers.
func approvalPrincipal(r *http.Request) string {
	if p := sessionAdmin(r); p != "unknown" {
		return p
	}
	return ""
}

// requireRole returns true when the current session has at least minRole.
// Writes HTTP 403 and returns false when the check fails.
//
// On the failure branch, requireRole calls recordRoleDivergence (C4)
// before writing the 403. recordRoleDivergence is purely
// observability: it never touches the response writer and never
// affects the return value. The 403 below is the real, only response —
// requireRole remains the defense-in-depth backstop, exactly as
// invariant #6 in CLAUDE.md requires.
func requireRole(w http.ResponseWriter, r *http.Request, minRole UIRole) bool {
	if uiRole(r).HasRole(minRole) {
		return true
	}
	recordRoleDivergence(r, minRole)
	http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
	return false
}
