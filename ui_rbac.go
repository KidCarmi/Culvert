package main

import "net/http"

// uiRoleKey is the context key used to propagate the authenticated UI role.
type uiRoleKey struct{}

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
func sessionAdmin(r *http.Request) string {
	sess, err := readSessionCookie(r)
	if err != nil || sess == nil {
		return "unknown"
	}
	if sess.Sub != "" {
		return sess.Sub
	}
	if sess.Email != "" {
		return sess.Email
	}
	return "unknown"
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
