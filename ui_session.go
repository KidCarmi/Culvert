package main

import (
	"net/http"
	"time"
)

// ── UI admin session cookie ───────────────────────────────────────────────
// Separate from the proxy-user ps_session cookie; same HMAC encoding.

const uiSessionCookieName = "ps_ui_session"

// isSecureRequest returns true when the request was received over TLS, either
// directly or via a reverse proxy that set X-Forwarded-Proto: https. Used to
// drive the dynamic Secure flag on UI session cookies.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func setUISessionCookie(w http.ResponseWriter, r *http.Request, username string, role UIRole) error {
	s := &Session{
		Sub:      username,
		Provider: "local",
		Role:     string(role),
		Exp:      time.Now().Add(getSessionTTL()).Unix(),
		Jti:      newSessionJti(),
	}
	value, err := encodeSession(s)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is set dynamically via isSecureRequest; HttpOnly+SameSiteStrict+HMAC-signed value are in place
		Name:     uiSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(getSessionTTL().Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func readUISessionCookie(r *http.Request) (*Session, error) {
	c, err := r.Cookie(uiSessionCookieName)
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeSession(c.Value)
}

func clearUISessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is set dynamically via isSecureRequest; HttpOnly+SameSiteStrict are in place
		Name:     uiSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// sessionRoleOrReject resolves the role carried by a verified session cookie
// into a role this build can evaluate, or refuses the session outright.
//
// THE EMPTY VALUE IS THE ONLY COMPATIBILITY CASE. Sessions minted before the
// role field existed carry "" and must keep resolving to RoleAdmin — those are
// pre-RBAC single-admin deployments and narrowing that would lock them out
// mid-session. Every OTHER unenrolled value is refused.
//
// The two used to be one branch (`if !role.HasRole(RoleViewer) { role = RoleAdmin }`),
// and the predicate does not distinguish them: rolePriority is a map, so an
// unenrolled key reads as 0 and "" and "read-only" and "Admin" were all equally
// below viewer — so all of them were promoted to ADMIN. The roster loader's
// missing role validation (see loadedRosterRole) made that reachable from a
// restored or hand-edited ui_users.json without forging anything: the value
// rides a legitimately HMAC-signed cookie the appliance minted itself.
//
// Splitting the branch is what makes the compat case narrow enough to keep.
func sessionRoleOrReject(sessionRole string) (UIRole, bool) {
	if sessionRole == "" {
		return RoleAdmin, true // pre-RBAC session, minted before the role field
	}
	role := UIRole(sessionRole)
	if !roleEnrolled(role) {
		return "", false
	}
	return role, true
}
