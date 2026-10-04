package main

import (
	"errors"
	"net/http"
	"time"
)

// ── UI admin session cookie ───────────────────────────────────────────────
// Separate from the proxy-user ps_session cookie; same HMAC encoding.

const uiSessionCookieName = "ps_ui_session"

const uiSessionAudience = "culvert-admin-ui"

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
		Audience: uiSessionAudience,
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
	sess, err := decodeSession(c.Value)
	if err != nil || sess == nil {
		return sess, err
	}
	// Only the UI login/setup issuer writes local sessions with an explicit
	// administrator-UI role. Portal cookies share the HMAC format but carry no
	// such role, so renaming ps_session must never confer UI authority.
	if sess.Provider != "local" || sess.Audience != uiSessionAudience {
		return nil, errors.New("session is not an admin UI session")
	}
	// Bound local sessions by BOTH the signed role and the current roster.
	// Demotion takes effect immediately; promotion needs a fresh login so an
	// older low-privilege cookie never silently acquires greater authority.
	signedRole, valid := sessionRoleOrReject(sess.Role)
	currentRole, exists := cfg.UIUserRole(sess.Sub)
	if !valid || !exists {
		return nil, errors.New("local session no longer authorized")
	}
	if signedRole.HasRole(currentRole) {
		sess.Role = string(currentRole)
	}
	return sess, nil
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
// Empty is also rejected: legacy role-less UI tokens are indistinguishable
// from valid proxy-portal tokens, which carry no admin role. Their holders must
// log in again. Never promote missing or unknown authorization to administrator.
func sessionRoleOrReject(sessionRole string) (UIRole, bool) {
	role := UIRole(sessionRole)
	if !roleEnrolled(role) {
		return "", false
	}
	return role, true
}
