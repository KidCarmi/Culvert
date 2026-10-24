package main

import (
	"net/http"
	"time"
)

// ── UI admin session cookie ───────────────────────────────────────────────
// Separate from the proxy-user ps_session cookie; same HMAC encoding.

const uiSessionCookieName = "ps_ui_session"

// uiSessionProvider is the Provider stamped on every session the ADMIN plane
// mints, and the token-class discriminator uiAuthMiddleware requires (
// SEC-UISESS-1). setUISessionCookie below is the only minter of
// uiSessionCookieName and has always set this value; the proxy end-user
// cookie (ps_session, session.go setSessionCookie) carries the IdP profile id
// instead. Both cookies share one signing key and one payload schema, so
// without this check the cookie NAME — which the caller chooses — was the only
// thing separating a proxy end user's session from an admin operator's.
//
// Read by setUISessionCookie and by classifyUISession. Keep it ONE constant: a
// second spelling at either site is how the issuer and the gate drift into
// disagreeing, and the direction that drift fails is open.
const uiSessionProvider = "local"

// isSecureRequest returns true when the request was received over TLS, either
// directly or via a reverse proxy that set X-Forwarded-Proto: https. Used to
// drive the dynamic Secure flag on UI session cookies.
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func setUISessionCookie(w http.ResponseWriter, r *http.Request, username string, role UIRole) error {
	s := &Session{
		Sub:      username,
		Provider: uiSessionProvider,
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

// uiSessionVerdict is the outcome of resolving the admin UI session cookie.
//
// The three states are NOT collapsible to a bool: "no usable cookie" and "a
// cookie that must not authorize" lead to different handling. uiAuthMiddleware
// falls through to the HTTP Basic scheme on the first and answers 401 (clearing
// the cookie) on the second, and apiAuthStatus reports the second as logged out
// rather than as the role the cookie claims.
type uiSessionVerdict int

const (
	// uiSessionAbsent: no cookie, or one that did not verify/decode. The
	// caller may try another authentication scheme.
	uiSessionAbsent uiSessionVerdict = iota
	// uiSessionRefused: a cookie is present and verified, but it is not an
	// admin session this build will honour.
	uiSessionRefused
	// uiSessionValid: the session authorizes the returned role.
	uiSessionValid
)

// resolveUISession is the ONE admission decision for the admin UI session
// cookie, shared by uiAuthMiddleware and by apiAuthStatus (SEC-UISESS-1).
//
// It exists because those two had drifted apart. /api/auth/status is on the
// uiAuthMiddleware public allowlist (isPublicUIAuthPath), so it never passes
// through the middleware and resolved the cookie itself — and its own comment
// claimed it applied "the same fail-closed resolution uiAuthMiddleware
// applies" while checking strictly less. A proxy-issued ps_session replayed
// under the admin cookie name was refused by the middleware but still reported
// by the status endpoint as `loggedIn: true, role: admin`, so the console
// rendered the full admin surface for a principal every gated endpoint then
// refused with 401. The same drift already mis-reported a DELETED user's
// session as an admin, because the roster check (Finding 5.2) lived only in the
// middleware.
//
// A second copy of this decision is how that divergence happened, and the
// direction it diverges is toward reporting more authority than is granted.
// Both call sites now read the verdict from here, and sseAuthStillValid's
// mid-stream re-check reads it from classifyUISession.
func resolveUISession(r *http.Request) (*Session, UIRole, uiSessionVerdict) {
	sess, err := readUISessionCookie(r)
	if err != nil || sess == nil {
		// No cookie, or one that failed to verify. Indistinguishable to the
		// caller by design: a forged or stale cookie must not be treated as
		// an assertion about identity, only as absent.
		return nil, "", uiSessionAbsent
	}
	role, verdict := classifyUISession(sess)
	return sess, role, verdict
}

// classifyUISession is resolveUISession's decision over an already VERIFIED
// payload, for a caller that has decoded the cookie itself (sseAuthStillValid
// must tell "no longer verifies" apart from "absent"). It never returns
// uiSessionAbsent.
func classifyUISession(sess *Session) (UIRole, uiSessionVerdict) {
	// The admin plane is the only minter of this cookie and always stamps
	// uiSessionProvider; anything else is a token issued for the proxy plane,
	// whose sessions set no Role and would take sessionRoleOrReject's
	// pre-RBAC compatibility branch to RoleAdmin.
	if sess.Provider != uiSessionProvider || !cfg.UIUserExists(sess.Sub) {
		return "", uiSessionRefused
	}
	role, ok := sessionRoleOrReject(sess.Role)
	if !ok {
		// A signed session naming a role this build does not enroll.
		return "", uiSessionRefused
	}
	return role, uiSessionValid
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
