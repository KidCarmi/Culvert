package main

import (
	"net/http"
	"time"
)

// ── UI admin session cookie ───────────────────────────────────────────────
// Separate from the proxy-user ps_session cookie; same HMAC encoding.

const uiSessionCookieName = "ps_ui_session"

// uiSessionProvider is the Provider value setUISessionCookie stamps on every
// admin-UI session it mints, and the ONLY value the admin plane honours. The
// minter below and uiSessionAdmissible share this constant so the two can
// never disagree about what an admin-UI session looks like.
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

// uiSessionAdmissible reports whether a cryptographically VERIFIED
// ps_ui_session payload may be honoured as an admin-UI session. Every admin
// surface that resolves a role, an identity or a trust decision from that
// cookie must pass through here.
//
// SEC-UISESSION-AUD-1. The admin-UI cookie (ps_ui_session) and the proxy-user
// portal cookie (ps_session) are the SAME signed token type under the SAME
// HMAC key, and the signature covers the PAYLOAD ONLY — not the cookie name.
// So a token this appliance minted for an ordinary IdP-authenticated proxy
// user verifies perfectly when it is replayed under the admin cookie's name.
// The payload carries no audience claim, so the only field that distinguishes
// the two is Provider: setUISessionCookie is the ONLY minter of
// ps_ui_session and stamps uiSessionProvider on every one, while the portal
// minter (setSessionCookie, session.go) copies the IdP profile id out of the
// asserted Identity and sets no Role at all.
//
// The pre-fix predicate was `Provider == "local" && !UIUserExists(Sub)`, which
// made the roster-existence requirement CONDITIONAL on the very field that
// tells the two cookies apart. A replayed portal token therefore skipped the
// existence check outright, and — because setSessionCookie sets no Role — the
// empty-role pre-RBAC compatibility branch in sessionRoleOrReject then
// resolved it to RoleADMIN. Any directory user who could complete
// captive-portal SSO held full admin on the control plane, with no forgery and
// no key: the appliance signed the token itself. It also bypassed admin TOTP
// and admin lockout, both of which live in the login handler and are never
// consulted on the cookie path.
//
// Both conditions are now REQUIRED, and that is behaviour-preserving for every
// legitimate admin session: ps_ui_session has exactly one minter, it hard-codes
// uiSessionProvider, and a local session whose Sub is absent from the roster
// was already refused before this change. Only the non-local branch tightens.
//
// Attribution is deliberately NOT routed through here: sessionAdmin (ui_rbac.go)
// and auditActor (ui_helpers.go) gate nothing, and recording the identity a
// refused session claimed is more useful than recording "unknown".
func uiSessionAdmissible(sess *Session) bool {
	return uiSessionAudience(sess) && cfg.UIUserExists(sess.Sub)
}

// uiSessionAudience is the AUDIENCE half on its own: it reports whether a
// verified payload was minted as an admin-UI session rather than as the
// proxy-user portal cookie. It is for a surface that needs the audience and
// nothing more — one that already runs BEHIND uiAuthMiddleware, which has
// applied the full uiSessionAdmissible test (roster existence included) before
// the handler is reached. Re-testing roster existence there would be redundant,
// and would make the surface refuse a principal the gate had already admitted.
//
// Everything that resolves a ROLE from the cookie must use uiSessionAdmissible,
// not this.
func uiSessionAudience(sess *Session) bool {
	return sess != nil && sess.Provider == uiSessionProvider
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
