package main

// ui_auth_logout_guard.go — the admission rules in front of the portal logout
// (`/auth/logout`), which since AU-29 performs a DURABLE, fleet-wide session
// revocation rather than a cookie clear. Codex P2 x2 on PR #1437; register rows
// AU-54 and AU-55.

import (
	"net/http"
	"strconv"
	"strings"
)

// portalLogoutIsCrossSite reports whether the browser says this request was
// initiated by another site (AU-55).
//
// The portal cookie is SameSite=Lax, which browsers DO send on a cross-site
// top-level GET navigation, and securityMiddleware's Origin check only runs on
// POST/PUT/DELETE — browsers send no Origin on a plain GET navigation, so it
// could not run there anyway. So any page the user visited could make this
// node revoke the user's session, write the revocations file, and gossip the
// entry to the fleet. Fetch Metadata is the signal that distinguishes that
// request from the user's own click: `cross-site` means another registrable
// domain initiated it.
//
// Only an explicit `cross-site` is treated as foreign. `same-origin`,
// `same-site`, `none` (typed URL, bookmark) and an ABSENT header keep the
// pre-existing behaviour. The absent case is deliberate and recorded in AU-55:
// a client that predates Fetch Metadata cannot be told apart from a curl or an
// older browser's genuine logout, and refusing to revoke for it would make a
// user's logout silently leave the token valid — the fail-OPEN direction for
// the control that withdraws session authority. What the absent case still
// permits is the pre-existing forced logout of the user's OWN session on such
// clients: availability, not authority.
func portalLogoutIsCrossSite(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site")
}

// portalLogoutConfirmationPage is the response to a cross-site logout request.
// It is a CONSTANT — nothing request-derived is interpolated — so it has no
// injection surface, and it needs no script, so securityMiddleware's CSP
// (`default-src 'self'`, nonce-only scripts, `frame-ancestors 'none'`) and
// X-Frame-Options: DENY apply to it unchanged, exactly as they do to the
// server-rendered sign-in page beside it in ui_auth.go. The form posts to the
// same origin, so the browser sends a matching Origin and the POST passes
// securityMiddleware's same-origin check — while a forged cross-site POST is
// refused there with 403.
const portalLogoutConfirmationPage = `<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>Culvert — Sign Out</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:0 16px}
h1{font-size:1.4rem}button{display:block;width:100%;padding:12px 16px;margin:8px 0;border:0;border-radius:6px;
background:#2563eb;color:#fff;font-size:1rem;cursor:pointer}button:hover{background:#1d4ed8}
a{display:block;text-align:center;margin-top:12px}
</style></head><body><h1>Sign out of Culvert?</h1>
<p>Another site asked to sign you out. Nothing has changed yet.</p>
<form method="POST" action="/auth/logout"><button type="submit">Sign out</button></form>
<a href="/">Stay signed in</a>
</body></html>`

// writePortalLogoutConfirmation answers a cross-site logout without mutating
// anything: no revocation, no cookie clear (AU-55).
func writePortalLogoutConfirmation(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// The page depends on a request header, and it must never be served from a
	// cache in answer to the user's own same-origin logout.
	h.Set("Cache-Control", "no-store")
	h.Add("Vary", "Sec-Fetch-Site")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(portalLogoutConfirmationPage))
}

// admitPortalLogout charges a logout that carries a session cookie to the
// per-client limiter the /api/ mutations use (AU-54), and answers 429 when the
// client is over it. It reports whether the handler may proceed.
//
// The durable revocation is one entry plus one full rewrite of the
// revocations file plus a gossip payload, and `setSessionCookie` stamps a
// fresh jti per login, so an authenticated identity looping login→logout
// added an entry and a whole-file write per cycle on a public route outside
// every limiter. `/api/auth/logout` already pays this limiter through
// securityMiddleware; this gives the portal route the same admission, and the
// same budget, without touching the revocation data model.
//
// Over the limit NOTHING happens — the session is neither revoked nor
// cleared. Skipping the revocation while still clearing the cookie would tell
// the user they are signed out while the token stays valid for any copy of
// it, which is the fail-open answer. A request with no cookie has nothing to
// revoke and is not charged.
func admitPortalLogout(w http.ResponseWriter, r *http.Request) bool {
	if _, err := r.Cookie(sessionCookieName); err != nil {
		return true
	}
	if apiLimiter.Allow(realClientIP(r)) {
		return true
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(apiRateWindow.Seconds())))
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
	return false
}
