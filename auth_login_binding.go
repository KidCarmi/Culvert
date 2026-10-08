package main

// auth_login_binding.go — interactive SSO login state is bound to the browser
// that started the login (#1528, login-CSRF).
//
// Without this, the OIDC `state` and the SAML RelayState were attributed to a
// client key for eviction fairness only. Anyone who began a login with their
// own IdP account could make a victim's browser finish it, and the victim then
// held a session for the ATTACKER's identity — their traffic attributed to,
// and governed by, someone else's policy (classic login CSRF).
//
// The rule is now: no login state is minted without a binding, and none is
// redeemed without proving it.
//
//   - /auth/select (the only place login state is minted) sets
//     ps_login_bind, a random value, on the UI host, and every state minted
//     there records the value's SHA-256. A provider REFUSES to mint state
//     without a binding in the request context, so an unbound state cannot
//     exist. The proxy's captive redirects therefore go to /auth/select on the
//     UI host (proxy_portal.go) instead of minting IdP URLs on whatever host
//     the user was browsing, where no UI-host cookie can be set.
//   - The OIDC callback is a top-level GET navigation, which carries a
//     SameSite=Lax cookie, so it checks the binding directly.
//   - On HTTPS the cookie is __Host-ps_login_bind (Secure, Path=/, no Domain)
//     and only that name is read. A sibling subdomain or a plain-HTTP origin
//     cannot set a __Host- cookie, so an attacker cannot plant THEIR OWN
//     legitimately-issued binding value in the victim's browser — the one
//     attack a random value alone does not stop (cookie injection). A
//     plain-HTTP admin UI cannot get that protection; browser-sso.md says so.
//   - The SAML ACS receives a cross-site POST, which does NOT carry a Lax
//     cookie (and SameSite=None needs Secure, which a plain-HTTP admin UI
//     cannot offer). So the ACS validates the assertion, parks the identity
//     under a one-time token, and 303s to /auth/saml/complete — a top-level
//     GET that does carry the cookie — where the binding is checked before
//     any session is issued.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
)

const (
	loginBindCookieName       = "ps_login_bind"
	loginBindSecureCookieName = "__Host-" + loginBindCookieName
	loginBindValueLen         = 32 // random bytes; base64url → 43 characters
)

// loginBindName is the binding cookie's name for this request's scheme. The
// same scheme decides it at mint and at check, so one login uses one name.
func loginBindName(r *http.Request) string {
	if isSecureRequest(r) {
		return loginBindSecureCookieName
	}
	return loginBindCookieName
}

// errLoginNotBound is returned when a callback cannot prove it comes from the
// browser that started the login.
var errLoginNotBound = errors.New("login was not started by this browser")

type loginBindingKey struct{}

// loginBindingFrom returns the binding hash /auth/select placed in the
// request context; ok=false means this request may not mint login state.
func loginBindingFrom(ctx context.Context) ([32]byte, bool) {
	b, ok := ctx.Value(loginBindingKey{}).([32]byte)
	return b, ok
}

func withLoginBinding(r *http.Request, h [32]byte) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), loginBindingKey{}, h))
}

func loginBindValueOK(v string) bool {
	b, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(b) == loginBindValueLen
}

// ensureLoginBinding reuses this browser's binding cookie when it has a
// well-formed one (several tabs and providers share it), otherwise mints a new
// one, and returns the request carrying the binding hash for state minting.
// The cookie lives as long as the state it protects.
func ensureLoginBinding(w http.ResponseWriter, r *http.Request) (*http.Request, error) {
	name := loginBindName(r)
	v := ""
	for _, c := range r.CookiesNamed(name) {
		if loginBindValueOK(c.Value) {
			v = c.Value
			break
		}
	}
	if v == "" {
		raw := make([]byte, loginBindValueLen)
		if _, err := rand.Read(raw); err != nil {
			return r, err
		}
		v = base64.RawURLEncoding.EncodeToString(raw)
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- dynamic Secure flag
		Name:  name,
		Value: v,
		// Path=/ (required by __Host-) also keeps the cookie working when
		// proxy.base_url carries a path prefix behind a reverse proxy.
		Path:     "/",
		MaxAge:   int(samlStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
	return withLoginBinding(r, sha256.Sum256([]byte(v))), nil
}

// loginBindingMatches reports whether r carries the binding cookie whose hash
// a login state recorded. A zero recorded hash never matches (fail closed).
// Every copy of the cookie is tried, so a junk copy planted at a longer path
// cannot block a legitimate login.
func loginBindingMatches(want [32]byte, r *http.Request) bool {
	if want == ([32]byte{}) {
		return false
	}
	match := 0
	for _, c := range r.CookiesNamed(loginBindName(r)) {
		if !loginBindValueOK(c.Value) {
			continue
		}
		got := sha256.Sum256([]byte(c.Value))
		match |= subtle.ConstantTimeCompare(got[:], want[:])
	}
	return match == 1
}
