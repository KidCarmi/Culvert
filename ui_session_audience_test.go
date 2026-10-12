package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── SEC-UISESS-1: the admin cookie is a token CLASS, not just a cookie name ──
//
// ps_session (proxy end-user, session.go setSessionCookie) and ps_ui_session
// (admin operator, ui_session.go setUISessionCookie) are signed with the SAME
// HMAC key, carry the SAME Session struct, and have NO audience/purpose
// discriminator between them. The cookie NAME was the only separation, and a
// name is attacker-chosen: whoever holds a ps_session value can present it as
// ps_ui_session.
//
// That mattered because the two fields that would have caught it both declined:
//
//   - sessionRoleOrReject("") resolves to RoleAdmin (ui_session.go). A proxy
//     session never sets Role, so every ps_session carries exactly the empty
//     string the pre-RBAC compatibility branch promotes to admin.
//   - the roster-existence backstop was gated on sess.Provider == "local"
//     (uiAuthMiddleware), and a proxy IdP session carries the IdP profile id,
//     so the check was skipped rather than failed.
//
// Net effect: an ORDINARY proxy end user who completed a normal captive-portal
// OIDC/SAML login — their own corporate credentials, no forgery, no XSS, no
// MITM, no knowledge of the signing key — could replay the cookie the appliance
// itself minted under the admin cookie name and be injected as RoleAdmin, which
// is above every requireRole gate and every C2 metadata role. The CP ships one
// signing key to every DP (controlplane_snapshot.go), so the token was admin on
// every node in the cluster.
//
// This contradicted an explicit written contract —
// docs/enterprise/IDENTITY-AND-ACCESS-DEPLOYMENT.md: "External IdPs
// (LDAP/OIDC/SAML) authenticate PROXY end-users, never admin operators …
// they never issue an admin session", with no admin SSO (GAP-IAM-02).
//
// The fix is the token-class check these gates are named for: the admin plane
// is the only minter of ps_ui_session and it has always stamped
// Provider "local" (ui_session.go, both call sites passing a roster-backed
// username), so a UI session whose provider is anything else was not issued as
// an admin session and is refused. The roster-existence check then applies
// unconditionally rather than only to local sessions.
//
// The DEFECT GATE below fails against the pre-fix middleware (200, role
// "admin"). The CONTROLS pin that the narrow fix did not take away the
// pre-RBAC compatibility case it had to preserve.

// driveUISessionMiddleware runs one /api request carrying sess under the ADMIN
// cookie name and reports the status, the role the middleware injected, and
// whether the inner handler was reached at all.
func driveUISessionMiddleware(t *testing.T, sess *Session) (int, UIRole, bool) {
	t.Helper()
	value, err := encodeSession(sess)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	var seen UIRole
	reached := false
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached, seen = true, uiRole(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen, reached
}

// proxyIssuedSessionValue mints a token through the REAL proxy-user issuer
// (setSessionCookie), so this gate tests the bytes the appliance actually hands
// an end user at the end of a captive-portal IdP login — not a hand-built
// struct that merely resembles one. It returns the cookie VALUE, which is all
// an attacker needs to re-present under another cookie name.
func proxyIssuedSessionValue(t *testing.T, id *Identity) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	if err := setSessionCookie(rec, req, id); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	t.Fatalf("setSessionCookie wrote no %s cookie", sessionCookieName)
	return ""
}

// TestSECUISESS1_ProxyIssuedTokenIsNotAnAdminSession is the DEFECT GATE.
//
// Pre-fix: 200 with injected role "admin" — privilege escalation from an
// ordinary proxy end user to control-plane admin.
func TestSECUISESS1_ProxyIssuedTokenIsNotAnAdminSession(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	// An ordinary proxy end user: a real IdP subject, deliberately NOT a member
	// of the admin roster seeded by configuredCfg (root, bob).
	value := proxyIssuedSessionValue(t, &Identity{
		Sub:      "browsing-user@corp.example",
		Email:    "browsing-user@corp.example",
		Provider: "oidc-corp",
		Groups:   []string{"everyone"},
	})
	if cfg.UIUserExists("browsing-user@corp.example") {
		t.Fatal("precondition: the proxy user must not be in the admin roster")
	}

	// Premise: the token the proxy issuer minted really does verify and really
	// does carry an empty Role. If either stops holding, this gate is testing
	// something other than the escalation it was written for.
	sess, err := decodeSession(value)
	if err != nil || sess == nil {
		t.Fatalf("premise: proxy-issued token does not decode: %v", err)
	}
	if sess.Role != "" {
		t.Fatalf("premise: proxy-issued session carries Role %q, expected empty", sess.Role)
	}

	var seen UIRole
	reached := false
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached, seen = true, uiRole(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if reached {
		t.Errorf("a proxy-issued ps_session replayed as %s reached the admin handler with injected role %q — "+
			"an ordinary proxy end user is a control-plane admin", uiSessionCookieName, seen)
	}
	if seen == RoleAdmin {
		t.Errorf("proxy-issued token was injected as %q", RoleAdmin)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a session the admin plane never issued", rec.Code)
	}
}

// TestSECUISESS1_ForeignProviderUISessionRefused covers the class rather than
// the one issuer: ANY verified session naming a provider the admin plane does
// not mint is refused, at every role value — including an explicitly elevated
// one, which a compromised or restored proxy-side roster could carry.
func TestSECUISESS1_ForeignProviderUISessionRefused(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	for _, provider := range []string{"oidc-corp", "saml-okta", "ldap-main", "", "LOCAL", "local "} {
		for _, role := range []string{"", string(RoleViewer), string(RoleOperator), string(RoleAdmin)} {
			name := provider + "/" + role
			t.Run(name, func(t *testing.T) {
				// Sub is a roster member, so the ONLY thing refusing this
				// session can be its provider — the roster backstop cannot be
				// what fires here.
				code, got, reached := driveUISessionMiddleware(t, &Session{
					Sub: "bob", Provider: provider, Role: role,
					Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
				})
				if reached {
					t.Errorf("session with provider %q role %q reached the handler as %q", provider, role, got)
				}
				if code != http.StatusUnauthorized {
					t.Errorf("status = %d, want 401 for provider %q role %q", code, provider, role)
				}
			})
		}
	}
}

// TestSECUISESS1_LocalEmptyRoleCompatSurvives is the CONTROL that keeps the fix
// narrow. The pre-RBAC compatibility case — a session minted before the Role
// field existed, by the admin plane, for a roster member — must still resolve
// to admin. Refusing it would pass the defect gate above while locking legacy
// single-admin deployments out mid-session, which is the exact trade
// sessionRoleOrReject's comment refuses to make.
func TestSECUISESS1_LocalEmptyRoleCompatSurvives(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	code, role, reached := driveUISessionMiddleware(t, &Session{
		Sub: "bob", Provider: "local", Role: "",
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if !reached || code != http.StatusOK {
		t.Fatalf("legacy local role-less session refused: status=%d reached=%v", code, reached)
	}
	if role != RoleAdmin {
		t.Fatalf("legacy local role-less session resolved to %q, want %q", role, RoleAdmin)
	}
}

// TestSECUISESS1_LocalEnrolledRolesPassThrough is the CONTROL for the ordinary
// path: a real admin login is untouched, at its exact role.
func TestSECUISESS1_LocalEnrolledRolesPassThrough(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	for _, want := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
		t.Run(string(want), func(t *testing.T) {
			code, got, reached := driveUISessionMiddleware(t, &Session{
				Sub: "bob", Provider: "local", Role: string(want),
				Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
			})
			if !reached || code != http.StatusOK {
				t.Fatalf("local %q session refused: status=%d reached=%v", want, code, reached)
			}
			if got != want {
				t.Fatalf("injected role = %q, want %q", got, want)
			}
		})
	}
}

// TestSECUISESS1_LocalSessionForDeletedUserRefused is the CONTROL for the
// roster backstop (Finding 5.2), which the fix moves out from behind the
// provider guard. A local session whose user no longer exists must still be
// refused — the fix must not have traded one bypass for another.
func TestSECUISESS1_LocalSessionForDeletedUserRefused(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	code, got, reached := driveUISessionMiddleware(t, &Session{
		Sub: "deleted-admin", Provider: "local", Role: string(RoleAdmin),
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if reached {
		t.Errorf("session for a user absent from the roster reached the handler as %q", got)
	}
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a deleted user's session", code)
	}
}
