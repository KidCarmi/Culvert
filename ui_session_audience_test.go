package main

import (
	"encoding/json"
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

// ── /api/auth/status: the public endpoint the middleware never sees ─────────
//
// Codex P2 on this PR, and correct: /api/auth/status is on
// isPublicUIAuthPath, so uiAuthMiddleware never runs for it and the handler
// resolved the cookie itself. Its comment claimed it applied "the same
// fail-closed resolution uiAuthMiddleware applies" while checking strictly
// less, so the first version of this fix refused the replayed proxy token on
// every gated route and still reported it here as `loggedIn: true,
// role: admin` — the console renders the whole admin surface for a principal
// that then gets 401 on every call it makes. The same drift already
// mis-reported a DELETED user as an admin, because the roster check lived
// only in the middleware.
//
// Both call sites now share resolveUISession. These gates pin the status
// endpoint's half of that contract.

// statusFor drives apiAuthStatus with sess under the admin cookie name and
// returns the decoded body.
func statusFor(t *testing.T, sess *Session) map[string]any {
	t.Helper()
	value, err := encodeSession(sess)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	apiAuthStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apiAuthStatus status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

// TestSECUISESS1_StatusRefusesProxyIssuedToken is the DEFECT GATE for the
// status endpoint. Pre-fix it answered loggedIn=true, role=admin.
func TestSECUISESS1_StatusRefusesProxyIssuedToken(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	// Premise: this endpoint really is public, so the middleware really is not
	// standing in front of it. If that changes, this gate's reasoning changes.
	if !isPublicUIAuthPath("/api/auth/status") {
		t.Fatal("premise broken: /api/auth/status is no longer on the public allowlist")
	}

	value := proxyIssuedSessionValue(t, &Identity{
		Sub:      "browsing-user@corp.example",
		Email:    "browsing-user@corp.example",
		Provider: "oidc-corp",
	})
	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	apiAuthStatus(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if body["loggedIn"] != false {
		t.Errorf("loggedIn = %v, want false — the status endpoint reports a proxy-issued token as an "+
			"authenticated principal while every gated route refuses it", body["loggedIn"])
	}
	if got, ok := body["role"]; ok {
		t.Errorf("role = %v was reported for a refused session; want no role at all", got)
	}
	if got, ok := body["user"]; ok {
		t.Errorf("user = %v was reported for a refused session; want no user at all", got)
	}
}

// TestSECUISESS1_StatusRefusesDeletedUser pins the half of the drift that
// predates this PR: the roster check (Finding 5.2) lived only in the
// middleware, so a deleted admin's own cookie still reported role=admin here.
func TestSECUISESS1_StatusRefusesDeletedUser(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	body := statusFor(t, &Session{
		Sub: "deleted-admin", Provider: "local", Role: string(RoleAdmin),
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if body["loggedIn"] != false {
		t.Errorf("loggedIn = %v for a user absent from the roster, want false", body["loggedIn"])
	}
}

// TestSECUISESS1_StatusReportsLocalSessions is the CONTROL: a real admin login
// still reports its exact role, and the pre-RBAC empty-role session still
// reports admin. Refusing either would pass the gates above while breaking the
// console for legitimate operators.
func TestSECUISESS1_StatusReportsLocalSessions(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	for _, tc := range []struct {
		name string
		role string
		want UIRole
	}{
		{"pre-RBAC empty role", "", RoleAdmin},
		{"viewer", string(RoleViewer), RoleViewer},
		{"operator", string(RoleOperator), RoleOperator},
		{"admin", string(RoleAdmin), RoleAdmin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := statusFor(t, &Session{
				Sub: "bob", Provider: "local", Role: tc.role,
				Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
			})
			if body["loggedIn"] != true {
				t.Fatalf("loggedIn = %v, want true for a local roster session", body["loggedIn"])
			}
			if body["user"] != "bob" {
				t.Errorf("user = %v, want %q", body["user"], "bob")
			}
			if body["role"] != string(tc.want) {
				t.Errorf("role = %v, want %q", body["role"], tc.want)
			}
		})
	}
}

// TestSECUISESS1_StatusRefusedCookieDoesNotFallBackToBasic is the second
// Codex P2, and a distinct case from the one above: MIXED auth.
//
// uiAuthMiddleware answers 401 on uiSessionRefused and returns — it never
// reaches its own Basic fallback. The first version of this fix only
// short-circuited the VALID verdict here, so a refused cookie fell through to
// Basic, and a request carrying both a refused ps_ui_session and valid Basic
// credentials was reported `loggedIn: true` while every gated route refused it
// with 401. Same contract break as the cookie-only case, one branch over.
//
// Reachable without an attacker: an operator whose account was deleted, or
// whose browser still holds a proxy-issued cookie, driving the API with Basic
// credentials. No escalation — Basic still has to verify — but the endpoint
// promises access the middleware will not grant, which is the direction that
// matters.
func TestSECUISESS1_StatusRefusedCookieDoesNotFallBackToBasic(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	// Premise: these Basic credentials really do verify, so a loggedIn=false
	// below is the refused COOKIE talking and not a bad password.
	probe := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	probe.SetBasicAuth("bob", "Sup3rSecret!x")
	if _, valid := verifyUIBasicAuth(probe, "bob", "Sup3rSecret!x"); !valid {
		t.Fatal("premise broken: the Basic credentials used by this gate no longer verify")
	}

	for _, tc := range []struct {
		name string
		sess *Session
	}{
		{"proxy-issued provider", &Session{
			Sub: "browsing-user@corp.example", Provider: "oidc-corp", Role: "",
			Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
		}},
		{"deleted local user", &Session{
			Sub: "deleted-admin", Provider: "local", Role: string(RoleAdmin),
			Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := encodeSession(tc.sess)
			if err != nil {
				t.Fatalf("encodeSession: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
			req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
			req.SetBasicAuth("bob", "Sup3rSecret!x")
			rec := httptest.NewRecorder()
			apiAuthStatus(rec, req)

			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body %q: %v", rec.Body.String(), err)
			}
			if body["loggedIn"] != false {
				t.Errorf("loggedIn = %v with a REFUSED cookie plus valid Basic credentials, want false — "+
					"uiAuthMiddleware answers 401 for this request and never tries Basic, so reporting it "+
					"as logged in promises access no gated route will grant", body["loggedIn"])
			}
		})
	}
}

// TestSECUISESS1_StatusBasicFallbackSurvives is the CONTROL that keeps the fix
// from over-refusing: with NO cookie at all, the Basic fallback is the
// documented CLI/API path and must still report the credential's real role.
// uiSessionAbsent is the verdict that leaves Basic its turn, in the middleware
// and here alike.
func TestSECUISESS1_StatusBasicFallbackSurvives(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)

	req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
	req.SetBasicAuth("bob", "Sup3rSecret!x")
	rec := httptest.NewRecorder()
	apiAuthStatus(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if body["loggedIn"] != true {
		t.Fatalf("loggedIn = %v for Basic credentials with no cookie, want true — the CLI/API path "+
			"must survive the refused-cookie fix", body["loggedIn"])
	}
	if body["user"] != "bob" || body["role"] != string(RoleViewer) {
		t.Errorf("Basic fallback reported user=%v role=%v, want bob/%s", body["user"], body["role"], RoleViewer)
	}
}

// TestSECUISESS1_StatusPreSetupStillBootstraps is the CONTROL for the
// bootstrap window: before setup completes the endpoint reports admin with no
// cookie at all, and sharing resolveUISession must not have disturbed that
// branch — it runs before any cookie is read.
func TestSECUISESS1_StatusPreSetupStillBootstraps(t *testing.T) {
	withSessionKey(t)
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if cfg.IsConfigured() {
		t.Fatal("precondition: cfg must be unconfigured")
	}

	rec := httptest.NewRecorder()
	apiAuthStatus(rec, httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if body["loggedIn"] != true || body["role"] != string(RoleAdmin) {
		t.Fatalf("pre-setup status = %v, want loggedIn=true role=admin (the setup wizard reads this)", body)
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

// TestSECUISESS1_SSERevalidationSharesTheAdmissionDecision pins that the
// mid-stream SSE re-check (sseAuthStillValid) applies the same decision as the
// connect-time gate rather than restating it. Before this it carried its own
// copy of the PRE-FIX predicate (`Provider == "local" && !UIUserExists`), so a
// foreign-provider token for a roster member, or a local session naming a role
// this build does not enroll, kept the stream alive.
func TestSECUISESS1_SSERevalidationSharesTheAdmissionDecision(t *testing.T) {
	withSessionKey(t)
	configuredCfg(t)
	if !cfg.AuthEnabled() {
		t.Fatal("precondition: auth must be enabled, or the re-check short-circuits to true")
	}
	exp := time.Now().Add(time.Hour).Unix()
	for _, tc := range []struct {
		name string
		sess *Session
		want bool
	}{
		{"foreign provider, roster member", &Session{Sub: "bob", Provider: "oidc-corp", Exp: exp}, false},
		{"foreign provider, admin role", &Session{Sub: "bob", Provider: "saml-okta", Role: string(RoleAdmin), Exp: exp}, false},
		{"local, role not enrolled", &Session{Sub: "bob", Provider: uiSessionProvider, Role: "superuser", Exp: exp}, false},
		{"local, deleted user", &Session{Sub: "gone", Provider: uiSessionProvider, Role: string(RoleViewer), Exp: exp}, false},
		// CONTROLS: the sessions the gate admits keep their stream.
		{"local, enrolled role", &Session{Sub: "bob", Provider: uiSessionProvider, Role: string(RoleViewer), Exp: exp}, true},
		{"local, pre-RBAC empty role", &Session{Sub: "bob", Provider: uiSessionProvider, Exp: exp}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.sess.Jti = newSessionJti()
			value, err := encodeSession(tc.sess)
			if err != nil {
				t.Fatalf("encodeSession: %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "/api/events", http.NoBody)
			req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
			if got := sseAuthStillValid(req); got != tc.want {
				t.Errorf("sseAuthStillValid = %v, want %v", got, tc.want)
			}
		})
	}
}
