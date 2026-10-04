package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestUISessionRole_DemotionTakesEffectWithoutLogin(t *testing.T) {
	setupTokenTestConfig(t)
	initSessionSecret()
	if err := cfg.SetAuth("owner", "Str0ngPassw0rd!"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.SetUIUser("demoted", "Str0ngPassw0rd!", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	if err := setUISessionCookie(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody), "demoted", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	cookie := w.Result().Cookies()[0]
	r := httptest.NewRequest(http.MethodPost, "/api/auth/users", strings.NewReader(`{"username":"demoted","role":"viewer"}`))
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	w = httptest.NewRecorder()
	apiAuthUsers(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("demote: %d %s", w.Code, w.Body.String())
	}
	if role, ok := cfg.VerifyUIUser("demoted", "Str0ngPassw0rd!"); !ok || role != RoleViewer {
		t.Fatalf("roster role=%s valid=%v", role, ok)
	}
	r = httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	uiAuthMiddleware(http.HandlerFunc(apiAuthUsers)).ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("demoted session still admitted: %d", w.Code)
	}
}

func TestUISessionRole_NeverExceedsCookieOrRoster(t *testing.T) {
	setupTokenTestConfig(t)
	initSessionSecret()
	for _, tc := range []struct {
		name, signed, provider string
		current, want          UIRole
		missing, denied        bool
	}{
		{name: "unchanged-admin", signed: "admin", provider: "local", current: RoleAdmin, want: RoleAdmin},
		{name: "admin-to-operator", signed: "admin", provider: "local", current: RoleOperator, want: RoleOperator},
		{name: "operator-to-viewer", signed: "operator", provider: "local", current: RoleViewer, want: RoleViewer},
		{name: "promotion-needs-login", signed: "viewer", provider: "local", current: RoleAdmin, want: RoleViewer},
		{name: "legacy-cookie-demoted", signed: "", provider: "local", current: RoleViewer, denied: true},
		{name: "legacy-cookie-admin", signed: "", provider: "local", current: RoleAdmin, denied: true},
		{name: "unknown-cookie-role", signed: "future-role", provider: "local", current: RoleAdmin, denied: true},
		{name: "deleted-user", signed: "admin", provider: "local", missing: true, denied: true},
		{name: "unsupported-provider", signed: "operator", provider: "oidc", missing: true, denied: true},
		{name: "empty-provider", signed: "admin", current: RoleAdmin, denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.missing {
				if err := cfg.SetUIUser(tc.name, "Str0ngPassw0rd!", tc.current); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := encodeSession(&Session{Sub: tc.name, Provider: tc.provider, Role: tc.signed, Audience: uiSessionAudience, Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
			r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: raw}) //nolint:gosec // G124: a REQUEST cookie; Secure/HttpOnly/SameSite are response attributes
			sess, err := readUISessionCookie(r)
			if tc.denied {
				if err == nil || sess != nil {
					t.Fatal("invalid local authority must be rejected")
				}
				return
			}
			if err != nil || sess == nil || sess.Role != string(tc.want) {
				t.Fatalf("effective session = %+v, error = %v; want role %s", sess, err, tc.want)
			}
		})
	}
}

func TestUISessionRole_RejectsReplayedPortalCookie(t *testing.T) {
	setupTokenTestConfig(t)
	initSessionSecret()
	if err := cfg.SetAuth("owner", "Str0ngPassw0rd!"); err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"oidc", "saml", "local", ""} {
		t.Run(provider, func(t *testing.T) {
			w := httptest.NewRecorder()
			// The genuine proxy-portal issuer deliberately carries no admin role.
			// Even a matching local username must not supply that missing authority.
			if err := setSessionCookie(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody), &Identity{Sub: "owner", Provider: provider}); err != nil {
				t.Fatal(err)
			}
			cookie := w.Result().Cookies()[0]
			cookie.Name = uiSessionCookieName
			r := httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
			r.AddCookie(cookie) //nolint:gosec // G124: a REQUEST cookie replayed from the response; attributes do not apply
			w = httptest.NewRecorder()
			uiAuthMiddleware(http.HandlerFunc(apiAuthUsers)).ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("portal token accepted as admin UI session: HTTP %d", w.Code)
			}
		})
	}
}

func TestUISessionRole_RequiresSignedAudience(t *testing.T) {
	setupTokenTestConfig(t)
	initSessionSecret()
	if err := cfg.SetAuth("owner", "Str0ngPassw0rd!"); err != nil {
		t.Fatal(err)
	}
	for _, audience := range []string{"", "proxy", uiSessionAudience} {
		raw, err := encodeSession(&Session{Sub: "owner", Provider: "local", Role: "admin", Audience: audience, Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()})
		if err != nil {
			t.Fatal(err)
		}
		// The shared decoder remains purpose-neutral for its other consumers.
		if _, err := decodeSession(raw); err != nil {
			t.Fatalf("shared decoder rejected signed purpose %q: %v", audience, err)
		}
		r := httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
		r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: raw}) //nolint:gosec // G124: a REQUEST cookie; Secure/HttpOnly/SameSite are response attributes
		_, err = readUISessionCookie(r)
		if (err == nil) != (audience == uiSessionAudience) {
			t.Fatalf("UI audience %q: error %v", audience, err)
		}
		if audience != "" {
			continue
		}
		parts := strings.Split(raw, ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatal(err)
		}
		claims["aud"] = uiSessionAudience
		payload, err = json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		forged := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
		r = httptest.NewRequest(http.MethodGet, "/api/auth/users", http.NoBody)
		r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: forged})
		if _, err := readUISessionCookie(r); err == nil {
			t.Fatal("adding the UI audience without re-signing must fail")
		}
	}
}

func TestUISessionRole_ProxyReaderRejectsOtherPurpose(t *testing.T) {
	initSessionSecret()
	issued := httptest.NewRecorder()
	if err := setUISessionCookie(issued, httptest.NewRequest(http.MethodGet, "/", http.NoBody), "viewer", RoleViewer); err != nil {
		t.Fatal(err)
	}
	cookie := issued.Result().Cookies()[0]
	cookie.Name = sessionCookieName
	r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	r.AddCookie(cookie)
	if sess, err := readSessionCookie(r); err == nil || sess != nil {
		t.Fatal("renamed administrator UI cookie must not authenticate a proxy identity")
	}
	for _, tc := range []struct {
		name, audience string
		legacy         bool
	}{
		{name: "current-proxy"},
		{name: "legacy-proxy", legacy: true},
		{name: "unknown-purpose", audience: "other-service", legacy: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cookie *http.Cookie
			if tc.legacy {
				raw, err := encodeSession(&Session{Sub: "portal-user", Provider: "oidc", Audience: tc.audience, Exp: time.Now().Add(time.Hour).Unix()})
				if err != nil {
					t.Fatal(err)
				}
				cookie = &http.Cookie{Name: sessionCookieName, Value: raw}
			} else {
				w := httptest.NewRecorder()
				if err := setSessionCookie(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody), &Identity{Sub: "portal-user", Provider: "oidc"}); err != nil {
					t.Fatal(err)
				}
				cookie = w.Result().Cookies()[0]
			}
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			r.AddCookie(cookie)
			sess, err := readSessionCookie(r)
			if tc.audience != "" {
				if err == nil || sess != nil {
					t.Fatal("unknown signed purpose must be refused")
				}
				return
			}
			if err != nil || sess == nil || sess.Sub != "portal-user" {
				t.Fatalf("genuine proxy session rejected: %v", err)
			}
		})
	}
}
