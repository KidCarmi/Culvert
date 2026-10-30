package main

// auth_enabled_roster_test.go — SEC-AUTHENABLED-1.
//
// AuthEnabled() carried the same `c.user`-only shape SEC-SETUPANCHOR-1 removed
// from IsConfigured(). loadUIUsersFile sets c.user ONLY from a record whose
// EFFECTIVE role is admin, so a roster that holds accounts but no present
// admin — the only admin clamped to RoleViewer by loadedRosterRole (a restore
// from a newer build), or a legacy pre-RBAC roster with an empty role —
// answered false, and two enforcement sites read that as "authentication is
// off" on a gateway that plainly has accounts:
//
//   - socks5Negotiate selected the SOCKS5 NO-AUTH method (0x05 0x00);
//   - sseAuthStillValid returned true unconditionally, so a stream with no
//     valid credential kept receiving live telemetry.
//
// The gates below drive the real SOCKS5 listener and the real SSE re-check,
// because the predicate only matters through the door it opens. Each defect
// gate also proves that USERPASS cannot be satisfied by an arbitrary
// credential: with no admin and no provider there is no proxy credential to
// verify against, and verifyAuthFrom's "no backend, auth disabled" sentinel
// would otherwise have accepted anything once the method was required. The
// negative controls pin the fresh-gateway and normal-admin states, which must
// behave exactly as before.

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// socks5UserPassStatus runs the full USERPASS handshake against addr and
// returns the RFC 1929 status byte (0x00 success, anything else failure).
func socks5UserPassStatus(t *testing.T, addr, user, pass string) byte {
	t.Helper()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return socks5HandshakeAuth(t, conn, user, pass)
}

// sseStreamWithCookie builds an /api/events request carrying value under the
// admin session cookie name ("" for no cookie at all).
func sseStreamWithCookie(t *testing.T, value string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/events", http.NoBody)
	if value != "" {
		req.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	}
	return req
}

// rosterSessionCookie mints a valid admin-plane session for the roster's own
// account, so the SSE gates can show the fix keeps a LEGITIMATE stream alive.
func rosterSessionCookie(t *testing.T, role UIRole) string {
	t.Helper()
	value, err := encodeSession(&Session{
		Sub: "alice", Provider: uiSessionProvider, Role: string(role),
		Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	return value
}

// assertProxyAuthRequired is the shared defect gate for a roster with accounts
// and no present admin. sessionRole is the role a session for the roster's
// account carries in that state.
func assertProxyAuthRequired(t *testing.T, sessionRole UIRole) {
	t.Helper()
	if !cfg.AuthEnabled() {
		t.Error("a roster holding an admitted account is an active authentication backend; AuthEnabled must be true")
	}

	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	if m := socks5SelectedMethod(t, addr, 0x00); m != 0xFF {
		t.Errorf("SEC-AUTHENABLED-1: SOCKS5 must refuse the no-auth offer (0xFF) on a gateway with accounts, got 0x%02x", m)
	}
	if m := socks5SelectedMethod(t, addr, 0x02); m != 0x02 {
		t.Errorf("SOCKS5 must select USERPASS (0x02), got 0x%02x", m)
	} else {
		// Requiring USERPASS is only a control if a credential is then
		// verified. No admin and no provider means nothing can verify one, so
		// every credential — arbitrary, empty, or the roster account's own UI
		// password — is refused rather than waved through by the
		// empty-backend sentinel.
		for _, cred := range []struct{ user, pass string }{
			{"attacker", "anything"},
			{"", ""},
			{"alice", "Sup3rSecret!x"},
		} {
			if st := socks5UserPassStatus(t, addr, cred.user, cred.pass); st == 0x00 {
				t.Errorf("SEC-AUTHENABLED-1: SOCKS5 USERPASS accepted %q with no proxy credential backend", cred.user)
			}
		}
	}

	withSessionKey(t)
	if sseAuthStillValid(sseStreamWithCookie(t, "")) {
		t.Error("SEC-AUTHENABLED-1: an SSE stream with no credential must be terminated on a gateway with accounts")
	}
	if sseAuthStillValid(sseStreamWithCookie(t, "not-a-signed-session")) {
		t.Error("SEC-AUTHENABLED-1: an SSE stream with a tampered session must be terminated")
	}
	// CONTROL: the account's own valid session keeps its stream.
	if !sseAuthStillValid(sseStreamWithCookie(t, rosterSessionCookie(t, sessionRole))) {
		t.Error("a valid session for the roster's own account must keep its SSE stream")
	}
}

// TestAuthEnabled_ClampedAdminRosterRequiresProxyAuth is the security gate for
// the least-privilege clamp route.
func TestAuthEnabled_ClampedAdminRosterRequiresProxyAuth(t *testing.T) {
	setupProxyTest(t)
	if roleEnrolled(UIRole("superadmin")) {
		t.Skip("this build enrolls 'superadmin'; the clamp cannot be provoked with it")
	}
	c := loadRoster(t, rosterWithRole(t, UIRole("superadmin")))
	if got := c.uiUsers["alice"].role; got != RoleViewer {
		t.Fatalf("premise broken: want the clamp to leave RoleViewer, got %q", got)
	}
	if c.user != "" || c.provider != nil {
		t.Fatalf("premise broken: want no admin term and no provider, got user=%q provider=%v", c.user, c.provider)
	}
	assertProxyAuthRequired(t, RoleViewer)
}

// TestAuthEnabled_LegacyEmptyRoleRosterRequiresProxyAuth is the same gate by
// the pre-RBAC route: an empty role is never RoleAdmin, so c.user stays empty.
func TestAuthEnabled_LegacyEmptyRoleRosterRequiresProxyAuth(t *testing.T) {
	setupProxyTest(t)
	c := loadRoster(t, rosterWithRole(t, ""))
	if c.user != "" || c.provider != nil {
		t.Fatalf("premise broken: want no admin term and no provider, got user=%q provider=%v", c.user, c.provider)
	}
	if len(c.uiUsers) != 1 {
		t.Fatalf("premise broken: want the record admitted to the roster, got %d", len(c.uiUsers))
	}
	assertProxyAuthRequired(t, "")
}

// TestAuthEnabled_FreshGatewayUnchanged is the first negative control: a
// gateway with no accounts at all keeps today's behaviour exactly — SOCKS5
// negotiates no-auth, the empty-backend sentinel still verifies, and the SSE
// re-check does not demand a credential nobody could hold.
func TestAuthEnabled_FreshGatewayUnchanged(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"no roster file", ""},
		{"empty envelope", `{"users":[]}`},
		{"empty legacy array", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			withRosterOnDisk(t, tc.body)
			if err := cfg.LoadUIUsersFile(); err != nil {
				t.Fatalf("load roster: %v", err)
			}
			if cfg.AuthEnabled() {
				t.Fatal("a gateway with no accounts must keep AuthEnabled false")
			}
			ln := startSOCKS5Listener(t)
			if m := socks5SelectedMethod(t, ln.Addr().String(), 0x00); m != 0x00 {
				t.Errorf("fresh gateway: SOCKS5 must still negotiate no-auth (0x00), got 0x%02x", m)
			}
			if !cfg.VerifyAuthFrom("198.51.100.7", "any", "thing") {
				t.Error("fresh gateway: the empty-backend sentinel must still report auth disabled")
			}
			if !sseAuthStillValid(sseStreamWithCookie(t, "")) {
				t.Error("fresh gateway: the SSE re-check must not demand a credential")
			}
		})
	}
}

// TestAuthEnabled_AdminRosterUnchanged is the second negative control: a
// normal roster with a present admin already required proxy authentication
// and still verifies the admin credential exactly as before.
func TestAuthEnabled_AdminRosterUnchanged(t *testing.T) {
	setupProxyTest(t)
	c := loadRoster(t, adminRoster(t, RoleAdmin))
	if c.user != "alice" {
		t.Fatalf("premise broken: want the admin term set from the roster, got %q", c.user)
	}
	if !cfg.AuthEnabled() {
		t.Fatal("an admin roster must keep AuthEnabled true")
	}
	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	if m := socks5SelectedMethod(t, addr, 0x00); m != 0xFF {
		t.Errorf("admin roster: SOCKS5 must refuse the no-auth offer (0xFF), got 0x%02x", m)
	}
	if st := socks5UserPassStatus(t, addr, "alice", "Sup3rSecret!x"); st != 0x00 {
		t.Errorf("admin roster: the admin's own credential must authenticate SOCKS5, got status 0x%02x", st)
	}
	if st := socks5UserPassStatus(t, addr, "alice", "wrong-password"); st == 0x00 {
		t.Error("admin roster: a wrong password must be refused")
	}

	withSessionKey(t)
	if sseAuthStillValid(sseStreamWithCookie(t, "")) {
		t.Error("admin roster: an SSE stream with no credential must be terminated")
	}
	if !sseAuthStillValid(sseStreamWithCookie(t, rosterSessionCookie(t, RoleAdmin))) {
		t.Error("admin roster: the admin's valid session must keep its SSE stream")
	}
}

// ── HTTP proxy (Stage-1 resolveRequestAuth) ──────────────────────────────────
//
// The HTTP proxy's gate is not AuthEnabled: resolveRequestAuth derives
// authRequired from hasCredentialCapableProvider (GetUser / provider / a
// credential-capable IdP) and, inside it, falls through the no-backend inert
// guard when neither a credential nor an SSO backend exists. A roster with
// accounts but no admin pair answered "no backend" to both, so under the
// Default outcome every request — with no credential, or with ANY presented
// credential, since arm 2 never runs without credCapable — left Stage-1
// unauthenticated and was decided by Stage-2 policy alone: an allow rule
// admitted it with no identity. These gates call resolveRequestAuth directly
// because "proceeded unauthenticated" is the Stage-1 contract; the 403 a test
// would see through handleRequest is only the default-deny backstop.

// httpProxyRequest is a proxied request with an optional Basic credential and
// an optional browser User-Agent (which selects the captive-portal branch).
func httpProxyRequest(t *testing.T, method, target, user, pass string, browser bool) *http.Request {
	t.Helper()
	r := makeRequest(target, nil)
	r.Method = method
	if user != "" || pass != "" {
		r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}
	if browser {
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0")
	}
	return r
}

// resolveHTTPProxyAuth runs Stage-1 on r and returns the recorder, the
// outcome and whether the request may proceed to Stage-2.
func resolveHTTPProxyAuth(t *testing.T, r *http.Request) (*httptest.ResponseRecorder, authOutcome, bool) {
	t.Helper()
	w := httptest.NewRecorder()
	out, proceed := resolveRequestAuth(w, r, "127.0.0.1", "sec-authenabled-1")
	return w, out, proceed
}

// assertHTTPProxyRefusesEverything is the HTTP half of the defect gate: with
// accounts but no admin pair and no provider, nothing can verify a credential,
// so every request is refused with the existing 407 challenge.
func assertHTTPProxyRefusesEverything(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		name           string
		method, target string
		user, pass     string
		browser        bool
	}{
		{"no credential", http.MethodGet, "http://sec-authenabled.example.test/", "", "", false},
		{"arbitrary credential", http.MethodGet, "http://sec-authenabled.example.test/", "attacker", "anything", false},
		{"roster account's own UI password", http.MethodGet, "http://sec-authenabled.example.test/", "alice", "Sup3rSecret!x", false},
		{"browser, no credential", http.MethodGet, "http://sec-authenabled.example.test/", "", "", true},
		{"CONNECT, no credential", http.MethodConnect, "http://sec-authenabled.example.test:443", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, tc.method, tc.target, tc.user, tc.pass, tc.browser))
			if proceed {
				t.Fatalf("SEC-AUTHENABLED-1: HTTP proxy request proceeded unauthenticated (source=%q identity=%q) on a gateway with accounts",
					out.source, out.identity)
			}
			if w.Code != http.StatusProxyAuthRequired {
				t.Errorf("want the existing 407 challenge, got %d", w.Code)
			}
			if got := w.Header().Get("Proxy-Authenticate"); got != `Basic realm="Culvert"` {
				t.Errorf("want the existing Basic challenge, got Proxy-Authenticate=%q", got)
			}
		})
	}
}

// TestAuthEnabled_ClampedAdminRosterHTTPProxyRefused is the HTTP gate for the
// least-privilege clamp route.
func TestAuthEnabled_ClampedAdminRosterHTTPProxyRefused(t *testing.T) {
	setupProxyTest(t)
	withFreshPolicyStore(t)
	if roleEnrolled(UIRole("superadmin")) {
		t.Skip("this build enrolls 'superadmin'; the clamp cannot be provoked with it")
	}
	c := loadRoster(t, rosterWithRole(t, UIRole("superadmin")))
	if c.user != "" || c.provider != nil || hasCredentialCapableProvider() {
		t.Fatal("premise broken: want no admin pair, no provider and no credential-capable IdP")
	}
	assertHTTPProxyRefusesEverything(t)
}

// TestAuthEnabled_LegacyEmptyRoleRosterHTTPProxyRefused is the same gate by
// the pre-RBAC route.
func TestAuthEnabled_LegacyEmptyRoleRosterHTTPProxyRefused(t *testing.T) {
	setupProxyTest(t)
	withFreshPolicyStore(t)
	c := loadRoster(t, rosterWithRole(t, ""))
	if c.user != "" || c.provider != nil || len(c.uiUsers) != 1 {
		t.Fatalf("premise broken: want one admitted account, no admin pair, no provider (user=%q accounts=%d)",
			c.user, len(c.uiUsers))
	}
	assertHTTPProxyRefusesEverything(t)
}

// TestAuthEnabled_HTTPProxyFreshGatewayUnchanged: with no accounts at all the
// no-backend inert guard still applies — Stage-1 proceeds unauthenticated and
// Stage-2's default-deny decides, exactly as before.
func TestAuthEnabled_HTTPProxyFreshGatewayUnchanged(t *testing.T) {
	setupProxyTest(t)
	withFreshPolicyStore(t)
	withRosterOnDisk(t, "")
	if err := cfg.LoadUIUsersFile(); err != nil {
		t.Fatalf("load roster: %v", err)
	}
	for _, browser := range []bool{false, true} {
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://fresh.example.test/", "", "", browser))
		if !proceed {
			t.Fatalf("fresh gateway (browser=%v): Stage-1 must stay inert, got status %d", browser, w.Code)
		}
		if out.source != "unauth" || out.identity != "" {
			t.Errorf("fresh gateway: want source=unauth and no identity, got source=%q identity=%q", out.source, out.identity)
		}
	}
}

// TestAuthEnabled_HTTPProxyAdminRosterUnchanged: a present admin pair still
// authenticates over Basic, and a request without a credential is challenged.
func TestAuthEnabled_HTTPProxyAdminRosterUnchanged(t *testing.T) {
	setupProxyTest(t)
	withFreshPolicyStore(t)
	loadRoster(t, adminRoster(t, RoleAdmin))

	_, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://admin.example.test/", "alice", "Sup3rSecret!x", false))
	if !proceed || out.identity != "alice" || out.source != "local" {
		t.Fatalf("admin roster: valid Basic must authenticate as alice/local, got proceed=%v identity=%q source=%q",
			proceed, out.identity, out.source)
	}
	w, _, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://admin.example.test/", "alice", "wrong", false))
	if proceed || w.Code != http.StatusProxyAuthRequired {
		t.Errorf("admin roster: a wrong password must 407, got proceed=%v status=%d", proceed, w.Code)
	}
	w, _, proceed = resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://admin.example.test/", "", "", false))
	if proceed || w.Code != http.StatusProxyAuthRequired {
		t.Errorf("admin roster: no credential must 407, got proceed=%v status=%d", proceed, w.Code)
	}
}

// TestAuthEnabled_HTTPProxyExemptStillExempt: the fix applies to the Default
// outcome only. On the SAME defect-state roster, an operator-chosen open
// default (Exempt) still admits a request with no credential, and a scoped
// Exempt rule still fires as a scoped exemption.
func TestAuthEnabled_HTTPProxyExemptStillExempt(t *testing.T) {
	t.Run("default Exempt", func(t *testing.T) {
		setupProxyTest(t)
		withFreshPolicyStore(t)
		loadRoster(t, rosterWithRole(t, ""))
		cfg.SetDefaultAuthOutcome(OutcomeExempt)
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://open.example.test/", "", "", false))
		if !proceed {
			t.Fatalf("default Exempt: a no-credential request must still be admitted, got status %d", w.Code)
		}
		if out.source != "unauth" {
			t.Errorf("default Exempt: want source=unauth, got %q", out.source)
		}
	})
	t.Run("scoped Exempt rule", func(t *testing.T) {
		setupProxyTest(t)
		withFreshPolicyStore(t)
		loadRoster(t, rosterWithRole(t, ""))
		setAuthExemptDisabled(false)
		t.Cleanup(func() { setAuthExemptDisabled(false) })
		const host = "scoped-exempt.example.test"
		policyStore.Add(slice7ExemptRule(host))
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://"+host+"/", "", "", false))
		// The invariant is "still admitted, no identity". The attribution
		// differs: before the fix this state skipped the whole Stage-1 gate
		// (source "unauth", the rule never evaluated); with the gate armed the
		// rule now fires and is recorded as a scoped exemption ("exempt").
		if !proceed {
			t.Fatalf("scoped Exempt: a no-credential request must still be exempted, got status %d", w.Code)
		}
		if out.identity != "" {
			t.Errorf("scoped Exempt: an exemption must never create an identity, got %q", out.identity)
		}
		t.Logf("scoped Exempt: source=%q", out.source)
	})
}

// TestAuthEnabled_HTTPProxyArmedGateEdges pins the two deliberate consequences
// of arming the gate in the defect state, both of which already hold on any
// gateway that has a backend: a presented credential is never exempted, and
// the Exempt kill switch is strictly MORE restrictive.
func TestAuthEnabled_HTTPProxyArmedGateEdges(t *testing.T) {
	t.Run("Exempt default, presented credential", func(t *testing.T) {
		setupProxyTest(t)
		withFreshPolicyStore(t)
		loadRoster(t, rosterWithRole(t, ""))
		cfg.SetDefaultAuthOutcome(OutcomeExempt)
		w, _, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://open.example.test/", "attacker", "anything", false))
		if proceed || w.Code != http.StatusProxyAuthRequired {
			t.Errorf("a presented credential nothing can verify must 407, never be exempted: proceed=%v status=%d", proceed, w.Code)
		}
	})
	t.Run("Exempt default, kill switch engaged", func(t *testing.T) {
		setupProxyTest(t)
		withFreshPolicyStore(t)
		loadRoster(t, rosterWithRole(t, ""))
		cfg.SetDefaultAuthOutcome(OutcomeExempt)
		setAuthExemptDisabled(true)
		t.Cleanup(func() { setAuthExemptDisabled(false) })
		w, _, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://open.example.test/", "", "", false))
		if proceed || w.Code != http.StatusProxyAuthRequired {
			t.Errorf("the kill switch forces Default, which must challenge on a gateway with accounts: proceed=%v status=%d", proceed, w.Code)
		}
	})
}
