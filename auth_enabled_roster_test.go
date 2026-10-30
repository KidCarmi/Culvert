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
