package main

// proxy_credential_parity_test.go — differential oracle: one credential is one
// principal on both proxy listeners (SWG-901 stage 3, owner Decision 2).
//
// For each supported password-verifying backend, the same credential is
// presented over HTTP proxy Basic (the real resolveRequestAuth) and over
// SOCKS5 RFC 1929 (the real socks5Negotiate over an in-memory conn). The
// resolved identity, groups and auth source must be identical, and the
// admin-console pair must be refused on BOTH — the admin account is not a
// proxy identity on any channel (owner Decision 2, 2026-11-23).

import (
	"net"
	"net/http"
	"slices"
	"testing"
	"time"
)

// socks5NegotiatedIdentity runs socks5Negotiate on one end of an in-memory
// connection while the client authenticates on the other, and returns the
// principal the server resolved (ok=false when it refused).
func socks5NegotiatedIdentity(t *testing.T, user, pass string) (ProxyIdentity, bool) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	type result struct {
		id ProxyIdentity
		ok bool
	}
	done := make(chan result, 1)
	go func() {
		id, ok := socks5Negotiate(server, "127.0.0.1")
		done <- result{id, ok}
	}()
	status := socks5HandshakeAuth(t, client, user, pass)
	res := <-done
	if (status == 0x00) != res.ok {
		t.Fatalf("SOCKS5 status 0x%02x disagrees with the server verdict ok=%v", status, res.ok)
	}
	return res.id, res.ok
}

func TestProxyCredentialParity_HTTPAndSOCKS5(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setup      func(t *testing.T)
		user, pass string
		wantID     string
		wantGroups []string
		wantSource string
	}{
		{
			name:       "registry_ldap",
			setup:      func(t *testing.T) { installCredentialRegistry(t, aliceStub(), false) },
			user:       "alice",
			pass:       "ldap-pass",
			wantID:     aliceDN,
			wantGroups: []string{engineeringDN},
			wantSource: "corp-ad",
		},
		{
			name:       "legacy_ldap",
			setup:      func(t *testing.T) { installCachedLegacyLDAP(t, "bob", "bob-dir-pass") },
			user:       "bob",
			pass:       "bob-dir-pass",
			wantID:     "bob",
			wantSource: "local",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noAdminInstall(t)
			tc.setup(t)

			_, httpOut, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://parity.example.test/", tc.user, tc.pass, false))
			if !proceed {
				t.Fatal("HTTP Basic refused the credential")
			}
			socksID, ok := socks5NegotiatedIdentity(t, tc.user, tc.pass)
			if !ok {
				t.Fatal("SOCKS5 refused the credential")
			}
			if httpOut.identity != tc.wantID || socksID.Identity != tc.wantID {
				t.Errorf("identity: HTTP %q, SOCKS5 %q, want %q", httpOut.identity, socksID.Identity, tc.wantID)
			}
			if httpOut.source != tc.wantSource || socksID.AuthSource != tc.wantSource {
				t.Errorf("auth source: HTTP %q, SOCKS5 %q, want %q", httpOut.source, socksID.AuthSource, tc.wantSource)
			}
			if !slices.Equal(httpOut.groups, tc.wantGroups) || !slices.Equal(socksID.Groups, tc.wantGroups) {
				t.Errorf("groups: HTTP %v, SOCKS5 %v, want %v", httpOut.groups, socksID.Groups, tc.wantGroups)
			}

			// The admin-console pair: refused on both listeners.
			assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
			if id, ok := socks5NegotiatedIdentity(t, noAdminUser, noAdminPass); ok {
				t.Errorf("SOCKS5 accepted the admin-console pair as %+v", id)
			}
		})
	}
}

// TestProxyCredentialParity_AdminOnlyRefusedOnBoth: with only the admin
// account, both listeners require a credential and refuse every one.
func TestProxyCredentialParity_AdminOnlyRefusedOnBoth(t *testing.T) {
	noAdminInstall(t)
	if !socks5AuthRequired() {
		t.Fatal("SOCKS5 must require USER/PASS on an admin-only node (no NO-AUTH fallback)")
	}
	assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
	if id, ok := socks5NegotiatedIdentity(t, noAdminUser, noAdminPass); ok {
		t.Errorf("SOCKS5 accepted the admin-console pair as %+v", id)
	}
}
