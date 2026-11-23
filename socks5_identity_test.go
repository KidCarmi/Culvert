package main

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ─────────────────────────────────────────────────────────────────────────────
// SWG-901 stage 3 — SOCKS5 identity through the SHARED credential resolver,
// password-only channel (owner direction 2026-11-23).
//
// What these tests pin, and why each is here:
//   - provider classes: a password-verifying provider (registry LDAP)
//     authenticates; an interactive/token provider (registry OIDC) is refused
//     with reason provider_not_supported_for_socks5, although HTTP Basic accepts
//     the same credential;
//   - NO administrative fallback: the admin-console credential never
//     authenticates SOCKS5 — alone, beside a directory, beside OIDC, beside a
//     non-directory legacy provider — and an admin who is also a directory user
//     authenticates only with the DIRECTORY password;
//   - a registry-only LDAP deployment requires USER/PASS on SOCKS5;
//   - identity-, group- and auth-source-scoped rules match SOCKS5 clients in
//     shadow and in enforce, and the request log carries identity/auth source;
//   - a wrong password fails exactly as on HTTP (status, statAuthFail, an
//     unattributed AUTH_FAIL entry), with the refusal reason recorded;
//   - NO-AUTH is "unauth".
// The differential oracle over the same backends is in socks5_parity_test.go.
// ─────────────────────────────────────────────────────────────────────────────

const (
	engineeringDN = "CN=Engineering,OU=Groups,DC=corp,DC=example"
	aliceDN       = "CN=Alice,OU=Users,DC=corp,DC=example"
)

// oidcTokenStub stands in for a compiled OIDC provider: like the real one it
// ignores the username and accepts a bearer token (introspection).
type oidcTokenStub struct {
	token    string
	identity *Identity
}

func (p *oidcTokenStub) Verify(u, tok string) bool {
	_, ok := p.ResolveIdentity(u, tok)
	return ok
}

func (p *oidcTokenStub) ResolveIdentity(_, tok string) (*Identity, bool) {
	if tok != p.token {
		return nil, false
	}
	return cloneIdentity(p.identity), true
}
func (p *oidcTokenStub) Name() string                                 { return "oidc:corp-oidc" }
func (p *oidcTokenStub) DisplayName() string                          { return "Stub OIDC" }
func (p *oidcTokenStub) CaptiveLoginURL(string, *http.Request) string { return "" }

// installCredentialRegistry installs a registry with the given LDAP stub (nil:
// none) and, when withOIDC, an enabled OIDC profile routing corp.example.
func installCredentialRegistry(t *testing.T, ldap *ldapStubProvider, withOIDC bool) {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	reg := &IdPRegistry{live: map[string]IdentityProvider{}}
	if ldap != nil {
		reg.profiles = append(reg.profiles, ldapTestProfile(ldap.profileID, "Corporate AD"))
		reg.live[ldap.profileID] = ldap
	}
	if withOIDC {
		reg.profiles = append(reg.profiles, &IdPProfile{ID: "corp-oidc", Name: "Corp OIDC", Type: IdPTypeOIDC, Enabled: true, EmailDomains: []string{"corp.example"}})
		reg.live["corp-oidc"] = &oidcTokenStub{token: "tok-1", identity: &Identity{Sub: "carol@corp.example", Provider: "corp-oidc"}}
	}
	idpRegistry = reg
}

// setupMixedCredentialBackends installs a local admin, a registry LDAP
// provider and a registry OIDC provider.
func setupMixedCredentialBackends(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	captureLoggerForTest(t)
	t.Cleanup(reqlog.SwapRingForTest())
	if err := cfg.SetAuth("admin", "admin-pass"); err != nil {
		t.Fatal(err)
	}
	installCredentialRegistry(t, aliceStub(), true)
}

// httpBasicProceeds runs the real HTTP Stage-1 pipeline with Basic credentials
// and reports whether it proceeded, and the status it wrote otherwise.
func httpBasicProceeds(t *testing.T, user, pass string) (proceed bool, code int) {
	t.Helper()
	r := makeRequest("http://basic.example.test/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	w := httptest.NewRecorder()
	_, proceed = resolveRequestAuth(w, r, "127.0.0.1", "swg901-class")
	return proceed, w.Code
}

// socks5AuthOutcome is one USER/PASS attempt over a real listener: the RFC
// 1929 status and the refusal reason counted for it ("" when accepted). The
// reason is read from the counter, which is charged before the failure reply
// is written, so it is settled once the client has read the status.
func socks5AuthOutcome(t *testing.T, addr, user, pass string) (status byte, reason string) {
	t.Helper()
	invalid0, unsupported0 := socks5AuthFailures[0].Load(), socks5AuthFailures[1].Load()
	status = socks5UserPassStatus(t, addr, user, pass)
	switch {
	case socks5AuthFailures[1].Load() > unsupported0:
		reason = socks5AuthReasonUnsupported
	case socks5AuthFailures[0].Load() > invalid0:
		reason = socks5AuthReasonInvalid
	}
	return status, reason
}

// TestSOCKS5Auth_ProviderClasses: the supported class (directory bind)
// authenticates; the interactive/token class (OIDC) is refused with
// provider_not_supported_for_socks5 even though HTTP Basic accepts the same
// credential; a wrong directory password is invalid_credentials.
func TestSOCKS5Auth_ProviderClasses(t *testing.T) {
	setupMixedCredentialBackends(t)
	if proceed, _ := httpBasicProceeds(t, "carol@corp.example", "tok-1"); !proceed {
		t.Fatal("precondition: HTTP Basic accepts the OIDC token")
	}
	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	unsupported0 := socks5AuthFailures[1].Load()
	for _, tc := range []struct {
		name, user, pass string
		wantOK           bool
		wantReason       string
	}{
		{"ldap_supported", "alice", "ldap-pass", true, ""},
		{"oidc_refused", "carol@corp.example", "tok-1", false, socks5AuthReasonUnsupported},
		{"ldap_wrong_password", "alice", "wrong", false, socks5AuthReasonInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := socks5AuthOutcome(t, addr, tc.user, tc.pass)
			if (status == 0x00) != tc.wantOK || reason != tc.wantReason {
				t.Errorf("status=0x%02x reason=%q, want ok=%v reason=%q", status, reason, tc.wantOK, tc.wantReason)
			}
		})
	}
	if socks5AuthFailures[1].Load() == unsupported0 {
		t.Error("the provider_not_supported_for_socks5 refusal was not counted")
	}
}

// acceptAnyProvider is a legacy (non-directory) provider that accepts every
// credential: if SOCKS5 consulted it, or fell back to the admin pair behind
// it, the admin row below would authenticate.
type acceptAnyProvider struct{}

func (acceptAnyProvider) Verify(string, string) bool { return true }
func (acceptAnyProvider) Name() string               { return "accept-any" }

// TestSOCKS5Auth_AdminCredentialNeverAuthenticates: no configuration makes the
// admin-console credential a SOCKS5 credential, and none falls back to it.
func TestSOCKS5Auth_AdminCredentialNeverAuthenticates(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setup      func(t *testing.T)
		wantReason string
	}{
		{"admin_only", func(*testing.T) {}, socks5AuthReasonUnsupported},
		{"admin_beside_directory", func(t *testing.T) { installCredentialRegistry(t, aliceStub(), false) }, socks5AuthReasonInvalid},
		{"admin_beside_oidc_only", func(t *testing.T) { installCredentialRegistry(t, nil, true) }, socks5AuthReasonUnsupported},
		{"admin_beside_non_directory_legacy_provider", func(t *testing.T) {
			cfg.SetProvider(acceptAnyProvider{})
			t.Cleanup(func() { cfg.SetProvider(nil) })
		}, socks5AuthReasonUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupProxyTest(t)
			captureLoggerForTest(t)
			if err := cfg.SetAuth("admin", "admin-pass"); err != nil {
				t.Fatal(err)
			}
			tc.setup(t)
			ln := startSOCKS5Listener(t)
			status, reason := socks5AuthOutcome(t, ln.Addr().String(), "admin", "admin-pass")
			if status == 0x00 {
				t.Fatal("the admin-console credential authenticated SOCKS5")
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// TestSOCKS5Auth_AdminWhoIsADirectoryUser: an admin who is ALSO a directory
// user authenticates SOCKS5 as the directory principal with the directory
// password; the admin-console password for the same username is refused.
func TestSOCKS5Auth_AdminWhoIsADirectoryUser(t *testing.T) {
	setupProxyTest(t)
	captureLoggerForTest(t)
	if err := cfg.SetAuth("alice", "console-pass"); err != nil {
		t.Fatal(err)
	}
	installCredentialRegistry(t, aliceStub(), false)
	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	if st, _ := socks5AuthOutcome(t, addr, "alice", "ldap-pass"); st != 0x00 {
		t.Errorf("the directory password must authenticate, got 0x%02x", st)
	}
	if st, reason := socks5AuthOutcome(t, addr, "alice", "console-pass"); st == 0x00 || reason != socks5AuthReasonInvalid {
		t.Errorf("the admin-console password must be refused as invalid_credentials, got 0x%02x %q", st, reason)
	}
}

// TestSOCKS5Identity_RegistryOnlyLDAPRequiresUserPass: with no local account
// and an enabled registry LDAP profile, SOCKS5 must not offer NO-AUTH (HTTP
// challenges in the same deployment), and the directory user authenticates.
func TestSOCKS5Identity_RegistryOnlyLDAPRequiresUserPass(t *testing.T) {
	setupProxyTest(t)
	captureLoggerForTest(t)
	installLDAPRegistry(t, "corp-ad", aliceStub())
	if cfg.AuthEnabled() {
		t.Fatal("precondition: no local account, so the old predicate offered NO-AUTH")
	}
	ln := startSOCKS5Listener(t)
	addr := ln.Addr().String()
	if m := socks5SelectedMethod(t, addr, 0x00); m != 0xFF {
		t.Errorf("registry-only LDAP: SOCKS5 must refuse NO-AUTH (0xFF), got 0x%02x", m)
	}
	if st := socks5UserPassStatus(t, addr, "alice", "ldap-pass"); st != 0x00 {
		t.Errorf("the directory user must authenticate SOCKS5, got status 0x%02x", st)
	}
	if st := socks5UserPassStatus(t, addr, "alice", "wrong"); st == 0x00 {
		t.Error("a wrong directory password authenticated SOCKS5")
	}
}

// socks5AuthedTry authenticates with USER/PASS, then CONNECTs.
func socks5AuthedTry(t *testing.T, addr, user, pass, host string, port uint16) socks5Attempt {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if st := socks5HandshakeAuth(t, conn, user, pass); st != 0x00 {
		t.Fatalf("USER/PASS for %q failed: 0x%02x", user, st)
	}
	return socks5SendRequest(t, conn, socks5ATYPDomain, host, port)
}

// identityRuleCases are identity/group/auth-source-scoped rulebases and whether
// they admit the directory user alice, run in enforce and shadow.
var identityRuleCases = []struct {
	name      string
	rule      PolicyRule
	wantAllow bool
}{
	{"identity_rule_matches", PolicyRule{Priority: 1, Name: "id-dn", SourceIdentity: aliceDN, DestFQDN: "localhost", Action: ActionAllow}, true},
	{"other_identity_default_deny", PolicyRule{Priority: 1, Name: "id-other", SourceIdentity: "someone-else", DestFQDN: "localhost", Action: ActionAllow}, false},
	{"group_rule_matches", PolicyRule{Priority: 1, Name: "id-eng", SourceGroup: engineeringDN, DestFQDN: "localhost", Action: ActionAllow}, true},
	{"auth_source_rule_matches", PolicyRule{Priority: 1, Name: "id-src", AuthSource: "corp-ad", DestFQDN: "localhost", Action: ActionAllow}, true},
	{"other_group_default_deny", PolicyRule{Priority: 1, Name: "id-fin", SourceGroup: "CN=Finance,OU=Groups,DC=corp,DC=example", DestFQDN: "localhost", Action: ActionAllow}, false},
}

// TestSOCKS5Identity_RulesMatchInEnforce: identity, group and auth-source rules
// decide authenticated SOCKS5 connections (default deny behind them), and the
// request log carries the resolved identity and auth source.
func TestSOCKS5Identity_RulesMatchInEnforce(t *testing.T) {
	for _, tc := range identityRuleCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnforceEnv(t, socks5PolicyEnforce, []PolicyRule{tc.rule}, "deny")
			installLDAPRegistry(t, "corp-ad", aliceStub())
			got := socks5AuthedTry(t, env.addr, "alice", "ldap-pass", "localhost", env.port)
			status := "POLICY_DEFAULT_DENY"
			if tc.wantAllow {
				assertEnforceReply(t, got, 0x00)
				assertTunnelEchoes(t, got.conn)
				status = "OK"
			} else {
				assertEnforceReply(t, got, 0x02)
			}
			e := socks5Entry(t, "localhost", status)
			if e.Identity != aliceDN || e.AuthSource != "corp-ad" {
				t.Errorf("entry identity/auth_source = %q/%q, want %q/corp-ad", e.Identity, e.AuthSource, aliceDN)
			}
		})
	}
}

// TestSOCKS5Identity_RulesMatchInShadow: the same rulebases in shadow record
// allow/rule for a matching principal and would_block/default otherwise —
// and still serve the connection.
func TestSOCKS5Identity_RulesMatchInShadow(t *testing.T) {
	for _, tc := range identityRuleCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnforceEnv(t, socks5PolicyShadow, []PolicyRule{tc.rule}, "deny")
			installLDAPRegistry(t, "corp-ad", aliceStub())
			before := readShadowCounters()
			got := socks5AuthedTry(t, env.addr, "alice", "ldap-pass", "localhost", env.port)
			assertEnforceReply(t, got, 0x00)
			assertTunnelEchoes(t, got.conn)
			d := readShadowCounters().minus(before)
			if tc.wantAllow && d.decisions[0][0] != 1 {
				t.Errorf("shadow must record allow/rule for the matching principal: %+v", d)
			}
			if !tc.wantAllow && d.decisions[1][1] != 1 {
				t.Errorf("shadow must record would_block/default for a non-matching principal: %+v", d)
			}
		})
	}
}

// TestSOCKS5Identity_WrongPasswordFailsLikeHTTP: the same bad directory
// credential, over HTTP Basic and over SOCKS5, is refused, bumps statAuthFail
// once and writes one AUTH_FAIL entry with no identity.
func TestSOCKS5Identity_WrongPasswordFailsLikeHTTP(t *testing.T) {
	setupMixedCredentialBackends(t)
	fails0 := atomic.LoadInt64(&statAuthFail)
	if proceed, code := httpBasicProceeds(t, "alice", "wrong"); proceed || code != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP: proceed=%v code=%d, want 407", proceed, code)
	}
	httpFails := atomic.LoadInt64(&statAuthFail) - fails0
	ln := startSOCKS5Listener(t)
	status, reason := socks5AuthOutcome(t, ln.Addr().String(), "alice", "wrong")
	socksFails := atomic.LoadInt64(&statAuthFail) - fails0 - httpFails
	if status != 0x01 || reason != socks5AuthReasonInvalid {
		t.Fatalf("SOCKS5: status=0x%02x reason=%q, want 0x01 invalid_credentials", status, reason)
	}
	if httpFails != 1 || socksFails != 1 {
		t.Errorf("statAuthFail: HTTP +%d, SOCKS5 +%d, want +1 each", httpFails, socksFails)
	}
	assertAuthFailEntry(t, "SOCKS5", socks5AuthReasonInvalid)
	assertAuthFailEntry(t, http.MethodGet, "")
}

func assertAuthFailEntry(t *testing.T, method, wantAction string) {
	t.Helper()
	entries := logGet()
	for i := range entries {
		if entries[i].Method == method && entries[i].Status == "AUTH_FAIL" {
			if entries[i].ActionTaken != wantAction {
				t.Errorf("%s AUTH_FAIL actionTaken = %q, want %q", method, entries[i].ActionTaken, wantAction)
			}
			if entries[i].Identity != "" || entries[i].AuthSource != "" {
				t.Errorf("%s AUTH_FAIL entry carries identity/auth_source %q/%q; a failed credential is unattributed", method, entries[i].Identity, entries[i].AuthSource)
			}
			return
		}
	}
	t.Errorf("no %s AUTH_FAIL entry", method)
}

// TestSOCKS5Identity_NoAuthIsUnauth: on a gateway with no credential backend a
// NO-AUTH client is "unauth" — an unauth-scoped rule decides it, and the entry
// says so.
func TestSOCKS5Identity_NoAuthIsUnauth(t *testing.T) {
	env := newEnforceEnv(t, socks5PolicyEnforce,
		[]PolicyRule{{Priority: 1, Name: "id-unauth-block", AuthSource: "unauth", DestFQDN: "*", Action: ActionBlockPage}}, "allow")
	got := socks5Try(t, env.addr, socks5ATYPDomain, "localhost", env.port)
	assertEnforceReply(t, got, 0x02)
	e := socks5Entry(t, "localhost", "POLICY_BLOCK")
	if e.RuleMatched != "id-unauth-block" || e.AuthSource != socks5UnauthSource || e.Identity != "" {
		t.Errorf("entry = rule %q identity %q auth_source %q, want id-unauth-block/\"\"/unauth", e.RuleMatched, e.Identity, e.AuthSource)
	}
}
