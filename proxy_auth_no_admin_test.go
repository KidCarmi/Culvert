package main

// proxy_auth_no_admin_test.go — owner Decision 2 (2026-11-23): management
// identities and data-plane identities are distinct.
//
// The admin-console account (the legacy admin pair and every roster account)
// authenticates the ADMIN plane only. HTTP proxy Basic resolves a presented
// credential through the shared resolver (proxy_credential.go), the same one
// SOCKS5 USER/PASS uses, and that resolver never consults the admin account —
// not when no proxy provider is configured, and not after a configured one
// rejects the credential.
//
// What these gates pin, and why each is here:
//   - admin-only installation: every presented credential, the admin pair
//     included, is refused with the existing 407 (fail closed, never
//     unauthenticated), and so is a request with no credential; admin UI
//     login with the same pair still succeeds;
//   - provider beside the admin account (registry LDAP, registry OIDC, legacy
//     LDAP, legacy OIDC): the provider's principals authenticate unchanged,
//     the admin pair is refused, and an admin who is also a directory user
//     authenticates only with the directory password;
//   - provider configured then removed or disabled: fail closed — no fallback
//     to the admin account and no fallback to unauthenticated access;
//   - explicitly configured unauthenticated access (the Exempt global default,
//     a scoped Exempt rule) is unchanged for credential-free requests, and the
//     no-account no-provider node keeps its inert Stage-2 semantics;
//   - the resolver itself refuses the admin pair on both channels in every
//     configuration (the construction legacyCredentialFor relies on).
// HTTP <-> SOCKS5 attribution parity is in proxy_credential_parity_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

const (
	noAdminUser = "admin"
	noAdminPass = "Adm1n-Console-pass"
)

// noAdminInstall resets the proxy state, installs an empty IdP registry and
// the admin-console account, and captures the request log and the logger.
func noAdminInstall(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	withFreshPolicyStore(t)
	captureLoggerForTest(t)
	t.Cleanup(reqlog.SwapRingForTest())
	orig := idpRegistry
	idpRegistry = &IdPRegistry{live: map[string]IdentityProvider{}}
	t.Cleanup(func() { idpRegistry = orig })
	if err := cfg.SetAuth(noAdminUser, noAdminPass); err != nil {
		t.Fatal(err)
	}
}

// assertHTTPBasicRefused drives the real HTTP Stage-1 with a Basic credential
// and requires the existing 407 challenge.
func assertHTTPBasicRefused(t *testing.T, user, pass string) {
	t.Helper()
	w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://no-admin.example.test/", user, pass, false))
	if proceed {
		t.Fatalf("HTTP Basic %q proceeded (identity=%q source=%q): the admin account is not a proxy identity", user, out.identity, out.source)
	}
	if w.Code != http.StatusProxyAuthRequired || w.Header().Get("Proxy-Authenticate") != `Basic realm="Culvert"` {
		t.Errorf("HTTP Basic %q: want the existing 407 Basic challenge, got %d %q", user, w.Code, w.Header().Get("Proxy-Authenticate"))
	}
}

// assertHTTPBasicAuthenticates requires the credential to authenticate as
// (identity, source).
func assertHTTPBasicAuthenticates(t *testing.T, user, pass, identity, source string) {
	t.Helper()
	w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://no-admin.example.test/", user, pass, false))
	if !proceed {
		t.Fatalf("HTTP Basic %q refused (status %d), want it to authenticate", user, w.Code)
	}
	if out.identity != identity || out.source != source {
		t.Errorf("HTTP Basic %q: identity/source = %q/%q, want %q/%q", user, out.identity, out.source, identity, source)
	}
}

// TestProxyAuthNoAdmin_AdminOnlyRefusesEveryCredential is the admin-only
// installation: the wizard's admin and no proxy provider. Before Decision 2
// the admin pair authenticated HTTP proxy traffic as identity "admin" /
// source "local"; now nothing on the node can verify a proxy credential, so
// every request that requires authentication is refused — never waved through.
func TestProxyAuthNoAdmin_AdminOnlyRefusesEveryCredential(t *testing.T) {
	noAdminInstall(t)
	if hasCredentialCapableProvider() {
		t.Fatal("the admin account must not count as a credential-capable proxy validator")
	}
	if !cfg.AuthEnabled() {
		t.Fatal("premise: the admin account keeps AuthEnabled true (admin plane, SOCKS5 method selection)")
	}

	fails0 := atomic.LoadInt64(&statAuthFail)
	for _, cred := range [][2]string{
		{noAdminUser, noAdminPass}, // the admin pair itself
		{noAdminUser, "wrong"},
		{"someone", "anything"},
	} {
		assertHTTPBasicRefused(t, cred[0], cred[1])
	}
	if got := atomic.LoadInt64(&statAuthFail) - fails0; got != 3 {
		t.Errorf("statAuthFail += %d, want 3 (one per refused credential)", got)
	}
	// No credential, non-browser and browser: the gate is armed (not the
	// no-backend inert path), and with no SSO provider the browser gets the
	// same 407 — nothing falls through to Stage 2 unauthenticated.
	for _, browser := range []bool{false, true} {
		w, _, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://no-admin.example.test/", "", "", browser))
		if proceed || w.Code != http.StatusProxyAuthRequired {
			t.Errorf("no credential (browser=%v): want 407, got proceed=%v status=%d", browser, proceed, w.Code)
		}
	}
	// Through the full request path too: the client sees the 407.
	w := httptest.NewRecorder()
	handleRequest(w, httpProxyRequest(t, http.MethodGet, "http://no-admin-e2e.example.test/", noAdminUser, noAdminPass, false))
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("handleRequest with the admin pair: status %d, want 407", w.Code)
	}

	// The admin plane is untouched: the same pair is still the administrator.
	if role, ok := cfg.VerifyUIUser(noAdminUser, noAdminPass); !ok || role != RoleAdmin {
		t.Errorf("admin UI credential check: role=%q ok=%v, want admin/true", role, ok)
	}
	snapshotLoginLimiter(t)
	withSessionKey(t)
	lw := httptest.NewRecorder()
	apiAuthLogin(lw, jsonReq(http.MethodPost, "/api/auth/login", map[string]any{"user": noAdminUser, "pass": noAdminPass}))
	if lw.Code != http.StatusOK {
		t.Fatalf("admin UI login: status %d, want 200 (body %s)", lw.Code, lw.Body.String())
	}
	var sawUISession bool
	for _, c := range lw.Result().Cookies() {
		if c.Name == uiSessionCookieName && c.Value != "" {
			sawUISession = true
		}
		if c.Name == sessionCookieName {
			t.Errorf("admin UI login set the PROXY session cookie %q", c.Name)
		}
	}
	if !sawUISession {
		t.Error("admin UI login did not issue the admin session cookie")
	}
}

// TestProxyAuthNoAdmin_ProvidersBesideAdminAccount: each supported external
// provider keeps authenticating its own principals exactly as before; only
// the admin pair changes, from "authenticated as local admin" to refused.
func TestProxyAuthNoAdmin_ProvidersBesideAdminAccount(t *testing.T) {
	t.Run("registry_ldap", func(t *testing.T) {
		noAdminInstall(t)
		installCredentialRegistry(t, aliceStub(), false)
		assertHTTPBasicAuthenticates(t, "alice", "ldap-pass", aliceDN, "corp-ad")
		assertHTTPBasicRefused(t, "alice", "wrong")
		assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
	})
	t.Run("registry_oidc", func(t *testing.T) {
		noAdminInstall(t)
		installCredentialRegistry(t, nil, true)
		assertHTTPBasicAuthenticates(t, "carol@corp.example", "tok-1", "carol@corp.example", "corp-oidc")
		assertHTTPBasicRefused(t, "carol@corp.example", "stale-token")
		assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
	})
	t.Run("legacy_ldap", func(t *testing.T) {
		noAdminInstall(t)
		installCachedLegacyLDAP(t, "bob", "bob-dir-pass")
		// The legacy LDAP bind provider supplies no identity of its own, so
		// the historical "local" auth-source label stays (proxy_credential.go).
		assertHTTPBasicAuthenticates(t, "bob", "bob-dir-pass", "bob", "local")
		assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
	})
	t.Run("legacy_oidc", func(t *testing.T) {
		noAdminInstall(t)
		cfg.SetProvider(tokenCheckingLegacyOIDC(t, "valid-token", introspectionResponse{Active: true, Sub: "dave-sub", Username: "dave"}))
		assertHTTPBasicAuthenticates(t, "dave", "valid-token", "dave-sub", "oidc")
		assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
	})
	t.Run("admin_who_is_a_directory_user", func(t *testing.T) {
		noAdminInstall(t)
		if err := cfg.SetAuth("alice", "console-pass"); err != nil {
			t.Fatal(err)
		}
		installCredentialRegistry(t, aliceStub(), false)
		assertHTTPBasicAuthenticates(t, "alice", "ldap-pass", aliceDN, "corp-ad")
		// Before Decision 2 the directory rejected this and the chain fell
		// back to the admin pair, authenticating "alice"/"local".
		assertHTTPBasicRefused(t, "alice", "console-pass")
	})
}

// tokenCheckingLegacyOIDC is a legacy OIDC provider whose introspection
// endpoint reports only token active (mockIDP reports every token active, so
// it would "authenticate" the admin password as a token — the OIDC verdict,
// not a fallback, but useless as an oracle here).
func tokenCheckingLegacyOIDC(t *testing.T, token string, active introspectionResponse) *OIDCAuth {
	t.Helper()
	allowLoopbackSSRF(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := introspectionResponse{}
		if r.ParseForm() == nil && r.PostForm.Get("token") == token {
			resp = active
		}
		json.NewEncoder(w).Encode(resp) //nolint:errcheck // test response writer
	}))
	t.Cleanup(srv.Close)
	a, err := NewOIDCAuth(OIDCConfig{IntrospectionURL: srv.URL, ClientID: "client", ClientSecret: "secret"})
	if err != nil {
		t.Fatalf("NewOIDCAuth: %v", err)
	}
	return a
}

// installCachedLegacyLDAP wires a legacy (YAML) LDAP provider whose cache
// already holds an authenticated verdict for (user, pass), so the test never
// dials a directory. Any other credential would dial the unreachable test URL
// and be refused by the provider.
func installCachedLegacyLDAP(t *testing.T, user, pass string) {
	t.Helper()
	a, err := NewLDAPAuth(LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=corp,dc=example"})
	if err != nil {
		t.Fatal(err)
	}
	a.cacheSet(cacheKey(user, pass), "", true, nil)
	cfg.SetProvider(a)
}

// TestProxyAuthNoAdmin_MissingProviderFailsClosed: a proxy provider that was
// configured and is then disabled, deleted or unwired leaves a node with the
// admin account and nothing that can verify a proxy credential. Every
// credential — the directory user's, the admin pair — and every request
// without one is refused; there is no fallback to the admin account and none
// to unauthenticated access.
func TestProxyAuthNoAdmin_MissingProviderFailsClosed(t *testing.T) {
	assertRefusesAll := func(t *testing.T, user, pass string) {
		t.Helper()
		assertHTTPBasicRefused(t, user, pass)
		assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
		w, _, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://no-admin.example.test/", "", "", false))
		if proceed || w.Code != http.StatusProxyAuthRequired {
			t.Errorf("no credential after the provider went away: want 407, got proceed=%v status=%d", proceed, w.Code)
		}
	}
	t.Run("registry_profile_disabled", func(t *testing.T) {
		noAdminInstall(t)
		installCredentialRegistry(t, aliceStub(), false)
		assertHTTPBasicAuthenticates(t, "alice", "ldap-pass", aliceDN, "corp-ad")
		idpRegistry.mu.Lock()
		idpRegistry.profiles[0].Enabled = false
		idpRegistry.mu.Unlock()
		assertRefusesAll(t, "alice", "ldap-pass")
	})
	t.Run("registry_profile_deleted", func(t *testing.T) {
		noAdminInstall(t)
		installCredentialRegistry(t, aliceStub(), false)
		assertHTTPBasicAuthenticates(t, "alice", "ldap-pass", aliceDN, "corp-ad")
		idpRegistry.mu.Lock()
		idpRegistry.profiles = nil
		delete(idpRegistry.live, "corp-ad")
		idpRegistry.mu.Unlock()
		assertRefusesAll(t, "alice", "ldap-pass")
	})
	t.Run("registry_profile_enabled_but_not_loaded", func(t *testing.T) {
		// An enabled profile that failed to compile: the gate counts it
		// (credCapable), arm 2 runs, nothing answers, and the chain must not
		// reach the admin pair behind it.
		noAdminInstall(t)
		installCredentialRegistry(t, aliceStub(), false)
		idpRegistry.mu.Lock()
		delete(idpRegistry.live, "corp-ad")
		idpRegistry.mu.Unlock()
		if !hasCredentialCapableProvider() {
			t.Fatal("premise: an enabled LDAP profile is credential-capable even when not loaded")
		}
		assertRefusesAll(t, "alice", "ldap-pass")
	})
	t.Run("legacy_provider_unwired", func(t *testing.T) {
		noAdminInstall(t)
		installCachedLegacyLDAP(t, "bob", "bob-dir-pass")
		assertHTTPBasicAuthenticates(t, "bob", "bob-dir-pass", "bob", "local")
		cfg.SetProvider(nil)
		assertRefusesAll(t, "bob", "bob-dir-pass")
	})
}

// TestProxyAuthNoAdmin_ExplicitUnauthenticatedAccessUnchanged: operator-chosen
// unauthenticated access keeps its defined semantics on an admin-only node —
// the Exempt default admits credential-free requests as "unauth", a scoped
// Exempt rule as "exempt" — and a presented credential is still never
// exempted. A node with no account and no provider keeps the frozen inert
// row: Stage 1 is skipped and Stage 2 decides.
func TestProxyAuthNoAdmin_ExplicitUnauthenticatedAccessUnchanged(t *testing.T) {
	t.Run("exempt_default", func(t *testing.T) {
		noAdminInstall(t)
		cfg.SetDefaultAuthOutcome(OutcomeExempt)
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://open.example.test/", "", "", false))
		if !proceed || out.source != "unauth" || out.identity != "" {
			t.Fatalf("Exempt default: want admitted as unauth with no identity, got proceed=%v status=%d source=%q identity=%q",
				proceed, w.Code, out.source, out.identity)
		}
		// Presented credentials are never exempted; the admin pair is not a
		// proxy credential, so it is refused here like any other.
		assertHTTPBasicRefused(t, noAdminUser, noAdminPass)
	})
	t.Run("scoped_exempt_rule", func(t *testing.T) {
		noAdminInstall(t)
		setAuthExemptDisabled(false)
		t.Cleanup(func() { setAuthExemptDisabled(false) })
		const host = "scoped-exempt-noadmin.example.test"
		policyStore.Add(slice7ExemptRule(host))
		w, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://"+host+"/", "", "", false))
		if !proceed || out.source != authSourceExempt || out.identity != "" {
			t.Fatalf("scoped Exempt: want admitted as exempt with no identity, got proceed=%v status=%d source=%q identity=%q",
				proceed, w.Code, out.source, out.identity)
		}
		// The rule does not cover other destinations.
		w, _, proceed = resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://not-covered.example.test/", "", "", false))
		if proceed || w.Code != http.StatusProxyAuthRequired {
			t.Errorf("an uncovered destination must still 407, got proceed=%v status=%d", proceed, w.Code)
		}
	})
	t.Run("no_account_no_provider_inert", func(t *testing.T) {
		noAdminInstall(t)
		if err := cfg.SetAuth("", ""); err != nil {
			t.Fatal(err)
		}
		cfg.mu.Lock()
		cfg.uiUsers = nil
		cfg.mu.Unlock()
		if cfg.AuthEnabled() || hasCredentialCapableProvider() {
			t.Fatal("premise: no account and no provider")
		}
		_, out, proceed := resolveHTTPProxyAuth(t, httpProxyRequest(t, http.MethodGet, "http://fresh.example.test/", "", "", false))
		if !proceed || out.source != "unauth" {
			t.Errorf("no-backend node: Stage 1 must stay inert (unauth), got proceed=%v source=%q", proceed, out.source)
		}
	})
}

// TestProxyCredential_AdminPairNeverResolves pins the resolver directly, on
// both channels, in every configuration the admin account can sit in. This is
// the construction legacyCredentialFor documents: the local pair is reachable
// only through a provider-less snapshot, which the resolver never hands on.
func TestProxyCredential_AdminPairNeverResolves(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T)
	}{
		{"admin_only", func(*testing.T) {}},
		{"beside_registry_ldap", func(t *testing.T) { installCredentialRegistry(t, aliceStub(), false) }},
		{"beside_registry_oidc", func(t *testing.T) { installCredentialRegistry(t, nil, true) }},
		{"beside_legacy_ldap", func(t *testing.T) { installCachedLegacyLDAP(t, "bob", "bob-dir-pass") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noAdminInstall(t)
			tc.setup(t)
			for _, ch := range []proxyCredentialChannel{credentialChannelHTTPBasic, credentialChannelSOCKS5} {
				if id, _, src, ok := resolvePresentedCredential(ch, "198.51.100.9", noAdminUser, noAdminPass); ok {
					t.Errorf("channel %d resolved the admin pair as %q/%q", ch, id, src)
				}
				if id, ok := legacyCredentialFor(ch, "198.51.100.9", noAdminUser, noAdminPass); ok || id != nil {
					t.Errorf("channel %d: the legacy half resolved the admin pair: %+v", ch, id)
				}
			}
		})
	}
}

// TestProxyAuthNoAdmin_CRDiagnosticNamesProxyProvider: on an admin-only node a
// CredentialRequired rule can never be satisfied, and the Diagnostics row must
// say so — it used to count the admin account as a validator.
func TestProxyAuthNoAdmin_CRDiagnosticNamesProxyProvider(t *testing.T) {
	noAdminInstall(t)
	checks := authCredentialRequiredDiagnostics([]PolicyRule{plainCRRule("cr-noadmin", "cr-noadmin.example.test")}, hasCredentialCapableProvider())
	if len(checks) != 1 || checks[0].Code != "auth_cr_no_credential_provider" || checks[0].Status != diagFail {
		t.Fatalf("want one auth_cr_no_credential_provider fail row on an admin-only node, got %+v", checks)
	}
	if strings.Contains(checks[0].OperatorAction, "local account") {
		t.Errorf("the remediation must not offer a local (admin) account: %q", checks[0].OperatorAction)
	}
	installCredentialRegistry(t, aliceStub(), false)
	if checks := authCredentialRequiredDiagnostics([]PolicyRule{plainCRRule("cr-noadmin", "cr-noadmin.example.test")}, hasCredentialCapableProvider()); len(checks) != 0 {
		t.Errorf("with an LDAP profile the CR rule is satisfiable: want no row, got %+v", checks)
	}
}
