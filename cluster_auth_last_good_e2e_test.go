package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/crewjam/saml"
)

func TestClusterAuth_LastGoodSnapshotKeepsSAMLSessionPolicyLocal(t *testing.T) {
	withClusterAuthLastGoodGlobals(t)
	setupProxyTest(t)

	cpSecret := []byte("0123456789abcdef0123456789abcdef")
	snap := ConfigSnapshot{
		Version:               77,
		ProxyBaseURL:          "https://proxy.example.test/culvert",
		TrustForwardedHeaders: true,
		DefaultAction:         "deny",
		PolicyRules: []PolicyRule{{
			Priority:    1,
			Name:        "engineering-can-reach-apps",
			SourceGroup: "engineering",
			DestFQDN:    "*",
			Action:      ActionAllow,
		}},
		SessionHMAC: hex.EncodeToString(cpSecret),
		IdPProfiles: []*IdPProfile{{
			ID:           "corp-saml",
			Name:         "Corp SAML",
			Type:         IdPTypeSAML,
			Enabled:      true,
			EmailDomains: []string{"example.test"},
			SAML: &SAMLProfileConfig{
				MetadataXML:     clusterAuthSAMLMetadataXML(t),
				NameIDFormat:    string(saml.EmailAddressNameIDFormat),
				GroupsAttribute: "groups",
				EmailAttribute:  "email",
				NameAttribute:   "displayName",
			},
		}},
	}

	applyLiveClusterSnapshot(t, snap)
	persistDPLastGoodConfigSnapshot(snap)
	cookie := sessionCookieForIdentity(t, &Identity{
		Sub:      "alice@example.test",
		Email:    "alice@example.test",
		Name:     "Alice Example",
		Groups:   []string{"engineering"},
		Provider: "corp-saml",
	})

	setupProxyTest(t)
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	sessionSecret = nil
	loaded, err := applyDPLastGoodConfigSnapshot()
	if err != nil {
		t.Fatalf("apply last-known-good snapshot: %v", err)
	}
	if loaded.Version != snap.Version {
		t.Fatalf("loaded version = %d, want %d", loaded.Version, snap.Version)
	}
	if !trustForwardedHeaders || cfg.ProxyBaseURL() != "https://proxy.example.test/culvert" {
		t.Fatalf("auth callback settings not restored: base=%q trust=%v", cfg.ProxyBaseURL(), trustForwardedHeaders)
	}
	if !sameBytes(sessionSecret, cpSecret) {
		t.Fatal("session HMAC was not restored from last-known-good snapshot")
	}
	if providers := idpRegistry.EnabledProviders(); len(providers) != 1 || providers[0].Name() != "saml:corp-saml" {
		t.Fatalf("enabled providers = %+v, want compiled SAML provider from cached snapshot", providers)
	}

	backend := clusterAuthBackend(t)
	assertClusterAuthRequest(t, backend.URL, cookie, http.StatusOK)
	assertClusterAuthRequest(t, backend.URL, sessionCookieForIdentity(t, &Identity{
		Sub:      "bob@example.test",
		Email:    "bob@example.test",
		Groups:   []string{"sales"},
		Provider: "corp-saml",
	}), http.StatusForbidden)

	clusterRoleIsDP.Store(true)
	activeDPClient.Store(&DataPlaneClient{})
	dpControlPlanePollFailing.Store(true)
	if got := checkDPLastGoodConfigSnapshot(); got.Status != diagWarn {
		t.Fatalf("last-known-good diagnostic = %q, want warn while CP is down with cached auth config", got.Status)
	}
}

func withClusterAuthLastGoodGlobals(t *testing.T) {
	t.Helper()
	origRegistry := idpRegistry
	origSecret := append([]byte(nil), sessionSecret...)
	origBaseURL := cfg.ProxyBaseURL()
	origTrustForwarded := trustForwardedHeaders
	origDP := clusterRoleIsDP.Load()
	origClient := activeDPClient.Load()
	origPollFailing := dpControlPlanePollFailing.Load()
	withDPLastGoodConfigTestGlobals(t)
	idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}
	t.Cleanup(func() {
		idpRegistry = origRegistry
		sessionSecret = origSecret
		SetProxyBaseURL(origBaseURL)
		trustForwardedHeaders = origTrustForwarded
		clusterRoleIsDP.Store(origDP)
		activeDPClient.Store(origClient)
		dpControlPlanePollFailing.Store(origPollFailing)
	})
}

func applyLiveClusterSnapshot(t *testing.T, snap ConfigSnapshot) {
	t.Helper()
	applyExternalAuthSnapshotSettings(snap)
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		t.Fatalf("sync IdP profiles from live snapshot: %v", err)
	}
	snap.IdPProfiles = nil
	applyConfigSnapshot(snap)
}

func clusterAuthBackend(t *testing.T) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-User-Identity"); got != "" {
			t.Fatalf("backend received X-User-Identity = %q, want scrubbed", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	return backend
}

func assertClusterAuthRequest(t *testing.T, targetURL string, cookie *http.Cookie, wantStatus int) {
	t.Helper()
	w := httptest.NewRecorder()
	r := makeRequest(targetURL, nil)
	r.AddCookie(cookie)
	handleRequest(w, r)
	if w.Code != wantStatus {
		t.Fatalf("proxy status = %d, want %d (body=%q)", w.Code, wantStatus, w.Body.String())
	}
}

func clusterAuthSAMLMetadataXML(t *testing.T) string {
	t.Helper()
	idpKey, idpCert := newSAMLTestKeyPair(t, "Cluster auth test IdP")
	metadataURL := mustParseSAMLTestURL(t, "https://idp.example.test/metadata")
	ssoURL := mustParseSAMLTestURL(t, "https://idp.example.test/sso")
	idp := &saml.IdentityProvider{
		Key:         idpKey,
		Certificate: idpCert,
		MetadataURL: *metadataURL,
		SSOURL:      *ssoURL,
	}
	raw, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatalf("marshal SAML metadata: %v", err)
	}
	return string(raw)
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func TestClusterAuth_ProxyTokenProviderParityFixtureStillCoversOIDC(t *testing.T) {
	provider := &testProxyIdentityProvider{idByToken: map[string]*Identity{
		"engineering-token": {
			Sub:      "alice@example.test",
			Email:    "alice@example.test",
			Groups:   []string{"engineering"},
			Provider: "oidc:corp-oidc",
		},
	}}
	backend := setupProxyIdentityE2E(t, provider)
	creds := base64.StdEncoding.EncodeToString([]byte("alice:engineering-token"))

	w := httptest.NewRecorder()
	r := makeRequest(backend.URL, map[string]string{"Proxy-Authorization": "Basic " + creds})
	handleRequest(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("OIDC-style token auth status = %d, want 200", w.Code)
	}

	w = httptest.NewRecorder()
	r = makeRequest(backend.URL, nil)
	r.AddCookie(sessionCookieForIdentity(t, &Identity{
		Sub:      "alice@example.test",
		Email:    "alice@example.test",
		Groups:   []string{"engineering"},
		Provider: "oidc:corp-oidc",
	}))
	handleRequest(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("browser-session auth status = %d, want 200", w.Code)
	}
}

func TestClusterAuth_LoginURLUsesCachedBaseURL(t *testing.T) {
	withClusterAuthLastGoodGlobals(t)
	setupProxyTest(t)
	snap := ConfigSnapshot{
		Version:      78,
		ProxyBaseURL: "https://proxy.example.test/culvert",
		IdPProfiles: []*IdPProfile{{
			ID:      "corp-saml",
			Name:    "Corp SAML",
			Type:    IdPTypeSAML,
			Enabled: true,
			SAML: &SAMLProfileConfig{
				MetadataXML: clusterAuthSAMLMetadataXML(t),
			},
		}},
	}
	persistDPLastGoodConfigSnapshot(snap)
	if _, err := applyDPLastGoodConfigSnapshot(); err != nil {
		t.Fatalf("apply last-known-good snapshot: %v", err)
	}
	providers := idpRegistry.EnabledProviders()
	if len(providers) != 1 {
		t.Fatalf("enabled providers = %d, want 1", len(providers))
	}
	loginURL := providers[0].CaptiveLoginURL("https://app.example.test/", httptest.NewRequest(http.MethodGet, "/", nil))
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("parse SAML login URL: %v", err)
	}
	if got := u.Query().Get("SAMLRequest"); got == "" {
		t.Fatal("SAML login URL missing SAMLRequest")
	}
}
