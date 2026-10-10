package main

// F-SSO-SCOPE-1: IP-bound sign-in, end to end through the product's own
// handlers (handleRequest, the login completion hook, logout, the admin API).
// The real-browser journey is ui_sso_ip_binding_e2e_test.go (uie2e tag).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ipsurrogate"
)

// withSSOSurrogate installs settings for one test and restores the previous
// runtime (and clears bindings) afterwards.
func withSSOSurrogate(t *testing.T, s ssoSurrogateSettings) {
	t.Helper()
	prev := ssoSurrogateCfg.Load()
	rt, err := resolveSSOSurrogateSettings(s)
	if err != nil {
		t.Fatal(err)
	}
	applySSOSurrogate(rt)
	ssoSurrogate.Clear()
	t.Cleanup(func() {
		ssoSurrogate.Clear()
		applySSOSurrogate(prev)
	})
}

func ssoLoginFrom(t *testing.T, remote string, id *Identity) ssoBindOutcome {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/callback", nil)
	r.RemoteAddr = remote
	return ssoSurrogateBindLogin(r, id)
}

func proxyFrom(remote, target string, headers map[string]string) *httptest.ResponseRecorder {
	r := makeRequest(target, headers)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	handleRequest(w, r)
	return w
}

var (
	ssoAlice = &Identity{Sub: "alice", Email: "alice@example.com", Groups: []string{"engineering"}, Provider: "corp"}
	ssoBob   = &Identity{Sub: "bob", Email: "bob@example.com", Groups: []string{"finance"}, Provider: "corp"}
)

// OFF (the default): the proxy never sends a browser to sign in — a browser
// SSO session authenticates no proxied traffic, so a redirect could only
// loop — and the challenge says why.
func TestSSOIPBinding_OffWithholdsSignInAndSaysWhy(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: false})
	w := proxyFrom("203.0.113.7:4000", "http://dest.example.test/", map[string]string{"User-Agent": "Mozilla/5.0"})
	if w.Code != http.StatusProxyAuthRequired || w.Header().Get("Location") != "" {
		t.Fatalf("off: %d %q, want 407 and no redirect", w.Code, w.Header().Get("Location"))
	}
	if !strings.Contains(w.Body.String(), "IP-bound sign-in is disabled") {
		t.Fatalf("challenge does not explain: %q", w.Body.String())
	}
	policyStore.Add(localSSO("sso-off.example.test"))
	w = proxyFrom("127.0.0.1:4000", "http://sso-off.example.test/", map[string]string{"Accept": "text/html"})
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "IP-bound sign-in is disabled") {
		t.Fatalf("SSORequired off: %d %q %q", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if o := ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice); o != ssoBindDisabled {
		t.Fatalf("a login bound while off: %s", o)
	}
}

// ON: a completed login binds its client address; traffic from that address
// carries the identity into policy (group allow) and other addresses are
// still challenged. A second user on another address is denied by policy.
func TestSSOIPBinding_BindAttributesIdentityToPolicy(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	backend, cb := startCountingBackend(t)
	policyStore.Add(PolicyRule{Priority: 10, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})

	if o := ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice); o != ssoBindBound {
		t.Fatalf("alice login: %s", o)
	}
	if o := ssoLoginFrom(t, "203.0.113.9:5000", ssoBob); o != ssoBindBound {
		t.Fatalf("bob login: %s", o)
	}
	before := cb.hitCount()
	if w := proxyFrom("203.0.113.7:4000", backend.URL+"/", nil); w.Code != http.StatusOK || cb.hitCount() != before+1 {
		t.Fatalf("alice (engineering, bound): %d, backend hits %d→%d", w.Code, before, cb.hitCount())
	}
	if w := proxyFrom("203.0.113.9:4000", backend.URL+"/", nil); w.Code != http.StatusForbidden {
		t.Fatalf("bob (finance, bound): %d, want 403 by policy", w.Code)
	}
	if w := proxyFrom("203.0.113.8:4000", backend.URL+"/", nil); w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unbound address: %d, want 407", w.Code)
	}
	if cb.hitCount() != before+1 {
		t.Fatal("a denied or unauthenticated request reached the backend")
	}
}

// A presented credential is never overridden by a binding: a wrong
// Proxy-Authorization from a bound address is still refused.
func TestSSOIPBinding_PresentedCredentialWins(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	w := proxyFrom("203.0.113.7:4000", "http://dest.example.test/", map[string]string{"Proxy-Authorization": "Basic YWxpY2U6d3Jvbmc="})
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("wrong credential from a bound address: %d, want 407", w.Code)
	}
}

// Excluded ranges are never bound, and their browsers are not sent to sign in
// (that would loop); loopback logins are never bound; a disabled transport
// drops every binding.
func TestSSOIPBinding_ExcludedLocalAndDisable(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true, ExcludeCIDRs: []string{"198.51.100.0/24", "::ffff:203.0.113.64/124"}})
	if o := ssoLoginFrom(t, "198.51.100.20:5000", ssoAlice); o != ssoBindExcluded {
		t.Fatalf("excluded login: %s", o)
	}
	if o := ssoLoginFrom(t, "203.0.113.70:5000", ssoAlice); o != ssoBindExcluded {
		t.Fatalf("mapped exclusion did not cover the plain address: %s", o)
	}
	if o := ssoLoginFrom(t, "127.0.0.1:5000", ssoAlice); o != ssoBindLocal {
		t.Fatalf("loopback login: %s", o)
	}
	w := proxyFrom("198.51.100.20:4000", "http://dest.example.test/", map[string]string{"User-Agent": "Mozilla/5.0"})
	if w.Code != http.StatusProxyAuthRequired || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "excluded") {
		t.Fatalf("excluded client: %d %q %q", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if w := proxyFrom("203.0.113.7:4000", "http://dest.example.test/", map[string]string{"User-Agent": "Mozilla/5.0"}); w.Code != http.StatusFound {
		t.Fatalf("included client not sent to sign in: %d", w.Code)
	}
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	rt, _ := resolveSSOSurrogateSettings(ssoSurrogateSettings{Enabled: false})
	applySSOSurrogate(rt)
	if ssoSurrogate.Len() != 0 {
		t.Fatal("disabling kept bindings")
	}
}

// Logout ends every binding of the user.
func TestSSOIPBinding_LogoutRevokes(t *testing.T) {
	setupAuthGateTest(t)
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	if !sessionSecretSet() {
		initSessionSecret()
	}
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	ssoLoginFrom(t, "203.0.113.11:5000", ssoAlice)
	ssoLoginFrom(t, "203.0.113.9:5000", ssoBob)
	ssoLoginFrom(t, "203.0.113.12:5000", &Identity{Sub: "alice", Provider: "other-idp"}) // same subject, another IdP: another identity
	rec := httptest.NewRecorder()
	if err := setSessionCookie(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil), ssoAlice); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/auth/logout", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	authLogout(httptest.NewRecorder(), r)
	if ssoSurrogate.Len() != 2 {
		t.Fatalf("after corp/alice's logout %d bindings remain, want bob's and other-idp/alice's", ssoSurrogate.Len())
	}
}

// When the transport is ON but a login cannot be bound, the browser gets a
// page saying so instead of a redirect back into the challenge.
func TestSSOIPBinding_UnboundLoginSaysWhy(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true, ExcludeCIDRs: []string{"198.51.100.0/24"}})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/callback", nil)
	r.RemoteAddr = "198.51.100.20:5000"
	w := httptest.NewRecorder()
	if !ssoSurrogateBindRefused(w, r, ssoAlice) || w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "excluded") {
		t.Fatalf("refusal page: %d %q", w.Code, w.Body.String())
	}
	r.RemoteAddr = "203.0.113.7:5000"
	if ssoSurrogateBindRefused(httptest.NewRecorder(), r, ssoAlice) {
		t.Fatal("a bound login was refused")
	}
}

func TestSSOIPBinding_SettingsValidationAndPersistence(t *testing.T) {
	for name, s := range map[string]ssoSurrogateSettings{
		"ttl too short": {TTLMinutes: 2},
		"ttl too long":  {TTLMinutes: 2000},
		"bad range":     {ExcludeCIDRs: []string{"not-a-range"}},
	} {
		if _, err := resolveSSOSurrogateSettings(s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	rt, err := resolveSSOSurrogateSettings(ssoSurrogateSettings{Enabled: true, ExcludeCIDRs: []string{"10.0.0.7", "10.0.0.0/8", " 10.0.0.0/8 "}})
	if err != nil || rt.settings.TTLMinutes != ssoSurrogateTTLDefaultMins || strings.Join(rt.settings.ExcludeCIDRs, ",") != "10.0.0.7/32,10.0.0.0/8" {
		t.Fatalf("normalised %+v %v", rt.settings, err)
	}
	prev := ssoSurrogateCfg.Load()
	t.Cleanup(func() { applySSOSurrogate(prev) })
	var s AdminSettings
	rt.saved = true
	snapshotSSOSurrogate(&s, rt)
	applySSOSurrogate(prev)
	applyAdminSSOSurrogate(&s)
	if got := currentSSOSurrogateSettings(); !got.Enabled || len(got.ExcludeCIDRs) != 2 || !ssoSurrogate.Enabled() {
		t.Fatalf("round trip: %+v", got)
	}
	// A damaged saved setting never turns the transport on.
	bad := AdminSettings{SSOSurrogateSaved: true, SSOSurrogateEnabled: true, SSOSurrogateExcludeCIDRs: []string{"garbage"}}
	applyAdminSSOSurrogate(&bad)
	if ssoSurrogate.Enabled() {
		t.Fatal("invalid saved settings enabled the transport")
	}
	// Never governed: nothing is written.
	applySSOSurrogate(prev)
	var fresh AdminSettings
	if prev.saved {
		t.Skip("a previous test persisted settings")
	}
	snapshotSSOSurrogate(&fresh, nil)
	if fresh.SSOSurrogateSaved {
		t.Fatal("an ungoverned transport was written to admin settings")
	}
}

// The admin API: viewers read settings, only admins change them or see the
// bindings (they name users and their addresses).
func TestSSOIPBinding_APIRoles(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: false})
	asRole := func(m, target, body string, role UIRole) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(context.WithValue(context.Background(), uiRoleKey{}, role), m, target, strings.NewReader(body))
		w := httptest.NewRecorder()
		if strings.HasPrefix(target, "/api/sso-ip-binding/bindings") {
			apiSSOSurrogateBindings(w, r)
		} else {
			apiSSOSurrogate(w, r)
		}
		return w
	}
	if w := asRole(http.MethodGet, "/api/sso-ip-binding", "", RoleViewer); w.Code != http.StatusOK {
		t.Fatalf("viewer GET: %d", w.Code)
	}
	if w := asRole(http.MethodPut, "/api/sso-ip-binding", `{"enabled":true}`, RoleViewer); w.Code != http.StatusForbidden || ssoSurrogate.Enabled() {
		t.Fatalf("viewer PUT: %d (enabled=%v)", w.Code, ssoSurrogate.Enabled())
	}
	if w := asRole(http.MethodGet, "/api/sso-ip-binding/bindings", "", RoleViewer); w.Code != http.StatusForbidden {
		t.Fatalf("viewer bindings: %d", w.Code)
	}
	if w := asRole(http.MethodPut, "/api/sso-ip-binding", `{"enabled":true,"ttlMinutes":1}`, RoleAdmin); w.Code != http.StatusBadRequest {
		t.Fatalf("admin invalid PUT: %d", w.Code)
	}
}

// ssoScoped returns base as an auth rule for host, scoped to client range cidr.
func ssoScoped(base PolicyRule, name, host, cidr string) PolicyRule {
	base.Name, base.DestFQDN = name, host
	base.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{cidr}}}}
	return base
}

// A binding is evidence of an earlier browser sign-in, so it never satisfies
// a rule demanding a credential presented on THIS request.
func TestSSOIPBinding_NeverSatisfiesCredentialRequired(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	policyStore.Add(PolicyRule{Priority: 10, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})
	policyStore.Add(ssoScoped(validCRRule(), "cr-rule", "cr.example.test", "203.0.113.0/24"))
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	if w := proxyFrom("203.0.113.7:4000", "http://cr.example.test/", nil); w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CredentialRequired destination from a bound address: %d, want 407", w.Code)
	}
	if w := proxyFrom("203.0.113.7:4000", "http://other.example.test/", nil); w.Code == http.StatusProxyAuthRequired {
		t.Fatal("control: the binding stopped working for ordinary destinations")
	}
}

// Under an SSORequired rule with providerRefs a binding counts only when the
// sign-in came from one of those providers.
func TestSSOIPBinding_SSORequiredHonoursProviderRefs(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true), idp("high-assurance", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	policyStore.Add(PolicyRule{Priority: 10, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})
	strict := ssoScoped(validSSORule(), "sso-strict", "strict.example.test", "203.0.113.0/24")
	strict.Auth.ProviderRefs = []string{"high-assurance"}
	loose := ssoScoped(validSSORule(), "sso-loose", "loose.example.test", "203.0.113.0/24")
	loose.Auth.ProviderRefs = []string{"corp"}
	policyStore.Add(strict)
	policyStore.Add(loose)
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice) // signed in through corp
	hdr := map[string]string{"Accept": "text/html", "User-Agent": "Mozilla/5.0"}
	if w := proxyFrom("203.0.113.7:4000", "http://strict.example.test/", hdr); w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "providers=high-assurance") {
		t.Fatalf("SSORequired(high-assurance) satisfied by a corp binding: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := proxyFrom("203.0.113.7:4000", "http://loose.example.test/", hdr); w.Code == http.StatusFound || w.Code == http.StatusProxyAuthRequired {
		t.Fatalf("SSORequired(corp) not satisfied by a corp binding: %d", w.Code)
	}
}

// A settings change tightens live bindings: newly excluded ranges lose them
// and every expiry is clamped to the new lifetime.
func TestSSOIPBinding_SettingsChangeTightensLiveBindings(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true, TTLMinutes: 600})
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	ssoLoginFrom(t, "198.51.100.20:5000", ssoBob)
	rt, _ := resolveSSOSurrogateSettings(ssoSurrogateSettings{Enabled: true, TTLMinutes: 5, ExcludeCIDRs: []string{"198.51.100.0/24"}})
	applySSOSurrogate(rt)
	l := ssoSurrogate.List(time.Now())
	if len(l) != 1 || l[0].Identity.Sub != "alice" || l[0].Expires.After(time.Now().Add(5*time.Minute+time.Second)) {
		t.Fatalf("after tightening: %+v", l)
	}
}

// A takeover of a live binding is counted and logged, and the newest login
// wins (a re-leased address or a handed-over device must not lock out).
func TestSSOIPBinding_TakeoverIsVisible(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	before := ssoSurrogateBinds[ssoBindRebound].Load()
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	if o := ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice); o != ssoBindBound {
		t.Fatalf("same user signing in again: %s", o)
	}
	if o := ssoLoginFrom(t, "203.0.113.7:5000", ssoBob); o != ssoBindRebound {
		t.Fatalf("takeover: %s, want rebound", o)
	}
	if ssoSurrogateBinds[ssoBindRebound].Load() != before+1 {
		t.Fatal("takeover not counted")
	}
	if id, ok := ssoSurrogate.Lookup(netip.MustParseAddr("203.0.113.7"), time.Now()); !ok || id.Sub != "bob" {
		t.Fatalf("newest login does not win: %+v", id)
	}
}

// A binding counts only while its IdP profile is enabled.
func TestSSOIPBinding_DisabledIdPStopsAttribution(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	corp := idp("corp", IdPTypeOIDC, true)
	withSSORegistry(t, corp)
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	policyStore.Add(PolicyRule{Priority: 10, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	if w := proxyFrom("203.0.113.7:4000", "http://x.example.test/", nil); w.Code == http.StatusProxyAuthRequired {
		t.Fatal("control: binding not honoured while the IdP is enabled")
	}
	idpRegistry.mu.Lock()
	corp.Enabled = false
	idpRegistry.mu.Unlock()
	if w := proxyFrom("203.0.113.7:4000", "http://x.example.test/", nil); w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("a disabled IdP's binding still attributed: %d", w.Code)
	}
}

// A binding never outlives the sign-in session it came from.
func TestSSOIPBinding_NeverOutlivesTheSession(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true, TTLMinutes: ssoSurrogateTTLMaxMins})
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	l := ssoSurrogate.List(time.Now())
	if len(l) != 1 || l[0].Expires.After(time.Now().Add(getSessionTTL()+time.Second)) {
		t.Fatalf("binding %v outlives the %v session", l, getSessionTTL())
	}
}

// A sign-in from the appliance's own address identifies no browser.
func TestSSOIPBinding_SelfAddressNeverBound(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	prev := ssoSurrogateSelfAddr
	ssoSurrogateSelfAddr = func(a netip.Addr) bool { return a.String() == "203.0.113.7" }
	t.Cleanup(func() { ssoSurrogateSelfAddr = prev })
	if o := ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice); o != ssoBindLocal {
		t.Fatalf("own address: %s, want local", o)
	}
}

// Re-enabling starts from an empty table, so a bind that raced the earlier
// disable cannot come back to life.
func TestSSOIPBinding_ReEnableStartsEmpty(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: false})
	_, _ = ssoSurrogate.Bind(netip.MustParseAddr("203.0.113.7"), ipsurrogate.Identity{Sub: "alice", Provider: "corp"}, time.Hour, time.Now()) // the raced insert
	rt, _ := resolveSSOSurrogateSettings(ssoSurrogateSettings{Enabled: true})
	applySSOSurrogate(rt)
	if ssoSurrogate.Len() != 0 {
		t.Fatal("a binding from before the disable survived the re-enable")
	}
}

// Turning the transport off never waits on the disk.
func TestSSOIPBinding_OffWinsOverAFailedSave(t *testing.T) {
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	setUISettingsTestPath(t, filepath.Join(blocker, "admin_settings.json"))
	r := httptest.NewRequestWithContext(context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin), http.MethodPut, "/api/sso-ip-binding", strings.NewReader(`{"enabled":false}`))
	w := httptest.NewRecorder()
	apiSSOSurrogate(w, r)
	if w.Code != http.StatusInternalServerError || ssoSurrogate.Enabled() || ssoSurrogate.Len() != 0 || !strings.Contains(w.Body.String(), "OFF now") {
		t.Fatalf("disable with a failing save: %d enabled=%v bindings=%d %q", w.Code, ssoSurrogate.Enabled(), ssoSurrogate.Len(), w.Body.String())
	}
	r = httptest.NewRequestWithContext(context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin), http.MethodPut, "/api/sso-ip-binding", strings.NewReader(`{"enabled":true}`))
	w = httptest.NewRecorder()
	apiSSOSurrogate(w, r)
	if w.Code != http.StatusInternalServerError || ssoSurrogate.Enabled() {
		t.Fatalf("enable with a failing save: %d enabled=%v (enabling must be saved first)", w.Code, ssoSurrogate.Enabled())
	}
}

// Requests attributed through a binding carry a distinct source in the log
// (and to AuthSource-scoped rules): "sso-ip:<provider>".
func TestSSOIPBinding_SourceMarksIPInference(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	backend, _ := startCountingBackend(t)
	policyStore.Add(PolicyRule{Priority: 10, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})
	ssoLoginFrom(t, "203.0.113.7:5000", ssoAlice)
	if w := proxyFrom("203.0.113.7:4000", backend.URL+"/", nil); w.Code != http.StatusOK {
		t.Fatalf("bound request: %d", w.Code)
	}
	u, _ := url.Parse(backend.URL)
	if e := findLogByHost(t, u.Host); e.Identity != "alice" || e.AuthSource != "sso-ip:corp" {
		t.Fatalf("log entry identity %q source %q, want alice / sso-ip:corp", e.Identity, e.AuthSource)
	}
}

// With no credential-capable backend a Basic challenge could never succeed:
// a withheld sign-in is a 403 that says why, not a 407 that re-prompts.
func TestSSOIPBinding_NoCredentialBackendRefusesWithoutBasic(t *testing.T) {
	setupProxyTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeSAML, true))
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: false})
	w := proxyFrom("203.0.113.7:4000", "http://dest.example.test/", map[string]string{"User-Agent": "Mozilla/5.0"})
	if w.Code != http.StatusForbidden || w.Header().Get("Proxy-Authenticate") != "" || !strings.Contains(w.Body.String(), "IP-bound sign-in is disabled") {
		t.Fatalf("SAML-only, transport off: %d %q %q", w.Code, w.Header().Get("Proxy-Authenticate"), w.Body.String())
	}
}
