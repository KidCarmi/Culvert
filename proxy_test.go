package main

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// setupProxyTest resets all global state for a clean test run.
func setupProxyTest(t *testing.T) {
	t.Helper()
	bl = &Blocklist{exact: map[string]bool{}, wildcards: map[string]bool{}}
	ipf = &IPFilter{single: map[string]bool{}}
	rl = &RateLimiter{clients: map[string]*clientBucket{}}
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	plugins = nil
}

// makeRequest builds a request that looks like a browser→proxy HTTP request.
func makeRequest(method, targetURL string, headers map[string]string) *http.Request {
	u, _ := url.Parse(targetURL)
	r := httptest.NewRequest(method, targetURL, nil)
	r.Host = u.Host
	r.URL = u
	r.RemoteAddr = "127.0.0.1:12345"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// ── Auth tests ────────────────────────────────────────────────────────────────

func TestHandleRequest_AuthRequired(t *testing.T) {
	setupProxyTest(t)
	if err := cfg.SetAuth("alice", "secret"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}

	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://example.com/", nil)
	handleRequest(w, r)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
	}
}

func TestHandleRequest_AuthWrongPassword(t *testing.T) {
	setupProxyTest(t)
	if err := cfg.SetAuth("alice", "secret"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}

	creds := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://example.com/", map[string]string{
		"Proxy-Authorization": "Basic " + creds,
	})
	handleRequest(w, r)

	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", w.Code)
	}
}

// ── Blocklist tests ───────────────────────────────────────────────────────────

func TestHandleRequest_BlockedHost(t *testing.T) {
	setupProxyTest(t)
	bl.Add("blocked.com")

	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://blocked.com/", nil)
	handleRequest(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleRequest_BlockedHostWildcard(t *testing.T) {
	setupProxyTest(t)
	bl.Add("*.evil.com")

	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://deep.sub.evil.com/", nil)
	handleRequest(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ── IP filter tests ───────────────────────────────────────────────────────────

func TestHandleRequest_IPBlocked(t *testing.T) {
	setupProxyTest(t)
	ipf.SetMode("block")
	ipf.Add("127.0.0.1") //nolint:errcheck

	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://example.com/", nil)
	handleRequest(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ── Rate limiter tests ────────────────────────────────────────────────────────

func TestHandleRequest_RateLimited(t *testing.T) {
	setupProxyTest(t)

	// Use a real upstream server so the first requests succeed.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	rl.Configure(2, time.Minute) // limit=2 per minute

	allowed := 0
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := makeRequest("GET", backend.URL+"/", nil)
		handleRequest(w, r)
		if w.Code != http.StatusTooManyRequests {
			allowed++
		}
	}
	if allowed > 2 {
		t.Errorf("expected at most 2 allowed, got %d", allowed)
	}
}

// ── Plugin tests ──────────────────────────────────────────────────────────────

func TestHandleRequest_PluginBlocks(t *testing.T) {
	setupProxyTest(t)
	plugins = []Middleware{&testPlugin{name: "block-all", decision: DecisionBlock}}

	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://example.com/", nil)
	handleRequest(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 from plugin, got %d", w.Code)
	}
}

// ── parseProxyAuth tests ──────────────────────────────────────────────────────

func TestParseProxyAuth_Valid(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
	u, p, ok := parseProxyAuth(r)
	if !ok || u != "user" || p != "pass" {
		t.Errorf("parseProxyAuth = (%q,%q,%v), want (user,pass,true)", u, p, ok)
	}
}

func TestParseProxyAuth_Missing(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	_, _, ok := parseProxyAuth(r)
	if ok {
		t.Error("expected ok=false with no auth header")
	}
}

func TestParseProxyAuth_Malformed(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Proxy-Authorization", "Basic notbase64!!!")
	_, _, ok := parseProxyAuth(r)
	if ok {
		t.Error("expected ok=false with invalid base64")
	}
}

// ── scrubForwardedHeaders tests ───────────────────────────────────────────────

func TestScrubForwardedHeaders_XFFPrivateStripped(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 1.2.3.4, 192.168.1.5")
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-Forwarded-For"); got != "1.2.3.4" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "1.2.3.4")
	}
}

func TestScrubForwardedHeaders_XFFAllPrivateRemoved(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 172.16.5.1, 192.168.100.50")
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-Forwarded-For"); got != "" {
		t.Errorf("X-Forwarded-For should be removed when all IPs are private, got %q", got)
	}
}

func TestScrubForwardedHeaders_XFFPublicKept(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 1.1.1.1")
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-Forwarded-For"); got != "8.8.8.8, 1.1.1.1" {
		t.Errorf("X-Forwarded-For = %q, want %q", got, "8.8.8.8, 1.1.1.1")
	}
}

func TestScrubForwardedHeaders_XRealIPPrivateRemoved(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Real-IP", "192.168.1.1")
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-Real-IP"); got != "" {
		t.Errorf("X-Real-IP with private addr should be removed, got %q", got)
	}
}

func TestScrubForwardedHeaders_XRealIPPublicKept(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Real-IP", "203.0.113.5")
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-Real-IP"); got != "203.0.113.5" {
		t.Errorf("X-Real-IP with public addr should be kept, got %q", got)
	}
}

func TestScrubForwardedHeaders_XUserIdentityAlwaysRemoved(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-User-Identity", "admin")
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-User-Identity"); got != "" {
		t.Errorf("X-User-Identity should always be stripped, got %q", got)
	}
}

// ── isPrivateIP tests ─────────────────────────────────────────────────────────

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"::1", true},
		{"fc00::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
		{"172.32.0.1", false}, // just outside 172.16/12
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("invalid test IP: %s", c.ip)
		}
		if got := isPrivateIP(ip); got != c.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", c.ip, got, c.private)
		}
	}
}

// ── FQDN suffix matching tests ────────────────────────────────────────────────

func TestMatchFQDN_SuffixMatch(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Palo Alto-style: bare domain matches itself AND all subdomains.
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"example.com", "deep.sub.example.com", true},
		// Must not match unrelated domains.
		{"example.com", "notexample.com", false},
		{"example.com", "evil-example.com", false},
		// Wildcard patterns still work as before.
		{"*.co.il", "www.co.il", true},
		{"*.co.il", "co.il", true},
		{"*.co.il", "evil.co.il.com", false},
		// Global wildcard.
		{"*", "anything.example.org", true},
	}
	for _, c := range cases {
		if got := matchFQDN(c.pattern, c.host); got != c.want {
			t.Errorf("matchFQDN(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// ── Zero Trust Default Deny tests ────────────────────────────────────────────

func TestHandleRequest_DefaultDeny_NoRules(t *testing.T) {
	setupProxyTest(t)
	// policyStore starts empty after setupProxyTest; no rules → default deny.
	w := httptest.NewRecorder()
	r := makeRequest("GET", "http://example.com/", nil)
	handleRequest(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("default deny: expected 403, got %d", w.Code)
	}
}

func TestHandleRequest_AllowedByRule(t *testing.T) {
	setupProxyTest(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	policyStore.rules = nil
	policyStore.Add(PolicyRule{
		Priority: 1,
		Name:     "allow-backend",
		DestFQDN: "*",
		Action:   ActionAllow,
	})

	// With a matching Allow rule, the request reaches the backend (200), not policy-deny (403).
	w := httptest.NewRecorder()
	r := makeRequest("GET", backend.URL+"/", nil)
	handleRequest(w, r)
	if w.Code == http.StatusForbidden {
		t.Errorf("allowed rule: expected not-403, got 403")
	}
}

// ── SSLBypassMatcher tests ────────────────────────────────────────────────────

func TestSSLBypassMatcher_GlobSuffix(t *testing.T) {
	m := &SSLBypassMatcher{}
	if err := m.Set([]string{"*.co.il"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	cases := []struct {
		host string
		want bool
	}{
		{"www.ynet.co.il", true},
		{"co.il", true},          // bare domain also matches
		{"evil.co.il.com", false}, // suffix must be exact
		{"example.com", false},
	}
	for _, c := range cases {
		if got := m.Matches(c.host); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestSSLBypassMatcher_GlobWildcard(t *testing.T) {
	m := &SSLBypassMatcher{}
	if err := m.Set([]string{"*"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !m.Matches("anything.example.com") {
		t.Error("wildcard * should match everything")
	}
}

func TestSSLBypassMatcher_Regex(t *testing.T) {
	m := &SSLBypassMatcher{}
	if err := m.Set([]string{`~^.*\.gov\.il$`}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !m.Matches("www.taxes.gov.il") {
		t.Error("regex should match www.taxes.gov.il")
	}
	if m.Matches("gov.il.evil.com") {
		t.Error("regex should not match gov.il.evil.com")
	}
}

func TestSSLBypassMatcher_InvalidRegex(t *testing.T) {
	m := &SSLBypassMatcher{}
	err := m.Set([]string{"~[invalid"})
	if err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestSSLBypassMatcher_EmptyList(t *testing.T) {
	m := &SSLBypassMatcher{}
	if m.Matches("example.com") {
		t.Error("empty bypass list should not match anything")
	}
}

func TestSSLBypassMatcher_AddRemoveList(t *testing.T) {
	m := &SSLBypassMatcher{}
	if err := m.Add("*.co.il"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Add("example.com"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Duplicate add is a no-op.
	if err := m.Add("*.co.il"); err != nil {
		t.Fatalf("Add duplicate: %v", err)
	}
	if got := m.List(); len(got) != 2 {
		t.Errorf("List len = %d, want 2", len(got))
	}
	if !m.Matches("news.co.il") {
		t.Error("should match news.co.il after Add")
	}
	removed := m.Remove("*.co.il")
	if !removed {
		t.Error("Remove should return true for existing pattern")
	}
	if m.Matches("news.co.il") {
		t.Error("should not match news.co.il after Remove")
	}
	if m.Remove("nonexistent") {
		t.Error("Remove should return false for missing pattern")
	}
}

func TestSSLBypassMatcher_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bypass.json"

	m := &SSLBypassMatcher{}
	// Loading a missing file should not error.
	if err := m.Load(path); err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	// Add patterns and save.
	m.Add("*.co.il")      //nolint:errcheck
	m.Add("example.com")  //nolint:errcheck
	m.Save()

	// Load into a fresh matcher and verify.
	m2 := &SSLBypassMatcher{}
	if err := m2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := m2.List(); len(got) != 2 {
		t.Errorf("after Load: List len = %d, want 2", len(got))
	}
	if !m2.Matches("www.co.il") {
		t.Error("after Load: should match www.co.il")
	}
}

// ── isWebSocketUpgrade tests ──────────────────────────────────────────────────

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		upgrade    string
		connection string
		want       bool
	}{
		{"websocket", "Upgrade", true},
		{"WebSocket", "upgrade, keep-alive", true},
		{"", "Upgrade", false},
		{"websocket", "", false},
		{"h2c", "Upgrade", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if c.upgrade != "" { r.Header.Set("Upgrade", c.upgrade) }
		if c.connection != "" { r.Header.Set("Connection", c.connection) }
		if got := isWebSocketUpgrade(r); got != c.want {
			t.Errorf("isWebSocketUpgrade(Upgrade=%q Connection=%q) = %v, want %v",
				c.upgrade, c.connection, got, c.want)
		}
	}
}
