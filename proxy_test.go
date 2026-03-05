package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// setupProxyTest resets all global state for a clean test run.
func setupProxyTest(t *testing.T) {
	t.Helper()
	bl = &Blocklist{hosts: map[string]bool{}}
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
