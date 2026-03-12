package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── firstNonZero / firstStr ──────────────────────────────────────────────────

func TestFirstNonZero(t *testing.T) {
	if got := firstNonZero(0, 0, 5); got != 5 {
		t.Errorf("firstNonZero(0,0,5) = %d, want 5", got)
	}
	if got := firstNonZero(0, 0, 0); got != 0 {
		t.Errorf("firstNonZero(0,0,0) = %d, want 0", got)
	}
	if got := firstNonZero(3, 7); got != 3 {
		t.Errorf("firstNonZero(3,7) = %d, want 3", got)
	}
}

func TestFirstStr(t *testing.T) {
	if got := firstStr("", "", "hello"); got != "hello" {
		t.Errorf("firstStr('','','hello') = %q, want 'hello'", got)
	}
	if got := firstStr("", "", ""); got != "" {
		t.Errorf("firstStr('','','') = %q, want ''", got)
	}
	if got := firstStr("a", "b"); got != "a" {
		t.Errorf("firstStr('a','b') = %q, want 'a'", got)
	}
}

// ─── handleHealth ─────────────────────────────────────────────────────────────

func TestHandleHealth(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	handleHealth(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("handleHealth status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"status":"ok"`) {
		t.Errorf("handleHealth body missing status:ok, got %q", body)
	}
	if !strings.Contains(body, `"uptime"`) {
		t.Errorf("handleHealth body missing uptime, got %q", body)
	}
}

// ─── matchCountry ─────────────────────────────────────────────────────────────

func TestMatchCountry(t *testing.T) {
	if matchCountry([]string{"US", "DE"}, "US") != true {
		t.Error("matchCountry should match US")
	}
	if matchCountry([]string{"US", "DE"}, "us") != true {
		t.Error("matchCountry should be case-insensitive")
	}
	if matchCountry([]string{"US", "DE"}, "FR") != false {
		t.Error("matchCountry should not match FR")
	}
	if matchCountry([]string{"US"}, "") != false {
		t.Error("matchCountry with empty code should return false")
	}
	if matchCountry([]string{}, "US") != false {
		t.Error("matchCountry with empty list should return false")
	}
}

// ─── HashCache ────────────────────────────────────────────────────────────────

func TestHashCache_GetSet(t *testing.T) {
	c := newHashCache(100, time.Minute)

	hash := SHA256Hex([]byte("test content"))
	result := ScanCacheResult{Clean: true, Source: "clamav"}
	c.Set(hash, result)

	got, ok := c.Get(hash)
	if !ok {
		t.Fatal("HashCache.Get should find cached entry")
	}
	if !got.Clean {
		t.Error("cached result should be clean")
	}
	if got.Source != "clamav" {
		t.Errorf("cached source = %q, want clamav", got.Source)
	}
}

func TestHashCache_Miss(t *testing.T) {
	c := newHashCache(100, time.Minute)
	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("HashCache.Get should miss for unknown hash")
	}
}

func TestHashCache_Expired(t *testing.T) {
	c := newHashCache(100, time.Millisecond)
	hash := SHA256Hex([]byte("expiring content"))
	c.Set(hash, ScanCacheResult{Clean: true})
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get(hash)
	if ok {
		t.Error("HashCache.Get should miss for expired entry")
	}
}

func TestHashCache_Eviction(t *testing.T) {
	c := newHashCache(4, time.Minute)
	for i := 0; i < 6; i++ {
		h := SHA256Hex([]byte(string(rune('a' + i))))
		c.Set(h, ScanCacheResult{Clean: true})
	}
	hits, misses, _ := c.Stats()
	_ = hits
	_ = misses
	// Just verify it doesn't panic and stats are accessible
}

func TestHashCache_Stats(t *testing.T) {
	c := newHashCache(100, time.Minute)
	hash := SHA256Hex([]byte("data"))
	c.Set(hash, ScanCacheResult{Clean: false, Reason: "EICAR"})
	c.Get(hash)  // hit
	c.Get("x")  // miss

	hits, misses, size := c.Stats()
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
	if size != 1 {
		t.Errorf("size = %d, want 1", size)
	}
}

func TestSHA256Hex(t *testing.T) {
	h1 := SHA256Hex([]byte("hello"))
	h2 := SHA256Hex([]byte("hello"))
	if h1 != h2 {
		t.Error("SHA256Hex should be deterministic")
	}
	if len(h1) != 64 {
		t.Errorf("SHA256Hex len = %d, want 64", len(h1))
	}
	h3 := SHA256Hex([]byte("world"))
	if h1 == h3 {
		t.Error("SHA256Hex should differ for different input")
	}
}

// ─── Session encode/decode ────────────────────────────────────────────────────

func init() {
	// Ensure session secret is initialised for session tests.
	if len(sessionSecret) == 0 {
		initSessionSecret()
	}
}

func TestEncodeDecodeSession(t *testing.T) {
	s := &Session{
		Sub:      "user-1",
		Email:    "user@example.com",
		Name:     "Test User",
		Provider: "local",
		Exp:      time.Now().Add(time.Hour).Unix(),
	}
	encoded, err := encodeSession(s)
	if err != nil {
		t.Fatalf("encodeSession error: %v", err)
	}
	decoded, err := decodeSession(encoded)
	if err != nil {
		t.Fatalf("decodeSession error: %v", err)
	}
	if decoded.Sub != s.Sub {
		t.Errorf("decoded.Sub = %q, want %q", decoded.Sub, s.Sub)
	}
	if decoded.Email != s.Email {
		t.Errorf("decoded.Email = %q, want %q", decoded.Email, s.Email)
	}
}


func TestSetClearSessionCookie(t *testing.T) {
	w := httptest.NewRecorder()
	id := &Identity{Sub: "u1", Email: "u@e.com", Name: "U", Provider: "local"}
	if err := setSessionCookie(w, id); err != nil {
		t.Fatalf("setSessionCookie error: %v", err)
	}
	cookies := w.Result().Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
		}
	}
	if !found {
		t.Error("setSessionCookie should write a session cookie")
	}

	w2 := httptest.NewRecorder()
	clearSessionCookie(w2)
	cookies2 := w2.Result().Cookies()
	for _, c := range cookies2 {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			return // success
		}
	}
	t.Error("clearSessionCookie should set MaxAge=-1 to delete the cookie")
}

func TestReadSessionCookie_NoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sess, err := readSessionCookie(r)
	if err != nil {
		t.Errorf("readSessionCookie with no cookie returned error: %v", err)
	}
	if sess != nil {
		t.Error("readSessionCookie with no cookie should return nil session")
	}
}


// ─── IPFilter ─────────────────────────────────────────────────────────────────

func TestIPFilter_AddRemove(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	if err := f.Add("10.0.0.1"); err != nil {
		t.Fatalf("Add IP error: %v", err)
	}
	if err := f.Add("192.168.0.0/24"); err != nil {
		t.Fatalf("Add CIDR error: %v", err)
	}
	list := f.List()
	if len(list) < 2 {
		t.Errorf("List should contain 2 entries, got %d", len(list))
	}
	f.Remove("10.0.0.1")
	f.Remove("192.168.0.0/24")
}

func TestIPFilter_SetGetMode(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	f.SetMode("allow")
	if got := f.Mode(); got != "allow" {
		t.Errorf("Mode() = %q, want allow", got)
	}
}

// ─── RateLimiter.Window ───────────────────────────────────────────────────────

func TestRateLimiter_Window(t *testing.T) {
	// rl is the package-level rate limiter; just verify accessors don't panic
	w := rl.Window()
	_ = w
	l := rl.Limit()
	_ = l
}

// ─── Config helpers ───────────────────────────────────────────────────────────

func TestConfig_SetProvider(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	// nil provider should not panic
	c.SetProvider(nil)
}

func TestConfig_ProxyBaseURL(t *testing.T) {
	old := proxyExternalBaseURL
	defer func() { proxyExternalBaseURL = old }()

	SetProxyBaseURL("https://proxy.example.com/")
	c := &Config{}
	if got := c.ProxyBaseURL(); got != "https://proxy.example.com" {
		t.Errorf("ProxyBaseURL() = %q, want without trailing slash", got)
	}
}

func TestConfig_OIDCLoginURL(t *testing.T) {
	old := oidcLoginURL
	defer func() { oidcLoginURL = old }()

	SetOIDCLoginURL("https://idp.example.com/auth")
	c := &Config{}
	if got := c.OIDCLoginURL(); got != "https://idp.example.com/auth" {
		t.Errorf("OIDCLoginURL() = %q, want https://idp.example.com/auth", got)
	}
}

func TestConfig_SetUIUsersFile(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile("/tmp/test-ui-users.json")
	// Verify it was stored (LoadUIUsersFile returns nil for empty file path)
	// Just test it doesn't panic
}

func TestConfig_LoadUIUsersFile_EmptyPath(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	// Empty path should return nil without doing anything
	if err := c.LoadUIUsersFile(); err != nil {
		t.Errorf("LoadUIUsersFile with empty path returned error: %v", err)
	}
}

func TestConfig_DeleteUIUser(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = c.SetUIUser("admin1", "pass1", RoleAdmin)
	_ = c.SetUIUser("admin2", "pass2", RoleAdmin)

	// Deleting one admin should succeed
	if err := c.DeleteUIUser("admin2"); err != nil {
		t.Errorf("DeleteUIUser error: %v", err)
	}

	// Deleting last admin should fail
	if err := c.DeleteUIUser("admin1"); err == nil {
		t.Error("DeleteUIUser should prevent deleting last admin")
	}
}

func TestConfig_SetUIUser_RoleUpdate(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = c.SetUIUser("op1", "pass", RoleOperator)
	// Update role without changing password (empty password string)
	_ = c.SetUIUser("op1", "", RoleViewer)
	users := c.ListUIUsers()
	for _, u := range users {
		if u.Username == "op1" && u.Role != RoleViewer {
			t.Errorf("role update failed, got %v want viewer", u.Role)
		}
	}
}

func TestInitAuditLog_EmptyPath(t *testing.T) {
	// Empty path should be a no-op
	if err := InitAuditLog(""); err != nil {
		t.Errorf("InitAuditLog('') returned error: %v", err)
	}
}

