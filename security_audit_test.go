package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	crand "crypto/rand"
)

// ── uiAuthMiddleware Tests ─────────────────────────────────────────────────

func TestUIAuthMiddleware_PublicPaths(t *testing.T) {
	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	publicPaths := []string{
		"/api/setup",
		"/api/setup/init",
		"/api/auth/login",
		"/api/auth/logout",
		"/api/auth/status",
		"/api/auth/totp/setup",
		"/auth/callback",
		"/proxy.pac",
	}

	for _, path := range publicPaths {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("path %s: got %d, want 200 (should be public)", path, w.Code)
		}
	}
}

func TestUIAuthMiddleware_BlocksUnauthenticated(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()

	// Create a config with auth enabled.
	testCfg := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = testCfg.SetAuth("testadmin", "password123")
	cfg = testCfg

	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/api/policy unauthenticated: got %d, want 401", w.Code)
	}
}

func TestUIAuthMiddleware_NoAuthGrantsAdmin(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()

	// No auth configured — all requests get admin.
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}

	var gotRole UIRole
	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRole = uiRole(r)
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 when auth disabled", w.Code)
	}
	if gotRole != RoleAdmin {
		t.Fatalf("role = %q, want admin when auth disabled", gotRole)
	}
}

func TestUIAuthMiddleware_StaticAssetsAlwaysPublic(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()

	testCfg := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = testCfg.SetAuth("user", "pass")
	cfg = testCfg

	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, path := range []string{"/", "/index.html", "/static/app.js"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("static path %s: got %d, want 200", path, w.Code)
		}
	}
}

func TestUIAuthMiddleware_BasicAuthWorks(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()

	testCfg := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = testCfg.SetAuth("admin", "secret")
	cfg = testCfg

	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	r.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("Basic auth: got %d, want 200", w.Code)
	}
}

func TestUIAuthMiddleware_BadBasicAuth(t *testing.T) {
	origCfg := cfg
	defer func() { cfg = origCfg }()

	testCfg := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	_ = testCfg.SetAuth("admin", "secret")
	cfg = testCfg

	handler := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/api/policy", nil)
	r.SetBasicAuth("admin", "wrong-password")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad Basic auth: got %d, want 401", w.Code)
	}
}

// ── requireRole enforcement on API handlers ────────────────────────────────

func TestAPISecFeedsSync_RequiresAdmin(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/feeds/sync", nil)
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	apiSecFeedsSync(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer calling apiSecFeedsSync: got %d, want 403", w.Code)
	}
}

func TestAPIDomainAllowlist_PUT_RequiresAdmin(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "/api/security-scan/feeds/domain-allowlist",
		strings.NewReader(`{"domains":["evil.com"]}`))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	apiDomainAllowlist(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer calling apiDomainAllowlist PUT: got %d, want 403", w.Code)
	}
}

func TestAPIDomainAllowlist_GET_RequiresViewer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/security-scan/feeds/domain-allowlist", nil)
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	apiDomainAllowlist(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatal("viewer should be able to GET domain allowlist")
	}
}

func TestAPISecYARAReload_RequiresAdmin(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/yara/reload", nil)
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	apiSecYARAReload(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer calling apiSecYARAReload: got %d, want 403", w.Code)
	}
}

func TestAPIExport_RequiresViewer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/export?format=json", nil)
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	apiExport(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatal("viewer should be able to call apiExport")
	}
}

func TestAPIClusterStatus_RequiresViewer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	ctx := context.WithValue(r.Context(), uiRoleKey{}, RoleViewer)
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	apiClusterStatus(w, r)

	if w.Code == http.StatusForbidden {
		t.Fatal("viewer should be able to call apiClusterStatus")
	}
}

// ── SSRF guard on apiBlocklistFeed ─────────────────────────────────────────

func TestAPIBlocklistFeed_RejectsPrivateURL(t *testing.T) {
	origSyncer := blFeedSyncer
	defer func() { blFeedSyncer = origSyncer }()
	blFeedSyncer = &BlocklistSyncer{}

	r := jsonReq(http.MethodPost, "/api/blocklist/feed", map[string]string{
		"url": "http://127.0.0.1:8080/malicious",
	})
	w := httptest.NewRecorder()
	apiBlocklistFeed(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("private URL: got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "private") {
		t.Fatalf("response should mention private: %s", w.Body.String())
	}
}

func TestAPIBlocklistFeed_RejectsMetadataURL(t *testing.T) {
	origSyncer := blFeedSyncer
	defer func() { blFeedSyncer = origSyncer }()
	blFeedSyncer = &BlocklistSyncer{}

	r := jsonReq(http.MethodPost, "/api/blocklist/feed", map[string]string{
		"url": "http://169.254.169.254/latest/meta-data/",
	})
	w := httptest.NewRecorder()
	apiBlocklistFeed(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("metadata URL: got %d, want 400", w.Code)
	}
}

func TestAPIBlocklistFeed_RejectsInternalNetwork(t *testing.T) {
	origSyncer := blFeedSyncer
	defer func() { blFeedSyncer = origSyncer }()
	blFeedSyncer = &BlocklistSyncer{}

	// 10.x.x.x is private.
	r := jsonReq(http.MethodPost, "/api/blocklist/feed", map[string]string{
		"url": "http://10.0.0.5:8080/blocklist.txt",
	})
	w := httptest.NewRecorder()
	apiBlocklistFeed(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("10.0.0.5 URL: got %d, want 400", w.Code)
	}
}

// ── Blocklist exceptions tests ─────────────────────────────────────────────

func TestBlocklistException_BypassesBlock(t *testing.T) {
	b := &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	b.Add("evil.com")
	if !b.IsBlocked("evil.com") {
		t.Fatal("evil.com should be blocked")
	}

	b.AddException("evil.com")
	if b.IsBlocked("evil.com") {
		t.Fatal("evil.com should NOT be blocked after adding exception")
	}

	b.RemoveException("evil.com")
	if !b.IsBlocked("evil.com") {
		t.Fatal("evil.com should be blocked after removing exception")
	}
}

func TestBlocklistException_WildcardException(t *testing.T) {
	b := &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	b.Add("*.example.com")
	if !b.IsBlocked("sub.example.com") {
		t.Fatal("sub.example.com should be blocked by wildcard")
	}

	b.AddException("*.example.com")
	if b.IsBlocked("sub.example.com") {
		t.Fatal("sub.example.com should NOT be blocked with wildcard exception")
	}
}

func TestBlocklistException_ListExceptions(t *testing.T) {
	b := &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	b.AddException("a.com")
	b.AddException("b.com")

	list := b.ListExceptions()
	if len(list) != 2 {
		t.Fatalf("expected 2 exceptions, got %d", len(list))
	}
}

// ── CA LoadCustomCA with RSA key rejection ─────────────────────────────────

func TestCertManager_LoadCustomCA_RejectsRSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(crand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("create RSA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER := x509.MarshalPKCS1PrivateKey(rsaKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})

	cm := &CertManager{}
	err = cm.LoadCustomCA(certPEM, keyPEM)
	if err == nil {
		t.Fatal("expected error for RSA key — only ECDSA supported")
	}
	if !strings.Contains(err.Error(), "ECDSA") {
		t.Fatalf("error should mention ECDSA, got: %v", err)
	}
}

// ── CA GetCert with empty ServerName ───────────────────────────────────────

func TestCertManager_GetCert_EmptyServerName_Audit(t *testing.T) {
	cm := &CertManager{}
	_ = cm.InitCA()

	cert, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: ""})
	if err != nil {
		t.Fatalf("GetCert empty ServerName: %v", err)
	}
	if cert == nil {
		t.Fatal("should return a cert even for empty ServerName")
	}
}

// ── ConnLimiter edge cases ─────────────────────────────────────────────────

func newTestConnLimiter(max int) *ConnLimiter {
	cl := &ConnLimiter{conns: make(map[string]*int64)}
	cl.Enable(max)
	return cl
}

func TestConnLimiter_ReleaseUnknownIP(t *testing.T) {
	cl := newTestConnLimiter(10)
	// Should not panic.
	cl.Release("never-acquired-ip")
}

func TestConnLimiter_EnableNegativeMax(t *testing.T) {
	cl := newTestConnLimiter(-1)
	max := cl.MaxPerIP()
	if max <= 0 {
		t.Fatalf("negative max should use default, got %d", max)
	}
}

func TestConnLimiter_AcquireReleaseCleanup(t *testing.T) {
	cl := newTestConnLimiter(100)

	for i := 0; i < 50; i++ {
		ip := "10.0.0." + string(rune('a'+i))
		if !cl.Acquire(ip) {
			t.Fatalf("Acquire failed for %s", ip)
		}
		cl.Release(ip)
	}

	if cl.ActiveIPs() != 0 {
		t.Fatalf("ActiveIPs = %d, want 0 after all releases", cl.ActiveIPs())
	}
}

// ── isSafeRedirectURL edge cases ───────────────────────────────────────────

func TestIsSafeRedirectURL_RejectsDangerous(t *testing.T) {
	// These should all be rejected without any DNS resolution.
	unsafe := []string{
		"javascript:alert(1)",
		"data:text/html,<h1>hi</h1>",
		"",
		"ftp://example.com/file",
		"/relative/path",       // not absolute
		"://missing-scheme.com", // invalid URL
	}
	for _, u := range unsafe {
		if isSafeRedirectURL(u) {
			t.Errorf("isSafeRedirectURL(%q) = true, want false", u)
		}
	}
}

func TestIsSafeRedirectURL_RejectsPrivateIP(t *testing.T) {
	// Redirect to private IP should be blocked.
	if isSafeRedirectURL("http://127.0.0.1/evil") {
		t.Error("loopback redirect should be rejected")
	}
	if isSafeRedirectURL("http://10.0.0.1/internal") {
		t.Error("private IP redirect should be rejected")
	}
}

// suppress unused import warning
var _ = rand.Int
