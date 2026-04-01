package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── P0.2: RFC 7230 hop-by-hop headers ───────────────────────────────────────

func TestRemoveHopHeaders_RFC7230Connection(t *testing.T) {
	h := http.Header{}
	// Connection header lists "X-Custom-Hop" as a hop-by-hop header.
	h.Set("Connection", "X-Custom-Hop, keep-alive")
	h.Set("X-Custom-Hop", "some-value")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Content-Type", "text/html")

	removeHopHeaders(h)

	if h.Get("X-Custom-Hop") != "" {
		t.Error("Connection-listed header X-Custom-Hop should be removed per RFC 7230 §6.1")
	}
	if h.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive should be removed")
	}
	if h.Get("Connection") != "" {
		t.Error("Connection should be removed")
	}
	if h.Get("Content-Type") == "" {
		t.Error("Content-Type should be preserved")
	}
}

func TestRemoveHopHeaders_TrailerSingular(t *testing.T) {
	h := http.Header{}
	h.Set("Trailer", "X-Checksum")
	removeHopHeaders(h)
	if h.Get("Trailer") != "" {
		t.Error("Trailer (singular) should be removed")
	}
}

// ── P0.4: GeoIP fail-closed ─────────────────────────────────────────────────

func TestGeoIPFailClosed(t *testing.T) {
	// When countrySet is true and cache misses, the rule should NOT match.
	// We test matchRuleConditions indirectly through the policy evaluation path.
	// A rule with DestCountry set should not match when GeoIP has no data.

	// Set up a minimal policy store with a geo-restricted rule.
	rule := PolicyRule{
		Name:        "geo-test",
		Priority:    1,
		Action:      ActionAllow,
		DestCountry: []string{"US"},
	}
	store := &PolicyStore{}
	_ = store.Add(rule)

	// With no GeoIP database loaded, rules with DestCountry should not match
	// (fail-closed behavior). The default action determines the outcome.
	setDefaultPolicyAction("deny")
	match := store.Evaluate("192.168.1.1", "", "", "example.com", nil)

	if match != nil {
		t.Error("GeoIP fail-closed: rule with DestCountry should NOT match when GeoIP data is unavailable")
	}
}

// ── P0.5: Cert cache LRU + TTL ─────────────────────────────────────────────

func TestCertCacheTTLExpiry(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	// Sign a leaf cert and cache it.
	hello := &tls.ClientHelloInfo{ServerName: "ttl-test.example.com"}
	cert1, err := cm.GetCert(hello)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	if cm.CertCacheLen() != 1 {
		t.Fatalf("expected 1 cached entry, got %d", cm.CertCacheLen())
	}

	// Manually expire the cache entry.
	cm.mu.Lock()
	cm.cache["ttl-test.example.com"].createdAt = time.Now().Add(-2 * certCacheTTL)
	cm.mu.Unlock()

	// Requesting again should re-sign (new cert).
	cert2, err := cm.GetCert(hello)
	if err != nil {
		t.Fatalf("GetCert after expiry: %v", err)
	}
	if cert1 == cert2 {
		t.Error("expected new cert after TTL expiry, got same pointer")
	}
}

func TestCertCacheLRUEviction(t *testing.T) {
	cm := &CertManager{cache: map[string]*certCacheEntry{}}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	// Pre-fill cache to exactly the limit with unique entries.
	now := time.Now()
	for i := 0; i < certCacheMaxSize; i++ {
		host := fmt.Sprintf("host-%d.example.com", i)
		cm.cache[host] = &certCacheEntry{cert: &tls.Certificate{}, createdAt: now}
		cm.cacheOrder = append(cm.cacheOrder, host)
	}

	if cm.CertCacheLen() != certCacheMaxSize {
		t.Fatalf("expected %d cached entries, got %d", certCacheMaxSize, cm.CertCacheLen())
	}

	// Adding one more should trigger eviction of oldest 10%.
	hello := &tls.ClientHelloInfo{ServerName: "eviction-trigger.example.com"}
	_, err := cm.GetCert(hello)
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}

	// After eviction: cache should be smaller than max (evicted 10% then added 1).
	if cm.CertCacheLen() > certCacheMaxSize {
		t.Errorf("cache should not exceed %d entries after eviction, got %d", certCacheMaxSize, cm.CertCacheLen())
	}
}

// ── P1.2: Dynamic session cookie Secure flag ────────────────────────────────

func TestIsSecureRequest(t *testing.T) {
	// Plain HTTP request.
	r := httptest.NewRequest("GET", "http://example.com/", nil)
	if isSecureRequest(r) {
		t.Error("plain HTTP should not be secure")
	}

	// Request with TLS.
	r2 := httptest.NewRequest("GET", "https://example.com/", nil)
	r2.TLS = &tls.ConnectionState{}
	if !isSecureRequest(r2) {
		t.Error("HTTPS request should be secure")
	}

	// Request behind reverse proxy with X-Forwarded-Proto.
	r3 := httptest.NewRequest("GET", "http://example.com/", nil)
	r3.Header.Set("X-Forwarded-Proto", "https")
	if !isSecureRequest(r3) {
		t.Error("X-Forwarded-Proto: https should be treated as secure")
	}
}

func TestSetSessionCookieSecureFlag(t *testing.T) {
	initSessionSecret()

	id := &Identity{Sub: "user1", Email: "user@test.com", Provider: "local"}

	// Plain HTTP — Secure should be false.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest("GET", "http://example.com/", nil)
	if err := setSessionCookie(w1, r1, id); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	for _, c := range w1.Result().Cookies() {
		if c.Name == sessionCookieName && c.Secure {
			t.Error("Secure flag should be false for plain HTTP")
		}
	}

	// HTTPS — Secure should be true.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "https://example.com/", nil)
	r2.TLS = &tls.ConnectionState{}
	if err := setSessionCookie(w2, r2, id); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	for _, c := range w2.Result().Cookies() {
		if c.Name == sessionCookieName && !c.Secure {
			t.Error("Secure flag should be true for HTTPS")
		}
	}
}
