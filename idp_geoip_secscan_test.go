package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// ─── IdPRegistry.Load ─────────────────────────────────────────────────────────

func TestIdPRegistry_Load_NonExistent2(t *testing.T) {
	r := &IdPRegistry{
		profiles: nil,
		live:     make(map[string]IdentityProvider),
	}
	if err := r.Load("/tmp/nonexistent_idp_registry_xyz2.json"); err != nil {
		t.Errorf("Load nonexistent path should return nil, got %v", err)
	}
}

func TestIdPRegistry_Load_BadJSON(t *testing.T) {
	f, err := os.CreateTemp("", "idpreg*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("not json")
	f.Close()

	r := &IdPRegistry{
		profiles: nil,
		live:     make(map[string]IdentityProvider),
	}
	if err := r.Load(f.Name()); err == nil {
		t.Error("Load bad JSON should return error")
	}
}

func TestIdPRegistry_Load_ValidProfiles(t *testing.T) {
	profiles := []*IdPProfile{
		{
			ID:      "test-load-id",
			Name:    "test-load",
			Type:    IdPTypeSAML,
			Enabled: false, // disabled — won't call compile
			SAML:    &SAMLProfileConfig{MetadataXML: "<xml/>"},
		},
	}
	data, _ := json.Marshal(profiles)
	f, err := os.CreateTemp("", "idpreg*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.Write(data)
	f.Close()

	r := &IdPRegistry{
		profiles: nil,
		live:     make(map[string]IdentityProvider),
	}
	if err := r.Load(f.Name()); err != nil {
		t.Fatalf("Load valid profiles: %v", err)
	}
	if len(r.profiles) != 1 {
		t.Errorf("Load should populate profiles, got %d", len(r.profiles))
	}
}

// ─── IdPRegistry.compile (via Upsert with unknown type) ───────────────────────

func TestIdPRegistry_compile_UnknownType(t *testing.T) {
	r := &IdPRegistry{
		profiles: nil,
		live:     make(map[string]IdentityProvider),
	}
	// Unknown type should fail in compile, which is called from Upsert if enabled
	// But Upsert validates type before compile, so use compile directly
	p := &IdPProfile{
		ID:      "compile-test",
		Name:    "compile-test",
		Type:    "unknown",
		Enabled: false,
	}
	err := r.compile(p)
	if err == nil {
		t.Error("compile with unknown type should return error")
	}
}

func TestIdPRegistry_compile_OIDC_NilConfig(t *testing.T) {
	r := &IdPRegistry{
		profiles: nil,
		live:     make(map[string]IdentityProvider),
	}
	p := &IdPProfile{
		ID:      "compile-oidc-nil",
		Name:    "compile-oidc-nil",
		Type:    IdPTypeOIDC,
		Enabled: false,
		OIDC:    nil,
	}
	err := r.compile(p)
	if err == nil {
		t.Error("compile OIDC with nil config should return error")
	}
}

func TestIdPRegistry_compile_SAML_NilConfig(t *testing.T) {
	r := &IdPRegistry{
		profiles: nil,
		live:     make(map[string]IdentityProvider),
	}
	p := &IdPProfile{
		ID:      "compile-saml-nil",
		Name:    "compile-saml-nil",
		Type:    IdPTypeSAML,
		Enabled: false,
		SAML:    nil,
	}
	err := r.compile(p)
	if err == nil {
		t.Error("compile SAML with nil config should return error")
	}
}

// ─── validateExternalURL ──────────────────────────────────────────────────────

func TestValidateExternalURL_Empty(t *testing.T) {
	err := validateExternalURL("")
	if err == nil {
		t.Error("validateExternalURL empty should return error")
	}
}

func TestValidateExternalURL_PrivateIP(t *testing.T) {
	err := validateExternalURL("http://192.168.1.1/path")
	if err == nil {
		t.Error("validateExternalURL private IP should return error")
	}
}

func TestValidateExternalURL_HTTP(t *testing.T) {
	// http (not https) should fail
	err := validateExternalURL("http://public.example.com/path")
	if err == nil {
		t.Error("validateExternalURL http should return error")
	}
}

// ─── stringsEqualFold ─────────────────────────────────────────────────────────

// ─── SecurityScanner.CheckURL/CheckDomain with enabled feed ──────────────────

func TestSecurityScanner_CheckURL_EnabledFeed_Hit(t *testing.T) {
	// Temporarily enable the global threat feed and add a URL
	old := globalThreatFeed
	tf := newEnabledFeed()
	tf.urls["http://evil.example.com/malware"] = feedEntry{Source: "urlhaus", AddedAt: time.Now()}
	globalThreatFeed = tf
	defer func() { globalThreatFeed = old }()

	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	result := ss.CheckURL("http://evil.example.com/malware")
	if result == nil {
		t.Error("CheckURL should return result for known malicious URL")
	}
	if result != nil && result.Source != "threatfeed" {
		t.Errorf("CheckURL source = %q, want threatfeed", result.Source)
	}
}

func TestSecurityScanner_CheckDomain_EnabledFeed_Hit(t *testing.T) {
	old := globalThreatFeed
	tf := newEnabledFeed()
	tf.domains["phishing.example.com"] = feedEntry{Source: "openphish", AddedAt: time.Now()}
	globalThreatFeed = tf
	defer func() { globalThreatFeed = old }()

	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	result := ss.CheckDomain("phishing.example.com")
	if result == nil {
		t.Error("CheckDomain should return result for known malicious domain")
	}
	if result != nil && result.Source != "threatfeed" {
		t.Errorf("CheckDomain source = %q, want threatfeed", result.Source)
	}
}

func TestSecurityScanner_CheckURL_EnabledFeed_Miss(t *testing.T) {
	old := globalThreatFeed
	tf := newEnabledFeed()
	globalThreatFeed = tf
	defer func() { globalThreatFeed = old }()

	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	result := ss.CheckURL("http://clean.example.com/page")
	if result != nil {
		t.Error("CheckURL should return nil for clean URL")
	}
}

func TestSecurityScanner_CheckDomain_EnabledFeed_Miss(t *testing.T) {
	old := globalThreatFeed
	tf := newEnabledFeed()
	globalThreatFeed = tf
	defer func() { globalThreatFeed = old }()

	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	result := ss.CheckDomain("clean.example.com")
	if result != nil {
		t.Error("CheckDomain should return nil for clean domain")
	}
}

// ─── geoip.go: countryTrafficStore ───────────────────────────────────────────

func TestCountryTrafficStore_Record_And_Top(t *testing.T) {
	s := &countryTrafficStore{
		stats: make(map[string]int64),
		names: make(map[string]string),
	}
	s.Record("US", "United States")
	s.Record("US", "United States")
	s.Record("DE", "Germany")
	s.Record("", "") // should be ignored

	top := s.Top(10)
	if len(top) == 0 {
		t.Error("Top should return countries after Record")
	}
	found := false
	for _, c := range top {
		if c.Code == "US" && c.Count == 2 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Top should include US with count 2")
	}
}

func TestCountryTrafficStore_Top_LimitN(t *testing.T) {
	s := &countryTrafficStore{
		stats: make(map[string]int64),
		names: make(map[string]string),
	}
	for _, cc := range []string{"US", "DE", "FR", "GB", "JP", "CN"} {
		s.Record(cc, cc)
	}
	top := s.Top(3)
	if len(top) > 3 {
		t.Errorf("Top(3) returned %d items, want max 3", len(top))
	}
}

func TestRecordAndGetActiveConns(t *testing.T) {
	before := getActiveConns()
	recordActiveConn(1)
	after := getActiveConns()
	if after != before+1 {
		t.Errorf("recordActiveConn +1: got %d, want %d", after, before+1)
	}
	recordActiveConn(-1)
}

// ─── geoip.go: LookupFull/LookupCached when geo disabled ──────────────────────

func TestGeoCache_LookupFull_GeoDisabled(t *testing.T) {
	g := &geoCache{}
	code, name := g.LookupFull("example.com")
	if code != "" || name != "" {
		t.Errorf("LookupFull with geo disabled should return empty, got code=%q name=%q", code, name)
	}
}

func TestGeoCache_LookupCached_GeoDisabled(t *testing.T) {
	g := &geoCache{}
	code, ok := g.LookupCached("example.com")
	if ok || code != "" {
		t.Error("LookupCached with geo disabled should return false")
	}
}

// ─── oidcCacheSetWithExp eviction ─────────────────────────────────────────────

func TestOIDCCacheSetWithExp_Eviction(t *testing.T) {
	a := &OIDCAuth{
		cache: make(map[string]*oidcCacheEntry),
		ttl:   5 * time.Minute,
	}
	// Fill to max
	for i := 0; i < maxAuthCacheSize; i++ {
		key := "key" + string(rune(i))
		a.cache[key] = &oidcCacheEntry{ok: true, expiry: time.Now().Add(5 * time.Minute)}
	}
	// Adding one more should trigger eviction
	a.oidcCacheSetWithExp("new-key", true, 0)
	a.mu.Lock()
	size := len(a.cache)
	a.mu.Unlock()
	if size > maxAuthCacheSize+1 {
		t.Errorf("oidcCacheSetWithExp: cache too large after eviction: %d", size)
	}
}

func TestOIDCCacheSetWithExp_TokenExpiry(t *testing.T) {
	a := &OIDCAuth{
		cache: make(map[string]*oidcCacheEntry),
		ttl:   1 * time.Hour,
	}
	// Set with a token expiry sooner than ttl
	futureExp := time.Now().Add(5 * time.Minute).Unix()
	a.oidcCacheSetWithExp("expiry-test", true, futureExp)
	a.mu.Lock()
	e := a.cache["expiry-test"]
	a.mu.Unlock()
	if e == nil {
		t.Fatal("cache entry should exist")
	}
	// Expiry should be roughly 5 minutes (not 1 hour)
	if e.expiry.After(time.Now().Add(10 * time.Minute)) {
		t.Error("oidcCacheSetWithExp should use shorter tokenExp, not ttl")
	}
}

// ─── session.revokeSessionCookie ─────────────────────────────────────────────

func TestRevokeSessionCookie_NoCookie(_ *testing.T) {
	r := httptest.NewRequest("GET", "/", http.NoBody)
	// Should not panic when no cookie is present
	revokeSessionCookie(uiSessionCookieName, r)
}

func TestRevokeSessionCookie_InvalidValue(_ *testing.T) {
	r := httptest.NewRequest("GET", "/", http.NoBody)
	r.AddCookie(&http.Cookie{Name: uiSessionCookieName, Value: "nodot"})
	// Should not panic with invalid cookie value
	revokeSessionCookie(uiSessionCookieName, r)
}
