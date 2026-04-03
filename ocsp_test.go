package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func TestOCSPChecker_EnableDisable(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	if oc.Enabled() {
		t.Fatal("should start disabled")
	}
	oc.Enable()
	if !oc.Enabled() {
		t.Fatal("should be enabled after Enable()")
	}
}

func TestOCSPChecker_VerifyDisabledReturnsNil(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	// Disabled: should return nil even with garbage input.
	err := oc.VerifyPeerCertificate([][]byte{{1, 2, 3}}, nil)
	if err != nil {
		t.Fatalf("disabled checker should return nil, got %v", err)
	}
}

func TestOCSPChecker_VerifyEmptyCerts(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.Enable()
	err := oc.VerifyPeerCertificate(nil, nil)
	if err != nil {
		t.Fatalf("empty certs should return nil, got %v", err)
	}
	err = oc.VerifyPeerCertificate([][]byte{}, nil)
	if err != nil {
		t.Fatalf("empty slice should return nil, got %v", err)
	}
}

func TestOCSPChecker_VerifyNoIssuerReturnsNil(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.Enable()

	// Generate a self-signed cert (no issuer in chain).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	// No verified chains, only one raw cert → no issuer found → nil.
	err := oc.VerifyPeerCertificate([][]byte{certDER}, nil)
	if err != nil {
		t.Fatalf("no issuer should fail open, got %v", err)
	}
}

func TestOCSPChecker_CacheHitNotRevoked(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.cache["abc"] = &ocspCacheEntry{
		revoked:   false,
		expiresAt: time.Now().Add(time.Hour),
	}
	revoked, found := oc.checkCached("abc")
	if !found {
		t.Fatal("should find cached entry")
	}
	if revoked {
		t.Fatal("should not be revoked")
	}
}

func TestOCSPChecker_CacheHitRevoked(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.cache["revoked-serial"] = &ocspCacheEntry{
		revoked:   true,
		expiresAt: time.Now().Add(time.Hour),
	}
	revoked, found := oc.checkCached("revoked-serial")
	if !found {
		t.Fatal("should find cached entry")
	}
	if !revoked {
		t.Fatal("should be revoked")
	}
}

func TestOCSPChecker_CacheExpired(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.cache["expired"] = &ocspCacheEntry{
		revoked:   false,
		expiresAt: time.Now().Add(-time.Hour),
	}
	_, found := oc.checkCached("expired")
	if found {
		t.Fatal("expired entry should not be found")
	}
}

func TestOCSPChecker_CacheResult(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.cacheResult("serial-123", true)
	if len(oc.cache) != 1 {
		t.Fatal("cache should have 1 entry")
	}
	e := oc.cache["serial-123"]
	if !e.revoked {
		t.Fatal("should be marked revoked")
	}
}

func TestOCSPChecker_CacheEviction(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	// Fill to max.
	for i := 0; i < ocspCacheMaxSize; i++ {
		oc.cache[big.NewInt(int64(i)).Text(16)] = &ocspCacheEntry{
			expiresAt: time.Now().Add(time.Hour),
		}
	}
	// Adding one more should trigger eviction.
	oc.cacheResult("new-serial", false)
	if len(oc.cache) > ocspCacheMaxSize {
		t.Fatalf("cache size = %d, should be <= %d", len(oc.cache), ocspCacheMaxSize)
	}
}

func TestOCSPChecker_CleanupCache(t *testing.T) {
	oc := &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}
	oc.cache["fresh"] = &ocspCacheEntry{expiresAt: time.Now().Add(time.Hour)}
	oc.cache["stale"] = &ocspCacheEntry{expiresAt: time.Now().Add(-time.Hour)}
	oc.CleanupCache()
	if len(oc.cache) != 1 {
		t.Fatalf("cache should have 1 entry after cleanup, got %d", len(oc.cache))
	}
	if _, ok := oc.cache["fresh"]; !ok {
		t.Fatal("fresh entry should remain")
	}
}

func TestResolveIssuer_FromVerifiedChains(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "issuer"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &key.PublicKey, key)
	issuer, _ := x509.ParseCertificate(issuerDER)
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(leafDER)

	chains := [][]*x509.Certificate{{leaf, issuer}}
	got := resolveIssuer(nil, chains)
	if got == nil {
		t.Fatal("should find issuer from verified chains")
	}
	if got.Subject.CommonName != "issuer" {
		t.Fatalf("issuer CN = %q, want issuer", got.Subject.CommonName)
	}
}

func TestResolveIssuer_FromRawCerts(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ca"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	got := resolveIssuer([][]byte{{0x30}, certDER}, nil) // first cert is garbage leaf
	if got == nil {
		t.Fatal("should parse issuer from rawCerts[1]")
	}
}

func TestResolveIssuer_NilWhenEmpty(t *testing.T) {
	got := resolveIssuer(nil, nil)
	if got != nil {
		t.Fatal("should return nil for empty input")
	}
	got = resolveIssuer([][]byte{{1}}, nil)
	if got != nil {
		t.Fatal("should return nil when only one raw cert")
	}
}

func TestConfigureTransportOCSP(t *testing.T) {
	transport := &http.Transport{}
	ConfigureTransportOCSP(transport)
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should be set")
	}
	if transport.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate should be set")
	}
	if transport.TLSClientConfig.VerifyConnection == nil {
		t.Fatal("VerifyConnection should be set")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("MinVersion should be TLS 1.2")
	}
}

func TestConfigureTransportOCSP_ExistingConfig(t *testing.T) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	ConfigureTransportOCSP(transport)
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("should preserve existing MinVersion")
	}
	if transport.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate should be set")
	}
}
