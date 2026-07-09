package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestOCSPChecker_EnableDisable(t *testing.T) {
	oc := New()
	if oc.Enabled() {
		t.Fatal("should start disabled")
	}
	oc.Enable()
	if !oc.Enabled() {
		t.Fatal("should be enabled after Enable()")
	}
}

func TestOCSPChecker_VerifyDisabledReturnsNil(t *testing.T) {
	oc := New()
	// Disabled: should return nil even with garbage input.
	err := oc.VerifyPeerCertificate([][]byte{{1, 2, 3}}, nil)
	if err != nil {
		t.Fatalf("disabled checker should return nil, got %v", err)
	}
}

func TestOCSPChecker_VerifyEmptyCerts(t *testing.T) {
	oc := New()
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
	oc := New()
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
	oc := New()
	oc.cache["abc"] = &cacheEntry{
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
	oc := New()
	oc.cache["revoked-serial"] = &cacheEntry{
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
	oc := New()
	oc.cache["expired"] = &cacheEntry{
		revoked:   false,
		expiresAt: time.Now().Add(-time.Hour),
	}
	_, found := oc.checkCached("expired")
	if found {
		t.Fatal("expired entry should not be found")
	}
}

func TestOCSPChecker_CacheResult(t *testing.T) {
	oc := New()
	oc.cacheResult("serial-123", true, cacheTTL)
	if len(oc.cache) != 1 {
		t.Fatal("cache should have 1 entry")
	}
	e := oc.cache["serial-123"]
	if !e.revoked {
		t.Fatal("should be marked revoked")
	}
}

// makeLeafWithResponder builds an issuer + leaf pair whose leaf lists the
// given OCSP responder URL. Returns the DER bytes (leaf first, issuer
// second — the rawCerts wire order).
func makeLeafWithResponder(t *testing.T, responderURL string) [][]byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "chaos-issuer"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "chaos-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		OCSPServer:   []string{responderURL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{leafDER, issuerDER}
}

// unreachableResponderURL returns a URL on a port that is guaranteed closed
// (bound then released), so responder queries fail fast with no network.
func unreachableResponderURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

// TestOCSPChecker_IndeterminateVerdictShortTTL is the CHAOS-04 regression:
// an all-responders-unreachable verdict must fail closed (error returned)
// but be cached on indeterminateTTL, not the 1h cacheTTL — otherwise a
// seconds-long responder blip hard-fails all TLS to the affected upstream
// for an hour after the responder recovers.
func TestOCSPChecker_IndeterminateVerdictShortTTL(t *testing.T) {
	oc := New()
	oc.Enable()
	rawCerts := makeLeafWithResponder(t, unreachableResponderURL(t))

	if err := oc.VerifyPeerCertificate(rawCerts, nil); err == nil {
		t.Fatal("unreachable responder must fail closed (want error, got nil)")
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := oc.cache[leaf.SerialNumber.Text(16)]
	if !ok {
		t.Fatal("indeterminate verdict should be cached")
	}
	if !entry.revoked {
		t.Fatal("indeterminate verdict must remain fail-closed (revoked=true)")
	}
	remaining := time.Until(entry.expiresAt)
	if remaining > indeterminateTTL {
		t.Fatalf("indeterminate verdict cached for %v — want <= %v (CHAOS-04 outage amplification)", remaining, indeterminateTTL)
	}
	if remaining <= 0 {
		t.Fatal("indeterminate verdict should still be cached for the short TTL")
	}

	// Within the short TTL the cached fail-closed verdict still rejects.
	if err := oc.VerifyPeerCertificate(rawCerts, nil); err == nil {
		t.Fatal("cached indeterminate verdict must still fail closed within its TTL")
	}

	// Once the short TTL lapses, the checker re-queries instead of serving
	// the stale outage verdict (simulated by expiring the entry).
	oc.cache[leaf.SerialNumber.Text(16)].expiresAt = time.Now().Add(-time.Second)
	if _, found := oc.checkCached(leaf.SerialNumber.Text(16)); found {
		t.Fatal("expired indeterminate verdict must not be served from cache")
	}
}

func TestOCSPChecker_CacheEviction(t *testing.T) {
	oc := New()
	// Fill to max.
	for i := 0; i < cacheMaxSize; i++ {
		oc.cache[big.NewInt(int64(i)).Text(16)] = &cacheEntry{
			expiresAt: time.Now().Add(time.Hour),
		}
	}
	// Adding one more should trigger eviction.
	oc.cacheResult("new-serial", false, cacheTTL)
	if len(oc.cache) > cacheMaxSize {
		t.Fatalf("cache size = %d, should be <= %d", len(oc.cache), cacheMaxSize)
	}
}

func TestOCSPChecker_CleanupCache(t *testing.T) {
	oc := New()
	oc.cache["fresh"] = &cacheEntry{expiresAt: time.Now().Add(time.Hour)}
	oc.cache["stale"] = &cacheEntry{expiresAt: time.Now().Add(-time.Hour)}
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

func TestChecker_CacheLen(t *testing.T) {
	oc := New()
	oc.cache["a"] = &cacheEntry{}
	oc.cache["b"] = &cacheEntry{}
	if got := oc.CacheLen(); got != 2 {
		t.Errorf("CacheLen() = %d, want 2", got)
	}
}
