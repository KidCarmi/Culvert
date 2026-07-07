package ocsp

// Chaos regression (CHAOS-04): an all-responders-unreachable verdict must stay
// fail-closed but must NOT be cached like a confirmed revocation for the full
// 1h TTL — otherwise a seconds-long responder blip keeps hard-failing TLS to
// the affected upstream for an hour after the responders recover.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// makeChainWithOCSPServer builds a CA + leaf whose AIA points at an
// unreachable OCSP responder, returning the raw DER chain (leaf, issuer).
func makeChainWithOCSPServer(t *testing.T, responderURL string) [][]byte {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "chaos-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "chaos-test-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		OCSPServer:   []string{responderURL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{leafDER, caDER}
}

func TestOCSPChecker_UnreachableResponderFailsClosed(t *testing.T) {
	oc := New()
	oc.Enable()

	// Reserved TEST-NET-1 address: the 5s query timeout bounds the dial.
	rawCerts := makeChainWithOCSPServer(t, "http://192.0.2.1:1/ocsp")

	err := oc.VerifyPeerCertificate(rawCerts, nil)
	if err == nil {
		t.Fatal("expected fail-closed error when all responders are unreachable")
	}
	if !strings.Contains(err.Error(), "indeterminate") {
		t.Fatalf("error should identify the verdict as indeterminate, got: %v", err)
	}
}

func TestOCSPChecker_IndeterminateVerdictUsesShortTTL(t *testing.T) {
	oc := New()
	oc.Enable()

	rawCerts := makeChainWithOCSPServer(t, "http://192.0.2.1:1/ocsp")
	if err := oc.VerifyPeerCertificate(rawCerts, nil); err == nil {
		t.Fatal("expected fail-closed error")
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		t.Fatal(err)
	}
	serialHex := leaf.SerialNumber.Text(16)

	oc.mu.RLock()
	entry, ok := oc.cache[serialHex]
	oc.mu.RUnlock()
	if !ok {
		t.Fatal("indeterminate verdict should be cached")
	}
	if !entry.revoked {
		t.Fatal("indeterminate verdict must stay fail-closed (cached as revoked)")
	}
	// The outage verdict must expire on the short indeterminate TTL, not the
	// full revocation TTL — allow generous slack for slow test machines.
	remaining := time.Until(entry.expiresAt)
	if remaining > indeterminateCacheTTL {
		t.Fatalf("indeterminate verdict cached for %v; want ≤ %v (not the %v revocation TTL)",
			remaining, indeterminateCacheTTL, cacheTTL)
	}
}

func TestOCSPChecker_CacheResultHonorsTTL(t *testing.T) {
	oc := New()
	oc.cacheResult("short-ttl", true, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	if _, found := oc.checkCached("short-ttl"); found {
		t.Fatal("entry cached with a short TTL should have expired")
	}
}
