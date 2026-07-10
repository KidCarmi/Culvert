package ocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cryptoocsp "golang.org/x/crypto/ocsp"
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
	revoked, _, found := oc.checkCached("abc")
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
	revoked, _, found := oc.checkCached("revoked-serial")
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
	_, _, found := oc.checkCached("expired")
	if found {
		t.Fatal("expired entry should not be found")
	}
}

func TestOCSPChecker_CacheResult(t *testing.T) {
	oc := New()
	oc.cacheResult("serial-123", true, false)
	if len(oc.cache) != 1 {
		t.Fatal("cache should have 1 entry")
	}
	e := oc.cache["serial-123"]
	if !e.revoked {
		t.Fatal("should be marked revoked")
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
	oc.cacheResult("new-serial", false, false)
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

func TestChecker_CountersDefaultZero(t *testing.T) {
	oc := New()
	if oc.FailClosedTotal() != 0 {
		t.Errorf("FailClosedTotal() = %d, want 0", oc.FailClosedTotal())
	}
	if oc.RevokedTotal() != 0 {
		t.Errorf("RevokedTotal() = %d, want 0", oc.RevokedTotal())
	}
	if !oc.LastFailClosedAt().IsZero() {
		t.Errorf("LastFailClosedAt() = %v, want zero time", oc.LastFailClosedAt())
	}
}

// buildLeafWithResponder generates an issuer + leaf pair where the leaf's
// AIA extension points at responderURL, for exercising checkResponders.
func buildLeafWithResponder(t *testing.T, responderURL string) (leaf, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) {
	t.Helper()
	issuerKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-issuer"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create issuer cert: %v", err)
	}
	issuer, err = x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("parse issuer cert: %v", err)
	}

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		OCSPServer:   []string{responderURL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, issuerTmpl, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return leaf, issuer, issuerKey
}

func TestOCSPChecker_CheckRespondersFailClosedIncrementsCounters(t *testing.T) {
	// Port 1 is a reserved, never-listening TCP port — the connection is
	// refused immediately instead of timing out, keeping the test fast.
	leaf, issuer, _ := buildLeafWithResponder(t, "http://127.0.0.1:1")

	oc := New()
	before := time.Now()
	if revoked, _ := oc.checkResponders(leaf, issuer); !revoked {
		t.Fatal("checkResponders should fail-closed (return true) when every responder is unreachable")
	}
	if got := oc.FailClosedTotal(); got != 1 {
		t.Errorf("FailClosedTotal() = %d, want 1", got)
	}
	if got := oc.RevokedTotal(); got != 0 {
		t.Errorf("RevokedTotal() = %d, want 0 (no responder ever confirmed revocation)", got)
	}
	if last := oc.LastFailClosedAt(); last.Before(before.Add(-time.Second)) {
		t.Errorf("LastFailClosedAt() = %v, want a time around %v", last, before)
	}
}

func TestOCSPChecker_CachedFailClosedKeepsCounterCurrent(t *testing.T) {
	// A sustained outage: the first handshake fails closed and caches the
	// verdict; every later handshake for the same serial hits the cache and
	// short-circuits checkResponders. The fail-closed counter and
	// last-occurrence must still advance, or the OCSP panel would show only
	// the first cache miss and under-report the ongoing outage (Codex P2 on
	// PR #581).
	leaf, issuer, _ := buildLeafWithResponder(t, "http://127.0.0.1:1")
	oc := New()
	oc.Enable()

	rawCerts := [][]byte{leaf.Raw, issuer.Raw}

	// First handshake: cache miss → fail-closed, counter = 1.
	if err := oc.VerifyPeerCertificate(rawCerts, nil); err == nil {
		t.Fatal("first handshake should fail closed (return an error)")
	}
	if got := oc.FailClosedTotal(); got != 1 {
		t.Fatalf("after first handshake FailClosedTotal() = %d, want 1", got)
	}
	firstTS := oc.LastFailClosedAt()

	// Second handshake: cache HIT (fail-closed) → counter must advance to 2,
	// and checkResponders must NOT have been consulted again (cache present).
	if got := oc.CacheLen(); got != 1 {
		t.Fatalf("expected the fail-closed verdict to be cached, CacheLen() = %d", got)
	}
	if err := oc.VerifyPeerCertificate(rawCerts, nil); err == nil {
		t.Fatal("cached fail-closed handshake should still fail closed")
	}
	if got := oc.FailClosedTotal(); got != 2 {
		t.Fatalf("cached fail-closed hit must advance the counter; FailClosedTotal() = %d, want 2", got)
	}
	if oc.LastFailClosedAt().Before(firstTS) {
		t.Fatal("cached fail-closed hit must not move last-occurrence backwards")
	}
	// A cached CONFIRMED revocation (failClosed=false) must return early
	// WITHOUT touching the fail-closed counter — only the outage path does.
	if _, failClosed, found := oc.checkCached(leaf.SerialNumber.Text(16)); !found || !failClosed {
		t.Fatal("the cached verdict for this serial must be marked fail-closed")
	}
}

func TestOCSPChecker_VerifyPeerCertificateRevokedIncrementsCounter(t *testing.T) {
	var issuerCert *x509.Certificate
	var issuerKey *ecdsa.PrivateKey
	var leafCert *x509.Certificate

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		reqBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read OCSP request: %v", err)
			return
		}
		ocspReq, err := cryptoocsp.ParseRequest(reqBytes)
		if err != nil {
			t.Errorf("parse OCSP request: %v", err)
			return
		}
		respBytes, err := cryptoocsp.CreateResponse(issuerCert, issuerCert, cryptoocsp.Response{
			Status:       cryptoocsp.Revoked,
			SerialNumber: ocspReq.SerialNumber,
			ThisUpdate:   time.Now().Add(-time.Minute),
			NextUpdate:   time.Now().Add(time.Hour),
		}, issuerKey)
		if err != nil {
			t.Errorf("create OCSP response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(respBytes)
	})

	leafCert, issuerCert, issuerKey = buildLeafWithResponder(t, srv.URL)

	oc := New()
	oc.Enable()
	err := oc.VerifyPeerCertificate([][]byte{leafCert.Raw}, [][]*x509.Certificate{{leafCert, issuerCert}})
	if err == nil {
		t.Fatal("expected revocation error, got nil")
	}
	if got := oc.RevokedTotal(); got != 1 {
		t.Errorf("RevokedTotal() = %d, want 1", got)
	}
	if got := oc.FailClosedTotal(); got != 0 {
		t.Errorf("FailClosedTotal() = %d, want 0 (responder answered)", got)
	}
}
