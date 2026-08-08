package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// CHAOS-30 — the inspection Root CA at and past expiry.
//
// signLeaf is the MITM trust chokepoint. Before this gate it read caCert/caKey
// and signed unconditionally, so an expired Root CA kept minting leaves that
// every client rejects on the ISSUER's dates — a fleet-wide inspected-HTTPS
// outage visible only on the client side. These tests pin the fail-closed
// refusal, the "a leaf must never outlive its issuer" clamp, and the counter
// that makes both observable.

// seedCA installs a self-signed CA with the given validity window and returns
// its key, so tests can place the CA anywhere relative to now.
func seedCA(t *testing.T, cm *Manager, notBefore, notAfter time.Time) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "CHAOS-30 CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	cm.SetCAForTest(cert, key)
	return key
}

// TestSignLeaf_ExpiredCARefusesToSign is the CHAOS-30 fail-closed gate. Against
// the pre-fix engine this test FAILS: signLeaf returned a perfectly-formed
// certificate signed by a dead CA.
func TestSignLeaf_ExpiredCARefusesToSign(t *testing.T) {
	cm := New()
	seedCA(t, cm, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Minute))

	cert, err := cm.signLeaf("expired.example.com")
	if err == nil {
		t.Fatal("signLeaf issued a leaf from an EXPIRED Root CA (fail-open); want ErrCAExpired")
	}
	if !errors.Is(err, ErrCAExpired) {
		t.Fatalf("signLeaf error = %v, want ErrCAExpired", err)
	}
	if cert != nil {
		t.Fatal("signLeaf returned a certificate alongside the refusal")
	}
	if got := cm.SignFailures(); got != 1 {
		t.Fatalf("SignFailures = %d, want 1 — the refusal must be counted, not silent", got)
	}
}

// TestGetCert_ExpiredCASurfacesTheRefusal proves the refusal reaches the
// tls.Config.GetCertificate callback (the handshake fails at the proxy, with a
// server-side error to log/alert on) instead of completing a handshake with a
// certificate the client will reject.
func TestGetCert_ExpiredCASurfacesTheRefusal(t *testing.T) {
	cm := New()
	seedCA(t, cm, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Minute))

	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "expired.example.com"}); !errors.Is(err, ErrCAExpired) {
		t.Fatalf("GetCert error = %v, want ErrCAExpired", err)
	}
	if cm.CertCacheLen() != 0 {
		t.Fatal("a refused sign must not populate the leaf cache")
	}
}

// TestSignLeaf_NoCARefusesToSign covers the nil-CA branch. Ready() gates the
// inspect path, but signLeaf is the chokepoint and must not depend on a caller
// having checked: pre-fix, a nil caCert/caKey reached x509.CreateCertificate.
func TestSignLeaf_NoCARefusesToSign(t *testing.T) {
	cm := New()
	if _, err := cm.signLeaf("nocA.example.com"); !errors.Is(err, ErrCANotReady) {
		t.Fatalf("signLeaf with no CA: error = %v, want ErrCANotReady", err)
	}
	if got := cm.SignFailures(); got != 1 {
		t.Fatalf("SignFailures = %d, want 1", got)
	}
}

// TestSignLeaf_NeverOutlivesIssuer pins the clamp. Pre-fix the leaf NotAfter
// was unconditionally now+24h, so in the CA's final day every leaf claimed
// validity past its own issuer — and GetCert's cache (which checks the LEAF's
// expiry) would keep serving it for up to certCacheTTL after the CA died.
func TestSignLeaf_NeverOutlivesIssuer(t *testing.T) {
	cm := New()
	caExpiry := time.Now().Add(90 * time.Minute) // < leafLifetime
	seedCA(t, cm, time.Now().Add(-time.Hour), caExpiry)

	leaf, err := cm.signLeaf("clamped.example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if leaf.Leaf.NotAfter.After(cm.CAExpiry()) {
		t.Fatalf("leaf NotAfter %s outlives issuer NotAfter %s",
			leaf.Leaf.NotAfter.UTC(), cm.CAExpiry().UTC())
	}
	// The clamp must not truncate a leaf when the CA has plenty of life left.
	cm2 := New()
	seedCA(t, cm2, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	long, err := cm2.signLeaf("normal.example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if d := time.Until(long.Leaf.NotAfter); d < leafLifetime-time.Minute {
		t.Fatalf("healthy-CA leaf lifetime = %s, want ~%s (clamp over-applied)", d, leafLifetime)
	}
}

// TestSignLeaf_HealthyCAUnaffected is the no-regression half: with a healthy CA
// the gate and clamp change nothing observable about the issued leaf.
func TestSignLeaf_HealthyCAUnaffected(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	leaf, err := cm.signLeaf("healthy.example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cm.CACertPEM()) {
		t.Fatal("append CA PEM")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "healthy.example.com"}); err != nil {
		t.Fatalf("healthy leaf failed verify: %v", err)
	}
	if got := cm.SignFailures(); got != 0 {
		t.Fatalf("SignFailures = %d on the healthy path, want 0", got)
	}
}

// TestCACertInfo_ExpiryIsExplicit pins the reporting contract: "expired" is a
// state the CA surface states outright rather than something callers re-derive
// from a date-truncated notAfter string.
func TestCACertInfo_ExpiryIsExplicit(t *testing.T) {
	cm := New()
	seedCA(t, cm, time.Now().Add(-2*time.Hour), time.Now().Add(-25*time.Hour))
	info := cm.CACertInfo()
	if info["expired"] != true {
		t.Fatalf("CACertInfo expired = %v, want true", info["expired"])
	}
	if d, _ := info["expiresInDays"].(int); d >= 0 {
		t.Fatalf("CACertInfo expiresInDays = %d, want negative for an expired CA", d)
	}

	cm2 := New()
	if err := cm2.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	info2 := cm2.CACertInfo()
	if info2["expired"] != false {
		t.Fatalf("CACertInfo expired = %v on a fresh CA, want false", info2["expired"])
	}
	if d, _ := info2["expiresInDays"].(int); d <= 0 {
		t.Fatalf("CACertInfo expiresInDays = %d on a fresh CA, want positive", d)
	}
}
