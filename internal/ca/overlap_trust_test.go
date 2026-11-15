package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"
)

// nearExpiryManager returns a Manager whose Root CA is inside the 30-day
// rotation window, plus that CA's certificate.
func nearExpiryManager(t *testing.T) (*Manager, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Culvert"}, CommonName: "Culvert Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
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
	cm := New()
	cm.SetCAForTest(cert, key)
	return cm, cert
}

// verifyServedChain verifies what a TLS client would: the served leaf, with the
// rest of the served chain as untrusted intermediates, against roots.
func verifyServedChain(t *testing.T, served *tls.Certificate, roots *x509.CertPool, host string) error {
	t.Helper()
	inter := x509.NewCertPool()
	for _, der := range served.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse served chain cert: %v", err)
		}
		inter.AddCert(c)
	}
	_, err := served.Leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: host})
	return err
}

// TestDualCAOverlap_ClientTrustingOnlyOldRootValidates pins the documented
// overlap contract (docs/operator/root-ca-expiry.md §5): after an automatic
// rotation, a client that still trusts only the OLD root keeps validating
// inspected connections until the old root expires.
func TestDualCAOverlap_ClientTrustingOnlyOldRootValidates(t *testing.T) {
	cm, oldRoot := nearExpiryManager(t)
	if !cm.RotateIfNeeded("", "") {
		t.Fatal("near-expiry CA should trigger rotation")
	}
	const host = "overlap.example.com"
	served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}

	oldOnly := x509.NewCertPool()
	oldOnly.AddCert(oldRoot)
	if err := verifyServedChain(t, served, oldOnly, host); err != nil {
		t.Errorf("client trusting only the OLD root rejects the post-rotation leaf: %v", err)
	}

	newOnly := x509.NewCertPool()
	newOnly.AddCert(cm.CACertForTest())
	if err := verifyServedChain(t, served, newOnly, host); err != nil {
		t.Errorf("client trusting only the NEW root rejects the post-rotation leaf: %v", err)
	}
}

// TestDualCAOverlap_SurvivesRestart: the secondary certificate is in-memory
// only, so after a restart the served chain is the bare leaf. A client that
// still trusts only the old root must keep validating then too.
func TestDualCAOverlap_SurvivesRestart(t *testing.T) {
	cm, oldRoot := nearExpiryManager(t)
	bundle := filepath.Join(t.TempDir(), "ca.bundle")
	if !cm.RotateIfNeeded(bundle, "") {
		t.Fatal("near-expiry CA should trigger rotation")
	}
	restarted := New()
	if err := restarted.LoadCA(bundle, ""); err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	const host = "restart.example.com"
	served, err := restarted.GetCert(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatalf("GetCert: %v", err)
	}
	oldOnly := x509.NewCertPool()
	oldOnly.AddCert(oldRoot)
	if err := verifyServedChain(t, served, oldOnly, host); err != nil {
		t.Errorf("after restart, client trusting only the OLD root rejects the leaf: %v", err)
	}
}
