package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // reproduces the RFC 5280 method-1 key identifier Go <= 1.24 emitted; not a security use
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// nearExpiryManagerWithKeyID is nearExpiryManager with the root's Subject Key
// Identifier chosen by the caller instead of derived by this toolchain.
func nearExpiryManagerWithKeyID(t *testing.T, keyID func(pub []byte) []byte) (*Manager, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("public key bytes: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Culvert"}, CommonName: "Culvert Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          keyID(pub.Bytes()),
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

// TestRenewal_LeafKeyIDStillNamesOldRoot: the overlap contract is that a client
// trusting only the OLD root keeps validating after an automatic renewal.
// TestDualCAOverlap_ClientTrustingOnlyOldRootValidates checks that with Go's
// verifier, which treats the leaf's Authority Key Identifier as a hint. OpenSSL
// does not: a leaf whose AKI differs from the candidate issuer's Subject Key
// Identifier is not issued by it (X509_V_ERR_AKID_SKID_MISMATCH), and the
// handshake fails with "unable to get local issuer certificate".
//
// Renewal keeps the key, but the renewed root's SKI was left for
// x509.CreateCertificate to derive, and that derivation is the toolchain's, not
// the key's: Go <= 1.24 used SHA-1, Go >= 1.25 uses truncated SHA-256. So a root
// issued by an older build (or any managed root whose SKI is not today's
// derivation) is renewed under a DIFFERENT key identifier, every new leaf names
// that one, and curl/Python/git clients that have only the old root reject every
// inspected connection for the whole overlap window.
func TestRenewal_LeafKeyIDStillNamesOldRoot(t *testing.T) {
	cases := map[string]func(pub []byte) []byte{
		// What a Culvert binary built with Go <= 1.24 wrote into its root.
		"sha1 key id from an older toolchain": func(pub []byte) []byte {
			h := sha1.Sum(pub) //nolint:gosec // see import
			return h[:]
		},
		"arbitrary key id": func([]byte) []byte { return []byte{0xC0, 0xFF, 0xEE, 0x01} },
	}
	for name, keyID := range cases {
		t.Run(name, func(t *testing.T) {
			cm, oldRoot := nearExpiryManagerWithKeyID(t, keyID)
			if !cm.RotateIfNeeded("", "") {
				t.Fatal("near-expiry CA should trigger rotation")
			}
			if got := cm.CACertForTest().SubjectKeyId; !bytes.Equal(got, oldRoot.SubjectKeyId) {
				t.Errorf("renewed root SKI = %x, want the old root's %x (same key, same identifier)", got, oldRoot.SubjectKeyId)
			}
			served, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "keyid.example.com"})
			if err != nil {
				t.Fatalf("GetCert: %v", err)
			}
			if !bytes.Equal(served.Leaf.AuthorityKeyId, oldRoot.SubjectKeyId) {
				t.Errorf("post-renewal leaf AKI = %x, old root SKI = %x: an AKI-enforcing client (OpenSSL) holding only the old root rejects this leaf",
					served.Leaf.AuthorityKeyId, oldRoot.SubjectKeyId)
			}
		})
	}
}
