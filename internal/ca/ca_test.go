package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestSignLeaf_ValidCert exercises the unexported leaf-signing path directly
// (moved from package main's ca_test.go with the ADR-0002 extraction). The
// assembled decrypt→sign→re-encrypt data path is covered end-to-end by
// package main's mitm_inspect_e2e_test.go.
func TestSignLeaf_ValidCert(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	cert, err := cm.signLeaf("example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if cert == nil {
		t.Fatal("signLeaf returned nil cert")
	}
}

// TestSignLeaf_SharedKeyAndChainVerify pins the perf-F3 invariants: every forged
// leaf reuses ONE private key, yet each leaf is still a distinct cert (unique
// serial), carries a populated Leaf, and chain-verifies against the CA. If the
// shared-key optimization ever regressed to per-leaf keys, or the DER-direct
// assembly produced an unverifiable/misbound cert, this fails.
func TestSignLeaf_SharedKeyAndChainVerify(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cm.CACertPEM()) {
		t.Fatal("append CA PEM")
	}

	a, err := cm.signLeaf("a.example.com")
	if err != nil {
		t.Fatalf("signLeaf a: %v", err)
	}
	b, err := cm.signLeaf("b.example.com")
	if err != nil {
		t.Fatalf("signLeaf b: %v", err)
	}

	// Shared key: both leaves must hold the SAME private key pointer.
	ka, ok := a.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("leaf a key type = %T, want *ecdsa.PrivateKey", a.PrivateKey)
	}
	kb, _ := b.PrivateKey.(*ecdsa.PrivateKey)
	if ka != kb {
		t.Fatal("F3 regression: forged leaves do not share one private key")
	}

	// Distinct certs despite the shared key (unique serials).
	if a.Leaf == nil || b.Leaf == nil {
		t.Fatal("Leaf not populated — GetCert TTL check relies on Leaf.NotAfter")
	}
	if a.Leaf.SerialNumber.Cmp(b.Leaf.SerialNumber) == 0 {
		t.Fatal("two leaves shared a serial number — not unique")
	}

	// Each leaf still chain-verifies against the CA, and its public key
	// corresponds to the shared private key (misbinding would break the TLS
	// handshake even though the chain verifies).
	for name, c := range map[string]struct {
		leaf *x509.Certificate
		host string
	}{"a": {a.Leaf, "a.example.com"}, "b": {b.Leaf, "b.example.com"}} {
		if _, err := c.leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: c.host}); err != nil {
			t.Fatalf("leaf %s failed chain verify: %v", name, err)
		}
		pub, ok := c.leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(&ka.PublicKey) {
			t.Fatalf("leaf %s public key does not match the shared private key", name)
		}
	}
}

// TestSignLeaf_DualCAOverlapChain covers the dual-CA overlap branch of the F3
// DER-direct assembly (previously untested): when a secondary CA is active, the
// leaf's Certificate chain must carry [leaf, secondaryCA-DER], and the leaf must
// verify against the primary (new) CA. Only the chain assembly is asserted here
// — the broader dual-CA trust semantics are pre-existing and out of scope.
func TestSignLeaf_DualCAOverlapChain(t *testing.T) {
	cm := New()

	// Seed a near-expiry CA so RotateIfNeeded rolls to a new primary and keeps
	// the old one as the active secondary (dual-CA overlap).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expiring CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 24 * time.Hour), // < 30-day overlap → triggers rotate
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	oldDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create old CA: %v", err)
	}
	oldCert, err := x509.ParseCertificate(oldDER)
	if err != nil {
		t.Fatalf("parse old CA: %v", err)
	}
	cm.SetCAForTest(oldCert, key)

	if !cm.RotateIfNeeded("", "") {
		t.Fatal("near-expiry CA should trigger rotation")
	}
	if !cm.SecondaryCAActive() {
		t.Fatal("expected an active secondary CA after rotation")
	}

	leaf, err := cm.signLeaf("dual.example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if len(leaf.Certificate) != 2 {
		t.Fatalf("dual-CA leaf chain = %d certs, want 2 (leaf + secondary CA)", len(leaf.Certificate))
	}
	cm.mu.RLock()
	secRaw := cm.secondaryCACert.Raw
	cm.mu.RUnlock()
	if !bytes.Equal(leaf.Certificate[1], secRaw) {
		t.Fatal("chain[1] is not the secondary CA DER")
	}

	// The leaf (signed by the new primary CA) verifies against the primary root.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cm.CACertPEM()) {
		t.Fatal("append primary CA PEM")
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "dual.example.com"}); err != nil {
		t.Fatalf("leaf failed verify against primary CA: %v", err)
	}
}
