package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// BenchmarkSignLeaf measures the perf-F3 leaf-signing path: a shared leaf key
// (no per-leaf P-256 keygen) and a DER-direct tls.Certificate (no PEM
// round-trip / X509KeyPair re-parse).
func BenchmarkSignLeaf(b *testing.B) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		b.Fatalf("InitCA: %v", err)
	}
	_, _ = cm.sharedLeafKey() // warm the shared key so the loop measures steady state
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cm.signLeaf("bench.example.com"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignLeaf_Baseline replicates the pre-F3 path (fresh keygen per leaf +
// MarshalECPrivateKey + PEM encode + tls.X509KeyPair) against the same CA, so
// the delta vs BenchmarkSignLeaf is purely the F3 win.
func BenchmarkSignLeaf_Baseline(b *testing.B) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		b.Fatalf("InitCA: %v", err)
	}
	cm.mu.RLock()
	caCert, caKey := cm.caCert, cm.caKey
	cm.mu.RUnlock()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			b.Fatal(err)
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			b.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: "bench.example.com"},
			NotBefore:    time.Now().Add(-5 * time.Minute),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     []string{"bench.example.com"},
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			b.Fatal(err)
		}
		keyDER, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			b.Fatal(err)
		}
		chainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		if _, err := tls.X509KeyPair(chainPEM, keyPEM); err != nil {
			b.Fatal(err)
		}
	}
}
