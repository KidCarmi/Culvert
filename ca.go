package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"time"
)

// CertManager manages the Root CA used for SSL inspection (MITM).
// It generates leaf certificates on-the-fly and caches them.
type CertManager struct {
	mu     sync.RWMutex
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	cache  map[string]*tls.Certificate
}

var certMgr = &CertManager{cache: map[string]*tls.Certificate{}}

// InitCA generates an in-memory Root CA key pair. Call once at startup.
func (cm *CertManager) InitCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ProxyShield"},
			CommonName:   "ProxyShield Root CA",
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}
	cm.mu.Lock()
	cm.caCert = cert
	cm.caKey = key
	cm.mu.Unlock()
	return nil
}

// CACertPEM returns the Root CA certificate encoded as PEM (for browser import).
func (cm *CertManager) CACertPEM() []byte {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.caCert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw})
}

// Ready returns true once the Root CA has been initialised.
func (cm *CertManager) Ready() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.caCert != nil
}

// GetCert is a tls.Config.GetCertificate callback that returns a dynamically
// signed certificate for the requested ServerName. Results are cached.
func (cm *CertManager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "unknown"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	cm.mu.RLock()
	if c, ok := cm.cache[host]; ok {
		cm.mu.RUnlock()
		return c, nil
	}
	cm.mu.RUnlock()

	cert, err := cm.signLeaf(host)
	if err != nil {
		return nil, err
	}
	cm.mu.Lock()
	cm.cache[host] = cert
	cm.mu.Unlock()
	return cert, nil
}

// signLeaf creates and signs a leaf TLS certificate for the given hostname.
func (cm *CertManager) signLeaf(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	caCert := cm.caCert
	caKey := cm.caKey
	cm.mu.RUnlock()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}
