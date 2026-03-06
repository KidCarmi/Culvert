package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
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

// caBundle is the plaintext PEM bundle written/read from disk.
// Format: PEM(CERTIFICATE) || PEM(EC PRIVATE KEY)
type caBundle struct {
	certPEM []byte
	keyPEM  []byte
}

// caMagic is a 4-byte file header so we can detect format errors early.
var caMagic = [4]byte{'P', 'S', 'C', 'A'}

const (
	caVersion      = byte(0x01)
	pbkdf2Iter     = 100_000
	pbkdf2SaltLen  = 32
	aesGCMNonceLen = 12
)

// InitCA generates a fresh in-memory Root CA key pair. Call once at startup
// when no persisted CA is available.
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
	cm.cache = map[string]*tls.Certificate{} // clear leaf cache on CA change
	cm.mu.Unlock()
	return nil
}

// LoadOrInitCA loads an existing CA bundle from path (decrypting with
// passphrase) or, if the file does not exist, generates a fresh CA and saves
// it. An empty passphrase disables encryption (development/testing only).
//
// The env var PROXYSHIELD_CA_PASSPHRASE is the recommended way to supply the
// passphrase so it never appears in CLI history or process listings.
func (cm *CertManager) LoadOrInitCA(path, passphrase string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// No existing bundle — generate and persist.
		if err := cm.InitCA(); err != nil {
			return fmt.Errorf("CA init: %w", err)
		}
		if err := cm.SaveCA(path, passphrase); err != nil {
			return fmt.Errorf("CA save: %w", err)
		}
		return nil
	}
	return cm.LoadCA(path, passphrase)
}

// SaveCA encrypts (AES-256-GCM, key derived via PBKDF2-SHA256) and writes the
// current Root CA key+cert to path. If passphrase is empty the bundle is
// written in plain PEM — only suitable for development/testing environments.
func (cm *CertManager) SaveCA(path, passphrase string) error {
	bundle, err := cm.exportBundle()
	if err != nil {
		return err
	}
	plaintext := append(bundle.certPEM, bundle.keyPEM...) //nolint:gocritic

	var data []byte
	if passphrase == "" {
		// No passphrase: write plain PEM (dev/test only).
		data = plaintext
	} else {
		data, err = encryptBundle(plaintext, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("CA encrypt: %w", err)
		}
	}
	// 0600 — owner-readable only; CA private key material.
	// filepath.Clean prevents path-traversal before write (G703).
	return os.WriteFile(filepath.Clean(path), data, 0600)
}

// LoadCA reads and decrypts a CA bundle previously written by SaveCA.
// If passphrase is empty the file is treated as plain PEM.
func (cm *CertManager) LoadCA(path, passphrase string) error {
	data, err := os.ReadFile(filepath.Clean(path)) // filepath.Clean prevents path-traversal (G703)
	if err != nil {
		return fmt.Errorf("CA read: %w", err)
	}

	var plaintext []byte
	if passphrase == "" || len(data) < 5 || [4]byte(data[:4]) != caMagic {
		// Plain PEM (no magic header) or empty passphrase.
		plaintext = data
	} else {
		plaintext, err = decryptBundle(data, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("CA decrypt: %w", err)
		}
	}
	return cm.importBundle(plaintext)
}

// exportBundle encodes the current CA cert and key as PEM blocks.
func (cm *CertManager) exportBundle() (caBundle, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.caCert == nil || cm.caKey == nil {
		return caBundle{}, errors.New("CA not initialised")
	}
	keyDER, err := x509.MarshalECPrivateKey(cm.caKey)
	if err != nil {
		return caBundle{}, err
	}
	return caBundle{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// importBundle parses a PEM bundle and stores the CA into the CertManager.
func (cm *CertManager) importBundle(data []byte) error {
	var certDER, keyDER []byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certDER = block.Bytes
		case "EC PRIVATE KEY":
			keyDER = block.Bytes
		}
	}
	if certDER == nil || keyDER == nil {
		return errors.New("CA bundle: missing CERTIFICATE or EC PRIVATE KEY block")
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("CA bundle: parse cert: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return fmt.Errorf("CA bundle: parse key: %w", err)
	}
	// Validate cert has not expired.
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("CA bundle: certificate expired at %s", cert.NotAfter)
	}
	cm.mu.Lock()
	cm.caCert = cert
	cm.caKey = key
	cm.cache = map[string]*tls.Certificate{}
	cm.mu.Unlock()
	return nil
}

// ── Encryption helpers ────────────────────────────────────────────────────────
// Wire format (encrypted):
//   [4] magic "PSCA"
//   [1] version (0x01)
//   [4] iterations (uint32 big-endian)
//   [32] PBKDF2 salt
//   [12] AES-GCM nonce
//   [...] ciphertext (AES-256-GCM)

func encryptBundle(plaintext, passphrase []byte) ([]byte, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	aesKey := pbkdf2.Key(passphrase, salt, pbkdf2Iter, 32, sha256.New)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	var iterBuf [4]byte
	binary.BigEndian.PutUint32(iterBuf[:], uint32(pbkdf2Iter))

	out := make([]byte, 0, 4+1+4+pbkdf2SaltLen+aesGCMNonceLen+len(ciphertext))
	out = append(out, caMagic[:]...)
	out = append(out, caVersion)
	out = append(out, iterBuf[:]...)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptBundle(data, passphrase []byte) ([]byte, error) {
	const hdrLen = 4 + 1 + 4 + pbkdf2SaltLen + aesGCMNonceLen
	if len(data) < hdrLen {
		return nil, errors.New("CA bundle: file too short")
	}
	if [4]byte(data[:4]) != caMagic {
		return nil, errors.New("CA bundle: bad magic")
	}
	if data[4] != caVersion {
		return nil, fmt.Errorf("CA bundle: unsupported version %d", data[4])
	}
	iter := int(binary.BigEndian.Uint32(data[5:9]))
	salt := data[9 : 9+pbkdf2SaltLen]
	nonce := data[9+pbkdf2SaltLen : 9+pbkdf2SaltLen+aesGCMNonceLen]
	ciphertext := data[hdrLen:]

	aesKey := pbkdf2.Key(passphrase, salt, iter, 32, sha256.New)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("CA bundle: decryption failed (wrong passphrase?)")
	}
	return plaintext, nil
}

// ── Certificate helpers ───────────────────────────────────────────────────────

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
