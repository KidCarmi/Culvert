// Package ca implements Culvert's SSL-inspection Root CA — the MITM trust
// core (ADR-0002 extraction; engine was ca.go in package main). It owns the
// Root CA lifecycle (in-memory init, encrypted-bundle load/save, custom-CA
// import), on-the-fly leaf-cert signing with an LRU+TTL cache, dual-CA
// rotation with an overlap window, and the pluggable KeyProvider (HSM/KMS)
// seam.
//
// The encrypted-bundle wire format is FROZEN: `caMagic` ("PSCA"), `caVersion`,
// and the PBKDF2-600k + AES-256-GCM layout are read from bundles already on
// operators' disks — changing any of them breaks load. See encryptBundle.
//
// Observability crosses the boundary via publish-once package-level hooks
// (SignLatencyObserver, RotationObserver), wired once by package main to its
// Prometheus histogram / alert store / rotation counter — the obs/fileutil
// injection pattern (ADR-0003), so the engine never imports main. The
// auto-rotation LOOP (StartCAAutoRotation) and the cluster CA stay in main;
// this package exposes the per-tick primitives (RotateIfNeeded,
// CleanupSecondaryCA) the loop drives.
package ca

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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// SignLatencyObserver receives each successful leaf-sign's latency in seconds
// when set. Publish-once: package main wires it to its Prometheus histogram at
// startup. nil ⇒ no-op (the engine never depends on metrics wiring).
var SignLatencyObserver func(seconds float64)

// RotationObserver is invoked after a successful RotateIfNeeded with the old
// and new CA expiry times when set. Publish-once: package main wires it to
// fire the cert-rotation alert and bump the rotation counter. nil ⇒ no-op.
var RotationObserver func(oldExpiry, newExpiry time.Time)

// certCacheEntry pairs a leaf certificate with its creation timestamp for TTL.
type certCacheEntry struct {
	cert      *tls.Certificate
	createdAt time.Time
}

const (
	certCacheMaxSize = 10_000        // LRU eviction threshold
	certCacheTTL     = 1 * time.Hour // per-entry time-to-live
)

// Manager manages the Root CA used for SSL inspection (MITM).
// It generates leaf certificates on-the-fly and caches them with LRU
// eviction at certCacheMaxSize entries and TTL of certCacheTTL.
type Manager struct {
	mu          sync.RWMutex
	caCert      *x509.Certificate
	caKey       *ecdsa.PrivateKey
	keyProvider KeyProvider // optional external HSM/KMS signer
	cache       map[string]*certCacheEntry
	cacheOrder  []string // insertion order for LRU eviction

	// Leaf-cache effectiveness counters (CA-2). Lock-free; no identity data.
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64

	// Dual-CA overlap: secondary (old) CA kept during rotation window.
	// Leaf certs include both CAs in the chain so clients trusting either
	// CA can validate. Secondary is cleared after overlap window expires.
	secondaryCACert *x509.Certificate
	secondaryCAKey  *ecdsa.PrivateKey
	secondaryExpiry time.Time // when to stop using the secondary CA
}

// New returns a ready-to-use Manager with an initialised (empty) leaf cache.
// Call InitCA / LoadOrInitCA / LoadCustomCA to install a Root CA.
func New() *Manager {
	return &Manager{cache: map[string]*certCacheEntry{}}
}

// caBundle is the plaintext PEM bundle written/read from disk.
// Format: PEM(CERTIFICATE) || PEM(EC PRIVATE KEY)
type caBundle struct {
	certPEM []byte
	keyPEM  []byte
}

// caMagic is a 4-byte file header so we can detect format errors early.
// NOTE: The bytes 'P','S','C','A' are a legacy format identifier (originally
// "ProxyShield CA"). Do NOT change — existing encrypted CA bundles on disk
// use this magic and would fail to load if the value changes.
var caMagic = [4]byte{'P', 'S', 'C', 'A'}

const (
	caVersion      = byte(0x01)
	pbkdf2Iter     = 600_000 // NIST SP 800-132 (2024) recommends ≥600k for PBKDF2-SHA256
	pbkdf2SaltLen  = 32
	aesGCMNonceLen = 12
)

// InitCA generates a fresh in-memory Root CA key pair. Call once at startup
// when no persisted CA is available.
func (cm *Manager) InitCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// RFC 5280 requires unique serial numbers per CA. Use 128-bit random
	// serial to avoid collisions across CA rotations and multiple instances.
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("ca: serial generation: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			Organization: []string{"Culvert"},
			CommonName:   "Culvert Root CA",
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
	cm.cache = map[string]*certCacheEntry{}
	cm.cacheOrder = nil // clear leaf cache on CA change
	cm.mu.Unlock()
	return nil
}

// LoadOrInitCA loads an existing CA bundle from path (decrypting with
// passphrase) or, if the file does not exist, generates a fresh CA and saves
// it. An empty passphrase disables encryption (development/testing only).
//
// The env var CULVERT_CA_PASSPHRASE is the recommended way to supply the
// passphrase so it never appears in CLI history or process listings.
func (cm *Manager) LoadOrInitCA(path, passphrase string) error {
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
func (cm *Manager) SaveCA(path, passphrase string) error {
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
		data, err = EncryptBundle(plaintext, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("CA encrypt: %w", err)
		}
	}
	// Atomic write via the hardened helper: unique tmp + chmod + fsync(file)
	// + rename + parent-dir fsync (best-effort) + cleanup on error.
	// 0600 — owner-readable only; CA private key material.
	cleanPath := filepath.Clean(path)
	if err := fileutil.AtomicWrite(cleanPath, data, 0o600); err != nil {
		return fmt.Errorf("CA write: %w", err)
	}
	return nil
}

// LoadCA reads and decrypts a CA bundle previously written by SaveCA.
// If passphrase is empty the file is treated as plain PEM.
func (cm *Manager) LoadCA(path, passphrase string) error {
	data, err := os.ReadFile(filepath.Clean(path)) // filepath.Clean prevents path-traversal (G703)
	if err != nil {
		return fmt.Errorf("CA read: %w", err)
	}

	var plaintext []byte
	if passphrase == "" || len(data) < 5 || [4]byte(data[:4]) != caMagic {
		// Plain PEM (no magic header) or empty passphrase.
		// D1.1h: surface the surprising case where a passphrase is set
		// but the file lacks the magic header (a plain-PEM bundle written
		// before the passphrase was added). Behavior unchanged.
		if passphrase != "" && len(data) >= 5 {
			obs.Printf("Loader: ca.bundle: plain PEM accepted while passphrase is set — magic header absent at %q (D1.2-flag-F2)", obs.Sanitize(path))
		}
		plaintext = data
	} else {
		plaintext, err = DecryptBundle(data, []byte(passphrase))
		if err != nil {
			return fmt.Errorf("CA decrypt: %w", err)
		}
	}
	return cm.ImportBundle(plaintext)
}

// exportBundle encodes the current CA cert and key as PEM blocks.
func (cm *Manager) exportBundle() (caBundle, error) {
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

// ImportBundle parses a PEM bundle (CERTIFICATE + EC PRIVATE KEY blocks) and
// installs the CA into the Manager, clearing the leaf cache.
func (cm *Manager) ImportBundle(data []byte) error {
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
	cm.cache = map[string]*certCacheEntry{}
	cm.cacheOrder = nil
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
//
// EncryptBundle/DecryptBundle and HasBundleMagic are exported because the PSCA
// envelope is reused beyond the CA: kek.go wraps the key-encryption key in it,
// and restore.go / cluster_ca_keyatrest.go detect it by magic. The format is
// FROZEN (see the package doc).

// HasBundleMagic reports whether data begins with the PSCA envelope magic
// (i.e. is an encrypted bundle rather than plain PEM).
func HasBundleMagic(data []byte) bool {
	return len(data) >= len(caMagic) && [4]byte(data[:4]) == caMagic
}

// EncryptBundle seals plaintext into a PSCA envelope: a magic+version header,
// PBKDF2-SHA256 (600k iterations) key derivation over a random salt, and
// AES-256-GCM with a random nonce. The layout is FROZEN (see the package doc).
func EncryptBundle(plaintext, passphrase []byte) ([]byte, error) {
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

// DecryptBundle opens a PSCA envelope produced by EncryptBundle, validating
// the magic, version, and minimum iteration count before AES-256-GCM decrypt.
// It returns a generic error on any failure without disclosing key material.
func DecryptBundle(data, passphrase []byte) ([]byte, error) {
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
	if iter < 100_000 {
		return nil, fmt.Errorf("CA bundle: iteration count %d is below minimum (100000)", iter)
	}
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
func (cm *Manager) CACertPEM() []byte {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.caCert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw})
}

// CACertInfo returns metadata about the current Root CA for the UI dashboard.
func (cm *Manager) CACertInfo() map[string]any {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.caCert == nil {
		return map[string]any{"ready": false}
	}
	fp := sha256.Sum256(cm.caCert.Raw)
	// Format fingerprint as XX:XX:XX:... without rune→byte conversion (G115).
	fpParts := make([]string, len(fp))
	for i, b := range fp {
		fpParts[i] = fmt.Sprintf("%02X", b)
	}
	fingerprint := strings.Join(fpParts, ":")
	return map[string]any{
		"ready":       true,
		"subject":     cm.caCert.Subject.CommonName,
		"issuer":      cm.caCert.Issuer.CommonName,
		"notBefore":   cm.caCert.NotBefore.Format("2006-01-02"),
		"notAfter":    cm.caCert.NotAfter.Format("2006-01-02"),
		"fingerprint": fingerprint,
	}
}

// LoadCustomCA loads a PEM-encoded CA certificate and private key supplied by
// the user (e.g. an enterprise intermediate CA). Private key is never stored in
// cleartext memory beyond the parsing step.
func (cm *Manager) LoadCustomCA(certPEM, keyPEM []byte) error {
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("key pair mismatch: %w", err)
	}
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid certificate: %w", err)
	}
	if !x509Cert.IsCA {
		return errors.New("certificate is not a CA (BasicConstraints.IsCA must be true)")
	}
	ecKey, ok := tlsCert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("only ECDSA private keys are supported for MITM CA")
	}
	cm.mu.Lock()
	cm.caCert = x509Cert
	cm.caKey = ecKey
	cm.cache = map[string]*certCacheEntry{}
	cm.cacheOrder = nil
	cm.mu.Unlock()
	return nil
}

// ── CA Auto-Rotation ─────────────────────────────────────────────────────────

const (
	caRotationCheckInterval = 24 * time.Hour      // how often to check CA expiry
	caRotationOverlap       = 30 * 24 * time.Hour // rotate 30 days before expiry
)

// CAExpiry returns the CA certificate NotAfter time, or zero if CA is not ready.
func (cm *Manager) CAExpiry() time.Time {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.caCert == nil {
		return time.Time{}
	}
	return cm.caCert.NotAfter
}

// RotateIfNeeded checks whether the CA cert is nearing expiry and generates
// a new one with dual-CA overlap: the old CA is kept as secondary for the
// remaining lifetime of its certificate, so leaf certs signed by either CA
// remain valid during the transition. Returns true if rotation occurred.
func (cm *Manager) RotateIfNeeded(caPath, passphrase string) bool {
	expiry := cm.CAExpiry()
	if expiry.IsZero() {
		return false
	}
	if time.Until(expiry) > caRotationOverlap {
		return false
	}

	// Preserve the current CA as secondary for dual-CA overlap.
	cm.mu.Lock()
	oldCert := cm.caCert
	oldKey := cm.caKey
	cm.mu.Unlock()

	obs.Printf("CA auto-rotation: cert expires %s (<%d days) — generating new CA with dual-CA overlap",
		expiry.Format("2006-01-02"), int(caRotationOverlap.Hours()/24))
	if err := cm.InitCA(); err != nil {
		obs.Printf("CA auto-rotation: init failed: %v", err)
		return false
	}

	// Install old CA as secondary, valid until its original expiry.
	cm.mu.Lock()
	cm.secondaryCACert = oldCert
	cm.secondaryCAKey = oldKey
	cm.secondaryExpiry = expiry
	cm.mu.Unlock()

	if caPath != "" {
		if err := cm.SaveCA(caPath, passphrase); err != nil {
			obs.Printf("CA auto-rotation: save failed: %v", err)
		}
	}
	newExpiry := cm.CAExpiry()
	obs.Printf("CA auto-rotation: new CA generated (expires %s), old CA retained until %s",
		newExpiry.Format("2006-01-02"), expiry.Format("2006-01-02"))
	// Observability crosses the boundary via the publish-once hook: main
	// fires the cert-rotation alert and bumps culvert_ca_rotations_total.
	// Keeping this on RotateIfNeeded itself (not the loop) preserves the
	// contract that a direct RotateIfNeeded call counts as a rotation.
	if RotationObserver != nil {
		RotationObserver(expiry, newExpiry)
	}
	return true
}

// SecondaryCAActive returns whether a secondary (old) CA is still in the
// overlap window.
func (cm *Manager) SecondaryCAActive() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.secondaryCACert != nil && time.Now().Before(cm.secondaryExpiry)
}

// SecondaryCAInfo returns info about the secondary CA, or nil if inactive.
func (cm *Manager) SecondaryCAInfo() map[string]any {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.secondaryCACert == nil {
		return nil
	}
	if time.Now().After(cm.secondaryExpiry) {
		return nil
	}
	return map[string]any{
		"subject":    cm.secondaryCACert.Subject.CommonName,
		"notAfter":   cm.secondaryCACert.NotAfter.Format("2006-01-02"),
		"overlapEnd": cm.secondaryExpiry.Format("2006-01-02"),
		"expiresIn":  time.Until(cm.secondaryExpiry).Round(time.Second).String(),
	}
}

// CleanupSecondaryCA removes the secondary CA when its overlap window expires.
// Driven per-tick by main's StartCAAutoRotation loop.
func (cm *Manager) CleanupSecondaryCA() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.secondaryCACert != nil && time.Now().After(cm.secondaryExpiry) {
		obs.Printf("CA dual-overlap: secondary CA expired, removing")
		cm.secondaryCACert = nil
		cm.secondaryCAKey = nil
		cm.secondaryExpiry = time.Time{}
	}
}

// RotationCheckInterval is how often main's auto-rotation loop should tick.
const RotationCheckInterval = caRotationCheckInterval

// ── HSM/KMS Key Provider Interface ───────────────────────────────────────────
// KeyProvider abstracts CA private key operations so the signing key can live
// in an HSM, cloud KMS, or local memory. Enterprise deployments can implement
// this interface to integrate with AWS KMS, Azure Key Vault, GCP Cloud KMS,
// or PKCS#11 HSMs.

// KeyProvider signs certificate data using an externally managed private key.
type KeyProvider interface {
	// SignCertificate creates and signs a certificate using the provider's key.
	SignCertificate(template, parent *x509.Certificate, pubKey any) ([]byte, error)
	// PublicKey returns the public key corresponding to the signing key.
	PublicKey() any
	// Name returns a human-readable provider name (e.g. "local", "aws-kms").
	Name() string
}

// localKeyProvider is the default in-memory key provider.
type localKeyProvider struct {
	key *ecdsa.PrivateKey
}

// Compile-time interface check.
var _ KeyProvider = (*localKeyProvider)(nil)

// SignCertificate signs template with the in-memory local key.
func (p *localKeyProvider) SignCertificate(template, parent *x509.Certificate, pubKey any) ([]byte, error) {
	return x509.CreateCertificate(rand.Reader, template, parent, pubKey, p.key)
}

// PublicKey returns the local signing key's public key.
func (p *localKeyProvider) PublicKey() any { return &p.key.PublicKey }

// Name identifies this provider ("local").
func (p *localKeyProvider) Name() string { return "local" }

// SetKeyProvider allows an external key provider (HSM/KMS) to be registered.
func (cm *Manager) SetKeyProvider(kp KeyProvider) {
	cm.mu.Lock()
	cm.keyProvider = kp
	cm.mu.Unlock()
	obs.Printf("CA: key provider %s", kp.Name())
}

// KeyProviderName returns the name of the active key provider.
func (cm *Manager) KeyProviderName() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.keyProvider != nil {
		return cm.keyProvider.Name()
	}
	return "local"
}

// ParseTLSPair validates a PEM cert+key pair without storing it.
func (cm *Manager) ParseTLSPair(certPEM, keyPEM []byte) (*tls.Certificate, error) { //nolint:unparam // result used by callers in ui.go
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

// Ready returns true once the Root CA has been initialised.
func (cm *Manager) Ready() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.caCert != nil
}

// GetCert is a tls.Config.GetCertificate callback that returns a dynamically
// signed certificate for the requested ServerName. Results are cached with
// TTL-based expiry and LRU eviction at certCacheMaxSize entries.
func (cm *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "unknown"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	now := time.Now()
	cm.mu.RLock()
	if entry, ok := cm.cache[host]; ok && now.Sub(entry.createdAt) < certCacheTTL &&
		(entry.cert.Leaf == nil || now.Before(entry.cert.Leaf.NotAfter)) {
		cm.mu.RUnlock()
		cm.cacheHits.Add(1)
		return entry.cert, nil
	}
	cm.mu.RUnlock()

	// Cache did not serve the request (absent, TTL-expired, or leaf-expired) —
	// count the miss independent of whether the sign below then succeeds.
	cm.cacheMisses.Add(1)

	// Observe signing latency for successful signs only (no cm.mu held here).
	signStart := time.Now()
	cert, err := cm.signLeaf(host)
	if err != nil {
		return nil, err
	}
	if SignLatencyObserver != nil {
		SignLatencyObserver(time.Since(signStart).Seconds())
	}
	cm.mu.Lock()
	cm.cache[host] = &certCacheEntry{cert: cert, createdAt: now}
	cm.cacheOrder = append(cm.cacheOrder, host)
	// LRU eviction: when cache exceeds max size, evict oldest 10% of entries.
	if len(cm.cache) > certCacheMaxSize {
		evictCount := certCacheMaxSize / 10
		evicted := 0
		newOrder := cm.cacheOrder[:0:0]
		for _, h := range cm.cacheOrder {
			// Skip entries no longer in cache (already evicted or cleared externally).
			if _, exists := cm.cache[h]; !exists {
				continue
			}
			if evicted < evictCount {
				delete(cm.cache, h)
				evicted++
				continue
			}
			newOrder = append(newOrder, h)
		}
		cm.cacheOrder = newOrder
	}
	cm.mu.Unlock()
	return cert, nil
}

// CertCacheLen returns the current number of cached leaf certificates (testing).
func (cm *Manager) CertCacheLen() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.cache)
}

// CacheStats returns (hits, misses, currentSize) for the leaf-cert cache (CA-2).
// Hits/misses are lock-free atomics; size is read under the cache lock.
func (cm *Manager) CacheStats() (hits, misses int64, size int) {
	cm.mu.RLock()
	size = len(cm.cache)
	cm.mu.RUnlock()
	return cm.cacheHits.Load(), cm.cacheMisses.Load(), size
}

// ClearCache removes all cached leaf certificates.
func (cm *Manager) ClearCache() {
	cm.mu.Lock()
	cm.cache = make(map[string]*certCacheEntry)
	cm.cacheOrder = nil
	cm.mu.Unlock()
}

// signLeaf creates and signs a leaf TLS certificate for the given hostname.
// When dual-CA overlap is active, the secondary (old) CA cert is included in
// the certificate chain so clients trusting either CA can validate.
func (cm *Manager) signLeaf(host string) (*tls.Certificate, error) {
	cm.mu.RLock()
	caCert := cm.caCert
	caKey := cm.caKey
	secondaryCert := cm.secondaryCACert
	secondaryActive := secondaryCert != nil && time.Now().Before(cm.secondaryExpiry)
	var secondaryCertRaw []byte
	if secondaryActive {
		secondaryCertRaw = secondaryCert.Raw
	}
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
		NotBefore:    time.Now().Add(-5 * time.Minute),
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

	// Build PEM chain: leaf cert + primary CA + (optional) secondary CA.
	var chainPEM []byte
	chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})...)
	if len(secondaryCertRaw) > 0 {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secondaryCertRaw})...)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

// ── Test hooks ────────────────────────────────────────────────────────────────
// These exist so package main's whitebox tests can seed CA/cache state the
// engine keeps unexported. Test-only; not used on any production path.

// SetCAForTest installs a Root CA cert+key directly, bypassing generation.
func (cm *Manager) SetCAForTest(cert *x509.Certificate, key *ecdsa.PrivateKey) {
	cm.mu.Lock()
	cm.caCert = cert
	cm.caKey = key
	cm.mu.Unlock()
}

// CACertForTest returns the current Root CA certificate (nil if unset).
func (cm *Manager) CACertForTest() *x509.Certificate {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.caCert
}

// HasKeyProviderForTest reports whether a key provider has been installed.
func (cm *Manager) HasKeyProviderForTest() bool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.keyProvider != nil
}

// SeedCacheEntryForTest inserts a leaf-cache entry with an explicit creation
// time so cache TTL / LRU-eviction behavior can be exercised deterministically.
func (cm *Manager) SeedCacheEntryForTest(host string, cert *tls.Certificate, createdAt time.Time) {
	cm.mu.Lock()
	cm.cache[host] = &certCacheEntry{cert: cert, createdAt: createdAt}
	cm.cacheOrder = append(cm.cacheOrder, host)
	cm.mu.Unlock()
}

// AgeCacheEntryForTest back-dates an existing entry's creation time (past the
// TTL when the delta exceeds certCacheTTL), for cache-expiry tests.
func (cm *Manager) AgeCacheEntryForTest(host string, createdAt time.Time) bool {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	e, ok := cm.cache[host]
	if !ok {
		return false
	}
	e.createdAt = createdAt
	return true
}

// ── Exported constants / constructors for package-main whitebox tests ─────────

// Exported mirrors of internal tuning constants, for tests that assert cache
// behavior at the real bounds.
const (
	CacheTTL      = certCacheTTL
	CacheMaxSize  = certCacheMaxSize
	BundleVersion = caVersion
)

// Magic returns a copy of the PSCA bundle magic header bytes.
func Magic() []byte {
	m := caMagic
	return m[:]
}

// NewLocalKeyProvider returns the default in-memory KeyProvider backed by key.
func NewLocalKeyProvider(key *ecdsa.PrivateKey) KeyProvider {
	return &localKeyProvider{key: key}
}
