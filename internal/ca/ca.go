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

// CAChangedObserver is invoked (with mu NOT held) whenever the active Root CA
// key/cert changes at runtime — InitCA (fresh generation, incl. the manual
// force-rotate API and the InitCA inside RotateIfNeeded) and LoadCustomCA
// (admin-uploaded CA). Publish-once: package main wires it to flush the
// client-facing MITM session-ticket keys so a TLS 1.3 client cannot RESUME a
// session authenticated under the previous CA (the PSK path never re-runs
// GetCertificate). nil ⇒ no-op. Startup-time calls are harmless (no sessions
// exist yet). This is intentionally distinct from RotationObserver, which is
// dual-CA-overlap-specific and does not fire on InitCA/LoadCustomCA.
var CAChangedObserver func()

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
	// leafKey is the process-wide key reused by EVERY forged leaf (perf F3).
	// Generated once, lazily, on first sign; independent of the CA, so it
	// survives CA rotation unchanged. Sharing one key removes a P-256 keygen
	// from every cache-miss handshake — the dominant signLeaf cost — with no
	// trust change: the leaf private key never leaves the proxy, and anyone
	// able to extract it gains nothing beyond what the co-located CA key
	// already grants. That co-location rationale holds because signLeaf signs
	// with caKey directly and never routes through the KeyProvider/HSM seam; if
	// leaf signing is ever wired to an HSM, revisit this — the in-memory leaf
	// key would then be a strictly weaker secret than the HSM-held CA key.
	// Read-mostly; guarded by mu like the rest of the struct.
	leafKey    *ecdsa.PrivateKey
	cache      map[string]*certCacheEntry
	cacheOrder []string // insertion order for LRU eviction

	// caGen identifies the installed CA. It is retired (incremented) by
	// resetLeafCacheLocked on every CA replacement, and is what keeps an
	// in-flight sign from outliving the CA it was started against. Lock-free
	// for readers; written only under mu.
	caGen atomic.Uint64

	// signFlightState collapses concurrent misses for one host onto one sign.
	// It carries its OWN mutex and is never touched while mu is held — see the
	// lock-order note in signflight.go.
	signFlightState

	// Leaf-cache effectiveness counters (CA-2). Lock-free; no identity data.
	cacheHits   atomic.Int64
	cacheMisses atomic.Int64

	// signRefusals counts leaf-sign attempts refused because the Root CA was
	// outside its own validity window (CHAOS-28). Lock-free; no identity data.
	signRefusals atomic.Int64

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
// ErrBundleDecrypt marks a bundle that carries the PSCA envelope but could
// not be unsealed with the supplied passphrase (wrong passphrase, or a
// damaged envelope). ErrBundleMalformed marks a bundle whose plaintext is not
// a CERTIFICATE + EC PRIVATE KEY pair. Both are matched with errors.Is by the
// admin surfaces, which publish a bounded class instead of the wrapped text.
var (
	ErrBundleDecrypt   = errors.New("CA bundle: decrypt failed")
	ErrBundleMalformed = errors.New("CA bundle: malformed")
)

var caMagic = [4]byte{'P', 'S', 'C', 'A'}

const (
	caVersion      = byte(0x01)
	pbkdf2Iter     = 600_000 // NIST SP 800-132 (2024) recommends ≥600k for PBKDF2-SHA256
	pbkdf2SaltLen  = 32
	aesGCMNonceLen = 12
)

// InitCA generates a fresh Root CA and installs it. It is the in-memory path
// (no bundle configured, tests); every path that HAS a bundle goes through
// NewRotationCandidate → PersistCandidate → Install so the trust anchor is
// durable before it is live (FE-6B.0).
func (cm *Manager) InitCA() error {
	c, err := NewRotationCandidate()
	if err != nil {
		return err
	}
	cm.Install(c)
	return nil
}

// LoadOrInitCA loads an existing CA bundle from path (decrypting with
// passphrase) or, if the file does not exist, generates a fresh CA, PERSISTS
// it and only then installs it. An empty passphrase disables encryption
// (development/testing only).
//
// The env var CULVERT_CA_PASSPHRASE is the recommended way to supply the
// passphrase so it never appears in CLI history or process listings.
func (cm *Manager) LoadOrInitCA(path, passphrase string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		// No existing bundle — generate, persist, then publish (FE-6B.0: a
		// first boot whose bundle write fails must not run on a CA the next
		// boot cannot load).
		c, err := NewRotationCandidate()
		if err != nil {
			return fmt.Errorf("CA init: %w", err)
		}
		if err := PersistCandidate(c, path, passphrase); err != nil {
			return fmt.Errorf("CA save: %w", err)
		}
		cm.Install(c)
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
			return fmt.Errorf("CA decrypt: %w: %w", ErrBundleDecrypt, err)
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
		return fmt.Errorf("%w: missing CERTIFICATE or EC PRIVATE KEY block", ErrBundleMalformed)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("%w: parse cert: %w", ErrBundleMalformed, err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return fmt.Errorf("%w: parse key: %w", ErrBundleMalformed, err)
	}
	// Validate cert has not expired.
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("CA bundle: certificate expired at %s", cert.NotAfter)
	}
	cm.mu.Lock()
	cm.caCert = cert
	cm.caKey = key
	cm.resetLeafCacheLocked()
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
	return map[string]any{
		"ready":       true,
		"subject":     cm.caCert.Subject.CommonName,
		"issuer":      cm.caCert.Issuer.CommonName,
		"notBefore":   cm.caCert.NotBefore.Format("2006-01-02"),
		"notAfter":    cm.caCert.NotAfter.Format("2006-01-02"),
		"fingerprint": FingerprintOf(cm.caCert),
	}
}

// LoadCustomCA validates and installs a PEM-encoded CA certificate and
// private key supplied by the user (e.g. an enterprise intermediate CA). It
// is ParseCACandidate + Install with no persistence step — the admin API
// persists the candidate FIRST (FE-6B.0); this remains for in-memory callers
// and tests. A refusal is a bounded *CandidateError.
func (cm *Manager) LoadCustomCA(certPEM, keyPEM []byte) error {
	c, err := ParseCACandidate(certPEM, keyPEM)
	if err != nil {
		return err
	}
	cm.Install(c)
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
//
// PERSIST BEFORE PUBLISH (FE-6B.0): when a bundle path is configured the
// replacement is written FIRST and installed only once the write landed. A
// write failure therefore leaves the CURRENT CA active — still valid for up
// to the 30-day overlap window — and the attempt is repeated at the next
// check; it never produces a memory-only CA that the next restart discards
// and re-mints differently. The failure is reported through
// RotationPersistFailureObserver with a bounded class (CHAOS-28 / CA-2, now
// describing a rotation that was NOT applied rather than one that was).
func (cm *Manager) RotateIfNeeded(caPath, passphrase string) bool {
	expiry := cm.CAExpiry()
	if !rotationDue(expiry) {
		return false
	}

	obs.Printf("CA auto-rotation: cert expires %s (<%d days) — generating new CA with dual-CA overlap",
		expiry.Format("2006-01-02"), int(caRotationOverlap.Hours()/24))
	c, err := NewRotationCandidate()
	if err != nil {
		obs.Printf("CA auto-rotation: init failed: %v", err)
		return false
	}
	if caPath != "" {
		if err := PersistCandidate(c, caPath, passphrase); err != nil {
			class := PersistFailureClass(err)
			obs.Printf("CA auto-rotation: bundle write failed (%s) — rotation NOT applied; the current CA stays active "+
				"and the attempt is repeated at the next check", class)
			if RotationPersistFailureObserver != nil {
				RotationPersistFailureObserver(class)
			}
			return false
		}
	}

	// Preserve the current CA as secondary for dual-CA overlap and publish
	// the (now durable) replacement in one swap.
	cm.mu.RLock()
	oldCert, oldKey := cm.caCert, cm.caKey
	cm.mu.RUnlock()
	cm.installLocked(c, oldCert, oldKey, expiry)

	if caPath != "" && RotationPersistSuccessObserver != nil {
		RotationPersistSuccessObserver()
	}
	newExpiry := cm.CAExpiry()
	obs.Printf("CA auto-rotation: new CA generated (expires %s), old CA retained until %s",
		newExpiry.Format("2006-01-02"), expiry.Format("2006-01-02"))
	// Observability crosses the boundary via the publish-once hook: main
	// fires the cert-rotation alert and bumps culvert_ca_rotations_total.
	// Only a rotation that is durable (or had nothing to persist) reaches
	// this line, so the success signal is gated on persistence by
	// construction.
	if RotationObserver != nil {
		RotationObserver(expiry, newExpiry)
	}
	return true
}

// RotationDue reports whether RotateIfNeeded WOULD rotate now: a CA is
// loaded and inside the rotation window. It is the single predicate both
// RotateIfNeeded and its caller consult, so a caller can tell a round that
// will write from one that will not (FE-6B.0 round 4: a round that writes
// nothing takes no writer posture against the operation ledger). A CA that
// is due stays due — time only moves forward — so a decision taken from
// this predicate under the caller's lock is not invalidated before the
// rotation runs.
func (cm *Manager) RotationDue() bool {
	return rotationDue(cm.CAExpiry())
}

func rotationDue(expiry time.Time) bool {
	return !expiry.IsZero() && time.Until(expiry) <= caRotationOverlap
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
//
// A miss is served through signOnce, which collapses concurrent misses for the
// same host onto ONE sign (signflight.go). The hit path below is untouched by
// that: it takes no flight lock and never allocates.
func (cm *Manager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := hello.ServerName
	if host == "" {
		host = "unknown"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if cert, ok := cm.cachedLeaf(host, time.Now()); ok {
		cm.cacheHits.Add(1)
		return cert, nil
	}

	// Cache did not serve the request (absent, TTL-expired, or leaf-expired) —
	// count the miss independent of whether the sign below then succeeds, and
	// independent of whether this caller leads its own sign or joins one
	// already in flight. So cacheHits + cacheMisses stays exactly the number of
	// GetCert calls, as it was before the single flight existed.
	cm.cacheMisses.Add(1)
	return cm.signOnce(host)
}

// cachedLeaf returns the cached leaf for host when one is present, inside its
// cache TTL, and not itself expired. It is the read half of GetCert, split out
// so signOnce can re-run the identical check before opening a flight.
func (cm *Manager) cachedLeaf(host string, now time.Time) (*tls.Certificate, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	entry, ok := cm.cache[host]
	if !ok || now.Sub(entry.createdAt) >= certCacheTTL {
		return nil, false
	}
	if entry.cert.Leaf != nil && !now.Before(entry.cert.Leaf.NotAfter) {
		return nil, false
	}
	return entry.cert, true
}

// storeLeaf installs a freshly signed leaf and runs LRU eviction. It is the
// write half of GetCert, unchanged in behaviour.
func (cm *Manager) storeLeaf(host string, cert *tls.Certificate, gen uint64, now time.Time) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	// A CA replacement retired this sign's generation while it was running, so
	// the leaf may be signed by the outgoing CA. Caching it would repopulate
	// the cache that the replacement had just cleared, and serve the outgoing
	// CA's leaf to every client for the full certCacheTTL. Drop it instead: the
	// next miss signs against the incoming CA. The cost is one wasted sign
	// during an admin CA change, which is the right side to err on.
	if cm.caGen.Load() != gen {
		return
	}
	// Track eviction order only for a host that is NOT already tracked
	// (CHAOS-28). Appending unconditionally leaked: a TTL-expired REFRESH
	// overwrites the map entry, so len(cache) does not change, the eviction
	// branch below never fires, and cacheOrder grows by one string per refresh
	// forever — an unbounded slice on a bounded map. A gateway with a stable
	// working set of W hosts added W entries per certCacheTTL indefinitely
	// (W=5,000 ⇒ ~120k strings/day), so the leak scaled with UPTIME, which is
	// exactly the axis an appliance is supposed to be good at. The duplicates
	// were also dead weight for eviction itself: the second and later copies of
	// a host always resolved to "already gone" and were skipped, so dropping
	// them changes no eviction decision — the first insertion still governs.
	if _, tracked := cm.cache[host]; !tracked {
		cm.cacheOrder = append(cm.cacheOrder, host)
	}
	cm.cache[host] = &certCacheEntry{cert: cert, createdAt: now}
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
}

// resetLeafCacheLocked drops every cached leaf and RETIRES the current CA
// generation. Callers must hold mu.
//
// The two halves are inseparable and that is the whole point of this helper
// existing rather than four open-coded map assignments. Clearing the cache
// alone is not enough to make a CA replacement take effect: a leaf sign that is
// already in flight was started against the OUTGOING CA, and without the
// generation bump a caller arriving AFTER the replacement would join that
// flight and be handed the outgoing CA's leaf — which a client that trusts only
// the incoming CA rejects — and the leader would then repopulate the
// just-cleared cache with it for the full certCacheTTL. Bumping the generation
// makes both impossible: post-replacement callers cannot join a pre-replacement
// flight, and a leader whose generation has been retired does not store its
// result. See signflight.go.
//
// Every site that installs or replaces a CA must go through here; that is
// pinned structurally by TestCAGeneration_EveryCacheResetRetiresTheGeneration.
func (cm *Manager) resetLeafCacheLocked() {
	cm.cache = map[string]*certCacheEntry{}
	cm.cacheOrder = nil
	cm.caGen.Add(1)
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
	cm.resetLeafCacheLocked()
	cm.mu.Unlock()
}

// sharedLeafKey returns the process-wide leaf key (perf F3), generating it once
// on first use with double-checked locking. Every forged leaf reuses this key;
// see the leafKey field comment for why that is safe.
func (cm *Manager) sharedLeafKey() (*ecdsa.PrivateKey, error) {
	cm.mu.RLock()
	k := cm.leafKey
	cm.mu.RUnlock()
	if k != nil {
		return k, nil
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cm.leafKey == nil { // re-check: another goroutine may have won the race
		nk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		cm.leafKey = nk
	}
	return cm.leafKey, nil
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

	// CHAOS-28 / CA-1: refuse to sign with a Root CA that is outside its own
	// validity window. x509.CreateCertificate does not check the parent's
	// NotBefore/NotAfter, so without this the engine happily mints leaves that
	// every client rejects — a silent, fleet-wide inspected-HTTPS outage. Fail
	// closed here so the condition is one countable event with an operator
	// signal, not N opaque client-side certificate warnings. See validity.go.
	now := time.Now()
	if err := caUsable(caCert, now); err != nil {
		cm.signRefusals.Add(1)
		if UnusableObserver != nil {
			UnusableObserver(err.Error())
		}
		return nil, err
	}

	leafKey, err := cm.sharedLeafKey()
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	// A leaf must never outlive (or predate) its issuer — see clampLeafValidity.
	// The guard above guarantees now < caCert.NotAfter, so the clamped window is
	// always non-empty.
	notBefore, notAfter := clampLeafValidity(now.Add(-5*time.Minute), now.Add(24*time.Hour), caCert)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	// Assemble the tls.Certificate directly from DER (perf F3) instead of
	// round-tripping through PEM + tls.X509KeyPair, which would re-marshal the
	// key, PEM-encode the chain, then parse it all back. The chain is leaf +
	// (optional) secondary CA; the primary CA is a trust anchor the client
	// already has, so it is intentionally not sent. PublicKey ↔ PrivateKey
	// consistency is guaranteed by construction (the template was signed with
	// leafKey.PublicKey), so skipping X509KeyPair's key-match check is safe.
	chain := [][]byte{certDER}
	if len(secondaryCertRaw) > 0 {
		chain = append(chain, secondaryCertRaw)
	}
	return &tls.Certificate{
		Certificate: chain,
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
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
	if _, tracked := cm.cache[host]; !tracked { // same no-duplicate rule as GetCert
		cm.cacheOrder = append(cm.cacheOrder, host)
	}
	cm.cache[host] = &certCacheEntry{cert: cert, createdAt: createdAt}
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
