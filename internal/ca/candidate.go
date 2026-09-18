package ca

// candidate.go — the validated-candidate API (FE-6B.0 backend-truth gate).
//
// THE DEFECT IT CLOSES: every Root-CA install path published FIRST and
// persisted SECOND. InitCA (the manual force-rotate, the first boot, the
// auto-rotation) and LoadCustomCA (the admin import) swapped the live CA and
// fired CAChangedObserver before a single byte reached the bundle, so a
// persistence failure left the process signing with a CA the next restart
// would never load — and the admin API reported it as a rotation that
// happened. A trust anchor the fleet is about to be provisioned with must be
// DURABLE before it is LIVE.
//
// THE MODEL: a Candidate is a fully validated (cert, key) pair that is NOT
// installed. It is produced by NewRotationCandidate (a fresh root) or
// ParseCACandidate (admin-supplied PEM, validated as a whole before anything
// is decided), written by PersistCandidate (atomic, 0600, the frozen PSCA
// envelope when a passphrase is set) and only then published by
// Manager.Install. A caller that cannot persist never installs.
//
// VALIDATION IS BOUNDED: ParseCACandidate answers a *CandidateError carrying
// ONE reason from a closed vocabulary and nothing else — never the parser's
// text, never key material — so an admin API can render it as a typed fact
// and a log line cannot carry a fragment of a private key.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Candidate validation reasons (closed vocabulary; the OpenAPI enum mirrors it).
const (
	CandidateMalformedPEM   = "malformed_pem"
	CandidateChainInvalid   = "chain_invalid"
	CandidateKeyMismatch    = "key_mismatch"
	CandidateNotCA          = "not_ca"
	CandidateUnsupportedKey = "unsupported_key"
	CandidateEncryptedKey   = "encrypted_key_unsupported"
	CandidateExpired        = "expired"
	CandidateNotYetValid    = "not_yet_valid"
)

// CandidateError is the bounded refusal of a candidate. Reason is one of the
// Candidate* constants; the text carries nothing else.
type CandidateError struct{ Reason string }

func (e *CandidateError) Error() string { return "certificate candidate refused: " + e.Reason }

// Candidate is a validated Root CA that has not been installed.
type Candidate struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewRotationCandidate mints a fresh Culvert Root CA (ECDSA P-256, 10 years,
// 128-bit random serial) without installing it.
func NewRotationCandidate() (*Candidate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// RFC 5280 requires unique serial numbers per CA. Use 128-bit random
	// serial to avoid collisions across CA rotations and multiple instances.
	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca: serial generation: %w", err)
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
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &Candidate{cert: cert, key: key}, nil
}

// ParseCACandidate validates an admin-supplied CA certificate (optionally
// followed by its issuing chain) and private key as ONE candidate. The whole
// input is decided before anything is returned; a refusal is a
// *CandidateError with a bounded reason:
//
//	malformed_pem              — no leading CERTIFICATE block, an undecodable
//	                             leaf, or an undecodable/unknown key block
//	chain_invalid              — a trailing CERTIFICATE block that does not parse
//	                             or does not issue the block before it
//	key_mismatch               — the key does not belong to the certificate
//	not_ca                     — BasicConstraints does not mark a CA
//	unsupported_key            — the CA key is not ECDSA (the only key the MITM
//	                             signer supports)
//	encrypted_key_unsupported  — a passphrase-protected key
//	expired / not_yet_valid    — outside its own validity window (the same
//	                             predicate Usable enforces on the live CA)
func ParseCACandidate(certPEM, keyPEM []byte) (*Candidate, error) {
	cert, _, reason := parseCertificateChain(certPEM)
	if reason != "" {
		return nil, &CandidateError{Reason: reason}
	}
	signer, reason := parsePrivateKey(keyPEM)
	if reason != "" {
		return nil, &CandidateError{Reason: reason}
	}
	if !publicKeyMatches(cert, signer) {
		return nil, &CandidateError{Reason: CandidateKeyMismatch}
	}
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return nil, &CandidateError{Reason: CandidateNotCA}
	}
	ecKey, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		return nil, &CandidateError{Reason: CandidateUnsupportedKey}
	}
	if reason := validityReason(cert, time.Now()); reason != "" {
		return nil, &CandidateError{Reason: reason}
	}
	return &Candidate{cert: cert, key: ecKey}, nil
}

// ParseTLSCandidate validates an admin-supplied server certificate chain and
// key for the admin-UI listener with the same bounded vocabulary (minus
// not_ca / unsupported_key: a UI leaf may be RSA or ECDSA and must NOT be a
// CA-only certificate — that is not checked, a CA can legally serve TLS).
// The returned *tls.Certificate is what tls.LoadX509KeyPair will build from
// the same bytes at the next boot; the pair is ALSO run through
// tls.X509KeyPair so a layout the boot loader would refuse is refused here.
func ParseTLSCandidate(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, chain, reason := parseCertificateChain(certPEM)
	if reason != "" {
		return nil, &CandidateError{Reason: reason}
	}
	signer, reason := parsePrivateKey(keyPEM)
	if reason != "" {
		return nil, &CandidateError{Reason: reason}
	}
	if !publicKeyMatches(cert, signer) {
		return nil, &CandidateError{Reason: CandidateKeyMismatch}
	}
	if reason := validityReason(cert, time.Now()); reason != "" {
		return nil, &CandidateError{Reason: reason}
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		// Everything above passed, so the only remaining disagreement is
		// the PEM layout the boot loader accepts; bounded as malformed.
		return nil, &CandidateError{Reason: CandidateMalformedPEM}
	}
	out := &tls.Certificate{Certificate: append([][]byte{cert.Raw}, chain...), PrivateKey: signer, Leaf: cert}
	return out, nil
}

// parseCertificateChain decodes the leading CERTIFICATE block as the leaf and
// every following CERTIFICATE block as its issuing chain, in order.
func parseCertificateChain(certPEM []byte) (leaf *x509.Certificate, chain [][]byte, reason string) {
	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, CandidateMalformedPEM
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, CandidateMalformedPEM
	}
	prev := leaf
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, CandidateChainInvalid
		}
		next, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, CandidateChainInvalid
		}
		if err := prev.CheckSignatureFrom(next); err != nil {
			return nil, nil, CandidateChainInvalid
		}
		chain = append(chain, next.Raw)
		prev = next
	}
	return leaf, chain, ""
}

// parsePrivateKey decodes the first PEM block of keyPEM as a private key.
func parsePrivateKey(keyPEM []byte) (signer crypto.Signer, reason string) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, CandidateMalformedPEM
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return nil, CandidateEncryptedKey
	}
	var (
		key any
		err error
	)
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, CandidateMalformedPEM
	}
	if err != nil {
		return nil, CandidateMalformedPEM
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, CandidateUnsupportedKey
	}
	return signer, ""
}

// publicKeyMatches reports whether signer's public key is the certificate's.
func publicKeyMatches(cert *x509.Certificate, signer crypto.Signer) bool {
	pub, ok := cert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return pub.Equal(signer.Public())
}

// validityReason maps the Usable predicate onto the candidate vocabulary.
func validityReason(cert *x509.Certificate, now time.Time) string {
	if now.After(cert.NotAfter) {
		return CandidateExpired
	}
	if now.Add(caClockSkewTolerance).Before(cert.NotBefore) {
		return CandidateNotYetValid
	}
	return ""
}

// Fingerprint is the SHA-256 of the certificate DER as upper-case
// colon-separated hex — the format CACertInfo has always published.
func (c *Candidate) Fingerprint() string { return FingerprintOf(c.cert) }

// FingerprintHex is the same digest as lower-case hex without separators —
// the material of the server-owned revision token.
func (c *Candidate) FingerprintHex() string { return FingerprintHexOf(c.cert) }

// Certificate returns the candidate's certificate (public material).
func (c *Candidate) Certificate() *x509.Certificate { return c.cert }

// Info is the public projection of the candidate: what a dry-run review
// shows an administrator. No key material.
func (c *Candidate) Info() map[string]any {
	return certificateInfo(c.cert)
}

// Bundle encodes the candidate exactly as SaveCA would write the live CA:
// PEM(CERTIFICATE) || PEM(EC PRIVATE KEY), sealed in the PSCA envelope when a
// passphrase is set.
func (c *Candidate) Bundle(passphrase string) ([]byte, error) {
	keyDER, err := x509.MarshalECPrivateKey(c.key)
	if err != nil {
		return nil, err
	}
	plaintext := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	if passphrase == "" {
		return plaintext, nil
	}
	data, err := EncryptBundle(plaintext, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("CA encrypt: %w", err)
	}
	return data, nil
}

// PersistCandidate writes the candidate's bundle atomically (0600) to path.
// Nothing is installed; a returned error means the bundle did not land.
func PersistCandidate(c *Candidate, path, passphrase string) error {
	data, err := c.Bundle(passphrase)
	if err != nil {
		return err
	}
	if err := fileutil.AtomicWrite(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("CA write: %w", err)
	}
	return nil
}

// Install publishes the candidate as the live Root CA: the leaf cache is
// cleared and CAChangedObserver fires (with mu NOT held). Callers that have
// a bundle path persist FIRST.
func (cm *Manager) Install(c *Candidate) {
	cm.installLocked(c, nil, nil, time.Time{})
}

// installLocked swaps the live CA and, when old is non-nil, keeps it as the
// dual-CA secondary until oldExpiry.
func (cm *Manager) installLocked(c *Candidate, oldCert *x509.Certificate, oldKey *ecdsa.PrivateKey, oldExpiry time.Time) {
	cm.mu.Lock()
	cm.caCert = c.cert
	cm.caKey = c.key
	cm.cache = map[string]*certCacheEntry{}
	cm.cacheOrder = nil
	if oldCert != nil {
		cm.secondaryCACert = oldCert
		cm.secondaryCAKey = oldKey
		cm.secondaryExpiry = oldExpiry
	}
	cm.mu.Unlock()
	if CAChangedObserver != nil {
		CAChangedObserver()
	}
}

// FingerprintOf formats a certificate's SHA-256 as upper-case colon hex.
func FingerprintOf(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	parts := make([]string, len(fp))
	for i, b := range fp {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// FingerprintHexOf formats a certificate's SHA-256 as lower-case plain hex.
func FingerprintHexOf(cert *x509.Certificate) string {
	fp := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fp[:])
}

// certificateInfo is the shared public projection of a certificate.
func certificateInfo(cert *x509.Certificate) map[string]any {
	return map[string]any{
		"subject":      cert.Subject.CommonName,
		"issuer":       cert.Issuer.CommonName,
		"isCA":         cert.BasicConstraintsValid && cert.IsCA,
		"keyAlgorithm": keyAlgorithmName(cert),
		"notBefore":    cert.NotBefore.UTC().Format(time.RFC3339),
		"notAfter":     cert.NotAfter.UTC().Format(time.RFC3339),
		"fingerprint":  FingerprintOf(cert),
	}
}

// keyAlgorithmName is a bounded description of the certificate's key.
func keyAlgorithmName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		if k, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && k.Curve != nil {
			return "ecdsa-" + k.Curve.Params().Name
		}
		return "ecdsa"
	case x509.RSA:
		return "rsa"
	case x509.Ed25519:
		return "ed25519"
	default:
		return "unknown"
	}
}

// LiveCertificateHex returns the live CA's lower-case hex fingerprint, or ""
// when no CA is installed. It is the material of the server-owned revision.
func (cm *Manager) LiveCertificateHex() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	if cm.caCert == nil {
		return ""
	}
	return FingerprintHexOf(cm.caCert)
}

// PersistFailureClass maps a bundle-write error onto a bounded class for
// operator surfaces (status rows, alerts, refusals) that must never carry
// a path or the raw OS text.
func PersistFailureClass(err error) string {
	var errno syscall.Errno
	switch {
	case err == nil:
		return ""
	case errors.Is(err, fs.ErrPermission):
		return "permission_denied"
	case errors.Is(err, fs.ErrNotExist):
		return "not_found"
	case errors.As(err, &errno):
		switch errno {
		case syscall.EROFS:
			return "read_only"
		case syscall.ENOSPC, syscall.EDQUOT:
			return "no_space"
		case syscall.ENOTDIR, syscall.EISDIR, syscall.EEXIST:
			return "not_a_file"
		case syscall.EIO:
			return "io_error"
		}
	}
	return "write_failed"
}
