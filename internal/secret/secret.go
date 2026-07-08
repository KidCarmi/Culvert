// Package secret is the compiler-enforced containment boundary for
// key-encryption-key (KEK) material and key-at-rest wrapping, per
// docs/adr/0007-secret-containment-boundary.md and
// roadmap/SECRET-CONTAINMENT-PLAN.md.
//
// The boundary IS the point of the package. The raw-KEK source is an
// UNEXPORTED interface method (kekSource.kek), so no code outside this package
// can obtain the KEK bytes. Callers receive an opaque *Provider (built via
// ResolveProvider/FileProvider/EnvProvider) and, from Open, an opaque *Sealed
// handle; plaintext is reachable only through the scoped Sealed.WithPlaintext
// escape hatch, which zeroizes on return. Seal/Open reuse the audited PSCA
// envelope in internal/ca (AES-256-GCM + PBKDF2-SHA256, random salt + nonce per
// call) — no new primitive is introduced.
//
// This package deliberately wires into NOTHING in this PR: it ships alongside
// the existing package-main kek.go helpers, with its own tests, and later PRs
// migrate each consumer (cluster CA, DP node, CDR client, backup/restore,
// diagnostics) onto it before the package-main byte-returning API is removed.
// This is the same land-the-foundation-first pattern kek.go itself used in
// CA-3 PR1.
package secret

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// redactedMark is what every formatting verb prints for a secret handle, so an
// accidental logger.Printf("%v"/"%+v"/"%#v"/"%x"/"%s", handle) can never reflect
// the backing bytes.
const redactedMark = "REDACTED"

// KEKLen is the size of a key-encryption key in bytes (256-bit). The KEK is fed
// to the PSCA envelope's PBKDF2 step as the passphrase input.
const KEKLen = 32

// EnvKEKName is the default environment variable carrying a hex-encoded KEK.
const EnvKEKName = "CULVERT_KEK"

// ErrKEKMissing is returned when a provider requires externally-supplied unlock
// material that is absent. Callers must fail closed.
var ErrKEKMissing = errors.New("secret: required key-encryption key is missing")

// kekSource is the UNEXPORTED raw-KEK source. Because kek() is unexported, only
// this package can implement or call it — the raw bytes never cross the package
// boundary. This is the mechanism that turns "no raw KEK in package main" into a
// compile error rather than a convention.
type kekSource interface {
	// kek returns the raw key-encryption key bytes. Never logged, audited, or
	// placed in metrics; consumed only by the envelope operations below.
	kek() ([]byte, error)
	// name is a short, non-secret identifier for diagnostics ("file"/"env").
	name() string
}

// Provider is an opaque handle to KEK material. It exposes NO exported method
// that returns the KEK. Construct via ResolveProvider/FileProvider/EnvProvider.
type Provider struct {
	src kekSource
}

// Name returns a short, non-secret provider identifier for diagnostics. Safe to
// log. It never returns key material.
func (p *Provider) Name() string {
	if p == nil || p.src == nil {
		return ""
	}
	return p.src.name()
}

// Format redacts the Provider under all fmt verbs so an accidental %v/%+v/%#v
// never reflects its internal source (KEK file path, env var name). Use Name()
// for intentional, non-secret provider identification in logs.
func (Provider) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "secret.Provider("+redactedMark+")")
}

// String redacts the Provider for Stringer consumers.
func (Provider) String() string { return "secret.Provider(" + redactedMark + ")" }

// GoString redacts the Provider for %#v / GoStringer consumers.
func (Provider) GoString() string { return "secret.Provider(" + redactedMark + ")" }

// providerKEK is the single internal chokepoint that yields raw KEK bytes to the
// envelope operations. Its result must never be exposed outside this package.
func providerKEK(p *Provider) ([]byte, error) {
	if p == nil || p.src == nil {
		return nil, errors.New("secret: nil provider")
	}
	k, err := p.src.kek()
	if err != nil {
		return nil, err
	}
	if len(k) == 0 {
		return nil, ErrKEKMissing
	}
	return k, nil
}

// ValidateProvider reports whether the provider can supply a KEK, WITHOUT
// returning any bytes. Use for availability / diagnostics checks that must not
// surface key material.
func ValidateProvider(p *Provider) error {
	_, err := providerKEK(p)
	return err
}

// Sealed is an opaque handle to plaintext secret bytes. It has no exported byte
// accessor; reach the plaintext only via WithPlaintext. Its Format/String/
// GoString methods below are REDACTING (not accessors): they exist precisely so
// fmt can never reflect the backing buffer.
type Sealed struct {
	b []byte
}

// Format implements fmt.Formatter so EVERY verb (%v, %+v, %#v, %s, %x, %d, …)
// prints a constant redaction instead of reflecting the plaintext buffer. fmt
// consults Formatter before Stringer/GoStringer, so this single method closes
// every verb. Value receiver so both Sealed and *Sealed are covered even when
// passed by value (fmt cannot take the address of a value operand).
func (Sealed) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "secret.Sealed("+redactedMark+")")
}

// String redacts for explicit Stringer consumers (belt and suspenders alongside
// Format).
func (Sealed) String() string { return "secret.Sealed(" + redactedMark + ")" }

// GoString redacts for %#v / GoStringer consumers.
func (Sealed) GoString() string { return "secret.Sealed(" + redactedMark + ")" }

// WithPlaintext runs fn with the plaintext, then zeroizes the buffer. The []byte
// passed to fn is invalid once fn returns; fn MUST NOT retain it. A Sealed is
// single-use: a second call after the buffer is zeroized returns an error.
func (s *Sealed) WithPlaintext(fn func([]byte) error) error {
	if s == nil || s.b == nil {
		return errors.New("secret: sealed is empty or already consumed")
	}
	if fn == nil {
		return errors.New("secret: nil WithPlaintext fn")
	}
	defer s.Destroy()
	return fn(s.b)
}

// Destroy zeroizes the plaintext buffer. Safe to call more than once.
func (s *Sealed) Destroy() {
	if s == nil {
		return
	}
	for i := range s.b {
		s.b[i] = 0
	}
	s.b = nil
}

// Seal encrypts plaintext under the provider's KEK using the PSCA envelope
// (AES-256-GCM + PBKDF2-SHA256, random salt + nonce per call).
func Seal(plaintext []byte, p *Provider) ([]byte, error) {
	k, err := providerKEK(p)
	if err != nil {
		return nil, err
	}
	return ca.EncryptBundle(plaintext, k)
}

// Open decrypts a PSCA envelope produced by Seal and returns an opaque handle.
// It fails closed on bad magic, unsupported version, a malformed header, a wrong
// KEK, or a corrupted ciphertext/tag — none of which disclose key material.
func Open(envelope []byte, p *Provider) (*Sealed, error) {
	k, err := providerKEK(p)
	if err != nil {
		return nil, err
	}
	plain, err := ca.DecryptBundle(envelope, k)
	if err != nil {
		return nil, err
	}
	return &Sealed{b: plain}, nil
}

// sealedOf wraps already-in-memory plaintext as a Sealed. Internal only: a
// Sealed must only ever originate inside this package.
func sealedOf(plaintext []byte) *Sealed { return &Sealed{b: plaintext} }

// OpenOrPlaintext returns an opaque handle for raw on-disk key bytes following
// the content-driven at-rest contract shared by every key-at-rest consumer: if
// the bytes are a PSCA envelope it decrypts them (fail closed on missing/wrong
// KEK or corruption); otherwise the plaintext is wrapped unchanged. The bool
// reports whether the input was encrypted. Returning a Sealed for BOTH branches
// means callers never hold raw key bytes directly — they reach the plaintext
// only through the scoped, zeroize-on-return WithPlaintext.
func OpenOrPlaintext(raw []byte, p *Provider) (*Sealed, bool, error) {
	if !IsEnvelope(raw) {
		return sealedOf(raw), false, nil
	}
	s, err := Open(raw, p)
	if err != nil {
		return nil, true, err
	}
	return s, true, nil
}

// SealToFile encrypts plaintext under p and writes the envelope to path with
// 0600 permissions, atomically (fileutil.AtomicWrite).
func SealToFile(path string, plaintext []byte, p *Provider) error {
	enc, err := Seal(plaintext, p)
	if err != nil {
		return err
	}
	if err := fileutil.AtomicWrite(filepath.Clean(path), enc, 0o600); err != nil {
		return fmt.Errorf("secret: write encrypted file: %w", err)
	}
	return nil
}

// OpenFile reads an envelope previously written by SealToFile and returns an
// opaque handle. Read or decrypt failures fail closed; no key material is
// included in the returned error.
func OpenFile(path string, p *Provider) (*Sealed, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // filepath.Clean guards path-traversal (G304)
	if err != nil {
		return nil, fmt.Errorf("secret: read encrypted file: %w", err)
	}
	return Open(data, p)
}

// IsEnvelope reports whether raw on-disk bytes are a PSCA envelope (the
// encrypted form produced by Seal). Mirrors the Root-CA / cluster-CA detector.
func IsEnvelope(data []byte) bool {
	return ca.HasBundleMagic(data)
}
