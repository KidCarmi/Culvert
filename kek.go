package main

// CA-3 PR1 — encrypted-file + KEK helper foundation.
//
// This file provides the reusable encryption foundation described in
// roadmap/CA-3-KEY-AT-REST-DESIGN.md for encrypting private-key material at
// rest. It deliberately wires into NOTHING in this PR: no cluster CA, no DP
// node key, no CDR key, no Root CA, no HA sync, no backup, no ConfigSnapshot,
// no rollback. Later PRs consume these helpers.
//
// Design invariants (from the ADR §3, §5):
//   - Reuse the existing PSCA envelope (encryptBundle/decryptBundle in ca.go) —
//     one audited crypto path, AES-256-GCM + PBKDF2-SHA256, magic + version,
//     random salt + random nonce per encryption.
//   - The KEK bytes are fed to the envelope as the PBKDF2 passphrase, so a
//     32-byte random KEK is stretched by the same 600k-iteration KDF as the
//     Root CA bundle. No new primitive is introduced.
//   - Authenticated encryption only; fail closed on unknown magic/version,
//     malformed envelope, wrong KEK, or corrupted ciphertext/tag (the GCM tag
//     check in decryptBundle covers wrong-KEK and tamper).
//   - Encrypted files and the local KEK file are written 0600 via
//     atomicWriteFile.
//   - Key material is never logged, audited, or exposed in metrics.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// kekLen is the size of a key-encryption key in bytes (256-bit). The KEK is
// random key material; it is fed to the PSCA envelope's PBKDF2 step as the
// passphrase input.
const kekLen = 32

// errKEKMissing is returned by a provider that requires externally-supplied
// unlock material when that material is absent. Callers must fail closed.
var errKEKMissing = errors.New("kek: required key-encryption key is missing")

// KEKProvider supplies the key-encryption key (KEK) used to wrap private-key
// material at rest. It is intentionally minimal: a source of KEK bytes plus a
// human-readable name for diagnostics. Implementations must NEVER log or
// otherwise expose the returned bytes.
//
// This is distinct from the existing KeyProvider interface (ca.go), which
// abstracts CA *signing* operations. KEKProvider abstracts the at-rest
// *wrapping* key.
type KEKProvider interface {
	// KEK returns the raw key-encryption key bytes. The returned slice must be
	// treated as secret: never log it, never put it in audit detail or metrics.
	KEK() ([]byte, error)
	// Name returns a short, non-secret identifier for the provider (e.g.
	// "file", "env"). Safe to log.
	Name() string
}

// ── Envelope helpers ───────────────────────────────────────────────────────
//
// These wrap the existing PSCA envelope (encryptBundle/decryptBundle in ca.go)
// so callers in later PRs have a single, intention-revealing entry point and so
// the "KEK bytes are the passphrase" contract lives in one place.

// encryptWithKEK encrypts plaintext under the provider's KEK using the PSCA
// envelope (AES-256-GCM + PBKDF2-SHA256, random salt + nonce per call).
func encryptWithKEK(plaintext []byte, p KEKProvider) ([]byte, error) {
	if p == nil {
		return nil, errors.New("kek: nil provider")
	}
	kek, err := p.KEK()
	if err != nil {
		return nil, err
	}
	if len(kek) == 0 {
		return nil, errKEKMissing
	}
	return ca.EncryptBundle(plaintext, kek)
}

// decryptWithKEK decrypts a PSCA envelope produced by encryptWithKEK using the
// provider's KEK. It fails closed on bad magic, unsupported version, a short or
// malformed header, a wrong KEK, or a corrupted ciphertext/tag — all surfaced
// by decryptBundle without disclosing key material.
func decryptWithKEK(data []byte, p KEKProvider) ([]byte, error) {
	if p == nil {
		return nil, errors.New("kek: nil provider")
	}
	kek, err := p.KEK()
	if err != nil {
		return nil, err
	}
	if len(kek) == 0 {
		return nil, errKEKMissing
	}
	return ca.DecryptBundle(data, kek)
}

// writeEncryptedFile encrypts plaintext under the provider's KEK and writes the
// resulting envelope to path with 0600 permissions via atomicWriteFile.
func writeEncryptedFile(path string, plaintext []byte, p KEKProvider) error {
	enc, err := encryptWithKEK(plaintext, p)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(filepath.Clean(path), enc, 0o600); err != nil {
		return fmt.Errorf("kek: write encrypted file: %w", err)
	}
	return nil
}

// readEncryptedFile reads an envelope previously written by writeEncryptedFile
// and decrypts it under the provider's KEK. Read or decrypt failures fail
// closed; no key material is included in the returned error.
func readEncryptedFile(path string, p KEKProvider) ([]byte, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // filepath.Clean guards path-traversal (G304)
	if err != nil {
		return nil, fmt.Errorf("kek: read encrypted file: %w", err)
	}
	return decryptWithKEK(data, p)
}

// ── File-based local KEK (model B) ─────────────────────────────────────────

// fileKEKProvider loads a 32-byte random KEK from a local file, generating the
// file (0600) on first use if it is absent. The KEK is stable across loads:
// once generated, subsequent calls return the same bytes.
//
// NOTE (CA-3 ADR §9): the KEK file MUST be excluded from any backup/snapshot
// that also contains the encrypted key files, otherwise model B provides no
// protection against backup/snapshot exposure. Backup wiring is a later PR;
// this provider does not register itself with any backup list, and the KEK
// file must never be placed into config-version snapshots.
type fileKEKProvider struct {
	path string
}

// Compile-time interface check.
var _ KEKProvider = (*fileKEKProvider)(nil)

// newFileKEKProvider returns a provider backed by the KEK file at path.
func newFileKEKProvider(path string) *fileKEKProvider {
	return &fileKEKProvider{path: filepath.Clean(path)}
}

func (p *fileKEKProvider) Name() string { return "file" }

// KEK returns the KEK bytes, generating and persisting a fresh random KEK on
// first use if the file does not exist. An existing-but-unreadable, wrong-sized,
// or too-permissive file fails closed rather than silently regenerating (which
// would destroy the ability to decrypt previously-written material).
func (p *fileKEKProvider) KEK() ([]byte, error) {
	if _, err := os.Stat(p.path); errors.Is(err, os.ErrNotExist) {
		return p.generate()
	}
	return p.load()
}

// load reads and validates an existing KEK file: it must be exactly kekLen
// bytes and must NOT be group/other-accessible (model B requires 0600 at rest,
// ADR §5). A too-permissive file is rejected rather than chmod-fixed, because a
// world-readable wrapping key may already have been exposed — failing closed
// forces operator awareness instead of silently masking the exposure.
func (p *fileKEKProvider) load() ([]byte, error) {
	fi, err := os.Stat(p.path)
	if err != nil {
		return nil, fmt.Errorf("kek: stat key file: %w", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("kek: file %q has permissions %#o; require 0600 (no group/other access) — run: chmod 600 %q", p.path, perm, p.path)
	}
	data, err := os.ReadFile(filepath.Clean(p.path)) // filepath.Clean guards path-traversal (G304)
	if err != nil {
		return nil, fmt.Errorf("kek: read key file: %w", err)
	}
	if len(data) != kekLen {
		// Fail closed: a malformed KEK file is not silently replaced, since
		// doing so would orphan any data already encrypted under the real KEK.
		return nil, fmt.Errorf("kek: file %q has unexpected size %d (want %d)", p.path, len(data), kekLen)
	}
	out := make([]byte, kekLen)
	copy(out, data)
	return out, nil
}

// generate creates a fresh random KEK and persists it 0600.
//
// It deliberately does NOT use atomicWriteFile: that helper renames over the
// destination unconditionally, so two callers racing on first use (two
// goroutines, or two processes sharing the data dir) could each generate a
// different KEK and the later rename would orphan the earlier caller's
// now-unpersisted key. Instead we write a fully-fsynced temp file and publish
// it with os.Link, which fails with EEXIST if the target already exists. The
// target therefore only ever appears as a complete file, and a caller that
// loses the race re-reads the winner's persisted KEK rather than returning its
// own orphaned bytes.
func (p *fileKEKProvider) generate() ([]byte, error) {
	kek := make([]byte, kekLen)
	if _, err := rand.Read(kek); err != nil {
		return nil, fmt.Errorf("kek: generate: %w", err)
	}
	dir := filepath.Dir(p.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(p.path)+".tmp.*")
	if err != nil {
		return nil, fmt.Errorf("kek: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // best-effort: removes the temp link, leaves the published target

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("kek: chmod temp: %w", err)
	}
	if _, err := tmp.Write(kek); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("kek: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("kek: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("kek: close temp: %w", err)
	}

	if err := os.Link(tmpName, p.path); err != nil {
		if errors.Is(err, os.ErrExist) {
			// Lost the race (or the file appeared concurrently) — load the
			// winner's complete, persisted KEK.
			return p.load()
		}
		return nil, fmt.Errorf("kek: publish key file: %w", err)
	}
	return kek, nil
}

// ── Environment / secret-supplied KEK (model C) ────────────────────────────

// envKEKName is the default environment variable carrying a hex-encoded KEK.
const envKEKName = "CULVERT_KEK"

// envKEKProvider sources the KEK from an environment variable holding a
// hex-encoded 32-byte key. It is the container/automation-friendly option
// (model C): the KEK never sits on the data disk.
type envKEKProvider struct {
	envName string
}

// Compile-time interface check.
var _ KEKProvider = (*envKEKProvider)(nil)

// newEnvKEKProvider returns a provider reading from the given env var name.
// An empty name defaults to CULVERT_KEK.
func newEnvKEKProvider(envName string) *envKEKProvider {
	if envName == "" {
		envName = envKEKName
	}
	return &envKEKProvider{envName: envName}
}

func (p *envKEKProvider) Name() string { return "env" }

// KEK decodes the hex KEK from the configured environment variable. A missing
// variable fails closed with errKEKMissing; a malformed or wrong-length value
// fails closed with a descriptive (key-free) error.
func (p *envKEKProvider) KEK() ([]byte, error) {
	raw, ok := os.LookupEnv(p.envName)
	if !ok || raw == "" {
		return nil, errKEKMissing
	}
	kek, err := hex.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("kek: env %s is not valid hex", p.envName)
	}
	if len(kek) != kekLen {
		return nil, fmt.Errorf("kek: env %s decodes to %d bytes (want %d)", p.envName, len(kek), kekLen)
	}
	return kek, nil
}

// ── Resolution ─────────────────────────────────────────────────────────────

// resolveKEKProvider selects a KEK provider deterministically: if the env var
// (envName, default CULVERT_KEK) is set and non-empty, the env provider (model
// C) is used; otherwise the file provider (model B) backed by filePath is used,
// which auto-generates the KEK file on first use.
//
// This mirrors the §5 resolution order minus the passphrase tier, which a later
// PR can add. It performs no I/O itself; the returned provider reads its source
// lazily on the first KEK() call so callers control when failures surface.
func resolveKEKProvider(envName, filePath string) KEKProvider {
	if envName == "" {
		envName = envKEKName
	}
	if v, ok := os.LookupEnv(envName); ok && v != "" {
		return newEnvKEKProvider(envName)
	}
	return newFileKEKProvider(filePath)
}

// kekEqual reports whether two KEKs are equal in constant time. Used by tests
// and any future rotation/verification path; never logs the inputs.
func kekEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
