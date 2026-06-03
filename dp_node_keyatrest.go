package main

// CA-3 PR3 — DP node private key encryption at rest.
//
// Adds at-rest encryption for the Data Plane node private key (./dp-node.key)
// on top of the CA-3 KEK foundation (kek.go, PR #315) and the shared detector
// helpers introduced for the cluster CA key (cluster_ca_keyatrest.go, PR #319).
// Scoped to the DP node private key ONLY: no cluster CA key, no CDR key, no
// Root CA, no HA protocol, no backup wiring, no ConfigSnapshot/rollback, no
// UI/diagnostics.
//
// Design (roadmap/CA-3-KEY-AT-REST-DESIGN.md §5–§7):
//
//   - Activation is opt-in-first: encryption of NEW writes (enrollment +
//     renewal persistence) and migration of an existing plaintext key happen
//     only when CULVERT_DP_NODE_KEY_ENCRYPT is truthy. Default off → plaintext
//     behavior unchanged.
//
//   - The READ path (buildClientTLS) is content-driven, NOT flag-driven: a key
//     file that is a PSCA envelope is always decrypted (fail closed on
//     missing/wrong KEK or corruption), regardless of the activation flag. A
//     decrypt failure NEVER triggers silent regeneration or re-enrollment.
//
//   - Only the private-key path changes. The DP cert (dp-node.crt) and the
//     trusted cluster CA cert (cluster-ca.crt) remain plaintext PEM.
//
//   - KEK material, decrypted key bytes, and plaintext PEM are never logged,
//     audited, or placed in metrics/ConfigSnapshot/rollback.

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// dpNodeKeyEncryptEnvVar opts DP node key encryption in (opt-in-first).
const dpNodeKeyEncryptEnvVar = "CULVERT_DP_NODE_KEY_ENCRYPT"

// dpNodeKEKFileName is the model-B local KEK file for the DP node key, kept in
// the same directory as the key. Independent of the Root CA passphrase and the
// cluster CA KEK; must be excluded from any backup that also contains the
// encrypted DP key (ADR §9 — backup wiring is a later PR).
const dpNodeKEKFileName = "dp-node.kek"

// dpNodeKeyEncryptionEnabled reports whether CA-3 at-rest encryption is enabled
// for the DP node private key. Default off (opt-in-first); enabled when
// CULVERT_DP_NODE_KEY_ENCRYPT is truthy. Read on each call (cheap; lets tests
// toggle via t.Setenv).
func dpNodeKeyEncryptionEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(dpNodeKeyEncryptEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// dpNodeKEKProvider resolves the KEK provider for the DP node key. CULVERT_KEK
// (model C) takes precedence; otherwise a local file KEK at <keydir>/dp-node.kek
// (model B, auto-generated 0600 on first use). Deterministic; no I/O until the
// KEK is actually needed.
func dpNodeKEKProvider(keyPath string) KEKProvider {
	dir := filepath.Dir(keyPath)
	if dir == "" {
		dir = "."
	}
	return resolveKEKProvider(envKEKName, filepath.Join(dir, dpNodeKEKFileName))
}

// decryptDPNodeKey returns the plaintext key PEM for raw on-disk DP key bytes.
// If the bytes are a PSCA envelope it decrypts with the resolved KEK and fails
// closed on any error (missing/wrong KEK, corrupt ciphertext/tag) — the caller
// must NOT regenerate/re-enroll on failure. Plaintext bytes pass through
// unchanged. The returned bool reports whether the on-disk form was encrypted.
func decryptDPNodeKey(keyPath string, rawKey []byte) (plainPEM []byte, wasEncrypted bool, err error) {
	if !isEncryptedKeyFile(rawKey) {
		return rawKey, false, nil
	}
	plain, derr := decryptWithKEK(rawKey, dpNodeKEKProvider(keyPath))
	if derr != nil {
		// Deliberately generic: no key material, no KEK detail.
		auditKeyAtRest(auditKeyAtRestUnlockFailed, keyAtRestObjDPNode)
		return nil, true, fmt.Errorf("DP node key: cannot decrypt at-rest key (KEK missing/wrong or file corrupt)")
	}
	return plain, true, nil
}

// loadDPNodeKeyPair reads the DP cert (always plaintext) and the DP key
// (decrypting if it is a PSCA envelope) and assembles a tls.Certificate. This
// replaces a direct tls.LoadX509KeyPair so the key read becomes encryption-aware
// while the cert read is unchanged.
func loadDPNodeKeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Clean(certFile)) // cert is public, plaintext PEM
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("DP node cert read: %w", err)
	}
	rawKey, err := os.ReadFile(filepath.Clean(keyFile))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("DP node key read: %w", err)
	}
	keyPEM, _, err := decryptDPNodeKey(keyFile, rawKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

// writeDPNodeKey persists a plaintext key PEM to keyPath, encrypting it with the
// resolved KEK when encryption is enabled, otherwise writing plaintext. Both
// branches write 0600 atomically.
func writeDPNodeKey(keyPath string, plainKeyPEM []byte) error {
	if dpNodeKeyEncryptionEnabled() {
		return writeEncryptedFile(keyPath, plainKeyPEM, dpNodeKEKProvider(keyPath))
	}
	return atomicWriteFile(keyPath, plainKeyPEM, 0o600)
}

// maybeMigrateDPNodeKey migrates an existing plaintext DP node key at keyPath to
// encrypted-at-rest when encryption is enabled. It is a no-op when encryption is
// disabled, when the file is absent, or when the file is already a PSCA
// envelope (idempotent). Intended to be called once at the DP startup load
// point (startDataPlane), not on every reconnect.
//
// A decrypt-only failure here (envelope present but unreadable) is surfaced so
// the caller can fail closed; it is NOT a migration.
func maybeMigrateDPNodeKey(keyPath string) error {
	if !dpNodeKeyEncryptionEnabled() {
		return nil
	}
	raw, err := os.ReadFile(filepath.Clean(keyPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing enrolled yet
	}
	if err != nil {
		return fmt.Errorf("DP node key read: %w", err)
	}
	if isEncryptedKeyFile(raw) {
		return nil // already encrypted — idempotent
	}
	// Validate it parses as a private key before rewriting anything. Accept any
	// format TLS accepts (EC / PKCS#8 / PKCS#1 RSA): a manually-provisioned DP
	// node (-dp-key) may carry a non-EC key that previously loaded via
	// tls.LoadX509KeyPair, and migration must not lock those nodes out.
	if err := parseAnyPrivateKeyPEM(raw); err != nil {
		return fmt.Errorf("DP node key: existing key not parseable; refusing to migrate: %w", err)
	}
	return migrateDPNodeKeyToEncrypted(keyPath, raw)
}

// migrateDPNodeKeyToEncrypted follows the ADR §6 ordering:
//  1. copy plaintext to <keyPath>.plaintext.bak BEFORE touching keyPath;
//  2. encrypt + atomically write ciphertext to keyPath;
//  3. verify decrypt + parse round-trip;
//  4. on any failure, restore keyPath from the .bak.
//
// A readable key always exists at either keyPath or the .bak throughout.
func migrateDPNodeKeyToEncrypted(keyPath string, plainKeyPEM []byte) (err error) {
	// CA-3 PR6 §10 audit: one completed/failed event per migration attempt.
	defer func() {
		if err != nil {
			auditKeyAtRest(auditKeyAtRestMigrateFailed, keyAtRestObjDPNode)
		} else {
			auditKeyAtRest(auditKeyAtRestMigrateCompleted, keyAtRestObjDPNode)
		}
	}()
	p := dpNodeKEKProvider(keyPath)
	bakPath := keyPath + ".plaintext.bak"

	if err := atomicWriteFile(bakPath, plainKeyPEM, 0o600); err != nil {
		return fmt.Errorf("DP node key migration: quarantine plaintext: %w", err)
	}
	if err := writeEncryptedFile(keyPath, plainKeyPEM, p); err != nil {
		_ = restoreDPNodeKeyPlaintext(keyPath, bakPath)
		return fmt.Errorf("DP node key migration: encrypt+write: %w", err)
	}
	if err := verifyEncryptedDPNodeKey(keyPath, plainKeyPEM, p); err != nil {
		_ = restoreDPNodeKeyPlaintext(keyPath, bakPath)
		return fmt.Errorf("DP node key migration: verify: %w", err)
	}
	logger.Printf("DataPlane: migrated DP node private key to encrypted-at-rest " +
		"(plaintext quarantined at dp-node.key.plaintext.bak — remove after verifying recovery)")
	return nil
}

// verifyEncryptedDPNodeKey re-reads keyPath, decrypts it, parses the key, and
// confirms the decrypted bytes match the source plaintext.
func verifyEncryptedDPNodeKey(keyPath string, wantPlainPEM []byte, p KEKProvider) error {
	got, err := readEncryptedFile(keyPath, p)
	if err != nil {
		return err
	}
	if err := parseAnyPrivateKeyPEM(got); err != nil {
		return fmt.Errorf("decrypted key does not parse: %w", err)
	}
	if !bytes.Equal(got, wantPlainPEM) {
		return errors.New("decrypted key does not match source")
	}
	return nil
}

// parseAnyPrivateKeyPEM verifies that pemBytes contains a private key in any
// format the TLS stack accepts (PKCS#8, PKCS#1 RSA, or SEC1 EC) — the same set
// tls.X509KeyPair tolerates. Used to validate a DP node key before/after
// migration without assuming ECDSA.
func parseAnyPrivateKeyPEM(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("not valid PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return nil
	}
	return errors.New("unsupported private key format (want PKCS#8, EC, or PKCS#1)")
}

// restoreDPNodeKeyPlaintext copies the quarantined plaintext back to keyPath so
// a readable key remains after a failed migration step.
func restoreDPNodeKeyPlaintext(keyPath, bakPath string) error {
	data, err := os.ReadFile(bakPath) // bakPath is internal, sibling of keyPath
	if err != nil {
		return err
	}
	return atomicWriteFile(keyPath, data, 0o600)
}
