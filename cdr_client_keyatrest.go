package main

// CA-3 PR3b — CDR/Sluice client private key encryption at rest.
//
// Adds at-rest encryption for the CDR/Sluice client private key (the per-
// instance ClientKeyPath written by cdr_health.go and read by cdr_pool.go via
// loadCDRCertBundle) on top of the CA-3 KEK foundation (kek.go, PR #315) and
// the shared detector/parse helpers (cluster_ca_keyatrest.go #319,
// dp_node_keyatrest.go #320). Scoped to the CDR client private key ONLY: no
// cluster CA, no DP node key, no Root CA, no HA protocol, no backup wiring, no
// ConfigSnapshot/rollback, no UI/diagnostics.
//
// Design (roadmap/CA-3-KEY-AT-REST-DESIGN.md §5–§7):
//
//   - Opt-in-first: new writes (RenewCert persistence) and migration of an
//     existing plaintext key happen only when CULVERT_CDR_CLIENT_KEY_ENCRYPT is
//     truthy. Default off → plaintext behavior unchanged.
//
//   - The READ/load path is content-driven, NOT flag-driven: a key file that is
//     a PSCA envelope is always decrypted (fail closed on missing/wrong KEK or
//     corruption), regardless of the flag. A decrypt failure NEVER triggers
//     silent regeneration/re-enrollment.
//
//   - Only the private-key path changes. The client cert and the CA cert remain
//     plaintext public certs.
//
//   - Instance-local: the KEK is anchored to the specific key file
//     (<keyPath>.kek), so one CDR instance's KEK/key never affects another.
//
//   - KEK material, decrypted key bytes, and plaintext PEM are never logged,
//     audited, or placed in metrics/ConfigSnapshot/rollback.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// cdrClientKeyEncryptEnvVar opts CDR client key encryption in (opt-in-first).
const cdrClientKeyEncryptEnvVar = "CULVERT_CDR_CLIENT_KEY_ENCRYPT"

// cdrClientKEKSuffix names the model-B local KEK file for a CDR client key. It
// is anchored to the key file itself (<keyPath>.kek) so each enrolled instance
// has an independent KEK. Must be excluded from any backup that also contains
// the encrypted client key (ADR §9 — backup wiring is a later PR).
const cdrClientKEKSuffix = ".kek"

// cdrClientKeyEncryptionEnabled reports whether CA-3 at-rest encryption is
// enabled for CDR client keys. Default off (opt-in-first); enabled when
// CULVERT_CDR_CLIENT_KEY_ENCRYPT is truthy. Read on each call (cheap; lets tests
// toggle via t.Setenv).
func cdrClientKeyEncryptionEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(cdrClientKeyEncryptEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// cdrClientKEKProvider resolves the KEK provider for a specific CDR client key.
// CULVERT_KEK (model C) takes precedence; otherwise a per-key-file local KEK at
// <keyPath>.kek (model B, auto-generated 0600 on first use). Anchoring to the
// key file keeps instances isolated. Deterministic; no I/O until the KEK is
// actually needed.
func cdrClientKEKProvider(keyPath string) KEKProvider {
	return resolveKEKProvider(envKEKName, filepath.Clean(keyPath)+cdrClientKEKSuffix)
}

// decryptCDRClientKey returns the plaintext key PEM for raw on-disk CDR client
// key bytes. If the bytes are a PSCA envelope it decrypts with the resolved KEK
// and fails closed on any error (missing/wrong KEK, corrupt ciphertext/tag) —
// the caller must NOT regenerate/re-enroll on failure. Plaintext bytes pass
// through unchanged. The returned bool reports whether the on-disk form was
// encrypted.
func decryptCDRClientKey(keyPath string, rawKey []byte) (plainPEM []byte, wasEncrypted bool, err error) {
	if !isEncryptedKeyFile(rawKey) {
		return rawKey, false, nil
	}
	plain, derr := decryptWithKEK(rawKey, cdrClientKEKProvider(keyPath))
	if derr != nil {
		// Deliberately generic: no key material, no KEK detail.
		auditKeyAtRest(auditKeyAtRestUnlockFailed, keyAtRestObjCDRClient)
		return nil, true, fmt.Errorf("cdr client key: cannot decrypt at-rest key (KEK missing/wrong or file corrupt)")
	}
	return plain, true, nil
}

// encodeCDRClientKeyForWrite returns the bytes to persist for a freshly issued
// plaintext client key PEM: an encrypted PSCA envelope when encryption is
// enabled, or the plaintext unchanged otherwise. The caller writes the result
// with its existing atomic tmp+rename flow.
func encodeCDRClientKeyForWrite(keyPath string, plainKeyPEM []byte) ([]byte, error) {
	if !cdrClientKeyEncryptionEnabled() {
		return plainKeyPEM, nil
	}
	return encryptWithKEK(plainKeyPEM, cdrClientKEKProvider(keyPath))
}

// maybeMigrateCDRClientKey migrates an existing plaintext CDR client key at
// keyPath to encrypted-at-rest when encryption is enabled. No-op when disabled,
// when the file is absent, or when it is already a PSCA envelope (idempotent).
// Instance-local: only touches the given key file. Called at the load point
// (loadCDRCertBundle) for the specific instance, not at a global startup.
func maybeMigrateCDRClientKey(keyPath string) error {
	if !cdrClientKeyEncryptionEnabled() {
		return nil
	}
	raw, err := os.ReadFile(filepath.Clean(keyPath))
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing enrolled yet for this instance
	}
	if err != nil {
		return fmt.Errorf("cdr client key read: %w", err)
	}
	if isEncryptedKeyFile(raw) {
		return nil // already encrypted — idempotent
	}
	// Accept any key format the TLS stack accepts (PKCS#8 / EC / RSA): the CDR
	// server issues the key, so don't assume ECDSA.
	if perr := parseAnyPrivateKeyPEM(raw); perr != nil {
		return fmt.Errorf("cdr client key: existing key not parseable; refusing to migrate: %w", perr)
	}
	return migrateCDRClientKeyToEncrypted(keyPath, raw)
}

// migrateCDRClientKeyToEncrypted follows the ADR §6 ordering:
//  1. copy plaintext to <keyPath>.plaintext.bak BEFORE touching keyPath;
//  2. encrypt + atomically write ciphertext to keyPath;
//  3. verify decrypt + parse round-trip;
//  4. on any failure, restore keyPath from the .bak.
//
// A readable key always exists at either keyPath or the .bak throughout.
func migrateCDRClientKeyToEncrypted(keyPath string, plainKeyPEM []byte) (err error) {
	// CA-3 PR6 §10 audit: one completed/failed event per migration attempt.
	defer func() {
		if err != nil {
			auditKeyAtRest(auditKeyAtRestMigrateFailed, keyAtRestObjCDRClient)
		} else {
			auditKeyAtRest(auditKeyAtRestMigrateCompleted, keyAtRestObjCDRClient)
		}
	}()
	p := cdrClientKEKProvider(keyPath)
	bakPath := keyPath + ".plaintext.bak"

	if err := atomicWriteFile(bakPath, plainKeyPEM, 0o600); err != nil {
		return fmt.Errorf("cdr client key migration: quarantine plaintext: %w", err)
	}
	if err := writeEncryptedFile(keyPath, plainKeyPEM, p); err != nil {
		_ = restoreCDRClientKeyPlaintext(keyPath, bakPath)
		return fmt.Errorf("cdr client key migration: encrypt+write: %w", err)
	}
	if err := verifyEncryptedCDRClientKey(keyPath, plainKeyPEM, p); err != nil {
		_ = restoreCDRClientKeyPlaintext(keyPath, bakPath)
		return fmt.Errorf("cdr client key migration: verify: %w", err)
	}
	logger.Printf("CDR: migrated client private key to encrypted-at-rest " +
		"(plaintext quarantined at <key>.plaintext.bak — remove after verifying recovery)")
	return nil
}

// verifyEncryptedCDRClientKey re-reads keyPath, decrypts it, parses the key, and
// confirms the decrypted bytes match the source plaintext.
func verifyEncryptedCDRClientKey(keyPath string, wantPlainPEM []byte, p KEKProvider) error {
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

// restoreCDRClientKeyPlaintext copies the quarantined plaintext back to keyPath
// so a readable key remains after a failed migration step.
func restoreCDRClientKeyPlaintext(keyPath, bakPath string) error {
	data, err := os.ReadFile(bakPath) // bakPath is internal, sibling of keyPath
	if err != nil {
		return err
	}
	return atomicWriteFile(keyPath, data, 0o600)
}
