package main

// CA-3 PR2 — cluster CA private key encryption at rest.
//
// This file adds at-rest encryption for the cluster CA private key
// (<dir>/cluster-ca.key) on top of the CA-3 KEK foundation (kek.go, PR #315).
// It is scoped to the CLUSTER CA private key only: no DP node key, no CDR key,
// no Root CA, no HA protocol, no backup wiring, no ConfigSnapshot/rollback, no
// UI/diagnostics.
//
// Design (roadmap/CA-3-KEY-AT-REST-DESIGN.md §5–§7):
//
//   - Activation is opt-in-first (§6 Phase 1): encryption of NEW writes /
//     migration of existing plaintext happens only when CULVERT_CLUSTER_CA_ENCRYPT
//     is truthy. When disabled, plaintext behavior is unchanged.
//
//   - The READ path is content-driven, NOT flag-driven: a key file that is a
//     PSCA envelope is always decrypted (fail closed if the KEK is
//     missing/wrong or the ciphertext is corrupt), regardless of the activation
//     flag. This guarantees an encrypted install is never silently treated as
//     plaintext or regenerated just because the flag was toggled off.
//
//   - loadFromPEM stays a pure plaintext-PEM parser; encryption lives only at
//     the disk read boundary (InitOrLoad) and the write boundaries (generate,
//     ImportCA, backupCAFiles). The HA path (ha.go ImportCASilent) and the
//     restore validator (restore.go) feed plaintext PEM to loadFromPEM and are
//     intentionally untouched by this PR.
//
//   - KEK material, decrypted key bytes, and plaintext PEM are never logged,
//     audited, or placed in metrics/ConfigSnapshot/rollback.

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// clusterCAEncryptEnvVar opts cluster CA key encryption in (opt-in-first).
const clusterCAEncryptEnvVar = "CULVERT_CLUSTER_CA_ENCRYPT"

// clusterCAKEKFileName is the model-B local KEK file for the cluster CA key,
// kept in the same directory as cluster-ca.key. It is independent of the Root
// CA's CULVERT_CA_PASSPHRASE and must be excluded from any backup that also
// contains cluster-ca.key (ADR §9 — backup wiring is a later PR).
const clusterCAKEKFileName = "cluster-ca.kek"

// clusterCAKeyEncryptionEnabled reports whether CA-3 at-rest encryption is
// enabled for the cluster CA private key. Default off (opt-in-first); enabled
// when CULVERT_CLUSTER_CA_ENCRYPT is a truthy value. Read on each call so tests
// can toggle via t.Setenv; the value is cheap to compute.
func clusterCAKeyEncryptionEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(clusterCAEncryptEnvVar))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// clusterCAKEKProvider resolves the KEK provider for the cluster CA key in dir.
// CULVERT_KEK (model C) takes precedence; otherwise a local file KEK at
// <dir>/cluster-ca.kek (model B, auto-generated 0600 on first use). Resolution
// is deterministic and performs no I/O until the KEK is actually needed.
func clusterCAKEKProvider(dir string) *secret.Provider {
	if dir == "" {
		dir = "."
	}
	// safeCAPath only fails on traversal in dir, which InitOrLoad/ImportCA have
	// already cleaned; fall back to a plain join on the (impossible) error path.
	kekPath, err := safeCAPath(dir, clusterCAKEKFileName)
	if err != nil {
		kekPath = clusterCAKEKFileName
	}
	return secret.ResolveProvider(secret.EnvKEKName, kekPath)
}

// isEncryptedKeyFile reports whether raw on-disk bytes are a PSCA envelope
// (the encrypted format produced by encryptBundle). Mirrors the magic check in
// ca.go LoadCA so the same detector governs both Root CA and cluster CA keys.
func isEncryptedKeyFile(data []byte) bool {
	return ca.HasBundleMagic(data)
}

// openClusterCAKey returns an opaque Sealed handle for raw on-disk key bytes.
// If the bytes are a PSCA envelope it decrypts with the resolved KEK and fails
// closed on any error (missing/wrong KEK, corrupt ciphertext/tag) — the caller
// must NOT regenerate the CA on failure. Plaintext bytes are wrapped unchanged.
// The returned bool reports whether the on-disk form was encrypted. Callers
// reach the plaintext only via Sealed.WithPlaintext (zeroized on return), so raw
// CA key bytes never cross back into package main as a plain []byte.
func openClusterCAKey(dir string, rawKey []byte) (*secret.Sealed, bool, error) {
	sealed, wasEncrypted, derr := secret.OpenOrPlaintext(rawKey, clusterCAKEKProvider(dir))
	if derr != nil {
		// Deliberately generic: no key material, no KEK detail.
		auditKeyAtRest(auditKeyAtRestUnlockFailed, keyAtRestObjClusterCA)
		return nil, wasEncrypted, fmt.Errorf("cluster CA key: cannot decrypt at-rest key (KEK missing/wrong or file corrupt)")
	}
	return sealed, wasEncrypted, nil
}

// writeClusterCAKey persists a plaintext key PEM to keyPath, encrypting it with
// the resolved KEK when encryption is enabled, otherwise writing plaintext.
// Both branches write 0600 atomically.
func writeClusterCAKey(dir, keyPath string, plainKeyPEM []byte) error {
	if clusterCAKeyEncryptionEnabled() {
		return secret.SealToFile(keyPath, plainKeyPEM, clusterCAKEKProvider(dir))
	}
	return fileutil.AtomicWrite(keyPath, plainKeyPEM, 0o600)
}

// migrateClusterCAKeyToEncrypted migrates an existing plaintext cluster CA key
// at keyPath to encrypted-at-rest, following the ADR §6 ordering:
//
//  1. copy the plaintext to <keyPath>.plaintext.bak BEFORE touching keyPath
//     (keyPath stays the readable key until the encrypted file is verified);
//  2. encrypt + atomically write ciphertext to keyPath;
//  3. verify decrypt + parse round-trip against the source;
//  4. on any failure, restore keyPath from the .bak so a readable key always
//     exists at either keyPath or the .bak.
//
// Idempotent: callers only invoke it when the on-disk key was plaintext, so a
// re-run after success (file now a PSCA envelope) is never reached. plainKeyPEM
// is the already-validated plaintext loaded by the caller.
func migrateClusterCAKeyToEncrypted(dir, keyPath string, plainKeyPEM []byte) (err error) {
	// CA-3 PR6 §10 audit: one completed/failed event per migration attempt.
	// Object is the logical subsystem name only — no path or key material.
	defer func() {
		if err != nil {
			auditKeyAtRest(auditKeyAtRestMigrateFailed, keyAtRestObjClusterCA)
		} else {
			auditKeyAtRest(auditKeyAtRestMigrateCompleted, keyAtRestObjClusterCA)
		}
	}()
	p := clusterCAKEKProvider(dir)
	bakPath := keyPath + ".plaintext.bak"

	// 1. Quarantine plaintext first (copy, not move).
	if err := fileutil.AtomicWrite(bakPath, plainKeyPEM, 0o600); err != nil {
		return fmt.Errorf("cluster CA key migration: quarantine plaintext: %w", err)
	}
	// 2. Encrypt + write ciphertext to the active path.
	if err := secret.SealToFile(keyPath, plainKeyPEM, p); err != nil {
		_ = restoreClusterCAKeyPlaintext(keyPath, bakPath)
		return fmt.Errorf("cluster CA key migration: encrypt+write: %w", err)
	}
	// 3. Verify decrypt + parse round-trip.
	if err := verifyEncryptedClusterCAKey(keyPath, plainKeyPEM, p); err != nil {
		_ = restoreClusterCAKeyPlaintext(keyPath, bakPath)
		return fmt.Errorf("cluster CA key migration: verify: %w", err)
	}
	logger.Printf("ClusterCA: migrated cluster CA private key to encrypted-at-rest " +
		"(plaintext quarantined at cluster-ca.key.plaintext.bak — remove after verifying recovery)")
	return nil
}

// verifyEncryptedClusterCAKey re-reads keyPath, decrypts it, parses the key, and
// confirms the decrypted bytes match the source plaintext. The decrypted bytes
// stay inside the WithPlaintext closure and are zeroized on return.
func verifyEncryptedClusterCAKey(keyPath string, wantPlainPEM []byte, p *secret.Provider) error {
	sealed, err := secret.OpenFile(keyPath, p)
	if err != nil {
		return err
	}
	return sealed.WithPlaintext(func(got []byte) error {
		block, _ := pem.Decode(got)
		if block == nil {
			return errors.New("decrypted key is not valid PEM")
		}
		if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
			return fmt.Errorf("decrypted key does not parse: %w", err)
		}
		if !bytes.Equal(got, wantPlainPEM) {
			return errors.New("decrypted key does not match source")
		}
		return nil
	})
}

// restoreClusterCAKeyPlaintext copies the quarantined plaintext back to keyPath
// so a readable key remains after a failed migration step.
func restoreClusterCAKeyPlaintext(keyPath, bakPath string) error {
	data, err := os.ReadFile(bakPath) // bakPath is internal, sibling of keyPath
	if err != nil {
		return err
	}
	return fileutil.AtomicWrite(keyPath, data, 0o600)
}
