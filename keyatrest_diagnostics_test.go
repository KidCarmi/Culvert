package main

// CA-3 PR6 — tests for key-at-rest audit events + diagnostics status.
//
// Audit assertions use the actor/action/object/baselineTS content-discriminator
// pattern (hasMatchingAuditEntry), NOT len(auditGet()) deltas, so they survive
// audit-ring saturation under -count=2 -shuffle=on. t.TempDir; t.Setenv; no
// sleeps/retries.

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKeyAtRest_Audit_MigrateCompleted: a successful cluster-CA plaintext→
// encrypted migration emits keyatrest.migrate.completed (object=cluster-ca).
func TestKeyAtRest_Audit_MigrateCompleted(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cluster-ca.key")
	plain := dpTestKeyPEM(t)

	baseTS := time.Now().UnixMilli()
	if err := migrateClusterCAKeyToEncrypted(dir, keyPath, plain); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !hasMatchingAuditEntry(auditGet(), keyAtRestActor, auditKeyAtRestMigrateCompleted, keyAtRestObjClusterCA, baseTS) {
		t.Fatal("expected keyatrest.migrate.completed audit entry for cluster-ca")
	}
}

// TestKeyAtRest_Audit_MigrateFailed: a migration that fails (malformed env KEK)
// emits keyatrest.migrate.failed.
func TestKeyAtRest_Audit_MigrateFailed(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(envKEKName, "not-valid-hex")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cluster-ca.key")

	baseTS := time.Now().UnixMilli()
	if err := migrateClusterCAKeyToEncrypted(dir, keyPath, dpTestKeyPEM(t)); err == nil {
		t.Fatal("expected migration to fail with malformed KEK")
	}
	if !hasMatchingAuditEntry(auditGet(), keyAtRestActor, auditKeyAtRestMigrateFailed, keyAtRestObjClusterCA, baseTS) {
		t.Fatal("expected keyatrest.migrate.failed audit entry for cluster-ca")
	}
}

// TestKeyAtRest_Audit_UnlockFailed: a decrypt failure (missing KEK) emits
// keyatrest.unlock.failed for each subsystem.
func TestKeyAtRest_Audit_UnlockFailed(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(envKEKName, "")
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "cluster-ca.key")
	// Produce an encrypted key, then remove the KEK so decrypt fails.
	if err := writeClusterCAKey(dir, keyPath, dpTestKeyPEM(t)); err != nil {
		t.Fatalf("write: %v", err)
	}
	enc := readFile(t, keyPath)

	baseTS := time.Now().UnixMilli()
	t.Setenv(envKEKName, "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100") // wrong KEK
	if _, _, err := decryptClusterCAKey(dir, enc); err == nil {
		t.Fatal("expected decrypt to fail with wrong KEK")
	}
	if !hasMatchingAuditEntry(auditGet(), keyAtRestActor, auditKeyAtRestUnlockFailed, keyAtRestObjClusterCA, baseTS) {
		t.Fatal("expected keyatrest.unlock.failed audit entry for cluster-ca")
	}
}

// TestKeyAtRest_Audit_NoEventWhenPlaintextDecrypt: a plaintext key (passthrough)
// must NOT emit any key-at-rest audit event.
func TestKeyAtRest_Audit_NoEventWhenPlaintextDecrypt(t *testing.T) {
	dir := t.TempDir()
	baseTS := time.Now().UnixMilli()
	if _, wasEnc, err := decryptClusterCAKey(dir, dpTestKeyPEM(t)); err != nil || wasEnc {
		t.Fatalf("plaintext passthrough: err=%v wasEnc=%v", err, wasEnc)
	}
	for _, e := range auditGet() {
		if e.Actor == keyAtRestActor && e.TS >= baseTS {
			t.Fatalf("unexpected key-at-rest audit event on plaintext passthrough: %s", e.Action)
		}
	}
}

// TestCheckKeyAtRest_DisabledIsOK: with no subsystem enabled, the diagnostics
// check reports OK and the disabled message — and never any key material.
func TestCheckKeyAtRest_DisabledIsOK(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "")
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	c := checkKeyAtRest()
	if c.Code != "key_at_rest" || c.Status != diagOK {
		t.Fatalf("unexpected check: %+v", c)
	}
	if !strings.Contains(c.Message, "disabled") {
		t.Fatalf("expected disabled message, got %q", c.Message)
	}
}

// TestCheckKeyAtRest_EnabledListsSubsystemsAndSource: enabled subsystems are
// listed by logical name, and the KEK source enum is reported — with no key/
// fingerprint/path content.
func TestCheckKeyAtRest_EnabledListsSubsystemsAndSource(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(dpNodeKeyEncryptEnvVar, "1")
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	// env KEK present → source "env".
	t.Setenv(envKEKName, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	c := checkKeyAtRest()
	if c.Status != diagOK {
		t.Fatalf("status = %q, want ok", c.Status)
	}
	if !strings.Contains(c.Message, keyAtRestObjClusterCA) || !strings.Contains(c.Message, keyAtRestObjDPNode) {
		t.Fatalf("message should list enabled subsystems: %q", c.Message)
	}
	if strings.Contains(c.Message, keyAtRestObjCDRClient) {
		t.Fatalf("cdr-client is disabled and must not be listed: %q", c.Message)
	}
	if !strings.Contains(c.Message, "KEK source: env") {
		t.Fatalf("expected env KEK source: %q", c.Message)
	}
	// The KEK bytes / hex must never appear in operator-facing output.
	if strings.Contains(c.Message, "00112233") {
		t.Fatal("KEK bytes leaked into diagnostics message")
	}
}

// TestCheckKeyAtRest_InOperatorContract: the check is wired into the aggregated
// operator contract returned by /api/diagnostics.
func TestCheckKeyAtRest_InOperatorContract(t *testing.T) {
	oc := buildOperatorContract()
	found := false
	for _, c := range oc.Checks {
		if c.Code == "key_at_rest" {
			found = true
		}
	}
	if !found {
		t.Fatal("key_at_rest check missing from operator contract")
	}
}
