package main

// CA-3 PR6 — tests for key-at-rest audit events + diagnostics status.
//
// Audit assertions use the actor/action/object/baselineTS content-discriminator
// pattern (hasMatchingAuditEntry), NOT len(auditGet()) deltas, so they survive
// audit-ring saturation under -count=2 -shuffle=on. t.TempDir; t.Setenv; no
// sleeps/retries.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
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
	if _, _, err := openClusterCAKey(dir, enc); err == nil {
		t.Fatal("expected decrypt to fail with wrong KEK")
	}
	if !hasMatchingAuditEntry(auditGet(), keyAtRestActor, auditKeyAtRestUnlockFailed, keyAtRestObjClusterCA, baseTS) {
		t.Fatal("expected keyatrest.unlock.failed audit entry for cluster-ca")
	}
}

// TestKeyAtRest_Audit_NoEventWhenPlaintextDecrypt: a plaintext key (passthrough)
// must NOT emit any key-at-rest audit event. The audit ring is a process-global
// shared by every test, so we cannot scan it for "any keyAtRest event since T"
// without false positives from concurrent/earlier tests. Instead we isolate the
// ring for this test (swap+restore) and assert that THIS call added no keyAtRest
// entry — the unlock-failed audit is only on the decrypt-error branch, which a
// plaintext passthrough never reaches.
func TestKeyAtRest_Audit_NoEventWhenPlaintextDecrypt(t *testing.T) {
	t.Cleanup(audit.SwapRingForTest())

	dir := t.TempDir()
	if _, wasEnc, err := openClusterCAKey(dir, dpTestKeyPEM(t)); err != nil || wasEnc {
		t.Fatalf("plaintext passthrough: err=%v wasEnc=%v", err, wasEnc)
	}
	for _, e := range auditGet() {
		if e.Actor == keyAtRestActor {
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

// TestCheckKeyAtRest_EnabledWithInvalidEnvKEKFails: a subsystem enabled while
// CULVERT_KEK is set to a malformed value must report FAIL (key unlock/migration
// will fail closed), not a false-healthy "file" fallback (Codex P2). The bad KEK
// value must not leak into the message.
func TestCheckKeyAtRest_EnabledWithInvalidEnvKEKFails(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "1")
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	t.Setenv(envKEKName, "not-valid-hex-kek") // set but malformed

	c := checkKeyAtRest()
	if c.Status != diagFail {
		t.Fatalf("status = %q, want fail for invalid CULVERT_KEK while enabled", c.Status)
	}
	if strings.Contains(c.Message, "KEK source: file") {
		t.Fatalf("must not report a healthy file fallback for an invalid env KEK: %q", c.Message)
	}
	if strings.Contains(c.Message, "not-valid-hex-kek") {
		t.Fatal("invalid KEK value leaked into diagnostics message")
	}
	if c.OperatorAction == "" {
		t.Fatal("expected an operator action for the invalid-KEK failure")
	}
}

// TestCheckKeyAtRest_DisabledWithInvalidEnvKEKWarns: an invalid CULVERT_KEK with
// all subsystems disabled is a latent misconfiguration → warn (it will break on
// enable), not a silent OK.
func TestCheckKeyAtRest_DisabledWithInvalidEnvKEKWarns(t *testing.T) {
	t.Setenv(clusterCAEncryptEnvVar, "")
	t.Setenv(dpNodeKeyEncryptEnvVar, "")
	t.Setenv(cdrClientKeyEncryptEnvVar, "")
	t.Setenv(envKEKName, "not-valid-hex-kek")

	c := checkKeyAtRest()
	if c.Status != diagWarn {
		t.Fatalf("status = %q, want warn for invalid CULVERT_KEK while disabled", c.Status)
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

// resetPlaintextKeyBackupGlobals isolates the three package globals
// plaintextKeyBackupCandidates() reads (globalClusterCA, activeDPClient,
// cdrInstances) for the duration of the calling test, restoring the prior
// values on cleanup — the same swap pattern already used by
// cluster_audit_test.go / dp_last_good_config_test.go / cdrstore_test.go.
func resetPlaintextKeyBackupGlobals(t *testing.T) {
	t.Helper()
	origCA := globalClusterCA
	origDP := activeDPClient.Load()
	origCDR := cdrInstances
	globalClusterCA = &clusterCA{}
	activeDPClient.Store(nil)
	cdrInstances = &CDRInstanceRegistry{}
	t.Cleanup(func() {
		globalClusterCA = origCA
		activeDPClient.Store(origDP)
		cdrInstances = origCDR
	})
}

// TestCheckPlaintextKeyBackups_NoneBootstrappedIsOK: with no cluster CA, no
// active DP client, and no enrolled CDR instances, there is nothing to scan
// and the check reports OK.
func TestCheckPlaintextKeyBackups_NoneBootstrappedIsOK(t *testing.T) {
	resetPlaintextKeyBackupGlobals(t)
	c := checkPlaintextKeyBackups()
	if c.Code != "plaintext_key_backup" || c.Status != diagOK {
		t.Fatalf("unexpected check: %+v", c)
	}
}

// TestCheckPlaintextKeyBackups_ClusterCA: a lingering cluster-ca.key.plaintext.bak
// is reported as a warning naming the cluster-ca subsystem, with an operator
// action, and never the file path.
func TestCheckPlaintextKeyBackups_ClusterCA(t *testing.T) {
	resetPlaintextKeyBackupGlobals(t)
	dir := t.TempDir()
	globalClusterCA = &clusterCA{dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.key.plaintext.bak"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	c := checkPlaintextKeyBackups()
	if c.Status != diagWarn {
		t.Fatalf("status = %q, want warn", c.Status)
	}
	if !strings.Contains(c.Message, keyAtRestObjClusterCA) {
		t.Fatalf("expected cluster-ca in message: %q", c.Message)
	}
	if c.OperatorAction == "" {
		t.Fatal("expected an operator action")
	}
	if strings.Contains(c.Message, dir) {
		t.Fatalf("path leaked into diagnostics message: %q", c.Message)
	}
}

// TestCheckPlaintextKeyBackups_DPNodeAndCDR: lingering backups for the DP
// node key and an enrolled CDR client key are both reported together.
func TestCheckPlaintextKeyBackups_DPNodeAndCDR(t *testing.T) {
	resetPlaintextKeyBackupGlobals(t)
	dir := t.TempDir()

	dpKey := filepath.Join(dir, "dp-node.key")
	if err := os.WriteFile(dpKey+".plaintext.bak", []byte("x"), 0o600); err != nil {
		t.Fatalf("write dp backup: %v", err)
	}
	activeDPClient.Store(&DataPlaneClient{keyFile: dpKey})

	cdrKey := filepath.Join(dir, "cdr-client.key")
	if err := os.WriteFile(cdrKey+".plaintext.bak", []byte("x"), 0o600); err != nil {
		t.Fatalf("write cdr backup: %v", err)
	}
	if _, err := cdrInstances.Add(CDREnrolledInstance{
		Name:              "sluice-1",
		Endpoint:          "sluice.example.internal:443",
		ServerFingerprint: strings.Repeat("ab", 32),
		CACertPath:        filepath.Join(dir, "ca.crt"),
		ClientCertPath:    filepath.Join(dir, "cdr-client.crt"),
		ClientKeyPath:     cdrKey,
	}); err != nil {
		t.Fatalf("add cdr instance: %v", err)
	}

	c := checkPlaintextKeyBackups()
	if c.Status != diagWarn {
		t.Fatalf("status = %q, want warn", c.Status)
	}
	if !strings.Contains(c.Message, keyAtRestObjDPNode) {
		t.Fatalf("expected dp-node in message: %q", c.Message)
	}
	if !strings.Contains(c.Message, keyAtRestObjCDRClient) {
		t.Fatalf("expected cdr-client in message: %q", c.Message)
	}
}

// TestCheckPlaintextKeyBackups_InOperatorContract: the check is wired into
// the aggregated operator contract returned by /api/diagnostics.
func TestCheckPlaintextKeyBackups_InOperatorContract(t *testing.T) {
	oc := buildOperatorContract()
	for _, c := range oc.Checks {
		if c.Code == "plaintext_key_backup" {
			return
		}
	}
	t.Fatal("plaintext_key_backup check missing from operator contract")
}
