package main

// CA-3 PR5 — HA composition / plaintext CA-key fallback removal tests.
//
// Verifies the HA leader→standby cluster CA transfer is encrypted-only (no
// plaintext CAKeyPEM), fails closed on a missing/invalid encrypted key, and
// that the standby persists the replicated CA at rest through the CA-3 cluster
// CA write path (#319) — encrypted iff CULVERT_CLUSTER_CA_ENCRYPT is set on the
// standby itself (per-node KEK; no shared at-rest KEK). Globals snapshot/
// restored; env via t.Setenv; t.TempDir; no sleeps/retries.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withClusterCAForHA points globalClusterCA at a fresh CA bootstrapped in dir
// and restores the original on cleanup. Returns the decrypted plaintext key PEM
// and cert PEM for building HA bundles.
func withClusterCAForHA(t *testing.T, dir string) (certPEM, keyPEM []byte) {
	t.Helper()
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })

	// Bootstrap a plaintext CA in a separate dir purely to mint a valid pair.
	srcDir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "") // plaintext source pair
	if err := (&clusterCA{}).InitOrLoad(srcDir); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	certPEM = readFile(t, filepath.Join(srcDir, "cluster-ca.crt"))
	keyPEM = readFile(t, filepath.Join(srcDir, "cluster-ca.key"))

	// The live (standby) cluster CA persists into dir.
	globalClusterCA = &clusterCA{dir: filepath.Clean(dir)}
	return certPEM, keyPEM
}

// TestHA_PR5_ApplyReplicatedCA_PersistsEncryptedWhenEnabled: a standby with
// CULVERT_CLUSTER_CA_ENCRYPT=true persists an encrypted cluster-ca.key after
// applying a replicated CA, and the cert stays plaintext.
func TestHA_PR5_ApplyReplicatedCA_PersistsEncryptedWhenEnabled(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := withClusterCAForHA(t, dir)

	const token = "ha-token-pr5-enabled" // #nosec G101 -- synthetic test fixture; never leaves this test
	enc, err := haEncryptKey(keyPEM, token)
	if err != nil {
		t.Fatalf("haEncryptKey: %v", err)
	}

	t.Setenv(clusterCAEncryptEnvVar, "true") // standby-local at-rest encryption
	t.Setenv(envKEKName, "")
	if err := applyReplicatedCA(certPEM, enc, token); err != nil {
		t.Fatalf("applyReplicatedCA: %v", err)
	}
	if !globalClusterCA.Ready() {
		t.Fatal("cluster CA not ready after replicate")
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	if !isEncryptedKeyFile(readFile(t, keyPath)) {
		t.Fatal("standby cluster-ca.key not encrypted at rest when enabled")
	}
	if isEncryptedKeyFile(readFile(t, filepath.Join(dir, "cluster-ca.crt"))) {
		t.Fatal("cluster-ca.crt must remain a plaintext cert")
	}
	// And it reloads cleanly from the encrypted at-rest copy.
	reload := &clusterCA{}
	if err := reload.InitOrLoad(dir); err != nil {
		t.Fatalf("reload encrypted standby CA: %v", err)
	}
}

// TestHA_PR5_ApplyReplicatedCA_PersistsPlaintextWhenDisabled: with encryption
// off on the standby, the replicated key persists as plaintext (unchanged).
func TestHA_PR5_ApplyReplicatedCA_PersistsPlaintextWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := withClusterCAForHA(t, dir)

	const token = "ha-token-pr5-disabled" // #nosec G101 -- synthetic test fixture; never leaves this test
	enc, err := haEncryptKey(keyPEM, token)
	if err != nil {
		t.Fatalf("haEncryptKey: %v", err)
	}

	t.Setenv(clusterCAEncryptEnvVar, "") // disabled on standby
	if err := applyReplicatedCA(certPEM, enc, token); err != nil {
		t.Fatalf("applyReplicatedCA: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	raw := readFile(t, keyPath)
	if isEncryptedKeyFile(raw) {
		t.Fatal("standby key encrypted while disabled")
	}
	if !bytes.Equal(raw, keyPEM) {
		t.Fatal("persisted plaintext key does not match replicated key")
	}
}

// TestHA_PR5_ApplyReplicatedCA_MissingEncryptedKeyFailsClosed: no plaintext
// fallback — an empty CAKeyEncrypted is rejected, not silently accepted.
func TestHA_PR5_ApplyReplicatedCA_MissingEncryptedKeyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	certPEM, _ := withClusterCAForHA(t, dir)

	if err := applyReplicatedCA(certPEM, "", "any-token"); err == nil {
		t.Fatal("expected fail-closed when encrypted CA key is missing")
	}
	if globalClusterCA.Ready() {
		t.Fatal("cluster CA must not be set from a keyless bundle")
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.key")); err == nil {
		t.Fatal("no key should have been persisted on fail-closed")
	}
}

// TestHA_PR5_ApplyReplicatedCA_WrongTokenFailsClosed: a bundle encrypted under a
// different HA token cannot be decrypted and must fail closed.
func TestHA_PR5_ApplyReplicatedCA_WrongTokenFailsClosed(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := withClusterCAForHA(t, dir)

	enc, err := haEncryptKey(keyPEM, "correct-token")
	if err != nil {
		t.Fatalf("haEncryptKey: %v", err)
	}
	if err := applyReplicatedCA(certPEM, enc, "wrong-token"); err == nil {
		t.Fatal("expected fail-closed with wrong HA token")
	}
	if globalClusterCA.Ready() {
		t.Fatal("cluster CA must not be set when decrypt fails")
	}
}

// TestHA_PR5_PartialApply_CAFailureDoesNotImportState: a bundle with a cert but
// missing CAKeyEncrypted must fail closed BEFORE any unrelated replicated state
// (cluster state / config snapshot) is applied.
func TestHA_PR5_PartialApply_CAFailureDoesNotImportState(t *testing.T) {
	dir := t.TempDir()
	certPEM, _ := withClusterCAForHA(t, dir)

	// Fresh cluster store + config store; record the pre-apply state so we can
	// prove nothing was imported.
	origStore := globalClusterStore
	origConfig := globalConfigStore
	t.Cleanup(func() {
		globalClusterStore = origStore
		globalConfigStore = origConfig
	})
	globalClusterStore = newTestClusterStore(t)
	globalConfigStore = &ConfigStore{}
	beforeVersion := globalConfigStore.Get().Version

	// A bundle carrying real cluster state + config, but NO encrypted CA key.
	bundle := &HAStateBundle{
		ClusterState:   buildHANonEmptyClusterState(t),
		CACertPEM:      string(certPEM),
		CAKeyEncrypted: "", // missing → must fail closed
		Config:         ConfigSnapshot{RateLimitRPM: 4242},
		Version:        99,
	}

	if applyHABundle(bundle, "any-token") {
		t.Fatal("applyHABundle should return false when the CA key is missing")
	}
	// Cluster state must NOT have been imported.
	if n := len(globalClusterStore.ListNodes()); n != 0 {
		t.Fatalf("cluster state was partially applied on a failed CA sync (%d nodes)", n)
	}
	// Config snapshot must NOT have been applied (version unchanged, marker absent).
	if globalConfigStore.Get().Version != beforeVersion {
		t.Fatal("config snapshot was applied on a failed CA sync")
	}
	// Live CA must be unchanged (the throwaway probe validated, never mutated it).
	if globalClusterCA.Ready() {
		t.Fatal("live cluster CA was mutated on a failed sync")
	}
}

func TestApplyHABundlePolicySaveFailureDoesNotReportSuccess(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)
	origStore := globalClusterStore
	t.Cleanup(func() { globalClusterStore = origStore })
	globalClusterStore = newTestClusterStore(t)

	path := filepath.Join(t.TempDir(), "policy.json")
	policyStore.path = path
	if err := os.Mkdir(path+".meta", 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := &HAStateBundle{
		ClusterState: buildHANonEmptyClusterState(t),
		Config: ConfigSnapshot{PolicyRules: []PolicyRule{{
			Name: "must-persist", Action: ActionAllow,
		}}},
	}

	if applyHABundle(bundle, "token") {
		t.Fatal("HA bundle reported success after policy metadata publication failed")
	}
}

// TestHA_PR5_PersistFailureLeavesLiveCAUnchanged: if persistReplicatedKey fails,
// applyReplicatedCA must NOT have mutated the live globalClusterCA in memory.
func TestHA_PR5_PersistFailureLeavesLiveCAUnchanged(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := withClusterCAForHA(t, dir)

	// Force the persist to fail: point the live CA's dir at a regular FILE, so
	// the cert write (os.CreateTemp in that "dir") fails. The live CA starts
	// empty (not Ready) and must stay that way.
	notADir := filepath.Join(t.TempDir(), "iam-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	globalClusterCA = &clusterCA{dir: notADir}

	const token = "persist-fail-token"
	enc, err := haEncryptKey(keyPEM, token)
	if err != nil {
		t.Fatalf("haEncryptKey: %v", err)
	}
	if err := applyReplicatedCA(certPEM, enc, token); err == nil {
		t.Fatal("expected persist failure to surface as an error")
	}
	if globalClusterCA.Ready() {
		t.Fatal("live cluster CA must not be Ready() after a persist failure")
	}
}

// buildHANonEmptyClusterState marshals a ClusterState with one node so the
// import is observably non-empty.
func buildHANonEmptyClusterState(t *testing.T) []byte {
	t.Helper()
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "replicated-node", Status: "connected"})
	raw, err := cs.ExportState()
	if err != nil {
		t.Fatalf("export state: %v", err)
	}
	return raw
}

// TestHA_PR5_BundleHasNoPlaintextKeyField: the wire payload of an HA bundle
// carries ca_key_encrypted and never ca_key_pem.
func TestHA_PR5_BundleHasNoPlaintextKeyField(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.token = "pr5-leader-token"
	globalHA.mu.Unlock()

	// A live cluster CA so the leader has a key to wrap.
	orig := globalClusterCA
	t.Cleanup(func() { globalClusterCA = orig })
	srcDir := t.TempDir()
	t.Setenv(clusterCAEncryptEnvVar, "")
	if err := (&clusterCA{}).InitOrLoad(srcDir); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	live := &clusterCA{}
	if err := live.InitOrLoad(srcDir); err != nil {
		t.Fatalf("load live CA: %v", err)
	}
	globalClusterCA = live

	svc := &controlPlaneServer{}
	raw, err := svc.HASync(context.Background(), json.RawMessage(`{"token":"pr5-leader-token"}`))
	if err != nil {
		t.Fatalf("HASync: %v", err)
	}
	if bytes.Contains(raw, []byte("ca_key_pem")) {
		t.Fatal("HA bundle must not contain ca_key_pem (plaintext fallback removed)")
	}
	if !bytes.Contains(raw, []byte("ca_key_encrypted")) {
		t.Fatal("HA bundle should carry ca_key_encrypted")
	}
	// No raw private-key PEM markers in the wire payload.
	if bytes.Contains(raw, []byte("EC PRIVATE KEY")) {
		t.Fatal("HA bundle wire payload must not contain plaintext key PEM")
	}
}
