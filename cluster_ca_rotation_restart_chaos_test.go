package main

// cluster_ca_rotation_restart_chaos_test.go — CHAOS-104 regression gates.
//
// The finding: the dual-CA overlap that makes a cluster-CA rotation survivable
// was MEMORY-ONLY. `commitImport` demotes the outgoing CA to
// `ca.secondaryCert/secondaryPEM/secondaryExp` and `AllCACertsPEM` publishes
// both into the Control Plane's mTLS client-CA pool, so a Data Plane node still
// presenting an old-CA node certificate keeps verifying for the whole overlap.
// None of those three fields is on the load path: `loadFromPEM` restores only
// `cert`/`key`/`certPEM`. A Control Plane restart anywhere inside the overlap
// therefore came back with a client-CA pool holding ONLY the new CA and
// rejected every node that had not yet renewed — the exact set that
// `cluster.json` durably records as `CARotation.RenewedNodes` pending.
//
// The asymmetry is the defect: the rotation's BOOKKEEPING is durable
// (`StartCARotation` → `saveLocked`, carrying `OldFingerprint` and
// `OldExpires`) and the outgoing CA's PEM is durable too (`backupCAFiles` →
// `cluster-ca.crt.bak`, written through `fileutil.AtomicWrite`). Only the
// binding between them was lost on restart, so the recovery needs no new
// durable state — just a load path that re-derives the secondary from the two
// records that already survive, and refuses to do so unless the backup's
// fingerprint matches the one the authority recorded.
//
// Both rotation entry points reach this: the admin import (`ImportCA`) and the
// UNATTENDED auto-rotation (`RotateIfNeeded`, which calls `ImportCA`), so the
// window opens without an operator present.
//
// Gates:
//   - TestCHAOS104_RestartDuringOverlap_KeepsOldCAInClientPool is the
//     behavioural reproduction: a node cert signed by the outgoing CA must keep
//     verifying against the pool a restarted process publishes. It FAILS
//     against the pre-fix tree.
//   - the rest pin the restore's refusal conditions, so the fix cannot become a
//     path that trusts whatever sits at the predictable `.bak` name.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// clusterStoreAt builds a ClusterStore persisted at a CALLER-CHOSEN path, so a
// test can reload the same cluster.json across a simulated restart.
// newTestClusterStore picks its own TempDir, which cannot express that.
func clusterStoreAt(t *testing.T, path string) *ClusterStore {
	t.Helper()
	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs.Load(path); err != nil {
		t.Fatalf("cluster store load %q: %v", path, err)
	}
	return cs
}

// useClusterStore swaps the global the rotation bookkeeping writes through, and
// restores it. globalClusterStore is process-global state: per the repo's
// test-hygiene rule a test that redirects it registers its own restoration.
func useClusterStore(t *testing.T, cs *ClusterStore) {
	t.Helper()
	orig := globalClusterStore
	t.Cleanup(func() { globalClusterStore = orig })
	globalClusterStore = cs
}

// newCAPair mints a self-signed CA cert/key PEM pair valid over the window.
func newCAPair(t *testing.T, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Culvert"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// signNodeCert mints a Data Plane node certificate through the production
// signer, so the gate verifies the real artifact a DP presents at mTLS.
func signNodeCert(t *testing.T, ca *clusterCA, nodeID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("node keygen: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID},
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	certPEM, _, _, err := ca.SignCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nodeID)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("signed node cert is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse node cert: %v", err)
	}
	return cert
}

// verifiesAgainstPublishedPool builds the client-CA pool exactly as
// controlplane_tls.go does — from AllCACertsPEM — and reports whether the node
// certificate chains to it for client auth. This is the mTLS admission
// decision the Control Plane makes for every DP.
func verifiesAgainstPublishedPool(t *testing.T, ca *clusterCA, node *x509.Certificate) bool {
	t.Helper()
	pool := x509.NewCertPool()
	if allCA := ca.AllCACertsPEM(); len(allCA) > 0 {
		pool.AppendCertsFromPEM(allCA)
	}
	_, err := node.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// rotateInto installs a freshly minted CA over the one in dir, driving the real
// import path (backup + dual-CA demotion + durable write + rotation tracking).
func rotateInto(t *testing.T, ca *clusterCA) {
	t.Helper()
	newCert, newKey := newCAPair(t, "Culvert Cluster CA (new)", time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := ca.ImportCA(newCert, newKey); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
}

// ── the reproduction ────────────────────────────────────────────────────────

func TestCHAOS104_RestartDuringOverlap_KeepsOldCAInClientPool(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "cluster.json")
	useClusterStore(t, clusterStoreAt(t, storePath))

	// A Control Plane with a cluster CA and one enrolled node.
	ca1 := &clusterCA{}
	if err := ca1.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	node := signNodeCert(t, ca1, "dp-1")
	if !verifiesAgainstPublishedPool(t, ca1, node) {
		t.Fatalf("precondition: the node cert must verify before any rotation")
	}

	// Rotate. The outgoing CA becomes the secondary and the overlap begins:
	// dp-1 has NOT renewed, and must keep verifying.
	rotateInto(t, ca1)
	if !ca1.SecondaryActive() {
		t.Fatalf("precondition: the dual-CA overlap must be active after a rotation")
	}
	if !verifiesAgainstPublishedPool(t, ca1, node) {
		t.Fatalf("precondition: the overlap must keep an unrenewed node verifying")
	}
	if st := globalClusterStore.CARotationStatus(); st == nil {
		t.Fatalf("precondition: the rotation must be recorded durably")
	}

	// ── the Control Plane restarts inside the overlap ──
	// Same /data: the same CA directory and the same cluster.json, reloaded by
	// a fresh process image.
	useClusterStore(t, clusterStoreAt(t, storePath))
	if st := globalClusterStore.CARotationStatus(); st == nil {
		t.Fatalf("the reloaded cluster store lost the in-progress rotation")
	}
	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad after restart: %v", err)
	}

	if !verifiesAgainstPublishedPool(t, ca2, node) {
		t.Fatalf("CHAOS-104: after a restart inside the dual-CA overlap the client-CA pool no longer " +
			"verifies an unrenewed node — every Data Plane node that has not renewed is locked out of mTLS")
	}
	if !ca2.SecondaryActive() {
		t.Errorf("the restored overlap must report SecondaryActive, so the cleanup loop still closes it")
	}
}

// A restart AFTER the overlap has lapsed must not resurrect the old CA: the
// overlap is a bounded migration window, not a permanent second trust anchor.
func TestCHAOS104_RestartAfterOverlapExpired_DoesNotRestoreOldCA(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "cluster.json")
	useClusterStore(t, clusterStoreAt(t, storePath))

	// An outgoing CA whose own validity has already ended: secondaryExp is the
	// old cert's NotAfter, so this rotation's overlap is already over.
	oldCert, oldKey := newCAPair(t, "Culvert Cluster CA (expired)", time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.crt"), oldCert, 0o600); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.key"), oldKey, 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	ca1 := &clusterCA{}
	if err := ca1.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	rotateInto(t, ca1)

	useClusterStore(t, clusterStoreAt(t, storePath))
	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad after restart: %v", err)
	}
	if ca2.SecondaryActive() {
		t.Errorf("a lapsed overlap must not be reinstated on restart")
	}
	if got, want := len(ca2.AllCACertsPEM()), len(ca2.CACertPEM()); got != want {
		t.Errorf("published pool = %d bytes, want only the primary (%d bytes)", got, want)
	}
}

// With no rotation recorded, a `.bak` left beside the CA by an earlier,
// COMPLETED rotation must not be trusted — otherwise the predictable backup
// name becomes a way to re-add a retired trust anchor.
func TestCHAOS104_NoRotationRecorded_IgnoresStaleBackup(t *testing.T) {
	dir := t.TempDir()
	useClusterStore(t, clusterStoreAt(t, filepath.Join(t.TempDir(), "cluster.json")))

	ca1 := &clusterCA{}
	if err := ca1.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	// A long-lived foreign CA parked at the predictable backup path.
	foreign, _ := newCAPair(t, "Attacker CA", time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.crt.bak"), foreign, 0o600); err != nil {
		t.Fatalf("plant backup: %v", err)
	}

	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad after restart: %v", err)
	}
	if ca2.SecondaryActive() {
		t.Errorf("no rotation is in progress — nothing may be reinstated as a secondary CA")
	}
}

// An in-progress rotation whose `.bak` does NOT match the fingerprint the
// authority recorded must be refused. The backup path is predictable, so the
// durable OldFingerprint is what makes the restore safe.
func TestCHAOS104_BackupFingerprintMismatch_IsRefused(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(t.TempDir(), "cluster.json")
	useClusterStore(t, clusterStoreAt(t, storePath))

	ca1 := &clusterCA{}
	if err := ca1.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	rotateInto(t, ca1)

	st := globalClusterStore.CARotationStatus()
	if st == nil || st.OldFingerprint == "" {
		t.Fatalf("precondition: rotation must record the outgoing fingerprint")
	}

	// Swap the backup for a different CA, keeping the recorded fingerprint.
	foreign, _ := newCAPair(t, "Attacker CA", time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.crt.bak"), foreign, 0o600); err != nil {
		t.Fatalf("overwrite backup: %v", err)
	}
	fp := sha256.Sum256(mustParseCert(t, foreign).Raw)
	if hex.EncodeToString(fp[:]) == st.OldFingerprint {
		t.Fatalf("test setup: the planted CA must not match the recorded fingerprint")
	}

	useClusterStore(t, clusterStoreAt(t, storePath))
	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad after restart: %v", err)
	}
	if ca2.SecondaryActive() {
		t.Errorf("a backup that does not match the recorded OldFingerprint must be refused")
	}
}

func mustParseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert
}
