package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── ClusterStore Tests ─────────────────────────────────────────────────────���

func TestClusterStore_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")

	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}

	// Load from non-existent file should succeed (empty state).
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load non-existent: %v", err)
	}

	// Register a node and save.
	cs.RegisterNode(&EnrolledNode{
		NodeID:     "dp-test-1",
		CertSerial: "abc123",
		CertExpiry: time.Now().Add(365 * 24 * time.Hour),
		EnrolledAt: time.Now(),
		Status:     "connected",
	})

	if err := cs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load into a fresh store.
	cs2 := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	nodes := cs2.ListNodes()
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].NodeID != "dp-test-1" {
		t.Fatalf("node ID = %q, want dp-test-1", nodes[0].NodeID)
	}
}

// TestClusterStore_Save_NoTmpLeak verifies that the converted writer
// (atomicWriteFile) does not leave orphaned *.tmp.* files in the parent
// directory after a successful Save. Regression guard for D1.1b.
func TestClusterStore_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")

	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	cs.RegisterNode(&EnrolledNode{
		NodeID:     "dp-tmpleak-1",
		CertSerial: "deadbeef",
		CertExpiry: time.Now().Add(24 * time.Hour),
		EnrolledAt: time.Now(),
		Status:     "connected",
	})
	if err := cs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	assertNoTmpLeak(t, dir)
}

func TestClusterStore_LoadCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	_ = os.WriteFile(path, []byte("not json"), 0o600)

	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	err := cs.Load(path)
	if err == nil {
		t.Fatal("expected error for corrupted file")
	}
}

// ── Token Tests ─────────────────────────────────────────────────────────────

func newTestClusterStore(t *testing.T) *ClusterStore {
	t.Helper()
	dir := t.TempDir()
	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	_ = cs.Load(filepath.Join(dir, "cluster.json"))
	return cs
}

func TestTokenGenerate_And_Validate(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, err := cs.GenerateToken("dp-", "", "admin", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if plaintext == "" {
		t.Fatal("token should not be empty")
	}

	// Validate with matching node ID.
	_, err = cs.ValidateAndConsumeToken(plaintext, "dp-east-1", "")
	if err != nil {
		t.Fatalf("ValidateAndConsumeToken: %v", err)
	}

	// Token should now be consumed — second use fails.
	_, err = cs.ValidateAndConsumeToken(plaintext, "dp-east-2", "")
	if err == nil {
		t.Fatal("expected error: token already consumed")
	}
}

func TestTokenValidate_Expired(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, _ := cs.GenerateToken("", "", "admin", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	_, err := cs.ValidateAndConsumeToken(plaintext, "node-1", "")
	if err == nil {
		t.Fatal("expected error: token expired")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error should mention 'expired', got: %v", err)
	}
}

func TestTokenValidate_WrongPrefix(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, _ := cs.GenerateToken("dp-east-", "", "admin", 1*time.Hour)

	_, err := cs.ValidateAndConsumeToken(plaintext, "dp-west-1", "")
	if err == nil {
		t.Fatal("expected error: prefix mismatch")
	}
	if !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("error should mention 'prefix', got: %v", err)
	}
}

func TestTokenValidate_CIDRRestriction(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, _ := cs.GenerateToken("", "10.0.0.0/8", "admin", 1*time.Hour)

	// Allowed IP.
	_, err := cs.ValidateAndConsumeToken(plaintext, "node-1", "10.1.2.3")
	if err != nil {
		t.Fatalf("should allow 10.1.2.3: %v", err)
	}
}

func TestTokenValidate_CIDRRestriction_Denied(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, _ := cs.GenerateToken("", "10.0.0.0/8", "admin", 1*time.Hour)

	_, err := cs.ValidateAndConsumeToken(plaintext, "node-1", "192.168.1.1")
	if err == nil {
		t.Fatal("expected error: CIDR mismatch")
	}
}

func TestTokenValidate_InvalidToken(t *testing.T) {
	cs := newTestClusterStore(t)

	_, err := cs.ValidateAndConsumeToken("nonexistent-token", "node-1", "")
	if err == nil {
		t.Fatal("expected error: invalid token")
	}
}

// TestTokenValidate_CorruptedCIDR_FailsClosed guards the fail-closed handling of
// a malformed AllowCIDR that reached the persisted token map (e.g. via on-disk
// state corruption or a hand-edited cluster.json). GenerateToken validates the
// CIDR at creation, so we inject the bad value directly into the token map to
// simulate corruption. Before the fix, net.ParseCIDR's discarded error left a
// nil *net.IPNet and cidr.Contains(ip) panicked inside the enrollment path.
func TestTokenValidate_CorruptedCIDR_FailsClosed(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, err := cs.GenerateToken("", "", "admin", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Corrupt the persisted token's AllowCIDR out-of-band.
	cs.mu.Lock()
	cs.st.Tokens[hashToken(plaintext)].AllowCIDR = "not-a-valid-cidr"
	cs.mu.Unlock()

	// Must return an error, not panic.
	_, err = cs.ValidateAndConsumeToken(plaintext, "node-1", "10.1.2.3")
	if err == nil {
		t.Fatal("expected fail-closed error for corrupted AllowCIDR, got nil")
	}
}

func TestTokenGenerate_InvalidCIDR(t *testing.T) {
	cs := newTestClusterStore(t)

	_, err := cs.GenerateToken("", "not-a-cidr", "admin", 1*time.Hour)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestTokenList_And_Delete(t *testing.T) {
	cs := newTestClusterStore(t)

	_, _ = cs.GenerateToken("a-", "", "admin", 1*time.Hour)
	_, _ = cs.GenerateToken("b-", "", "admin", 1*time.Hour)

	tokens := cs.ListTokens()
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}

	// Delete one.
	hash := tokens[0].TokenHash
	if !cs.DeleteToken(hash) {
		t.Fatal("DeleteToken should return true")
	}
	if cs.DeleteToken(hash) {
		t.Fatal("second DeleteToken should return false")
	}
	if len(cs.ListTokens()) != 1 {
		t.Fatal("expected 1 token after delete")
	}
}

// ── Node Registry Tests ─────────────────────────────────────────────────────

func TestNodeRegistry_RegisterAndList(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected"})
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-2", Status: "connected"})

	nodes := cs.ListNodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
}

func TestNodeRegistry_GetNode(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "ser1"})

	n, ok := cs.GetNode("dp-1")
	if !ok {
		t.Fatal("GetNode should find dp-1")
	}
	if n.CertSerial != "ser1" {
		t.Fatalf("serial = %q, want ser1", n.CertSerial)
	}

	_, ok = cs.GetNode("dp-nonexistent")
	if ok {
		t.Fatal("GetNode should not find nonexistent node")
	}
}

func TestNodeRegistry_UpdateSeen(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "disconnected"})
	cs.UpdateNodeSeen("dp-1", "10.0.0.5", "")

	n, _ := cs.GetNode("dp-1")
	if n.Status != "connected" {
		t.Fatalf("status = %q, want connected", n.Status)
	}
	if n.IPAddress != "10.0.0.5" {
		t.Fatalf("IP = %q, want 10.0.0.5", n.IPAddress)
	}
}

// ── Revocation Tests ────────────────────────────────────────────────────────

func TestRevocation_RevokeNode(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "ser1"})

	err := cs.RevokeNode("dp-1", "admin", "compromised")
	if err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}

	n, _ := cs.GetNode("dp-1")
	if n.Status != "revoked" {
		t.Fatalf("status = %q, want revoked", n.Status)
	}

	if !cs.IsRevoked("ser1") {
		t.Fatal("cert should be revoked")
	}
	if cs.IsRevoked("ser-unknown") {
		t.Fatal("unknown cert should not be revoked")
	}
}

func TestRevocation_DoubleRevoke(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "ser1"})
	_ = cs.RevokeNode("dp-1", "admin", "test")

	err := cs.RevokeNode("dp-1", "admin", "again")
	if err == nil {
		t.Fatal("expected error: already revoked")
	}
}

func TestRevocation_NonexistentNode(t *testing.T) {
	cs := newTestClusterStore(t)

	err := cs.RevokeNode("dp-ghost", "admin", "test")
	if err == nil {
		t.Fatal("expected error: node not found")
	}
}

func TestRevocation_ListRevoked(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	cs.RegisterNode(&EnrolledNode{NodeID: "dp-2", Status: "connected", CertSerial: "s2"})
	_ = cs.RevokeNode("dp-1", "admin", "test")

	revoked := cs.ListRevoked()
	if len(revoked) != 1 {
		t.Fatalf("expected 1 revoked, got %d", len(revoked))
	}
	if revoked[0].NodeID != "dp-1" {
		t.Fatalf("revoked node = %q, want dp-1", revoked[0].NodeID)
	}
}

// ── Heartbeat Monitor Tests ─────────────────────────────────────────────────

func TestHeartbeat_MarksDisconnected(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{
		NodeID:   "dp-1",
		Status:   "connected",
		LastSeen: time.Now().Add(-2 * time.Minute), // 2 min ago, past 90s threshold
	})

	cs.checkHeartbeats()

	n, _ := cs.GetNode("dp-1")
	if n.Status != "disconnected" {
		t.Fatalf("status = %q, want disconnected", n.Status)
	}
}

func TestHeartbeat_SkipsRevoked(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{
		NodeID:   "dp-1",
		Status:   "revoked",
		LastSeen: time.Now().Add(-2 * time.Minute),
	})

	cs.checkHeartbeats() // should not change revoked status

	n, _ := cs.GetNode("dp-1")
	if n.Status != "revoked" {
		t.Fatalf("status = %q, want revoked (unchanged)", n.Status)
	}
}

func TestHeartbeat_RecentNodeStaysConnected(t *testing.T) {
	cs := newTestClusterStore(t)

	cs.RegisterNode(&EnrolledNode{
		NodeID:   "dp-1",
		Status:   "connected",
		LastSeen: time.Now(), // just now
	})

	cs.checkHeartbeats()

	n, _ := cs.GetNode("dp-1")
	if n.Status != "connected" {
		t.Fatalf("status = %q, want connected", n.Status)
	}
}

// ── Cluster CA Tests ────────────────────────────────────────────────────────

func TestClusterCA_InitOrLoad(t *testing.T) {
	dir := t.TempDir()

	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}

	if !ca.Ready() {
		t.Fatal("CA should be ready after init")
	}
	if ca.CACertFingerprint() == "" {
		t.Fatal("fingerprint should not be empty")
	}
	if len(ca.CACertPEM()) == 0 {
		t.Fatal("CA PEM should not be empty")
	}

	// Files should exist on disk.
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.crt")); err != nil {
		t.Fatalf("cluster-ca.crt not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.key")); err != nil {
		t.Fatalf("cluster-ca.key not created: %v", err)
	}

	// Load existing CA.
	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad (existing): %v", err)
	}
	if ca2.CACertFingerprint() != ca.CACertFingerprint() {
		t.Fatal("reloaded CA should have same fingerprint")
	}
}

// TestClusterCA_RotationFailure_SurfacedInInfo proves the Product Experience
// fix: an auto-rotation failure (previously logger.Printf-only, invisible
// until the CA actually expired) is now readable via Info() — the same
// accessor GET /api/cluster/ca and the Cluster CA GUI panel already use —
// and a subsequent successful ImportCA clears it.
func TestClusterCA_RotationFailure_SurfacedInInfo(t *testing.T) {
	dir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}

	ca.recordRotationFailure(errors.New("disk full"))

	info := ca.Info()
	if got := info["lastRotationError"]; got != "disk full" {
		t.Fatalf("lastRotationError = %v, want %q", got, "disk full")
	}
	if at, _ := info["lastRotationErrorAt"].(string); at == "" {
		t.Fatal("lastRotationErrorAt should be set")
	}

	certPEM, keyPEM := seedClusterCAFiles(t)
	if err := ca.ImportCA(certPEM, keyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	info = ca.Info()
	if _, ok := info["lastRotationError"]; ok {
		t.Fatal("lastRotationError should be cleared after a successful ImportCA")
	}
}

// ── D1.1f: bootstrap consistency tests ─────────────────────────────────────

// seedClusterCAFiles bootstraps a clusterCA into a fresh temp dir and
// returns the cert and key PEM bytes. Used by partial-pair / mismatch
// tests to obtain real, parseable PEM material.
func seedClusterCAFiles(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	var err error
	certPEM, err = os.ReadFile(filepath.Join(dir, "cluster-ca.crt"))
	if err != nil {
		t.Fatalf("seed read cert: %v", err)
	}
	keyPEM, err = os.ReadFile(filepath.Join(dir, "cluster-ca.key"))
	if err != nil {
		t.Fatalf("seed read key: %v", err)
	}
	return certPEM, keyPEM
}

func TestClusterCA_PartialPair_FailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		present string // file pre-created on disk
		absent  string // file that must remain absent after InitOrLoad
		useCert bool   // true → seed `present` with cert PEM; false → key PEM
	}{
		{name: "cert_only", present: "cluster-ca.crt", absent: "cluster-ca.key", useCert: true},
		{name: "key_only", present: "cluster-ca.key", absent: "cluster-ca.crt", useCert: false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			certPEM, keyPEM := seedClusterCAFiles(t)
			seed := keyPEM
			if c.useCert {
				seed = certPEM
			}
			if err := os.WriteFile(filepath.Join(dir, c.present), seed, 0o600); err != nil {
				t.Fatalf("write seed: %v", err)
			}

			ca := &clusterCA{}
			err := ca.InitOrLoad(dir)
			if err == nil {
				t.Fatalf("expected error on partial pair (%s)", c.name)
			}
			if !strings.Contains(err.Error(), "partial pair") {
				t.Errorf("error should mention partial pair, got: %v", err)
			}

			// Surviving file must NOT have been overwritten.
			after, err := os.ReadFile(filepath.Join(dir, c.present))
			if err != nil {
				t.Fatalf("read %s after: %v", c.present, err)
			}
			if !bytes.Equal(after, seed) {
				t.Errorf("%s was overwritten despite partial-pair detection", c.present)
			}
			// Missing file must still be missing — bootstrap refused to create one.
			if _, err := os.Stat(filepath.Join(dir, c.absent)); !os.IsNotExist(err) {
				t.Errorf("%s should not have been created; stat err = %v", c.absent, err)
			}
		})
	}
}

func TestClusterCA_EmptyDir_BootstrapsSuccessfully(t *testing.T) {
	dir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad on empty dir: %v", err)
	}
	if !ca.Ready() {
		t.Error("CA should be ready after bootstrap on empty dir")
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.crt")); err != nil {
		t.Fatalf("cluster-ca.crt missing after bootstrap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "cluster-ca.key")); err != nil {
		t.Fatalf("cluster-ca.key missing after bootstrap: %v", err)
	}
}

func TestClusterCA_MatchedPair_LoadsSuccessfully(t *testing.T) {
	dir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("seed bootstrap: %v", err)
	}
	// Reload from disk into a fresh struct — should succeed (matched pair).
	ca2 := &clusterCA{}
	if err := ca2.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad reload: %v", err)
	}
	if !ca2.Ready() {
		t.Error("CA should be ready after reload")
	}
}

func TestClusterCA_MismatchedPair_FailsClosed(t *testing.T) {
	dir := t.TempDir()

	// Bootstrap two distinct CAs in separate seed dirs and mix the halves.
	certA, _ := seedClusterCAFiles(t)
	_, keyB := seedClusterCAFiles(t)

	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.crt"), certA, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cluster-ca.key"), keyB, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	ca := &clusterCA{}
	err := ca.InitOrLoad(dir)
	if err == nil {
		t.Fatal("expected error on mismatched cert/key pair")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention mismatch, got: %v", err)
	}
}

func TestClusterCA_Bootstrap_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	if err := (&clusterCA{}).InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	assertNoTmpLeak(t, dir)
}

// ── D1.1g: renewal-path consistency tests ─────────────────────────────────

// TestClusterCA_PartialRenewal_DetectedOnRestart simulates the failure
// window in ImportCA where rename(cert) succeeds but rename(key) does not
// (or the process crashes between the two writes). After D1.1g, ImportCA
// uses two atomicWriteFile calls — each file is durable on its own, but
// the two-file commit is still not atomic. The post-condition is that on
// next startup, D1.1f's cross-validation in loadFromPEM detects the
// mismatched pair and InitOrLoad fails closed.
func TestClusterCA_PartialRenewal_DetectedOnRestart(t *testing.T) {
	dir := t.TempDir()

	// Bootstrap CA1 in dir. ca holds CA1 cert/key in memory and on disk.
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap CA1: %v", err)
	}
	keyPath := filepath.Join(dir, "cluster-ca.key")
	oldKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read CA1 key: %v", err)
	}

	// Generate CA2 by bootstrapping into a separate seed dir, then
	// import its cert+key into ca. After ImportCA returns, dir contains
	// CA2's cert and CA2's key (matched pair).
	newCertPEM, newKeyPEM := seedClusterCAFiles(t)
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err != nil {
		t.Fatalf("ImportCA CA2: %v", err)
	}

	// Simulate the partial-renewal outcome: the cert rename committed,
	// the key rename did not (or a crash landed between them). On disk
	// we now have CA2's cert paired with CA1's key.
	if err := os.WriteFile(keyPath, oldKeyPEM, 0o600); err != nil {
		t.Fatalf("revert key file: %v", err)
	}

	// A fresh clusterCA loading dir must fail closed via cross-validation.
	ca2 := &clusterCA{}
	err = ca2.InitOrLoad(dir)
	if err == nil {
		t.Fatal("expected error on partial-renewal mismatch")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention mismatch (cross-validation), got: %v", err)
	}
}

// TestClusterCA_ImportCA_NoTmpLeak verifies that the converted ImportCA
// writers (atomicWriteFile per file) do not leave orphaned *.tmp.* files
// in the dir after a successful renewal.
func TestClusterCA_ImportCA_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()

	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	newCertPEM, newKeyPEM := seedClusterCAFiles(t)
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err != nil {
		t.Fatalf("ImportCA: %v", err)
	}

	assertNoTmpLeak(t, dir)
}

func TestClusterCA_SignCSR(t *testing.T) {
	dir := t.TempDir()

	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}

	// Generate a test CSR.
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dp-test-node"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, serial, expiry, err := ca.SignCSR(csrPEM, "dp-test-node")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatal("cert PEM should not be empty")
	}
	if serial == "" {
		t.Fatal("serial should not be empty")
	}
	if expiry.Before(time.Now()) {
		t.Fatal("expiry should be in the future")
	}

	// Parse and verify the signed cert.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if cert.Subject.CommonName != "dp-test-node" {
		t.Fatalf("CN = %q, want dp-test-node", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "Culvert Cluster CA" {
		t.Fatalf("issuer = %q, want Culvert Cluster CA", cert.Issuer.CommonName)
	}
}

func TestClusterCA_SignCSR_InvalidCSR(t *testing.T) {
	dir := t.TempDir()

	ca := &clusterCA{}
	_ = ca.InitOrLoad(dir)

	_, _, _, err := ca.SignCSR([]byte("not a pem"), "node")
	if err == nil {
		t.Fatal("expected error for invalid CSR")
	}
}

func TestClusterCA_SignCSR_NotReady(t *testing.T) {
	ca := &clusterCA{} // not initialized

	_, _, _, err := ca.SignCSR([]byte("anything"), "node")
	if err == nil {
		t.Fatal("expected error when CA not initialized")
	}
}

// ── Hash Token Tests ────────────────────────────────────────────────────────

func TestHashToken_Deterministic(t *testing.T) {
	h1 := hashToken("test-token-123")
	h2 := hashToken("test-token-123")
	if h1 != h2 {
		t.Fatal("same input should produce same hash")
	}
	h3 := hashToken("different-token")
	if h1 == h3 {
		t.Fatal("different inputs should produce different hashes")
	}
}

// ── API Endpoint Tests ──────────────────────────────────────────────────────

func TestAPIClusterTokens_RequiresCP(t *testing.T) {
	// Save and restore cluster role.
	origRole := clusterRole.role
	defer func() { clusterRole.role = origRole }()
	clusterRole.role = "standalone"

	w := httptest.NewRecorder()
	body := strings.NewReader(`{"ttl_hours": 1}`)
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/tokens", body)
	r.Header.Set("Content-Type", "application/json")
	// Inject admin role.
	r = adminCtx(r)

	apiClusterTokens(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAPIClusterNodes_GET(t *testing.T) {
	// Swap global store.
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-api-1", Status: "connected"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/cluster/nodes", nil)
	r = adminCtx(r)

	apiClusterNodes(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp struct {
		Nodes []EnrolledNode `json:"nodes"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(resp.Nodes))
	}
}

func TestAPIClusterRevoke_POST(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-rev-1", Status: "connected", CertSerial: "s1"})

	w := httptest.NewRecorder()
	body := strings.NewReader(`{"node_id":"dp-rev-1","reason":"test"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/revoke", body)
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)

	apiClusterRevoke(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	n, _ := globalClusterStore.GetNode("dp-rev-1")
	if n.Status != "revoked" {
		t.Fatalf("status = %q, want revoked", n.Status)
	}
}

func TestAPIClusterRevoke_MissingNodeID(t *testing.T) {
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"reason":"test"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/cluster/revoke", body)
	r.Header.Set("Content-Type", "application/json")
	r = adminCtx(r)

	apiClusterRevoke(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestAPIClusterStatus_IncludesEnrollInfo(t *testing.T) {
	origRole := clusterRole.role
	origStore := globalClusterStore
	origCA := globalClusterCA
	defer func() {
		clusterRole.role = origRole
		globalClusterStore = origStore
		globalClusterCA = origCA
	}()

	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = ":50051"
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected"})

	// Init a test CA.
	dir := t.TempDir()
	testCA := &clusterCA{}
	_ = testCA.InitOrLoad(dir)
	globalClusterCA = testCA

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	apiClusterStatus(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["enrollEnabled"] != true {
		t.Fatal("enrollEnabled should be true")
	}
	if resp["caFingerprint"] == "" {
		t.Fatal("caFingerprint should not be empty")
	}
	enrolled, ok := resp["enrolledNodes"].([]any)
	if !ok || len(enrolled) != 1 {
		t.Fatalf("expected 1 enrolledNode, got %v", resp["enrolledNodes"])
	}
}

// TestAPIClusterStatus_SurfacesGRPCCompression pins the operator-visible
// read-only surfacing of the CULVERT_CLUSTER_GRPC_COMPRESSION startup flag
// (see CLAUDE.md) so its effective value can never silently regress back to
// invisible without a test failure.
func TestAPIClusterStatus_SurfacesGRPCCompression(t *testing.T) {
	orig := clusterGRPCCompression
	defer func() { clusterGRPCCompression = orig }()

	for _, want := range []bool{true, false} {
		clusterGRPCCompression = want

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
		apiClusterStatus(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		got, ok := resp["grpcCompressionEnabled"].(bool)
		if !ok {
			t.Fatalf("grpcCompressionEnabled missing or not a bool: %v", resp["grpcCompressionEnabled"])
		}
		if got != want {
			t.Fatalf("grpcCompressionEnabled = %v, want %v", got, want)
		}
	}
}

// ── End-to-End Enrollment Flow Test ─────────────────────────────────────────

func TestEnrollmentFlow_TokenToCSRToNode(t *testing.T) {
	// Set up a test cluster store and CA.
	cs := newTestClusterStore(t)
	dir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(dir); err != nil {
		t.Fatalf("CA init: %v", err)
	}

	// Step 1: Generate a token.
	plaintext, err := cs.GenerateToken("dp-", "", "admin", 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	// Step 2: Validate the token (simulating what the Enroll RPC does).
	_, err = cs.ValidateAndConsumeToken(plaintext, "dp-new-node", "10.0.0.1")
	if err != nil {
		t.Fatalf("ValidateAndConsumeToken: %v", err)
	}

	// Step 3: Generate a CSR (simulating what the DP node does).
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "dp-new-node"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Step 4: Sign the CSR (what the CP does).
	certPEM, serial, expiry, err := ca.SignCSR(csrPEM, "dp-new-node")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}

	// Step 5: Register the node.
	cs.RegisterNode(&EnrolledNode{
		NodeID:     "dp-new-node",
		CertSerial: serial,
		CertExpiry: expiry,
		EnrolledAt: time.Now(),
		Status:     "connected",
		EnrolledBy: "admin",
	})

	// Verify node is registered.
	n, ok := cs.GetNode("dp-new-node")
	if !ok {
		t.Fatal("node should be registered")
	}
	if n.CertSerial != serial {
		t.Fatalf("serial = %q, want %q", n.CertSerial, serial)
	}

	// Verify cert is valid and signed by our CA.
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CACertPEM())
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("cert verification failed: %v", err)
	}

	// Step 6: Revoke the node.
	err = cs.RevokeNode("dp-new-node", "admin", "test cleanup")
	if err != nil {
		t.Fatalf("RevokeNode: %v", err)
	}
	if !cs.IsRevoked(serial) {
		t.Fatal("node cert should be in CRL")
	}

	// Step 7: Token should be consumed — can't reuse.
	_, err = cs.ValidateAndConsumeToken(plaintext, "dp-another", "")
	if err == nil {
		t.Fatal("expected error: token already consumed")
	}
}

// ── Persistence Round-Trip Test ─────────────────────────────────────────────

func TestClusterStore_PersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")

	// Create and populate store.
	cs1 := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	_ = cs1.Load(path)

	// Generate token.
	plaintext, _ := cs1.GenerateToken("dp-", "10.0.0.0/8", "admin", 24*time.Hour)
	_, _ = cs1.ValidateAndConsumeToken(plaintext, "dp-1", "10.0.0.1")

	// Register and revoke a node.
	cs1.RegisterNode(&EnrolledNode{
		NodeID: "dp-1", CertSerial: "s1", Status: "connected",
		CertExpiry: time.Now().Add(365 * 24 * time.Hour),
	})
	cs1.RegisterNode(&EnrolledNode{
		NodeID: "dp-2", CertSerial: "s2", Status: "connected",
	})
	_ = cs1.RevokeNode("dp-2", "admin", "test")
	_ = cs1.Save()

	// Load into fresh store.
	cs2 := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs2.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify nodes.
	nodes := cs2.ListNodes()
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	// Verify revocation survived.
	if !cs2.IsRevoked("s2") {
		t.Fatal("s2 should still be revoked after reload")
	}
	if cs2.IsRevoked("s1") {
		t.Fatal("s1 should not be revoked")
	}

	// Verify token survived.
	tokens := cs2.ListTokens()
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if !tokens[0].Used {
		t.Fatal("token should be marked as used")
	}
}

// ── Concurrent Access Test ──────────────────────────────────────────────────

func TestClusterStore_ConcurrentAccess(t *testing.T) {
	cs := newTestClusterStore(t)

	// Register some initial nodes.
	for i := 0; i < 10; i++ {
		cs.RegisterNode(&EnrolledNode{
			NodeID: "dp-" + string(rune('a'+i)),
			Status: "connected",
		})
	}

	// Run concurrent operations.
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				cs.ListNodes()
				cs.ListTokens()
				cs.ListRevoked()
				cs.UpdateNodeSeen("dp-a", "10.0.0.1", "")
				cs.GetNode("dp-b")
				cs.IsRevoked("serial-x")
			}
		}(i)
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}
