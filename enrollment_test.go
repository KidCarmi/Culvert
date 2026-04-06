package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── ClusterStore Tests ──────────────────────────────────────────────────────

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

func TestClusterStore_LoadCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")
	os.WriteFile(path, []byte("not json"), 0600)

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
	cs.Load(filepath.Join(dir, "cluster.json"))
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
	err = cs.ValidateToken(plaintext, "dp-east-1", "")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}

	// Token should now be consumed — second use fails.
	err = cs.ValidateToken(plaintext, "dp-east-2", "")
	if err == nil {
		t.Fatal("expected error: token already consumed")
	}
}

func TestTokenValidate_Expired(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, _ := cs.GenerateToken("", "", "admin", 1*time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	err := cs.ValidateToken(plaintext, "node-1", "")
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

	err := cs.ValidateToken(plaintext, "dp-west-1", "")
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
	err := cs.ValidateToken(plaintext, "node-1", "10.1.2.3")
	if err != nil {
		t.Fatalf("should allow 10.1.2.3: %v", err)
	}
}

func TestTokenValidate_CIDRRestriction_Denied(t *testing.T) {
	cs := newTestClusterStore(t)

	plaintext, _ := cs.GenerateToken("", "10.0.0.0/8", "admin", 1*time.Hour)

	err := cs.ValidateToken(plaintext, "node-1", "192.168.1.1")
	if err == nil {
		t.Fatal("expected error: CIDR mismatch")
	}
}

func TestTokenValidate_InvalidToken(t *testing.T) {
	cs := newTestClusterStore(t)

	err := cs.ValidateToken("nonexistent-token", "node-1", "")
	if err == nil {
		t.Fatal("expected error: invalid token")
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

	cs.GenerateToken("a-", "", "admin", 1*time.Hour)
	cs.GenerateToken("b-", "", "admin", 1*time.Hour)

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
	cs.UpdateNodeSeen("dp-1", "10.0.0.5")

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
	cs.RevokeNode("dp-1", "admin", "test")

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
	cs.RevokeNode("dp-1", "admin", "test")

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
	ca.InitOrLoad(dir)

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
	err = cs.ValidateToken(plaintext, "dp-new-node", "10.0.0.1")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
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
	err = cs.ValidateToken(plaintext, "dp-another", "")
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
	cs1.Load(path)

	// Generate token.
	plaintext, _ := cs1.GenerateToken("dp-", "10.0.0.0/8", "admin", 24*time.Hour)
	cs1.ValidateToken(plaintext, "dp-1", "10.0.0.1")

	// Register and revoke a node.
	cs1.RegisterNode(&EnrolledNode{
		NodeID: "dp-1", CertSerial: "s1", Status: "connected",
		CertExpiry: time.Now().Add(365 * 24 * time.Hour),
	})
	cs1.RegisterNode(&EnrolledNode{
		NodeID: "dp-2", CertSerial: "s2", Status: "connected",
	})
	cs1.RevokeNode("dp-2", "admin", "test")
	cs1.Save()

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

