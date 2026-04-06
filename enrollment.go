package main

// ─── Node Enrollment System ──────────────────────────────────────────────────
//
// Provides GUI-driven Data Plane node enrollment for Culvert clusters.
//
//  1. Admin clicks [+ Enroll Node] in the GUI → generates a one-time token
//  2. Token is shown as a single-line enrollment command
//  3. Operator runs the command on a new server
//  4. New node generates an ECDSA P-256 keypair + CSR
//  5. Node presents token + CSR to the Control Plane via gRPC Enroll RPC
//  6. CP validates token, signs CSR → returns signed cert + CA cert
//  7. Node persists certs and restarts in normal DP mode
//
// Security properties:
//   - Tokens stored as SHA-256 hashes (DB leak doesn't compromise tokens)
//   - One-time use (consumed on first use)
//   - Time-limited (default 24h, configurable)
//   - Optional CIDR restriction
//   - Instant revocation via in-memory CRL
//   - Full audit trail

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Cluster State ───────────────────────────────────────────────────────────

// ClusterState holds all enrollment-related state persisted to cluster.json.
type ClusterState struct {
	Nodes   map[string]*EnrolledNode `json:"nodes"`
	Tokens  map[string]*EnrollToken  `json:"tokens"`  // key = SHA-256(token)
	Revoked []RevokedCert            `json:"revoked"`
	Version int64                    `json:"version"` // monotonic config version
}

// EnrolledNode represents a registered Data Plane node.
type EnrolledNode struct {
	NodeID     string    `json:"node_id"`
	CertSerial string    `json:"cert_serial"`
	CertExpiry time.Time `json:"cert_expiry"`
	EnrolledAt time.Time `json:"enrolled_at"`
	EnrolledBy string    `json:"enrolled_by"` // admin username
	LastSeen   time.Time `json:"last_seen"`
	Status     string    `json:"status"` // "connected", "disconnected", "revoked"
	IPAddress  string    `json:"ip_address"`
	Version    string    `json:"version"` // culvert version on node
}

// EnrollToken represents an enrollment token (plaintext never stored).
type EnrollToken struct {
	TokenHash  string    `json:"token_hash"` // SHA-256 hex
	NodePrefix string    `json:"node_prefix"`
	AllowCIDR  string    `json:"allow_cidr"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	Used       bool      `json:"used"`
	UsedByNode string    `json:"used_by_node"`
	UsedAt     time.Time `json:"used_at,omitempty"`
}

// RevokedCert tracks a revoked node certificate.
type RevokedCert struct {
	CertSerial string    `json:"cert_serial"`
	NodeID     string    `json:"node_id"`
	RevokedAt  time.Time `json:"revoked_at"`
	RevokedBy  string    `json:"revoked_by"`
	Reason     string    `json:"reason"`
}

// ─── ClusterStore ────────────────────────────────────────────────────────────

// ClusterStore manages cluster state with persistence.
type ClusterStore struct {
	mu             sync.RWMutex
	st             ClusterState
	path           string // JSON file path for persistence
	heartbeatCount int    // counter for periodic save in UpdateNodeSeen
}

var globalClusterStore = &ClusterStore{
	st: ClusterState{
		Nodes:   make(map[string]*EnrolledNode),
		Tokens:  make(map[string]*EnrollToken),
		Revoked: []RevokedCert{},
	},
}

// Load reads cluster state from a JSON file.
func (cs *ClusterStore) Load(path string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.path = path
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // first run, start empty
		}
		return fmt.Errorf("read cluster state: %w", err)
	}
	var st ClusterState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse cluster state: %w", err)
	}
	if st.Nodes == nil {
		st.Nodes = make(map[string]*EnrolledNode)
	}
	if st.Tokens == nil {
		st.Tokens = make(map[string]*EnrollToken)
	}
	if st.Revoked == nil {
		st.Revoked = []RevokedCert{}
	}
	cs.st = st
	return nil
}

// Save persists cluster state to disk.
func (cs *ClusterStore) Save() error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if cs.path == "" {
		return nil // no persistence path set
	}
	data, err := json.MarshalIndent(cs.st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cluster state: %w", err)
	}
	return os.WriteFile(cs.path, data, 0o600)
}

// ─── Token Management ────────────────────────────────────────────────────────

// hashToken returns the SHA-256 hex digest of a token string.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// GenerateToken creates a new enrollment token and returns the plaintext
// (shown once to the admin). The store only keeps the SHA-256 hash.
func (cs *ClusterStore) GenerateToken(nodePrefix, allowCIDR, createdBy string, ttl time.Duration) (string, error) {
	// Validate CIDR if provided.
	if allowCIDR != "" {
		if _, _, err := net.ParseCIDR(allowCIDR); err != nil {
			return "", fmt.Errorf("invalid CIDR: %w", err)
		}
	}

	// Generate 32 bytes of cryptographic randomness.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := hashToken(plaintext)

	token := &EnrollToken{
		TokenHash:  hash,
		NodePrefix: nodePrefix,
		AllowCIDR:  allowCIDR,
		ExpiresAt:  time.Now().Add(ttl),
		CreatedBy:  createdBy,
		CreatedAt:  time.Now(),
	}

	cs.mu.Lock()
	cs.st.Tokens[hash] = token
	cs.mu.Unlock()

	if err := cs.Save(); err != nil {
		return "", fmt.Errorf("persist token: %w", err)
	}

	return plaintext, nil
}

// TokenInfo holds metadata returned by ValidateAndConsumeToken so callers
// don't need to re-access the token map after validation.
type TokenInfo struct {
	CreatedBy string
}

// ValidateAndConsumeToken checks if a plaintext token is valid for the given
// node ID and source IP. On success, it marks the token as consumed, persists
// state to disk, and returns token metadata. The entire operation is atomic
// under a single lock+save, preventing replay attacks after crashes.
func (cs *ClusterStore) ValidateAndConsumeToken(plaintext, nodeID, sourceIP string) (TokenInfo, error) {
	hash := hashToken(plaintext)

	cs.mu.Lock()

	tok, ok := cs.st.Tokens[hash]
	if !ok {
		cs.mu.Unlock()
		return TokenInfo{}, fmt.Errorf("invalid token")
	}
	if tok.Used {
		cs.mu.Unlock()
		return TokenInfo{}, fmt.Errorf("token already consumed by node %q", tok.UsedByNode)
	}
	if time.Now().After(tok.ExpiresAt) {
		cs.mu.Unlock()
		return TokenInfo{}, fmt.Errorf("token expired at %s", tok.ExpiresAt.Format(time.RFC3339))
	}
	if tok.NodePrefix != "" && !strings.HasPrefix(nodeID, tok.NodePrefix) {
		cs.mu.Unlock()
		return TokenInfo{}, fmt.Errorf("node ID %q does not match required prefix %q", nodeID, tok.NodePrefix)
	}
	if tok.AllowCIDR != "" {
		_, cidr, _ := net.ParseCIDR(tok.AllowCIDR)
		ip := net.ParseIP(sourceIP)
		if ip == nil || !cidr.Contains(ip) {
			cs.mu.Unlock()
			return TokenInfo{}, fmt.Errorf("source IP %s not in allowed CIDR %s", sourceIP, tok.AllowCIDR)
		}
	}

	// Mark consumed and capture metadata before releasing lock.
	tok.Used = true
	tok.UsedByNode = nodeID
	tok.UsedAt = time.Now()
	info := TokenInfo{CreatedBy: tok.CreatedBy}
	cs.mu.Unlock()

	// Persist consumed state so it survives crashes.
	if err := cs.Save(); err != nil {
		return TokenInfo{}, fmt.Errorf("persist token state: %w", err)
	}
	return info, nil
}

// Deprecated: Use ValidateAndConsumeToken instead, which also persists and returns metadata.
func (cs *ClusterStore) ValidateToken(plaintext, nodeID, sourceIP string) error {
	_, err := cs.ValidateAndConsumeToken(plaintext, nodeID, sourceIP)
	return err
}

// ListTokens returns all tokens (active and consumed).
func (cs *ClusterStore) ListTokens() []EnrollToken {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	result := make([]EnrollToken, 0, len(cs.st.Tokens))
	for _, t := range cs.st.Tokens {
		result = append(result, *t)
	}
	return result
}

// DeleteToken removes a token by its hash.
func (cs *ClusterStore) DeleteToken(tokenHash string) bool {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if _, ok := cs.st.Tokens[tokenHash]; !ok {
		return false
	}
	delete(cs.st.Tokens, tokenHash)
	return true
}

// ─── Node Registry ───────────────────────────────────────────────────────────

// RegisterNode adds a newly enrolled node to the registry.
func (cs *ClusterStore) RegisterNode(node *EnrolledNode) {
	cs.mu.Lock()
	cs.st.Nodes[node.NodeID] = node
	cs.mu.Unlock()
	if err := cs.Save(); err != nil {
		logger.Printf("Enrollment: failed to persist node %s: %v", node.NodeID, err)
	}
}

// GetNode returns a node by ID.
func (cs *ClusterStore) GetNode(nodeID string) (*EnrolledNode, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	n, ok := cs.st.Nodes[nodeID]
	return n, ok
}

// UpdateNodeSeen updates the LastSeen timestamp and status.
// Persists to disk every 10 heartbeats to avoid excessive I/O while
// still surviving restarts with reasonably fresh status.
func (cs *ClusterStore) UpdateNodeSeen(nodeID, ipAddr string) {
	cs.mu.Lock()
	if n, ok := cs.st.Nodes[nodeID]; ok {
		n.LastSeen = time.Now()
		n.Status = "connected"
		if ipAddr != "" {
			n.IPAddress = ipAddr
		}
	}
	cs.heartbeatCount++
	shouldSave := cs.heartbeatCount%10 == 0
	cs.mu.Unlock()
	if shouldSave {
		_ = cs.Save() //nolint:errcheck // best-effort periodic persistence
	}
}

// ListNodes returns all enrolled nodes.
func (cs *ClusterStore) ListNodes() []EnrolledNode {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	result := make([]EnrolledNode, 0, len(cs.st.Nodes))
	for _, n := range cs.st.Nodes {
		result = append(result, *n)
	}
	return result
}

// ─── Node Revocation ─────────────────────────────────────────────────────────

// RevokeNode revokes a node's certificate and marks it as revoked.
// State is persisted to disk so revocations survive CP restarts.
func (cs *ClusterStore) RevokeNode(nodeID, revokedBy, reason string) error {
	cs.mu.Lock()
	node, ok := cs.st.Nodes[nodeID]
	if !ok {
		cs.mu.Unlock()
		return fmt.Errorf("node %q not found", nodeID)
	}
	if node.Status == "revoked" {
		cs.mu.Unlock()
		return fmt.Errorf("node %q already revoked", nodeID)
	}

	node.Status = "revoked"

	cs.st.Revoked = append(cs.st.Revoked, RevokedCert{
		CertSerial: node.CertSerial,
		NodeID:     nodeID,
		RevokedAt:  time.Now(),
		RevokedBy:  revokedBy,
		Reason:     reason,
	})
	cs.mu.Unlock()

	if err := cs.Save(); err != nil {
		return fmt.Errorf("persist revocation: %w", err)
	}
	return nil
}

// IsRevoked checks if a certificate serial number is in the CRL.
func (cs *ClusterStore) IsRevoked(certSerial string) bool {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	for _, r := range cs.st.Revoked {
		if r.CertSerial == certSerial {
			return true
		}
	}
	return false
}

// ListRevoked returns all revoked certificates.
func (cs *ClusterStore) ListRevoked() []RevokedCert {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	result := make([]RevokedCert, len(cs.st.Revoked))
	copy(result, cs.st.Revoked)
	return result
}

// ─── Heartbeat Monitor ───────────────────────────────────────────────────────

const (
	heartbeatTimeout    = 90 * time.Second // 3 missed 30s polls
	heartbeatStaleWarn  = 24 * time.Hour
	heartbeatCheckEvery = 30 * time.Second
)

// StartHeartbeatMonitor runs a background loop that checks node health.
func (cs *ClusterStore) StartHeartbeatMonitor(done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(heartbeatCheckEvery)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				cs.checkHeartbeats()
			}
		}
	}()
}

func (cs *ClusterStore) checkHeartbeats() {
	cs.mu.Lock()
	now := time.Now()
	changed := cs.checkNodeLiveness(now)
	if cs.gcExpiredTokens(now) {
		changed = true
	}
	if cs.gcOldRevocations(now) {
		changed = true
	}
	cs.mu.Unlock()

	if changed {
		_ = cs.Save() //nolint:errcheck // best-effort periodic persistence
	}
}

// checkNodeLiveness marks unreachable nodes as disconnected. Caller holds mu.
func (cs *ClusterStore) checkNodeLiveness(now time.Time) bool {
	changed := false
	for _, node := range cs.st.Nodes {
		if node.Status == "revoked" || node.LastSeen.IsZero() {
			continue
		}
		elapsed := now.Sub(node.LastSeen)
		if elapsed > heartbeatTimeout && node.Status == "connected" {
			node.Status = "disconnected"
			changed = true
			logger.Printf("Enrollment: node %s unreachable (last seen %s ago)", node.NodeID, elapsed.Round(time.Second))
		}
		if elapsed > heartbeatStaleWarn && node.Status == "disconnected" {
			logger.Printf("Enrollment: node %s stale for >24h — consider revoking", node.NodeID)
		}
	}
	return changed
}

// gcExpiredTokens removes consumed (>7d) and unused-expired (>24h) tokens. Caller holds mu.
func (cs *ClusterStore) gcExpiredTokens(now time.Time) bool {
	changed := false
	for hash, tok := range cs.st.Tokens {
		if tokenExpired(tok, now) {
			delete(cs.st.Tokens, hash)
			changed = true
		}
	}
	return changed
}

func tokenExpired(tok *EnrollToken, now time.Time) bool {
	if tok.Used {
		return now.Sub(tok.UsedAt) > 7*24*time.Hour
	}
	return now.After(tok.ExpiresAt) && now.Sub(tok.ExpiresAt) > 24*time.Hour
}

// gcOldRevocations removes revoked cert entries older than 1 year. Caller holds mu.
func (cs *ClusterStore) gcOldRevocations(now time.Time) bool {
	if len(cs.st.Revoked) == 0 {
		return false
	}
	changed := false
	cleaned := make([]RevokedCert, 0, len(cs.st.Revoked))
	for _, r := range cs.st.Revoked {
		if now.Sub(r.RevokedAt) < 366*24*time.Hour {
			cleaned = append(cleaned, r)
		} else {
			changed = true
		}
	}
	cs.st.Revoked = cleaned
	return changed
}

// ─── Cluster CA (separate from MITM CA) ──────────────────────────────────────
// The cluster CA signs node certificates for mTLS enrollment.
// It is auto-generated on first use and persisted alongside cluster.json.

type clusterCA struct {
	mu            sync.RWMutex
	cert          *x509.Certificate
	key           *ecdsa.PrivateKey
	certPEM       []byte
	dir           string // persisted directory for cluster-ca.crt/key
	secondaryCert *x509.Certificate
	secondaryPEM  []byte
	secondaryExp  time.Time // when secondary CA expires (auto-cleanup)
	onRotate      func()    // callback to rebuild TLS cert pool after import
}

var globalClusterCA = &clusterCA{}

// safeCAPath returns filepath.Join(dir, name) after rejecting directory traversal.
func safeCAPath(dir, name string) (string, error) {
	if strings.Contains(dir, "..") {
		return "", fmt.Errorf("invalid CA directory: path traversal not allowed")
	}
	cleaned := filepath.Clean(filepath.Join(dir, name))
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("invalid CA path: directory traversal not allowed")
	}
	return cleaned, nil
}

// InitOrLoad initializes or loads the cluster CA from disk.
func (ca *clusterCA) InitOrLoad(dir string) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.dir = filepath.Clean(dir)
	certPath, err := safeCAPath(ca.dir, "cluster-ca.crt")
	if err != nil {
		return err
	}
	keyPath, err := safeCAPath(ca.dir, "cluster-ca.key")
	if err != nil {
		return err
	}

	// Try loading existing CA.
	certPEM, err1 := os.ReadFile(certPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if err1 == nil && err2 == nil {
		return ca.loadFromPEM(certPEM, keyPEM)
	}

	// Generate new cluster CA.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate cluster CA key: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return fmt.Errorf("generate CA serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Culvert Cluster CA", Organization: []string{"Culvert"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return fmt.Errorf("create cluster CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse cluster CA cert: %w", err)
	}

	// Persist to disk.
	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal cluster CA key: %w", err)
	}
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEMBlock, 0o600); err != nil {
		return fmt.Errorf("write cluster CA cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEMBlock, 0o600); err != nil {
		return fmt.Errorf("write cluster CA key: %w", err)
	}

	ca.cert = cert
	ca.key = privKey
	ca.certPEM = certPEMBlock
	logger.Printf("ClusterCA: generated new cluster CA (expires %s)", cert.NotAfter.Format("2006-01-02"))
	return nil
}

func (ca *clusterCA) loadFromPEM(certPEM, keyPEM []byte) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("no PEM certificate block found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse cluster CA cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("no PEM key block found")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse cluster CA key: %w", err)
	}

	ca.cert = cert
	ca.key = key
	ca.certPEM = certPEM
	logger.Printf("ClusterCA: loaded existing cluster CA (expires %s)", cert.NotAfter.Format("2006-01-02"))
	return nil
}

// SignCSR signs a CSR and returns the signed certificate PEM.
func (ca *clusterCA) SignCSR(csrPEM []byte, nodeID string) (certPEM []byte, serial string, expiry time.Time, err error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	if ca.cert == nil || ca.key == nil {
		return nil, "", time.Time{}, fmt.Errorf("cluster CA not initialized")
	}

	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, "", time.Time{}, fmt.Errorf("no PEM CSR block found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, "", time.Time{}, fmt.Errorf("CSR signature invalid: %w", err)
	}

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNum, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("generate serial: %w", err)
	}

	notAfter := time.Now().Add(365 * 24 * time.Hour) // 1 year
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      pkix.Name{CommonName: nodeID, Organization: []string{"Culvert Data Plane"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("sign certificate: %w", err)
	}

	certPEMBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEMBlock, serialNum.Text(16), notAfter, nil
}

// CACertPEM returns the CA certificate in PEM format.
func (ca *clusterCA) CACertPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certPEM
}

// CACertFingerprint returns the SHA-256 fingerprint of the CA cert.
func (ca *clusterCA) CACertFingerprint() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return ""
	}
	fp := sha256.Sum256(ca.cert.Raw)
	return hex.EncodeToString(fp[:])
}

// Ready returns true if the cluster CA is initialized.
func (ca *clusterCA) Ready() bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.cert != nil && ca.key != nil
}

// ImportCA validates and replaces the cluster CA with user-provided PEM cert+key.
//
// Dual-CA overlap: the old CA is preserved as a secondary so that existing
// enrolled nodes (whose certs were signed by the old CA) continue to be
// accepted until their certificates expire. New enrollments get certs
// signed by the new CA. The secondary is auto-cleaned when the old CA
// certificate expires.
// parseAndValidateCACert parses and validates a CA certificate PEM block.
func parseAndValidateCACert(certPEM []byte) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM certificate block found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA (BasicConstraints.IsCA = false)")
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate has already expired (%s)", cert.NotAfter.Format("2006-01-02"))
	}
	return cert, nil
}

// parseAndValidateCAKey parses an ECDSA private key PEM block with descriptive errors.
func parseAndValidateCAKey(keyPEM []byte, certPub *ecdsa.PublicKey) (*ecdsa.PrivateKey, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("no PEM private key block found")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		if _, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); rsaErr == nil {
			return nil, fmt.Errorf("RSA keys are not supported; cluster CA requires an ECDSA P-256 private key")
		}
		if _, pkcs8Err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); pkcs8Err == nil {
			return nil, fmt.Errorf("key is PKCS#8 but not ECDSA; cluster CA requires an ECDSA P-256 private key (EC PRIVATE KEY PEM block)")
		}
		return nil, fmt.Errorf("parse private key: %w — cluster CA requires an ECDSA P-256 key", err)
	}
	if !certPub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("certificate and private key do not match")
	}
	return key, nil
}

func (ca *clusterCA) ImportCA(certPEM, keyPEM []byte) error {
	cert, err := parseAndValidateCACert(certPEM)
	if err != nil {
		return err
	}
	key, err := parseAndValidateCAKey(keyPEM, cert.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		return err
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	dir := ca.dir
	if dir == "" {
		dir = "."
	}
	certFile, pathErr := safeCAPath(dir, "cluster-ca.crt")
	if pathErr != nil {
		return pathErr
	}
	keyFile, pathErr := safeCAPath(dir, "cluster-ca.key")
	if pathErr != nil {
		return pathErr
	}

	// ── Backup old CA before overwriting ──
	if ca.certPEM != nil {
		if bakPath, e := safeCAPath(dir, "cluster-ca.crt.bak"); e == nil {
			_ = os.WriteFile(bakPath, ca.certPEM, 0o600)
		}
		if bakPath, e := safeCAPath(dir, "cluster-ca.key.bak"); e == nil {
			// Re-derive keyFile path inline so gosec sees the sanitiser chain.
			safeKeyFile := filepath.Clean(filepath.Join(dir, "cluster-ca.key"))
			if !strings.Contains(safeKeyFile, "..") {
				if oldKey, readErr := os.ReadFile(safeKeyFile); readErr == nil { // #nosec G304 -- ".." rejected
					_ = os.WriteFile(bakPath, oldKey, 0o600)
				}
			}
		}
	}

	// ── Dual-CA overlap: preserve old CA as secondary ──
	if ca.cert != nil {
		ca.secondaryCert = ca.cert
		ca.secondaryPEM = ca.certPEM
		ca.secondaryExp = ca.cert.NotAfter
		logger.Printf("ClusterCA: old CA preserved as secondary (expires %s)",
			ca.cert.NotAfter.Format("2006-01-02"))
	}

	// ── Persist new CA to disk ──
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		return fmt.Errorf("write cluster CA cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write cluster CA key: %w", err)
	}

	ca.cert = cert
	ca.key = key
	ca.certPEM = certPEM

	fp := sha256.Sum256(cert.Raw)
	logger.Printf("ClusterCA: imported custom CA (expires %s, fingerprint %s)",
		cert.NotAfter.Format("2006-01-02"), sanitizeLog(hex.EncodeToString(fp[:])))

	// Notify TLS layer to rebuild cert pool with both CAs.
	if ca.onRotate != nil {
		ca.onRotate()
	}
	return nil
}

// SecondaryActive returns true if a secondary (old) CA is still in the overlap period.
func (ca *clusterCA) SecondaryActive() bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.secondaryCert != nil && time.Now().Before(ca.secondaryExp)
}

// CleanupSecondary removes the secondary CA if it has expired.
func (ca *clusterCA) CleanupSecondary() {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.secondaryCert != nil && time.Now().After(ca.secondaryExp) {
		logger.Printf("ClusterCA: secondary CA expired, removing overlap")
		ca.secondaryCert = nil
		ca.secondaryPEM = nil
		ca.secondaryExp = time.Time{}
		if ca.onRotate != nil {
			ca.onRotate()
		}
	}
}

// AllCACertsPEM returns PEM blocks for all active CAs (primary + secondary if overlapping).
// Used by buildServerTLS to populate the client cert pool.
func (ca *clusterCA) AllCACertsPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	var buf []byte
	if ca.certPEM != nil {
		buf = append(buf, ca.certPEM...)
	}
	if ca.secondaryCert != nil && time.Now().Before(ca.secondaryExp) && ca.secondaryPEM != nil {
		buf = append(buf, ca.secondaryPEM...)
	}
	return buf
}

// RotateIfNeeded checks cluster CA expiry and auto-rotates if it expires
// within 30 days. Preserves the old CA as secondary for dual-CA overlap.
func (ca *clusterCA) RotateIfNeeded() {
	ca.mu.RLock()
	if ca.cert == nil {
		ca.mu.RUnlock()
		return
	}
	daysLeft := time.Until(ca.cert.NotAfter).Hours() / 24
	ca.mu.RUnlock()

	if daysLeft > 30 {
		return
	}
	logger.Printf("ClusterCA: expires in %.0f days — auto-rotating", daysLeft)

	// Generate new CA.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (keygen): %v", err)
		return
	}
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (serial): %v", err)
		return
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Culvert Cluster CA", Organization: []string{"Culvert"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (create cert): %v", err)
		return
	}
	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (marshal key): %v", err)
		return
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// ImportCA handles dual-CA overlap, backup, persistence, and TLS pool rebuild.
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (import): %v", err)
		return
	}
	logger.Printf("ClusterCA: auto-rotated successfully (new CA expires %s)",
		template.NotAfter.Format("2006-01-02"))
}

// Info returns cluster CA metadata for the admin API.
func (ca *clusterCA) Info() map[string]any {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return map[string]any{"initialized": false}
	}
	fp := sha256.Sum256(ca.cert.Raw)
	info := map[string]any{
		"initialized": true,
		"subject":     ca.cert.Subject.CommonName,
		"expires":     ca.cert.NotAfter.Format(time.RFC3339),
		"fingerprint": hex.EncodeToString(fp[:]),
		"serial":      ca.cert.SerialNumber.Text(16),
	}
	if ca.secondaryCert != nil && time.Now().Before(ca.secondaryExp) {
		sfp := sha256.Sum256(ca.secondaryCert.Raw)
		info["dualCAActive"] = true
		info["secondaryCA"] = map[string]any{
			"subject":     ca.secondaryCert.Subject.CommonName,
			"expires":     ca.secondaryCert.NotAfter.Format(time.RFC3339),
			"fingerprint": hex.EncodeToString(sfp[:]),
		}
	}
	return info
}

// ─── Enrollment Request/Response (gRPC) ──────────────────────────────────────

// EnrollRequest is sent by a DP node during enrollment.
type EnrollRequest struct {
	Token  string `json:"token"`
	CSR    string `json:"csr"`     // PEM-encoded CSR
	NodeID string `json:"node_id"`
}

// EnrollResponse is returned by the CP after successful enrollment.
type EnrollResponse struct {
	CertPEM string `json:"cert_pem"` // signed node certificate
	CAPEM   string `json:"ca_pem"`   // cluster CA certificate
	NodeID  string `json:"node_id"`
	CPAddr  string `json:"cp_addr"` // control plane gRPC address for reconnect
}

