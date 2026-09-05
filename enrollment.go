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

	"github.com/KidCarmi/Culvert/internal/secret"
)

// ─── Cluster State ───────────────────────────────────────────────────────────

// ClusterState holds all enrollment-related state persisted to cluster.json.
type ClusterState struct {
	Nodes      map[string]*EnrolledNode `json:"nodes"`
	Tokens     map[string]*EnrollToken  `json:"tokens"` // key = SHA-256(token)
	Revoked    []RevokedCert            `json:"revoked"`
	Version    int64                    `json:"version"` // monotonic config version
	CARotation *CARotationState         `json:"ca_rotation,omitempty"`
}

// CARotationState tracks the progress of an active CA rotation.
// Created when a new CA is imported during dual-CA overlap, cleared when
// all nodes have renewed or the overlap period ends.
type CARotationState struct {
	StartedAt      time.Time         `json:"started_at"`
	NewFingerprint string            `json:"new_fingerprint"` // SHA-256 of new CA cert
	OldFingerprint string            `json:"old_fingerprint"` // SHA-256 of old (secondary) CA cert
	OldExpires     time.Time         `json:"old_expires"`     // when secondary CA expires
	RenewedNodes   map[string]string `json:"renewed_nodes"`   // nodeID → timestamp of renewal
	TotalNodes     int               `json:"total_nodes"`     // snapshot of enrolled (non-revoked) count at start
}

// EnrolledNode represents a registered Data Plane node.
type EnrolledNode struct {
	NodeID     string            `json:"node_id"`
	CertSerial string            `json:"cert_serial"`
	CertExpiry time.Time         `json:"cert_expiry"`
	EnrolledAt time.Time         `json:"enrolled_at"`
	EnrolledBy string            `json:"enrolled_by"` // admin username
	LastSeen   time.Time         `json:"last_seen"`
	Status     string            `json:"status"` // "connected", "disconnected", "revoked", "draining"
	IPAddress  string            `json:"ip_address"`
	Version    string            `json:"version"`          // culvert version on node
	Labels     map[string]string `json:"labels,omitempty"` // admin-assigned labels (e.g. "region":"us-east", "tier":"dmz")
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
	// Re-surface an unreconciled quarantine from a prior boot (CHAOS-07):
	// after a corrupt load the node saves a fresh EMPTY cluster.json that
	// parses cleanly next time, so the /readyz row and the revoked-cert
	// amnesia would go silent while the .corrupt.* evidence persists.
	noteResidualQuarantine("cluster", path)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // first run, start empty
		}
		return fmt.Errorf("read cluster state: %w", err)
	}
	var st ClusterState
	if err := json.Unmarshal(data, &st); err != nil {
		// CHAOS-07: present-but-corrupt cluster DB. The caller "starts
		// fresh", and the next Save would overwrite the enrolled-node
		// roster AND the revoked-cert list — revoked DP certs would
		// validate again with no trace. Quarantine the evidence first.
		quarantineCorruptStateFile("cluster", path, err)
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
	// If a CA rotation was in progress at shutdown and the JSON payload
	// omits or nils out renewed_nodes, RecordNodeRenewed will panic with
	// "assignment to entry in nil map" when the first node reports back.
	// Normalise defensively — same pattern as the top-level maps above.
	if st.CARotation != nil && st.CARotation.RenewedNodes == nil {
		st.CARotation.RenewedNodes = make(map[string]string)
	}
	cs.st = st
	return nil
}

// Save persists cluster state to disk.
//
// Uses RLock so concurrent admin-handler Save() calls do not block each
// other. atomicWriteFile keeps each write atomic on its own (unique tmp
// + rename), but switching to Lock for stronger serialization is worth
// re-evaluating in a follow-up.
func (cs *ClusterStore) Save() error {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return cs.saveLocked()
}

// saveLocked persists state without acquiring locks — caller must hold mu.
func (cs *ClusterStore) saveLocked() error {
	if cs.path == "" {
		return nil // no persistence path set
	}
	data, err := json.MarshalIndent(cs.st, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cluster state: %w", err)
	}
	if err := atomicWriteFile(cs.path, data, 0o600); err != nil {
		return err
	}
	statClusterStoreSaves.Add(1) // CL-9 PR2: count successful persists
	return nil
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
func (cs *ClusterStore) ValidateAndConsumeToken(plaintext, nodeID, sourceIP string) (out TokenInfo, err error) {
	// CL-9 PR1: count token outcomes. Runs after the method's explicit
	// cs.mu.Unlock on every path; the atomic acquires no lock.
	defer func() {
		if err != nil {
			statEnrollFailures.Add(1)
		} else {
			statEnrollTokensConsumed.Add(1)
		}
	}()

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
		_, cidr, cidrErr := net.ParseCIDR(tok.AllowCIDR)
		if cidrErr != nil || cidr == nil {
			// Malformed CIDR (e.g. corrupted persisted token state). Fail
			// closed rather than dereferencing a nil *net.IPNet below.
			cs.mu.Unlock()
			return TokenInfo{}, fmt.Errorf("token has invalid allowed CIDR %q: %w", tok.AllowCIDR, cidrErr)
		}
		ip := net.ParseIP(sourceIP)
		if ip == nil || !cidr.Contains(ip) {
			cs.mu.Unlock()
			return TokenInfo{}, fmt.Errorf("source IP %s not in allowed CIDR %s", sourceIP, tok.AllowCIDR)
		}
	}

	// Mark consumed and capture metadata; persist while lock is held to prevent
	// race between consumption and crash (B15).
	tok.Used = true
	tok.UsedByNode = nodeID
	tok.UsedAt = time.Now()
	info := TokenInfo{CreatedBy: tok.CreatedBy}
	if err := cs.saveLocked(); err != nil {
		cs.mu.Unlock()
		return TokenInfo{}, fmt.Errorf("persist token state: %w", err)
	}
	cs.mu.Unlock()
	return info, nil
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

// TokenExists checks whether a plaintext token is valid (exists, unused, not expired).
// It does NOT consume the token.
func (cs *ClusterStore) TokenExists(plaintext string) bool {
	hash := hashToken(plaintext)
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	tok, ok := cs.st.Tokens[hash]
	if !ok || tok.Used || time.Now().After(tok.ExpiresAt) {
		return false
	}
	return true
}

// ─── Node Registry ───────────────────────────────────────────────────────────

// autoGeoLabel sets geo:country and geo:country_name labels on a node when
// GeoIP is enabled and the node has a non-empty IPAddress.  Existing labels
// are preserved; geo labels are only added, never overwritten by the caller's
// explicit values.
func autoGeoLabel(node *EnrolledNode) {
	if node.IPAddress == "" {
		return
	}
	if code, name := geo.LookupFull(node.IPAddress); code != "" {
		if node.Labels == nil {
			node.Labels = make(map[string]string)
		}
		node.Labels["geo:country"] = code
		node.Labels["geo:country_name"] = name
	}
}

// RegisterNode adds a newly enrolled node to the registry.
// If GeoIP is enabled, auto-populates geo:country and geo:country_name labels.
func (cs *ClusterStore) RegisterNode(node *EnrolledNode) {
	autoGeoLabel(node)
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

// UpdateNodeSeen updates the LastSeen timestamp and status. An empty ipAddr or
// version is skipped so a heartbeat that omits either (e.g. an older DP that
// predates the M5 version report) never wipes a previously-recorded value.
// Persists to disk every 10 heartbeats to avoid excessive I/O while
// still surviving restarts with reasonably fresh status.
func (cs *ClusterStore) UpdateNodeSeen(nodeID, ipAddr, version string) {
	cs.mu.Lock()
	if n, ok := cs.st.Nodes[nodeID]; ok {
		n.LastSeen = time.Now()
		n.Status = "connected"
		if ipAddr != "" {
			n.IPAddress = ipAddr
			autoGeoLabel(n)
		}
		if version != "" {
			n.Version = version
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

// NodeCounts returns the total number of enrolled nodes and the subset that
// are currently "connected" (CL-9 PR1). Allocation-free; for scrape-time gauges.
func (cs *ClusterStore) NodeCounts() (total, connected int) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	for _, n := range cs.st.Nodes {
		total++
		if n.Status == "connected" {
			connected++
		}
	}
	return
}

// SetNodeLabels replaces the label set on a node. Pass nil or empty map to clear.
func (cs *ClusterStore) SetNodeLabels(nodeID string, labels map[string]string) error {
	cs.mu.Lock()
	node, ok := cs.st.Nodes[nodeID]
	if !ok {
		cs.mu.Unlock()
		return fmt.Errorf("node %q not found", nodeID)
	}
	if len(labels) == 0 {
		node.Labels = nil
	} else {
		node.Labels = make(map[string]string, len(labels))
		for k, v := range labels {
			node.Labels[k] = v
		}
	}
	cs.mu.Unlock()
	return cs.Save()
}

// SetNodeDraining sets a node's status to "draining" for maintenance mode.
func (cs *ClusterStore) SetNodeDraining(nodeID string, draining bool) error {
	cs.mu.Lock()
	node, ok := cs.st.Nodes[nodeID]
	if !ok {
		cs.mu.Unlock()
		return fmt.Errorf("node %q not found", nodeID)
	}
	if node.Status == "revoked" {
		cs.mu.Unlock()
		return fmt.Errorf("node %q is revoked", nodeID)
	}
	if draining {
		node.Status = "draining"
	} else {
		node.Status = "connected"
	}
	cs.mu.Unlock()
	return cs.Save()
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

// RevokeSerial appends a certificate serial to the CRL WITHOUT changing the
// owning node's status — for certs superseded while the node stays
// registered (expired-node re-enrollment). RevokeNode remains the operator
// path that retires the node itself.
func (cs *ClusterStore) RevokeSerial(certSerial, nodeID, revokedBy, reason string) error {
	cs.mu.Lock()
	cs.st.Revoked = append(cs.st.Revoked, RevokedCert{
		CertSerial: certSerial,
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

// ─── CA Rotation Tracking ───────────────────────────────────────────────────

// StartCARotation records the beginning of a CA rotation. Called from ImportCA
// when dual-CA overlap begins. Counts only non-revoked nodes.
func (cs *ClusterStore) StartCARotation(newFP, oldFP string, oldExpires time.Time) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	total := 0
	for _, n := range cs.st.Nodes {
		if n.Status != "revoked" {
			total++
		}
	}
	cs.st.CARotation = &CARotationState{
		StartedAt:      time.Now(),
		NewFingerprint: newFP,
		OldFingerprint: oldFP,
		OldExpires:     oldExpires,
		RenewedNodes:   make(map[string]string),
		TotalNodes:     total,
	}
	if err := cs.saveLocked(); err != nil {
		logger.Printf("CARotation: failed to persist start: %v", err)
	}
	logger.Printf("CARotation: started — %d nodes pending renewal", total)
}

// RecordNodeRenewed marks a node as having renewed its cert during active rotation.
func (cs *ClusterStore) RecordNodeRenewed(nodeID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.st.CARotation == nil {
		return
	}
	cs.st.CARotation.RenewedNodes[nodeID] = time.Now().UTC().Format(time.RFC3339)
	renewed := len(cs.st.CARotation.RenewedNodes)
	total := cs.st.CARotation.TotalNodes
	logger.Printf("CARotation: node %q renewed (%d/%d complete)", sanitizeLog(nodeID), renewed, total)
	if renewed >= total {
		logger.Printf("CARotation: all %d nodes renewed — rotation complete", total)
	}
	if err := cs.saveLocked(); err != nil {
		logger.Printf("CARotation: failed to persist renewal: %v", err)
	}
}

// CARotationStatus returns the current rotation state, or nil if no rotation is active.
func (cs *ClusterStore) CARotationStatus() *CARotationState {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	if cs.st.CARotation == nil {
		return nil
	}
	// Return a copy.
	rot := *cs.st.CARotation
	rot.RenewedNodes = make(map[string]string, len(cs.st.CARotation.RenewedNodes))
	for k, v := range cs.st.CARotation.RenewedNodes {
		rot.RenewedNodes[k] = v
	}
	return &rot
}

// ClearCARotation clears the rotation state (e.g. when overlap ends).
func (cs *ClusterStore) ClearCARotation() {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if cs.st.CARotation != nil {
		cs.st.CARotation = nil
		if err := cs.saveLocked(); err != nil {
			logger.Printf("CARotation: failed to persist clear: %v", err)
		}
	}
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
	// B16: Persist under held lock to prevent concurrent mutations from
	// overwriting heartbeat status transitions between unlock and save.
	if changed {
		_ = cs.saveLocked() //nolint:errcheck // best-effort periodic persistence
	}
	cs.mu.Unlock()
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
			statHeartbeatDisconnects.Add(1)
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

// ExportState returns the full cluster state as JSON for HA replication.
func (cs *ClusterStore) ExportState() (json.RawMessage, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return json.Marshal(cs.st)
}

// ImportFullState replaces the entire cluster state from HA leader replication.
func (cs *ClusterStore) ImportFullState(data json.RawMessage) error {
	var st ClusterState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse replicated state: %w", err)
	}
	if st.Nodes == nil {
		st.Nodes = make(map[string]*EnrolledNode)
	}
	if st.Tokens == nil {
		st.Tokens = make(map[string]*EnrollToken)
	}
	// Same nil-map defence as Load() — a follower that replays replicated
	// state while a CA rotation is in progress would otherwise panic on the
	// first RecordNodeRenewed call if renewed_nodes was null/missing.
	if st.CARotation != nil && st.CARotation.RenewedNodes == nil {
		st.CARotation.RenewedNodes = make(map[string]string)
	}
	cs.mu.Lock()
	cs.st = st
	_ = cs.saveLocked()
	cs.mu.Unlock()
	return nil
}

// ─── Cluster CA (separate from MITM CA) ──────────────────────────────────────
// The cluster CA signs node certificates for mTLS enrollment.
// It is auto-generated on first use and persisted alongside cluster.json.

type clusterCA struct {
	// mu guards the fields below. It is held for the SHORTEST possible window
	// and NEVER across a call that reads the cluster CA back (directly or via
	// globalClusterCA): every such call takes mu.RLock, sync.RWMutex is not
	// reentrant, and the receiver IS the package global in production. See
	// ImportCA and CleanupSecondary for the two sites where that was a hard
	// self-deadlock (CHAOS-50).
	mu sync.RWMutex
	// importMu serialises whole import/cleanup operations — including their
	// post-commit side effects — WITHOUT holding mu across them, so concurrent
	// imports cannot interleave while readers stay unblocked.
	importMu      sync.Mutex
	cert          *x509.Certificate
	key           *ecdsa.PrivateKey
	certPEM       []byte
	dir           string // persisted directory for cluster-ca.crt/key
	secondaryCert *x509.Certificate
	secondaryPEM  []byte
	secondaryExp  time.Time // when secondary CA expires (auto-cleanup)
	onRotate      func()    // callback to rebuild TLS cert pool after import
	// lastRotationErr/lastRotationErrAt record the most recent RotateIfNeeded
	// failure so it is visible on Info() (admin API) instead of only in logs —
	// otherwise a stuck auto-rotation (e.g. a read-only CA directory) is
	// silent until the CA actually expires and the cluster mTLS trust breaks.
	// Cleared on the next successful ImportCA (auto-rotation or manual).
	lastRotationErr   string
	lastRotationErrAt time.Time
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

	// Inspect on-disk state. Distinguish four cases:
	//   (true,  true)  → load existing pair (cross-validated by loadFromPEM)
	//   (false, false) → fresh bootstrap (fall through)
	//   (true,  false) or (false, true) → fail closed: refuse to overwrite
	//     a surviving file with a regenerated CA. Operator must remove both
	//     files for a clean re-bootstrap, or restore the missing one.
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	certMissing := certErr != nil && os.IsNotExist(certErr)
	keyMissing := keyErr != nil && os.IsNotExist(keyErr)

	// Surface non-ENOENT read errors (permission, I/O, etc.) — fail closed.
	if certErr != nil && !certMissing {
		return fmt.Errorf("read cluster CA cert %q: %w", certPath, certErr)
	}
	if keyErr != nil && !keyMissing {
		return fmt.Errorf("read cluster CA key %q: %w", keyPath, keyErr)
	}

	switch {
	case !certMissing && !keyMissing:
		// CA-3: decrypt at-rest key if it is a PSCA envelope (content-driven,
		// fail closed on KEK/corruption — never regenerate). loadFromPEM stays
		// a pure plaintext-PEM parser.
		sealed, wasEncrypted, decErr := openClusterCAKey(ca.dir, keyPEM)
		if decErr != nil {
			return decErr
		}
		// The decrypted CA key stays inside the closure and is zeroized on return;
		// it never crosses back into package main as a plain []byte.
		return sealed.WithPlaintext(func(plainKey []byte) error {
			if err := ca.loadFromPEM(certPEM, plainKey); err != nil {
				return err
			}
			// Opt-in migration: plaintext on disk + encryption enabled → migrate.
			if !wasEncrypted && clusterCAKeyEncryptionEnabled() {
				return migrateClusterCAKeyToEncrypted(ca.dir, keyPath, plainKey)
			}
			return nil
		})
	case !certMissing && keyMissing:
		return fmt.Errorf("cluster CA bootstrap: partial pair on disk (cert %q present, key %q missing) — refuse to overwrite; remove both files for fresh bootstrap or restore the missing one", certPath, keyPath)
	case certMissing && !keyMissing:
		return fmt.Errorf("cluster CA bootstrap: partial pair on disk (cert %q missing, key %q present) — refuse to overwrite; remove both files for fresh bootstrap or restore the missing one", certPath, keyPath)
	}
	// Both missing — generate new cluster CA.
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

	// Each file written via the hardened atomic helper. Note: this does
	// NOT make the two-file bootstrap atomic — a crash between cert and
	// key writes still leaves a partial pair. That state is detected on
	// next startup by the partial-pair check above and fails closed.
	if err := atomicWriteFile(certPath, certPEMBlock, 0o600); err != nil {
		return fmt.Errorf("write cluster CA cert: %w", err)
	}
	// CA-3: encrypt the key at rest when enabled; plaintext otherwise.
	if err := writeClusterCAKey(ca.dir, keyPath, keyPEMBlock); err != nil {
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

	// Cross-validate: cert public key must match private key public component.
	// Cluster CA is ECDSA P-256 by construction (see InitOrLoad); a non-ECDSA
	// cert public key is rejected explicitly so any future RSA/Ed25519 swap
	// must update this check intentionally rather than silently bypassing it.
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("cluster CA cert public key is %T, expected *ecdsa.PublicKey", cert.PublicKey)
	}
	keyPub := &key.PublicKey
	if certPub.Curve != keyPub.Curve ||
		certPub.X.Cmp(keyPub.X) != 0 ||
		certPub.Y.Cmp(keyPub.Y) != 0 {
		return fmt.Errorf("cluster CA cert/key mismatch: public keys do not agree")
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

	// CHAOS-50 / CA-13: fail CLOSED when the cluster CA is outside its own
	// validity window. x509.CreateCertificate does not check the parent's
	// NotBefore/NotAfter, so without this the CP kept minting node identities
	// that no peer can verify — and because Enroll accepts an unauthenticated
	// caller (VerifyClientCertIfGiven), the operator's recovery action returned
	// success while producing a certificate that was dead on arrival.
	//
	// The guard lives HERE rather than only at the RPC gates because both the
	// Enroll and the RenewCert path reach the signer, and renewal is the one
	// that runs unattended on every node in the fleet.
	if err := clusterCAUsable(ca.cert, time.Now()); err != nil {
		noteClusterCASignRefused(err.Error())
		return nil, "", time.Time{}, err
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

	// CHAOS-50 / CA-13: clamp the node cert to the issuer's window. Unclamped,
	// a node enrolled at any point in the cluster CA's final year held a
	// certificate whose stated expiry was months past its issuer's — so every
	// surface (the nodes API, the node's own checkDPCertExpiry) reported months
	// of validity while the chain was days from dying. See
	// clampNodeCertValidity for why the clamp is inert on a healthy fleet.
	notBefore, notAfter, clamped := clampNodeCertValidity(
		time.Now().Add(-5*time.Minute),
		time.Now().Add(365*24*time.Hour), // 1 year
		ca.cert,
	)
	if clamped {
		noteClusterCAClamped(notAfter)
	}
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      pkix.Name{CommonName: nodeID, Organization: []string{"Culvert Data Plane"}},
		NotBefore:    notBefore,
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

// CAKeyPEM returns the PEM-encoded CA private key for HA state replication.
// SECURITY: This is sensitive material — only transmitted over mTLS to
// authenticated HA peers.
func (ca *clusterCA) CAKeyPEM() []byte {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.key == nil {
		return nil
	}
	keyBytes, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
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

// KeyDir reports the directory the cluster CA key pair persists to, or ""
// before InitOrLoad has run. Read-only accessor for diagnostics
// (keyatrest_diagnostics.go) — never exposes key material.
func (ca *clusterCA) KeyDir() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.dir
}

// ImportCA validates and replaces the cluster CA with user-provided PEM cert+key.
//
// Dual-CA overlap: the old CA is preserved as a secondary so that existing
// enrolled nodes (whose certs were signed by the old CA) continue to be
// accepted until their certificates expire. New enrollments get certs
// signed by the new CA. The secondary is auto-cleaned when the old CA
// certificate expires.
// backupCAFiles copies the current CA cert and key to .bak files.
// Uses in-memory key to avoid any file reads (eliminates gosec G703/G304).
// Best-effort, errors ignored.
func backupCAFiles(dir string, certPEM []byte, key *ecdsa.PrivateKey) {
	certBak, e1 := safeCAPath(dir, "cluster-ca.crt.bak")
	keyBak, e2 := safeCAPath(dir, "cluster-ca.key.bak")
	if e1 != nil || e2 != nil {
		return
	}
	_ = os.WriteFile(certBak, certPEM, 0o600)
	if key != nil {
		if der, err := x509.MarshalECPrivateKey(key); err == nil {
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
			// CA-3: when encryption is enabled, the key .bak must not be left
			// as plaintext on disk. Best-effort, consistent with this helper.
			if clusterCAKeyEncryptionEnabled() {
				_ = secret.SealToFile(keyBak, keyPEM, clusterCAKEKProvider(dir))
			} else {
				_ = os.WriteFile(keyBak, keyPEM, 0o600)
			}
		}
	}
}

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
	// Reject a NOT-YET-VALID CA at the door, symmetric with the expiry check
	// above: under the strict Usable() gate a successful import of such a CA
	// would instantly disable issuance ("import succeeded" followed by every
	// enrollment refusing until NotBefore arrives) — the review P1 on the
	// competing CHAOS-50 implementation (#1166). A small tolerance absorbs
	// honest clock skew from the host that generated the CA; anything beyond
	// it is either a clock fault (fix NTP) or a mis-cut certificate, and both
	// are better refused with this message than accepted into an unusable
	// trust root.
	if notBefore := cert.NotBefore.Add(-5 * time.Minute); time.Now().Before(notBefore) {
		return nil, fmt.Errorf("certificate is not valid until %s — importing it would disable node-certificate issuance until then; check this host's clock (NTP) or re-issue the CA",
			cert.NotBefore.UTC().Format(time.RFC3339))
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

// clusterCAImportEffects carries everything the post-commit side effects need,
// captured while ca.mu is held so they can run once it is RELEASED. See
// ImportCA for why that split is mandatory rather than stylistic.
type clusterCAImportEffects struct {
	onRotate     func()
	newFP        string
	oldFP        string
	secondaryExp time.Time
	trackRotate  bool // false on a first import: a bootstrap is not a rotation
}

// ImportCA validates a cert+key pair, commits it as the active cluster CA, and
// then runs the post-commit side effects (TLS-pool rebuild, rotation tracking,
// config publication, metrics).
//
// CHAOS-50: the commit and the side effects are DELIBERATELY split, with ca.mu
// released in between, because every one of those side effects reads the cluster
// CA back through the package global — and the global IS this receiver in
// production. Running them under the write lock was a hard self-deadlock, proven
// on main with this stack:
//
//	goroutine [sync.RWMutex.RLock]:
//	  (*clusterCA).CACertFingerprint(0x…480)
//	  (*clusterCA).ImportCA(0x…480, …)      ← already holds Lock on 0x…480
//
// sync.RWMutex is not reentrant, so the goroutine blocked forever WHILE HOLDING
// the write lock: every later SignCSR (enrollment and renewal), Ready(), Info(),
// CACertFingerprint (hence all config publication) and AllCACertsPEM (hence the
// TLS pool rebuild) blocked behind it. One import wedged the whole control
// plane until restart.
//
// It fired on two ordinary paths, not an exotic one: POST /api/cluster/ca (the
// documented enterprise custom-CA import) and, unattended, RotateIfNeeded 30
// days before the CA's expiry — which also hangs the shared rotation goroutine,
// so the INSPECTION CA silently stops rotating too.
//
// The reason it survived is worth recording: the test suite knew. Every test
// that reaches ImportCA points globalClusterCA at a SEPARATE empty CA
// specifically so the snapshot read misses the held lock
// (cluster_ca_keyatrest_test.go says so in as many words, calling it "a
// pre-existing self-deadlock … out of scope"). The workaround made the suite
// green and kept the defect off the register. TestChaos50_ImportCADoesNotDeadlock
// now drives the production aliasing on purpose.
//
// Concurrent imports are serialised by importMu instead, so two admins racing
// cannot interleave side effects — and readers are never blocked by them.
func (ca *clusterCA) ImportCA(certPEM, keyPEM []byte) error {
	cert, err := parseAndValidateCACert(certPEM)
	if err != nil {
		return err
	}
	key, err := parseAndValidateCAKey(keyPEM, cert.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		return err
	}

	ca.importMu.Lock()
	defer ca.importMu.Unlock()

	eff, err := ca.commitImport(cert, key, certPEM, keyPEM)
	if err != nil {
		return err
	}

	// ── Post-commit side effects, with ca.mu RELEASED ──
	//
	// Ordering is preserved from the original: rebuild the TLS pool first (so a
	// handshake arriving now sees both CAs), then start rotation tracking, then
	// publish the snapshot that tells DP nodes to renew.
	if eff.onRotate != nil {
		eff.onRotate()
	}
	if eff.trackRotate {
		globalClusterStore.StartCARotation(eff.newFP, eff.oldFP, eff.secondaryExp)
	}
	// Bump config version so DP nodes pick up the new CA fingerprint on next poll.
	// A commit-time rejection (config over a cap) is logged + alerted + surfaced
	// via LastPublishError; CA rotation itself already succeeded above.
	_ = globalConfigStore.Update(CurrentConfigSnapshot())

	statClusterCARotations.Add(1)
	// CHAOS-50: the other half of the rotation-degraded pair. A rotation that
	// LANDED is the only evidence that clears the warning — see
	// clusterCARotationDegraded for why the cumulative counter must not be used
	// for that. The cert+key are on disk by this point (both writes inside
	// commitImport returned nil), so this is an observed persistence success,
	// not an assumption.
	noteClusterCARotated()
	return nil
}

// commitImport is the locked half of ImportCA: backup, dual-CA demotion,
// durable write, and the in-memory swap. It returns the inputs the caller needs
// for the side effects it must run with ca.mu released.
func (ca *clusterCA) commitImport(cert *x509.Certificate, key *ecdsa.PrivateKey, certPEM, keyPEM []byte) (clusterCAImportEffects, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	var eff clusterCAImportEffects

	dir := ca.dir
	if dir == "" {
		dir = "."
	}
	certFile, pathErr := safeCAPath(dir, "cluster-ca.crt")
	if pathErr != nil {
		return eff, pathErr
	}
	keyFile, pathErr := safeCAPath(dir, "cluster-ca.key")
	if pathErr != nil {
		return eff, pathErr
	}

	// ── Backup old CA before overwriting ──
	if ca.certPEM != nil {
		backupCAFiles(dir, ca.certPEM, ca.key)
	}

	// ── Dual-CA overlap: preserve old CA as secondary ──
	if ca.cert != nil {
		ca.secondaryCert = ca.cert
		ca.secondaryPEM = ca.certPEM
		ca.secondaryExp = ca.cert.NotAfter
		logger.Printf("ClusterCA: old CA preserved as secondary (expires %s)",
			ca.cert.NotAfter.Format("2006-01-02"))
	}

	// Persist new CA via atomicWriteFile (per-file durability: unique tmp +
	// chmod + fsync + rename + parent-dir fsync). NOT a true two-file
	// commit — a crash between the cert and key writes can leave the new
	// cert with the old key on disk (mismatch). That state is detected on
	// the next startup by loadFromPEM cross-validation (D1.1f) and fails
	// closed; auto-repair is intentionally out of scope.
	if err := atomicWriteFile(certFile, certPEM, 0o600); err != nil {
		return eff, fmt.Errorf("write cluster CA cert: %w", err)
	}
	// CA-3: encrypt the key at rest when enabled; plaintext otherwise.
	if err := writeClusterCAKey(dir, keyFile, keyPEM); err != nil {
		return eff, fmt.Errorf("write cluster CA key: %w", err)
	}

	ca.cert = cert
	ca.key = key
	ca.certPEM = certPEM
	// A successful import (auto-rotation or manual) resolves any prior
	// auto-rotation failure that Info() was surfacing.
	ca.lastRotationErr = ""
	ca.lastRotationErrAt = time.Time{}

	fp := sha256.Sum256(cert.Raw)
	logger.Printf("ClusterCA: imported custom CA (expires %s, fingerprint %s)",
		cert.NotAfter.Format("2006-01-02"), sanitizeLog(hex.EncodeToString(fp[:])))

	// Capture the side-effect inputs while the lock is held; the caller runs
	// them once it is released.
	eff.onRotate = ca.onRotate
	newFP := sha256.Sum256(cert.Raw)
	eff.newFP = hex.EncodeToString(newFP[:])
	// Rotation tracking is guarded on the secondary EXISTING. secondaryCert is
	// set above only when a CA was already installed, so the FIRST import on a
	// node that never ran InitOrLoad (a non-cluster node whose admin posts
	// /api/cluster/ca) dereferenced nil here — and it did so AFTER ca.cert/key
	// were already swapped in, so the panic left the new CA installed with the
	// TLS pool never rebuilt and no rotation tracking. There is no rotation to
	// track when there was no prior CA: this is a bootstrap, not a rotation.
	if ca.secondaryCert != nil {
		oldFP := sha256.Sum256(ca.secondaryCert.Raw)
		eff.oldFP = hex.EncodeToString(oldFP[:])
		eff.secondaryExp = ca.secondaryExp
		eff.trackRotate = true
	}
	return eff, nil
}

// SecondaryActive returns true if a secondary (old) CA is still in the overlap period.
func (ca *clusterCA) SecondaryActive() bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.secondaryCert != nil && time.Now().Before(ca.secondaryExp)
}

// CleanupSecondary removes the secondary CA if it has expired.
//
// CHAOS-50: same commit-then-notify split as ImportCA, and for the same reason.
// onRotate is rebuildCPCertPool, which reads globalClusterCA.AllCACertsPEM()
// under mu.RLock — so calling it under mu.Lock self-deadlocked. This site is
// strictly worse than the import one because it is entirely UNATTENDED: the
// daily rotation loop reaches it ~30 days after any rotation, when the dual-CA
// overlap window closes. The wedged goroutine is the shared rotation loop
// itself, so the inspection CA would stop rotating too, and the cluster CA's
// write lock would stay held for the life of the process.
func (ca *clusterCA) CleanupSecondary() {
	ca.importMu.Lock()
	defer ca.importMu.Unlock()

	ca.mu.Lock()
	cleaned := false
	if ca.secondaryCert != nil && time.Now().After(ca.secondaryExp) {
		logger.Printf("ClusterCA: secondary CA expired, removing overlap")
		ca.secondaryCert = nil
		ca.secondaryPEM = nil
		ca.secondaryExp = time.Time{}
		cleaned = true
	}
	onRotate := ca.onRotate
	ca.mu.Unlock()

	if !cleaned {
		return
	}
	// ── Post-commit side effects, with ca.mu RELEASED ──
	if onRotate != nil {
		onRotate()
	}
	// Clear rotation tracking — overlap period is over.
	globalClusterStore.ClearCARotation()
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

// recordRotationFailure records the most recent auto-rotation failure for
// Info() to surface. err is an internal crypto/x509 error, never user input.
func (ca *clusterCA) recordRotationFailure(err error) {
	ca.mu.Lock()
	ca.lastRotationErr = err.Error()
	ca.lastRotationErrAt = time.Now()
	ca.mu.Unlock()
	// CHAOS-50 / CA-13: Info() alone made this visible only to an operator who
	// happened to open the Cluster CA panel. Rotation is the ONLY recovery this
	// CA has, so a rotation that keeps failing needs to reach monitoring — a
	// counter, an alert, and a diagnostics row — not just a panel nobody is
	// looking at. Called with ca.mu released: the health record has its own
	// mutex and must never be taken under this one.
	noteClusterCARotationFailure(err.Error())
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

	if daysLeft > clusterCARenewalWindow.Hours()/24 {
		return
	}
	logger.Printf("ClusterCA: expires in %.0f days — auto-rotating", daysLeft)

	// Generate new CA.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (keygen): %v", err)
		ca.recordRotationFailure(err)
		return
	}
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (serial): %v", err)
		ca.recordRotationFailure(err)
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
		ca.recordRotationFailure(err)
		return
	}
	newCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (marshal key): %v", err)
		ca.recordRotationFailure(err)
		return
	}
	newKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// ImportCA handles dual-CA overlap, backup, persistence, and TLS pool rebuild.
	// On success it clears lastRotationErr itself (while still holding ca.mu).
	if err := ca.ImportCA(newCertPEM, newKeyPEM); err != nil {
		logger.Printf("ClusterCA: auto-rotation failed (import): %v", err)
		ca.recordRotationFailure(err)
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
	if ca.lastRotationErr != "" {
		info["lastRotationError"] = ca.lastRotationErr
		info["lastRotationErrorAt"] = ca.lastRotationErrAt.UTC().Format(time.RFC3339)
	}
	// CHAOS-50 / CA-13: usability is reported SEPARATELY from "initialized".
	// This is an admin/operator surface (GET /api/cluster/ca, viewer role), so
	// it carries the actionable cause — unlike the unauthenticated probe rows,
	// which get a fixed string. usableReason is the only place an operator can
	// read WHICH bound was violated without going to the logs.
	usable := clusterCAUsable(ca.cert, time.Now())
	info["usable"] = usable == nil
	if usable != nil {
		info["unusableReason"] = usable.Error()
	}
	info["expiresInDays"] = int(time.Until(ca.cert.NotAfter).Hours() / 24)
	snap := clusterCAFailures()
	info["signRefused"] = snap.SignRefusals
	info["nodeCertsClamped"] = snap.ClampedIssuances
	info["rotationFailures"] = snap.RotationFailures
	info["rotationDegraded"] = snap.RotationDegraded
	return info
}

// ─── Enrollment Request/Response (gRPC) ──────────────────────────────────────

// EnrollRequest is sent by a DP node during enrollment.
type EnrollRequest struct {
	Token  string `json:"token"`
	CSR    string `json:"csr"` // PEM-encoded CSR
	NodeID string `json:"node_id"`
}

// EnrollResponse is returned by the CP after successful enrollment.
type EnrollResponse struct {
	CertPEM string `json:"cert_pem"` // signed node certificate
	CAPEM   string `json:"ca_pem"`   // cluster CA certificate
	NodeID  string `json:"node_id"`
	CPAddr  string `json:"cp_addr"`         // control plane gRPC address for reconnect
	Epoch   int64  `json:"epoch,omitempty"` // issuing CP's fencing epoch (ADR-0005 S3; seeds the DP ratchet)
}
