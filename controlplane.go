package main

// ─── Control Plane / Data Plane separation ────────────────────────────────────
//
// Architecture:
//
//   ┌──────────────────────┐    gRPC (mTLS)    ┌─────────────────────────┐
//   │    Control Plane     │ ────────────────> │      Data Plane          │
//   │  :9090 Web UI/API    │                   │  :8080 HTTP proxy        │
//   │  Auth configuration  │ <config push/pull │  :1080 SOCKS5            │
//   │  Blocklist mgmt      │                   │  Read-only config        │
//   │  Metrics aggregation │                   │  Applies rules locally   │
//   └──────────────────────┘                   └─────────────────────────┘
//       Separate process/pod                       Separate process/pod
//
// The Data Plane polls the Control Plane for configuration updates via gRPC.
// The Control Plane aggregates metrics pushed by each Data Plane node.
//
// For single-binary deployments (development/simple setups), both planes run
// in the same process — the gRPC channel is just an in-process call.
//
// ─────────────────────────────────────────────────────────────────────────────
//
// This file provides:
//   1. ConfigSnapshot  — immutable config struct passed between planes
//   2. ConfigStore     — thread-safe store with versioning + subscriber channel
//   3. gRPC server     — serves config snapshots and receives metric pushes
//   4. gRPC client     — polls Control Plane; updates local state on change
//
// Wire protocol (no .proto file needed for this implementation):
//   Uses encoding/json over a gRPC unary stream to keep the implementation
//   self-contained without requiring protoc.  In a production deployment,
//   replace the JSON codec with generated protobuf for efficiency.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ─── ConfigSnapshot ───────────────────────────────────────────────────────────

// ConfigSnapshot is the canonical, immutable view of proxy configuration that
// the Control Plane distributes to Data Plane nodes.
type ConfigSnapshot struct {
	Version       int64    `json:"version"`
	BlockedHosts  []string `json:"blocked_hosts"`
	IPFilterMode  string   `json:"ip_filter_mode"`
	IPList        []string `json:"ip_list"`
	RateLimitRPM  int      `json:"rate_limit_rpm"`
	AuthEnabled   bool     `json:"auth_enabled"`
	UnauthMode    bool     `json:"unauth_mode"`
	UpdatedAt     string   `json:"updated_at"`
	CAFingerprint string   `json:"ca_fingerprint,omitempty"` // cluster CA SHA-256 fingerprint; DP triggers renewal when this changes

	// Full policy sync — all policy state pushed from CP to DP.
	DefaultAction     string           `json:"default_action"`               // "allow" or "deny"
	PolicyRules       []PolicyRule     `json:"policy_rules,omitempty"`       // ordered policy rules
	PolicyVersion     int64            `json:"policy_version"`               // monotonic policy version
	SSLBypassPatterns []string         `json:"ssl_bypass_patterns,omitempty"`
	URLCategories     []CategoryEntry  `json:"url_categories,omitempty"`
	FileProfiles      []FileExtProfile `json:"file_profiles,omitempty"`
	RewriteRules      []RewriteRule    `json:"rewrite_rules,omitempty"`
	DPIPatterns       []string         `json:"dpi_patterns,omitempty"`
	MaxConnsPerIP     int              `json:"max_conns_per_ip"`

	// HA: CP addresses that DPs should know about for automatic failover.
	// Populated by the leader with its own address + standby address.
	// DPs update their connection list on every config sync — no manual
	// --dp-cp-addr configuration needed.
	CPAddresses []string `json:"cp_addresses,omitempty"`

	// PAC distribution: sync PAC exclusions from CP to DPs.
	PACExclusions []string `json:"pac_exclusions,omitempty"`

	// Threat feed sync: include feed data so DPs don't fetch independently.
	ThreatFeedURLs    map[string]int64 `json:"threat_feed_urls,omitempty"`
	ThreatFeedDomains map[string]int64 `json:"threat_feed_domains,omitempty"`
	ThreatDomainAllowlist []string     `json:"threat_domain_allowlist,omitempty"`

	// Session secret sync: shared HMAC key so sessions are valid across nodes.
	SessionHMAC string `json:"session_hmac,omitempty"`

	// Bandwidth / QoS policies synced from CP to DP.
	BandwidthPolicies []BandwidthPolicy `json:"bandwidth_policies,omitempty"`

	// Node group definitions synced from CP to DP.
	NodeGroups []NodeGroup `json:"node_groups,omitempty"`

	// Category groups for policy rules.
	CategoryGroups []CategoryGroup `json:"category_groups,omitempty"`

	// Global file-block extension list (day-3 audit CRIT-2).
	FileBlockExtensions []string `json:"file_block_extensions,omitempty"`

	// OTLP endpoint for metrics + traces export (day-3 audit CRIT-3).
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`
}

// ─── ConfigStore ──────────────────────────────────────────────────────────────

// ConfigStore holds the current ConfigSnapshot and notifies subscribers when
// it changes.  Used by the Control Plane to publish updates.
type ConfigStore struct {
	mu      sync.RWMutex
	snap    ConfigSnapshot
	version int64
	subs    []chan struct{}
}

var globalConfigStore = &ConfigStore{}

// Update atomically replaces the snapshot and notifies all subscribers.
func (s *ConfigStore) Update(snap ConfigSnapshot) {
	s.mu.Lock()
	s.version++
	snap.Version = s.version
	snap.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	s.snap = snap
	subs := append([]chan struct{}{}, s.subs...)
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	logger.Printf("ControlPlane: config v%d published", snap.Version)
}

// Get returns the current snapshot.
func (s *ConfigStore) Get() ConfigSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// Subscribe returns a channel that receives a signal on every config update.
func (s *ConfigStore) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}

// ─── gRPC service definition (no protoc needed) ───────────────────────────────

// We implement a minimal gRPC service using the grpc framework but with a
// hand-written codec.  This avoids protoc as a build dependency.

// configServiceName is the fully-qualified gRPC service name.
const configServiceName = "culvert.ConfigService"

// methodGetConfig, methodPushMetrics, and methodEnroll are the RPC method descriptors.
var (
	methodGetConfig          = fmt.Sprintf("/%s/GetConfig", configServiceName)
	methodPushMetrics        = fmt.Sprintf("/%s/PushMetrics", configServiceName)
	methodEnroll             = fmt.Sprintf("/%s/Enroll", configServiceName)
	methodSyncRateLimits     = fmt.Sprintf("/%s/SyncRateLimits", configServiceName)
	methodSyncRevocations    = fmt.Sprintf("/%s/SyncRevocations", configServiceName)
	methodPushAuditEvents    = fmt.Sprintf("/%s/PushAuditEvents", configServiceName)
	methodRenewCert          = fmt.Sprintf("/%s/RenewCert", configServiceName)
	methodHASync             = fmt.Sprintf("/%s/HASync", configServiceName)
)

// MetricsReport is sent by Data Plane nodes to the Control Plane.
type MetricsReport struct {
	NodeID   string `json:"node_id"`
	Total    int64  `json:"total"`
	Blocked  int64  `json:"blocked"`
	AuthFail int64  `json:"auth_fail"`
	Uptime   string `json:"uptime"`
}

// nodeMetrics aggregates metrics from all connected Data Plane nodes.
var (
	nodeMetricsMu sync.RWMutex
	nodeMetrics   = map[string]MetricsReport{}
)

// ─── Distributed rate limit aggregation ──────────────────────────────────────
//
// The CP aggregates per-IP request counts from all DP nodes. Each DP sends
// delta counts for "hot" IPs (those near their limit). The CP stores the
// latest snapshot per node, and on each SyncRateLimits call returns the
// cluster-wide total minus the requesting node's own counts.

type rateLimitAggregator struct {
	mu       sync.Mutex
	perNode  map[string]map[string]int // nodeID → {IP → count}
	expireAt map[string]time.Time      // nodeID → last update time
}

var globalRLAggregator = &rateLimitAggregator{
	perNode:  map[string]map[string]int{},
	expireAt: map[string]time.Time{},
}

// Update stores the latest rate limit snapshot from a node.
func (a *rateLimitAggregator) Update(nodeID string, deltas []RateLimitDelta) {
	counts := make(map[string]int, len(deltas))
	for _, d := range deltas {
		counts[d.IP] = d.Count
	}
	a.mu.Lock()
	a.perNode[nodeID] = counts
	a.expireAt[nodeID] = time.Now()
	a.mu.Unlock()
}

// ClusterTotalsExcluding returns per-IP totals across all nodes except excludeNode.
// Stale entries (>2 minutes without update) are pruned.
func (a *rateLimitAggregator) ClusterTotalsExcluding(excludeNode string) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Prune stale nodes.
	cutoff := time.Now().Add(-2 * time.Minute)
	for nid, t := range a.expireAt {
		if t.Before(cutoff) {
			delete(a.perNode, nid)
			delete(a.expireAt, nid)
		}
	}

	totals := map[string]int{}
	for nid, counts := range a.perNode {
		if nid == excludeNode {
			continue
		}
		for ip, count := range counts {
			totals[ip] += count
		}
	}
	return totals
}

// Stats returns the number of tracked nodes and total hot IPs.
func (a *rateLimitAggregator) Stats() (nodes int, hotIPs int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := map[string]bool{}
	for _, counts := range a.perNode {
		for ip := range counts {
			seen[ip] = true
		}
	}
	return len(a.perNode), len(seen)
}

// ─── Distributed session revocation aggregation ─────────────────────────────
//
// Each node sends its revocation list to the CP. The CP merges all lists and
// returns the unified set so every node can enforce logouts from any node.

type revocationAggregator struct {
	mu      sync.Mutex
	perNode map[string][]RevocationEntry // nodeID → latest entries
}

var globalRevAggregator = &revocationAggregator{
	perNode: map[string][]RevocationEntry{},
}

// Update stores the latest revocation entries from a node.
func (a *revocationAggregator) Update(nodeID string, entries []RevocationEntry) {
	a.mu.Lock()
	a.perNode[nodeID] = entries
	a.mu.Unlock()
}

// MergedExcluding returns all revocation entries from other nodes.
func (a *revocationAggregator) MergedExcluding(nodeID string) []RevocationEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var merged []RevocationEntry
	seen := map[string]bool{}
	for nid, entries := range a.perNode {
		if nid == nodeID {
			continue
		}
		for _, e := range entries {
			if time.Unix(e.Expiry, 0).Before(now) {
				continue // expired
			}
			if !seen[e.Token] {
				seen[e.Token] = true
				merged = append(merged, e)
			}
		}
	}
	return merged
}

// ─── Centralized audit log ──────────────────────────────────────────────────
//
// Data Plane nodes push audit events to the Control Plane, which stores them
// in a ring buffer for the admin UI. This provides unified visibility across
// all nodes without requiring each node to have its own audit log viewer.

// ClusterAuditEntry wraps an AuditEntry with the originating node ID.
type ClusterAuditEntry struct {
	NodeID string     `json:"node_id"`
	Entry  AuditEntry `json:"entry"`
}

type clusterAuditLog struct {
	mu      sync.Mutex
	entries []ClusterAuditEntry
	maxSize int
}

var globalClusterAudit = &clusterAuditLog{maxSize: 5000}

// Append adds entries from a Data Plane node.
func (c *clusterAuditLog) Append(nodeID string, events []AuditEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range events {
		c.entries = append(c.entries, ClusterAuditEntry{NodeID: nodeID, Entry: e})
	}
	// Ring buffer: trim to maxSize.
	if len(c.entries) > c.maxSize {
		c.entries = c.entries[len(c.entries)-c.maxSize:]
	}
}

// Recent returns the last n entries.
func (c *clusterAuditLog) Recent(n int) []ClusterAuditEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n <= 0 || len(c.entries) == 0 {
		return nil
	}
	if n > len(c.entries) {
		n = len(c.entries)
	}
	start := len(c.entries) - n
	out := make([]ClusterAuditEntry, n)
	copy(out, c.entries[start:])
	return out
}

// Count returns total entries.
func (c *clusterAuditLog) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// clusterRole tracks this node's role for the admin UI.
// Protected by clusterRoleMu for concurrent reads during enableControlPlane transitions.
var (
	clusterRoleMu sync.RWMutex
	clusterRole   struct {
		role     string // "standalone", "control-plane", "data-plane"
		grpcAddr string // gRPC listen address (CP) or connect-to address (DP)
		nodeID   string // this node's identifier
		grpcSrv  *grpc.Server
		certFile string // TLS cert path (for HA deploy command)
		keyFile  string // TLS key path (for HA deploy command)
		caFile   string // CA cert path (for HA deploy command)
	}
)

// enrollRateLimit tracks per-IP enrollment attempt timestamps for rate limiting.
// Limits to 5 attempts per minute per IP to prevent brute-force token guessing.
var enrollRateLimit struct {
	mu      sync.Mutex
	attempts map[string][]time.Time
}

func init() {
	enrollRateLimit.attempts = make(map[string][]time.Time)
}

// enrollRateLimitAllow returns true if the IP is allowed to attempt enrollment.
func enrollRateLimitAllow(ip string) bool {
	const (
		maxAttempts = 5
		window      = time.Minute
	)
	enrollRateLimit.mu.Lock()
	defer enrollRateLimit.mu.Unlock()

	now := time.Now()
	// Prune old entries.
	recent := enrollRateLimit.attempts[ip][:0]
	for _, t := range enrollRateLimit.attempts[ip] {
		if now.Sub(t) < window {
			recent = append(recent, t)
		}
	}
	enrollRateLimit.attempts[ip] = recent

	if len(recent) >= maxAttempts {
		return false
	}
	enrollRateLimit.attempts[ip] = append(enrollRateLimit.attempts[ip], now)
	return true
}

// NodeMetricsList returns a copy of all connected Data Plane node metrics.
func NodeMetricsList() []MetricsReport {
	nodeMetricsMu.RLock()
	defer nodeMetricsMu.RUnlock()
	list := make([]MetricsReport, 0, len(nodeMetrics))
	for _, m := range nodeMetrics {
		list = append(list, m)
	}
	return list
}

// ─── Control Plane gRPC server ────────────────────────────────────────────────

type controlPlaneServer struct{}

// verifyNode extracts the peer TLS certificate from the gRPC context,
// matches it to an enrolled node by cert serial, verifies the self-reported
// nodeID matches the certificate identity, and checks revocation status.
// Returns the verified node ID or an error.
func verifyNode(ctx context.Context, claimedNodeID string) error {
	if claimedNodeID == "" {
		return status.Errorf(codes.InvalidArgument, "node_id required")
	}

	// In mTLS mode, verify cert serial matches enrolled node.
	if err := verifyNodeCert(ctx, claimedNodeID); err != nil {
		return err
	}

	// Check revocation regardless of TLS mode.
	node, exists := globalClusterStore.GetNode(claimedNodeID)
	if exists && globalClusterStore.IsRevoked(node.CertSerial) {
		return status.Errorf(codes.PermissionDenied, "node %q is revoked", claimedNodeID)
	}
	return nil
}

// verifyNodeCert extracts the peer TLS cert serial and matches it to the enrolled node.
func verifyNodeCert(ctx context.Context, claimedNodeID string) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil // insecure dev mode — skip cert pinning
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil
	}
	peerSerial := tlsInfo.State.PeerCertificates[0].SerialNumber.Text(16)
	node, exists := globalClusterStore.GetNode(claimedNodeID)
	if !exists {
		return status.Errorf(codes.NotFound, "node %q not enrolled", claimedNodeID)
	}
	if node.CertSerial != peerSerial {
		return status.Errorf(codes.PermissionDenied,
			"cert serial mismatch: node %q expects %s, peer presented %s",
			claimedNodeID, node.CertSerial, peerSerial)
	}
	return nil
}

func (s *controlPlaneServer) GetConfig(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
	// GetConfig is called during initial poll before enrollment completes, so
	// it must remain reachable without a full node-identity check. However,
	// the snapshot carries secrets (SessionHMAC) that must NOT leak to
	// unenrolled callers. We redact those fields unless the peer's TLS cert
	// serial matches an enrolled, non-revoked node. (C1 fix.)
	snap := globalConfigStore.Get()
	// Include cluster CA fingerprint so DP nodes detect CA rotation.
	if fp := globalClusterCA.CACertFingerprint(); fp != "" {
		snap.CAFingerprint = fp
	}
	if !callerIsEnrolledNode(ctx) {
		snap.SessionHMAC = ""
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

// callerIsEnrolledNode returns true when the gRPC peer presented a TLS
// certificate whose serial matches an enrolled, non-revoked cluster node.
// Used by GetConfig to decide whether to redact cluster secrets from the
// response.
//
// Unlike verifyNodeCert this is a POSITIVE check (caller must prove
// enrolment) — a missing peer cert or missing TLS info yields false, so
// unauthenticated bootstrap callers are correctly treated as unenrolled.
func callerIsEnrolledNode(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return false
	}
	serial := tlsInfo.State.PeerCertificates[0].SerialNumber.Text(16)
	if globalClusterStore.IsRevoked(serial) {
		return false
	}
	for _, n := range globalClusterStore.ListNodes() {
		if n.CertSerial == serial {
			return true
		}
	}
	return false
}

func (s *controlPlaneServer) PushMetrics(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var report MetricsReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}

	// Verify node identity (cert pinning) and check revocation.
	if err := verifyNode(ctx, report.NodeID); err != nil {
		return nil, err
	}

	nodeMetricsMu.Lock()
	nodeMetrics[report.NodeID] = report
	nodeMetricsMu.Unlock()

	// Update heartbeat.
	globalClusterStore.UpdateNodeSeen(report.NodeID, "")

	logger.Printf("ControlPlane: metrics from node %s (total=%d)", report.NodeID, report.Total)
	return json.RawMessage(`{"ok":true}`), nil
}

// SyncRateLimits receives hot-IP deltas from a DP node and returns cluster-wide
// totals (excluding the requesting node) for distributed rate limiting.
func (s *controlPlaneServer) SyncRateLimits(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var gossip RateLimitGossip
	if err := json.Unmarshal(raw, &gossip); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if err := verifyNode(ctx, gossip.NodeID); err != nil {
		return nil, err
	}

	// Store this node's hot-IP counts.
	globalRLAggregator.Update(gossip.NodeID, gossip.Deltas)

	// Return cluster totals minus this node's own counts.
	remote := globalRLAggregator.ClusterTotalsExcluding(gossip.NodeID)
	broadcast := RateLimitBroadcast{RemoteCounts: remote}
	b, err := json.Marshal(broadcast)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

// SyncRevocations receives revoked session tokens from a DP node and returns
// the merged list from all other nodes, enabling cluster-wide session invalidation.
func (s *controlPlaneServer) SyncRevocations(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		NodeID  string            `json:"node_id"`
		Entries []RevocationEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, err
	}
	globalRevAggregator.Update(req.NodeID, req.Entries)
	remote := globalRevAggregator.MergedExcluding(req.NodeID)
	b, err := json.Marshal(map[string]any{"entries": remote})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

// PushAuditEvents receives audit events from a DP node for centralized logging.
func (s *controlPlaneServer) PushAuditEvents(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		NodeID string       `json:"node_id"`
		Events []AuditEntry `json:"events"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, err
	}
	if len(req.Events) > 0 {
		globalClusterAudit.Append(req.NodeID, req.Events)
	}
	return json.RawMessage(`{"ok":true}`), nil
}

// Enroll handles node enrollment: validates token, signs CSR, registers node.
func (s *controlPlaneServer) Enroll(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req EnrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}

	if req.Token == "" || req.CSR == "" || req.NodeID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token, csr, and node_id are required")
	}

	// Rate limit enrollment attempts per IP.
	sourceIP := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		sourceIP, _, _ = net.SplitHostPort(p.Addr.String())
	}
	if sourceIP != "" && !enrollRateLimitAllow(sourceIP) {
		return nil, status.Errorf(codes.ResourceExhausted, "enrollment rate limited — try again later")
	}

	// Check if node ID is already registered and not revoked.
	// Use a generic error message to avoid leaking enrolled node names.
	if existing, ok := globalClusterStore.GetNode(req.NodeID); ok && existing.Status != "revoked" {
		return nil, status.Errorf(codes.PermissionDenied, "enrollment denied")
	}

	// Validate and consume the enrollment token atomically (persisted to disk).
	// Returns token metadata so we don't need to re-access the map.
	tokInfo, err := globalClusterStore.ValidateAndConsumeToken(req.Token, req.NodeID, sourceIP)
	if err != nil {
		logger.Printf("Enrollment: rejected node %q: %v", sanitizeLog(req.NodeID), err)
		return nil, status.Errorf(codes.PermissionDenied, "enrollment denied: %v", err)
	}

	// Validate CSR CommonName matches claimed node ID to prevent identity spoofing.
	csrBlock, _ := pem.Decode([]byte(req.CSR))
	if csrBlock == nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: no PEM block found")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}
	if csr.Subject.CommonName != req.NodeID {
		return nil, status.Errorf(codes.InvalidArgument,
			"CSR CommonName %q does not match claimed node_id %q", csr.Subject.CommonName, req.NodeID)
	}

	// Sign the CSR.
	if !globalClusterCA.Ready() {
		return nil, status.Errorf(codes.FailedPrecondition, "cluster CA not initialized")
	}
	certPEM, serial, expiry, err := globalClusterCA.SignCSR([]byte(req.CSR), req.NodeID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign CSR: %v", err)
	}

	// Register the node (persists to disk).
	node := &EnrolledNode{
		NodeID:     req.NodeID,
		CertSerial: serial,
		CertExpiry: expiry,
		EnrolledAt: time.Now(),
		LastSeen:   time.Now(),
		Status:     "connected",
		EnrolledBy: tokInfo.CreatedBy,
	}
	globalClusterStore.RegisterNode(node)

	logger.Printf("Enrollment: node %q enrolled (serial=%s, expires=%s)", req.NodeID, serial, expiry.Format("2006-01-02"))

	resp := EnrollResponse{
		CertPEM: string(certPEM),
		CAPEM:   string(globalClusterCA.CACertPEM()),
		NodeID:  req.NodeID,
		CPAddr:  clusterRole.grpcAddr,
	}
	b, _ := json.Marshal(resp)
	return b, nil
}

// RenewCert handles certificate renewal requests from enrolled DP nodes.
// The node must be enrolled and not revoked. A new cert is signed from the CSR.
func (s *controlPlaneServer) RenewCert(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		NodeID string `json:"node_id"`
		CSR    string `json:"csr"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if req.NodeID == "" || req.CSR == "" {
		return nil, fmt.Errorf("node_id and csr are required")
	}

	// Verify the caller is the enrolled node (cert pinning).
	if err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, fmt.Errorf("RenewCert: %w", err)
	}

	// Sign the new CSR.
	certPEM, serial, expiry, err := globalClusterCA.SignCSR([]byte(req.CSR), req.NodeID)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}

	// Update the enrolled node's cert serial and expiry.
	// Hold lock through saveLocked() to prevent race with concurrent mutations (B14).
	globalClusterStore.mu.Lock()
	if node, ok := globalClusterStore.st.Nodes[req.NodeID]; ok {
		node.CertSerial = serial
		node.CertExpiry = expiry
		globalClusterStore.st.Nodes[req.NodeID] = node
	}
	if err := globalClusterStore.saveLocked(); err != nil {
		logger.Printf("RenewCert: failed to persist updated node: %v", err)
	}
	globalClusterStore.mu.Unlock()

	logger.Printf("RenewCert: renewed cert for node %q (serial=%s, expires=%s)", req.NodeID, serial, expiry.Format("2006-01-02"))

	// Track renewal progress if a CA rotation is active.
	globalClusterStore.RecordNodeRenewed(req.NodeID)

	resp, _ := json.Marshal(map[string]string{
		"cert_pem": string(certPEM),
		"ca_pem":   string(globalClusterCA.AllCACertsPEM()),
	})
	return resp, nil
}

// HAStateBundle is the full state package sent from leader to standby CP.
// Contains everything the standby needs to promote to leader if needed.
// The CA private key is encrypted with AES-256-GCM using the HA token as
// passphrase (1.6 fix: never transmit CA key in plaintext).
type HAStateBundle struct {
	ClusterState    json.RawMessage `json:"cluster_state"`
	CACertPEM       string          `json:"ca_cert_pem"`
	CAKeyPEM        string          `json:"ca_key_pem,omitempty"`         // deprecated: plaintext CA key (removed)
	CAKeyEncrypted  string          `json:"ca_key_encrypted,omitempty"`   // base64(salt + nonce + ciphertext)
	Config          ConfigSnapshot  `json:"config"`
	Version         int64           `json:"version"`
}

// haEncryptKey encrypts data with AES-256-GCM using a key derived from the
// HA token via PBKDF2-SHA256. Returns base64(salt + nonce + ciphertext).
func haEncryptKey(plaintext []byte, token string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	aesKey := pbkdf2.Key([]byte(token), salt, 100_000, 32, sha256.New)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(salt)+len(nonce)+len(ct))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// haDecryptKey decrypts a base64-encoded (salt + nonce + ciphertext) blob
// using the HA token as passphrase.
func haDecryptKey(encoded string, token string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(data) < 32+12 {
		return nil, errors.New("ha decrypt: data too short")
	}
	salt := data[:32]
	nonce := data[32:44]
	ct := data[44:]
	aesKey := pbkdf2.Key([]byte(token), salt, 100_000, 32, sha256.New)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// HASync returns the full state bundle for HA standby replication.
// Authenticated via a shared HA token (not node cert pinning).
func (s *controlPlaneServer) HASync(_ context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Verify HA token.
	if !globalHA.VerifyToken(req.Token) {
		return nil, status.Errorf(codes.PermissionDenied, "invalid HA token")
	}

	// Build state bundle.
	stateJSON, err := globalClusterStore.ExportState()
	if err != nil {
		return nil, fmt.Errorf("export cluster state: %w", err)
	}

	// 1.6 fix: encrypt CA private key with HA token before transmission.
	var caKeyEncrypted string
	if keyPEM := globalClusterCA.CAKeyPEM(); len(keyPEM) > 0 {
		enc, encErr := haEncryptKey(keyPEM, req.Token)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt CA key for HA sync: %w", encErr)
		}
		caKeyEncrypted = enc
	}

	bundle := HAStateBundle{
		ClusterState:   stateJSON,
		CACertPEM:      string(globalClusterCA.CACertPEM()),
		CAKeyEncrypted: caKeyEncrypted,
		Config:         CurrentConfigSnapshot(),
		Version:        globalConfigStore.Get().Version,
	}

	resp, _ := json.Marshal(bundle)
	return resp, nil
}

// StartControlPlaneGRPC starts the gRPC server for the Control Plane.
// addr example: ":50051"
// certFile/keyFile: mTLS certificate paths.  Pass empty strings for insecure
// (development only — never in production).
// clusterInsecure controls whether the CP allows insecure (non-TLS) gRPC.
// Set via --cluster-insecure flag. When false (default), CP startup fails
// without TLS certificates to prevent accidental production exposure.
var clusterInsecure bool

// cpServerOption returns the gRPC server option for the Control Plane based on
// available TLS certs or the --cluster-insecure flag.
func cpServerOption(addr, certFile, keyFile, caFile string) (grpc.ServerOption, error) {
	switch {
	case certFile != "" && keyFile != "":
		creds, err := buildServerTLS(certFile, keyFile, caFile)
		if err != nil {
			return nil, fmt.Errorf("gRPC TLS: %w", err)
		}
		logger.Printf("ControlPlane: gRPC %s (mTLS)", strings.ReplaceAll(addr, "\n", ""))
		return grpc.Creds(creds), nil
	case clusterInsecure:
		logWarnf("ControlPlane: gRPC %s (insecure — all cluster data unencrypted!)", strings.ReplaceAll(addr, "\n", ""))
		return grpc.EmptyServerOption{}, nil
	default:
		return nil, fmt.Errorf("TLS certificates required for Control Plane (use --cluster-insecure to override for development)")
	}
}

func StartControlPlaneGRPC(addr, certFile, keyFile, caFile string) error {
	serverOpt, err := cpServerOption(addr, certFile, keyFile, caFile)
	if err != nil {
		return err
	}

	srv := grpc.NewServer(serverOpt)
	svc := &controlPlaneServer{}

	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: configServiceName,
		HandlerType: (*controlPlaneServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "GetConfig",
				Handler:    wrapUnary(svc.GetConfig),
			},
			{
				MethodName: "PushMetrics",
				Handler:    wrapUnary(svc.PushMetrics),
			},
			{
				MethodName: "Enroll",
				Handler:    wrapUnary(svc.Enroll),
			},
			{
				MethodName: "SyncRateLimits",
				Handler:    wrapUnary(svc.SyncRateLimits),
			},
			{
				MethodName: "SyncRevocations",
				Handler:    wrapUnary(svc.SyncRevocations),
			},
			{
				MethodName: "PushAuditEvents",
				Handler:    wrapUnary(svc.PushAuditEvents),
			},
			{
				MethodName: "RenewCert",
				Handler:    wrapUnary(svc.RenewCert),
			},
			{
				MethodName: "HASync",
				Handler:    wrapUnary(svc.HASync),
			},
			{
				MethodName: "TriggerUpdate",
				Handler:    wrapUnary(svc.TriggerUpdate),
			},
		},
		Streams: []grpc.StreamDesc{},
	}, svc)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}
	clusterRole.grpcSrv = srv

	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Printf("ControlPlane gRPC error: %v", err)
		}
	}()
	return nil
}

// StopControlPlaneGRPC gracefully stops the gRPC server, draining in-flight
// RPCs before closing. Called during SIGTERM/SIGINT shutdown.
func StopControlPlaneGRPC() {
	if clusterRole.grpcSrv != nil {
		logger.Printf("ControlPlane: graceful gRPC shutdown...")
		clusterRole.grpcSrv.GracefulStop()
		logger.Printf("ControlPlane: gRPC stopped")
	}
}

// wrapUnary adapts our JSON handler signature to grpc.methodHandler.
func wrapUnary(fn func(context.Context, json.RawMessage) (json.RawMessage, error)) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
	return func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var raw json.RawMessage
		if err := dec(&raw); err != nil {
			return nil, err
		}
		return fn(ctx, raw)
	}
}

// ─── Data Plane gRPC client ───────────────────────────────────────────────────

// DataPlaneClient polls the Control Plane for configuration and applies changes
// to the local proxy state (blocklist, IP filter, rate limiter).
//
// When multiple CP addresses are configured (HA mode), the client automatically
// fails over to the next address on connection failure, trying each in order.
type DataPlaneClient struct {
	nodeID      string
	conn        *grpc.ClientConn
	addrs       []string // all CP addresses (for HA failover)
	activeIdx   int      // index into addrs of current connection
	certFile    string   // TLS cert for reconnection
	keyFile     string   // TLS key for reconnection
	caFile      string   // CA cert for reconnection
	mu          sync.Mutex
	lastVersion int64
	failCount   int // consecutive fetch failures for exponential backoff
}

// backoff sleeps for an exponentially increasing duration after consecutive
// Control Plane failures: 2s, 4s, 8s, … capped at 60s.
func (c *DataPlaneClient) backoff(ctx context.Context) {
	c.failCount++
	delay := time.Duration(1<<min(c.failCount, 6)) * time.Second // 2s…64s
	if delay > 60*time.Second {
		delay = 60 * time.Second
	}
	logger.Printf("DataPlane: backing off %s (failure #%d)", delay, c.failCount)
	select {
	case <-time.After(delay):
	case <-ctx.Done():
	}
}

func (c *DataPlaneClient) resetBackoff() {
	c.failCount = 0
}

// NewDataPlaneClient connects to the Control Plane at addr. The addr parameter
// may contain multiple comma-separated addresses for HA failover (e.g.
// "cp1:50051,cp2:50051"). The client connects to the first reachable address
// and automatically fails over to the next on connection failure.
func NewDataPlaneClient(nodeID, addr, certFile, keyFile, caFile string) (*DataPlaneClient, error) {
	addrs := strings.Split(addr, ",")
	for i := range addrs {
		addrs[i] = strings.TrimSpace(addrs[i])
	}

	c := &DataPlaneClient{
		nodeID:   nodeID,
		addrs:    addrs,
		certFile: certFile,
		keyFile:  keyFile,
		caFile:   caFile,
	}

	// Connect to the first reachable CP.
	if err := c.connect(addrs[0]); err != nil {
		return nil, err
	}
	if len(addrs) > 1 {
		logger.Printf("DataPlane: HA mode — %d CP addresses configured, failover enabled", len(addrs))
	}
	return c, nil
}

// connect establishes a gRPC connection to the given address.
func (c *DataPlaneClient) connect(addr string) error {
	var dialOpt grpc.DialOption
	if c.certFile != "" && c.keyFile != "" {
		creds, err := buildClientTLS(c.certFile, c.keyFile, c.caFile)
		if err != nil {
			return fmt.Errorf("gRPC client TLS: %w", err)
		}
		dialOpt = grpc.WithTransportCredentials(creds)
	} else {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
		logger.Printf("DataPlane: connecting to %s (insecure — dev only!)", addr)
	}

	conn, err := grpc.NewClient(addr, dialOpt)
	if err != nil {
		return fmt.Errorf("gRPC dial %s: %w", addr, err)
	}
	// Close old connection if any.
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = conn
	logger.Printf("DataPlane: connected to ControlPlane at %s", addr)
	return nil
}

// failover tries the next CP address in the list. Returns true if a new
// connection was established, false if all addresses have been tried.
func (c *DataPlaneClient) failover() bool {
	if len(c.addrs) <= 1 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Try each address once (round-robin).
	for i := 1; i < len(c.addrs); i++ {
		nextIdx := (c.activeIdx + i) % len(c.addrs)
		nextAddr := c.addrs[nextIdx]
		logger.Printf("DataPlane: failing over to CP at %s", nextAddr)
		if err := c.connect(nextAddr); err != nil {
			logger.Printf("DataPlane: failover to %s failed: %v", nextAddr, err)
			continue
		}
		c.activeIdx = nextIdx
		c.failCount = 0
		return true
	}
	return false
}

// Run starts background loops for config sync, metrics, and cluster gossip.
func (c *DataPlaneClient) Run(ctx context.Context, pollInterval time.Duration) {
	go c.pollLoop(ctx, pollInterval)
	go c.metricsLoop(ctx, pollInterval*2)
	go c.rateLimitGossipLoop(ctx, 5*time.Second)
	go c.revocationSyncLoop(ctx, 3*time.Second)
	go c.auditPushLoop(ctx, 10*time.Second)
}

func (c *DataPlaneClient) pollLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Fetch immediately on start.
	c.fetchAndApply(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.fetchAndApply(ctx)
		}
	}
}

func (c *DataPlaneClient) fetchAndApply(ctx context.Context) {
	raw, err := c.call(ctx, methodGetConfig, json.RawMessage("{}"))
	if err != nil {
		c.failCount++
		logger.Printf("DataPlane: GetConfig error: %v", err)
		// After 3 consecutive failures, attempt failover to another CP.
		if c.failCount >= 3 && len(c.addrs) > 1 {
			if c.failover() {
				logger.Printf("DataPlane: failover succeeded — retrying GetConfig")
				// Retry immediately on the new connection.
				raw, err = c.call(ctx, methodGetConfig, json.RawMessage("{}"))
				if err != nil {
					logger.Printf("DataPlane: GetConfig error after failover: %v", err)
					c.backoff(ctx)
					return
				}
				// Fall through to apply.
			} else {
				c.backoff(ctx)
				return
			}
		} else {
			c.backoff(ctx)
			return
		}
	}
	c.resetBackoff()
	var snap ConfigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		logger.Printf("DataPlane: parse config error: %v", err)
		return
	}
	if snap.Version <= c.lastVersion {
		return // nothing changed
	}
	c.lastVersion = snap.Version
	applyConfigSnapshot(snap)
}

func (c *DataPlaneClient) metricsLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report := MetricsReport{
				NodeID:   c.nodeID,
				Total:    atomic.LoadInt64(&statTotal),
				Blocked:  atomic.LoadInt64(&statBlocked),
				AuthFail: atomic.LoadInt64(&statAuthFail),
				Uptime:   uptime(),
			}
			b, _ := json.Marshal(report)
			if _, err := c.call(ctx, methodPushMetrics, b); err != nil {
				logger.Printf("DataPlane: PushMetrics error: %v", err)
			}
		}
	}
}

// rateLimitGossipLoop periodically syncs hot-IP rate limit deltas with the
// Control Plane. Only sends data when the rate limiter is enabled and there
// are IPs exceeding the hot threshold (>50% of limit).
func (c *DataPlaneClient) rateLimitGossipLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Enable cluster-aware rate limiting now that we're connected to CP.
	clusterRateLimitEnabled.Store(true)
	logger.Printf("DataPlane: distributed rate limiting enabled (gossip every %s)", interval)

	for {
		select {
		case <-ctx.Done():
			clusterRateLimitEnabled.Store(false)
			return
		case <-ticker.C:
			if !rl.Enabled() {
				continue
			}
			deltas := rl.ExportHotDeltas()
			gossip := RateLimitGossip{
				NodeID: c.nodeID,
				Deltas: deltas,
			}
			b, _ := json.Marshal(gossip)
			raw, err := c.call(ctx, methodSyncRateLimits, b)
			if err != nil {
				logger.Printf("DataPlane: SyncRateLimits error: %v", err)
				continue
			}
			var broadcast RateLimitBroadcast
			if err := json.Unmarshal(raw, &broadcast); err != nil {
				logger.Printf("DataPlane: SyncRateLimits parse error: %v", err)
				continue
			}
			clusterCounts.Apply(broadcast.RemoteCounts)
		}
	}
}

// revocationSyncLoop syncs session revocation entries with the CP every few
// seconds, enabling cluster-wide session invalidation on logout.
func (c *DataPlaneClient) revocationSyncLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	logger.Printf("DataPlane: distributed session revocation enabled (sync every %s)", interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			local := sessionRevoked.ExportRevocations()
			req := struct {
				NodeID  string            `json:"node_id"`
				Entries []RevocationEntry `json:"entries"`
			}{
				NodeID:  c.nodeID,
				Entries: local,
			}
			b, _ := json.Marshal(req)
			raw, err := c.call(ctx, methodSyncRevocations, b)
			if err != nil {
				logger.Printf("DataPlane: SyncRevocations error: %v", err)
				continue
			}
			var resp struct {
				Entries []RevocationEntry `json:"entries"`
			}
			if err := json.Unmarshal(raw, &resp); err != nil {
				logger.Printf("DataPlane: SyncRevocations parse error: %v", err)
				continue
			}
			if added := sessionRevoked.MergeRevocations(resp.Entries); added > 0 {
				logger.Printf("DataPlane: merged %d remote session revocations", added)
				if err := sessionRevoked.SaveRevocations(); err != nil {
					logger.Printf("DataPlane: failed to persist revocations: %v", err)
				}
			}
		}
	}
}

// auditPushLoop forwards local audit events to the CP for centralized logging.
func (c *DataPlaneClient) auditPushLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	logger.Printf("DataPlane: centralized audit log enabled (push every %s)", interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events := drainPendingAuditEvents()
			if len(events) == 0 {
				continue
			}
			req := struct {
				NodeID string       `json:"node_id"`
				Events []AuditEntry `json:"events"`
			}{
				NodeID: c.nodeID,
				Events: events,
			}
			b, _ := json.Marshal(req)
			if _, err := c.call(ctx, methodPushAuditEvents, b); err != nil {
				logger.Printf("DataPlane: PushAuditEvents error (%d events): %v", len(events), err)
				// Re-queue events so they're retried on the next interval.
				requeueAuditEvents(events)
			}
		}
	}
}

// call performs a unary gRPC call with a JSON payload.
func (c *DataPlaneClient) call(ctx context.Context, method string, req json.RawMessage) (json.RawMessage, error) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var resp json.RawMessage
	err := c.conn.Invoke(callCtx, method, req, &resp)
	return resp, err
}

// activeDPClient is a reference to the running DP client so that config sync
// can dynamically update the CP address list for HA failover discovery.
var activeDPClient atomic.Pointer[DataPlaneClient]

// updateDPAddresses updates the active DP client's CP address list.
// Called from applyConfigSnapshot when the CP pushes new HA addresses.
func updateDPAddresses(addrs []string) {
	c := activeDPClient.Load()
	if c == nil || len(addrs) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Only update if the addresses actually changed.
	if slicesEqual(c.addrs, addrs) {
		return
	}
	old := c.addrs
	c.addrs = addrs
	logger.Printf("DataPlane: CP address list updated: %v -> %v", old, addrs)
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lastSeenCAFingerprint tracks the most recent cluster CA fingerprint the DP has seen.
// When this changes, the DP knows the CP rotated the CA and triggers immediate cert renewal.
var lastSeenCAFingerprint atomic.Value // string

// caRotationNotify is signaled when the DP detects a CA rotation from the CP.
// The dpCertRenewalLoop listens on this channel to trigger immediate renewal.
var caRotationNotify = make(chan struct{}, 1)

// applyConfigSnapshot updates all local proxy state from a received snapshot.
func applyConfigSnapshot(snap ConfigSnapshot) {
	// Blocklist. All four maps MUST be pre-allocated — AddManual/AddException
	// on a Data Plane node after a snapshot push would otherwise panic with
	// "assignment to entry in nil map" (production defect caught by the
	// qa-determinism gate).
	newBL := &Blocklist{
		exact:      map[string]bool{},
		wildcards:  map[string]bool{},
		manual:     map[string]bool{},
		exceptions: map[string]bool{},
	}
	for _, h := range snap.BlockedHosts {
		newBL.Add(h)
	}
	bl = newBL

	// IP filter.
	newIPF := &IPFilter{single: map[string]bool{}}
	newIPF.SetMode(snap.IPFilterMode)
	for _, ip := range snap.IPList {
		if err := newIPF.Add(ip); err != nil {
			logger.Printf("DataPlane: invalid IP %q: %v", ip, err)
		}
	}
	ipf = newIPF

	// Rate limiter.
	if snap.RateLimitRPM != rl.Limit() {
		rl.Configure(snap.RateLimitRPM, time.Minute)
	}

	// Default policy action.
	if snap.DefaultAction != "" {
		setDefaultPolicyAction(snap.DefaultAction)
	}

	// Policy rules.
	if snap.PolicyRules != nil {
		policyStore.ReplaceAll(snap.PolicyRules)
	}

	// SSL bypass patterns.
	if snap.SSLBypassPatterns != nil {
		if err := sslBypass.Set(snap.SSLBypassPatterns); err != nil {
			logger.Printf("DataPlane: SSL bypass patterns: %v", err)
		}
	}

	// URL categories.
	if snap.URLCategories != nil {
		catStore.ReplaceAll(snap.URLCategories)
	}

	// File profiles.
	if snap.FileProfiles != nil {
		globalProfileStore.ReplaceAll(snap.FileProfiles)
	}

	// Rewrite rules.
	if snap.RewriteRules != nil {
		rewriter.SetRules(snap.RewriteRules)
	}

	// DPI patterns.
	if snap.DPIPatterns != nil {
		if err := dpiScanner.Set(snap.DPIPatterns); err != nil {
			logger.Printf("DataPlane: DPI patterns: %v", err)
		}
	}

	// Connection limits.
	if snap.MaxConnsPerIP > 0 {
		connLimiter.Enable(snap.MaxConnsPerIP)
	}

	// Detect cluster CA rotation: if the fingerprint changed, trigger immediate cert renewal.
	if snap.CAFingerprint != "" {
		prev, _ := lastSeenCAFingerprint.Load().(string)
		if prev != "" && prev != snap.CAFingerprint {
			logger.Printf("DataPlane: cluster CA rotated (fingerprint changed) — triggering immediate cert renewal")
			select {
			case caRotationNotify <- struct{}{}:
			default:
			}
		}
		lastSeenCAFingerprint.Store(snap.CAFingerprint)
	}

	// HA: update DP's CP address list for automatic failover discovery.
	if len(snap.CPAddresses) > 0 {
		updateDPAddresses(snap.CPAddresses)
	}

	// PAC exclusions.
	if snap.PACExclusions != nil {
		cur := pacStore.Get()
		cur.Exclusions = snap.PACExclusions
		if err := pacStore.Set(cur); err != nil {
			logger.Printf("DataPlane: PAC exclusions: %v", err)
		}
	}

	// Threat feed data (only if populated — can be large).
	if len(snap.ThreatFeedURLs) > 0 || len(snap.ThreatFeedDomains) > 0 {
		globalThreatFeed.ImportFeedData(snap.ThreatFeedURLs, snap.ThreatFeedDomains)
		logger.Printf("DataPlane: imported threat feed (%d URLs, %d domains)",
			len(snap.ThreatFeedURLs), len(snap.ThreatFeedDomains))
	}
	if snap.ThreatDomainAllowlist != nil {
		globalThreatFeed.SetDomainAllowlist(snap.ThreatDomainAllowlist)
	}

	// Session secret.
	if snap.SessionHMAC != "" {
		key, err := hex.DecodeString(snap.SessionHMAC)
		if err == nil && len(key) >= 32 {
			sessionSecret = key
			logger.Printf("DataPlane: session secret synced from control plane")
		} else if err != nil {
			logger.Printf("DataPlane: invalid session secret hex: %v", err)
		}
	}

	// Bandwidth / QoS policies.
	if snap.BandwidthPolicies != nil && globalBandwidth != nil {
		globalBandwidth.ReplaceAll(snap.BandwidthPolicies)
	}

	// Category groups.
	if snap.CategoryGroups != nil {
		globalCategoryGroups.ReplaceAll(snap.CategoryGroups)
	}

	// Global file-block extensions (CRIT-2).
	if snap.FileBlockExtensions != nil {
		fileBlocker.ClearAll()
		for _, ext := range snap.FileBlockExtensions {
			fileBlocker.Add(ext)
		}
	}

	// OTLP endpoint (CRIT-3).
	if snap.OTLPEndpoint != "" {
		if !globalOTLP.Enabled() || globalOTLP.Endpoint() != snap.OTLPEndpoint {
			globalOTLP.Configure(snap.OTLPEndpoint, nil)
			globalOTLPTraces.Configure(snap.OTLPEndpoint, nil)
		}
	} else if globalOTLP.Enabled() {
		globalOTLP.Stop()
		globalOTLPTraces.Stop()
	}

	// Node groups.
	if snap.NodeGroups != nil && globalNodeGroups != nil {
		globalNodeGroups.ReplaceAll(snap.NodeGroups)
	}

	logger.Printf("DataPlane: applied config v%d (%d blocked hosts, %d rules, ip_mode=%s, rate=%d rpm)",
		snap.Version, len(snap.BlockedHosts), len(snap.PolicyRules), snap.IPFilterMode, snap.RateLimitRPM)
}

// CurrentConfigSnapshot builds a ConfigSnapshot from the current live state.
// Used by the Control Plane to serve the initial configuration.
func CurrentConfigSnapshot() ConfigSnapshot {
	snap := ConfigSnapshot{
		BlockedHosts: bl.List(),
		IPFilterMode: ipf.Mode(),
		IPList:       ipf.List(),
		RateLimitRPM: rl.Limit(),
		AuthEnabled:  cfg.AuthEnabled(),
		UnauthMode:   cfg.UnauthMode(),
	}
	if fp := globalClusterCA.CACertFingerprint(); fp != "" {
		snap.CAFingerprint = fp
	}

	// Full policy sync.
	snap.DefaultAction = defaultPolicyAction()
	snap.PolicyRules = policyStore.List()
	pv, _ := policyStore.policyVersion()
	snap.PolicyVersion = pv
	snap.SSLBypassPatterns = sslBypass.List()
	cats := catStore.All()
	snap.URLCategories = cats
	profiles := globalProfileStore.List()
	fpSnap := make([]FileExtProfile, len(profiles))
	for i, p := range profiles {
		fpSnap[i] = *p
	}
	snap.FileProfiles = fpSnap
	snap.RewriteRules = rewriter.List()
	snap.DPIPatterns = dpiScanner.List()
	snap.MaxConnsPerIP = connLimiter.MaxPerIP()

	// HA: include all CP addresses so DPs auto-discover failover targets.
	snap.CPAddresses = buildCPAddressList()

	// PAC exclusions.
	pacCfg := pacStore.Get()
	snap.PACExclusions = pacCfg.Exclusions

	// Threat feed data.
	if globalThreatFeed.Enabled() {
		snap.ThreatFeedURLs = globalThreatFeed.ExportURLs()
		snap.ThreatFeedDomains = globalThreatFeed.ExportDomains()
		snap.ThreatDomainAllowlist = globalThreatFeed.DomainAllowlist()
	}

	// Session secret (hex-encoded for safe JSON transport).
	if len(sessionSecret) > 0 {
		snap.SessionHMAC = hex.EncodeToString(sessionSecret)
	}

	// Bandwidth / QoS policies.
	if globalBandwidth != nil {
		snap.BandwidthPolicies = globalBandwidth.List()
	}

	// Node groups.
	if globalNodeGroups != nil {
		snap.NodeGroups = globalNodeGroups.List()
	}

	// Category groups.
	snap.CategoryGroups = globalCategoryGroups.List()

	// Global file-block extensions (CRIT-2: DP nodes need the blocklist).
	snap.FileBlockExtensions = fileBlocker.List()

	// OTLP endpoint (CRIT-3: DP nodes need the endpoint to export spans/metrics).
	snap.OTLPEndpoint = globalOTLP.Endpoint()

	return snap
}

// buildCPAddressList returns the list of all CP gRPC addresses for DP failover.
// Includes this leader's address + the HA standby address (if HA is enabled).
func buildCPAddressList() []string {
	haStatus := globalHA.Status()
	if !haStatus.Enabled {
		return nil // no HA = no address list needed
	}
	clusterRoleMu.RLock()
	myAddr := clusterRole.grpcAddr
	clusterRoleMu.RUnlock()

	// haStatus.PeerAddr is the leader's externally reachable address (set during Enable HA).
	// For the leader, we include: [leader_addr, standby_addr]
	// The leader's reachable addr is stored as peerAddr in the HA state.
	addrs := []string{haStatus.PeerAddr}
	// Also include the local listen addr if it's different and looks reachable.
	if myAddr != "" && myAddr != haStatus.PeerAddr {
		addrs = append(addrs, myAddr)
	}
	return addrs
}

// ─── TLS helpers ──────────────────────────────────────────────────────────────

// cpTLSConfig holds a reference to the server TLS config so that the cert
// pool can be rebuilt dynamically when the cluster CA is rotated.
var cpTLSConfig struct {
	mu      sync.Mutex
	cfg     *tls.Config
	baseCAF string // path to base CA file (operator-provided)
}

// rebuildCPCertPool rebuilds the TLS client CA pool with the base CA file
// plus all active cluster CAs (primary + secondary overlap).
// Called by globalClusterCA.onRotate after import or cleanup.
func rebuildCPCertPool() {
	cpTLSConfig.mu.Lock()
	defer cpTLSConfig.mu.Unlock()
	if cpTLSConfig.cfg == nil {
		return
	}
	pool := x509.NewCertPool()
	if cpTLSConfig.baseCAF != "" {
		caPath := filepath.Clean(cpTLSConfig.baseCAF)
		if !strings.Contains(caPath, "..") {
			if pemData, err := os.ReadFile(caPath); err == nil { // #nosec G304 -- admin CLI flag, ".." rejected
				pool.AppendCertsFromPEM(pemData)
			}
		}
	}
	if allCA := globalClusterCA.AllCACertsPEM(); len(allCA) > 0 {
		pool.AppendCertsFromPEM(allCA)
	}
	cpTLSConfig.cfg.ClientCAs = pool
	logger.Printf("ControlPlane: TLS client CA pool rebuilt")
}

func buildServerTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	if strings.Contains(certFile, "..") || strings.Contains(keyFile, "..") || strings.Contains(caFile, "..") {
		return nil, fmt.Errorf("invalid cert/key/ca path: directory traversal not allowed")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		// Add all active cluster CAs (primary + secondary overlap).
		if allCA := globalClusterCA.AllCACertsPEM(); len(allCA) > 0 {
			pool.AppendCertsFromPEM(allCA)
		}
		tlsCfg.ClientCAs = pool
		// VerifyClientCertIfGiven allows unenrolled nodes to call Enroll
		// without a client cert, while still verifying certs from enrolled nodes.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven

		// Store reference for dynamic cert pool rebuild on CA rotation.
		cpTLSConfig.mu.Lock()
		cpTLSConfig.cfg = tlsCfg
		cpTLSConfig.baseCAF = caFile
		cpTLSConfig.mu.Unlock()

		// Wire up the rotation callback so ImportCA/CleanupSecondary
		// rebuild the pool automatically.
		globalClusterCA.mu.Lock()
		globalClusterCA.onRotate = rebuildCPCertPool
		globalClusterCA.mu.Unlock()
	}
	return credentials.NewTLS(tlsCfg), nil
}

func buildClientTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	// Guard: reject directory traversal in CLI-provided CA path.
	cleaned := filepath.Clean(caFile)
	if strings.Contains(cleaned, "..") {
		return nil, fmt.Errorf("invalid CA path: directory traversal not allowed")
	}
	pool := x509.NewCertPool()
	pemData, err := os.ReadFile(cleaned) // #nosec G304 -- admin-provided CLI flag, ".." rejected above
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid certificates in %s", sanitizeLog(caFile))
	}
	return pool, nil
}
