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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	Version      int64    `json:"version"`
	BlockedHosts []string `json:"blocked_hosts"`
	IPFilterMode string   `json:"ip_filter_mode"`
	IPList       []string `json:"ip_list"`
	RateLimitRPM int      `json:"rate_limit_rpm"`
	AuthEnabled  bool     `json:"auth_enabled"`
	UnauthMode   bool     `json:"unauth_mode"`
	UpdatedAt    string   `json:"updated_at"`
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
var clusterRole struct {
	role     string // "standalone", "control-plane", "data-plane"
	grpcAddr string // gRPC listen address (CP) or connect-to address (DP)
	nodeID   string // this node's identifier
	grpcSrv  *grpc.Server
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
func verifyNode(ctx context.Context, claimedNodeID string) (string, error) {
	if claimedNodeID == "" {
		return "", status.Errorf(codes.InvalidArgument, "node_id required")
	}

	// In insecure dev mode (no mTLS), skip cert pinning but still check revocation.
	p, ok := peer.FromContext(ctx)
	if ok && p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(tlsInfo.State.PeerCertificates) > 0 {
			peerSerial := tlsInfo.State.PeerCertificates[0].SerialNumber.Text(16)
			// Verify claimed node ID matches the cert's enrolled serial.
			node, exists := globalClusterStore.GetNode(claimedNodeID)
			if !exists {
				return "", status.Errorf(codes.NotFound, "node %q not enrolled", claimedNodeID)
			}
			if node.CertSerial != peerSerial {
				return "", status.Errorf(codes.PermissionDenied,
					"cert serial mismatch: node %q expects %s, peer presented %s",
					claimedNodeID, node.CertSerial, peerSerial)
			}
		}
	}

	// Check revocation regardless of TLS mode.
	if node, exists := globalClusterStore.GetNode(claimedNodeID); exists {
		if globalClusterStore.IsRevoked(node.CertSerial) {
			return "", status.Errorf(codes.PermissionDenied, "node %q is revoked", claimedNodeID)
		}
	}
	return claimedNodeID, nil
}

func (s *controlPlaneServer) GetConfig(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
	// GetConfig is called during initial poll before enrollment completes.
	// No node identity check required — config is not secret, and unenrolled
	// nodes need it to bootstrap.
	snap := globalConfigStore.Get()
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

func (s *controlPlaneServer) PushMetrics(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var report MetricsReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}

	// Verify node identity (cert pinning) and check revocation.
	if _, err := verifyNode(ctx, report.NodeID); err != nil {
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
	if _, err := verifyNode(ctx, gossip.NodeID); err != nil {
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
	if _, err := verifyNode(ctx, req.NodeID); err != nil {
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
	if _, err := verifyNode(ctx, req.NodeID); err != nil {
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

	// Check if node ID is already registered and not revoked.
	if existing, ok := globalClusterStore.GetNode(req.NodeID); ok && existing.Status != "revoked" {
		return nil, status.Errorf(codes.AlreadyExists, "node %q is already enrolled", req.NodeID)
	}

	// Extract peer IP for CIDR validation.
	sourceIP := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		sourceIP, _, _ = net.SplitHostPort(p.Addr.String())
	}

	// Validate and consume the enrollment token atomically (persisted to disk).
	// Returns token metadata so we don't need to re-access the map.
	tokInfo, err := globalClusterStore.ValidateAndConsumeToken(req.Token, req.NodeID, sourceIP)
	if err != nil {
		logger.Printf("Enrollment: rejected node %q: %v", sanitizeLog(req.NodeID), err)
		return nil, status.Errorf(codes.PermissionDenied, "enrollment denied: %v", err)
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
	if _, err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, fmt.Errorf("RenewCert: %w", err)
	}

	// Sign the new CSR.
	certPEM, serial, expiry, err := globalClusterCA.SignCSR([]byte(req.CSR), req.NodeID)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}

	// Update the enrolled node's cert serial and expiry.
	globalClusterStore.mu.Lock()
	if node, ok := globalClusterStore.st.Nodes[req.NodeID]; ok {
		node.CertSerial = serial
		node.CertExpiry = expiry
		globalClusterStore.st.Nodes[req.NodeID] = node
	}
	globalClusterStore.mu.Unlock()
	if err := globalClusterStore.Save(); err != nil {
		logger.Printf("RenewCert: failed to persist updated node: %v", err)
	}

	logger.Printf("RenewCert: renewed cert for node %q (serial=%s, expires=%s)", req.NodeID, serial, expiry.Format("2006-01-02"))

	resp, _ := json.Marshal(map[string]string{
		"cert_pem": string(certPEM),
		"ca_pem":   string(globalClusterCA.AllCACertsPEM()),
	})
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

func StartControlPlaneGRPC(addr, certFile, keyFile, caFile string) error {
	var serverOpt grpc.ServerOption
	if certFile != "" && keyFile != "" {
		creds, err := buildServerTLS(certFile, keyFile, caFile)
		if err != nil {
			return fmt.Errorf("gRPC TLS: %w", err)
		}
		serverOpt = grpc.Creds(creds)
		logger.Printf("ControlPlane gRPC → %s (mTLS)", strings.ReplaceAll(addr, "\n", ""))
	} else if clusterInsecure {
		serverOpt = grpc.EmptyServerOption{}
		logger.Printf("WARNING: ControlPlane gRPC → %s (insecure — all cluster data unencrypted!)", strings.ReplaceAll(addr, "\n", ""))
	} else {
		return fmt.Errorf("TLS certificates required for Control Plane (use --cluster-insecure to override for development)")
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
type DataPlaneClient struct {
	nodeID      string
	conn        *grpc.ClientConn
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

// NewDataPlaneClient connects to the Control Plane at addr.
func NewDataPlaneClient(nodeID, addr, certFile, keyFile, caFile string) (*DataPlaneClient, error) {
	var dialOpt grpc.DialOption
	if certFile != "" && keyFile != "" {
		creds, err := buildClientTLS(certFile, keyFile, caFile)
		if err != nil {
			return nil, fmt.Errorf("gRPC client TLS: %w", err)
		}
		dialOpt = grpc.WithTransportCredentials(creds)
	} else {
		dialOpt = grpc.WithTransportCredentials(insecure.NewCredentials())
		logger.Printf("DataPlane: connecting to %s (insecure — dev only!)", addr)
	}

	conn, err := grpc.NewClient(addr, dialOpt)
	if err != nil {
		return nil, fmt.Errorf("gRPC dial: %w", err)
	}
	logger.Printf("DataPlane: connected to ControlPlane at %s", addr)
	return &DataPlaneClient{nodeID: nodeID, conn: conn}, nil
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
		c.backoff(ctx)
		logger.Printf("DataPlane: GetConfig error: %v", err)
		return
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

// applyConfigSnapshot updates all local proxy state from a received snapshot.
func applyConfigSnapshot(snap ConfigSnapshot) {
	// Blocklist.
	newBL := &Blocklist{exact: map[string]bool{}, wildcards: map[string]bool{}}
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

	logger.Printf("DataPlane: applied config v%d (%d blocked hosts, ip_mode=%s, rate=%d rpm)",
		snap.Version, len(snap.BlockedHosts), snap.IPFilterMode, snap.RateLimitRPM)
}

// CurrentConfigSnapshot builds a ConfigSnapshot from the current live state.
// Used by the Control Plane to serve the initial configuration.
func CurrentConfigSnapshot() ConfigSnapshot {
	return ConfigSnapshot{
		BlockedHosts: bl.List(),
		IPFilterMode: ipf.Mode(),
		IPList:       ipf.List(),
		RateLimitRPM: rl.Limit(),
		AuthEnabled:  cfg.AuthEnabled(),
		UnauthMode:   cfg.UnauthMode(),
	}
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
		if pem, err := os.ReadFile(cpTLSConfig.baseCAF); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	if allCA := globalClusterCA.AllCACertsPEM(); len(allCA) > 0 {
		pool.AppendCertsFromPEM(allCA)
	}
	cpTLSConfig.cfg.ClientCAs = pool
	logger.Printf("ControlPlane: TLS client CA pool rebuilt (%d CAs)", len(pool.Subjects())) //nolint:staticcheck // Subjects() deprecated but fine for count
}

func buildServerTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	if strings.Contains(certFile, "..") || strings.Contains(keyFile, "..") {
		return nil, fmt.Errorf("invalid cert/key path: directory traversal not allowed")
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
	if strings.Contains(caFile, "..") {
		return nil, fmt.Errorf("invalid CA path: directory traversal not allowed")
	}
	pool := x509.NewCertPool()
	cleaned := filepath.Clean(caFile)
	pemData, err := os.ReadFile(cleaned) // #nosec G304 -- guarded above: ".." rejected
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid certificates in %s", sanitizeLog(caFile))
	}
	return pool, nil
}
