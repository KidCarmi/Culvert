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
	methodGetConfig   = fmt.Sprintf("/%s/GetConfig", configServiceName)
	methodPushMetrics = fmt.Sprintf("/%s/PushMetrics", configServiceName)
	methodEnroll      = fmt.Sprintf("/%s/Enroll", configServiceName)
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

// clusterRole tracks this node's role for the admin UI.
var clusterRole struct {
	role     string // "standalone", "control-plane", "data-plane"
	grpcAddr string // gRPC listen address (CP) or connect-to address (DP)
	nodeID   string // this node's identifier
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

func (s *controlPlaneServer) GetConfig(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
	snap := globalConfigStore.Get()
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

func (s *controlPlaneServer) PushMetrics(_ context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var report MetricsReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}

	// Check if node is revoked.
	if node, ok := globalClusterStore.GetNode(report.NodeID); ok {
		if globalClusterStore.IsRevoked(node.CertSerial) {
			return nil, status.Errorf(codes.PermissionDenied, "node %s is revoked", report.NodeID)
		}
	}

	nodeMetricsMu.Lock()
	nodeMetrics[report.NodeID] = report
	nodeMetricsMu.Unlock()

	// Update heartbeat.
	globalClusterStore.UpdateNodeSeen(report.NodeID, "")

	logger.Printf("ControlPlane: metrics from node %s (total=%d)", report.NodeID, report.Total)
	return json.RawMessage(`{"ok":true}`), nil
}

// Enroll handles node enrollment: validates token, signs CSR, registers node.
func (s *controlPlaneServer) Enroll(_ context.Context, raw json.RawMessage) (json.RawMessage, error) {
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

	// Validate the enrollment token (also marks it as consumed).
	if err := globalClusterStore.ValidateToken(req.Token, req.NodeID, ""); err != nil {
		logger.Printf("Enrollment: rejected node %q: %v", req.NodeID, err)
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

	// Register the node.
	node := &EnrolledNode{
		NodeID:     req.NodeID,
		CertSerial: serial,
		CertExpiry: expiry,
		EnrolledAt: time.Now(),
		LastSeen:   time.Now(),
		Status:     "connected",
	}
	// Find who created the token to record as enrolledBy.
	hash := hashToken(req.Token)
	if tok, exists := globalClusterStore.st.Tokens[hash]; exists {
		node.EnrolledBy = tok.CreatedBy
	}
	globalClusterStore.RegisterNode(node)

	if err := globalClusterStore.Save(); err != nil {
		logger.Printf("Enrollment: failed to persist state: %v", err)
	}

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

// StartControlPlaneGRPC starts the gRPC server for the Control Plane.
// addr example: ":50051"
// certFile/keyFile: mTLS certificate paths.  Pass empty strings for insecure
// (development only — never in production).
func StartControlPlaneGRPC(addr, certFile, keyFile, caFile string) error {
	var serverOpt grpc.ServerOption
	if certFile != "" && keyFile != "" {
		creds, err := buildServerTLS(certFile, keyFile, caFile)
		if err != nil {
			return fmt.Errorf("gRPC TLS: %w", err)
		}
		serverOpt = grpc.Creds(creds)
		logger.Printf("ControlPlane gRPC → %s (mTLS)", strings.ReplaceAll(addr, "\n", ""))
	} else {
		serverOpt = grpc.EmptyServerOption{}
		logger.Printf("ControlPlane gRPC → %s (insecure — dev only!)", strings.ReplaceAll(addr, "\n", ""))
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
		},
		Streams: []grpc.StreamDesc{},
	}, svc)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}
	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Printf("ControlPlane gRPC error: %v", err)
		}
	}()
	return nil
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

// Run starts two background loops:
//  1. Config polling — fetches config every interval and applies changes.
//  2. Metrics push  — reports local stats to the Control Plane every interval.
func (c *DataPlaneClient) Run(ctx context.Context, pollInterval time.Duration) {
	go c.pollLoop(ctx, pollInterval)
	go c.metricsLoop(ctx, pollInterval*2)
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

func buildServerTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
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
		// Also add cluster CA to the pool so enrolled nodes are accepted.
		if globalClusterCA.Ready() {
			pool.AppendCertsFromPEM(globalClusterCA.CACertPEM())
		}
		tlsCfg.ClientCAs = pool
		// VerifyClientCertIfGiven allows unenrolled nodes to call Enroll
		// without a client cert, while still verifying certs from enrolled nodes.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
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
	cleaned := filepath.Clean(caFile)
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates in %s", caFile)
	}
	return pool, nil
}
