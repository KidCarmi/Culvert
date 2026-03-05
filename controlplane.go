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
const configServiceName = "proxyshield.ConfigService"

// methodGetConfig and methodPushMetrics are the RPC method descriptors.
var (
	methodGetConfig   = fmt.Sprintf("/%s/GetConfig", configServiceName)
	methodPushMetrics = fmt.Sprintf("/%s/PushMetrics", configServiceName)
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
	nodeMetricsMu.Lock()
	nodeMetrics[report.NodeID] = report
	nodeMetricsMu.Unlock()
	logger.Printf("ControlPlane: metrics from node %s (total=%d)", report.NodeID, report.Total)
	return json.RawMessage(`{"ok":true}`), nil
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
		logger.Printf("ControlPlane gRPC → %s (mTLS)", addr)
	} else {
		serverOpt = grpc.EmptyServerOption{}
		logger.Printf("ControlPlane gRPC → %s (insecure — dev only!)", addr)
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
	nodeID     string
	conn       *grpc.ClientConn
	lastVersion int64
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
		logger.Printf("DataPlane: GetConfig error: %v", err)
		return
	}
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
	newBL := &Blocklist{hosts: map[string]bool{}}
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
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert // mTLS
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
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates in %s", caFile)
	}
	return pool, nil
}
