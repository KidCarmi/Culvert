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
// The control-plane implementation is split across cohesive files (DEBT-003
// god-file decomposition — same package, no behaviour change):
//   - controlplane.go          — gRPC service definition + CP-side aggregators
//                                (rate-limit / revocation / audit) + enrollment
//                                rate-limiting + node-metrics list (this file)
//   - controlplane_snapshot.go — ConfigSnapshot struct + caps, ConfigStore, and
//                                the whole applyConfigSnapshot / DP last-good /
//                                CurrentConfigSnapshot lifecycle
//   - controlplane_server.go   — the Control Plane gRPC server + all RPC
//                                handlers (GetConfig/PushMetrics/Enroll/RenewCert/
//                                HASync/…) + enrollment admission
//   - controlplane_client.go   — the Data Plane gRPC client + poll/metrics/
//                                gossip/revocation/audit loops
//   - controlplane_tls.go      — shared mTLS config + cert-pool rebuild
//
// Wire protocol (no .proto file needed for this implementation):
//   Uses encoding/json over a gRPC unary stream to keep the implementation
//   self-contained without requiring protoc.  In a production deployment,
//   replace the JSON codec with generated protobuf for efficiency.

import (
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
)

// ─── gRPC service definition (no protoc needed) ───────────────────────────────

// We implement a minimal gRPC service using the grpc framework but with a
// hand-written codec.  This avoids protoc as a build dependency.

// configServiceName is the fully-qualified gRPC service name.
const configServiceName = "culvert.ConfigService"

// methodGetConfig, methodPushMetrics, and methodEnroll are the RPC method descriptors.
var (
	methodGetConfig       = fmt.Sprintf("/%s/GetConfig", configServiceName)
	methodPushMetrics     = fmt.Sprintf("/%s/PushMetrics", configServiceName)
	methodEnroll          = fmt.Sprintf("/%s/Enroll", configServiceName)
	methodSyncRateLimits  = fmt.Sprintf("/%s/SyncRateLimits", configServiceName)
	methodSyncRevocations = fmt.Sprintf("/%s/SyncRevocations", configServiceName)
	methodPushAuditEvents = fmt.Sprintf("/%s/PushAuditEvents", configServiceName)
	methodRenewCert       = fmt.Sprintf("/%s/RenewCert", configServiceName)
	methodHASync          = fmt.Sprintf("/%s/HASync", configServiceName)
)

// getConfigRequest is the GetConfig request body (P0-3). The DP reports the
// config version it already holds so the CP can skip resending an unchanged
// snapshot. Absent/zero (old DP, or first poll) means "send the full snapshot".
type getConfigRequest struct {
	KnownVersion int64 `json:"known_version,omitempty"`
}

// configUnchangedReply is the tiny GetConfig response the CP returns when the
// DP's KnownVersion is already current. The distinctive config_unchanged key
// lets the DP detect it with a cheap probe before attempting a full snapshot
// unmarshal. Never carries any snapshot data or secrets.
type configUnchangedReply struct {
	ConfigUnchanged bool  `json:"config_unchanged"`
	Version         int64 `json:"version,omitempty"`
}

// MetricsReport is sent by Data Plane nodes to the Control Plane.
type MetricsReport struct {
	NodeID   string `json:"node_id"`
	Total    int64  `json:"total"`
	Blocked  int64  `json:"blocked"`
	AuthFail int64  `json:"auth_fail"`
	Uptime   string `json:"uptime"`
	// M5 PR-A: raw version facts so the CP (and TAC Cloud) can tell which
	// config each DP actually applied without correlating on the box. All
	// additive + omitempty: a mixed-version cluster where an older DP omits
	// them degrades to the zero value, never errors (the snapshot discipline).
	ConfigVersion  int64  `json:"config_version,omitempty"`  // applied config-snapshot version (DP-side c.lastVersion)
	PolicyVersion  int64  `json:"policy_version,omitempty"`  // running policy-store generation on the node
	Epoch          int64  `json:"epoch,omitempty"`           // highest fencing epoch the node has observed
	CulvertVersion string `json:"culvert_version,omitempty"` // build version string on the node
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
	mu       sync.Mutex
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

// enrollRateLimitWindow is the sliding window over which enrollment attempts
// accumulate. Shared by enrollRateLimitAllow and the cleanup sweep so the two
// agree on staleness. (enrollRateLimitAllow keeps its own local const equal to
// this for the hot path; both are one minute.)
const enrollRateLimitWindow = time.Minute

// enrollRateLimitCleanup drops per-IP entries whose every timestamp has aged
// out of the window. enrollRateLimitAllow prunes a slice only on that same IP's
// NEXT attempt, so an IP that enrolls once and never returns would otherwise
// leave a permanent entry — unbounded growth keyed by client IP. Called
// periodically by the shared security-limiter janitor; a no-op on non-control-
// plane nodes (the map is empty there).
func enrollRateLimitCleanup() {
	enrollRateLimit.mu.Lock()
	defer enrollRateLimit.mu.Unlock()
	now := time.Now()
	for ip, times := range enrollRateLimit.attempts {
		fresh := times[:0]
		for _, t := range times {
			if now.Sub(t) < enrollRateLimitWindow {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(enrollRateLimit.attempts, ip)
		} else {
			enrollRateLimit.attempts[ip] = fresh
		}
	}
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
