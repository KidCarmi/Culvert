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
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
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
	methodGetConfigDelta  = fmt.Sprintf("/%s/GetConfigDelta", configServiceName)
)

// getConfigDeltaRequest is the GetConfigDelta request body (T3 P1). The DP
// reports the blocklist config version it currently holds so the CP can return
// just the incremental {added, removed} chain to reach the newest version — or a
// resync directive when the DP is too far behind to be caught up incrementally.
type getConfigDeltaRequest struct {
	KnownVersion int64  `json:"known_version"`
	KnownFP      string `json:"known_fp,omitempty"` // DP's current synced fingerprint (diagnostic)
}

// getConfigDeltaReply is the GetConfigDelta response.
//
// Mode:
//   - "unchanged": the DP is already current; nothing to apply.
//   - "delta": Deltas carry the ordered, gap-free blocklist chain from
//     BaseVersion to TargetVersion; Remainder carries the target snapshot with
//     BlockedHosts omitted (the small non-blocklist slices, applied wholesale);
//     TargetFP is the synced fingerprint the DP must reach after applying the
//     chain (a mismatch forces a full resync).
//   - "resync": the DP must fall back to a full GetConfig (gap, resync marker,
//     or a raced/lagging delta ring).
//
// Epoch is the issuing CP's fencing epoch at response time — the DP applies the
// same dpObserveEpoch ratchet it applies to a full snapshot (ADR-0005 S3), so a
// fenced-out zombie CP cannot poison the incremental base.
type getConfigDeltaReply struct {
	Mode          string           `json:"mode"`
	BaseVersion   int64            `json:"base_version,omitempty"`
	TargetVersion int64            `json:"target_version,omitempty"`
	Epoch         int64            `json:"epoch,omitempty"`
	Deltas        []blocklistDelta `json:"deltas,omitempty"`
	TargetFP      string           `json:"target_fp,omitempty"`
	// Remainder is the target snapshot MINUS BlockedHosts (which rides as the
	// delta chain), pre-marshaled so the CP shares one remainder marshal across
	// the fleet instead of re-marshaling the host-scale non-blocklist slices per
	// DP. The DP unmarshals it into a ConfigSnapshot.
	Remainder json.RawMessage `json:"remainder,omitempty"`
}

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
	// M5 PR-A + T3 P1 reverse telemetry: raw version facts plus the blocklist
	// synced fingerprint the DP enforces, so the CP (and TAC Cloud) can tell which
	// config each DP actually applied and surface fleet convergence/stragglers
	// without correlating on the box. All additive + omitempty: a mixed-version
	// cluster where an older DP omits them degrades to the zero value, never
	// errors (the snapshot discipline).
	ConfigVersion  int64  `json:"config_version,omitempty"`  // applied config-snapshot version (DP-side c.lastVersion)
	PolicyVersion  int64  `json:"policy_version,omitempty"`  // running policy-store generation on the node
	Epoch          int64  `json:"epoch,omitempty"`           // highest fencing epoch the node has observed
	CulvertVersion string `json:"culvert_version,omitempty"` // build version string on the node
	SyncedFP       string `json:"synced_fp,omitempty"`       // T3 P1: blocklist synced fingerprint (drift detection)
	// AuditClusterPushDrops is CHAOS-61's DP->CP audit push-queue drop count
	// (auditPendingDrops(), process-lifetime, never reset) as observed on THIS
	// node when the report was built. It only ever moves on a Data Plane node
	// (the counter is charged by internal/audit's DP push-queue path, which a
	// Control Plane never exercises). Carried in the heartbeat, rather than left
	// as a purely local /healthz/metrics fact, so the CP's own dashboard can
	// aggregate it across the fleet instead of requiring an admin to open every
	// DP's admin UI individually to learn the centralized audit trail has a gap.
	AuditClusterPushDrops int64 `json:"audit_cluster_push_drops,omitempty"`
	// AuditDropsReported is the capability bit for the field above: true from
	// every build that reports AuditClusterPushDrops. With omitempty a zero
	// count and a legacy build that cannot report one decode identically, so
	// the CP keys "is this node's count trustworthy?" on this bit instead.
	AuditDropsReported bool `json:"audit_drops_reported,omitempty"`
}

// nodeMetrics aggregates metrics from all connected Data Plane nodes.
var (
	nodeMetricsMu sync.RWMutex
	nodeMetrics   = map[string]MetricsReport{}
)

// auditClusterPushDropsTotal is the CHAOS-61 counter an admin should actually
// look at: this node's own drops (non-zero only when this process is itself a
// Data Plane) plus the drops most recently reported by every OTHER Data Plane
// node heartbeating to it (non-zero only on a Control Plane). A standalone or
// DP node has no entries in nodeMetrics and this degrades to
// auditPendingDrops() alone; a Control Plane node's own auditPendingDrops() is
// always zero, so this degrades to the fleet sum. Either way, GET /api/stats
// reports the number that answers "is our centralized audit trail complete?"
// from whichever node the admin happens to be looking at.
//
// A process that runs both roles also heartbeats to itself, so its own
// nodeMetrics entry carries the same process-lifetime counter as
// auditPendingDrops(); that entry is skipped (the local read is fresher) so
// the drops are not counted twice.
func auditClusterPushDropsTotal() int64 {
	total := auditPendingDrops()
	// clusterRole is read-only outside the cluster-role arbiter
	// (cluster_role_arbiter.go) — every other reader goes through
	// clusterRoleSnapshot(), since a direct RLock can observe a mixed tuple
	// while the CP claim is asynchronous.
	self := clusterRoleSnapshot().nodeID
	nodeMetricsMu.RLock()
	for id := range nodeMetrics {
		if self != "" && id == self {
			continue
		}
		total += nodeMetrics[id].AuditClusterPushDrops
	}
	nodeMetricsMu.RUnlock()
	return total
}

// auditClusterPushUnreportingNodes counts enrolled nodes whose audit drop
// count the Control Plane cannot trust, so a zero total is not evidence the
// centralized trail is complete:
//   - disconnected (heartbeat timeout) or draining (SetNodeDraining, for
//     maintenance): the node cannot deliver its count, and losing the CP
//     link — or going down for maintenance — is exactly when its push queue
//     drops. checkNodeLiveness only ever flips "connected" to "disconnected",
//     so a draining DP that actually stops heartbeating never becomes
//     "disconnected" either; it would otherwise go unnoticed indefinitely;
//   - connected with no heartbeat on file yet (CP restart, HA promotion, or
//     the ~60s metricsLoop startup window) or heartbeating from a build
//     without AuditDropsReported (a rolling upgrade): either way there is no
//     trustworthy drop field to read.
//
// Reported beside the total so the dashboard can say "unknown" instead of
// "complete". Zero on a standalone or DP-only node.
func auditClusterPushUnreportingNodes() int {
	nodes := globalClusterStore.ListNodes()
	n := 0
	nodeMetricsMu.RLock()
	defer nodeMetricsMu.RUnlock()
	for i := range nodes {
		switch nodes[i].Status {
		case "disconnected", "draining":
			n++
		case "connected":
			if m, ok := nodeMetrics[nodes[i].NodeID]; !ok || !m.AuditDropsReported {
				n++
			}
		}
	}
	return n
}

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
	// cpLocal holds the Control Plane's OWN revocations (CHAOS-68).
	//
	// It is a SEPARATE FIELD rather than a reserved key in perNode, and that is
	// the whole point: a reserved key is only as safe as the guarantee that no
	// enrolled node can ever be named it, and node ids reach this map from an
	// enrollment. A field cannot be addressed by Update(nodeID, …) at all, so a
	// node cannot overwrite the CP's slot and MergedExcluding cannot filter the
	// CP's entries out of that node's merge — regardless of what the node is
	// called. Collision is structurally absent instead of merely unlikely.
	cpLocal []RevocationEntry
	// respCursor is, per requesting node, where the budgeted SyncRevocations
	// REPLY's rotating window stopped (AU-71). An entry exists only while that
	// node's reply is over budget, and its key space is perNode's (verified
	// node ids), so it is bounded by the same thing.
	respCursor map[string]revSyncCursor
}

var globalRevAggregator = &revocationAggregator{
	perNode: map[string][]RevocationEntry{},
}

// responseCursor returns where nodeID's previous over-budget reply stopped.
func (a *revocationAggregator) responseCursor(nodeID string) revSyncCursor {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.respCursor[nodeID]
}

// setResponseCursor records where nodeID's reply stopped; a cleared cursor
// (the whole set fitted) deletes the entry.
func (a *revocationAggregator) setResponseCursor(nodeID string, c revSyncCursor) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !c.set {
		delete(a.respCursor, nodeID)
		return
	}
	if a.respCursor == nil {
		a.respCursor = map[string]revSyncCursor{}
	}
	a.respCursor[nodeID] = c
}

// maxRevocationsPerNode caps how many revocation entries the Control Plane
// retains from ONE Data Plane node.
//
// CHAOS-73: this aggregator is the DP→CP push direction, and it bounded
// nothing — neither the entry count nor the key length — while
// MergedExcluding walks the union of EVERY node's entries and allocates a
// dedup map over it on EVERY SyncRevocations call, which each node makes
// every 3 s. So one node's oversized push cost the CP O(total) CPU and
// allocation per node per tick, and was then fanned back out to every other
// node in the fleet to be merged and persisted.
//
// internal/audit's DP→CP queue already caps this same direction at 1000 with
// a drops counter on the explicit reasoning that a DP which cannot reach its
// CP must not grow unbounded; the identical argument applies in reverse to a
// CP aggregating from its fleet. The cap is deliberately far above any real
// deployment (a node holds one entry per logout inside one session TTL) so
// reaching it means a node is malfunctioning or hostile, not busy.
const maxRevocationsPerNode = 4096

// Update stores the latest revocation entries from a node, bounded, and
// RETURNS the bounded set it retained.
//
// Entries are DROPPED rather than the push being refused: a refusal would
// also discard the node's legitimate entries, and the honest degradation is
// that cluster-wide revocation is incomplete for the overflow — which is
// counted, because a dropped revocation means a session an operator killed
// may still authenticate on other nodes.
//
// THE RETURN VALUE IS THE BOUND, AND EVERY CONSUMER OF A PEER'S PUSH MUST USE
// IT RATHER THAN THE RAW REQUEST. CHAOS-68 gave the CP's SyncRevocations
// handler a SECOND consumer of the same slice — mergeAndPersistRevocations,
// which writes the peer's entries into the Control Plane's OWN sessionRevoked
// — and that consumer was handed `req.Entries` while only the fan-out slot
// got the bounded set. The per-node cap then governed what the CP broadcast
// but not what it enforced and persisted locally, so one enrolled node could
// fill the GLOBAL MaxRevocationEntries (65536) from a single 16 MiB request
// (~490k minimal entries) and make the CP refuse every LATER remote
// revocation with RevokeCapacity — a genuine logout on another node no longer
// honoured on the Control Plane, which is the exact fail-open CHAOS-68 exists
// to close. Returning the bounded slice makes the one cap govern both
// consumers structurally, instead of each call site remembering to re-apply
// it. Gate: session_revocation_cp_merge_bound_test.go.
func (a *revocationAggregator) Update(nodeID string, entries []RevocationEntry) []RevocationEntry {
	// Capacity is bounded by the cap, not by the peer-supplied length: the
	// stored slice must not retain a backing array proportional to the whole
	// request (Codex P2, PR #1591).
	kept := make([]RevocationEntry, 0, min(len(entries), maxRevocationsPerNode))
	dropped := 0
	for _, e := range entries {
		// CHAOS-68 added a second free-form field to the wire, a user
		// revocation's User. It is bounded exactly like the token, for the
		// reason Prov is cleared below: a length bound on one field is no
		// bound on what is stored and fanned out if a sibling field is not.
		if len(e.Token) > session.MaxRevocationTokenLen || len(e.User) > session.MaxRevocationTokenLen {
			dropped++
			continue
		}
		if len(kept) >= maxRevocationsPerNode {
			dropped++
			continue
		}
		// Provenance is meaningful ONLY for this node's own persistence file,
		// and nothing on the gossip path reads it — but it is a decodable
		// field on the wire, so a peer can attach an arbitrarily large value
		// that the length bound above (which measures the TOKEN) does not see.
		// The Control Plane retains these entries and fans them to every other
		// node every 3 s, so clearing it here is what makes the per-node
		// bounds bound what is actually stored and broadcast (Codex P2).
		e.Prov = ""
		kept = append(kept, e)
	}
	if dropped > 0 {
		clusterRevocationDrops.Add(int64(dropped))
	}
	a.mu.Lock()
	a.perNode[nodeID] = kept
	a.mu.Unlock()
	// Safe to hand out: a later Update for this node REPLACES the map value
	// with a freshly allocated slice rather than mutating this backing array,
	// and MergeRevocations only reads the entries it is given.
	return kept
}

// clusterRevocationDrops counts revocation entries the Control Plane refused
// to retain from a Data Plane node (over-long key, or past the per-node cap).
// Non-zero means cluster-wide session revocation is incomplete.
var clusterRevocationDrops atomic.Int64

// clusterRevocationDropTotal reports the count for the metrics surface.
func clusterRevocationDropTotal() int64 { return clusterRevocationDrops.Load() }

// UpdateLocal stores the Control Plane's own revocation entries (CHAOS-68).
//
// Before this, the aggregator had exactly one writer — a Data Plane push — so
// the CP contributed nothing to the fleet-wide merge. The admin UI runs on the
// CP, which makes it the node where logouts and account deletions actually
// happen, so the one node whose revocations mattered most was the one node
// whose revocations went nowhere.
func (a *revocationAggregator) UpdateLocal(entries []RevocationEntry) {
	a.mu.Lock()
	a.cpLocal = entries
	a.mu.Unlock()
}

// MergedExcluding returns all revocation entries from other nodes, plus the
// Control Plane's own (which are never excluded — the requester is never the CP).
func (a *revocationAggregator) MergedExcluding(nodeID string) []RevocationEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	var merged []RevocationEntry
	seen := map[string]bool{}
	for _, e := range a.cpLocal {
		// SEC-REVEXP-1: the one oracle, not a local comparison. `exp.Before(now)`
		// is `now.After(exp)` transposed, and every wire expiry is a whole second
		// while `now` carries a sub-second remainder — so for the whole second
		// numbered Expiry it omitted an entry whose cookie Decode still accepts.
		// This loop answers a DP's SyncRevocations, so the omission reached the
		// requesting node as "no such revocation" (AU-72).
		if !session.RevocationLiveAt(now, e.Expiry) {
			continue // expired on the shared oracle
		}
		if !seen[e.Token] {
			seen[e.Token] = true
			merged = append(merged, e)
		}
	}
	for nid, entries := range a.perNode {
		if nid == nodeID {
			continue
		}
		for _, e := range entries {
			// Same oracle as the CP loop above. Leaving this one on the raw
			// predicate would put two dialects of one question inside one
			// function, which is the shape AU-62 was.
			if !session.RevocationLiveAt(now, e.Expiry) {
				continue // expired on the shared oracle
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
		certFile string // TLS cert path (for HA deploy command)
		keyFile  string // TLS key path (for HA deploy command)
		caFile   string // CA cert path (for HA deploy command)
	}
)

// isManagedDataPlane reports whether this node is an enrolled Data Plane node
// (role "data-plane"), i.e. a node whose fleet-authoritative configuration is
// owned by a Control Plane. Such a node MUST NOT accept local mutations of
// CP-authoritative feed policy (F3a-2): the CP is the single writer, and a local
// edit would either be silently overwritten on the next config sync or diverge
// the node from the fleet. A standalone or control-plane node is locally
// authoritative and may edit freely. Read under clusterRoleMu.
func isManagedDataPlane() bool {
	return clusterRoleSnapshot().role == "data-plane"
}

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
