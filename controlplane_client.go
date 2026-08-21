package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// clusterGRPCCompressionEnvVar opts the DP into gzip-compressing its CP↔DP
// gRPC stream. It is a rollout/transition control, read once at startup
// (startup-scoped, recorded GUI-parity deferral — same class as the HA-lease
// endpoints and -cluster-insecure; the resolved value is still surfaced
// read-only on GET /api/cluster/status as grpcCompressionEnabled, same
// status-only precedent as the HA Fencing Lease card, so an operator can
// confirm the effective setting without shelling in). Default OFF: an
// unset/typo'd value leaves compression disabled so a partially-upgraded or
// rolled-back cluster can never go dark (the frame increase alone carries an
// uncompressed 2 M-host snapshot). Enable it only after every Control Plane
// in the fleet runs a build that registers the gzip codec (CP-first upgrade
// complete).
const clusterGRPCCompressionEnvVar = "CULVERT_CLUSTER_GRPC_COMPRESSION"

// clusterGRPCCompression is the resolved opt-in flag, read once at startup.
var clusterGRPCCompression = readClusterGRPCCompression()

// readClusterGRPCCompression parses the opt-in env var. Fail-safe: only an
// explicit true-ish value enables compression; everything else (unset,
// unknown, false-ish) leaves it off.
func readClusterGRPCCompression() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(clusterGRPCCompressionEnvVar))) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// ─── Data Plane gRPC client ───────────────────────────────────────────────────

// DataPlaneClient polls the Control Plane for configuration and applies changes
// to the local proxy state (blocklist, IP filter, rate limiter).
//
// When multiple CP addresses are configured (HA mode), the client automatically
// fails over to the next address on connection failure, trying each in order.
type DataPlaneClient struct {
	nodeID    string
	conn      *grpc.ClientConn
	addrs     []string // all CP addresses (for HA failover)
	activeIdx int      // index into addrs of current connection
	certFile  string   // TLS cert for reconnection
	keyFile   string   // TLS key for reconnection
	caFile    string   // CA cert for reconnection
	mu        sync.Mutex
	// lastVersion / lastPolicyVersion are the version facts of the config
	// snapshot this node has APPLIED — the config-store version and the CP's
	// monotonic policy generation carried on that snapshot (NOT the DP-local
	// policyStore apply counter, which ReplaceAll bumps to 1,2,… regardless of
	// the CP generation). fetchAndApply is the sole writer; both are seeded from
	// the last-known-good snapshot at startup so the heartbeat reports the
	// config the node is already enforcing even before the first successful CP
	// poll. Atomic because metricsLoop (a separate goroutine) reads them to
	// stamp the heartbeat report — race-free under -race. (T3 P1 reads
	// lastVersion.Load() for the delta base + convergence telemetry.)
	lastVersion       atomic.Int64
	lastPolicyVersion atomic.Int64
	failCount         int  // consecutive fetch failures for exponential backoff
	deltaUnsupported  bool // T3 P1: set when a CP returns Unimplemented for GetConfigDelta
	deltaProbeSkips   int  // T3 P1: polls skipped since the delta latch was set (re-probe counter)
	callForTest       func(context.Context, string, json.RawMessage) (json.RawMessage, error)
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

	// clusterClientCallOptions carries the mandatory raw codec (the default
	// proto codec cannot marshal json.RawMessage), the raised frame budget (an
	// enterprise 2 M-host snapshot is ~60 MiB, past gRPC's 4 MiB default), and
	// the opt-in gzip compressor. See controlplane_codec.go and
	// CULVERT_CLUSTER_GRPC_COMPRESSION for the CP-first migration rationale.
	conn, err := grpc.NewClient(addr, dialOpt, grpc.WithDefaultCallOptions(clusterClientCallOptions()...))
	if err != nil {
		return fmt.Errorf("gRPC dial %s: %w", addr, err)
	}
	// Close old connection if any.
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = conn
	// A new connection may be a different (possibly newer) CP — re-probe delta
	// support. Safe under the callers' locking: connect runs pre-goroutine in
	// NewDataPlaneClient and under c.mu in reconnectActive/failover.
	c.deltaUnsupported = false
	logger.Printf("DataPlane: connected to ControlPlane at %s", addr)
	return nil
}

// reconnectActive redials the currently-active CP address, re-reading the
// node cert/key/CA from disk (connect → buildClientTLS). This is how a
// freshly renewed DP certificate actually reaches the wire (CHAOS-12): gRPC
// only consults TLS material when the connection is constructed, so without
// a redial the old cert keeps being presented until process restart — and
// once the CP's dual-CA rotation cleanup drops the old CA, every reconnect
// with the old cert fails despite a valid renewed cert sitting on disk.
// On failure the existing connection is kept (connect swaps only after
// success), so the CP link degrades to the pre-renewal state instead of
// dropping.
func (c *DataPlaneClient) reconnectActive() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.addrs) == 0 {
		return nil // test-constructed stub with no real connection
	}
	return c.connect(c.addrs[c.activeIdx])
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

// pollConfig performs one GetConfig poll (with HA failover on repeated failure)
// and returns the raw response bytes. ok is false when the poll failed and a
// backoff was applied — the caller must return without applying. Split out of
// fetchAndApply to keep that function under the funlen budget.
func (c *DataPlaneClient) pollConfig(ctx context.Context) (raw json.RawMessage, ok bool) {
	// P0-3: report the version we already hold so the CP can reply with a tiny
	// "unchanged" sentinel instead of the full snapshot when nothing changed.
	// fetchAndApply is the only writer and runs on a single config-loop
	// goroutine; the atomic load keeps metricsLoop's concurrent read race-free.
	reqBody, _ := json.Marshal(getConfigRequest{KnownVersion: c.lastVersion.Load()})
	// CL-9 PR4: time the primary config poll (success only). Scope is exactly
	// this c.call — not the failover retry, unmarshal, validate, or apply.
	pollStart := time.Now()
	raw, err := c.call(ctx, methodGetConfig, reqBody)
	if err == nil {
		dpPollHist.Observe(time.Since(pollStart).Seconds())
	}
	if err != nil {
		dpMarkCPPollFailing()
		c.failCount++
		logger.Printf("DataPlane: GetConfig error: %v", err)
		// Only attempt failover after 3 consecutive failures with a peer to
		// fail over to; otherwise back off and retry the same CP next tick.
		if c.failCount < 3 || len(c.addrs) <= 1 {
			c.backoff(ctx)
			return nil, false
		}
		if !c.failover() {
			c.backoff(ctx)
			return nil, false
		}
		logger.Printf("DataPlane: failover succeeded — retrying GetConfig")
		// Retry immediately on the new connection; on success fall through to apply.
		raw, err = c.call(ctx, methodGetConfig, reqBody)
		if err != nil {
			dpMarkCPPollFailing()
			logger.Printf("DataPlane: GetConfig error after failover: %v", err)
			c.backoff(ctx)
			return nil, false
		}
	}
	c.resetBackoff()
	dpMarkCPPollHealthy()
	return raw, true
}

func (c *DataPlaneClient) fetchAndApply(ctx context.Context) {
	// T3 P1: when we already hold a version, try the incremental blocklist delta
	// first. tryDeltaSync returns true when it fully handled this cycle (nothing
	// changed, or the delta applied and verified); false falls through to the
	// full-snapshot path below (fresh DP, resync directive, old CP, or any error
	// — the full path owns backoff/failover).
	//
	// Safe across a restart even though lastVersion is now seeded from the
	// last-known-good snapshot at startup (dp_enrollment.go): both persist paths
	// write the CP-AUTHORITATIVE (manual-free) blocklist as the last-good
	// BlockedHosts, so applyDPLastGoodConfigSnapshot restores a syncedFP consistent
	// with the CP's fingerprint for that version. The KnownFP idle-drift check and
	// the post-apply fingerprint verification then force a FULL resync on any
	// inconsistency (e.g. a crash-mid-apply), so a first-poll delta can never
	// silently persist divergent state.
	if c.lastVersion.Load() > 0 && c.tryDeltaSync(ctx) {
		return
	}
	raw, ok := c.pollConfig(ctx)
	if !ok {
		return
	}
	// P0-3: detect the CP's "unchanged" sentinel before attempting a full
	// snapshot unmarshal. On an unchanged poll (the common case) this is a tiny
	// response and we skip the ~60 MiB unmarshal + validate + apply entirely.
	// Probing into a one-field struct also cheaply ignores a full snapshot
	// response (config_unchanged absent → false) without allocating its slices.
	var probe configUnchangedReply
	if err := json.Unmarshal(raw, &probe); err == nil && probe.ConfigUnchanged {
		return // CP confirmed our version is current; nothing to do
	}
	// A full snapshot: record its size so the next poll's deadline is budgeted
	// for a transfer this large even if that poll turns out to be unchanged.
	dpLastFullSnapshotBytes.Store(int64(len(raw)))
	var snap ConfigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		logger.Printf("DataPlane: parse config error: %v", err)
		markConfigSnapshotApplyRejected()
		return
	}
	// H5: validate per-slice caps BEFORE advancing lastVersion so that a
	// rejected (over-cap) snapshot does not poison the version counter —
	// otherwise the same poisoned version number would suppress every
	// subsequent legitimate snapshot via the "snap.Version <= lastVersion"
	// short-circuit below.
	if err := validateConfigSnapshot(snap); err != nil {
		logger.Printf("DataPlane: rejecting config snapshot v%d: %v", snap.Version, err)
		markConfigSnapshotApplyRejected()
		return
	}
	// ADR-0005 S3: the epoch fence must run BEFORE any caller-side mutation
	// — external-auth/IdP application below, the last-good persist, and the
	// lastVersion advance would otherwise let a fenced-out zombie CP poison
	// the last-good file and the version ratchet even though
	// applyConfigSnapshot rejects (Codex review, PR #536). Same poison
	// rationale as the H5 placement above. applyConfigSnapshot re-checks
	// (equal epoch passes) for its other callers.
	if !dpObserveEpoch("config snapshot", snap.Epoch) {
		return
	}
	if snap.Version <= c.lastVersion.Load() {
		return // nothing changed
	}
	snapForDisk := snap
	applyExternalAuthSnapshotSettings(snap)
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		logger.Printf("DataPlane: config snapshot v%d apply incomplete: %v", snap.Version, err)
		markConfigSnapshotApplyRejected()
		return
	}
	snap.IdPProfiles = nil
	// fetchAndApply pre-validated above, so a rejection here is unexpected; log
	// and do NOT persist last-good or advance lastVersion on it (a partial/empty
	// apply must not be recorded as the new good state).
	if err := applyConfigSnapshot(snap); err != nil {
		logger.Printf("DataPlane: config snapshot v%d apply rejected: %v", snap.Version, err)
		markConfigSnapshotApplyRejected()
		return
	}
	persistDPLastGoodConfigSnapshot(snapForDisk)
	dpMarkCPPollHealthy()
	markConfigSnapshotApplyOK()
	c.lastVersion.Store(snap.Version)
	c.lastPolicyVersion.Store(snap.PolicyVersion)
}

// tryDeltaSync performs one GetConfigDelta poll. Returns true when the cycle is
// fully handled (unchanged, delta applied+verified, or a fenced-out CP we skip);
// false to fall through to the full-snapshot path. Never touches failCount — the
// full path owns backoff/failover, so a delta error costs at most one wasted RPC
// before the full poll runs.
func (c *DataPlaneClient) tryDeltaSync(ctx context.Context) bool {
	c.mu.Lock()
	unsupported := c.deltaUnsupported
	if unsupported {
		// Re-probe periodically even without a reconnect: gRPC transparently
		// re-heals the transport on the SAME ClientConn across an in-place CP
		// upgrade, so connect() (which clears the latch) is never called. Without
		// this, a DP that met an old CP would use the full path forever after the
		// CP is upgraded. Every deltaReprobeInterval polls we clear the latch and
		// probe once more; a still-old CP just re-latches.
		c.deltaProbeSkips++
		if c.deltaProbeSkips >= deltaReprobeInterval {
			c.deltaProbeSkips = 0
			c.deltaUnsupported = false
			unsupported = false
		}
	}
	c.mu.Unlock()
	if unsupported {
		return false // known-old CP: skip straight to the full path
	}

	req, _ := json.Marshal(getConfigDeltaRequest{KnownVersion: c.lastVersion.Load(), KnownFP: bl.SyncedFingerprint()})
	raw, err := c.call(ctx, methodGetConfigDelta, req)
	if err != nil {
		if status.Code(err) == codes.Unimplemented {
			c.mu.Lock()
			c.deltaUnsupported = true
			c.deltaProbeSkips = 0
			c.mu.Unlock()
			logger.Printf("DataPlane: control plane has no GetConfigDelta — using full config sync (will re-probe)")
		}
		return false // fall back to the full path (which handles backoff/failover)
	}
	var reply getConfigDeltaReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		logger.Printf("DataPlane: parse config delta error: %v", err)
		return false
	}
	switch reply.Mode {
	case "unchanged":
		c.resetBackoff()
		dpMarkCPPollHealthy()
		return true
	case "delta":
		return c.applyDeltaReply(reply)
	default: // "resync" or unknown → full path
		return false
	}
}

// applyDeltaReply applies a delta-mode reply. Returns true when applied+verified
// (lastVersion advanced), false to fall through to a full resync. Ordering
// (Codex review): epoch fence, then the BLOCKLIST delta + cap + fingerprint
// verification BEFORE any other store is touched, then the non-blocklist
// remainder (external-auth/IdP/policy/…). A rejected delta (cap or fingerprint
// mismatch) therefore leaves auth/IdP/policy UNTOUCHED — never advanced to a
// version whose blocklist could not be verified.
func (c *DataPlaneClient) applyDeltaReply(reply getConfigDeltaReply) bool {
	// ADR-0005 S3: fence before ANY mutation. A fenced-out zombie CP's delta is
	// rejected; skip the cycle rather than fall through to a full pull that would
	// re-fence identically.
	if !dpObserveEpoch("config delta", reply.Epoch) {
		return true
	}
	// Base must match ours (strict sequential), and the target must move strictly
	// FORWARD. Advancing lastVersion to a CP-controlled TargetVersion without the
	// forward check would let a buggy/hostile CP jump it to a huge value, after
	// which every full-path snapshot (snap.Version <= lastVersion) is silently
	// suppressed — a stale-config freeze DoS.
	if len(reply.Remainder) == 0 || reply.BaseVersion != c.lastVersion.Load() || reply.TargetVersion <= reply.BaseVersion {
		return false // malformed, base moved, or non-monotonic target → full resync
	}
	var remainder ConfigSnapshot
	if err := json.Unmarshal(reply.Remainder, &remainder); err != nil {
		logger.Printf("DataPlane: parse delta remainder v%d: %v — full resync", reply.TargetVersion, err)
		markConfigSnapshotApplyRejected()
		return false
	}
	if err := validateConfigSnapshot(remainder); err != nil {
		logger.Printf("DataPlane: rejecting delta remainder v%d: %v", reply.TargetVersion, err)
		markConfigSnapshotApplyRejected()
		return false
	}
	// applyBlocklistDeltaSnapshot applies the blocklist chain and verifies the
	// cap + fingerprint FIRST, and ONLY on success applies the non-blocklist
	// remainder (external-auth before IdP, then the rest) — so no auth/IdP/policy
	// mutation happens for a delta whose blocklist is rejected. snapForDisk keeps
	// the full remainder (incl. IdP profiles) for the last-good file.
	snapForDisk := remainder
	if err := applyBlocklistDeltaSnapshot(remainder, reply.Deltas, reply.TargetFP); err != nil {
		logger.Printf("DataPlane: delta v%d apply failed: %v — full resync", reply.TargetVersion, err)
		markConfigSnapshotApplyRejected()
		return false
	}
	// Persist a RECONSTRUCTED full last-good: the remainder omits BlockedHosts, so
	// a cold restart would otherwise re-apply an empty blocklist. Use FeedList()
	// (CP-authoritative, non-manual) — NOT List() — so the on-disk BlockedHosts is
	// fingerprint-consistent with the CP's feed-only target: List() would fold in
	// DP-local manual blocks the CP set never had, poisoning syncedFP on reload.
	// (Enforcement of manual blocks is unaffected — ReplaceFeedEntries re-injects
	// them on the restart apply.) This is load-bearing: lastVersion IS restored
	// from the last-good at startup (dp_enrollment.go), so a fingerprint-consistent
	// on-disk BlockedHosts is what lets a first-poll delta resume safely instead of
	// forcing a spurious resync every restart (see the fetchAndApply gate).
	snapForDisk.BlockedHosts = bl.FeedList()
	persistDPLastGoodConfigSnapshot(snapForDisk)
	dpMarkCPPollHealthy()
	markConfigSnapshotApplyOK()
	c.resetBackoff()
	c.lastVersion.Store(reply.TargetVersion)
	c.lastPolicyVersion.Store(remainder.PolicyVersion)
	logger.Printf("DataPlane: applied config delta → v%d (%d step(s))", reply.TargetVersion, len(reply.Deltas))
	return true
}

// buildMetricsReport assembles the DP→CP heartbeat report. The version facts
// are raw diagnostics (M5 PR-A): ConfigVersion/PolicyVersion are the APPLIED
// snapshot's identity (seeded from the last-known-good snapshot at startup, so
// they are populated even before the first successful poll), Epoch is the
// highest fencing epoch observed, and CulvertVersion is this build. SyncedFP is
// the T3 P1 blocklist synced fingerprint (fleet convergence/drift). All reads
// are atomic or set-once — safe from the metricsLoop goroutine.
func (c *DataPlaneClient) buildMetricsReport() MetricsReport {
	return MetricsReport{
		NodeID:         c.nodeID,
		Total:          atomic.LoadInt64(&statTotal),
		Blocked:        atomic.LoadInt64(&statBlocked),
		AuthFail:       atomic.LoadInt64(&statAuthFail),
		Uptime:         uptime(),
		ConfigVersion:  c.lastVersion.Load(),
		PolicyVersion:  c.lastPolicyVersion.Load(),
		Epoch:          dpLastSeenEpoch.Load(),
		CulvertVersion: version,
		SyncedFP:       bl.SyncedFingerprint(),
	}
}

func (c *DataPlaneClient) metricsLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report := c.buildMetricsReport()
			b, _ := json.Marshal(report)
			raw, err := c.call(ctx, methodPushMetrics, b)
			if err != nil {
				logger.Printf("DataPlane: PushMetrics error: %v", err)
				continue
			}
			// ADR-0005 S3: every heartbeat reply carries the CP's fencing
			// epoch — ratchet it so leadership changes are learned between
			// config polls (a stale reply just logs; nothing to reject here).
			var reply dpHeartbeatReply
			if json.Unmarshal(raw, &reply) == nil {
				_ = dpObserveEpoch("heartbeat reply", reply.Epoch)
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
//
// c.conn is read under c.mu for a single pointer snapshot, then the
// lock is released BEFORE Invoke runs (holding the lock across the
// RPC would serialize all DP loops and block any failover for the
// 5-second timeout). The local conn variable is the snapshot the
// caller uses; if a concurrent c.failover() replaces c.conn after we
// release the lock, our snapshot is still a valid *grpc.ClientConn
// — gRPC's lazy Close() on the swapped-out conn allows in-flight
// Invoke calls to either complete or surface a transport-closing
// error. CL-11: the snapshot prevents the unsynchronized field read
// that `go test -race` flagged at this line.
func (c *DataPlaneClient) call(ctx context.Context, method string, req json.RawMessage) (json.RawMessage, error) {
	if c.callForTest != nil {
		return c.callForTest(ctx, method, req)
	}
	callCtx, cancel := context.WithTimeout(ctx, callDeadline(method))
	defer cancel()
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	var resp json.RawMessage
	err := conn.Invoke(callCtx, method, req, &resp)
	return resp, err
}

// Config-poll deadline model (P1 #4). A fixed 5s deadline was fine for the old
// ~4 MiB-capped snapshot, but a 2 M-host config (~60 MiB) can legitimately take
// far longer to transfer on a thin WAN — a timeout there increments failCount
// and triggers spurious failover churn against a HEALTHY leader. The
// snapshot-carrying RPCs (GetConfig, HASync) therefore get a deadline that
// SCALES with the last full snapshot size at a conservative WAN throughput
// floor; all other RPCs keep the tight 5s.
const (
	dpTightCallDeadline  = 5 * time.Second
	dpConfigBaseDeadline = 15 * time.Second
	dpConfigMaxDeadline  = 300 * time.Second
	dpConfigWANFloorBps  = 512 * 1024 // 512 KiB/s (~4 Mbit/s) — a starved-link floor
)

// deltaReprobeInterval is how many polls a DP stays on the full path after a CP
// returns Unimplemented for GetConfigDelta before re-probing. Covers the in-place
// CP-upgrade case where gRPC re-heals the transport on the same ClientConn and
// connect() (which clears the latch) never runs. At the default poll interval
// this re-probes a few minutes after an upgrade — cheap, and self-correcting.
const deltaReprobeInterval = 20

// dpLastFullSnapshotBytes is the size of the most recent FULL config snapshot
// the DP received (not the tiny version-unchanged sentinel). It predicts how big
// the next change will be, so an unchanged poll still budgets enough time for a
// potential full transfer. Exposed as culvert_dp_config_last_snapshot_bytes.
var dpLastFullSnapshotBytes atomic.Int64

// callDeadline picks the per-RPC deadline. GetConfig/HASync carry the snapshot,
// so they scale with the last full size; everything else stays tight.
func callDeadline(method string) time.Duration {
	switch method {
	case methodGetConfig, methodHASync, methodGetConfigDelta:
		// GetConfigDelta carries a delta chain (up to the ring's byte bound) plus
		// the non-blocklist remainder — a multi-MiB reply on a thin WAN. Without the
		// scaled deadline it would time out at 5s and fall through to the full pull,
		// so the delta path would add a wasted RPC and save nothing for exactly the
		// larger changes it should optimize. Budget it like the snapshot RPCs.
		return scaledConfigDeadline(dpLastFullSnapshotBytes.Load())
	default:
		return dpTightCallDeadline
	}
}

// scaledConfigDeadline = base + lastBytes / WAN-floor, clamped. With no history
// (first poll) it is just the base, generous enough for a moderate initial
// snapshot on a slow link; once a full snapshot is seen it tracks that size.
func scaledConfigDeadline(lastBytes int64) time.Duration {
	d := dpConfigBaseDeadline
	if lastBytes > 0 {
		d += time.Duration(lastBytes/dpConfigWANFloorBps) * time.Second
	}
	if d > dpConfigMaxDeadline {
		d = dpConfigMaxDeadline
	}
	return d
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
