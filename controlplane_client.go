package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
	callForTest func(context.Context, string, json.RawMessage) (json.RawMessage, error)
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

func (c *DataPlaneClient) fetchAndApply(ctx context.Context) {
	// CL-9 PR4: time the primary config poll (success only). Scope is exactly
	// this c.call — not the failover retry, unmarshal, validate, or apply.
	pollStart := time.Now()
	raw, err := c.call(ctx, methodGetConfig, json.RawMessage("{}"))
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
			return
		}
		if !c.failover() {
			c.backoff(ctx)
			return
		}
		logger.Printf("DataPlane: failover succeeded — retrying GetConfig")
		// Retry immediately on the new connection; on success fall through to apply.
		raw, err = c.call(ctx, methodGetConfig, json.RawMessage("{}"))
		if err != nil {
			dpMarkCPPollFailing()
			logger.Printf("DataPlane: GetConfig error after failover: %v", err)
			c.backoff(ctx)
			return
		}
	}
	c.resetBackoff()
	dpMarkCPPollHealthy()
	var snap ConfigSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		logger.Printf("DataPlane: parse config error: %v", err)
		return
	}
	// H5: validate per-slice caps BEFORE advancing lastVersion so that a
	// rejected (over-cap) snapshot does not poison the version counter —
	// otherwise the same poisoned version number would suppress every
	// subsequent legitimate snapshot via the "snap.Version <= lastVersion"
	// short-circuit below.
	if err := validateConfigSnapshot(snap); err != nil {
		logger.Printf("DataPlane: rejecting config snapshot v%d: %v", snap.Version, err)
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
	if snap.Version <= c.lastVersion {
		return // nothing changed
	}
	snapForDisk := snap
	applyExternalAuthSnapshotSettings(snap)
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		logger.Printf("DataPlane: config snapshot v%d apply incomplete: %v", snap.Version, err)
		return
	}
	snap.IdPProfiles = nil
	applyConfigSnapshot(snap)
	persistDPLastGoodConfigSnapshot(snapForDisk)
	dpMarkCPPollHealthy()
	c.lastVersion = snap.Version
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
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	var resp json.RawMessage
	err := conn.Invoke(callCtx, method, req, &resp)
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
