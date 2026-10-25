package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
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
	// pendingAddrs is a CP address list whose redial failed (CHAOS-91), held
	// for retryPendingAddresses. Guarded by mu.
	pendingAddrs []string
	// jitter decorrelates this node's retry delays from the rest of the fleet
	// (CHAOS-89). Assigned once by NewDataPlaneClient and never mutated, so the
	// loop goroutines that read it need no synchronisation. A nil value — every
	// struct-literal client in the tests — means "no jitter", which is exactly
	// what a cadence assertion wants: see jitterDelay.
	jitter func(time.Duration) time.Duration
}

// dpBackoffCeiling caps the post-failure retry delay. A DP that cannot reach
// its CP keeps the last-known-good snapshot it is already enforcing, so the
// cost of a longer retry delay is convergence latency, not an outage — and the
// benefit is that N data planes do not hold a struggling control plane down.
const dpBackoffCeiling = 60 * time.Second

// dpFailoverAfterFailures is how many CONSECUTIVE failed config polls must
// accumulate before the client redials a peer CP.
//
// The threshold is re-crossed every dpFailoverAfterFailures failures rather
// than tested once, so a sustained outage probes each configured CP
// periodically (a CP can come back on an address the client is not currently
// pinned to) while the backoff ladder below keeps growing toward the ceiling.
// Testing `failCount < 3` once instead would make EVERY failed poll past the
// third redial, turning a dead CP pair into permanent connection churn.
const dpFailoverAfterFailures = 3

// backoff sleeps for an exponentially increasing, jittered duration after
// consecutive Control Plane failures: 2s, 4s, 8s, … capped at dpBackoffCeiling.
//
// CHAOS-89 — two corrections to the original implementation, both of which the
// empirical ladder disproved rather than inspection:
//
//  1. It no longer increments failCount. It used to, on top of the increment
//     its only caller (pollConfig) had already applied, so the streak advanced
//     by TWO per failed poll: the ladder a fleet actually ran was 4s, 16s, 60s
//     — the documented 60s ceiling reached on the THIRD failed poll instead of
//     the sixth, and the "3 consecutive failures" failover gate tripping on the
//     SECOND. The streak now has exactly one writer.
//
//  2. The delay is jittered. A control plane is a shared dependency, and the
//     event that makes every data plane start backing off is usually the single
//     event of the CP going away — a restart, a rolling upgrade, a node reboot.
//     An unjittered ladder is deterministic in the failure count alone, so a
//     fleet that failed together retries together forever and then reconnects
//     in one instant when the CP returns, each node asking for a config
//     snapshot that can legitimately reach tens of MiB (see the deadline model
//     below). Jitter is applied PER ATTEMPT, not drawn once per node as
//     internal/feedsched does: feedsched spreads a steady-state cadence, where
//     a stable offset is both sufficient and reproducible, whereas this spreads
//     a thundering herd triggered by one shared instant, and two nodes that
//     happened to draw neighbouring stable offsets would stay in phase through
//     exactly the outage the jitter exists for.
func (c *DataPlaneClient) backoff(ctx context.Context) {
	delay := c.jitterDelay(controlPlaneBackoffDelay(c.failCount))
	logger.Printf("DataPlane: backing off %s (failure #%d)", delay, c.failCount)
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// controlPlaneBackoffDelay is the un-jittered retry ladder for a given
// consecutive-failure streak: 2s, 4s, 8s, 16s, 32s, then dpBackoffCeiling from
// the 6th failure on. Pure, so the contract is asserted directly instead of
// being inferred from a log line or a stopwatch: backoff() observes its delay
// only through a select that a cancelled context short-circuits (CodeRabbit,
// PR #1658).
//
// A streak of 0 cannot happen on this path (the caller increments before
// backing off) but is clamped to the first rung rather than returning 1s, so a
// future caller cannot accidentally shorten the documented 2s floor.
func controlPlaneBackoffDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := time.Duration(1<<min(failures, 6)) * time.Second // 2s…64s
	if d > dpBackoffCeiling {
		return dpBackoffCeiling
	}
	return d
}

// dpRetryJitterFrac is the ±fraction applied to every retry delay, matching
// internal/feedsched's DefaultJitterFrac so the two cadence planes are tuned
// alike. It is deliberately modest: the point is to decorrelate a fleet, not to
// reshape the ladder, and a wide spread on the 2s rung would start eating into
// the convergence latency the ladder exists to bound.
const dpRetryJitterFrac = 0.10

// dpRetryJitter returns the per-attempt jitter function installed on every
// production client. See backoff for why this is drawn per attempt rather than
// once per node as internal/feedsched.StableJitter does.
func dpRetryJitter(frac float64) func(time.Duration) time.Duration {
	if frac <= 0 {
		return func(d time.Duration) time.Duration { return d }
	}
	return func(d time.Duration) time.Duration {
		if d <= 0 {
			return d
		}
		off := (rand.Float64()*2 - 1) * frac // #nosec G404 -- fleet spread, not crypto
		j := d + time.Duration(float64(d)*off)
		if j <= 0 {
			return d
		}
		return j
	}
}

// jitterDelay applies the client's fleet-decorrelation jitter, falling back to
// the exact delay when no jitter function is installed. The fallback is load
// bearing for the tests: a struct-literal DataPlaneClient asserts the ladder
// itself, and a randomised delay would make that assertion a range check.
func (c *DataPlaneClient) jitterDelay(d time.Duration) time.Duration {
	if c.jitter == nil {
		return d
	}
	return c.jitter(d)
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
		jitter:   dpRetryJitter(dpRetryJitterFrac),
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
//
// CHAOS-89: a successful redial deliberately does NOT clear failCount. It used
// to, and that single assignment defeated the entire backoff ladder on every
// HA deployment: a reachable-but-not-serving CP pair (overloaded, fenced out,
// or timing out an oversized snapshot) answers the TCP/TLS dial while failing
// GetConfig, so each failover reset the streak to zero, the streak re-crossed
// the threshold two polls later, and the client flapped between CPs every few
// seconds FOREVER — never reaching even the second rung, let alone the 60s
// ceiling. Connectivity to a CP is not evidence that the CP is serving config;
// only a successful poll is, and that is what resetBackoff marks.
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
		return true
	}
	return false
}

// dpStartupStaggerMax caps the one-time phase offset applied before each
// CP-facing ticker starts (CHAOS-89).
//
// Five seconds is chosen against the ONE deadline a stagger can actually
// endanger: heartbeatTimeout (enrollment.go) marks a node disconnected after
// 90s of silence, and the heartbeat rides metricsLoop at 2× the 30s poll
// interval, so the slack is 30s. A ≤5s offset spends at most a sixth of that
// and cannot, on its own or combined with one slow round, make a healthy node
// look disconnected — while still converting a fleet-wide instantaneous burst
// into a smooth rate.
const dpStartupStaggerMax = 5 * time.Second

// staggerLoopStart waits a one-time random phase offset before a CP-facing
// ticker starts, and reports false when ctx was cancelled during the wait (the
// caller must then run its own teardown and return).
//
// Why a phase offset and not per-tick jitter: time.Ticker's period is fixed
// from the moment it is created, so the fleet's spread is decided entirely by
// WHEN each node's ticker starts. Offsetting the start therefore breaks
// lockstep permanently, for the whole process lifetime, at the cost of one
// sub-interval delay and with every existing cadence semantic — including
// Ticker's tick-coalescing when a round runs long — left exactly as it was.
// Rewriting the five loops onto resettable timers would spread the fleet no
// better and would change that coalescing behaviour as a side effect.
//
// The offset is drawn PER LOOP rather than once per node, so the five loops of
// a single data plane also stop firing as one burst against the CP.
func staggerLoopStart(ctx context.Context, interval time.Duration) bool {
	d := dpStaggerDelay(interval)
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// dpStaggerDelay is the phase-offset source. It exists as a variable only so a
// test can install a KNOWN offset: the ordering contract "the cold-start poll is
// never staggered" cannot otherwise be asserted, because a real offset is drawn
// from [0, 5s) and a test that merely waits 5s for the first poll passes whether
// the fetch runs before the wait or after it (CodeRabbit review of PR #1618).
// Same test-seam precedent as callForTest above and the logger global.
//
// Production never reassigns it; a test that does must restore it only after
// joining the loop goroutine it affected.
var dpStaggerDelay = dpStartupStagger

// dpStartupStagger draws the phase offset: uniform over [0, interval) and
// never more than dpStartupStaggerMax, so a sub-second loop is staggered
// within its own period instead of being delayed past it.
func dpStartupStagger(interval time.Duration) time.Duration {
	span := min(interval, dpStartupStaggerMax)
	if span <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(span))) // #nosec G404 -- fleet spread, not crypto
}

// Run starts background loops for config sync, metrics, and cluster gossip.
func (c *DataPlaneClient) Run(ctx context.Context, pollInterval time.Duration) {
	go c.pollLoop(ctx, pollInterval)
	go c.metricsLoop(ctx, pollInterval*2)
	go c.rateLimitGossipLoop(ctx, 5*time.Second, rl)
	go c.revocationSyncLoop(ctx, 3*time.Second)
	go c.auditPushLoop(ctx, 10*time.Second)
}

func (c *DataPlaneClient) pollLoop(ctx context.Context, interval time.Duration) {
	// Fetch immediately on start — deliberately NOT staggered. A node with no
	// last-known-good snapshot enforces nothing until this lands, so delaying
	// it to smooth a one-time boot burst would trade a security property for
	// load. The stagger below spreads every SUBSEQUENT poll, which is the
	// sustained herd; the cold-start burst is recorded as residual risk.
	c.fetchAndApply(ctx)
	if !staggerLoopStart(ctx, interval) {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
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
		// Only attempt failover every dpFailoverAfterFailures consecutive
		// failures, and only with a peer to fail over to; otherwise back off
		// and retry the same CP next tick. The modulo (rather than `<`) is what
		// keeps a sustained outage probing both CPs periodically WITHOUT
		// redialling on every single failed poll — see dpFailoverAfterFailures.
		if c.failCount%dpFailoverAfterFailures != 0 || len(c.addrs) <= 1 {
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
			// Not charged separately: the streak counts failed POLLS, and this
			// retry is part of the poll that already charged it above.
			// failover() keeps the streak (CHAOS-89), so the gate re-crosses
			// after dpFailoverAfterFailures more failed polls, whichever CP they
			// hit. (#1658 charged the retry while failover() still zeroed the
			// streak; with the reset gone, that extra charge would advance the
			// streak twice per failover poll and fail over every two polls.)
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
	// CHAOS-91: a CP address list deferred by a failed redial is retried at the
	// top of EVERY cycle — before the delta fast path, which returns early on
	// every "unchanged" reply and would otherwise starve the retry (Codex P2 on
	// #1618) — so it is not lost once lastVersion has advanced past the
	// snapshot that carried it.
	c.retryPendingAddresses()
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
	// re-fence identically. The fence reads every epoch the reply carries, not
	// only its own label (deltaReplyEpochs).
	if !dpObserveEpoch("config delta", deltaReplyEpochs(reply, 0).highest) {
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
	if !fenceDeltaTarget(deltaReplyEpochs(reply, remainder.Epoch)) {
		return true // still before any mutation
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

// deltaEpochs is what a delta reply says about fencing epochs: the highest it
// carries anywhere (its own label, every delta entry's, the remainder's) and
// the lowest stamp on its TARGET data (the remainder's — the target
// snapshot's stamp — and the last delta's, which produced the target). The
// reply's own label is not target data: a stale label on data committed under
// a higher epoch is ratcheted past, not trusted.
type deltaEpochs struct{ highest, target int64 }

// deltaReplyEpochs reads every epoch a delta reply carries (Codex P1
// 4302926140 on #1645). A CP that labelled the reply from live HA state could
// send version N+1, committed with a new grant's epoch E2, labelled with the
// old E1; checking the label alone, the Data Plane applied N+1 without
// ratcheting to E2 and could later accept a higher-version E1 snapshot from a
// fenced Control Plane. remainderEpoch: 0 until the remainder is parsed.
func deltaReplyEpochs(reply getConfigDeltaReply, remainderEpoch int64) deltaEpochs {
	e := deltaEpochs{highest: max(reply.Epoch, remainderEpoch), target: remainderEpoch}
	for i := range reply.Deltas {
		e.highest = max(e.highest, reply.Deltas[i].Epoch)
	}
	if n := len(reply.Deltas); n > 0 {
		e.target = min(e.target, reply.Deltas[n-1].Epoch)
	}
	return e
}

// fenceDeltaTarget is the delta fence once the remainder is parsed: ratchet to
// the highest epoch the reply carries, then require its target to stand at
// that ratchet. Older chain entries may carry older epochs (a chain can span a
// failover), but a target labelled below an epoch the same reply carries is a
// fenced Control Plane's write after a higher-epoch commit (S3's zombie
// shape): rejected. Two ordinary dpObserveEpoch calls, so its ratchet contract
// (CAS forward, persisted, 0 accepted only while unseeded) is unchanged.
func fenceDeltaTarget(e deltaEpochs) bool {
	return dpObserveEpoch("config delta", e.highest) && dpObserveEpoch("config delta target", e.target)
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
		// CHAOS-61: report this node's own DP->CP audit-queue drop count so the
		// CP can aggregate it (auditClusterPushDropsTotal, controlplane.go)
		// instead of the fact only being visible on this DP's own /healthz.
		AuditClusterPushDrops: auditPendingDrops(),
		AuditDropsReported:    true,
	}
}

func (c *DataPlaneClient) metricsLoop(ctx context.Context, interval time.Duration) {
	if !staggerLoopStart(ctx, interval) {
		return
	}
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
func (c *DataPlaneClient) rateLimitGossipLoop(ctx context.Context, interval time.Duration, limiter *RateLimiter) {
	// Enable cluster-aware rate limiting now that we're connected to CP. This
	// is local arming, not an RPC, so it stays un-staggered.
	limiter.SetClusterEnabled(true)
	logger.Printf("DataPlane: distributed rate limiting enabled (gossip every %s)", interval)
	// A cancellation during the stagger must still disarm, exactly as the
	// ctx.Done() branch below does.
	if !staggerLoopStart(ctx, interval) {
		limiter.SetClusterEnabled(false)
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			limiter.SetClusterEnabled(false)
			return
		case <-ticker.C:
			// CHAOS-61: evaluate broadcast freshness on EVERY tick, including the
			// ones whose RPC fails — reporting only from the success branch
			// would mean the state is never reported during the outage that
			// causes it.
			//
			// This deliberately does NOT report on a node whose rate limiter is
			// off: ClusterFreshness is un-armed there and returns a
			// not-stale status, because AllowClusterAware short-circuits before
			// consulting a remote count, so there is no enforcement for an
			// expired broadcast to degrade. The first version of this call
			// claimed the opposite in its own comment and pinned every freshness
			// surface at "degraded" on the default posture (limit 0).
			noteClusterRateLimitFreshness(limiter)
			if !limiter.Enabled() {
				continue
			}
			deltas := rateLimitWireDeltas(limiter)
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
			limiter.ApplyRemoteCounts(broadcast.RemoteCounts)
		}
	}
}

// revocationSyncLoop syncs session revocation entries with the CP every few
// seconds, enabling cluster-wide session invalidation on logout.
func (c *DataPlaneClient) revocationSyncLoop(ctx context.Context, interval time.Duration) {
	logger.Printf("DataPlane: distributed session revocation enabled (sync every %s)", interval)
	if !staggerLoopStart(ctx, interval) {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

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
	logger.Printf("DataPlane: centralized audit log enabled (push every %s)", interval)
	if !staggerLoopStart(ctx, interval) {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

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
	c.pendingAddrs = nil // a newer list supersedes any deferred one
	if !c.applyAddressesLocked(addrs) {
		// Deferred, not dropped: fetchAndApply has already persisted this
		// snapshot and will advance lastVersion, so an unchanged CP never
		// re-sends the list. retryPendingAddresses re-applies it before each
		// config poll until the redial succeeds (Codex P2 on #1618).
		c.pendingAddrs = append([]string(nil), addrs...)
	}
}

// retryPendingAddresses re-applies an address list whose redial failed.
// Called at the start of every config poll, so a list deferred by a transient
// dial failure (for example a certificate renewal caught between writing the
// cert and the key) converges within one poll interval of the dial working
// again, instead of waiting for the next config version.
func (c *DataPlaneClient) retryPendingAddresses() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingAddrs == nil {
		return
	}
	addrs := c.pendingAddrs
	c.pendingAddrs = nil
	if !c.applyAddressesLocked(addrs) {
		c.pendingAddrs = addrs
	}
}

// applyAddressesLocked installs addrs as the CP address list and reports
// whether it did. It reports false only when the active address was dropped
// and the redial to the new list failed; the caller decides whether to retry.
// The caller must hold c.mu.
func (c *DataPlaneClient) applyAddressesLocked(addrs []string) bool {
	// Only update if the addresses actually changed.
	if slicesEqual(c.addrs, addrs) {
		return true
	}
	old := c.addrs
	// CHAOS-91 (found while fixing CHAOS-71 address-republish rider): activeIdx is an index INTO
	// c.addrs naming the address c.conn is connected to, so replacing the slice
	// without re-resolving it leaves a stale index. A shrinking list then makes
	// reconnectActive's `c.addrs[c.activeIdx]` panic — its len==0 guard does not
	// cover an index past a non-empty slice — and reconnectActive is the
	// certificate-renewal redial (CHAOS-12), so the crash lands on a path that
	// runs unattended on a healthy node.
	//
	// Reachable before this fix and newly easy to reach: a DP configured with
	// two CP addresses sits at activeIdx=1 after one failover, and an HA
	// promotion published a ONE-element list (CHAOS-71 address-republish rider), which is exactly the
	// shrink that panics.
	//
	// Re-resolve by ADDRESS, not by clamping the index: clamping would silently
	// re-point activeIdx at a different CP than the one c.conn actually holds.
	active := ""
	if c.activeIdx >= 0 && c.activeIdx < len(old) {
		active = old[c.activeIdx]
	}
	nextIdx, activeListed := 0, false
	for i := range addrs {
		if addrs[i] == active {
			nextIdx, activeListed = i, true
			break
		}
	}

	// The active address is no longer a member, so REDIAL (CodeRabbit review of
	// PR #1618). Re-pointing activeIdx alone is not enough and the first version
	// of this fix got that wrong: `call` invokes over c.conn, not over
	// c.addrs[c.activeIdx], so the index and the connection are independent, and
	// nothing else redials on a list change — reconnectActive runs only for a
	// certificate renewal, and failover only off a failure streak.
	//
	// Leaving c.conn alone is therefore not merely untidy. A de-listed CP that is
	// still RESPONSIVE — the ordinary shape right after an HA promotion, where
	// the old leader is up but no longer authoritative — keeps answering this
	// node's polls, so every poll SUCCEEDS, resetBackoff clears the streak, the
	// failover gate is never reached, and the data plane applies a demoted CP's
	// configuration indefinitely. With the fencing lease unset (the default until
	// S5 wires it) the snapshot carries epoch 0, so the DP-side ratchet does not
	// reject it either.
	//
	// A failed redial keeps BOTH the old list and the old connection, rather than
	// adopting a list this node cannot reach; the caller holds the new list as
	// pending and retries it before the next poll, so the update is deferred,
	// not lost.
	if !activeListed && c.conn != nil {
		if err := c.connect(addrs[0]); err != nil {
			logger.Printf("DataPlane: CP address list dropped the active address %q but redial to %q failed, keeping the current list and connection and retrying before the next poll: %q",
				sanitizeLog(active), sanitizeLog(addrs[0]), sanitizeLog(err.Error()))
			return false
		}
	}
	c.addrs = addrs
	c.activeIdx = nextIdx
	// Both lists are peer-supplied — addrs arrives verbatim in the CP's config
	// snapshot — so they are untrusted log values under the CWE-117 rule in
	// docs/agent-context/conventions.md: format, then sanitize with the barrier
	// CodeQL recognises, and print with %q. The pre-fix line logged both with a
	// bare %v.
	logger.Printf("DataPlane: CP address list updated: %q -> %q (active %q at index %d)",
		sanitizeLog(fmt.Sprint(old)), sanitizeLog(fmt.Sprint(addrs)), sanitizeLog(active), c.activeIdx)
	return true
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
