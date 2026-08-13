package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/halease"
	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// ── Control Plane High Availability ─────────────────────────────────────────
//
// Active/Passive HA with built-in state replication. No shared filesystem
// required — the leader CP replicates all state (cluster.json, CA cert+key,
// config snapshot) to the standby CP over the existing mTLS gRPC channel.
//
// Flow:
//   1. Admin enables CP from GUI, clicks "Enable HA" → generates HA token
//   2. GUI shows a deploy command for the standby (includes --ha-join URL)
//   3. Admin runs command on Server B → standby syncs state, stands by
//   4. If the leader dies, failover depends on the mode:
//      - LEASE mode (ADR-0005; --ha-etcd-endpoints set): automatic failover is
//        always on and SAFE — the standby promotes only after ACQUIRING the
//        etcd fencing lease (denied while the leader lives), a partitioned
//        leader self-fences to read-only standby, and --ha-auto-failover is
//        ignored. See ha_lease.go (S2), ha_fencing.go (S3), ha_failover.go (S4).
//      - LEGACY mode (no lease): auto-failover is OPT-IN and OFF by default —
//        a 2-node cluster without a witness cannot promote safely on a
//        surviving-leader partition (ADR-0004 / RISK-001). Default (manual):
//        the standby stays read-only until an operator acts.
//   5. DPs automatically failover (--dp-cp-addr supports comma-separated addrs)
//
// Restart behaviour (ADR-0004): on restart a node honours its PERSISTED role —
// a standby re-enters standby (it never silently self-asserts as a second
// leader). A restarted LEADER in lease mode must RE-ACQUIRE the lease
// (acquireLeaseForResume waits out its own previous process's ghost lease);
// denied + a recorded standby address (ADR-0005 S0, learned via HASync) means
// the standby promoted meanwhile, so the node re-enters standby and resyncs
// from it (enterStandbyResync). In legacy mode a restarted leader resumes
// leadership — it has no way to probe its peer — and under auto-failover it
// logs a split-brain-risk warning.
//
// Authentication: standby presents a shared HA token in every HASync RPC.
// The leader verifies it against the stored token.

// HAState tracks the HA status of this Control Plane instance.
type HAState struct {
	mu           sync.RWMutex
	role         string         // "leader", "standby", or "" (HA disabled)
	token        string         // shared HA token for authentication
	peerAddr     string         // address of the other CP
	standbyAddr  string         // leader-side: the standby's advertised address, learned via HASync (ADR-0005 S0 — failback target)
	since        time.Time      // when current role was acquired
	autoFailover bool           // standby self-promotes on leader loss (default OFF — see ADR-0004)
	term         uint64         // leadership epoch — bumped on each promotion (ADR-0004 Slice 1c)
	pc           promoteContext // params captured at StartAsStandby so a manual/planned promote can reuse them
	stopCh       chan struct{}
	wg           sync.WaitGroup // tracks the standby sync + lease keepalive goroutines (Stop joins them)
	stopping     bool           // latched by Stop before signaling: refuses new loop spawns so the join cannot chase freshly-created channels

	// plannedPromotion (leader side) signals the standby, via the next HASync
	// bundle, to perform a COORDINATED promotion — a planned handoff (e.g. a CP
	// rolling update) that must happen even when auto-failover is OFF. Distinct
	// from unplanned auto-failover. (ADR-0004 Slice 1e.)
	plannedPromotion atomic.Bool
	// promoted guards promote() so the expensive onPromote (gRPC server start)
	// runs at most once whether triggered by the sync loop, a manual API call,
	// or a planned handoff.
	promoted atomic.Bool

	// ── Fencing lease (ADR-0005 S2; nil provider = legacy manual mode) ──
	lease            halease.Provider
	leaseCandidateID string
	leaseEpoch       int64         // epoch of our current grant; 0 = not held
	leaseConfirmedAt time.Time     // local time of the last backend-CONFIRMED grant/renew
	leaseValidFor    time.Duration // validity the backend confirmed at leaseConfirmedAt
	leaseStopCh      chan struct{} // keepalive loop stop; nil = not running

	// ── Lease-arbitrated failover (ADR-0005 S4) ──
	resync        haResyncContext // material to re-enter standby after a demotion (cluster loader)
	lastSyncOK    time.Time       // last successful HASync apply (freshness-gate input)
	lastSelfFence time.Time       // last self-fence (re-promotion hysteresis)

	// syncFailCount mirrors standbyLoopState.failCount (standby side) so the
	// consecutive-failure streak toward haStandbyMaxFail is visible outside the
	// loop goroutine — previously an operator had no warning before a standby
	// silently hit the auto-failover/self-fence threshold (see setSyncFailCount).
	syncFailCount int

	// syncPanics counts standby sync ROUNDS contained by the CHAOS-25 guard.
	// A contained round deliberately does NOT advance syncFailCount (see
	// standbyLoop), so without its own counter a standby whose apply path
	// panics every tick would sit at sync_fail_count=0 forever and read as
	// healthy while replication is dead. syncPanicAlerted is the fire-once
	// latch, re-armed by the next successful sync.
	syncPanics       int
	syncPanicAlerted bool
}

// promoteContext holds the parameters StartAsStandby threads into the sync loop,
// captured so PromoteManually / a planned handoff can promote without them.
type promoteContext struct {
	grpcAddr, certFile, keyFile, caFile string
	onPromote                           func() error
	set                                 bool
}

var globalHA = &HAState{}

// HAStatus returns a snapshot of the current HA state for API/UI consumption.
type HAStatus struct {
	Enabled        bool   `json:"enabled"`
	Role           string `json:"role"`                      // "leader", "standby", or ""
	Since          string `json:"since,omitempty"`           // RFC3339
	PeerAddr       string `json:"peer_addr,omitempty"`       // other CP address
	AutoFailover   bool   `json:"auto_failover"`             // standby self-promotes on leader loss (ADR-0004)
	Term           uint64 `json:"term"`                      // leadership epoch (ADR-0004 Slice 1c)
	StandbyAddr    string `json:"standby_addr,omitempty"`    // leader-side failback target (ADR-0005 S0)
	SyncFailCount  int    `json:"sync_fail_count,omitempty"` // standby-side: consecutive HASync failures since last success
	LastSyncOK     string `json:"last_sync_ok,omitempty"`    // standby-side: RFC3339 of the last successful HASync apply
	SyncPanics     int    `json:"sync_panics,omitempty"`     // standby-side: sync rounds contained by the panic guard (CHAOS-25)
	PlannedHandoff bool   `json:"planned_handoff"`           // leader-side: coordinated handoff armed (ADR-0004 Slice 1e) — the next HASync instructs the standby to promote
}

func (h *HAState) Status() HAStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := HAStatus{
		Enabled:      h.role != "",
		Role:         h.role,
		PeerAddr:     h.peerAddr,
		AutoFailover: h.autoFailover,
		Term:         h.term,
		StandbyAddr:  h.standbyAddr,
	}
	if !h.since.IsZero() {
		s.Since = h.since.Format(time.RFC3339)
	}
	// Leader-only: plannedPromotion only has meaning on the leader (it's what
	// the leader stamps into the next HASync bundle); a standby never arms it.
	if h.role == "leader" {
		s.PlannedHandoff = h.plannedPromotion.Load()
	}
	// Standby-only: on auto-promotion setFail(N) can run just before promote()
	// flips h.role to "leader" (nothing else resets syncFailCount), so gate
	// here rather than trust callers not to leak a stale failure streak onto
	// a freshly-promoted leader (e.g. via apiClusterStatus, which embeds this
	// struct verbatim).
	if h.role == "standby" {
		s.SyncFailCount = h.syncFailCount
		s.SyncPanics = h.syncPanics
		if !h.lastSyncOK.IsZero() {
			s.LastSyncOK = h.lastSyncOK.Format(time.RFC3339)
		}
	}
	return s
}

// setSyncFailCount records the standby sync loop's current consecutive-failure
// streak (see standbyLoopState.failCount) so it can be read back through
// Status()/apiClusterHA. Called from the standby loop goroutine on every
// success/failure transition; safe to call from any goroutine.
func (h *HAState) setSyncFailCount(n int) {
	h.mu.Lock()
	h.syncFailCount = n
	h.mu.Unlock()
}

// snapshotConfigLocked builds the persisted haConfig from the live state.
// Caller must hold h.mu. Centralises the field→config mapping so RecordStandbyAddr
// (and future callers) persist a canonical record.
func (h *HAState) snapshotConfigLocked() *haConfig {
	return &haConfig{
		Enabled:      h.role != "",
		Token:        h.token,
		PeerAddr:     h.peerAddr,
		Role:         h.role,
		AutoFailover: h.autoFailover,
		Term:         h.term,
		StandbyAddr:  h.standbyAddr,
	}
}

// RecordStandbyAddr (leader side) records the standby's advertised address,
// learned from the HASync request (ADR-0005 S0). This is the failback target:
// when this leader later loses the lease and demotes, it must resync FROM the
// standby — but the topology otherwise never tells the leader the standby's
// address (ADR-0004 asymmetry). Persisted (throttled to changes) so it survives
// a leader restart. No-op unless we are the leader and the address changed.
func (h *HAState) RecordStandbyAddr(addr string) {
	if addr == "" {
		return
	}
	h.mu.Lock()
	if h.role != "leader" || h.standbyAddr == addr {
		h.mu.Unlock()
		return
	}
	h.standbyAddr = addr
	cfg := h.snapshotConfigLocked()
	h.mu.Unlock()
	_ = saveHAConfig(cfg)
	logger.Printf("HA: recorded standby address %q (failback target, ADR-0005 S0)", sanitizeLog(addr))
}

// StandbyAddr returns the leader's recorded standby address (failback target),
// or "" if not yet learned.
func (h *HAState) StandbyAddr() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.standbyAddr
}

// advertiseAddr returns this node's own gRPC address (captured at StartAsStandby)
// so the standby can advertise it to the leader in each HASync request.
func (h *HAState) advertiseAddr() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pc.grpcAddr
}

// autoFailoverEnabled reports whether this node may self-promote on leader loss.
// Default OFF: 2-node active/passive has no witness, so unattended auto-promotion
// is unsafe (split-brain). See ADR-0004 / RISK-001.
func (h *HAState) autoFailoverEnabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.autoFailover
}

// IsLeader returns true if this CP is the HA leader.
func (h *HAState) IsLeader() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.role == "leader"
}

// VerifyToken checks if the provided token matches the stored HA token.
func (h *HAState) VerifyToken(token string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.token != "" && subtle.ConstantTimeCompare([]byte(h.token), []byte(token)) == 1
}

// ── Leader Mode ─────────────────────────────────────────────────────────────

// EnableAsLeader marks this node as the HA leader and generates an HA token.
// autoFailover records whether the standby is permitted to self-promote on
// leader loss (default OFF — see ADR-0004); the leader stores the preference so
// the standby deploy command carries it. Returns the generated token for
// inclusion in the standby deploy command.
func (h *HAState) EnableAsLeader(peerAddr string, autoFailover bool) (string, error) {
	// ADR-0005 S2: even HA genesis must hold the fence when a lease backend
	// is configured — otherwise the first leader never acquires, never
	// keepalives, and has no write authority. No-op in legacy mode.
	if !h.acquireLeaseForLeadership("ha enable") {
		return "", fmt.Errorf("fencing lease not acquired — cannot enable HA leadership (see logs)")
	}
	h.mu.Lock()
	h.role = "leader"
	h.peerAddr = peerAddr
	h.since = time.Now()
	h.autoFailover = autoFailover
	if h.lease != nil {
		h.term = termFromEpoch(h.leaseEpoch) // term collapses into the fencing epoch (ADR-0005 Finding 6)
	} else {
		h.term = 1 // first leadership epoch (ADR-0004 Slice 1c)
	}
	h.token = generateHAToken()
	h.stopCh = make(chan struct{})
	token, term := h.token, h.term

	// Persist HA config so leader restarts know HA is enabled.
	_ = saveHAConfig(&haConfig{
		Enabled:      true,
		Token:        h.token,
		PeerAddr:     peerAddr,
		Role:         "leader",
		AutoFailover: autoFailover,
		Term:         h.term,
	})
	h.mu.Unlock()
	h.startLeaseKeepalive()

	logPeerAddr := sanitizeLog(peerAddr)
	logger.Printf("HA: enabled as leader (peer=%q, auto_failover=%v, term=%d)", logPeerAddr, autoFailover, term)
	return token, nil
}

// ResumeAsLeader restores leader state from a persisted haConfig on restart
// WITHOUT bumping the term — it is the same leadership epoch continuing, not a
// new promotion. Replaces the previous EnableAsLeader-then-patch-token dance in
// main.go so the persisted term/token survive a restart intact (ADR-0004).
func (h *HAState) ResumeAsLeader(cfg *haConfig) {
	// ADR-0005 S2: a restarting leader's old lease expired during the
	// restart, so it must re-acquire. Granted ⇒ normal leadership (epoch,
	// keepalive). Denied ⇒ S4: if the ex-standby's address was recorded
	// (S0) and the loader provided resync material, re-enter STANDBY
	// against it instead of asserting an unfenced leader role; otherwise
	// fall back to the S2 stance (role kept, NO write authority, CRITICAL
	// alert).
	leaseGranted := h.acquireLeaseForResume()
	if !leaseGranted && h.leaseConfigured() {
		h.mu.Lock()
		h.token = cfg.Token
		h.standbyAddr = cfg.StandbyAddr
		h.autoFailover = cfg.AutoFailover
		h.mu.Unlock()
		if h.enterStandbyResync("unfenced leader resume") {
			return
		}
	}
	h.mu.Lock()
	h.role = "leader"
	h.peerAddr = cfg.PeerAddr
	h.token = cfg.Token
	h.autoFailover = cfg.AutoFailover
	h.term = cfg.Term
	if h.lease != nil && leaseGranted {
		h.term = termFromEpoch(h.leaseEpoch) // term collapses into the fencing epoch (ADR-0005 Finding 6)
	}
	h.standbyAddr = cfg.StandbyAddr // restore failback target across restart (ADR-0005 S0)
	h.since = time.Now()
	h.stopCh = make(chan struct{})
	leaseConfigured := h.lease != nil
	h.mu.Unlock()
	if leaseConfigured && !leaseGranted {
		logger.Printf("HA: CRITICAL — resumed leader role WITHOUT the fencing lease; write authority is OFF until an operator acts (ADR-0005 S2)")
		go alerts.Fire("ha_resume_unfenced", alerts.Payload{
			Event:  "ha_resume_unfenced",
			Detail: "leader restarted but could not acquire the fencing lease; serving read-only (no write authority)",
			Source: "ha",
		})
	}
	h.startLeaseKeepalive()
	// Re-persist the SAME values (idempotent; keeps the file canonical).
	_ = saveHAConfig(cfg)
}

// ── Standby Mode ────────────────────────────────────────────────────────────

// StartAsStandby connects to the leader CP and begins state replication.
// When the leader becomes unreachable (3 consecutive failures), the standby
// promotes itself to leader by calling onPromote.
func (h *HAState) StartAsStandby(ctx context.Context, leaderAddr, token string,
	grpcAddr, certFile, keyFile, caFile string, autoFailover bool,
	onPromote func() error) {
	h.mu.Lock()
	if h.stopping {
		// Stop() is joining our goroutines — spawning a new sync loop here
		// would hand it a channel the in-flight stopLoops already missed.
		h.mu.Unlock()
		logger.Printf("HA: stop in progress — not (re-)entering standby against %s", sanitizeLog(leaderAddr))
		return
	}
	h.role = "standby"
	h.peerAddr = leaderAddr
	h.token = token
	h.since = time.Now()
	h.autoFailover = autoFailover
	h.syncFailCount = 0 // fresh loop — don't carry over a stale streak from a prior standby stint
	h.pc = promoteContext{grpcAddr: grpcAddr, certFile: certFile, keyFile: keyFile, caFile: caFile, onPromote: onPromote, set: true}
	h.promoted.Store(false)
	stopCh := make(chan struct{})
	h.stopCh = stopCh
	// wg.Add INSIDE the lock: atomic with the stopping check above. An Add
	// after Stop()'s Wait began (counter possibly 0) is documented WaitGroup
	// misuse — the latch is set under this same mutex before Wait starts, so
	// passing the check guarantees this Add happens-before it.
	h.wg.Add(1)
	h.mu.Unlock()

	// Persist HA config so standby restarts know HA is enabled.
	_ = saveHAConfig(&haConfig{
		Enabled:      true,
		Token:        token,
		PeerAddr:     leaderAddr,
		Role:         "standby",
		AutoFailover: autoFailover,
	})

	logger.Printf("HA: starting as standby (leader=%q, auto_failover=%v)", sanitizeLog(leaderAddr), autoFailover)

	go func() {
		defer h.wg.Done() // Add is in the locked section above
		h.standbyLoop(ctx, stopCh, leaderAddr, token, certFile, keyFile, caFile)
	}()
}

// haStandbyMaxFail is the number of consecutive HASync failures (≈ maxFail × 5s)
// that trips the leader-unreachable threshold.
const haStandbyMaxFail = 3

// standbyLoopState carries the standby sync loop's mutable state so the per-tick
// logic lives in small methods (keeps standbyLoop's cognitive complexity low).
type standbyLoopState struct {
	h                         *HAState
	ctx                       context.Context
	leaderAddr, token         string
	certFile, keyFile, caFile string
	client                    *DataPlaneClient
	failCount                 int
	manualWarned              bool // warn-once latch for the auto-failover-disabled path

	// syncFn overrides the leader-sync call. nil ⇒ the production path
	// (h.syncFromLeader). It exists so the CHAOS-25 fault-injection tests can
	// make a round panic without standing up a gRPC leader; production never
	// sets it.
	syncFn func() bool
}

// sync performs one leader-sync attempt through the (optionally injected) seam.
func (s *standbyLoopState) sync() bool {
	if s.syncFn != nil {
		return s.syncFn()
	}
	return s.h.syncFromLeader(s.ctx, s.client, s.token)
}

// haStandbySyncComponent labels contained standby-sync panics in the crash
// plane (culvert_crash_records_total{component}).
const haStandbySyncComponent = "ha-standby-sync"

// haPromoteComponent labels contained panics raised by the caller-supplied
// onPromote hook (CP gRPC server startup).
const haPromoteComponent = "ha-promote"

// guardedTick runs ONE standby sync round under the CHAOS-25 panic guard and
// reports whether the loop should exit (this node promoted to leader).
//
// Per-ROUND, never per-goroutine — the CHAOS-24 contract (internal/obs/guard.go).
// A `defer recover()` at the top of standbyLoop would let the loop RETURN on a
// panic, and that is the worst outcome available here: the node keeps
// role="standby" and a live process, but it stops replicating AND stops watching
// the leader, so the failover detector is dead. The leader could then die with
// nothing left to notice — HA silently gone, every dashboard green.
//
// The fail-closed decision this guard encodes (the finding inside the finding):
//
//	a panicking round is NOT evidence that the leader is unreachable.
//
// The whole round is guarded, so a panic raised while fetching/applying the
// bundle unwinds BEFORE tick's setFail(failCount+1) — the promotion streak is
// left untouched by design, and this function additionally refuses to report
// `exit` on a panicking round. That ordering is load-bearing, not incidental:
// the bundle is leader-supplied content, so a deterministic apply-path panic
// repeats every 5s tick. Charging those rounds toward haStandbyMaxFail would
// auto-promote a standby whose ONLY problem is its own parser — and in legacy
// (unfenced) mode, with a perfectly healthy leader still serving, that is a
// remotely-triggerable SPLIT BRAIN. It would have made containment strictly
// worse than the crash it replaced: today the process dies and restarts into a
// crash-loop, which is loud, single-writer, and safe.
//
// A panic raised later — inside promote() itself, after a genuine sync failure
// already advanced the streak — keeps that (correct) increment and simply
// leaves the node a standby, retryable on the next tick.
//
// The cost of not counting is that a permanently panicking standby never
// escalates on its own, so the containment is reported instead: crash record +
// culvert_crash_records_total{component="ha-standby-sync"}, the sync_panics
// status field, and a fire-once ha_sync_panic alert (notePanicRound).
func (s *standbyLoopState) guardedTick() (exit bool) {
	if runGuarded(haStandbySyncComponent, func() { exit = s.tick() }) {
		s.h.notePanicRound(s.leaderAddr)
		return false
	}
	return exit
}

// notePanicRound records a CONTAINED standby-sync panic. Because the panicking
// round is deliberately kept out of the failure streak (see guardedTick), this
// counter + alert are the ONLY operator-facing signal that replication has
// stalled — without them the containment would trade a loud crash for a silent
// one, which is the failure class the guard exists to remove.
func (h *HAState) notePanicRound(leaderAddr string) {
	h.mu.Lock()
	h.syncPanics++
	n := h.syncPanics
	first := !h.syncPanicAlerted
	h.syncPanicAlerted = true
	h.mu.Unlock()

	logger.Printf("HA: standby sync round panicked and was CONTAINED (contained_rounds=%d, leader=%q) — "+
		"state replication from the leader is stalled. The failure streak is deliberately NOT advanced, "+
		"so this node will not auto-promote on its own fault (that would risk split brain against a "+
		"healthy leader). Manual promotion remains available if the leader is genuinely down.",
		n, sanitizeLog(leaderAddr))

	if first {
		go alerts.Fire("ha_sync_panic", alerts.Payload{
			Event:  "ha_sync_panic",
			Host:   leaderAddr,
			Detail: "standby HA sync round panicked and was contained; replication is stalled and automatic failover is suppressed for this node (manual promotion available)",
			Source: "ha",
		})
	}
}

// clearSyncPanicAlert re-arms the fire-once ha_sync_panic latch after a healthy
// round, so a LATER stall alerts again instead of being swallowed by the first
// occurrence. The cumulative syncPanics counter is never reset — it is the
// durable "this node has been here before" signal for the operator.
func (h *HAState) clearSyncPanicAlert() {
	h.mu.Lock()
	h.syncPanicAlerted = false
	h.mu.Unlock()
}

// standbyLoop receives ITS OWN stop channel from StartAsStandby rather than
// re-reading h.stopCh: promote() and Stop() close-then-nil the field, so a
// loop goroutine scheduled after such a close would capture nil and select
// on it forever — deadlocking the Stop() join. The passed channel is the one
// created for this loop instance; if it was already closed before the
// goroutine ran, the select fires immediately and the loop exits.
func (h *HAState) standbyLoop(ctx context.Context, stopCh chan struct{}, leaderAddr, token string,
	certFile, keyFile, caFile string) {
	// The sync RPCs can block (gRPC wait-for-ready against an unreachable
	// leader) far longer than a tick; the select below only observes stopCh
	// BETWEEN ticks. Tie a derived context to stopCh so stopLoops interrupts
	// in-flight work too — Stop() joins this goroutine and must not wait out
	// a dial. The watcher exits via the deferred cancel when the loop returns.
	loopCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-stopCh:
			cancel()
		case <-loopCtx.Done():
		}
	}()

	s := &standbyLoopState{
		h: h, ctx: loopCtx, leaderAddr: leaderAddr, token: token,
		certFile: certFile, keyFile: keyFile, caFile: caFile,
	}
	// Connect to leader using the same gRPC client infrastructure as DPs.
	if c, cerr := NewDataPlaneClient("ha-standby", leaderAddr, certFile, keyFile, caFile); cerr != nil {
		logger.Printf("HA: failed to connect to leader: %v — will retry", cerr)
	} else {
		s.client = c
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	s.guardedSyncOnce() // try immediately

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			if s.guardedTick() {
				return
			}
		}
	}
}

// onMaxFail handles the leader-unreachable threshold. Returns true when the loop
// should EXIT (this node promoted to leader); false to keep the standby
// read-only and retrying.
//
// Lease mode (ADR-0005 S4): promotion is arbitrated by the FENCE, not the
// --ha-auto-failover flag — Acquire is denied while the leader lives, so the
// split-brain that made the flag opt-in cannot happen; freshness + hysteresis
// additionally gate the automatic path (see leaseAutoPromote).
//
// Legacy mode (ADR-0004, unchanged): auto-failover only when opted in;
// otherwise warn once and stay read-only until an operator acts.
func (s *standbyLoopState) onMaxFail() bool {
	if s.h.leaseConfigured() {
		return s.h.leaseAutoPromote()
	}
	if s.h.autoFailoverEnabled() {
		s.h.promote("leader unreachable")
		// Report whether promotion ACTUALLY happened, mirroring the lease path
		// above. promote() is not infallible: onPromote can return an error, or
		// (CHAOS-25) panic and be contained — both reset the once-guard and
		// leave this node a standby. Returning an unconditional true there told
		// standbyLoop to exit, permanently ending BOTH replication and leader
		// monitoring on a node that never became a leader — the silent-stall
		// outcome the per-round guard exists to prevent, reached one level up.
		// Returning IsLeader() keeps the loop ticking so the next round retries
		// the promotion, exactly as lease mode already does.
		return s.h.IsLeader()
	}
	if !s.manualWarned {
		s.h.warnManualFailoverRequired(s.leaderAddr)
		s.manualWarned = true
	}
	return false
}

// setFail updates the loop-local failure streak and mirrors it onto HAState
// so it's visible outside the loop goroutine (apiClusterHA / admin UI).
func (s *standbyLoopState) setFail(n int) {
	s.failCount = n
	s.h.setSyncFailCount(n)
}

// syncOnce performs a single sync attempt without reconnecting (the immediate
// try at loop start), updating failCount.
func (s *standbyLoopState) syncOnce() {
	if s.client == nil {
		s.setFail(s.failCount + 1)
		return
	}
	if s.sync() {
		s.setFail(0)
		s.manualWarned = false
		s.h.clearSyncPanicAlert()
	} else {
		s.setFail(s.failCount + 1)
	}
}

// guardedSyncOnce is guardedTick's counterpart for the immediate try at loop
// start. The very first bundle a standby applies is the most likely to panic
// (it is the largest and the only one applied against a cold local state), and
// an unguarded panic there would kill the process during startup — a crash-loop
// that never reaches the retry the loop was built to provide.
func (s *standbyLoopState) guardedSyncOnce() {
	if runGuarded(haStandbySyncComponent, s.syncOnce) {
		s.h.notePanicRound(s.leaderAddr)
	}
}

// tick runs one loop iteration: reconnect if needed, then sync. Returns true
// when the loop should exit (this node was promoted to leader).
func (s *standbyLoopState) tick() bool {
	if s.client == nil {
		c, err := NewDataPlaneClient("ha-standby", s.leaderAddr, s.certFile, s.keyFile, s.caFile)
		if err != nil {
			s.setFail(s.failCount + 1)
			logger.Printf("HA: reconnect to leader failed (%d/%d): %v", s.failCount, haStandbyMaxFail, err)
			return s.failCount >= haStandbyMaxFail && s.onMaxFail()
		}
		s.client = c
	}
	if s.sync() {
		s.setFail(0)
		s.manualWarned = false // leader recovered — re-arm the warning
		s.h.clearSyncPanicAlert()
		return false
	}
	if s.ctx.Err() != nil {
		// The loop is being stopped (stopCh watcher cancelled the context) —
		// the aborted RPC is shutdown, NOT evidence of a dead leader. Counting
		// it could manufacture the third failure and trip onMaxFail into a
		// promotion (role flip + lease grab) on a node that is going away.
		return true
	}
	s.setFail(s.failCount + 1)
	logger.Printf("HA: sync failed (%d/%d)", s.failCount, haStandbyMaxFail)
	return s.failCount >= haStandbyMaxFail && s.onMaxFail()
}

// warnManualFailoverRequired logs and alerts that the leader is unreachable
// while automatic failover is disabled, so this standby is intentionally
// staying read-only. The operator must promote it (admin UI) or restart it as
// leader. See ADR-0004 / RISK-001.
func (h *HAState) warnManualFailoverRequired(leaderAddr string) {
	logger.Printf("HA: leader %s unreachable and automatic failover is DISABLED — staying standby (read-only). "+
		"Manual failover required: promote via the admin UI or restart this node as leader (ADR-0004/RISK-001).",
		sanitizeLog(leaderAddr))
	go alerts.Fire("ha_manual_failover_required", alerts.Payload{
		Event:  "ha_manual_failover_required",
		Host:   leaderAddr,
		Detail: "leader unreachable; automatic failover disabled; standby staying read-only pending manual action",
		Source: "ha",
	})
}

// syncFromLeader calls HASync on the leader and applies the state bundle.
func (h *HAState) syncFromLeader(ctx context.Context, client *DataPlaneClient, token string) bool {
	// ADR-0005 S0: advertise this standby's own address so the leader can record
	// it as the failback target (the topology otherwise never tells the leader).
	reqBytes, _ := json.Marshal(map[string]string{"token": token, "standby_addr": h.advertiseAddr()})
	raw, err := client.call(ctx, methodHASync, json.RawMessage(reqBytes))
	if err != nil {
		logger.Printf("HA: HASync RPC error: %v", err)
		return false
	}
	// Record the HA bundle size so the NEXT HASync poll's deadline scales with
	// it. An HA-only standby never runs fetchAndApply (the GetConfig path), so
	// without this its HASync deadline would stay at the 15s base and a large
	// bundle (2M-host config) over a slow WAN would time out every sync and
	// never mark the standby healthy (P1, Codex #841).
	dpLastFullSnapshotBytes.Store(int64(len(raw)))

	var bundle HAStateBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		logger.Printf("HA: parse state bundle error: %v", err)
		return false
	}
	// ADR-0005 S3 (Finding 7): PULLER-side fence — verify the bundle's
	// epoch against our own lease backend BEFORE any import. A zombie
	// leader serving stale state must not reach ImportFullState.
	if !h.verifyBundleEpoch(bundle.Epoch) {
		return false
	}
	ok := applyHABundle(&bundle, token)
	if ok {
		h.markSyncOK() // ADR-0005 S4: freshness-gate input
		// Seed the standby's epoch from the leader's term (ADR-0004 Slice 1c/1e,
		// Codex P2): without this a standby starts at term 0, so its first
		// promotion reports term 1 — identical to the original leader's term 1,
		// and the /healthz split-brain signal can't tell which side promoted
		// later. Carrying the leader term means a promotion yields leaderTerm+1,
		// strictly greater, so the post-promotion epoch is monotonic.
		h.seedTermFromLeader(bundle.LeaderTerm)
	}
	// Coordinated planned handoff (ADR-0004 Slice 1e): the leader sets
	// PromoteRequested in the bundle before a deliberate takedown (e.g. a CP
	// rolling update). Promote even when auto-failover is OFF — this is a
	// planned, leader-initiated handoff, not an unattended auto-failover. Only
	// after the state apply succeeded, so the new leader has the latest state.
	if ok && bundle.PromoteRequested && !h.IsLeader() {
		logger.Printf("HA: leader requested a planned promotion — performing coordinated handoff")
		h.promote("planned handoff requested by leader")
	}
	return ok
}

// seedTermFromLeader raises this standby's epoch to the leader's term (never
// lowers it), so a later promotion produces a strictly-higher epoch than the
// leader's last-known term. Standby-only; a no-op once this node is leader.
func (h *HAState) seedTermFromLeader(leaderTerm uint64) {
	h.mu.Lock()
	if h.role != "leader" && leaderTerm > h.term {
		h.term = leaderTerm
	}
	h.mu.Unlock()
}

// applyHABundle applies a decoded HA state bundle on the standby, fail-closed
// and ordered for atomicity. Split out from syncFromLeader so the apply phase is
// testable without a live gRPC client.
//
// CA-3 PR5: the replicated CA is applied FIRST — it is the failure-prone step
// (decrypt + validate + persist) and has no plaintext fallback. Importing the
// cluster state and config snapshot only after the CA succeeds guarantees a CA
// failure does not leave unrelated replicated state partially applied.
func applyHABundle(bundle *HAStateBundle, token string) bool {
	// CHAOS-01 (HA-promotion follow-up): remember the leader's published config
	// version so a later promotion seeds this node's version floor above it.
	// applyConfigSnapshot below applies bundle.Config but does NOT advance the
	// local ConfigStore.version (that counter moves only when THIS node
	// publishes as CP), so without this the promoted CP would reseed only from
	// its own stale/absent floor + wall clock and could re-issue versions the
	// DPs already applied from the old leader. Recorded up front (the epoch
	// fence in syncFromLeader already ran) so a raised floor is guaranteed even
	// if a downstream apply step below fails — a higher floor never harms DPs.
	noteReplicatedLeaderVersion(bundle.Version)

	if bundle.CACertPEM != "" {
		if err := applyReplicatedCA([]byte(bundle.CACertPEM), bundle.CAKeyEncrypted, token); err != nil {
			logger.Printf("HA: apply replicated CA failed (no state imported): %v", err)
			return false
		}
	}

	// Apply cluster state (only after the CA has been validated + applied).
	if err := globalClusterStore.ImportFullState(bundle.ClusterState); err != nil {
		logger.Printf("HA: import cluster state error: %v", err)
		return false
	}

	// Apply config snapshot. FAIL CLOSED: applyConfigSnapshot silently applies
	// nothing on a rejected (over-cap / stale-epoch) config, so ignoring its
	// result would let the standby markSyncOK on stale/empty config and then,
	// once promoted, serve it fleet-wide. A rejected config aborts the resync so
	// freshness/sync-OK is not set on partial state.
	if err := applyConfigSnapshot(bundle.Config); err != nil {
		logger.Printf("HA: replicated config snapshot rejected — resync NOT marked healthy: %v", err)
		return false
	}

	// Seed the local ConfigStore's snapshot from the replicated bundle so that, on
	// a later promotion, the FIRST published delta diffs against the version DPs
	// actually hold (bundle.Version) instead of a nil baseline. Without this the
	// promoted leader's first Update records an "add-everything" delta whose Base
	// pins to a live DP version; harmless (fp-verify → resync) but a spurious full
	// resync. Snapshot only — version/published are still managed by
	// armVersionPersistence at promotion.
	globalConfigStore.seedReplicatedSnapshot(bundle.Config)

	return true
}

// applyReplicatedCA decrypts the HA-token-wrapped cluster CA key and installs it
// on the standby, fail-closed and without partial mutation:
//
//  1. require + decrypt the encrypted key (no plaintext fallback);
//  2. validate the cert+key pair into a throwaway clusterCA — the live
//     globalClusterCA is NOT touched if the pair is bad;
//  3. persist at rest via the CA-3 write path (#319) — encrypted iff
//     CULVERT_CLUSTER_CA_ENCRYPT is set on THIS node (per-node KEK, no shared
//     at-rest KEK, no double-wrap of the in-transit blob);
//  4. only after persistence succeeds, mutate the live CA in memory.
//
// So a decrypt, validation, or persist failure leaves globalClusterCA unchanged.
// No key bytes are logged.
func applyReplicatedCA(certPEM []byte, caKeyEncrypted, token string) error {
	if caKeyEncrypted == "" {
		return fmt.Errorf("encrypted CA key missing from HA bundle (plaintext fallback removed)")
	}
	keyPEM, decErr := haDecryptKey(caKeyEncrypted, token)
	if decErr != nil {
		return fmt.Errorf("decrypt CA key: %w", decErr)
	}
	// (2) Validate the pair WITHOUT mutating the live CA.
	probe := &clusterCA{}
	if err := probe.loadFromPEM(certPEM, keyPEM); err != nil {
		return fmt.Errorf("validate replicated CA: %w", err)
	}
	// (3) Persist before mutating memory. Pass certPEM explicitly so the new
	// cert is written (the live CA still holds the old cert at this point).
	if err := globalClusterCA.persistReplicatedKey(certPEM, keyPEM); err != nil {
		return fmt.Errorf("persist replicated CA key: %w", err)
	}
	// (4) Memory mutation last. loadFromPEM re-validates; we already proved the
	// pair parses, so this is the lowest-risk step.
	if err := globalClusterCA.ImportCASilent(certPEM, keyPEM); err != nil {
		return fmt.Errorf("import CA: %w", err)
	}
	return nil
}

// promote switches this standby to leader mode using the promote context
// captured at StartAsStandby. reason labels the trigger (unplanned auto-failover,
// a manual operator promotion, or a coordinated planned handoff). It is
// idempotent: the `promoted` guard ensures the expensive onPromote (gRPC server
// start) runs at most once, so a manual/planned promote cannot race the sync
// loop's auto-promote. On an onPromote failure the guard is reset so a later
// attempt can retry.
func (h *HAState) promote(reason string) {
	if !h.promoted.CompareAndSwap(false, true) {
		return // already promoted (or another trigger won the race)
	}
	h.mu.RLock()
	pc := h.pc
	h.mu.RUnlock()
	if !pc.set || pc.onPromote == nil {
		h.promoted.Store(false)
		logger.Printf("HA: promote (%s) requested but no promote context available — ignoring", reason)
		return
	}

	// ADR-0005 S2: every path to leadership goes through the fence. Denied
	// or transport-unknown ⇒ no promotion. A grant whose onPromote then
	// fails leaves an unkept lease that simply expires after its TTL
	// (bounded stall; the S1 Provider deliberately has no Release).
	if !h.acquireLeaseForLeadership(reason) {
		h.promoted.Store(false)
		logger.Printf("HA: promote (%s) blocked by the fencing lease — staying as standby", sanitizeLog(reason))
		return
	}

	logger.Printf("HA: promoting to leader (%s)", reason)
	// CHAOS-25: onPromote starts the CP gRPC server — foreign, failure-prone
	// startup work reached from THREE callers (the standby loop, the planned
	// handoff, and the admin PromoteManually API). A panic in it is
	// operationally identical to the error it already handles: the node did not
	// become a leader. Treat it that way — reset the once-guard, stay standby,
	// stay retryable — rather than letting it kill an in-line gateway. The lease
	// grant taken just above is left unkept and simply expires after its TTL,
	// exactly as the error branch already documents; haIssuanceAllowed is
	// role-gated, so a standby holding an unrenewed grant issues nothing.
	var promoteErr error
	if runGuarded(haPromoteComponent, func() { promoteErr = pc.onPromote() }) {
		h.promoted.Store(false) // allow a later retry (we are provably not leader here)
		logger.Printf("HA: promote panicked and was contained — staying as standby (retryable)")
		return
	}
	if promoteErr != nil {
		h.promoted.Store(false) // allow a later retry
		logger.Printf("HA: promote failed: %v — staying as standby", promoteErr)
		return
	}

	h.mu.Lock()
	h.role = "leader"
	h.since = time.Now()
	if h.lease != nil {
		h.term = termFromEpoch(h.leaseEpoch) // term collapses into the fencing epoch (ADR-0005 Finding 6)
	} else {
		h.term++ // new leadership epoch (ADR-0004 Slice 1c)
	}
	cfg := &haConfig{
		Enabled:      true,
		Token:        h.token,
		PeerAddr:     h.peerAddr,
		Role:         "leader",
		AutoFailover: h.autoFailover,
		Term:         h.term,
	}
	newTerm := h.term
	promoteEpoch := h.leaseEpoch // fencing epoch in effect (0 in legacy mode)
	h.mu.Unlock()
	statHAFailovers.Add(1) // CL-9 PR3: count standby→leader promotions only
	// M5: record the promotion in the failover ring. promote() is the single
	// path every promotion funnels through — auto-failover, planned handoff, and
	// PromoteManually all call it — so this one append covers them all.
	globalHAFailoverRing.Load().record("standby", "leader", reason, promoteEpoch, time.Now())

	// Update persisted config.
	_ = saveHAConfig(cfg)

	// Becoming leader makes the standby sync loop pointless — stop it so a
	// manual/planned promotion (which runs outside the loop) doesn't leave it
	// spinning against the old leader. Idempotent with the auto-failover path,
	// which also exits the loop after promote returns. Signal-only (never
	// Stop()): auto-failover reaches here FROM the standby loop goroutine, and
	// joining would deadlock waiting on ourselves.
	h.stopLoops()
	h.startLeaseKeepalive() // after stopLoops(): it halts the keepalive too

	logger.Printf("HA: now serving as leader (promoted from standby, term=%d)", newTerm)
}

// PromoteManually performs an explicit, operator- or orchestrator-triggered
// promotion of this standby to leader — the manual-failover path (ADR-0004
// Slice 1e). Unlike auto-failover it does NOT require --ha-auto-failover: an
// explicit promotion is a deliberate, coordinated action, not an unattended
// reaction to leader silence, so it carries no split-brain surprise. Returns an
// error if this node is not a promotable standby.
func (h *HAState) PromoteManually() error {
	h.mu.RLock()
	role := h.role
	ctxSet := h.pc.set
	h.mu.RUnlock()
	if role != "standby" {
		return fmt.Errorf("cannot promote: node role is %q, not standby", role)
	}
	if !ctxSet {
		return fmt.Errorf("cannot promote: no promote context (node was not started as a standby)")
	}
	h.promote("manual promotion")
	if !h.IsLeader() {
		return fmt.Errorf("promotion did not complete (see logs)")
	}
	return nil
}

// stopLoops signals the sync loop and the lease keepalive loop to exit
// WITHOUT waiting for them. Internal use only (promote runs on the standby
// loop's own goroutine); external callers want Stop.
func (h *HAState) stopLoops() {
	h.mu.Lock()
	if h.stopCh != nil {
		close(h.stopCh)
		h.stopCh = nil
	}
	h.mu.Unlock()
	h.stopLeaseKeepalive()
}

// Stop terminates the sync loop and the lease keepalive loop and WAITS for
// them to finish. The join matters: a fencing keepalive round that lost the
// lease re-enters standby (enterStandbyResync → StartAsStandby) and persists
// the HA config on its own goroutine — returning before it finishes lets
// callers (shutdown, tests restoring globals) pull state out from under a
// write that is still in flight.
//
// The stopping latch is set BEFORE the signal: a keepalive goroutine already
// inside selfFence would otherwise re-enter standby AFTER stopLoops ran,
// creating a fresh stop channel nobody closes — turning the join into a
// shutdown deadlock. With the latch, StartAsStandby/startLeaseKeepalive
// refuse to spawn while Stop is in flight (the node is going away; a resync
// loop it would immediately have to kill is pure waste). Cleared after the
// join — Stop is not terminal, restart afterwards is legitimate.
func (h *HAState) Stop() {
	h.mu.Lock()
	h.stopping = true
	h.mu.Unlock()
	h.stopLoops()
	h.wg.Wait()
	h.mu.Lock()
	h.stopping = false
	h.mu.Unlock()
}

// ── HA Config Persistence ───────────────────────────────────────────────────

const haConfigFile = "ha_config.json"

type haConfig struct {
	Enabled      bool   `json:"enabled"`
	Token        string `json:"token"`
	PeerAddr     string `json:"peer_addr"`
	Role         string `json:"role"`                   // "leader" or "standby"
	AutoFailover bool   `json:"auto_failover"`          // standby self-promotes on leader loss (ADR-0004; default OFF)
	Term         uint64 `json:"term"`                   // leadership epoch (ADR-0004 Slice 1c)
	StandbyAddr  string `json:"standby_addr,omitempty"` // leader-side failback target (ADR-0005 S0)
}

func haConfigPath() string {
	dir := filepath.Dir(clusterDBPathGlobal)
	return filepath.Join(dir, haConfigFile)
}

func saveHAConfig(cfg *haConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// CL-7: atomicWriteFile gives unique tmp + chmod + fsync(file) +
	// rename + best-effort fsync(parent dir) — replaces the previous
	// plain os.WriteFile which left a non-durable / potentially-
	// truncated file on crash.
	return atomicWriteFile(haConfigPath(), data, 0o600)
}

// haRestartAction decides what a node restarting on the normal CP path should
// do given its persisted HA config: "standby" (re-enter standby, do NOT assert
// leadership), "leader" (resume leadership — includes legacy configs with no
// role for back-compat), or "none" (HA disabled / unreadable config → plain CP).
// ADR-0004: a persisted standby must never silently come up as a second leader.
func haRestartAction(cfg *haConfig, loadErr error) string {
	if loadErr != nil || cfg == nil || !cfg.Enabled {
		return "none"
	}
	if cfg.Role == "standby" {
		return "standby"
	}
	return "leader"
}

func loadHAConfig() (*haConfig, error) {
	data, err := os.ReadFile(haConfigPath())
	if err != nil {
		return nil, err
	}
	var cfg haConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ── Token Generation ────────────────────────────────────────────────────────

func generateHAToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── Health Endpoint ─────────────────────────────────────────────────────────

// addRequestLogHealth annotates a healthy /healthz response when persistent
// request-log or audit-log writes are failing (e.g. disk full). Each field is
// added only when non-zero so existing health-probe consumers see an unchanged
// body in the normal case; the node stays "ok" — degraded logging must not
// pull it out of the load balancer.
func addRequestLogHealth(resp map[string]any) {
	if n := reqlog.WriteErrors(); n > 0 {
		resp["requestLogWriteErrors"] = n
	}
	// Audit-log loss is the compliance-critical half of the same fault: the
	// durable "who changed what" record is incomplete, and the in-memory ring
	// that the UI renders from is volatile and capped at 500 entries.
	if n := auditWriteErrors(); n > 0 {
		resp["auditLogWriteErrors"] = n
	}
	// Saturation of the async JSONL queue: no entry is lost, but request
	// goroutines are waiting on the disk again, so latency is affected.
	if n := reqlog.Backpressure(); n > 0 {
		resp["requestLogBackpressure"] = n
	}
}

// apiHealthz is an unauthenticated health-check endpoint for load balancers.
// Returns 200 if this CP is the leader (or if HA is disabled), 503 otherwise.
// Load balancers should route DP traffic only to the 200-returning CP.
func apiHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := globalHA.Status()
	// If HA is not enabled, this node is standalone — always healthy.
	if !status.Enabled {
		resp := map[string]any{"status": "ok", "role": "standalone", "leader": true, "write_authority": true, "version": version}
		addRequestLogHealth(resp)
		jsonOK(w, resp)
		return
	}
	if status.Role == "leader" {
		// ADR-0004 Slice 1c: surface term + write_authority + auto_failover so an
		// external monitor scraping BOTH CPs can DETECT split-brain (two nodes
		// reporting role=leader, comparable by term). ADR-0005 S2: in lease mode
		// write_authority is gated on the fencing lease (WriteAllowed) and the
		// epoch + lease_valid fields are surfaced; legacy mode keeps the honest
		// role-based value (WriteAllowed is true with no provider).
		resp := map[string]any{
			"status": "ok", "role": "leader", "leader": true, "since": status.Since,
			"term": status.Term, "write_authority": globalHA.WriteAllowed(), "auto_failover": status.AutoFailover,
			"version": version,
		}
		addLeaseHealth(resp, globalHA)
		addRequestLogHealth(resp)
		jsonOK(w, resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	standbyResp := map[string]any{
		"status": "standby", "role": "standby", "leader": false,
		"term": status.Term, "write_authority": false, "auto_failover": status.AutoFailover,
		"version": version,
	}
	addLeaseHealth(standbyResp, globalHA)
	resp, _ := json.Marshal(standbyResp)
	_, _ = w.Write(resp)
}

// apiClusterHA handles GET (status) and POST (enable HA) for the admin UI.
func apiClusterHA(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		status := globalHA.Status()
		resp := map[string]any{
			"enabled":       status.Enabled,
			"role":          status.Role,
			"since":         status.Since,
			"peer_addr":     status.PeerAddr,
			"auto_failover": status.AutoFailover,
			"term":          status.Term,
		}
		// ADR-0005 S5: surface the fencing-lease posture (GUI parity for the
		// -ha-etcd-endpoints wiring; the endpoints themselves are startup
		// config — read-once, restart-scoped — so the panel shows STATUS).
		addLeaseHealth(resp, globalHA)
		// M5: recent role-transition history (promotions + self-fences), newest
		// first. Raw facts for the HA panel; empty when nothing has transitioned.
		resp["failover_events"] = globalHAFailoverRing.Load().list()
		if status.Enabled && status.Role == "leader" {
			resp["deploy_cmd"] = haDeployCommand()
			// ADR-0004 Slice 1e: surface whether a coordinated planned handoff is
			// armed. Previously the leader could arm plannedPromotion internally
			// with no admin-visible way to see (or set) it — an operator taking
			// the leader down for planned maintenance had no signal the standby
			// would promote cleanly on the next sync.
			resp["planned_handoff"] = status.PlannedHandoff
		}
		if status.Enabled && status.Role == "standby" {
			// Previously invisible outside the "HA: sync failed (N/3)" log line —
			// an operator had no warning before a standby silently crossed
			// haStandbyMaxFail and self-fenced/failed-over (ADR-0004/RISK-001).
			resp["sync_fail_count"] = status.SyncFailCount
			resp["sync_max_fail"] = haStandbyMaxFail
			if status.LastSyncOK != "" {
				resp["last_sync_ok"] = status.LastSyncOK
			}
		}
		jsonOK(w, resp)

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiClusterHAEnable(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiClusterHAEnable enables HA mode at runtime from the admin GUI.
//
// Intentionally OUT of the config-version rollback surface — runtime
// lifecycle action (HA leader-election state is ephemeral; no durable
// config to version). Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (runtime/lifecycle).
func apiClusterHAEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LeaderAddr   string `json:"leader_addr"`   // this leader's externally reachable gRPC address
		AutoFailover bool   `json:"auto_failover"` // opt-in standby self-promotion (default OFF — ADR-0004)
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.LeaderAddr == "" {
		http.Error(w, "leader_addr is required (e.g. \"cp1.internal:50051\")", http.StatusBadRequest)
		return
	}

	// Check that we're already running as CP.
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	if role != "control-plane" {
		http.Error(w, "must be running as Control Plane to enable HA", http.StatusConflict)
		return
	}

	// Check if HA is already enabled.
	if globalHA.Status().Enabled {
		http.Error(w, "HA is already enabled", http.StatusConflict)
		return
	}

	// Enable as leader and generate token. With a fencing-lease backend
	// configured this is Acquire-gated (ADR-0005 S2) and can fail.
	token, err := globalHA.EnableAsLeader(req.LeaderAddr, req.AutoFailover)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	deployCmd := haDeployCommand()
	jsonOK(w, map[string]any{
		"ok":            true,
		"role":          "leader",
		"leader_addr":   req.LeaderAddr,
		"auto_failover": req.AutoFailover,
		"deploy_cmd":    deployCmd,
	})

	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.ha-enable",
		Object: req.LeaderAddr,
		Detail: fmt.Sprintf("HA enabled, token generated (token=%s…), auto_failover=%v", token[:8], req.AutoFailover),
	})
}

// ── Planned promotion (leader side) ─────────────────────────────────────────

// RequestPlannedPromotion (leader) arms the coordinated-handoff flag so the next
// HASync bundle instructs the standby to promote. Used before a deliberate
// leader takedown (e.g. a CP rolling update). Clear with ClearPlannedPromotion.
func (h *HAState) RequestPlannedPromotion() { h.plannedPromotion.Store(true) }

// ClearPlannedPromotion disarms the coordinated-handoff flag.
func (h *HAState) ClearPlannedPromotion() { h.plannedPromotion.Store(false) }

// apiClusterHAPromote handles POST /api/cluster/ha/promote — the explicit
// manual-failover action (ADR-0004 Slice 1e). It promotes THIS node (a standby)
// to leader. Auth: admin RBAC for the operator UI path. Unlike auto-failover it
// needs no --ha-auto-failover, because an explicit promotion is deliberate.
func apiClusterHAPromote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if err := globalHA.PromoteManually(); err != nil {
		// Inline-sanitize the engine error (CWE-117) before it reaches the log
		// via the response path; the message names only role/context, no input.
		http.Error(w, "promote failed: "+err.Error(), http.StatusConflict)
		return
	}
	status := globalHA.Status()
	jsonOK(w, map[string]any{"ok": true, "role": status.Role, "term": status.Term})

	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.ha-promote",
		Object: "self",
		Detail: fmt.Sprintf("manual standby→leader promotion (term=%d)", status.Term),
	})
}

// apiClusterHAPlannedHandoff handles POST /api/cluster/ha/planned-handoff —
// arms or disarms the coordinated-handoff flag (ADR-0004 Slice 1e) on this
// node, the HA leader. When armed, the next HASync bundle instructs the
// standby to promote immediately on receipt — even with auto-failover off —
// so an admin can drain the leader for planned maintenance (OS patch,
// Culvert upgrade, planned reboot) without either an unattended
// failure-detection window (killing the leader outright) or an
// unsynchronized manual "/promote" on the standby (which doesn't confirm the
// standby is caught up or tell the old leader to step down). Prior to this,
// RequestPlannedPromotion/ClearPlannedPromotion had no caller anywhere in the
// binary — the coordinated-handoff design existed but was unreachable.
func apiClusterHAPlannedHandoff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req struct {
		Armed bool `json:"armed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	status := globalHA.Status()
	if !status.Enabled || status.Role != "leader" {
		http.Error(w, "planned handoff can only be armed on the HA leader", http.StatusConflict)
		return
	}
	action := "cluster.ha-planned-handoff-disarm"
	if req.Armed {
		globalHA.RequestPlannedPromotion()
		action = "cluster.ha-planned-handoff-arm"
	} else {
		globalHA.ClearPlannedPromotion()
	}
	jsonOK(w, map[string]any{"ok": true, "armed": req.Armed})

	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: action,
		Object: "self",
		Detail: fmt.Sprintf("coordinated planned handoff armed=%v (next HASync instructs the standby to promote)", req.Armed),
	})
}

// haDeployCommand generates the CLI command for deploying the standby CP.
// Includes enterprise TLS cert paths when the leader was started with them,
// so the admin knows exactly which cert files to stage on the standby server.
func haDeployCommand() string {
	clusterRoleMu.RLock()
	grpcAddr := clusterRole.grpcAddr
	certFile := clusterRole.certFile
	keyFile := clusterRole.keyFile
	caFile := clusterRole.caFile
	clusterRoleMu.RUnlock()

	globalHA.mu.RLock()
	token := globalHA.token
	leaderAddr := globalHA.peerAddr
	autoFailover := globalHA.autoFailover
	globalHA.mu.RUnlock()

	cmd := fmt.Sprintf("./culvert --cp-grpc-addr %s --ha-join %s --ha-token %s",
		grpcAddr, leaderAddr, token)

	// Include enterprise TLS paths so standby uses the same cert setup.
	if certFile != "" {
		cmd += fmt.Sprintf(" \\\n  --cp-grpc-cert %s --cp-grpc-key %s", certFile, keyFile)
	}
	if caFile != "" {
		cmd += fmt.Sprintf(" \\\n  --cp-grpc-ca %s", caFile)
	}
	// Carry the auto-failover preference to the standby (default OFF — the
	// flag only appears when the operator explicitly enabled it). See ADR-0004.
	if autoFailover {
		cmd += " \\\n  --ha-auto-failover"
	}
	return cmd
}

// ── ImportCASilent ──────────────────────────────────────────────────────────

// ImportCASilent loads a CA cert+key without triggering rotation tracking or
// config version bumps. Used by HA standby to silently replicate leader state.
func (ca *clusterCA) ImportCASilent(certPEM, keyPEM []byte) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.loadFromPEM(certPEM, keyPEM)
}

// persistReplicatedKey writes the replicated cluster CA cert + key to disk on an
// HA standby. The cert is written plaintext; the key goes through the CA-3
// cluster-CA write path (writeClusterCAKey), so it is encrypted at rest iff
// CULVERT_CLUSTER_CA_ENCRYPT is enabled on THIS node — a per-node decision that
// does not require the leader's KEK. keyPEM is the decrypted plaintext key PEM;
// it is never logged. certPEM is passed explicitly (not read from ca.certPEM)
// so this can persist the new pair BEFORE the live CA is mutated in memory.
//
// No-op (not an error) when the CA has no persistence dir configured — some
// deployments run the cluster CA in-memory only.
func (ca *clusterCA) persistReplicatedKey(certPEM, keyPEM []byte) error {
	ca.mu.RLock()
	dir := ca.dir
	ca.mu.RUnlock()
	if dir == "" {
		return nil
	}
	certPath, err := safeCAPath(dir, "cluster-ca.crt")
	if err != nil {
		return err
	}
	keyPath, err := safeCAPath(dir, "cluster-ca.key")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write cluster CA cert: %w", err)
	}
	// CA-3 (#319): encrypted at rest when enabled on this node, plaintext otherwise.
	return writeClusterCAKey(dir, keyPath, keyPEM)
}
