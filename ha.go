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
//   4. If leader dies AND auto-failover is enabled → standby promotes after 3
//      failed sync attempts. Auto-failover is OPT-IN and OFF by default: a
//      2-node active/passive cluster has no witness, so unattended promotion on
//      a surviving-leader partition is a split-brain (ADR-0004 / RISK-001).
//      Default (manual): the standby stays read-only until an operator acts.
//   5. DPs automatically failover (--dp-cp-addr supports comma-separated addrs)
//
// Restart behaviour (ADR-0004): on restart a node honours its PERSISTED role —
// a standby re-enters standby (it never silently self-asserts as a second
// leader). A restarted LEADER resumes leadership because the topology gives it
// no way to probe its peer: the standby is the gRPC client, so the leader does
// not record the standby's address (peerAddr holds the *leader's own* advertised
// address — see haDeployCommand). True "handshake the peer on restart, become
// standby if it already leads" therefore requires recording the standby's
// address and is deferred to the failover-mechanism work; until then a
// leader-resume under auto-failover logs a split-brain-risk warning.
//
// Authentication: standby presents a shared HA token in every HASync RPC.
// The leader verifies it against the stored token.

// HAState tracks the HA status of this Control Plane instance.
type HAState struct {
	mu           sync.RWMutex
	role         string         // "leader", "standby", or "" (HA disabled)
	token        string         // shared HA token for authentication
	peerAddr     string         // address of the other CP
	since        time.Time      // when current role was acquired
	autoFailover bool           // standby self-promotes on leader loss (default OFF — see ADR-0004)
	term         uint64         // leadership epoch — bumped on each promotion (ADR-0004 Slice 1c)
	pc           promoteContext // params captured at StartAsStandby so a manual/planned promote can reuse them
	stopCh       chan struct{}

	// plannedPromotion (leader side) signals the standby, via the next HASync
	// bundle, to perform a COORDINATED promotion — a planned handoff (e.g. a CP
	// rolling update) that must happen even when auto-failover is OFF. Distinct
	// from unplanned auto-failover. (ADR-0004 Slice 1e.)
	plannedPromotion atomic.Bool
	// promoted guards promote() so the expensive onPromote (gRPC server start)
	// runs at most once whether triggered by the sync loop, a manual API call,
	// or a planned handoff.
	promoted atomic.Bool
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
	Enabled      bool   `json:"enabled"`
	Role         string `json:"role"`                // "leader", "standby", or ""
	Since        string `json:"since,omitempty"`     // RFC3339
	PeerAddr     string `json:"peer_addr,omitempty"` // other CP address
	AutoFailover bool   `json:"auto_failover"`       // standby self-promotes on leader loss (ADR-0004)
	Term         uint64 `json:"term"`                // leadership epoch (ADR-0004 Slice 1c)
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
	}
	if !h.since.IsZero() {
		s.Since = h.since.Format(time.RFC3339)
	}
	return s
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
func (h *HAState) EnableAsLeader(peerAddr string, autoFailover bool) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.role = "leader"
	h.peerAddr = peerAddr
	h.since = time.Now()
	h.autoFailover = autoFailover
	h.term = 1 // first leadership epoch (ADR-0004 Slice 1c)
	h.token = generateHAToken()
	h.stopCh = make(chan struct{})

	// Persist HA config so leader restarts know HA is enabled.
	_ = saveHAConfig(&haConfig{
		Enabled:      true,
		Token:        h.token,
		PeerAddr:     peerAddr,
		Role:         "leader",
		AutoFailover: autoFailover,
		Term:         h.term,
	})

	logger.Printf("HA: enabled as leader (peer=%q, auto_failover=%v, term=%d)", sanitizeLog(peerAddr), autoFailover, h.term)
	return h.token
}

// ResumeAsLeader restores leader state from a persisted haConfig on restart
// WITHOUT bumping the term — it is the same leadership epoch continuing, not a
// new promotion. Replaces the previous EnableAsLeader-then-patch-token dance in
// main.go so the persisted term/token survive a restart intact (ADR-0004).
func (h *HAState) ResumeAsLeader(cfg *haConfig) {
	h.mu.Lock()
	h.role = "leader"
	h.peerAddr = cfg.PeerAddr
	h.token = cfg.Token
	h.autoFailover = cfg.AutoFailover
	h.term = cfg.Term
	h.since = time.Now()
	h.stopCh = make(chan struct{})
	h.mu.Unlock()
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
	h.role = "standby"
	h.peerAddr = leaderAddr
	h.token = token
	h.since = time.Now()
	h.autoFailover = autoFailover
	h.pc = promoteContext{grpcAddr: grpcAddr, certFile: certFile, keyFile: keyFile, caFile: caFile, onPromote: onPromote, set: true}
	h.promoted.Store(false)
	h.stopCh = make(chan struct{})
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

	go h.standbyLoop(ctx, leaderAddr, token, certFile, keyFile, caFile)
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
}

func (h *HAState) standbyLoop(ctx context.Context, leaderAddr, token string,
	certFile, keyFile, caFile string) {
	// Capture the stop channel once. promote() calls Stop() (which closes then
	// nils h.stopCh), so reading the field per-iteration could select on a nil
	// channel after a manual/planned promotion; the local keeps the closed
	// channel reachable so the loop exits cleanly.
	h.mu.RLock()
	stopCh := h.stopCh
	h.mu.RUnlock()

	s := &standbyLoopState{
		h: h, ctx: ctx, leaderAddr: leaderAddr, token: token,
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

	s.syncOnce() // try immediately

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			if s.tick() {
				return
			}
		}
	}
}

// onMaxFail handles the leader-unreachable threshold. Returns true when the loop
// should EXIT (auto-failover promoted this node to leader); false to keep the
// standby read-only and retrying (auto-failover disabled — the default split-
// brain mitigation; see ADR-0004), warning once until the leader returns.
func (s *standbyLoopState) onMaxFail() bool {
	if s.h.autoFailoverEnabled() {
		s.h.promote("leader unreachable")
		return true
	}
	if !s.manualWarned {
		s.h.warnManualFailoverRequired(s.leaderAddr)
		s.manualWarned = true
	}
	return false
}

// syncOnce performs a single sync attempt without reconnecting (the immediate
// try at loop start), updating failCount.
func (s *standbyLoopState) syncOnce() {
	if s.client == nil {
		s.failCount++
		return
	}
	if s.h.syncFromLeader(s.ctx, s.client, s.token) {
		s.failCount = 0
		s.manualWarned = false
	} else {
		s.failCount++
	}
}

// tick runs one loop iteration: reconnect if needed, then sync. Returns true
// when the loop should exit (this node was promoted to leader).
func (s *standbyLoopState) tick() bool {
	if s.client == nil {
		c, err := NewDataPlaneClient("ha-standby", s.leaderAddr, s.certFile, s.keyFile, s.caFile)
		if err != nil {
			s.failCount++
			logger.Printf("HA: reconnect to leader failed (%d/%d): %v", s.failCount, haStandbyMaxFail, err)
			return s.failCount >= haStandbyMaxFail && s.onMaxFail()
		}
		s.client = c
	}
	if s.h.syncFromLeader(s.ctx, s.client, s.token) {
		s.failCount = 0
		s.manualWarned = false // leader recovered — re-arm the warning
		return false
	}
	s.failCount++
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
	reqBytes, _ := json.Marshal(map[string]string{"token": token})
	raw, err := client.call(ctx, methodHASync, json.RawMessage(reqBytes))
	if err != nil {
		logger.Printf("HA: HASync RPC error: %v", err)
		return false
	}

	var bundle HAStateBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		logger.Printf("HA: parse state bundle error: %v", err)
		return false
	}
	ok := applyHABundle(&bundle, token)
	if ok {
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

	// Apply config snapshot.
	applyConfigSnapshot(bundle.Config)

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

	logger.Printf("HA: promoting to leader (%s)", reason)
	if err := pc.onPromote(); err != nil {
		h.promoted.Store(false) // allow a later retry
		logger.Printf("HA: promote failed: %v — staying as standby", err)
		return
	}

	h.mu.Lock()
	h.role = "leader"
	h.since = time.Now()
	h.term++ // new leadership epoch (ADR-0004 Slice 1c)
	cfg := &haConfig{
		Enabled:      true,
		Token:        h.token,
		PeerAddr:     h.peerAddr,
		Role:         "leader",
		AutoFailover: h.autoFailover,
		Term:         h.term,
	}
	newTerm := h.term
	h.mu.Unlock()
	statHAFailovers.Add(1) // CL-9 PR3: count standby→leader promotions only

	// Update persisted config.
	_ = saveHAConfig(cfg)

	// Becoming leader makes the standby sync loop pointless — stop it so a
	// manual/planned promotion (which runs outside the loop) doesn't leave it
	// spinning against the old leader. Idempotent with the auto-failover path,
	// which also exits the loop after promote returns.
	h.Stop()

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

// Stop terminates the sync loop.
func (h *HAState) Stop() {
	h.mu.Lock()
	if h.stopCh != nil {
		close(h.stopCh)
		h.stopCh = nil
	}
	h.mu.Unlock()
}

// ── HA Config Persistence ───────────────────────────────────────────────────

const haConfigFile = "ha_config.json"

type haConfig struct {
	Enabled      bool   `json:"enabled"`
	Token        string `json:"token"`
	PeerAddr     string `json:"peer_addr"`
	Role         string `json:"role"`          // "leader" or "standby"
	AutoFailover bool   `json:"auto_failover"` // standby self-promotes on leader loss (ADR-0004; default OFF)
	Term         uint64 `json:"term"`          // leadership epoch (ADR-0004 Slice 1c)
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
// request-log writes are failing (e.g. disk full). The field is added only
// when non-zero so existing health-probe consumers see an unchanged body in
// the normal case; the node stays "ok" — degraded logging must not pull it
// out of the load balancer.
func addRequestLogHealth(resp map[string]any) {
	if n := atomic.LoadInt64(&statReqLogWriteErrors); n > 0 {
		resp["requestLogWriteErrors"] = n
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
		resp := map[string]any{"status": "ok", "role": "standalone", "leader": true, "write_authority": true}
		addRequestLogHealth(resp)
		jsonOK(w, resp)
		return
	}
	if status.Role == "leader" {
		// ADR-0004 Slice 1c: surface term + write_authority + auto_failover so an
		// external monitor scraping BOTH CPs can DETECT split-brain (two nodes
		// reporting role=leader, comparable by term). write_authority is the
		// honest Slice-1 value (role==leader); the failover-mechanism slice will
		// gate it on quorum.
		resp := map[string]any{
			"status": "ok", "role": "leader", "leader": true, "since": status.Since,
			"term": status.Term, "write_authority": true, "auto_failover": status.AutoFailover,
		}
		addRequestLogHealth(resp)
		jsonOK(w, resp)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	resp, _ := json.Marshal(map[string]any{
		"status": "standby", "role": "standby", "leader": false,
		"term": status.Term, "write_authority": false, "auto_failover": status.AutoFailover,
	})
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
		if status.Enabled && status.Role == "leader" {
			resp["deploy_cmd"] = haDeployCommand()
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

	// Enable as leader and generate token.
	token := globalHA.EnableAsLeader(req.LeaderAddr, req.AutoFailover)

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
