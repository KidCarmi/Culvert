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
	"time"
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
//   4. If leader dies → standby promotes after 3 failed sync attempts
//   5. DPs automatically failover (--dp-cp-addr supports comma-separated addrs)
//
// Leader failback: when the original leader restarts, it loads its persisted
// HA config, detects the peer is already serving, and becomes standby.
//
// Authentication: standby presents a shared HA token in every HASync RPC.
// The leader verifies it against the stored token.

// HAState tracks the HA status of this Control Plane instance.
type HAState struct {
	mu       sync.RWMutex
	role     string    // "leader", "standby", or "" (HA disabled)
	token    string    // shared HA token for authentication
	peerAddr string    // address of the other CP
	since    time.Time // when current role was acquired
	stopCh   chan struct{}
}

var globalHA = &HAState{}

// HAStatus returns a snapshot of the current HA state for API/UI consumption.
type HAStatus struct {
	Enabled  bool   `json:"enabled"`
	Role     string `json:"role"`               // "leader", "standby", or ""
	Since    string `json:"since,omitempty"`     // RFC3339
	PeerAddr string `json:"peer_addr,omitempty"` // other CP address
}

func (h *HAState) Status() HAStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := HAStatus{
		Enabled:  h.role != "",
		Role:     h.role,
		PeerAddr: h.peerAddr,
	}
	if !h.since.IsZero() {
		s.Since = h.since.Format(time.RFC3339)
	}
	return s
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
// Returns the generated token for inclusion in the standby deploy command.
func (h *HAState) EnableAsLeader(peerAddr string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.role = "leader"
	h.peerAddr = peerAddr
	h.since = time.Now()
	h.token = generateHAToken()
	h.stopCh = make(chan struct{})

	// Persist HA config so leader restarts know HA is enabled.
	_ = saveHAConfig(&haConfig{
		Enabled:  true,
		Token:    h.token,
		PeerAddr: peerAddr,
		Role:     "leader",
	})

	logger.Printf("HA: enabled as leader (peer=%s)", sanitizeLog(peerAddr))
	return h.token
}

// ── Standby Mode ────────────────────────────────────────────────────────────

// StartAsStandby connects to the leader CP and begins state replication.
// When the leader becomes unreachable (3 consecutive failures), the standby
// promotes itself to leader by calling onPromote.
func (h *HAState) StartAsStandby(ctx context.Context, leaderAddr, token string,
	grpcAddr, certFile, keyFile, caFile string,
	onPromote func() error) {

	h.mu.Lock()
	h.role = "standby"
	h.peerAddr = leaderAddr
	h.token = token
	h.since = time.Now()
	h.stopCh = make(chan struct{})
	h.mu.Unlock()

	// Persist HA config so standby restarts know HA is enabled.
	_ = saveHAConfig(&haConfig{
		Enabled:  true,
		Token:    token,
		PeerAddr: leaderAddr,
		Role:     "standby",
	})

	logger.Printf("HA: starting as standby (leader=%s)", sanitizeLog(leaderAddr))

	go h.standbyLoop(ctx, leaderAddr, token, grpcAddr, certFile, keyFile, caFile, onPromote)
}

func (h *HAState) standbyLoop(ctx context.Context, leaderAddr, token string,
	grpcAddr, certFile, keyFile, caFile string,
	onPromote func() error) {

	// Connect to leader using the same gRPC client infrastructure as DPs.
	client, err := NewDataPlaneClient("ha-standby", leaderAddr, certFile, keyFile, caFile)
	if err != nil {
		logger.Printf("HA: failed to connect to leader: %v — will retry", err)
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	failCount := 0
	const maxFail = 3

	// Try immediately.
	if client != nil {
		if h.syncFromLeader(ctx, client, token) {
			failCount = 0
		} else {
			failCount++
		}
	} else {
		failCount++
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			if client == nil {
				// Retry connection.
				client, err = NewDataPlaneClient("ha-standby", leaderAddr, certFile, keyFile, caFile)
				if err != nil {
					failCount++
					logger.Printf("HA: reconnect to leader failed (%d/%d): %v", failCount, maxFail, err)
					if failCount >= maxFail {
						h.promote(grpcAddr, certFile, keyFile, caFile, onPromote)
						return
					}
					continue
				}
			}

			if h.syncFromLeader(ctx, client, token) {
				failCount = 0
			} else {
				failCount++
				logger.Printf("HA: sync failed (%d/%d)", failCount, maxFail)
				if failCount >= maxFail {
					h.promote(grpcAddr, certFile, keyFile, caFile, onPromote)
					return
				}
			}
		}
	}
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
	return applyHABundle(&bundle, token)
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

// promote switches this standby to leader mode. The grpcAddr/certFile/keyFile/
// caFile params are threaded from Start → standbyLoop → promote for call-site
// symmetry with the reconnect path and kept for a future promote impl; they are
// pre-existing and not introduced by CA-3.
//
//nolint:unparam // see note above — params kept for signature symmetry / future use
func (h *HAState) promote(grpcAddr, certFile, keyFile, caFile string, onPromote func() error) {
	logger.Printf("HA: leader unreachable — promoting to leader")

	if err := onPromote(); err != nil {
		logger.Printf("HA: promote failed: %v — staying as standby", err)
		return
	}

	h.mu.Lock()
	h.role = "leader"
	h.since = time.Now()
	h.mu.Unlock()
	statHAFailovers.Add(1) // CL-9 PR3: count standby→leader promotions only

	// Update persisted config.
	_ = saveHAConfig(&haConfig{
		Enabled:  true,
		Token:    h.token,
		PeerAddr: h.peerAddr,
		Role:     "leader",
	})

	logger.Printf("HA: now serving as leader (promoted from standby)")
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
	Enabled  bool   `json:"enabled"`
	Token    string `json:"token"`
	PeerAddr string `json:"peer_addr"`
	Role     string `json:"role"` // "leader" or "standby"
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
		jsonOK(w, map[string]any{"status": "ok", "role": "standalone", "leader": true})
		return
	}
	if status.Role == "leader" {
		jsonOK(w, map[string]any{"status": "ok", "role": "leader", "leader": true, "since": status.Since})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	resp, _ := json.Marshal(map[string]any{"status": "standby", "role": "standby", "leader": false})
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
			"enabled":   status.Enabled,
			"role":      status.Role,
			"since":     status.Since,
			"peer_addr": status.PeerAddr,
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
		LeaderAddr string `json:"leader_addr"` // this leader's externally reachable gRPC address
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
	token := globalHA.EnableAsLeader(req.LeaderAddr)

	deployCmd := haDeployCommand()
	jsonOK(w, map[string]any{
		"ok":         true,
		"role":       "leader",
		"leader_addr": req.LeaderAddr,
		"deploy_cmd": deployCmd,
	})

	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  sessionAdmin(r),
		Action: "cluster.ha-enable",
		Object: req.LeaderAddr,
		Detail: fmt.Sprintf("HA enabled, token generated (token=%s…)", token[:8]),
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
