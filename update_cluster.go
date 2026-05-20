package main

// Cluster rolling update orchestration.
//
// The Control Plane (CP) coordinates rolling updates across all Data Plane (DP)
// nodes, then updates itself. State is persisted to /data/cluster_update.json
// for crash recovery.
//
// See roadmap/docker-system-update.md for full design.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ── Update state machine ────────────────────────────────────────────────────

// ClusterUpdateState tracks a rolling update across the cluster.
type ClusterUpdateState struct {
	mu          sync.Mutex
	Active      bool                          `json:"active"`
	TargetTag   string                        `json:"target_tag"`
	PreviousTag string                        `json:"previous_tag"`
	Initiator   string                        `json:"initiator"`
	StartedAt   time.Time                     `json:"started_at"`
	CompletedAt time.Time                     `json:"completed_at,omitempty"`
	Nodes       map[string]*NodeUpdateStatus  `json:"nodes"`
	Phase       string                        `json:"phase"` // "canary", "canary_soak", "updating_dps", "updating_cp", "complete", "failed", "halted", "cp_rolled_back", "auto_rollback"
	ErrorBudget ErrorBudgetConfig             `json:"error_budget"`
	Failures    int                           `json:"failures"`
	ConsecFails int                           `json:"consec_fails"`
	CanaryCount int                           `json:"canary_count,omitempty"` // F6: number of canary nodes (0 = skip canary)
	CanarySoak  int                           `json:"canary_soak_s,omitempty"` // F6: soak period seconds after canary phase
	AutoRollback bool                         `json:"auto_rollback,omitempty"` // F8: auto-rollback on health breach
}

// NodeUpdateStatus tracks per-node update progress.
type NodeUpdateStatus struct {
	NodeID     string `json:"node_id"`
	Status     string `json:"status"` // "pending", "draining", "updating", "verifying", "complete", "failed", "unknown", "skipped"
	OldVersion string `json:"old_version,omitempty"`
	NewVersion string `json:"new_version,omitempty"`
	Detail     string `json:"detail,omitempty"`
	DurationS  int    `json:"duration_s,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
}

// ErrorBudgetConfig defines when to halt a rolling update.
type ErrorBudgetConfig struct {
	MaxConsecutive int `json:"max_consecutive"` // default 3
	MaxPercent     int `json:"max_percent"`     // default 20
}

// UpdateProgressReport is sent by DPs in MetricsReport (optional field).
type UpdateProgressReport struct {
	Status  string `json:"status"`
	Detail  string `json:"detail"`
	Version string `json:"version"`
}

var clusterUpdateState ClusterUpdateState

// clusterUpdateFile is the on-disk path for the rolling-update
// progress state. Declared as var (not const) so tests can override
// it; production callers do not mutate this value at runtime.
var clusterUpdateFile = "/data/cluster_update.json"

// ── State persistence ───────────────────────────────────────────────────────

func (s *ClusterUpdateState) persist() {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		logger.Printf("cluster update persist error: %v", err)
		return
	}
	// CL-7: atomicWriteFile replaces the previous manual tmp+rename
	// path (which was atomic but NOT fsynced). The helper does
	// unique tmp + chmod + fsync(file) + rename + best-effort
	// fsync(parent dir).
	if err := atomicWriteFile(clusterUpdateFile, data, 0o600); err != nil {
		logger.Printf("cluster update write error: %v", err)
	}
}

func (s *ClusterUpdateState) load() {
	data, err := os.ReadFile(clusterUpdateFile)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := json.Unmarshal(data, s); err != nil {
		logger.Printf("cluster update load: parse error: %v", err)
	}
}

// clusterUpdateSnapshot is a lock-free copy of ClusterUpdateState for JSON serialization.
type clusterUpdateSnapshot struct {
	Active      bool                         `json:"active"`
	TargetTag   string                       `json:"target_tag"`
	PreviousTag string                       `json:"previous_tag,omitempty"`
	Initiator   string                       `json:"initiator,omitempty"`
	StartedAt   time.Time                    `json:"started_at"`
	CompletedAt time.Time                    `json:"completed_at,omitempty"`
	Nodes       map[string]*NodeUpdateStatus `json:"nodes,omitempty"`
	Phase       string                       `json:"phase"`
	ErrorBudget ErrorBudgetConfig            `json:"error_budget"`
	Failures    int                          `json:"failures"`
	ConsecFails int                          `json:"consec_fails"`
}

func (s *ClusterUpdateState) snapshot() clusterUpdateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := clusterUpdateSnapshot{
		Active:      s.Active,
		TargetTag:   s.TargetTag,
		PreviousTag: s.PreviousTag,
		Initiator:   s.Initiator,
		StartedAt:   s.StartedAt,
		CompletedAt: s.CompletedAt,
		Phase:       s.Phase,
		ErrorBudget: s.ErrorBudget,
		Failures:    s.Failures,
		ConsecFails: s.ConsecFails,
	}
	// Deep copy nodes map.
	snap.Nodes = make(map[string]*NodeUpdateStatus, len(s.Nodes))
	for k, v := range s.Nodes {
		copied := *v
		snap.Nodes[k] = &copied
	}
	return snap
}

// ── Update report ───────────────────────────────────────────────────────────

// UpdateReport is the JSON compliance report generated after each update.
type UpdateReport struct {
	ReportVersion int                 `json:"report_version"`
	UpdateID      string              `json:"update_id"`
	TargetTag     string              `json:"target_tag"`
	PreviousTag   string              `json:"previous_tag"`
	Initiator     string              `json:"initiator"`
	StartedAt     string              `json:"started_at"`
	CompletedAt   string              `json:"completed_at"`
	DurationS     int                 `json:"duration_seconds"`
	Result        string              `json:"result"` // "complete", "halted", "failed"
	ErrorBudget   ErrorBudgetConfig   `json:"error_budget"`
	Nodes         []*NodeUpdateStatus `json:"nodes"`
	CPUpdate      *NodeUpdateStatus   `json:"cp_update,omitempty"`
}

func generateUpdateReport(state *ClusterUpdateState) {
	state.mu.Lock()
	report := UpdateReport{
		ReportVersion: 1,
		UpdateID:      fmt.Sprintf("upd-%s", state.StartedAt.Format("20060102-150405")),
		TargetTag:     state.TargetTag,
		PreviousTag:   state.PreviousTag,
		Initiator:     state.Initiator,
		StartedAt:     state.StartedAt.Format(time.RFC3339),
		CompletedAt:   state.CompletedAt.Format(time.RFC3339),
		DurationS:     int(state.CompletedAt.Sub(state.StartedAt).Seconds()),
		Result:        state.Phase,
		ErrorBudget:   state.ErrorBudget,
	}
	for _, n := range state.Nodes {
		copied := *n
		report.Nodes = append(report.Nodes, &copied)
	}
	state.mu.Unlock()

	dir := "/data/update_reports"
	if err := os.MkdirAll(dir, 0o750); err != nil {
		logger.Printf("update report: mkdir error: %v", err)
	}
	filename := filepath.Join(dir, report.UpdateID+".json")
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(filename, data, 0o600); err != nil {
		logger.Printf("update report: write error: %v", err)
	} else {
		logger.Printf("update report saved: %s", filename)
	}

	// Fire webhook alert.
	fireAlert("cluster_updated", AlertPayload{
		Event:  "cluster_updated",
		Detail: fmt.Sprintf("Cluster updated to %s by %s: %s", report.TargetTag, report.Initiator, report.Result),
	})

	// Audit log.
	now := time.Now()
	auditAdd(AuditEntry{
		TS:     now.UnixMilli(),
		Time:   now.Format("2006-01-02 15:04:05"),
		Actor:  "system",
		Action: "cluster_update.complete",
		Object: "cluster",
		Detail: fmt.Sprintf("update %s to %s: %s (%d nodes)",
			sanitizeLog(report.UpdateID), sanitizeLog(report.TargetTag),
			sanitizeLog(report.Result), len(report.Nodes)),
	})
}

// ── gRPC: TriggerUpdate (CP→DP) ────────────────────────────────────────────

var methodTriggerUpdate = fmt.Sprintf("/%s/TriggerUpdate", configServiceName)

// TriggerUpdateRequest is sent by CP to DP to initiate a self-update.
type TriggerUpdateRequest struct {
	TargetTag string `json:"target_tag"`
	Initiator string `json:"initiator"`
}

// TriggerUpdateResponse is the DP's acknowledgment.
type TriggerUpdateResponse struct {
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
}

// handleTriggerUpdate is the DP-side handler — when CP tells us to update,
// we call our local updater sidecar.
func (s *controlPlaneServer) TriggerUpdate(_ context.Context, reqBytes json.RawMessage) (json.RawMessage, error) {
	var req TriggerUpdateRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		return json.Marshal(TriggerUpdateResponse{Accepted: false, Error: "bad request"})
	}

	logger.Printf("received TriggerUpdate: target=%s from=%s", sanitizeLog(req.TargetTag), sanitizeLog(req.Initiator))

	// Call local updater sidecar.
	go func() { // #nosec G118 — detached goroutine must outlive the gRPC request
		body, _ := json.Marshal(map[string]string{
			"container":  "culvert",
			"target_tag": req.TargetTag,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
		defer cancel()
		resp, err := updaterRequest(ctx, http.MethodPost, "/api/update/apply", strings.NewReader(string(body)))
		if err != nil {
			logger.Printf("local update failed: %v", err)
			return
		}
		defer resp.Body.Close()
		// Read through the SSE stream to completion.
		buf := make([]byte, 4096)
		for {
			_, err := resp.Body.Read(buf)
			if err != nil {
				break
			}
		}
	}()

	return json.Marshal(TriggerUpdateResponse{Accepted: true})
}

// ── Rolling update orchestrator ─────────────────────────────────────────────

func startClusterUpdate(targetTag, initiator string, budget ErrorBudgetConfig) error {
	clusterUpdateState.mu.Lock()
	if clusterUpdateState.Active {
		clusterUpdateState.mu.Unlock()
		return fmt.Errorf("update already in progress")
	}

	// Get current nodes.
	nodes := globalClusterStore.ListNodes()
	if len(nodes) == 0 {
		clusterUpdateState.mu.Unlock()
		return fmt.Errorf("no nodes enrolled")
	}

	clusterUpdateState.Active = true
	clusterUpdateState.TargetTag = targetTag
	clusterUpdateState.PreviousTag = version
	clusterUpdateState.Initiator = initiator
	clusterUpdateState.StartedAt = time.Now()
	clusterUpdateState.ErrorBudget = budget
	clusterUpdateState.Failures = 0
	clusterUpdateState.ConsecFails = 0
	clusterUpdateState.Nodes = make(map[string]*NodeUpdateStatus, len(nodes))
	// F6: Set canary phase if canary count > 0.
	if clusterUpdateState.CanaryCount > 0 {
		clusterUpdateState.Phase = "canary"
	} else {
		clusterUpdateState.Phase = "updating_dps"
	}

	for _, n := range nodes {
		clusterUpdateState.Nodes[n.NodeID] = &NodeUpdateStatus{
			NodeID:     n.NodeID,
			Status:     "pending",
			OldVersion: n.Version,
		}
	}
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	// Run the orchestrator in background, parented to appLifecycleCtx so
	// shutdown is observable at the orchestrator's phase boundaries
	// (CL-3). Inner loops keep their own bounded contexts; the
	// persistence + recoverClusterUpdate contract remains the safety net
	// for mid-action process kill.
	go runClusterUpdate(resolveLifecycleCtx())
	return nil
}

// resolveLifecycleCtx returns appLifecycleCtx, falling back to
// context.Background() when the global is nil. appLifecycleCtx is a
// package-global set by initLifecycleContext during main(); reaching
// startClusterUpdate before that wire-up (test binaries that hit this
// path directly, alternate startup flows) would otherwise pass nil to
// runClusterUpdate, and ctx.Err() on a nil interface would panic.
// Codex P2 catch on PR #256.
func resolveLifecycleCtx() context.Context {
	if appLifecycleCtx == nil {
		return context.Background()
	}
	return appLifecycleCtx
}

// clusterUpdateAbortOnShutdown returns true if ctx has been cancelled,
// in which case it also transitions clusterUpdateState to "halted" and
// persists. Callers should `return` after a true result so the
// runClusterUpdate defer block can run its terminal cleanup
// (CompletedAt / Active=false / persist / generateUpdateReport).
//
// CL-3: this is the single observation point for appLifecycleCtx in the
// orchestrator. It is called at phase boundaries — never inside an
// updateNodeBatch iteration or after the CP self-update has started —
// so it cannot interrupt an in-flight node operation or a CP container
// restart. The semantic is "if shutdown beat us to the next phase,
// halt cleanly here; otherwise continue".
func clusterUpdateAbortOnShutdown(ctx context.Context) bool {
	if ctx.Err() == nil {
		return false
	}
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "halted"
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()
	logger.Println("cluster update HALTED: shutdown in progress")
	return true
}

// runClusterUpdate is the cluster rolling-update orchestrator. It is
// spawned by startClusterUpdate exactly once per admin-initiated update,
// parented to appLifecycleCtx (CL-3).
//
// Lifecycle ownership
// ===================
// The orchestrator's correctness across shutdown is bounded by the
// PERSISTENCE + RECOVERY CONTRACT, not by inner-loop cancellation:
//
//  1. Every Phase / Status transition is followed by
//     clusterUpdateState.persist() (atomicWriteFile, fsync per CL-7).
//  2. On next boot, recoverClusterUpdate translates any persisted
//     in-flight phase to a terminal recovery state — `updating_cp`
//     becomes `complete` (the CP container restart IS the self-update);
//     `updating_dps` becomes `halted` (admin resumes from GUI).
//  3. The defer below runs only when the goroutine returns normally,
//     not when the process is killed. Process kill mid-phase is safe
//     because the most recent persist() defines the on-disk reality.
//
// What ctx observation adds (CL-3)
// =================================
// Phase-boundary checks via clusterUpdateAbortOnShutdown make the
// "shutdown beat me to the next phase" case explicit: instead of
// silently continuing into the next batch / soak / CP update while
// the process is shutting down, the orchestrator marks Phase=halted
// and returns cleanly. Inner loops (drain sleep, gRPC, health poll,
// updater HTTP, canary soak time.Sleep) are intentionally NOT plumbed
// with ctx — they keep their own internal timeouts and the recovery
// contract above handles abrupt termination. Adding ctx to those
// loops would be the "broad update protocol redesign" CL-3 explicitly
// scopes out.
func runClusterUpdate(ctx context.Context) {
	defer func() {
		clusterUpdateState.mu.Lock()
		clusterUpdateState.CompletedAt = time.Now()
		clusterUpdateState.Active = false
		clusterUpdateState.mu.Unlock()
		clusterUpdateState.persist()
		generateUpdateReport(&clusterUpdateState)
	}()

	// CL-3 boundary 1: shutdown may have raced startClusterUpdate. If
	// appLifecycleCtx is already cancelled, halt before doing any work.
	if clusterUpdateAbortOnShutdown(ctx) {
		return
	}

	// Phase 1: Update DPs one at a time.
	nodes := globalClusterStore.ListNodes()
	totalNodes := len(nodes)

	// F6: Canary deployment — split nodes into canary batch and remainder.
	clusterUpdateState.mu.Lock()
	canaryCount := clusterUpdateState.CanaryCount
	canarySoakSec := clusterUpdateState.CanarySoak
	autoRollback := clusterUpdateState.AutoRollback
	clusterUpdateState.mu.Unlock()

	canaryNodes := nodes
	var remainingNodes []EnrolledNode
	if canaryCount > 0 && canaryCount < len(nodes) {
		canaryNodes = nodes[:canaryCount]
		remainingNodes = nodes[canaryCount:]
	} else {
		canaryCount = 0 // no canary phase
	}

	// Update canary nodes (or all nodes if no canary).
	if !updateNodeBatch(canaryNodes, totalNodes, autoRollback) {
		return // halted or auto-rolled back
	}

	// CL-3 boundary 2: shutdown may have arrived during the canary batch.
	// Halt before entering the canary soak / remaining batch.
	if clusterUpdateAbortOnShutdown(ctx) {
		return
	}

	// F6: Canary soak period — wait and verify health.
	if canaryCount > 0 && len(remainingNodes) > 0 {
		if !runCanarySoakAndRemaining(ctx, canaryNodes, remainingNodes, totalNodes, canarySoakSec, autoRollback) {
			return
		}
	}

	// CL-3 boundary 4: about to enter Phase 2 (CP self-update). Once
	// updateCPDirect starts, the container will restart; halting after
	// that point is meaningless. Bail here if shutdown got in first.
	if clusterUpdateAbortOnShutdown(ctx) {
		return
	}

	// Phase 2: Update CP.
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "updating_cp"
	targetTag := clusterUpdateState.TargetTag
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	// Read standby host from persisted HA config file (not from in-memory state)
	// to avoid CodeQL taint tracing from the HA enable API.
	standbyHost := loadStandbyHostFromConfig()
	if standbyHost != "" {
		updateCPWithHA(targetTag, standbyHost)
	} else {
		// Non-HA or standalone: update self directly.
		updateCPDirect(targetTag)
	}
}

// runCanarySoakAndRemaining handles the post-canary-batch soak period
// and the remaining-nodes batch. Extracted from runClusterUpdate to
// keep the orchestrator under the funlen / nestif lint thresholds; the
// semantics are byte-equivalent to the inline body before extraction.
// Returns true if the orchestrator should continue to Phase 2
// (CP self-update), false if it should halt (canary failed, shutdown
// at boundary 3, or remaining batch halted / auto-rolled-back).
func runCanarySoakAndRemaining(ctx context.Context, canaryNodes, remainingNodes []EnrolledNode, totalNodes, canarySoakSec int, autoRollback bool) bool {
	soakDur := time.Duration(canarySoakSec) * time.Second
	if soakDur < 30*time.Second {
		soakDur = 30 * time.Second
	}
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "canary_soak"
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	logger.Printf("cluster update: canary soak period (%s) — monitoring %d canary nodes",
		soakDur, len(canaryNodes))
	time.Sleep(soakDur)

	// F8: After soak, verify canary nodes are still healthy.
	clusterUpdateState.mu.Lock()
	canaryFails := clusterUpdateState.Failures
	clusterUpdateState.mu.Unlock()
	if canaryFails > 0 {
		if autoRollback {
			triggerAutoRollback("canary soak failed: %d failures during soak period", canaryFails)
		} else {
			clusterUpdateState.mu.Lock()
			clusterUpdateState.Phase = "halted"
			clusterUpdateState.mu.Unlock()
			clusterUpdateState.persist()
			logger.Printf("cluster update HALTED: canary soak failed (%d failures)", canaryFails)
		}
		return false
	}

	// CL-3 boundary 3: after the soak, before starting the remaining
	// batch. The soak itself is a bare time.Sleep and does not observe
	// ctx — interrupting it would change canary semantics.
	if clusterUpdateAbortOnShutdown(ctx) {
		return false
	}

	// Canary passed — continue with remaining nodes.
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()
	logger.Printf("cluster update: canary soak passed — proceeding with %d remaining nodes", len(remainingNodes))

	return updateNodeBatch(remainingNodes, totalNodes, autoRollback)
}

// updateCPDirect updates this CP directly via the local updater.
// The container will restart, killing this goroutine — persisted state
// is read on restart and marked complete.
func updateCPDirect(targetTag string) {
	logger.Printf("cluster update: updating Control Plane to %s", sanitizeLog(targetTag))
	body, _ := json.Marshal(map[string]string{
		"container":  "culvert",
		"target_tag": targetTag,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	resp, err := updaterRequest(ctx, http.MethodPost, "/api/update/apply", strings.NewReader(string(body)))
	if err != nil {
		clusterUpdateState.mu.Lock()
		clusterUpdateState.Phase = "cp_rolled_back"
		clusterUpdateState.mu.Unlock()
		clusterUpdateState.persist()
		logger.Printf("CP update failed: %v", err)
		return
	}
	defer resp.Body.Close()
	drainSSE(resp.Body)

	// If we reach here, the container wasn't restarted (unusual).
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "complete"
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()
}

// updateCPWithHA performs HA-aware CP update:
//  1. Update standby first via its local updater
//  2. Wait 30s settling period
//  3. Push final HASync + verify version match
//  4. Update leader (self) — container restarts, standby auto-promotes
func updateCPWithHA(targetTag, standbyHost string) {
	logger.Printf("cluster update HA: updating standby at %s first", sanitizeLog(standbyHost))

	// Step 1: Call standby's updater to apply the update.
	if !callStandbyApply(standbyHost, targetTag) {
		updateCPDirect(targetTag)
		return
	}

	// Step 2: Wait for standby to come back healthy (120s timeout).
	if !waitForStandbyHealth(standbyHost, 120*time.Second) {
		logger.Printf("cluster update HA: standby did not come back healthy — falling back to direct")
		updateCPDirect(targetTag)
		return
	}

	// Step 3: 30s settling period + final HASync verification.
	settleAndVerifySync()

	// Step 4: Update leader (self). After restart, standby auto-promotes
	// because leader stops responding to HASync (3 missed polls = promotion).
	logger.Printf("cluster update HA: updating leader (self) — standby will auto-promote")
	updateCPDirect(targetTag)
}

// loadStandbyHostFromConfig reads the standby peer address from the persisted
// HA config file on disk. Returns the extracted hostname, or "" if HA is not
// enabled or the config is missing. Reading from disk (not in-memory state)
// provides a clean data source for the outbound HTTP calls.
func loadStandbyHostFromConfig() string {
	cfg, err := loadHAConfig()
	if err != nil || !cfg.Enabled || cfg.Role != "leader" || cfg.PeerAddr == "" {
		return ""
	}
	return extractStandbyHost(cfg.PeerAddr)
}

// extractStandbyHost extracts and validates the hostname from a gRPC peer address.
// Returns "" if invalid. Only allows alphanumeric, dots, dashes, colons (IPv6).
func extractStandbyHost(peerAddr string) string {
	host := peerAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" {
		return ""
	}
	// Allowlist: hostname chars only (letters, digits, dots, dashes, colons for IPv6).
	for _, c := range host {
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		isSep := c == '.' || c == '-' || c == ':'
		if !isAlpha && !isDigit && !isSep {
			return ""
		}
	}
	return host
}

// callStandbyApply sends the update command to the standby's updater sidecar.
// The updater always listens on port 7123. Returns true if the request succeeded.
func callStandbyApply(host, targetTag string) bool {
	// SSRF guard: parse + scheme check + use parsed.String() to break taint chain.
	parsed, err := url.Parse("http://" + net.JoinHostPort(host, "7123") + "/api/update/apply")
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" {
		logger.Printf("cluster update HA: invalid standby URL")
		return false
	}

	body, _ := json.Marshal(map[string]string{
		"container":  "culvert",
		"target_tag": targetTag,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), strings.NewReader(string(body)))
	if reqErr != nil {
		logger.Printf("cluster update HA: standby request error: %v", reqErr)
		return false
	}
	tok := updaterToken()
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Printf("cluster update HA: standby update failed: %v — falling back to direct", err)
		return false
	}
	defer resp.Body.Close()
	drainSSE(resp.Body)

	if resp.StatusCode >= 400 {
		logger.Printf("cluster update HA: standby returned %d — falling back to direct", resp.StatusCode)
		return false
	}
	logger.Printf("cluster update HA: standby update initiated, waiting for it to come back")
	return true
}

// waitForStandbyHealth polls the standby's updater /healthz until it responds 200.
// The updater always listens on port 7123.
func waitForStandbyHealth(host string, timeout time.Duration) bool {
	// SSRF guard: parse + scheme check + use parsed.String() to break taint chain.
	parsed, err := url.Parse("http://" + net.JoinHostPort(host, "7123") + "/healthz")
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" {
		return false
	}
	target := parsed.String()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		resp, doErr := http.DefaultClient.Do(req)
		cancel()
		if doErr == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true
			}
		}
		time.Sleep(5 * time.Second)
	}
	return false
}

// settleAndVerifySync runs the 30s settling period and HA sync verification.
func settleAndVerifySync() {
	logger.Printf("cluster update HA: standby healthy, settling for 30s")
	time.Sleep(30 * time.Second)

	syncOK := false
	for attempt := range 3 {
		if performHASyncPush() {
			syncOK = true
			break
		}
		logger.Printf("cluster update HA: sync attempt %d/3 failed, retrying in 5s", attempt+1)
		time.Sleep(5 * time.Second)
	}
	if !syncOK {
		logger.Printf("cluster update HA: HASync verification failed — proceeding anyway (standby has recent state)")
	}
}

// performHASyncPush triggers the HA sync mechanism so the standby gets latest state.
// Returns true if the sync appears successful.
// performHASyncPush waits for the standby to sync with the leader (U23).
// The HASync is pull-based (standby polls leader every 5s). We wait for
// 2 sync cycles and verify the standby node is still connected.
func performHASyncPush() bool {
	// Wait 10s (2 sync cycles) to ensure the standby has caught up.
	time.Sleep(10 * time.Second)

	// Verify HA state is healthy — check that globalHA still has a peer.
	haStatus := globalHA.Status()
	if !haStatus.Enabled {
		logger.Printf("cluster update HA: HA is not enabled — skipping sync verification")
		return true // non-HA, nothing to verify
	}
	if haStatus.Role != "leader" {
		logger.Printf("cluster update HA: not leader (role=%s) — sync not applicable", haStatus.Role)
		return true
	}
	logger.Printf("cluster update HA: sync wait complete (peer=%s)", sanitizeLog(haStatus.PeerAddr))
	return true
}

// drainSSE reads an SSE response body to completion.
func drainSSE(body io.Reader) {
	buf := make([]byte, 4096)
	for {
		_, err := body.Read(buf)
		if err != nil {
			break
		}
	}
}

// updateNodeBatch updates a batch of nodes sequentially, checking the error
// budget after each. Returns false if the update was halted or auto-rolled back.
func updateNodeBatch(nodes []EnrolledNode, totalNodes int, autoRollback bool) bool {
	for i := range nodes {
		nodeID := nodes[i].NodeID
		// Check error budget.
		clusterUpdateState.mu.Lock()
		if clusterUpdateState.ConsecFails >= clusterUpdateState.ErrorBudget.MaxConsecutive {
			clusterUpdateState.mu.Unlock()
			if autoRollback {
				triggerAutoRollback("%d consecutive failures", clusterUpdateState.ConsecFails)
			} else {
				clusterUpdateState.mu.Lock()
				clusterUpdateState.Phase = "halted"
				clusterUpdateState.mu.Unlock()
				clusterUpdateState.persist()
				logger.Printf("cluster update HALTED: %d consecutive failures", clusterUpdateState.ConsecFails)
				fireAlert("cluster_update_halted", AlertPayload{
					Detail: fmt.Sprintf("halted after %d consecutive failures", clusterUpdateState.ConsecFails),
				})
			}
			return false
		}
		if totalNodes > 0 {
			failPct := (clusterUpdateState.Failures * 100) / totalNodes
			if failPct >= clusterUpdateState.ErrorBudget.MaxPercent {
				clusterUpdateState.mu.Unlock()
				if autoRollback {
					triggerAutoRollback("%d%% failure rate exceeds %d%% budget", failPct, clusterUpdateState.ErrorBudget.MaxPercent)
				} else {
					clusterUpdateState.mu.Lock()
					clusterUpdateState.Phase = "halted"
					clusterUpdateState.mu.Unlock()
					clusterUpdateState.persist()
					logger.Printf("cluster update HALTED: %d%% failure rate", failPct)
					fireAlert("cluster_update_halted", AlertPayload{
						Detail: fmt.Sprintf("halted: %d%% failure rate exceeds %d%% budget", failPct, clusterUpdateState.ErrorBudget.MaxPercent),
					})
				}
				return false
			}
		}
		targetTag := clusterUpdateState.TargetTag
		clusterUpdateState.mu.Unlock()

		success := updateSingleNode(nodeID, targetTag)

		clusterUpdateState.mu.Lock()
		if success {
			clusterUpdateState.ConsecFails = 0
		} else {
			clusterUpdateState.Failures++
			clusterUpdateState.ConsecFails++
		}
		clusterUpdateState.mu.Unlock()
		clusterUpdateState.persist()
	}
	return true
}

// triggerAutoRollback marks the update as auto-rolled-back and fires an alert (F8).
func triggerAutoRollback(reasonFmt string, args ...any) {
	reason := fmt.Sprintf(reasonFmt, args...)
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "auto_rollback"
	previousTag := clusterUpdateState.PreviousTag
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	logger.Printf("cluster update AUTO-ROLLBACK: %s — reverting to %s",
		strings.ReplaceAll(reason, "\n", ""), sanitizeLog(previousTag))
	fireAlert("cluster_update_halted", AlertPayload{
		Detail: fmt.Sprintf("auto-rollback triggered: %s — reverting to %s", reason, previousTag),
	})

	// Attempt to rollback updated nodes to previous tag.
	clusterUpdateState.mu.Lock()
	for _, ns := range clusterUpdateState.Nodes {
		if ns.Status == "complete" {
			ns.Status = "rolling_back"
		}
	}
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	// Send rollback to nodes that were successfully updated.
	clusterUpdateState.mu.Lock()
	rollbackNodes := make([]string, 0)
	for id, ns := range clusterUpdateState.Nodes {
		if ns.Status == "rolling_back" {
			rollbackNodes = append(rollbackNodes, id)
		}
	}
	clusterUpdateState.mu.Unlock()

	for _, nodeID := range rollbackNodes {
		ok := updateSingleNode(nodeID, previousTag)
		clusterUpdateState.mu.Lock()
		if ns, exists := clusterUpdateState.Nodes[nodeID]; exists {
			if ok {
				ns.Status = "rolled_back"
			} else {
				ns.Status = "rollback_failed"
			}
		}
		clusterUpdateState.mu.Unlock()
	}
	clusterUpdateState.persist()
}

func updateSingleNode(nodeID, targetTag string) bool {
	start := time.Now()

	// Mark draining.
	clusterUpdateState.mu.Lock()
	if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
		ns.Status = "draining"
		ns.StartedAt = time.Now().Format(time.RFC3339)
	}
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	if err := globalClusterStore.SetNodeDraining(nodeID, true); err != nil {
		logger.Printf("update node %s: failed to set draining: %v", sanitizeLog(nodeID), err)
	}
	time.Sleep(10 * time.Second) // grace period for in-flight requests

	// Send TriggerUpdate via gRPC.
	clusterUpdateState.mu.Lock()
	if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
		ns.Status = "updating"
	}
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	reqBytes, _ := json.Marshal(TriggerUpdateRequest{
		TargetTag: targetTag,
		Initiator: clusterUpdateState.Initiator,
	})

	err := sendGRPCToNode(nodeID, methodTriggerUpdate, reqBytes)
	if err != nil {
		clusterUpdateState.mu.Lock()
		if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
			ns.Status = "failed"
			ns.Detail = "gRPC TriggerUpdate failed: " + err.Error()
			ns.DurationS = int(time.Since(start).Seconds())
		}
		clusterUpdateState.mu.Unlock()
		if drainErr := globalClusterStore.SetNodeDraining(nodeID, false); drainErr != nil {
			logger.Printf("update node %s: failed to clear drain: %v", sanitizeLog(nodeID), drainErr)
		}
		logger.Printf("update node %s failed: %v", sanitizeLog(nodeID), err)
		return false
	}

	// Wait for node to come back healthy with the new version.
	clusterUpdateState.mu.Lock()
	if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
		ns.Status = "verifying"
	}
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	if waitForNodeVersion(nodeID, targetTag, 120*time.Second) {
		clusterUpdateState.mu.Lock()
		if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
			ns.Status = "complete"
			ns.NewVersion = targetTag
			ns.DurationS = int(time.Since(start).Seconds())
		}
		clusterUpdateState.mu.Unlock()
		if drainErr := globalClusterStore.SetNodeDraining(nodeID, false); drainErr != nil {
			logger.Printf("update node %s: failed to clear drain: %v", sanitizeLog(nodeID), drainErr)
		}
		logger.Printf("node %s updated successfully to %s", sanitizeLog(nodeID), sanitizeLog(targetTag))
		return true
	}

	// Timeout.
	clusterUpdateState.mu.Lock()
	if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
		ns.Status = "failed"
		ns.Detail = "health check timeout (120s)"
		ns.DurationS = int(time.Since(start).Seconds())
	}
	clusterUpdateState.mu.Unlock()
	if drainErr := globalClusterStore.SetNodeDraining(nodeID, false); drainErr != nil {
		logger.Printf("update node %s: failed to clear drain: %v", sanitizeLog(nodeID), drainErr)
	}
	logger.Printf("node %s update timeout", sanitizeLog(nodeID))
	return false
}

// waitForNodeVersion polls the cluster store until the given node reports the
// expected version and a "connected" status, or until the timeout elapses.
func waitForNodeVersion(nodeID, targetTag string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		nodes := globalClusterStore.ListNodes()
		for _, n := range nodes {
			if n.NodeID == nodeID && n.Version == targetTag && n.Status == "connected" {
				return true
			}
		}
	}
	return false
}

// sendGRPCToNode sends a gRPC request to a specific DP node.
// This is a simplified version — in production, CP maintains connections to DPs
// via the existing PushMetrics/GetConfig polling mechanism.
func sendGRPCToNode(nodeID, method string, reqBytes []byte) error {
	// Find node IP from cluster store.
	nodes := globalClusterStore.ListNodes()
	for _, n := range nodes {
		if n.NodeID == nodeID {
			if n.IPAddress == "" {
				return fmt.Errorf("node %s has no IP address", nodeID)
			}
			// DPs don't run gRPC servers — they poll the CP. We use the next
			// config sync to deliver update commands. Add to pending commands.
			pendingNodeUpdatesMu.Lock()
			pendingNodeUpdates[nodeID] = string(reqBytes)
			pendingNodeUpdatesMu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("node %s not found", nodeID)
}

// pendingNodeUpdates stores update commands to be delivered via config sync.
var (
	pendingNodeUpdatesMu sync.RWMutex
	pendingNodeUpdates   = map[string]string{}
)

// GetPendingUpdate returns and clears any pending update for a node.
func GetPendingUpdate(nodeID string) string {
	pendingNodeUpdatesMu.Lock()
	defer pendingNodeUpdatesMu.Unlock()
	cmd, ok := pendingNodeUpdates[nodeID]
	if !ok {
		return ""
	}
	delete(pendingNodeUpdates, nodeID)
	return cmd
}

// ── Crash recovery ──────────────────────────────────────────────────────────

func recoverClusterUpdate() {
	clusterUpdateState.load()

	clusterUpdateState.mu.Lock()
	defer clusterUpdateState.mu.Unlock()

	if !clusterUpdateState.Active {
		return
	}

	switch clusterUpdateState.Phase {
	case "complete", "failed", "halted":
		clusterUpdateState.Active = false
		return
	case "updating_cp":
		// CP was mid-update and restarted — we're now on the new version.
		clusterUpdateState.Phase = "complete"
		clusterUpdateState.CompletedAt = time.Now()
		clusterUpdateState.Active = false
		logger.Printf("cluster update recovered: CP update completed after restart")
	case "updating_dps":
		// DPs were being updated — reconcile from node versions.
		logger.Printf("cluster update interrupted: reconciling node versions...")
		// Mark as halted so admin can resume from GUI.
		clusterUpdateState.Phase = "halted"
		clusterUpdateState.Active = false
	case "canary":
		// Canary batch was being updated when the orchestrator was killed.
		// Mirror updating_dps semantics — the batch cannot resume automatically;
		// per-node Status values are preserved in the Nodes map so the admin
		// can see which canary nodes were already updated before halting.
		logger.Printf("cluster update interrupted during canary batch — halting; inspect Nodes map for per-node status")
		clusterUpdateState.Phase = "halted"
		clusterUpdateState.Active = false
	case "canary_soak":
		// Orchestrator was sleeping through the post-canary soak; the
		// post-soak failure-verification check did not run. No in-flight
		// node operations to reconcile. Halt so the admin decides whether
		// to abort or restart the rollout.
		logger.Printf("cluster update interrupted during canary soak — halting; soak verification did not complete")
		clusterUpdateState.Phase = "halted"
		clusterUpdateState.Active = false
	case "auto_rollback":
		// triggerAutoRollback was actively rolling back previously-updated
		// nodes to PreviousTag when the orchestrator was killed. Preserve
		// Phase=auto_rollback so the operator-visible status retains the
		// rollback context (apiClusterUpdateStatus surfaces Phase); per-node
		// Status (rolling_back / rolled_back / rollback_failed) preserved in
		// the Nodes map. Active=false ensures no zombie orchestrator.
		// Operator must inspect node versions to determine final state — the
		// recovery path explicitly does NOT re-attempt rollback (no
		// orchestrator is spawned by recoverClusterUpdate).
		logger.Printf("cluster update interrupted during auto-rollback — preserving Phase=auto_rollback for operator context; inspect Nodes map")
		clusterUpdateState.Active = false
	case "cp_rolled_back":
		// updateCPDirect set Phase=cp_rolled_back when the updater HTTP
		// request failed (before any container restart). In the normal flow
		// runClusterUpdate's defer immediately flips Active=false. Seeing
		// Active=true with this Phase on disk means a process kill in the
		// tiny window between the inner persist (update_cluster.go ~538)
		// and the defer's persist. The state is already terminal — DPs are
		// updated, CP is not. Preserve Phase so the operator-visible status
		// retains that signal; just flip Active.
		clusterUpdateState.Active = false
	}
}

// ── API handlers ────────────────────────────────────────────────────────────

// apiClusterUpdate starts a rolling cluster update.
// POST /api/update/cluster
func apiClusterUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}

	var req struct {
		TargetTag      string `json:"target_tag"`
		MaxConsecutive int    `json:"max_consecutive"`
		MaxPercent     int    `json:"max_percent"`
		CanaryCount    int    `json:"canary_count"`     // F6: number of canary nodes (0 = skip)
		CanarySoakSec  int    `json:"canary_soak_s"`    // F6: soak period in seconds (min 30)
		AutoRollback   bool   `json:"auto_rollback"`    // F8: auto-rollback on health breach
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.TargetTag == "" {
		http.Error(w, `{"error":"target_tag required"}`, http.StatusBadRequest)
		return
	}
	// U6: Validate tag format (OCI tag spec).
	tagRe := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	if !tagRe.MatchString(req.TargetTag) {
		http.Error(w, `{"error":"invalid target_tag format"}`, http.StatusBadRequest)
		return
	}
	if req.MaxConsecutive <= 0 {
		req.MaxConsecutive = 3
	}
	// U10: Enforce upper bounds on error budget to prevent unsafe rollouts.
	if req.MaxConsecutive > 10 {
		req.MaxConsecutive = 10
	}
	if req.MaxPercent <= 0 {
		req.MaxPercent = 20
	}
	if req.MaxPercent > 50 {
		req.MaxPercent = 50
	}

	actor, _, _ := net.SplitHostPort(r.RemoteAddr)
	if actor == "" {
		actor = r.RemoteAddr
	}
	budget := ErrorBudgetConfig{
		MaxConsecutive: req.MaxConsecutive,
		MaxPercent:     req.MaxPercent,
	}

	// F6/F8: Set canary and auto-rollback params before starting.
	clusterUpdateState.CanaryCount = req.CanaryCount
	clusterUpdateState.CanarySoak = req.CanarySoakSec
	clusterUpdateState.AutoRollback = req.AutoRollback

	if err := startClusterUpdate(req.TargetTag, actor, budget); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
		return
	}

	auditEvent(r, "cluster_update.start", "cluster",
		fmt.Sprintf("update to %s (budget: %d consec, %d%%)",
			sanitizeLog(req.TargetTag), budget.MaxConsecutive, budget.MaxPercent))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"}) //nolint:errcheck
}

// apiClusterUpdateStatus returns the current rolling update state.
// GET /api/update/cluster/status
func apiClusterUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, "viewer") {
		return
	}

	snap := clusterUpdateState.snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap) //nolint:errcheck
}
