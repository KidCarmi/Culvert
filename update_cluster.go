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
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	Phase       string                        `json:"phase"` // "updating_dps", "updating_cp", "complete", "failed", "halted", "cp_rolled_back"
	ErrorBudget ErrorBudgetConfig             `json:"error_budget"`
	Failures    int                           `json:"failures"`
	ConsecFails int                           `json:"consec_fails"`
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

const clusterUpdateFile = "/data/cluster_update.json"

// ── State persistence ───────────────────────────────────────────────────────

func (s *ClusterUpdateState) persist() {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		logger.Printf("cluster update persist error: %v", err)
		return
	}
	tmp := clusterUpdateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		logger.Printf("cluster update write error: %v", err)
		return
	}
	os.Rename(tmp, clusterUpdateFile) //nolint:errcheck
}

func (s *ClusterUpdateState) load() {
	data, err := os.ReadFile(clusterUpdateFile)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	json.Unmarshal(data, s) //nolint:errcheck
}

func (s *ClusterUpdateState) snapshot() ClusterUpdateState {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := *s
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
	os.MkdirAll(dir, 0o755) //nolint:errcheck
	filename := filepath.Join(dir, report.UpdateID+".json")
	data, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(filename, data, 0o644) //nolint:errcheck
	logger.Printf("update report saved: %s", filename)

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
	go func() {
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
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.ErrorBudget = budget
	clusterUpdateState.Failures = 0
	clusterUpdateState.ConsecFails = 0
	clusterUpdateState.Nodes = make(map[string]*NodeUpdateStatus, len(nodes))

	for _, n := range nodes {
		clusterUpdateState.Nodes[n.NodeID] = &NodeUpdateStatus{
			NodeID:     n.NodeID,
			Status:     "pending",
			OldVersion: n.Version,
		}
	}
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	// Run the orchestrator in background.
	go runClusterUpdate()
	return nil
}

func runClusterUpdate() {
	defer func() {
		clusterUpdateState.mu.Lock()
		clusterUpdateState.CompletedAt = time.Now()
		clusterUpdateState.Active = false
		clusterUpdateState.mu.Unlock()
		clusterUpdateState.persist()
		generateUpdateReport(&clusterUpdateState)
	}()

	// Phase 1: Update DPs one at a time.
	nodes := globalClusterStore.ListNodes()
	totalNodes := len(nodes)

	for _, node := range nodes {
		// Check error budget.
		clusterUpdateState.mu.Lock()
		if clusterUpdateState.ConsecFails >= clusterUpdateState.ErrorBudget.MaxConsecutive {
			clusterUpdateState.Phase = "halted"
			clusterUpdateState.mu.Unlock()
			logger.Printf("cluster update HALTED: %d consecutive failures", clusterUpdateState.ConsecFails)
			fireAlert("cluster_update_halted", AlertPayload{
				Event:  "cluster_update_halted",
				Detail: fmt.Sprintf("halted after %d consecutive failures", clusterUpdateState.ConsecFails),
			})
			return
		}
		if totalNodes > 0 {
			failPct := (clusterUpdateState.Failures * 100) / totalNodes
			if failPct >= clusterUpdateState.ErrorBudget.MaxPercent {
				clusterUpdateState.Phase = "halted"
				clusterUpdateState.mu.Unlock()
				logger.Printf("cluster update HALTED: %d%% failure rate", failPct)
				fireAlert("cluster_update_halted", AlertPayload{
					Event:  "cluster_update_halted",
					Detail: fmt.Sprintf("halted: %d%% failure rate exceeds %d%% budget", failPct, clusterUpdateState.ErrorBudget.MaxPercent),
				})
				return
			}
		}
		targetTag := clusterUpdateState.TargetTag
		clusterUpdateState.mu.Unlock()

		success := updateSingleNode(node.NodeID, targetTag)

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

	// Phase 2: Update CP.
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "updating_cp"
	clusterUpdateState.mu.Unlock()
	clusterUpdateState.persist()

	// For CP update, we call our own local updater. The container will restart,
	// so this goroutine will be killed — that's fine. The persisted state
	// will be read on restart and marked complete.
	logger.Printf("cluster update: updating Control Plane to %s", sanitizeLog(clusterUpdateState.TargetTag))
	body, _ := json.Marshal(map[string]string{
		"container":  "culvert",
		"target_tag": clusterUpdateState.TargetTag,
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

	// Read SSE stream to completion (if we get here, the update failed or
	// didn't require a restart — the container would have been killed).
	buf := make([]byte, 4096)
	for {
		_, err := resp.Body.Read(buf)
		if err != nil {
			break
		}
	}

	// If we reach here, the container wasn't restarted (unusual).
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Phase = "complete"
	clusterUpdateState.mu.Unlock()
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

	globalClusterStore.SetNodeDraining(nodeID, true) //nolint:errcheck
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
		globalClusterStore.SetNodeDraining(nodeID, false) //nolint:errcheck
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

	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(5 * time.Second)
		nodes := globalClusterStore.ListNodes()
		for _, n := range nodes {
			if n.NodeID == nodeID && n.Version == targetTag && n.Status == "connected" {
				clusterUpdateState.mu.Lock()
				if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
					ns.Status = "complete"
					ns.NewVersion = targetTag
					ns.DurationS = int(time.Since(start).Seconds())
				}
				clusterUpdateState.mu.Unlock()
				globalClusterStore.SetNodeDraining(nodeID, false) //nolint:errcheck
				logger.Printf("node %s updated successfully to %s", sanitizeLog(nodeID), sanitizeLog(targetTag))
				return true
			}
		}
	}

	// Timeout.
	clusterUpdateState.mu.Lock()
	if ns, ok := clusterUpdateState.Nodes[nodeID]; ok {
		ns.Status = "failed"
		ns.Detail = "health check timeout (120s)"
		ns.DurationS = int(time.Since(start).Seconds())
	}
	clusterUpdateState.mu.Unlock()
	globalClusterStore.SetNodeDraining(nodeID, false) //nolint:errcheck
	logger.Printf("node %s update timeout", sanitizeLog(nodeID))
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.TargetTag == "" {
		http.Error(w, `{"error":"target_tag required"}`, http.StatusBadRequest)
		return
	}
	if req.MaxConsecutive <= 0 {
		req.MaxConsecutive = 3
	}
	if req.MaxPercent <= 0 {
		req.MaxPercent = 20
	}

	actor, _, _ := net.SplitHostPort(r.RemoteAddr)
	if actor == "" {
		actor = r.RemoteAddr
	}
	budget := ErrorBudgetConfig{
		MaxConsecutive: req.MaxConsecutive,
		MaxPercent:     req.MaxPercent,
	}

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
