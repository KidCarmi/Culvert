package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClusterUpdateState_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster_update.json")

	state := &ClusterUpdateState{
		Active:    true,
		TargetTag: "v2.0.0",
		Initiator: "admin",
		StartedAt: time.Now(),
		Phase:     "updating_dps",
		Nodes: map[string]*NodeUpdateStatus{
			"dp-1": {NodeID: "dp-1", Status: "pending"},
			"dp-2": {NodeID: "dp-2", Status: "complete"},
		},
		ErrorBudget: ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20},
	}

	// Serialize
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Deserialize
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var loaded ClusterUpdateState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !loaded.Active {
		t.Error("loaded.Active should be true")
	}
	if loaded.TargetTag != "v2.0.0" {
		t.Errorf("TargetTag = %q, want v2.0.0", loaded.TargetTag)
	}
	if loaded.Phase != "updating_dps" {
		t.Errorf("Phase = %q, want updating_dps", loaded.Phase)
	}
	if len(loaded.Nodes) != 2 {
		t.Errorf("len(Nodes) = %d, want 2", len(loaded.Nodes))
	}
	if loaded.Nodes["dp-2"].Status != "complete" {
		t.Errorf("dp-2 status = %q, want complete", loaded.Nodes["dp-2"].Status)
	}
}

func TestErrorBudgetConfig_Defaults(t *testing.T) {
	cfg := ErrorBudgetConfig{}
	if cfg.MaxConsecutive != 0 {
		t.Errorf("default MaxConsecutive = %d, want 0", cfg.MaxConsecutive)
	}
	cfg.MaxConsecutive = 3
	cfg.MaxPercent = 20
	if cfg.MaxConsecutive != 3 {
		t.Error("MaxConsecutive not set")
	}
}

func TestNodeUpdateStatus_JSON(t *testing.T) {
	ns := NodeUpdateStatus{
		NodeID:     "dp-east-1",
		Status:     "updating",
		OldVersion: "v1.0.0",
		Detail:     "pulling image",
		DurationS:  45,
	}
	data, err := json.Marshal(ns)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded NodeUpdateStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.NodeID != "dp-east-1" {
		t.Errorf("NodeID = %q", decoded.NodeID)
	}
	if decoded.Status != "updating" {
		t.Errorf("Status = %q", decoded.Status)
	}
}

func TestAPIClusterUpdateStatus(t *testing.T) {
	// Ensure clean state
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.Nodes = nil
	clusterUpdateState.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/update/cluster/status", nil)
	w := httptest.NewRecorder()
	apiClusterUpdateStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["active"] != false {
		t.Errorf("active = %v, want false", resp["active"])
	}
}

func TestAPIClusterUpdateStatus_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/update/cluster/status", nil)
	w := httptest.NewRecorder()
	apiClusterUpdateStatus(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIClusterUpdate_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/cluster", nil)
	w := httptest.NewRecorder()
	apiClusterUpdate(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIClusterUpdate_Unauthorized(t *testing.T) {
	// Without auth session, admin endpoints return 403
	req := httptest.NewRequest(http.MethodPost, "/api/update/cluster",
		strings.NewReader(`{"target_tag":"v2.0.0"}`))
	w := httptest.NewRecorder()
	apiClusterUpdate(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestUpdateReport_JSON(t *testing.T) {
	report := UpdateReport{
		ReportVersion: 1,
		UpdateID:      "upd-20260407-143022",
		TargetTag:     "v2.1.0",
		PreviousTag:   "v2.0.3",
		Initiator:     "admin",
		StartedAt:     time.Now().Format(time.RFC3339),
		CompletedAt:   time.Now().Format(time.RFC3339),
		DurationS:     120,
		Result:        "complete",
		Nodes: []*NodeUpdateStatus{
			{NodeID: "dp-1", Status: "complete", OldVersion: "v2.0.3", NewVersion: "v2.1.0", DurationS: 45},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), "upd-20260407-143022") {
		t.Error("report ID not found in JSON")
	}
}

func TestStartClusterUpdate_AlreadyActive(t *testing.T) {
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = true
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.mu.Unlock()

	err := startClusterUpdate("v2.0.0", "admin", ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20})
	if err == nil {
		t.Error("expected error when update already active")
	}

	// Cleanup
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.mu.Unlock()
}

func TestExtractStandbyHost(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"standby.host:50051", "standby.host"},
		{"10.0.0.5:50051", "10.0.0.5"},
		{"[::1]:50051", "::1"},
		{"simple-host", "simple-host"},
		{"host-with-dash.example.com:9090", "host-with-dash.example.com"},
		{"", ""},
		{"host with spaces:50051", ""},
		{"evil;rm -rf:50051", ""},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, tt := range tests {
		got := extractStandbyHost(tt.input)
		if got != tt.want {
			t.Errorf("extractStandbyHost(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLoadStandbyHostFromConfig(t *testing.T) {
	// Just verify it doesn't panic; result depends on test environment state
	host := loadStandbyHostFromConfig()
	t.Logf("loadStandbyHostFromConfig = %q", host)
}

func TestDrainSSE(t *testing.T) {
	r := strings.NewReader("data: {\"step\":\"complete\"}\n\ndata: done\n\n")
	drainSSE(r)
	// Should not panic or hang
}

func TestClusterUpdateSnapshot(t *testing.T) {
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = true
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.TargetTag = "v3.0.0"
	clusterUpdateState.Nodes = map[string]*NodeUpdateStatus{
		"dp-1": {NodeID: "dp-1", Status: "complete"},
	}
	clusterUpdateState.mu.Unlock()

	snap := clusterUpdateState.snapshot()
	if !snap.Active {
		t.Error("snapshot Active should be true")
	}
	if snap.Phase != "updating_dps" {
		t.Errorf("snapshot Phase = %q", snap.Phase)
	}
	if snap.TargetTag != "v3.0.0" {
		t.Errorf("snapshot TargetTag = %q", snap.TargetTag)
	}
	if len(snap.Nodes) != 1 {
		t.Errorf("snapshot Nodes len = %d", len(snap.Nodes))
	}

	// Cleanup
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.Nodes = nil
	clusterUpdateState.mu.Unlock()
}

func TestGetPendingUpdate_NoPending(t *testing.T) {
	tag := GetPendingUpdate("dp-unknown")
	if tag != "" {
		t.Errorf("expected empty pending update, got %q", tag)
	}
}

func TestRecoverClusterUpdate_NoFile(t *testing.T) {
	// Should not panic when no state file exists
	recoverClusterUpdate()
}
