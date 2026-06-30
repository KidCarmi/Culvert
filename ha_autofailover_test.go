package main

// ha_autofailover_test.go — Slice 1a (ADR-0004): HA defaults to MANUAL
// failover. These tests pin the opt-in semantics of --ha-auto-failover /
// the auto_failover API field: default OFF, persisted in ha_config.json,
// surfaced in status, and carried into the standby deploy command only when
// explicitly enabled.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withCPRoleForHA installs a control-plane clusterRole + a temp HA config dir
// and returns a cleanup func. Mirrors the fixture used by TestAPIClusterHA_Enable.
func withCPRoleForHA(t *testing.T) func() {
	t.Helper()
	cleanup := swapGlobalHA(t)
	origPath := clusterDBPathGlobal
	clusterDBPathGlobal = t.TempDir() + "/cluster.json"

	clusterRoleMu.Lock()
	origRole := clusterRole.role
	origAddr := clusterRole.grpcAddr
	clusterRole.role = "control-plane"
	clusterRole.grpcAddr = ":50051"
	clusterRoleMu.Unlock()

	return func() {
		globalHA.Stop()
		cleanup()
		clusterDBPathGlobal = origPath
		clusterRoleMu.Lock()
		clusterRole.role = origRole
		clusterRole.grpcAddr = origAddr
		clusterRoleMu.Unlock()
	}
}

func enableHAViaAPI(t *testing.T, body string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/cluster/ha", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	w := httptest.NewRecorder()
	apiClusterHA(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("enable HA: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// Default (no auto_failover in body) → MANUAL: deploy command must NOT carry
// the flag, and status reports auto_failover=false.
func TestHA_AutoFailover_DefaultOff(t *testing.T) {
	defer withCPRoleForHA(t)()

	resp := enableHAViaAPI(t, `{"leader_addr":"cp1.internal:50051"}`)
	if resp["auto_failover"] != false {
		t.Errorf("enable response auto_failover = %v, want false (default)", resp["auto_failover"])
	}
	cmd, _ := resp["deploy_cmd"].(string)
	if strings.Contains(cmd, "--ha-auto-failover") {
		t.Errorf("default deploy_cmd must NOT carry --ha-auto-failover: %s", cmd)
	}
	if globalHA.autoFailoverEnabled() {
		t.Error("globalHA.autoFailoverEnabled() must be false by default")
	}
	if globalHA.Status().AutoFailover {
		t.Error("Status().AutoFailover must be false by default")
	}
}

// Explicit opt-in (auto_failover:true) → AUTOMATIC: flag is persisted, surfaced,
// and carried into the deploy command so the standby starts with it.
func TestHA_AutoFailover_OptIn(t *testing.T) {
	defer withCPRoleForHA(t)()

	resp := enableHAViaAPI(t, `{"leader_addr":"cp1.internal:50051","auto_failover":true}`)
	if resp["auto_failover"] != true {
		t.Errorf("enable response auto_failover = %v, want true", resp["auto_failover"])
	}
	cmd, _ := resp["deploy_cmd"].(string)
	if !strings.Contains(cmd, "--ha-auto-failover") {
		t.Errorf("opt-in deploy_cmd must carry --ha-auto-failover: %s", cmd)
	}
	if !globalHA.autoFailoverEnabled() {
		t.Error("globalHA.autoFailoverEnabled() must be true after opt-in")
	}

	// Status round-trips the flag for the GUI.
	if !globalHA.Status().AutoFailover {
		t.Error("Status().AutoFailover must be true after opt-in")
	}
}

// The preference survives a save/load of ha_config.json (leader-restart path).
func TestHA_Config_RoundTripsAutoFailover(t *testing.T) {
	origPath := clusterDBPathGlobal
	clusterDBPathGlobal = t.TempDir() + "/cluster.json"
	defer func() { clusterDBPathGlobal = origPath }()

	for _, want := range []bool{true, false} {
		if err := saveHAConfig(&haConfig{
			Enabled:      true,
			Token:        "tok",
			PeerAddr:     "cp-peer:50051",
			Role:         "leader",
			AutoFailover: want,
		}); err != nil {
			t.Fatalf("save: %v", err)
		}
		got, err := loadHAConfig()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if got.AutoFailover != want {
			t.Errorf("AutoFailover round-trip = %v, want %v", got.AutoFailover, want)
		}
	}
}
