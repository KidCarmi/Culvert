package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClusterMetrics_HARoleGauge verifies culvert_ha_role maps disabled/leader/
// standby to 0/1/2 via haRoleCode().
func TestClusterMetrics_HARoleGauge(t *testing.T) {
	restore := swapGlobalHA(t)
	defer restore()

	if got := haRoleCode(); got != 0 {
		t.Errorf("disabled role code = %d, want 0", got)
	}

	globalHA.mu.Lock()
	globalHA.role = "leader"
	globalHA.mu.Unlock()
	if got := haRoleCode(); got != 1 {
		t.Errorf("leader role code = %d, want 1", got)
	}

	globalHA.mu.Lock()
	globalHA.role = "standby"
	globalHA.mu.Unlock()
	if got := haRoleCode(); got != 2 {
		t.Errorf("standby role code = %d, want 2", got)
	}
}

// TestClusterMetrics_HAFailover_SuccessIncrements verifies a successful
// standby→leader promote() increments the failover counter.
func TestClusterMetrics_HAFailover_SuccessIncrements(t *testing.T) {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.mu.Unlock()

	before := statHAFailovers.Load()
	h.promote("", "", "", "", func() error { return nil })
	if got := statHAFailovers.Load(); got != before+1 {
		t.Errorf("ha_failovers = %d, want %d after successful promote", got, before+1)
	}
	if got := h.Status().Role; got != "leader" {
		t.Errorf("role = %q, want leader after promote", got)
	}
}

// TestClusterMetrics_HAFailover_FailedDoesNotIncrement verifies a promote whose
// onPromote callback errors does NOT increment the failover counter.
func TestClusterMetrics_HAFailover_FailedDoesNotIncrement(t *testing.T) {
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.mu.Unlock()

	before := statHAFailovers.Load()
	h.promote("", "", "", "", func() error { return errTestPromoteFail })
	if got := statHAFailovers.Load(); got != before {
		t.Errorf("ha_failovers = %d, want %d after failed promote", got, before)
	}
	if got := h.Status().Role; got != "standby" {
		t.Errorf("role = %q, want standby after failed promote", got)
	}
}

// TestClusterMetrics_HAFailover_EnableAsLeaderDoesNotIncrement verifies the
// initial designated-leader path is not counted as a failover.
func TestClusterMetrics_HAFailover_EnableAsLeaderDoesNotIncrement(t *testing.T) {
	restore := swapGlobalHA(t)
	defer restore()

	before := statHAFailovers.Load()
	globalHA.EnableAsLeader("cp2:50051")
	if got := statHAFailovers.Load(); got != before {
		t.Errorf("ha_failovers = %d, want %d after EnableAsLeader (not a failover)", got, before)
	}
}

// TestClusterMetrics_UpdateGauges verifies the rolling-update gauges reflect
// active/completed/total, and that an inactive update renders in_progress=0.
func TestClusterMetrics_UpdateGauges(t *testing.T) {
	clusterUpdateState.mu.Lock()
	origActive := clusterUpdateState.Active
	origNodes := clusterUpdateState.Nodes
	clusterUpdateState.mu.Unlock()
	t.Cleanup(func() {
		clusterUpdateState.mu.Lock()
		clusterUpdateState.Active = origActive
		clusterUpdateState.Nodes = origNodes
		clusterUpdateState.mu.Unlock()
	})

	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = true
	clusterUpdateState.Nodes = map[string]*NodeUpdateStatus{
		"a": {NodeID: "a", Status: "complete"},
		"b": {NodeID: "b", Status: "complete"},
		"c": {NodeID: "c", Status: "updating"},
	}
	clusterUpdateState.mu.Unlock()

	inProgress, completed, total := updateProgressGauges()
	if inProgress != 1 || completed != 2 || total != 3 {
		t.Errorf("updateProgressGauges() = (%d,%d,%d), want (1,2,3)", inProgress, completed, total)
	}

	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.mu.Unlock()
	if inProgress, _, _ := updateProgressGauges(); inProgress != 0 {
		t.Errorf("in_progress = %d, want 0 when inactive", inProgress)
	}
}

// TestClusterMetrics_PR3Rendered verifies /metrics renders all five families.
func TestClusterMetrics_PR3Rendered(t *testing.T) {
	oldTok := metricsToken
	t.Cleanup(func() { metricsToken = oldTok })
	metricsToken = ""

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_ha_role gauge",
		"culvert_ha_role ",
		"# TYPE culvert_ha_failovers_total counter",
		"culvert_ha_failovers_total ",
		"# TYPE culvert_cluster_update_in_progress gauge",
		"culvert_cluster_update_in_progress ",
		"# TYPE culvert_cluster_update_completed_nodes gauge",
		"culvert_cluster_update_completed_nodes ",
		"# TYPE culvert_cluster_update_total_nodes gauge",
		"culvert_cluster_update_total_nodes ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}

var errTestPromoteFail = errTestPromote{}

type errTestPromote struct{}

func (errTestPromote) Error() string { return "test promote failure" }
