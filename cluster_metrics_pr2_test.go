package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestClusterMetrics_HeartbeatDisconnects verifies CL-9 PR2: a connected node
// going stale increments culvert_heartbeat_disconnects_total exactly once, and a
// node already disconnected does not increment again. Delta-based; no sleeps.
func TestClusterMetrics_HeartbeatDisconnects(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{
		NodeID:   "n1",
		Status:   "connected",
		LastSeen: time.Now().Add(-2 * heartbeatTimeout), // stale → should disconnect
	})

	before := statHeartbeatDisconnects.Load()
	cs.checkHeartbeats()
	if got := statHeartbeatDisconnects.Load(); got != before+1 {
		t.Fatalf("heartbeat_disconnects = %d, want %d after connected→disconnected", got, before+1)
	}
	if n, ok := cs.GetNode("n1"); !ok || n.Status != "disconnected" {
		t.Fatalf("node n1 status = %v, want disconnected", n)
	}

	// Already disconnected: a second check must not re-increment.
	before2 := statHeartbeatDisconnects.Load()
	cs.checkHeartbeats()
	if got := statHeartbeatDisconnects.Load(); got != before2 {
		t.Errorf("heartbeat_disconnects = %d, want %d (already-disconnected node must not re-count)", got, before2)
	}
}

// TestClusterMetrics_StoreSaves_SavePath verifies Save() increments the cadence
// counter (Save delegates to the saveLocked chokepoint).
func TestClusterMetrics_StoreSaves_SavePath(t *testing.T) {
	cs := newTestClusterStore(t)
	before := statClusterStoreSaves.Load()
	if err := cs.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := statClusterStoreSaves.Load(); got != before+1 {
		t.Errorf("cluster_store_saves = %d, want %d after Save()", got, before+1)
	}
}

// TestClusterMetrics_StoreSaves_DirectSaveLockedPath verifies a mutation that
// calls saveLocked() directly (ValidateAndConsumeToken) also increments the
// counter — proving the chokepoint covers direct callers, not just Save().
func TestClusterMetrics_StoreSaves_DirectSaveLockedPath(t *testing.T) {
	cs := newTestClusterStore(t)
	plaintext, err := cs.GenerateToken("dp-", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	before := statClusterStoreSaves.Load()
	if _, err := cs.ValidateAndConsumeToken(plaintext, "dp-1", ""); err != nil {
		t.Fatalf("ValidateAndConsumeToken: %v", err)
	}
	if got := statClusterStoreSaves.Load(); got != before+1 {
		t.Errorf("cluster_store_saves = %d, want %d after direct saveLocked() path", got, before+1)
	}
}

// TestClusterMetrics_PR2Rendered verifies /metrics renders both families.
func TestClusterMetrics_PR2Rendered(t *testing.T) {
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
		"# TYPE culvert_heartbeat_disconnects_total counter",
		"culvert_heartbeat_disconnects_total ",
		"# TYPE culvert_cluster_store_saves_total counter",
		"culvert_cluster_store_saves_total ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}
