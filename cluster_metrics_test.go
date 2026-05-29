package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestEnrollmentMetrics_TokenOutcomes verifies CL-9 PR1 token counters: a valid
// consume increments culvert_enrollment_tokens_consumed_total, an invalid token
// increments culvert_enrollment_failures_total. Delta-based for shuffle-safety.
func TestEnrollmentMetrics_TokenOutcomes(t *testing.T) {
	cs := newTestClusterStore(t)

	// Valid consume → one success.
	plaintext, err := cs.GenerateToken("dp-", "", "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	beforeOK := statEnrollTokensConsumed.Load()
	beforeFail := statEnrollFailures.Load()
	if _, err := cs.ValidateAndConsumeToken(plaintext, "dp-east-1", ""); err != nil {
		t.Fatalf("ValidateAndConsumeToken(valid): %v", err)
	}
	if got := statEnrollTokensConsumed.Load(); got != beforeOK+1 {
		t.Errorf("tokens_consumed = %d, want %d after valid consume", got, beforeOK+1)
	}
	if got := statEnrollFailures.Load(); got != beforeFail {
		t.Errorf("failures = %d, want %d (valid consume must not fail)", got, beforeFail)
	}

	// Invalid token → one failure, no success.
	beforeOK = statEnrollTokensConsumed.Load()
	beforeFail = statEnrollFailures.Load()
	if _, err := cs.ValidateAndConsumeToken("not-a-real-token", "dp-east-2", ""); err == nil {
		t.Fatal("ValidateAndConsumeToken(invalid) should have errored")
	}
	if got := statEnrollFailures.Load(); got != beforeFail+1 {
		t.Errorf("failures = %d, want %d after invalid token", got, beforeFail+1)
	}
	if got := statEnrollTokensConsumed.Load(); got != beforeOK {
		t.Errorf("tokens_consumed = %d, want %d (invalid token must not consume)", got, beforeOK)
	}
}

// TestClusterStore_NodeCounts verifies total vs connected accounting.
func TestClusterStore_NodeCounts(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "n1", Status: "connected"})
	cs.RegisterNode(&EnrolledNode{NodeID: "n2", Status: "connected"})
	cs.RegisterNode(&EnrolledNode{NodeID: "n3", Status: "disconnected"})
	cs.RegisterNode(&EnrolledNode{NodeID: "n4", Status: "revoked"})

	total, connected := cs.NodeCounts()
	if total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	if connected != 2 {
		t.Errorf("connected = %d, want 2", connected)
	}
}

// TestEnrollmentMetrics_Rendered verifies /metrics renders all four families
// with the expected node-count values from the active globalClusterStore.
func TestEnrollmentMetrics_Rendered(t *testing.T) {
	oldTok := metricsToken
	oldStore := globalClusterStore
	t.Cleanup(func() {
		metricsToken = oldTok
		globalClusterStore = oldStore
	})
	metricsToken = ""

	cs := newTestClusterStore(t)
	cs.RegisterNode(&EnrolledNode{NodeID: "a", Status: "connected"})
	cs.RegisterNode(&EnrolledNode{NodeID: "b", Status: "disconnected"})
	cs.RegisterNode(&EnrolledNode{NodeID: "c", Status: "connected"})
	globalClusterStore = cs

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_enrollment_tokens_consumed_total counter",
		"culvert_enrollment_tokens_consumed_total ",
		"# TYPE culvert_enrollment_failures_total counter",
		"culvert_enrollment_failures_total ",
		"# TYPE culvert_enrollment_nodes gauge",
		"culvert_enrollment_nodes 3",
		"# TYPE culvert_enrollment_nodes_connected gauge",
		"culvert_enrollment_nodes_connected 2",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}
