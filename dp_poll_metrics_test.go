package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDPPollHistogram_ObserveAndRender verifies CL-9 PR4: dpPollHist.Observe
// advances count/sum/buckets, and /metrics renders the bucket/sum/count family.
// Delta-based for shuffle-safety; no network, no sleeps.
func TestDPPollHistogram_ObserveAndRender(t *testing.T) {
	oldTok := metricsToken
	t.Cleanup(func() { metricsToken = oldTok })
	metricsToken = ""

	beforeCount := atomic.LoadInt64(&dpPollHist.total)
	dpPollHist.Observe(0.02) // → le="0.025" bucket

	if got := atomic.LoadInt64(&dpPollHist.total); got != beforeCount+1 {
		t.Fatalf("dpPollHist count = %d, want %d after one Observe", got, beforeCount+1)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_dp_poll_duration_seconds histogram",
		"culvert_dp_poll_duration_seconds_bucket{le=\"0.025\"}",
		"culvert_dp_poll_duration_seconds_bucket{le=\"+Inf\"}",
		"culvert_dp_poll_duration_seconds_sum ",
		"culvert_dp_poll_duration_seconds_count ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n--- body ---\n%s", want, body)
		}
	}
}
