package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/secscan"
)

// TestMetrics_ClamAVScanErrorsDualEmit pins the T-31 terminology-governance
// fix (docs/engineering/TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-28.md): the
// legacy culvert_clam_scan_errors_total series and its canonical
// culvert_clamav_scan_errors_total counterpart must always render the exact
// same value from /metrics, so a dashboard built against the culvert_clamav_*
// prefix never silently misses ClamAV scan-error volume.
func TestMetrics_ClamAVScanErrorsDualEmit(t *testing.T) {
	oldTok := metricsToken
	t.Cleanup(func() { metricsToken = oldTok })
	metricsToken = ""

	errCount := secscan.Counters().ClamScanError

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", http.NoBody)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	for _, want := range []string{
		"# TYPE culvert_clam_scan_errors_total counter",
		"# TYPE culvert_clamav_scan_errors_total counter",
		fmt.Sprintf("culvert_clam_scan_errors_total %d", errCount),
		fmt.Sprintf("culvert_clamav_scan_errors_total %d", errCount),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}
