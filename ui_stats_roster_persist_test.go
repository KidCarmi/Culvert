package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestAPIStats_SurfacesRosterPersistCounters pins that the CHAOS-70 roster
// persistence counters reach the dashboard poll, not only /metrics.
func TestAPIStats_SurfacesRosterPersistCounters(t *testing.T) {
	resetRosterPersistCountersForTest()
	t.Cleanup(resetRosterPersistCountersForTest)
	rosterPersistRefused.Store(2)
	rosterPersistBestEffort.Store(5)

	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/stats", http.NoBody))
	r.RemoteAddr = "198.51.100.8:9999"
	apiStats(w, r)

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	if got, _ := body["adminRosterPersistFailures"].(float64); got != 2 {
		t.Errorf("adminRosterPersistFailures = %v, want 2", body["adminRosterPersistFailures"])
	}
	if got, _ := body["adminRosterPersistDegraded"].(float64); got != 5 {
		t.Errorf("adminRosterPersistDegraded = %v, want 5", body["adminRosterPersistDegraded"])
	}
}

// TestUI_RosterPersistHintIsWired pins that the SPA actually reads both fields.
func TestUI_RosterPersistHintIsWired(t *testing.T) {
	b, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"roster-persist-hint", "adminRosterPersistFailures", "adminRosterPersistDegraded"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("static/index.html does not reference %q", want)
		}
	}
}
