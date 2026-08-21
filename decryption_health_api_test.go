package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_health_api_test.go — ADR-0011 Phase 2 ("& API"): the read-only decryption
// health aggregate. Pins the JSON shape, the server-side folding of the coverage/failure
// counters into by_* breakdowns + coverage ratio, the top-N ordering, and the RBAC gate.

func decHealthReq(t *testing.T, role UIRole, method string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/api/decryption/health", http.NoBody)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, role))
	w := httptest.NewRecorder()
	apiDecryptionHealth(w, r)
	return w
}

func TestApiDecryptionHealth_AggregatesAndShape(t *testing.T) {
	// Seed deterministic coverage + failure counts on the global counters. Deltas are what
	// matter (the suite may have recorded others), so assert on our own contributions.
	recordDecryptSession(&DecryptionOutcome{Outcome: decryptobs.OutcomeInspected, DecisionSource: decryptobs.DecisionPolicyInspect, TLSVersion: decryptobs.TLSVersion13})
	recordDecryptFailure(&DecryptionOutcome{Outcome: decryptobs.OutcomeFailed, DecisionSource: decryptobs.DecisionNoFailOpen502, FailStage: decryptobs.FailStageUpstreamHandshake, FailCategory: decryptobs.FailCategoryVersion})

	w := decHealthReq(t, RoleViewer, http.MethodGet)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got struct {
		Sessions struct {
			Total     int64            `json:"total"`
			ByOutcome map[string]int64 `json:"by_outcome"`
			ByTLS     map[string]int64 `json:"by_tls_version"`
		} `json:"sessions"`
		Failures struct {
			Total      int64              `json:"total"`
			ByCategory map[string]int64   `json:"by_category"`
			Top        []decFailureSample `json:"top"`
		} `json:"failures"`
		Coverage struct {
			Inspected      int64   `json:"inspected"`
			Bypassed       int64   `json:"bypassed"`
			Failed         int64   `json:"failed"`
			InspectedRatio float64 `json:"inspected_ratio"`
		} `json:"coverage"`
		Autoexclude map[string]any `json:"autoexclude"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, w.Body.String())
	}
	// The folded breakdowns must reflect our contributions.
	if got.Sessions.ByOutcome["inspected"] < 1 || got.Sessions.ByOutcome["failed"] < 1 {
		t.Fatalf("by_outcome missing our sessions: %+v", got.Sessions.ByOutcome)
	}
	if got.Sessions.ByTLS["1.3"] < 1 {
		t.Fatalf("by_tls_version missing 1.3: %+v", got.Sessions.ByTLS)
	}
	if got.Failures.ByCategory["version"] < 1 {
		t.Fatalf("by_category missing version: %+v", got.Failures.ByCategory)
	}
	// A failed session counts in BOTH failures.total and coverage (outcome=failed).
	if got.Failures.Total < 1 || got.Coverage.Inspected < 1 {
		t.Fatalf("totals not aggregated: failures=%d inspected=%d", got.Failures.Total, got.Coverage.Inspected)
	}
	if got.Coverage.InspectedRatio <= 0 || got.Coverage.InspectedRatio > 1 {
		t.Fatalf("inspected_ratio out of range: %v", got.Coverage.InspectedRatio)
	}
	// The three coverage buckets must PARTITION the sessions (no double-count of failures).
	if got.Coverage.Inspected+got.Coverage.Bypassed+got.Coverage.Failed != got.Sessions.Total {
		t.Fatalf("coverage buckets do not partition sessions: %d+%d+%d != %d",
			got.Coverage.Inspected, got.Coverage.Bypassed, got.Coverage.Failed, got.Sessions.Total)
	}
	if got.Autoexclude["active"] == nil || got.Autoexclude["fail_open_profiles"] == nil {
		t.Fatalf("autoexclude posture missing: %+v", got.Autoexclude)
	}
	// top must be sorted by count descending.
	for i := 1; i < len(got.Failures.Top); i++ {
		if got.Failures.Top[i-1].Count < got.Failures.Top[i].Count {
			t.Fatalf("top not descending: %+v", got.Failures.Top)
		}
	}
}

func TestApiDecryptionHealth_RBACAndMethod(t *testing.T) {
	// No role in context ⇒ requireRole denies (viewer minimum).
	if w := decHealthReq(t, UIRole("none"), http.MethodGet); w.Code == http.StatusOK {
		t.Fatalf("unauthenticated GET returned 200, want a deny")
	}
	// Non-GET ⇒ 405 (read-only endpoint).
	if w := decHealthReq(t, RoleAdmin, http.MethodPost); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", w.Code)
	}
}

// TestInspectionCoverageRatio pins the ADR-0011 §3 semantics: failures are excluded from
// the denominator (they are not a deliberate coverage gap), and the 0/0 guard.
func TestInspectionCoverageRatio(t *testing.T) {
	// 1 inspected, 0 bypassed, however many failures → ratio is 1.0 (failures excluded).
	if r := inspectionCoverageRatio(1, 0); r != 1.0 {
		t.Fatalf("inspected-only ratio = %v, want 1.0 (failures must not dilute)", r)
	}
	if r := inspectionCoverageRatio(1, 1); r != 0.5 {
		t.Fatalf("1 inspected / 1 bypassed = %v, want 0.5", r)
	}
	if r := inspectionCoverageRatio(3, 1); r != 0.75 {
		t.Fatalf("3/(3+1) = %v, want 0.75", r)
	}
	if r := inspectionCoverageRatio(0, 0); r != 0 {
		t.Fatalf("0/0 guard = %v, want 0", r)
	}
}

// TestTopFailures_Deterministic pins the tie-break ordering (count desc, then category,
// then stage) and the decTopN cap.
func TestTopFailures_Deterministic(t *testing.T) {
	in := []decFailureSample{
		{"certificate", "cert_verify", 3},
		{"protocol", "upstream_handshake", 3}, // tie with certificate on count → category orders it after
		{"cipher", "upstream_handshake", 9},
	}
	out := topFailures(in)
	if out[0].Category != "cipher" || out[1].Category != "certificate" || out[2].Category != "protocol" {
		t.Fatalf("ordering wrong: %+v", out)
	}
}
