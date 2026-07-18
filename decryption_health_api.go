package main

// decryption_health_api.go — ADR-0011 Phase 2 ("& API" half): the read-only decryption
// health aggregate. GET /api/decryption/health (viewer) folds the coverage
// (culvert_decrypt_sessions_total) and failure-taxonomy (culvert_decrypt_failures_total)
// counters — plus the adaptive auto-exclusion posture — into one server-computed operator
// view: "what fraction of TLS is inspected, why is the rest bypassed, and why did the
// failures fail". It is side-effect-free and reads only already-recorded counters (no new
// probe, nothing on the proxy hot path). The Decryption Health SPA panel and the request-
// feed dec.* drill-down are Phase 3; this ships the API only, mirroring the read-only
// governance/control-plane precedent.

import (
	"net/http"
	"sort"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decTopN bounds the top-N failure list returned to the UI.
const decTopN = 10

// apiDecryptionHealth serves the ADR-0011 decryption coverage + failure aggregate.
func apiDecryptionHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}

	sessions := decSessions.snapshot()
	byOutcome := map[string]int64{}
	bySource := map[string]int64{}
	byTLS := map[string]int64{}
	var sessionTotal int64
	for i := range sessions {
		s := &sessions[i]
		byOutcome[s.Outcome] += s.Count
		bySource[s.Source] += s.Count
		byTLS[s.TLSVersion] += s.Count
		sessionTotal += s.Count
	}

	failures := decFailures.snapshot()
	byCategory := map[string]int64{}
	byStage := map[string]int64{}
	var failureTotal int64
	for i := range failures {
		f := &failures[i]
		byCategory[f.Category] += f.Count
		byStage[f.Stage] += f.Count
		failureTotal += f.Count
	}

	// Coverage split: inspected vs every non-inspected outcome. inspected_ratio is the
	// headline "decryption coverage" number (inspected / all decisioned sessions).
	inspected := byOutcome[decryptobs.OutcomeInspected.String()]
	var inspectedRatio float64
	if sessionTotal > 0 {
		inspectedRatio = float64(inspected) / float64(sessionTotal)
	}

	foProfiles, foRules := failOpenFootprint()
	aeStats := autoExclude().Stats()

	jsonOK(w, map[string]any{
		"sessions": map[string]any{
			"total":              sessionTotal,
			"by_outcome":         byOutcome,
			"by_decision_source": bySource,
			"by_tls_version":     byTLS,
		},
		"failures": map[string]any{
			"total":       failureTotal,
			"by_category": byCategory,
			"by_stage":    byStage,
			"top":         topFailures(failures),
		},
		"coverage": map[string]any{
			"inspected":       inspected,
			"not_inspected":   sessionTotal - inspected,
			"failed":          byOutcome[decryptobs.OutcomeFailed.String()],
			"inspected_ratio": inspectedRatio,
		},
		"autoexclude": map[string]any{
			"active":             aeStats.Active,
			"pending":            aeStats.Pending,
			"hit_total":          atomic.LoadInt64(&autoExcludeHitCounter),
			"rescue_total":       atomic.LoadInt64(&autoExcludeRescueCounter),
			"surge_total":        atomic.LoadInt64(&autoExcludeSurgeCounter),
			"fail_open_profiles": foProfiles,
			"fail_open_rules":    foRules,
		},
	})
}

// topFailures returns the highest-count failure series (category+stage), descending, capped
// at decTopN. Ties break by category then stage so the order is deterministic.
func topFailures(samples []decFailureSample) []decFailureSample {
	out := make([]decFailureSample, len(samples))
	copy(out, samples)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Stage < out[j].Stage
	})
	if len(out) > decTopN {
		out = out[:decTopN]
	}
	return out
}
