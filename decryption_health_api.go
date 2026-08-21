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

	// Coverage split: the three buckets PARTITION every session — inspected, bypassed
	// (all bypass/exclusion: manual + learned + rescued + not_decrypted), and failed.
	// Per ADR-0011 §3 the headline coverage number is inspected ÷ (inspected + bypass/
	// exclusion) — failures are a SEPARATE widget and must NOT dilute the denominator or
	// be folded into the bypassed bucket (Codex #814).
	inspected := byOutcome[decryptobs.OutcomeInspected.String()]
	failed := byOutcome[decryptobs.OutcomeFailed.String()]
	bypassed := sessionTotal - inspected - failed
	inspectedRatio := inspectionCoverageRatio(inspected, bypassed)

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
			"bypassed":        bypassed, // all bypass/exclusion outcomes (NOT failures)
			"failed":          failed,   // separate bucket, excluded from inspected_ratio
			"inspected_ratio": inspectedRatio,
		},
		// ADR-0011 §3 coverage-erosion trend: per-interval delta samples (may be empty
		// until the sampler has ticked at least once).
		"trend": decTrend.snapshot(),
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

// inspectionCoverageRatio is the ADR-0011 §3 headline coverage number:
// inspected ÷ (inspected + bypass/exclusion). Failures are deliberately NOT in the
// denominator — a decryption that was attempted and failed is a failure to triage, not a
// deliberate coverage gap, so counting it against coverage would understate how much
// traffic policy actually chose to bypass. Returns 0 when nothing was decisioned.
func inspectionCoverageRatio(inspected, bypassed int64) float64 {
	denom := inspected + bypassed
	if denom <= 0 {
		return 0
	}
	return float64(inspected) / float64(denom)
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
