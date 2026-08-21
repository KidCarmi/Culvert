package main

// saas_feed_metrics.go — F3b-4: hand-written Prometheus metrics for the signed SaaS feed.
//
// Bounded cardinality by construction: the ONLY labels are `result` (a small fixed
// outcome/recovery class set) and `state` (the nine derived states). Nothing is ever
// labeled by hostname, URL, digest, generation id, ETag, free-form error, or category.
// Scrape-time gauges (active version, seconds-to-expiry, next-run delay, footprint) are
// computed from the status snapshot and OMITTED when there is nothing to report (an
// absent series reads clearer than a fabricated zero — the release-catalog convention).

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Process-lifetime outcome counters (incremented by the runtime/scheduler).
var (
	statSaaSFeedRefreshActivated  atomic.Int64
	statSaaSFeedRefreshNoChange   atomic.Int64
	statSaaSFeedRefreshFailed     atomic.Int64
	statSaaSFeedRefreshSkipped    atomic.Int64
	statSaaSFeedVerifyFailures    atomic.Int64
	statSaaSFeedFloorPersistFails atomic.Int64
	statSaaSFeedEquivocation      atomic.Int64
	statSaaSFeedRecoveryOK        atomic.Int64
	statSaaSFeedRecoveryDegraded  atomic.Int64
)

// saasFeedRecordRefreshOutcome increments the bounded refresh counters + specific
// integrity counters from one refresh cycle's outcome + error class.
func saasFeedRecordRefreshOutcome(outcome saasFeedRefreshOutcome, errClass string) {
	switch outcome {
	case refreshActivated:
		statSaaSFeedRefreshActivated.Add(1)
	case refreshNoChange:
		statSaaSFeedRefreshNoChange.Add(1)
	case refreshFailed:
		statSaaSFeedRefreshFailed.Add(1)
	case refreshSkipped:
		statSaaSFeedRefreshSkipped.Add(1)
	}
	switch errClass {
	case saasFeedErrVerify:
		statSaaSFeedVerifyFailures.Add(1)
	case saasFeedErrFloor:
		statSaaSFeedFloorPersistFails.Add(1)
	case saasFeedErrPersist:
		statSaaSFeedFloorPersistFails.Add(1)
	}
}

// saasFeedRecordRecovery increments the recovery counters from a recovery result.
func saasFeedRecordRecovery(res recoveryResult) {
	if res.Class == recoveryEquivocation {
		statSaaSFeedEquivocation.Add(1)
	}
	if res.Critical {
		statSaaSFeedRecoveryDegraded.Add(1)
	} else {
		statSaaSFeedRecoveryOK.Add(1)
	}
}

// saasFeedWritePrometheus appends the culvert_saasfeed_* metrics. Called from
// handleMetrics alongside the other subsystem writers.
func saasFeedWritePrometheus(w *strings.Builder) {
	w.WriteString("\n# HELP culvert_saasfeed_refresh_total Signed SaaS feed refresh outcomes\n")
	w.WriteString("# TYPE culvert_saasfeed_refresh_total counter\n")
	fmt.Fprintf(w, "culvert_saasfeed_refresh_total{result=\"activated\"} %d\n", statSaaSFeedRefreshActivated.Load())
	fmt.Fprintf(w, "culvert_saasfeed_refresh_total{result=\"no_change\"} %d\n", statSaaSFeedRefreshNoChange.Load())
	fmt.Fprintf(w, "culvert_saasfeed_refresh_total{result=\"failed\"} %d\n", statSaaSFeedRefreshFailed.Load())
	fmt.Fprintf(w, "culvert_saasfeed_refresh_total{result=\"skipped\"} %d\n", statSaaSFeedRefreshSkipped.Load())

	w.WriteString("\n# HELP culvert_saasfeed_verify_failures_total Signed SaaS feed verification failures\n")
	w.WriteString("# TYPE culvert_saasfeed_verify_failures_total counter\n")
	fmt.Fprintf(w, "culvert_saasfeed_verify_failures_total %d\n", statSaaSFeedVerifyFailures.Load())

	w.WriteString("\n# HELP culvert_saasfeed_floor_persist_failures_total Signed SaaS feed floor/activation persistence failures\n")
	w.WriteString("# TYPE culvert_saasfeed_floor_persist_failures_total counter\n")
	fmt.Fprintf(w, "culvert_saasfeed_floor_persist_failures_total %d\n", statSaaSFeedFloorPersistFails.Load())

	w.WriteString("\n# HELP culvert_saasfeed_equivocation_total Signed SaaS feed equivocation (fail-closed) rejections\n")
	w.WriteString("# TYPE culvert_saasfeed_equivocation_total counter\n")
	fmt.Fprintf(w, "culvert_saasfeed_equivocation_total %d\n", statSaaSFeedEquivocation.Load())

	w.WriteString("\n# HELP culvert_saasfeed_recovery_total Signed SaaS feed startup/crash recovery outcomes\n")
	w.WriteString("# TYPE culvert_saasfeed_recovery_total counter\n")
	fmt.Fprintf(w, "culvert_saasfeed_recovery_total{result=\"ok\"} %d\n", statSaaSFeedRecoveryOK.Load())
	fmt.Fprintf(w, "culvert_saasfeed_recovery_total{result=\"degraded\"} %d\n", statSaaSFeedRecoveryDegraded.Load())

	snap := globalSaaSFeedStatus.Snapshot()

	w.WriteString("\n# HELP culvert_saasfeed_failures_since_start Signed SaaS feed refresh failures since process start\n")
	w.WriteString("# TYPE culvert_saasfeed_failures_since_start counter\n")
	fmt.Fprintf(w, "culvert_saasfeed_failures_since_start %d\n", snap.FailuresSinceStart)

	w.WriteString("\n# HELP culvert_saasfeed_consecutive_failures Signed SaaS feed consecutive refresh failures\n")
	w.WriteString("# TYPE culvert_saasfeed_consecutive_failures gauge\n")
	fmt.Fprintf(w, "culvert_saasfeed_consecutive_failures %d\n", snap.ConsecutiveFailures)

	// state info gauge (bounded to the nine derived states; label is a compile-time enum).
	w.WriteString("\n# HELP culvert_saasfeed_state_info Current signed SaaS feed state (1 for the active state)\n")
	w.WriteString("# TYPE culvert_saasfeed_state_info gauge\n")
	fmt.Fprintf(w, "culvert_saasfeed_state_info{state=\"%s\"} 1\n", snap.State.String())

	// Active-generation gauges — omitted entirely when no signed generation is active.
	if snap.ActiveFeedVersion > 0 {
		w.WriteString("\n# HELP culvert_saasfeed_active_feed_version Active signed SaaS feed version\n")
		w.WriteString("# TYPE culvert_saasfeed_active_feed_version gauge\n")
		fmt.Fprintf(w, "culvert_saasfeed_active_feed_version %d\n", snap.ActiveFeedVersion)
	}
	if !snap.ExpiresAt.IsZero() && snap.ActiveFeedVersion > 0 {
		w.WriteString("\n# HELP culvert_saasfeed_expires_in_seconds Seconds until the active signed SaaS feed snapshot expires (negative = expired)\n")
		w.WriteString("# TYPE culvert_saasfeed_expires_in_seconds gauge\n")
		fmt.Fprintf(w, "culvert_saasfeed_expires_in_seconds %.0f\n", time.Until(snap.ExpiresAt).Seconds())
	}
	if !snap.NextAttempt.IsZero() {
		w.WriteString("\n# HELP culvert_saasfeed_next_run_delay_seconds Seconds until the next scheduled refresh\n")
		w.WriteString("# TYPE culvert_saasfeed_next_run_delay_seconds gauge\n")
		fmt.Fprintf(w, "culvert_saasfeed_next_run_delay_seconds %.0f\n", time.Until(snap.NextAttempt).Seconds())
	}

	w.WriteString("\n# HELP culvert_saasfeed_active_hosts Composed signed SaaS feed host count\n")
	w.WriteString("# TYPE culvert_saasfeed_active_hosts gauge\n")
	fmt.Fprintf(w, "culvert_saasfeed_active_hosts %d\n", snap.HostCount)
	w.WriteString("\n# HELP culvert_saasfeed_active_categories Composed signed SaaS feed category count\n")
	w.WriteString("# TYPE culvert_saasfeed_active_categories gauge\n")
	fmt.Fprintf(w, "culvert_saasfeed_active_categories %d\n", snap.CategoryCount)
	w.WriteString("\n# HELP culvert_saasfeed_active_overrides Applied admin category-override count\n")
	w.WriteString("# TYPE culvert_saasfeed_active_overrides gauge\n")
	fmt.Fprintf(w, "culvert_saasfeed_active_overrides %d\n", snap.OverrideCount)
}
