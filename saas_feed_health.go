package main

// saas_feed_health.go — F3b-4: the signed-feed readiness component (report-only).
//
// The row is NEVER gating (it takes only the checks map, not allOK), mirroring the ca /
// policy_loaded / DP-health rows. Because the compiled embedded baseline is always a
// valid serving fallback, an unreachable origin can never make readiness fail: a stuck
// origin or an expired last-known-good is a visible degradation, not an outage. A
// corruption/equivocation/authority-loss state is surfaced as a failing (still
// non-gating) row so /ready?strict=1 can eject the node if an operator opts in.

// appendSaaSFeedHealthCheck adds the report-only saas_feed readiness row.
func appendSaaSFeedHealthCheck(checks map[string]*readinessCheck) {
	if checks == nil {
		return
	}
	snap := globalSaaSFeedStatus.Snapshot()
	switch snap.State {
	case saasFeedStateDisabled:
		checks["saas_feed"] = &readinessCheck{Status: "ok", Detail: "disabled (embedded baseline)"}
	case saasFeedStateEmbedded:
		checks["saas_feed"] = &readinessCheck{Status: "ok", Detail: "embedded baseline"}
	case saasFeedStateFresh, saasFeedStateSyncing, saasFeedStateRecovering:
		checks["saas_feed"] = &readinessCheck{Status: "ok", Detail: snap.State.String()}
	case saasFeedStateStale, saasFeedStateDegraded:
		// Serving a valid LKG but the origin is stuck / the snapshot is past expiry:
		// degraded, but never fail-closed on age — report-only.
		checks["saas_feed"] = &readinessCheck{Status: "fail", Detail: snap.State.String()}
	case saasFeedStateWaitingForAuthority, saasFeedStateCritical:
		// Critical: managed DP without authority, or a corruption/equivocation state.
		// Still non-gating (the embedded baseline serves); visible under strict.
		checks["saas_feed"] = &readinessCheck{Status: "fail", Detail: snap.State.String()}
	}
}
