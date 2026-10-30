package main

// diagnostics_cluster_ratelimit.go — operator-contract row for a stale cluster
// rate-limit broadcast.
//
// When a Data Plane stops receiving the Control Plane's rate-limit broadcast it
// deliberately falls back to its LOCAL limit (CHAOS-61), and that was reported
// only in a log line, a Prometheus gauge and a banner on the Cluster page. The
// one-page diagnostics report, where an operator checks "is this node healthy",
// stayed green while the cluster-wide rate limit was not being enforced.
//
// Report-only: derived from ClusterFreshness (the same verdict the Cluster page
// and the metric use), no I/O, no change to rate limiting. Contributes nothing
// unless cluster rate limiting is armed on this node and its broadcast is stale.
// Carries no node, IP or address data.

import (
	"fmt"
	"time"
)

// checkClusterRateLimitFreshness returns zero or one row for r.
func checkClusterRateLimitFreshness(r *RateLimiter) []OperatorContractCheck {
	st := r.ClusterFreshness()
	if !st.Armed || !st.Stale {
		return nil
	}
	detail := "no Control Plane broadcast has been received yet"
	if st.Applied && st.Age >= 0 {
		detail = fmt.Sprintf("the last Control Plane broadcast was %s ago (limit %s)",
			st.Age.Round(time.Second), st.MaxAge.Round(time.Second))
	}
	return []OperatorContractCheck{{
		Code:   "cluster_ratelimit_freshness",
		Status: diagWarn,
		Message: "cluster rate limiting is degraded — " + detail +
			"; this node enforces only its local rate limit and ignores other nodes' request counts",
		OperatorAction: "Cluster → Distributed rate limiting shows the broadcast age and how many times it has gone stale. " +
			"Check that the Control Plane is reachable from this node (Cluster → nodes); the row clears on the next broadcast. " +
			"Rate limits remain enforced locally in the meantime.",
	}}
}
