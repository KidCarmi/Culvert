package main

import "github.com/KidCarmi/Culvert/internal/admission"

type clusterRateLimitStatus = admission.ClusterRateLimitStatus

// The engine owns the verdict and episode latch; main only renders transitions.
func noteClusterRateLimitFreshness(r *RateLimiter) {
	observation := r.ObserveClusterFreshness()
	switch observation.Transition {
	case admission.FreshnessStale:
		logger.Printf("WARN cluster rate limiting: no Control Plane broadcast within the %s window — "+
			"other nodes' request counts are no longer applied on this node (local rate limits still enforced)", observation.Status.MaxAge)
	case admission.FreshnessRecovered:
		logger.Printf("cluster rate limiting: Control Plane broadcast is current again — "+
			"other nodes' request counts are being applied (stale episodes: %d)", observation.Status.Episodes)
	}
}

// clusterRateLimitBroadcastAgeMetric renders the broadcast age for Prometheus.
// A node that has NEVER received a broadcast reports -1 rather than 0: 0 would
// read as "a broadcast just landed", the exact opposite of the truth, and there
// is no age to report for an event that never happened.
func clusterRateLimitBroadcastAgeMetric(st clusterRateLimitStatus) float64 {
	if !st.Applied {
		return -1
	}
	return st.Age.Seconds()
}
