package main

// RateLimitDelta is a per-IP request count sent from DP → CP.
type RateLimitDelta struct {
	IP    string `json:"ip"`
	Count int    `json:"count"` // current qualifying in-window count (historical wire name)
}

// RateLimitGossip is the DP → CP message containing hot-IP deltas.
type RateLimitGossip struct {
	NodeID string           `json:"node_id"`
	Deltas []RateLimitDelta `json:"deltas"`
}

// RateLimitBroadcast is the CP → DP response with cluster-wide totals
// (excluding the requesting node's own counts, so the DP can add them locally).
type RateLimitBroadcast struct {
	// RemoteCounts maps IP → total requests from OTHER nodes in the current window.
	RemoteCounts map[string]int `json:"remote_counts"`
}

// rateLimitWireDeltas preserves nil as JSON null and maps engine counts into
// the existing transport schema. Accounting remains owned by the engine.
func rateLimitWireDeltas(r *RateLimiter) []RateLimitDelta {
	counts := r.ExportHotDeltas()
	if counts == nil {
		return nil
	}
	deltas := make([]RateLimitDelta, len(counts))
	for i, count := range counts {
		deltas[i] = RateLimitDelta{IP: count.IP, Count: count.Count}
	}
	return deltas
}
