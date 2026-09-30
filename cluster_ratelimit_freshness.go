package main

// CHAOS-61 — the freshness health plane for cluster-wide rate limiting.
//
// The defect this file exists to make visible is in security.go: the DP applied
// the Control Plane's RemoteCounts broadcast and then enforced it forever,
// because Apply is reached only from the gossip loop's SUCCESS branch. The
// enforcement fix is the expiry gate on clusterCountStore.FreshCount. This file
// answers the second half — an operator has to be able to SEE that the node's
// rate-limiting semantics changed.
//
// Why it needs its own surface at all, given /ready already carries a cp_poll
// row: cp_poll says the Control Plane is unreachable. It does not say which
// enforcement decisions on this node changed as a result, and the two are not
// the same question. A node can be denying a customer's traffic 429 for a
// reason that has nothing to do with that customer's current request rate, and
// the per-request RATE_LIMITED log line names only the IP. So the transition —
// "this node stopped counting other nodes' traffic" — is logged ONCE in each
// direction, and the live state is a gauge.
//
// Freshness is EVALUATED, never latched: ClusterFreshness() derives it
// from the applied-at stamp and the live window on every read. That is the same
// discipline as ca_health.go's Usable() — recovery is a fact about the world,
// not a flag someone has to remember to clear — and it means a gossip loop that
// wedges entirely (so no transition is ever recorded) still reports the truth to
// /metrics and the admin API.
//
// The gauges are emitted ONLY on a node where cluster rate limiting is armed.
// `remote_stale 0` on a standalone proxy that never had a Control Plane is
// indistinguishable from a healthy clustered node, and the paging rule here is
// `== 1` — the socks5_listener / cluster_ca precedent.

import (
	"sync"
	"sync/atomic"
	"time"
)

// clusterRateLimitStatus is the read-side snapshot of the cluster rate-limit
// broadcast's freshness. Every field is derived at read time.
type clusterRateLimitStatus struct {
	// Armed is true only when this node's allow/deny decisions ACTUALLY consult
	// remote counts. That needs BOTH halves of the condition AllowAuto →
	// AllowClusterAware requires: the DP gossip loop is running (so AllowAuto
	// dispatches to the cluster-aware path) AND the rate limiter itself is
	// enabled (AllowClusterAware returns true immediately when it is not,
	// before FreshCount is ever reached).
	//
	// Both halves are load-bearing, and the second one was missed in the first
	// version of this file. rateLimitGossipLoop enables distributed admission
	// unconditionally when it starts, but skips every RPC while rl.Enabled() is
	// false — which is the DEFAULT posture, since Configure only enables the
	// limiter for a limit > 0. On such a node no broadcast can ever be applied,
	// so a cluster-flag-only Armed reported a permanent, un-clearable
	// degradation — gauge pinned at 1, an episode counted, a warning logged, a
	// banner shown — on a node that is not rate limiting at all and for which
	// no remote count is ever consulted. That is precisely the failure this
	// file's own emission rule exists to prevent (a 0/1 gauge on a node that
	// never had the feature is indistinguishable from a broken one), applied to
	// "is gossip running" but not to "is anything being decided". Found by
	// Codex review on PR #1346.
	Armed bool
	// Applied is true once any broadcast has been received. False on a node
	// that has never reached its Control Plane. Reported honestly regardless of
	// Armed — it is a fact about what arrived, not about what is enforced.
	Applied bool
	// Age is how long ago the last broadcast landed (0 when none has).
	Age time.Duration
	// MaxAge is the window past which a broadcast can no longer describe the
	// current window — the rate limiter's own window.
	MaxAge time.Duration
	// Stale is true when the remote half of a decision this node is ACTUALLY
	// MAKING is not being applied: it is armed, and either no broadcast has ever
	// landed or the last one is at least MaxAge old. An un-armed node is never
	// stale — there is no decision for an expired broadcast to degrade, so
	// reporting one would be a false alarm on every surface at once.
	Stale bool
	// Episodes counts fresh→stale transitions observed by the gossip loop since
	// startup. It is the operator's "has this happened before" signal; the
	// gauge alone cannot distinguish one long outage from six short ones.
	Episodes int64
}

// ClusterFreshness computes the current freshness state. Safe to call
// from any goroutine and from a scrape handler.
func (r *RateLimiter) ClusterFreshness() clusterRateLimitStatus {
	st := clusterRateLimitStatus{
		Armed:    r.ClusterEnabled() && r.Enabled(),
		MaxAge:   clusterRemoteCountMaxAge(r.Window()),
		Episodes: r.clusterObservation.episodes.Load(),
	}
	if appliedAt, ok := r.remoteCounts.AppliedAt(); ok {
		st.Applied = true
		st.Age = time.Since(appliedAt)
	}
	if !st.Armed {
		// Nothing on this node consults a remote count, so no broadcast — absent,
		// current or long expired — can be degrading anything. Staleness is a
		// statement about enforcement, not about the age of a value nobody reads.
		return st
	}
	if !st.Applied {
		st.Stale = true // nothing applied yet: the remote half contributes nothing
		return st
	}
	if st.Age < 0 {
		// Clock rollback between the stamp and this read. Treating a negative
		// age as fresh would honour a broadcast for however far back the clock
		// moved; treating it as stale degrades to local-only, which is the same
		// place every other failure lands. Fail toward the local decision.
		st.Stale = true
		return st
	}
	st.Stale = st.Age >= st.MaxAge
	return st
}

// clusterRateLimitObservation holds only this limiter's diagnostic history.
// The freshness verdict is derived, never latched here.
type clusterRateLimitObservation struct {
	mu       sync.Mutex
	reported bool // stale transition logged and not yet cleared
	episodes atomic.Int64
}

// noteClusterRateLimitFreshness records one observation of the freshness state,
// logging each transition once. Called from the DP gossip loop on every tick —
// success and failure alike — so recovery is reported from the same place as
// onset and neither depends on the other branch running.
func (r *RateLimiter) noteClusterRateLimitFreshness() {
	st := r.ClusterFreshness()
	if !st.Armed {
		return
	}
	r.clusterObservation.mu.Lock()
	defer r.clusterObservation.mu.Unlock()
	switch {
	case st.Stale && !r.clusterObservation.reported:
		r.clusterObservation.reported = true
		r.clusterObservation.episodes.Add(1)
		// No IP, no count, no Control-Plane address: this line is about the
		// enforcement change, and the cause is already logged in full by the
		// gossip and poll loops on every occurrence.
		logger.Printf("WARN cluster rate limiting: no Control Plane broadcast within the %s window — "+
			"other nodes' request counts are no longer applied on this node (local rate limits still enforced)",
			st.MaxAge)
	case !st.Stale && r.clusterObservation.reported:
		r.clusterObservation.reported = false
		logger.Printf("cluster rate limiting: Control Plane broadcast is current again — "+
			"other nodes' request counts are being applied (stale episodes: %d)", r.clusterObservation.episodes.Load())
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
