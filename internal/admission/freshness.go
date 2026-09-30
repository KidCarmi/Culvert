package admission

import (
	"sync"
	"sync/atomic"
	"time"
)

// ClusterRateLimitStatus is the read-side snapshot of the cluster rate-limit
// broadcast's freshness. Every field is derived at read time.
type ClusterRateLimitStatus struct {
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
func (r *RateLimiter) ClusterFreshness() ClusterRateLimitStatus {
	st := ClusterRateLimitStatus{
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

// FreshnessTransition describes an observed diagnostic transition.
type FreshnessTransition uint8

// Observation transitions; an unchanged observation requires no log message.
const (
	FreshnessUnchanged FreshnessTransition = iota
	FreshnessStale
	FreshnessRecovered
)

// FreshnessObservation is the engine's observation and transition, for rendering
// by its caller. Episodes includes this observation; admission never uses it.
type FreshnessObservation struct {
	Status     ClusterRateLimitStatus
	Transition FreshnessTransition
}

// ObserveClusterFreshness records a transition once per stale episode. The
// caller owns logging and must serialize observation/rendering as the gossip
// loop does. No clock, logger, transport or background worker is installed.
func (r *RateLimiter) ObserveClusterFreshness() FreshnessObservation {
	st := r.ClusterFreshness()
	out := FreshnessObservation{Status: st}
	if !st.Armed {
		return out
	}
	r.clusterObservation.mu.Lock()
	defer r.clusterObservation.mu.Unlock()
	switch {
	case st.Stale && !r.clusterObservation.reported:
		r.clusterObservation.reported = true
		r.clusterObservation.episodes.Add(1)
		out.Transition = FreshnessStale
	case !st.Stale && r.clusterObservation.reported:
		r.clusterObservation.reported = false
		out.Transition = FreshnessRecovered
	}
	out.Status.Episodes = r.clusterObservation.episodes.Load()
	return out
}
