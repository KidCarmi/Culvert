package admission

import (
	"sync"
	"testing"
	"time"
)

// withClusterRateLimiter constructs an independent owner; no application fixture.
func withClusterRateLimiter(t *testing.T, limit int, window time.Duration) *RateLimiter {
	t.Helper()
	r := NewRateLimiter()
	r.Configure(limit, window)
	r.SetClusterEnabled(true)
	return r
}

// applyAtForTest applies a broadcast as if it had landed at ts, so a test can
// age a broadcast without sleeping.
func (c *clusterCountStore) applyAtForTest(remote map[string]int, ts time.Time) {
	c.mu.Lock()
	c.counts = remote
	c.mu.Unlock()
	c.appliedAtNano.Store(ts.UnixNano())
}

// TestChaos61_StaleBroadcastNoLongerDeniesForever is THE defect gate. A
// broadcast that put an IP at the limit, then aged past the rate-limit window,
// must stop denying that IP. Pre-fix this loops false forever.
func TestChaos61_StaleBroadcastNoLongerDeniesForever(t *testing.T) {
	const limit = 10
	window := time.Minute
	r := withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.7"
	// The Control Plane's last word before it went away: this IP had already
	// used the whole cluster-wide budget on OTHER nodes.
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now())
	if r.AllowClusterAware(ip) {
		t.Fatal("a CURRENT broadcast at the limit must deny — the distributed limit is not working")
	}

	// The CP goes away. No further Apply ever happens; the broadcast ages.
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(-window-time.Second))

	for i := 0; i < 5; i++ {
		if !r.AllowClusterAware(ip) {
			t.Fatalf("request %d denied by a broadcast older than the %s window: "+
				"the node is enforcing a frozen snapshot of the past", i+1, window)
		}
	}
}

// TestChaos61_FrozenBroadcastDoesNotShrinkTheLocalBudget covers the quieter
// half of the same defect: even a remote count well BELOW the limit permanently
// shrinks this node's local allowance once it can no longer be refreshed.
func TestChaos61_FrozenBroadcastDoesNotShrinkTheLocalBudget(t *testing.T) {
	const limit = 10
	window := time.Minute
	r := withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.8"
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit / 2}, time.Now().Add(-window-time.Second))

	allowed := 0
	for i := 0; i < limit; i++ {
		if r.AllowClusterAware(ip) {
			allowed++
		}
	}
	if allowed != limit {
		t.Fatalf("allowed %d of %d requests; a stale remote count is still consuming the local budget", allowed, limit)
	}
}

// TestChaos61_FreshBroadcastStillSuppresses is the control for the two defect
// gates: on a HEALTHY cluster the distributed limit must behave exactly as it
// did before. A "fix" that simply ignored remote counts passes every defect
// gate above and fails here.
func TestChaos61_FreshBroadcastStillSuppresses(t *testing.T) {
	const limit = 10
	window := time.Minute
	r := withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.9"
	remote := 6
	r.remoteCounts.applyAtForTest(map[string]int{ip: remote}, time.Now())

	allowed := 0
	for i := 0; i < limit; i++ {
		if r.AllowClusterAware(ip) {
			allowed++
		}
	}
	if allowed != limit-remote {
		t.Fatalf("allowed %d requests with a fresh remote count of %d and limit %d; want %d — "+
			"the distributed rate limiter is no longer suppressing", allowed, remote, limit, limit-remote)
	}
}

// TestChaos61_BroadcastAppliesForTheWholeWindow pins the boundary from the
// other side: a broadcast is honoured right up to the window, not clipped early
// by a shorter ad-hoc constant.
func TestChaos61_BroadcastAppliesForTheWholeWindow(t *testing.T) {
	const limit = 10
	window := time.Minute
	r := withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.10"
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(-window/2))
	if r.AllowClusterAware(ip) {
		t.Fatalf("a broadcast %s old was ignored inside a %s window — the distributed limit expires too early", window/2, window)
	}
}

// TestChaos61_MaxAgeIsDerivedFromTheLimiterWindow proves the expiry rule tracks
// the live limiter rather than a hardcoded minute: a longer window must keep a
// broadcast applicable for longer.
func TestChaos61_MaxAgeIsDerivedFromTheLimiterWindow(t *testing.T) {
	const limit = 10
	window := 10 * time.Minute
	r := withClusterRateLimiter(t, limit, window)

	const ip = "198.51.100.11"
	// Five minutes old: stale under a one-minute window, fresh under this one.
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(-5*time.Minute))
	if r.AllowClusterAware(ip) {
		t.Fatal("a 5m-old broadcast was ignored under a 10m window — the max-age is not derived from the limiter")
	}

	if got, want := clusterRemoteCountMaxAge(window), window; got != want {
		t.Fatalf("clusterRemoteCountMaxAge(%s) = %s, want %s", window, got, want)
	}
	if got := clusterRemoteCountMaxAge(0); got != clusterRemoteCountFallbackMaxAge {
		t.Fatalf("clusterRemoteCountMaxAge(0) = %s, want the %s fallback", got, clusterRemoteCountFallbackMaxAge)
	}
}

// TestChaos61_NeverAppliedBroadcastContributesNothing covers the cold-start
// node: no broadcast has ever landed, so there is nothing to add.
func TestChaos61_NeverAppliedBroadcastContributesNothing(t *testing.T) {
	r := withClusterRateLimiter(t, 10, time.Minute)
	if got := r.remoteCounts.FreshCount("203.0.113.5", time.Now(), time.Minute); got != 0 {
		t.Fatalf("FreshCount on a node that never received a broadcast = %d, want 0", got)
	}
	st := r.ClusterFreshness()
	if st.Applied {
		t.Fatal("Applied is true with no broadcast ever received")
	}
	if !st.Stale {
		t.Fatal("a node with no broadcast must report stale — the remote half contributes nothing")
	}
}

// TestChaos61_ClockRollbackDegradesToLocal pins the fail-toward-local direction
// for a negative age: honouring a future-stamped broadcast would extend its life
// by however far the clock moved back.
func TestChaos61_ClockRollbackDegradesToLocal(t *testing.T) {
	const limit = 10
	r := withClusterRateLimiter(t, limit, time.Minute)

	const ip = "203.0.113.6"
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(2*time.Hour))
	st := r.ClusterFreshness()
	if !st.Stale {
		t.Fatal("a future-stamped broadcast (clock rollback) must be treated as stale")
	}
	if !r.AllowClusterAware(ip) {
		t.Fatal("a future-stamped broadcast is still suppressing traffic")
	}
}

// TestChaos61_StaleEpisodeIsCountedOncePerEpisode proves the transition is
// reported per EPISODE, not per gossip tick — the gossip loop calls this every
// 5s, so a per-tick counter would report an hour-long outage as 720 episodes.
func TestChaos61_StaleEpisodeIsCountedOncePerEpisode(t *testing.T) {
	r := withClusterRateLimiter(t, 10, time.Minute)

	r.remoteCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	for i := 0; i < 12; i++ { // one minute of gossip ticks during the outage
		r.ObserveClusterFreshness()
	}
	if got := r.ClusterFreshness().Episodes; got != 1 {
		t.Fatalf("stale episodes after 12 ticks of one outage = %d, want 1", got)
	}

	// The CP comes back: a fresh broadcast lands and the next tick clears.
	r.remoteCounts.Apply(map[string]int{})
	r.ObserveClusterFreshness()
	if got := r.ClusterFreshness().Episodes; got != 1 {
		t.Fatalf("recovery changed the episode count to %d, want 1", got)
	}

	// A SECOND outage is a second episode.
	r.remoteCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	r.ObserveClusterFreshness()
	if got := r.ClusterFreshness().Episodes; got != 2 {
		t.Fatalf("stale episodes after a second outage = %d, want 2", got)
	}
}

// TestChaos61_FreshnessIsEvaluatedNotLatched proves recovery needs no explicit
// clearing path: the state is derived from the stamp on every read, so a gossip
// loop that stops running entirely still reports the truth to /metrics.
func TestChaos61_FreshnessIsEvaluatedNotLatched(t *testing.T) {
	r := withClusterRateLimiter(t, 10, time.Minute)

	r.remoteCounts.applyAtForTest(map[string]int{}, time.Now().Add(-2*time.Minute))
	if !r.ClusterFreshness().Stale {
		t.Fatal("an aged broadcast is not reported stale")
	}
	// No noteClusterRateLimitFreshness call at all — nothing to clear.
	r.remoteCounts.Apply(map[string]int{})
	if r.ClusterFreshness().Stale {
		t.Fatal("freshness stayed stale after a new broadcast landed — the state is latched, not evaluated")
	}
}

// withClusterGossipButLimiterOff reproduces the DEFAULT posture of a Data Plane
// node: rateLimitGossipLoop has enabled distributed admission, but the rate
// limiter itself is off (Configure enables it only for a limit > 0), so the
// loop skips every RPC and no broadcast can ever be applied.
func withClusterGossipButLimiterOff(t *testing.T) *RateLimiter {
	t.Helper()
	return withClusterRateLimiter(t, 0, 0)
}

// TestChaos61_LimiterOffStillReportsWhatArrived pins that suppressing the ALARM
// does not suppress the FACTS: a broadcast that did land is still reported, so
// the surface stays diagnostic rather than going blank.
func TestChaos61_LimiterOffStillReportsWhatArrived(t *testing.T) {
	r := withClusterGossipButLimiterOff(t)
	r.remoteCounts.applyAtForTest(map[string]int{"203.0.113.20": 5}, time.Now().Add(-2*time.Hour))

	st := r.ClusterFreshness()
	if !st.Applied {
		t.Fatal("Applied is false after a broadcast landed — the un-armed path is hiding a fact, not just an alarm")
	}
	if st.Age <= 0 {
		t.Fatalf("Age = %s after a broadcast landed 2h ago", st.Age)
	}
	if st.Stale {
		t.Fatal("an expired broadcast is reported stale on a node that consults no remote count")
	}
}

// TestChaos61_FreshCountRacesApply runs the hot-path reader against the gossip
// writer under -race: the stamp is an atomic outside the mutex, so the
// publication order (map under the lock, stamp after) has to be correct.
func TestChaos61_FreshCountRacesApply(t *testing.T) {
	r := withClusterRateLimiter(t, 100, time.Minute)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				r.remoteCounts.Apply(map[string]int{"203.0.113.9": 1})
			}
		}
	}()
	for i := 0; i < 2000; i++ {
		_ = r.remoteCounts.FreshCount("203.0.113.9", time.Now(), time.Minute)
		_ = r.ClusterFreshness()
	}
	close(stop)
	wg.Wait()
}
