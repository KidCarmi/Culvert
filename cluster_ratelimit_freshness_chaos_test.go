package main

// CHAOS-61 gates — the Data Plane's cluster rate-limit broadcast under a
// Control Plane outage.
//
// The defect: clusterCountStore.Apply is reached ONLY from the DP gossip loop's
// success branch, so a failed SyncRateLimits left the last broadcast frozen in
// the map for the rest of the process lifetime while AllowClusterAware kept
// adding it to every local count. An IP whose remote total was at or near the
// limit when the CP went away was denied on this node PERMANENTLY.
//
// Every DEFECT gate below (StaleBroadcast*, FrozenBroadcast*) was verified
// failing against the pre-fix shape — the old clusterCounts.Get(ip) with no expiry — and
// the CONTROL gates exist because the cheapest way to pass the defect gates is
// to stop consulting remote counts at all, which would silently delete the
// distributed rate limiter.

import (
	"strings"

	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// useProductionRateLimiter binds only tests of real application adapters.
func useProductionRateLimiter(t *testing.T, r *RateLimiter) {
	t.Helper()
	old := rl
	rl = r
	t.Cleanup(func() { rl = old })
}

// ── Defect gates ────────────────────────────────────────────────────────────

// ── Control gates ───────────────────────────────────────────────────────────

// ── Freshness reporting ─────────────────────────────────────────────────────

// TestChaos61_MetricsOnlyOnAnArmedNode pins the emission rule: `remote_stale 0`
// on a standalone proxy that never had a Control Plane is indistinguishable
// from a healthy clustered node, and the paging rule is `== 1`.
func TestChaos61_MetricsOnlyOnAnArmedNode(t *testing.T) {
	r := withClusterRateLimiter(t, 10, time.Minute)
	useProductionRateLimiter(t, r)

	r.SetClusterEnabled(false)
	if body := renderMetrics(t); strings.Contains(body, "culvert_cluster_ratelimit_remote_stale") {
		t.Fatal("cluster rate-limit gauges emitted on a node where cluster rate limiting is not armed")
	}

	r.SetClusterEnabled(true)
	r.ApplyRemoteCounts(map[string]int{})
	r.Configure(10, time.Nanosecond)
	for !r.ClusterFreshness().Stale {
		time.Sleep(time.Microsecond)
	}
	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_cluster_ratelimit_remote_stale 1") {
		t.Fatalf("armed + stale did not render remote_stale 1:\n%s", extractClusterRLMetrics(body))
	}
	if !strings.Contains(body, "culvert_cluster_ratelimit_stale_episodes_total") {
		t.Fatal("stale-episode counter missing from the exposition")
	}
	if !strings.Contains(body, "culvert_cluster_ratelimit_broadcast_age_seconds") {
		t.Fatal("broadcast-age gauge missing from the exposition")
	}
}

func extractClusterRLMetrics(body string) string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.Contains(line, "cluster_ratelimit") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// ── The armed condition (Codex review, PR #1346) ────────────────────────────

// TestChaos61_LimiterOffIsNeverReportedStale is the regression gate for the
// false alarm: on a node that is not rate limiting, no remote count is ever
// consulted (AllowClusterAware short-circuits), so nothing can be degraded —
// yet a cluster-flag-only armed condition pinned every surface at "degraded"
// permanently, on the DEFAULT posture.
func TestChaos61_LimiterOffIsNeverReportedStale(t *testing.T) {
	r := withClusterGossipButLimiterOff(t)
	useProductionRateLimiter(t, r)

	st := r.ClusterFreshness()
	if st.Armed {
		t.Fatal("Armed is true while the rate limiter is off — AllowClusterAware never reaches a remote count there")
	}
	if st.Stale {
		t.Fatal("a node that is not rate limiting is reported stale: a permanent false alarm on the default posture")
	}

	// Ticking the gossip loop's reporter must not log, count an episode, or
	// arm any surface. A hundred ticks is an ordinary few minutes of uptime.
	for i := 0; i < 100; i++ {
		noteClusterRateLimitFreshness(r)
	}
	if got := r.ClusterFreshness().Episodes; got != 0 {
		t.Fatalf("stale episodes on a node that is not rate limiting = %d, want 0", got)
	}
	if body := renderMetrics(t); strings.Contains(body, "culvert_cluster_ratelimit_remote_stale") {
		t.Fatal("/metrics exports the cluster rate-limit gauges on a node whose limiter is off")
	}
}

// TestChaos61_ArmedNeedsBothHalves is the control: suppressing the false alarm
// must not suppress the REAL one. Turning the limiter on — the other half of
// the condition AllowAuto → AllowClusterAware requires — arms the surface and
// the genuine degradation is reported again.
func TestChaos61_ArmedNeedsBothHalves(t *testing.T) {
	r := withClusterGossipButLimiterOff(t)
	useProductionRateLimiter(t, r)
	if r.ClusterFreshness().Armed {
		t.Fatal("armed with the limiter off")
	}

	// Cluster flag on AND limiter on, with no broadcast ever applied: the real
	// degradation this whole file exists to surface.
	r.Configure(10, time.Minute)
	st := r.ClusterFreshness()
	if !st.Armed {
		t.Fatal("not armed with both the gossip loop running and the limiter enabled")
	}
	if !st.Stale {
		t.Fatal("a genuinely armed node with no broadcast is not reported stale — the fix silenced the real alarm")
	}
	noteClusterRateLimitFreshness(r)
	if got := r.ClusterFreshness().Episodes; got != 1 {
		t.Fatalf("stale episodes = %d on a real degradation, want 1", got)
	}
	if body := renderMetrics(t); !strings.Contains(body, "culvert_cluster_ratelimit_remote_stale 1") {
		t.Fatal("/metrics does not report the real degradation once both halves are armed")
	}

	// And the other half in isolation: limiter on but no gossip loop running
	// (a standalone proxy) must stay un-armed.
	r.SetClusterEnabled(false)
	if r.ClusterFreshness().Armed {
		t.Fatal("armed on a standalone node with no DP gossip loop")
	}
}

// ── Concurrency ─────────────────────────────────────────────────────────────

// ── The DP→CP audit push queue ──────────────────────────────────────────────

// TestChaos61_AuditPushQueueOverflowIsCounted is the second defect gate. The
// bound is correct; the silence was not. Pre-fix there is no counter at all.
func TestChaos61_AuditPushQueueOverflowIsCounted(t *testing.T) {
	restore := audit.ResetPendingForTest()
	defer restore()

	const overflow = 250
	for i := 0; i < audit.MaxPendingForTest()+overflow; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add"})
	}
	if got := audit.PendingDrops(); got != int64(overflow) {
		t.Fatalf("PendingDrops = %d after overflowing the queue by %d, want %d — "+
			"the centralized audit trail loses entries with no counter", got, overflow, overflow)
	}
	if got := len(audit.Drain()); got != audit.MaxPendingForTest() {
		t.Fatalf("queue held %d entries, want the cap %d", got, audit.MaxPendingForTest())
	}
}

// TestChaos61_AuditRequeueOverflowIsCounted covers the path an actual CP outage
// takes: Drain, push fails, Requeue — repeatedly. The requeued (older) events
// are the ones discarded, and that loss must be charged too.
func TestChaos61_AuditRequeueOverflowIsCounted(t *testing.T) {
	restore := audit.ResetPendingForTest()
	defer restore()

	queueCap := audit.MaxPendingForTest()
	for i := 0; i < queueCap; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add", Object: "old"})
	}
	events := audit.Drain()
	if audit.PendingDrops() != 0 {
		t.Fatalf("drops charged before any overflow: %d", audit.PendingDrops())
	}
	// New activity arrives while the push is in flight, then the push fails.
	const fresh = 40
	for i := 0; i < fresh; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add", Object: "new"})
	}
	audit.Requeue(events)

	if got := audit.PendingDrops(); got != fresh {
		t.Fatalf("PendingDrops after a failed push = %d, want %d", got, fresh)
	}
	// The trim keeps the newest: every "new" entry survived, and exactly the
	// oldest unsent history was discarded.
	held := audit.Drain()
	if len(held) != queueCap {
		t.Fatalf("queue held %d entries, want the cap %d", len(held), queueCap)
	}
	newest := held[len(held)-1]
	if newest.Object != "new" {
		t.Fatalf("newest retained entry Object = %q, want %q (the trim must keep the newest)", newest.Object, "new")
	}
}

// TestChaos61_AuditPushDropsSurfaceOnHealthz pins the operator surface: the
// field appears only when non-zero, so an unaffected node's /healthz body is
// byte-identical to before.
func TestChaos61_AuditPushDropsSurfaceOnHealthz(t *testing.T) {
	restore := audit.ResetPendingForTest()
	defer restore()

	resp := map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["auditClusterPushDrops"]; ok {
		t.Fatal("auditClusterPushDrops present with zero drops — existing probe consumers see a changed body")
	}

	for i := 0; i < audit.MaxPendingForTest()+1; i++ {
		audit.QueueForClusterForTest(audit.Entry{Action: "policy.add"})
	}
	resp = map[string]any{}
	addRequestLogHealth(resp)
	if _, ok := resp["auditClusterPushDrops"]; !ok {
		t.Fatal("auditClusterPushDrops missing from /healthz after the push queue dropped entries")
	}
}

// withClusterRateLimiter constructs an independent owner; no application fixture.
func withClusterRateLimiter(t *testing.T, limit int, window time.Duration) *RateLimiter {
	t.Helper()
	r := newRateLimiter()
	r.Configure(limit, window)
	r.SetClusterEnabled(true)
	return r
}

// withClusterGossipButLimiterOff reproduces the DEFAULT posture of a Data Plane
// node: rateLimitGossipLoop has enabled distributed admission, but the rate
// limiter itself is off (Configure enables it only for a limit > 0), so the
// loop skips every RPC and no broadcast can ever be applied.
func withClusterGossipButLimiterOff(t *testing.T) *RateLimiter {
	t.Helper()
	return withClusterRateLimiter(t, 0, 0)
}

func TestChaos61_NeverAppliedBroadcastAgeMetric(t *testing.T) {
	st := newRateLimiter().ClusterFreshness()
	if got := clusterRateLimitBroadcastAgeMetric(st); got != -1 {
		t.Fatalf("broadcast age metric = %g with no broadcast, want -1 (0 would read as 'just landed')", got)
	}
}
