package admission

import (
	"testing"
	"time"
)

// ── An in-flight broadcast is not a clock rollback ───────────────────────────
//
// AllowClusterAware captures its decision clock (`now`) BEFORE taking the shard
// lock and hands that same instant to FreshCount. The gossip loop's Apply stamps
// appliedAtNano with its own time.Now(). When a broadcast lands between those
// two steps the stamp is newer than the decision's `now`, FreshCount computed a
// NEGATIVE age, and CHAOS-61's clock-rollback rule zeroed the remote half of the
// decision. The node then decided on its local count alone and ADMITTED a
// request the cluster-wide limit should have refused — a transient, self-
// inflicted fail-open of distributed rate limiting on every gossip tick that
// overlapped a decision. Seen in CI as TestDistributedAdmission_ProductionWiring
// admitting the SOCKS5 leg (6 local + 2 remote against a limit of 8) right after
// the HTTP leg was correctly denied, with gossip running every millisecond.
//
// ClusterFreshness never had the defect: it loads the stamp and THEN reads the
// clock (time.Since), so the same instant reported "fresh" on the diagnostics
// while enforcement treated it as stale — two answers to one question, the
// exact condition the negative-age rule was written to avoid.
//
// The fix re-reads the clock once, only on a negative age, AFTER the stamp was
// loaded. A stamp that is still in the future against that later read is a
// genuine rollback and stays stale; a stamp that merely postdates the caller's
// decision clock is fresh. The steady-state hot path takes no extra clock read.

// TestChaos61_InFlightBroadcastIsFreshNotRolledBack is the defect gate. The
// decision clock is captured, THEN the broadcast is applied (the forced
// interleaving), THEN the remote half is read with the earlier clock — as the
// hot path does. The broadcast must count. Deterministic: the decision clock is
// placed a full second behind the stamp, so no sleep or scheduling is involved,
// and the re-read happens after the stamp by construction.
func TestChaos61_InFlightBroadcastIsFreshNotRolledBack(t *testing.T) {
	const limit = 8
	r := withClusterRateLimiter(t, limit, time.Minute)
	const ip = "198.51.100.71"

	decisionNow := time.Now().Add(-time.Second) // captured before the shard lock
	r.remoteCounts.Apply(map[string]int{ip: 2}) // gossip lands mid-decision

	if got := r.remoteCounts.FreshCount(ip, decisionNow, time.Minute); got != 2 {
		t.Fatalf("FreshCount with a decision clock older than an in-flight broadcast = %d, want 2: "+
			"the broadcast was treated as a clock rollback and the decision fell back to local-only (fail-open)", got)
	}
	// Enforcement and diagnostics must agree on the same instant.
	if st := r.ClusterFreshness(); st.Stale || !st.Applied {
		t.Fatalf("ClusterFreshness disagrees with FreshCount on a live broadcast: %+v", st)
	}
}

// TestChaos61_InFlightBroadcastStillDeniesAtTheClusterLimit is the end-to-end
// verdict: six local requests plus a broadcast of two against a limit of eight
// must deny, through the production AllowClusterAware path, while Apply is
// landing continuously (the gossip-every-millisecond shape of the CI failure).
// Under the defect a decision whose clock predates the latest stamp admits.
func TestChaos61_InFlightBroadcastStillDeniesAtTheClusterLimit(t *testing.T) {
	const limit = 8
	r := withClusterRateLimiter(t, limit, time.Minute)
	const ip = "198.51.100.72"
	for i := 0; i < 6; i++ {
		if !r.Allow(ip) {
			t.Fatal("priming local count")
		}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				r.remoteCounts.Apply(map[string]int{ip: 2})
			}
		}
	}()
	r.remoteCounts.Apply(map[string]int{ip: 2})
	admitted := 0
	for i := 0; i < 5000; i++ {
		if r.AllowClusterAware(ip) {
			admitted++
		}
	}
	close(stop)
	<-done
	if admitted != 0 {
		t.Fatalf("%d of 5000 decisions admitted %s over the cluster-wide limit while broadcasts were landing", admitted, ip)
	}
}

// TestChaos61_GenuineRollbackIsStillStale pins the half the fix must not move:
// a stamp that is in the future against a clock read taken AFTER it was loaded
// is a real rollback and contributes zero, on both FreshCount and the
// production decision, exactly as TestChaos61_ClockRollbackDegradesToLocal
// requires. The re-read must not turn the rollback rule into "always fresh".
func TestChaos61_GenuineRollbackIsStillStale(t *testing.T) {
	const limit = 10
	r := withClusterRateLimiter(t, limit, time.Minute)
	const ip = "203.0.113.6"
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(2*time.Hour))

	if got := r.remoteCounts.FreshCount(ip, time.Now(), time.Minute); got != 0 {
		t.Fatalf("FreshCount on a future-stamped broadcast = %d, want 0 (clock rollback must stay stale)", got)
	}
	if !r.AllowClusterAware(ip) {
		t.Fatal("a future-stamped broadcast is still suppressing traffic")
	}
	if st := r.ClusterFreshness(); !st.Stale {
		t.Fatal("ClusterFreshness must still report a future-stamped broadcast as stale")
	}
	// A stamp only just ahead of the caller's clock but behind the re-read is
	// NOT a rollback; one ahead of both is. The boundary is the re-read, not
	// the caller's clock.
	r.remoteCounts.applyAtForTest(map[string]int{ip: limit}, time.Now().Add(time.Hour))
	if got := r.remoteCounts.FreshCount(ip, time.Now().Add(-time.Second), time.Minute); got != 0 {
		t.Fatalf("a stamp ahead of the re-read clock counted %d, want 0", got)
	}
}
