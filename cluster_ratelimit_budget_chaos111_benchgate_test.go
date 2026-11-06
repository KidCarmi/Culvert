//go:build benchgate

package main

// cluster_ratelimit_budget_chaos111_benchgate_test.go — CHAOS-111 wall-clock
// gates for the hot-IP gossip plane. They apply PRODUCTION budgets (the 5 s
// gossip interval, the RPC's own deadline), so they run only in the isolated,
// uninstrumented benchgate job: under the default suite's race and coverage
// instrumentation the same round measured 7.3 s and the gate reported the
// instrumentation, not the fix. The structural assertions these timings rest on
// (one generation per round, Stats served from it) stay in the default suite in
// cluster_ratelimit_budget_chaos111_test.go.
//
//   go test -tags benchgate -run 'TestBenchGate_CHAOS111_' -count=1 -v .

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestBenchGate_CHAOS111_AWholeRoundStaysInsideTheGossipInterval is the gate for
// the finding itself. Every node in the fleet gossips once per interval, and
// each call used to rebuild the fleet total map under one global mutex, so the
// round cost was quadratic in fleet size. The CONTROL measures the pre-fix shape
// on the SAME fixture and requires it to be materially worse — without it, a
// machine fast enough to pass the bound would report the fix as working on a
// tree where it was not.
func TestBenchGate_CHAOS111_AWholeRoundStaysInsideTheGossipInterval(t *testing.T) {
	resetCHAOS111Accounting(t)
	const nodes = 50
	agg := newTestRLAggregator()
	for n := range nodes {
		agg.Update(fmt.Sprintf("dp-node-%02d", n), hotFixture(n, maxGossipHotIPsPerNode, 64))
	}

	// One full round: every node's ingest plus its reply, marshalled, exactly
	// as SyncRateLimits does it.
	start := time.Now()
	for n := range nodes {
		id := fmt.Sprintf("dp-node-%02d", n)
		agg.Update(id, hotFixture(n, maxGossipHotIPsPerNode, 64))
		totals, _ := agg.ClusterTotalsExcluding(id)
		if _, err := json.Marshal(RateLimitBroadcast{RemoteCounts: totals}); err != nil {
			t.Fatal(err)
		}
	}
	round := time.Since(start)

	// CONTROL: the pre-fix read, rebuilt inside every call.
	start = time.Now()
	for n := range nodes {
		totals := naiveTotalsExcluding(agg, fmt.Sprintf("dp-node-%02d", n))
		if _, err := json.Marshal(RateLimitBroadcast{RemoteCounts: totals}); err != nil {
			t.Fatal(err)
		}
	}
	preFix := time.Since(start)

	t.Logf("%d-node round at %d hot IPs each: fixed %s, pre-fix shape %s (%.1fx)",
		nodes, maxGossipHotIPsPerNode, round.Round(time.Millisecond),
		preFix.Round(time.Millisecond), float64(preFix)/float64(round))

	// The budget: a round must finish inside the gossip interval with room to
	// spare, since the Control Plane also serves config polls on the same CPU.
	if budget := rlGossipInterval / 2; round > budget {
		t.Fatalf("a %d-node round took %s, over half the %s gossip interval: the plane cannot keep up with its own cadence",
			nodes, round, rlGossipInterval)
	}
	// And no single reply may approach the RPC's own deadline.
	if perCall := round / nodes; perCall > dpTightCallDeadline/10 {
		t.Fatalf("one gossip call costs %s, within 10x of its %s deadline", perCall, dpTightCallDeadline)
	}
	if preFix < round*2 {
		t.Fatalf("control: the pre-fix per-call rebuild (%s) is not materially worse than the cached generation (%s) on this fixture, so this gate is not measuring the fix",
			preFix, round)
	}
}

// TestBenchGate_CHAOS111_StatsDoesNotWalkTheFleet pins the admin-surface cost.
// Stats() used to build a set of every IP on every node while holding the
// aggregator mutex — 1.736 s at 50 x 50 000, from a viewer-gated GET — so the
// dashboard that REPORTS the overload competed with the data path's ingest for
// the lock.
func TestBenchGate_CHAOS111_StatsDoesNotWalkTheFleet(t *testing.T) {
	resetCHAOS111Accounting(t)
	const nodes = 50
	agg := newTestRLAggregator()
	for n := range nodes {
		agg.Update(fmt.Sprintf("dp-node-%02d", n), hotFixture(n, maxGossipHotIPsPerNode, 64))
	}
	agg.ClusterTotalsExcluding("dp-node-00") // build the generation

	start := time.Now()
	for range 200 {
		if gotNodes, gotIPs := agg.Stats(); gotNodes != nodes || gotIPs != nodes*maxGossipHotIPsPerNode {
			t.Fatalf("Stats = (%d, %d), want (%d, %d)", gotNodes, gotIPs, nodes, nodes*maxGossipHotIPsPerNode)
		}
	}
	el := time.Since(start)
	if perCall := el / 200; perCall > 2*time.Millisecond {
		t.Fatalf("Stats() costs %s per call against a generation already built; it is walking the fleet again", perCall)
	}
}
