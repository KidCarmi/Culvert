package main

// cluster_ratelimit_budget_chaos111_test.go — CHAOS-111 gates for the hot-IP
// gossip plane in package main: the wire legs, the Control Plane's cached
// aggregation generation, the omission accounting, and the controls that stop
// each fix being passed the cheap way.
//
// The pre-fix failure these reproduce is NOT "a message got large". It is the
// plane switching itself off: one SyncRateLimits call took 5.542 s against its
// own 5 s deadline because the fleet total map was rebuilt inside every call,
// a round owed ~277 s of serial work against a 5 s interval, and the resulting
// stale broadcast degraded every node to LOCAL limiting — 50x the configured
// limit on a 50-node fleet. So the gates assert COST and VERDICT, not only
// byte counts.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestRLAggregator returns an aggregator isolated from the process global.
func newTestRLAggregator() *rateLimitAggregator {
	return &rateLimitAggregator{
		perNode:  map[string]map[string]int{},
		expireAt: map[string]time.Time{},
	}
}

// resetCHAOS111Accounting restores every omission counter and gauge after a
// test. They are process globals: a test that charges them and does not restore
// them makes the next test's assertion about a gauge depend on run order.
func resetCHAOS111Accounting(t *testing.T) {
	t.Helper()
	exT, inT, bcT := rlExportOmittedTotal.Load(), rlIngestOmittedTotal.Load(), rlBroadcastOmittedTotal.Load()
	exN, inN, bcN := rlExportOmittedNow.Load(), rlIngestOmittedNow.Load(), rlBroadcastOmittedNow.Load()
	tracked, logged := rlTrackedIPsNow.Load(), rlOmitLogged.Load()
	t.Cleanup(func() {
		rlExportOmittedTotal.Store(exT)
		rlIngestOmittedTotal.Store(inT)
		rlBroadcastOmittedTotal.Store(bcT)
		rlExportOmittedNow.Store(exN)
		rlIngestOmittedNow.Store(inN)
		rlBroadcastOmittedNow.Store(bcN)
		rlTrackedIPsNow.Store(tracked)
		rlOmitLogged.Store(logged)
	})
}

// hotFixture builds n deltas with deterministic IPv6 addresses and counts.
func hotFixture(nodeIdx, n, count int) []RateLimitDelta {
	deltas := make([]RateLimitDelta, n)
	for i := range deltas {
		j := nodeIdx*n + i
		deltas[i] = RateLimitDelta{IP: fmt.Sprintf("2001:db8:1:%x::%x", j>>16, j&0xffff), Count: count}
	}
	return deltas
}

// naiveTotalsExcluding is the pre-CHAOS-111 definition, kept as the oracle: sum
// every live node's slot except the requester's, positive entries only.
func naiveTotalsExcluding(a *rateLimitAggregator, exclude string) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	totals := map[string]int{}
	for nid, counts := range a.perNode {
		if nid == exclude {
			continue
		}
		for ip, count := range counts {
			totals[ip] += count
		}
	}
	return totals
}

// ─── The request leg, through the REAL frame ────────────────────────────────

// TestCHAOS111_GossipOverTheBoundStillSyncs is the end-to-end defect gate, run
// against the production registration and the production call options, i.e.
// the REAL 16 MiB inbound limit. Its NEGATIVE CONTROL goes first: it proves the
// pre-fix shape — one entry per hot IP, unbounded — is refused outright, so the
// success below is load-bearing rather than a message that was always going to
// fit.
func TestCHAOS111_GossipOverTheBoundStillSyncs(t *testing.T) {
	resetCHAOS111Accounting(t)
	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })
	prevAgg := globalRLAggregator
	globalRLAggregator = newTestRLAggregator()
	t.Cleanup(func() { globalRLAggregator = prevAgg })

	dial := startBufconnCP(t)
	conn := dial(t, clusterClientCallOptions()...)

	// NEGATIVE CONTROL: the unbounded export a flood produced pre-fix.
	unbounded := RateLimitGossip{NodeID: "dp-flooded", Deltas: hotFixture(0, 500_000, 64)}
	raw, err := json.Marshal(unbounded)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= maxClusterInboundMsgSize {
		t.Fatalf("control fixture is only %d bytes; it must exceed the %d byte inbound limit to be meaningful",
			len(raw), maxClusterInboundMsgSize)
	}
	var resp json.RawMessage
	if err := conn.Invoke(context.Background(), methodSyncRateLimits, json.RawMessage(raw), &resp); err == nil {
		t.Fatal("control: an unbounded hot-IP gossip request was ACCEPTED; the 16 MiB inbound limit no longer bounds this leg, so the bound below proves nothing")
	}

	// The fix: the same flood, exported through the production bound.
	limiter := newRateLimiter()
	limiter.Configure(2, time.Minute) // threshold clamps to 1: one request makes an IP hot
	for i := range maxExportedHotIPs * 3 {
		limiter.Allow(fmt.Sprintf("2001:db8:2:%x::%x", i>>16, i&0xffff))
	}
	deltas, omitted := rateLimitWireDeltas(limiter)
	if len(deltas) != maxExportedHotIPs {
		t.Fatalf("bounded export carried %d entries, want the bound %d", len(deltas), maxExportedHotIPs)
	}
	if omitted != maxExportedHotIPs*2 {
		t.Fatalf("omitted = %d, want %d", omitted, maxExportedHotIPs*2)
	}
	body, err := json.Marshal(RateLimitGossip{NodeID: "dp-flooded", Deltas: deltas})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > maxClusterInboundMsgSize {
		t.Fatalf("bounded request is %d bytes, over the %d byte limit", len(body), maxClusterInboundMsgSize)
	}
	resp = nil
	if err := conn.Invoke(context.Background(), methodSyncRateLimits, json.RawMessage(body), &resp); err != nil {
		t.Fatalf("bounded hot-IP gossip failed through the real frame: %v", err)
	}
	var broadcast RateLimitBroadcast
	if err := json.Unmarshal(resp, &broadcast); err != nil {
		t.Fatalf("decode broadcast: %v", err)
	}
	if nodes, hot := globalRLAggregator.Stats(); nodes != 1 || hot != maxExportedHotIPs {
		t.Fatalf("Control Plane retained nodes=%d hot=%d, want 1 and %d", nodes, hot, maxExportedHotIPs)
	}
}

// ─── The cost that actually failed ──────────────────────────────────────────

//
// The WALL-CLOCK gates for this section (a 50-node round inside the gossip
// interval, with the pre-fix per-call rebuild as an in-run control, and Stats
// against an already-built generation) live in the isolated benchgate path,
// cluster_ratelimit_budget_chaos111_benchgate_test.go: a production budget
// applied under the default suite's race and coverage instrumentation measures
// the instrumentation, not the fix. What stays here is the STRUCTURE those
// timings rest on, asserted deterministically.

// pinRLGeneration returns the aggregator's current generation with its build
// stamp refreshed, so the next call is inside rlTotalsCacheTTL however slow the
// runner. It keeps the structural gates below deterministic under -race and
// coverage, where a real round can legitimately outlive the TTL.
func pinRLGeneration(t *testing.T, agg *rateLimitAggregator) *rlTotalsGeneration {
	t.Helper()
	agg.mu.Lock()
	defer agg.mu.Unlock()
	if agg.gen == nil {
		t.Fatal("no generation has been built")
	}
	agg.gen.builtAt = time.Now()
	return agg.gen
}

// currentRLGeneration reads the aggregator's published generation.
func currentRLGeneration(agg *rateLimitAggregator) *rlTotalsGeneration {
	agg.mu.Lock()
	defer agg.mu.Unlock()
	return agg.gen
}

// TestCHAOS111_AWholeRoundIsServedFromOneGeneration is the functional half of
// the finding's gate; the wall-clock half is
// TestBenchGate_CHAOS111_AWholeRoundStaysInsideTheGossipInterval. Every node in
// the fleet gossips once per interval, and each call used to rebuild the fleet
// total map under one global mutex, so the round cost was quadratic in fleet
// size. A full round of known nodes — each ingest plus its reply, marshalled,
// exactly as SyncRateLimits does it — must be served from ONE generation, with
// every reply bounded. Removing the cache (rebuilding per call) fails the
// identity check, which no runner speed can mask.
func TestCHAOS111_AWholeRoundIsServedFromOneGeneration(t *testing.T) {
	resetCHAOS111Accounting(t)
	const nodes = 50
	agg := newTestRLAggregator()
	for n := range nodes {
		agg.Update(fmt.Sprintf("dp-node-%02d", n), hotFixture(n, maxGossipHotIPsPerNode, 64))
	}
	agg.ClusterTotalsExcluding("dp-node-00") // build the generation

	fleet := nodes * maxGossipHotIPsPerNode
	for n := range nodes {
		id := fmt.Sprintf("dp-node-%02d", n)
		agg.Update(id, hotFixture(n, maxGossipHotIPsPerNode, 64))
		gen := pinRLGeneration(t, agg)
		totals, omitted := agg.ClusterTotalsExcluding(id)
		if currentRLGeneration(agg) != gen {
			t.Fatalf("%s: the reply rebuilt the generation inside its TTL; a round must be served from one cached aggregation", id)
		}
		if len(totals) == 0 || len(totals) > maxBroadcastHotIPs {
			t.Fatalf("%s: reply carried %d entries, want 1..%d", id, len(totals), maxBroadcastHotIPs)
		}
		// Every other node's addresses have a positive remote count; whatever
		// the reply does not carry must be reported, never silently dropped.
		if want := fleet - maxGossipHotIPsPerNode - len(totals); omitted < want {
			t.Fatalf("%s: omitted = %d, want at least %d (%d remote hot IPs, %d carried)",
				id, omitted, want, fleet-maxGossipHotIPsPerNode, len(totals))
		}
		if _, err := json.Marshal(RateLimitBroadcast{RemoteCounts: totals}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCHAOS111_StatsDoesNotWalkTheFleet pins the admin-surface half
// functionally; the per-call cost is TestBenchGate_CHAOS111_StatsDoesNotWalkTheFleet.
// Stats() used to build a set of every IP on every node while holding the
// aggregator mutex — 1.736 s at 50 x 50 000, from a viewer-gated GET — so the
// dashboard that REPORTS the overload competed with the data path's ingest for
// the lock. It must answer from the generation already built, without
// rebuilding it, and report the numbers the walk would.
func TestCHAOS111_StatsDoesNotWalkTheFleet(t *testing.T) {
	resetCHAOS111Accounting(t)
	const nodes = 50
	agg := newTestRLAggregator()
	for n := range nodes {
		agg.Update(fmt.Sprintf("dp-node-%02d", n), hotFixture(n, maxGossipHotIPsPerNode, 64))
	}
	agg.ClusterTotalsExcluding("dp-node-00") // build the generation

	for range 200 {
		gen := pinRLGeneration(t, agg)
		if gotNodes, gotIPs := agg.Stats(); gotNodes != nodes || gotIPs != nodes*maxGossipHotIPsPerNode {
			t.Fatalf("Stats = (%d, %d), want (%d, %d)", gotNodes, gotIPs, nodes, nodes*maxGossipHotIPsPerNode)
		}
		if currentRLGeneration(agg) != gen {
			t.Fatal("Stats() rebuilt the generation inside its TTL; it must read the one already built")
		}
	}
}

// ─── Equivalence: the bound must not change ordinary behaviour ──────────────

// TestCHAOS111_ControlTotalsMatchThePreFixDefinition is the differential
// oracle. For a fleet whose hot set fits the bounds — which is every deployment
// not under a distinct-address flood — the reply must equal the pre-fix
// definition entry for entry, and omit nothing. The cheapest ways to pass the
// cost gate above are to send less or to cache too long; both fail here.
func TestCHAOS111_ControlTotalsMatchThePreFixDefinition(t *testing.T) {
	resetCHAOS111Accounting(t)
	agg := newTestRLAggregator()
	// Overlapping sets, so an IP's total genuinely spans nodes, plus one IP
	// that exists ONLY on the requester (the pre-fix code omitted it, because
	// its total excluding the requester is zero).
	agg.Update("node-a", []RateLimitDelta{
		{IP: "198.51.100.1", Count: 30}, {IP: "198.51.100.2", Count: 20}, {IP: "198.51.100.9", Count: 11},
	})
	agg.Update("node-b", []RateLimitDelta{
		{IP: "198.51.100.1", Count: 10}, {IP: "198.51.100.3", Count: 5},
	})
	agg.Update("node-c", []RateLimitDelta{
		{IP: "198.51.100.2", Count: 7}, {IP: "198.51.100.3", Count: 1},
	})

	for _, node := range []string{"node-a", "node-b", "node-c", "node-unknown"} {
		got, omitted := agg.ClusterTotalsExcluding(node)
		if omitted != 0 {
			t.Fatalf("%s: omitted = %d for a hot set inside every bound, want 0", node, omitted)
		}
		want := naiveTotalsExcluding(agg, node)
		for ip, count := range want {
			if count <= 0 {
				continue
			}
			if got[ip] != count {
				t.Fatalf("%s: %s = %d, pre-fix definition says %d", node, ip, got[ip], count)
			}
		}
		for ip, count := range got {
			if want[ip] != count {
				t.Fatalf("%s: reply carries %s = %d, which the pre-fix definition does not", node, ip, count)
			}
		}
		if _, ok := got["198.51.100.9"]; ok && node == "node-a" {
			t.Fatal("an IP only node-a reported must not be in node-a's own reply")
		}
	}
}

// TestCHAOS111_GenerationIsSelfConsistentAcrossASlotReplacement pins why the
// generation records the slots it summed instead of reading the live ones.
// Subtracting a node's CURRENT slot from an older total over-subtracts and
// under-counts the cluster — the fail-open direction — whenever the node's
// counts have grown since the generation was built.
func TestCHAOS111_GenerationIsSelfConsistentAcrossASlotReplacement(t *testing.T) {
	resetCHAOS111Accounting(t)
	agg := newTestRLAggregator()
	agg.Update("node-a", []RateLimitDelta{{IP: "203.0.113.5", Count: 10}})
	agg.Update("node-b", []RateLimitDelta{{IP: "203.0.113.5", Count: 4}})
	if got, _ := agg.ClusterTotalsExcluding("node-a"); got["203.0.113.5"] != 4 {
		t.Fatalf("first reply = %d, want 4", got["203.0.113.5"])
	}
	// node-a's traffic grows inside the cached generation's TTL.
	agg.Update("node-a", []RateLimitDelta{{IP: "203.0.113.5", Count: 900}})
	got, _ := agg.ClusterTotalsExcluding("node-a")
	if got["203.0.113.5"] != 4 {
		t.Fatalf("reply after a slot replacement = %d, want 4: the generation must subtract the slot it SUMMED, "+
			"not the live one (900 against a total of 14 would under-count the cluster to zero)", got["203.0.113.5"])
	}
}

// TestCHAOS111_ANewNodeIsVisibleAtOnce pins the one invalidation the cache
// keeps. A node contributing nothing until the generation ages out would make
// the fleet undercount for up to rlTotalsCacheTTL on every enrollment.
func TestCHAOS111_ANewNodeIsVisibleAtOnce(t *testing.T) {
	resetCHAOS111Accounting(t)
	agg := newTestRLAggregator()
	agg.Update("node-a", []RateLimitDelta{{IP: "203.0.113.7", Count: 3}})
	agg.ClusterTotalsExcluding("node-a") // generation built without node-b
	agg.Update("node-b", []RateLimitDelta{{IP: "203.0.113.7", Count: 5}})
	if got, _ := agg.ClusterTotalsExcluding("node-a"); got["203.0.113.7"] != 5 {
		t.Fatalf("a newly seen node contributed %d, want 5 immediately", got["203.0.113.7"])
	}
}

// TestCHAOS111_ControlStaleNodesArePrunedByTheGeneration pins that moving the
// prune into the rebuild did not lose it: a node that goes quiet past
// rlNodeStaleAfter stops counting.
func TestCHAOS111_ControlStaleNodesArePrunedByTheGeneration(t *testing.T) {
	resetCHAOS111Accounting(t)
	agg := newTestRLAggregator()
	agg.perNode["gone"] = map[string]int{"203.0.113.1": 100}
	agg.expireAt["gone"] = time.Now().Add(-rlNodeStaleAfter - time.Minute)
	agg.Update("live", []RateLimitDelta{{IP: "203.0.113.2", Count: 5}})
	got, _ := agg.ClusterTotalsExcluding("live")
	if _, ok := got["203.0.113.1"]; ok {
		t.Fatal("a node quiet past rlNodeStaleAfter still contributes to the broadcast")
	}
	if nodes, _ := agg.Stats(); nodes != 1 {
		t.Fatalf("Stats nodes = %d after pruning, want 1", nodes)
	}
}

// ─── The receiver does not trust the sender ─────────────────────────────────

// TestCHAOS111_IngestBoundHoldsAgainstAPeerIgnoringIt drives the REAL handler
// with a gossip far over the bound — a node predating the export bound, or one
// behaving badly. What the Control Plane RETAINS is its own decision, because
// retained heap x fleet size is what made the aggregator attacker-sized.
func TestCHAOS111_IngestBoundHoldsAgainstAPeerIgnoringIt(t *testing.T) {
	resetCHAOS111Accounting(t)
	prevInsecure := clusterInsecure
	clusterInsecure = true
	t.Cleanup(func() { clusterInsecure = prevInsecure })
	prevAgg := globalRLAggregator
	globalRLAggregator = newTestRLAggregator()
	t.Cleanup(func() { globalRLAggregator = prevAgg })

	// One hotter IP must survive the truncation; the rest are colder.
	deltas := hotFixture(0, maxGossipHotIPsPerNode*2, 50)
	deltas = append(deltas, RateLimitDelta{IP: "203.0.113.200", Count: 9999})
	raw, err := json.Marshal(RateLimitGossip{NodeID: "dp-old", Deltas: deltas})
	if err != nil {
		t.Fatal(err)
	}
	srv := &controlPlaneServer{}
	if _, err := srv.SyncRateLimits(context.Background(), raw); err != nil {
		t.Fatalf("SyncRateLimits refused an over-bound gossip instead of truncating it: %v", err)
	}
	_, hot := globalRLAggregator.Stats()
	if hot != maxGossipHotIPsPerNode {
		t.Fatalf("Control Plane retained %d hot IPs from one node, want the bound %d", hot, maxGossipHotIPsPerNode)
	}
	if want := len(deltas) - maxGossipHotIPsPerNode; rlIngestOmittedNow.Load() != int64(want) {
		t.Fatalf("ingest omission gauge = %d, want %d", rlIngestOmittedNow.Load(), want)
	}
	if rlIngestOmittedTotal.Load() == 0 {
		t.Fatal("ingest omission counter was not charged")
	}
	// The truncation must keep the HOTTEST, which is the one an operator cares
	// about: it is the IP closest to crossing the limit.
	totals, _ := globalRLAggregator.ClusterTotalsExcluding("someone-else")
	if totals["203.0.113.200"] != 9999 {
		t.Fatalf("the hottest IP was truncated away (got %d): the bound must drop the COLDEST", totals["203.0.113.200"])
	}
}

// ─── Accounting: present tense vs cumulative (AU-43) ────────────────────────

// TestCHAOS111_OmissionGaugeClearsWhenTheHotSetFitsAgain is the AU-43 gate. A
// present-tense claim must name the value that clears it, and the gauges are
// rewritten on EVERY round including the ones that omit nothing.
func TestCHAOS111_OmissionGaugeClearsWhenTheHotSetFitsAgain(t *testing.T) {
	resetCHAOS111Accounting(t)
	rlExportOmittedTotal.Store(0)
	rlExportOmittedNow.Store(0)

	limiter := newRateLimiter()
	limiter.Configure(2, time.Minute)
	for i := range maxExportedHotIPs + 25 {
		limiter.Allow(fmt.Sprintf("2001:db8:3:%x::%x", i>>16, i&0xffff))
	}
	_, omitted := rateLimitWireDeltas(limiter)
	noteRateLimitHotIPsOmitted(&rlExportOmittedTotal, &rlExportOmittedNow, "export", "dp-1", omitted, maxExportedHotIPs)
	if rlExportOmittedNow.Load() != 25 {
		t.Fatalf("export gauge = %d while over the bound, want 25", rlExportOmittedNow.Load())
	}
	charged := rlExportOmittedTotal.Load()
	if charged != 25 {
		t.Fatalf("export counter = %d, want 25", charged)
	}

	// The flood stops; the next round's hot set fits.
	fits := newRateLimiter()
	fits.Configure(100, time.Minute)
	for range 60 {
		fits.Allow("198.51.100.44")
	}
	_, omitted = rateLimitWireDeltas(fits)
	noteRateLimitHotIPsOmitted(&rlExportOmittedTotal, &rlExportOmittedNow, "export", "dp-1", omitted, maxExportedHotIPs)
	if rlExportOmittedNow.Load() != 0 {
		t.Fatalf("export gauge = %d after a round that omitted nothing, want 0: a present-tense surface must clear",
			rlExportOmittedNow.Load())
	}
	// CONTROL: the cheapest way to clear the gauge is to zero the counter,
	// which deletes the magnitude every rate alert is built on.
	if rlExportOmittedTotal.Load() != charged {
		t.Fatalf("control: the cumulative counter changed from %d to %d on recovery; it must survive",
			charged, rlExportOmittedTotal.Load())
	}
}

// ─── The security property the truncation rests on ──────────────────────────

// TestCHAOS111_AnOmittedIPKeepsItsLocalRateLimit is the gate for the whole
// safety argument. Truncating gossip is only acceptable because an omitted IP
// still has a LOCAL count, and AllowClusterAware sums local + remote — so an
// omission narrows ONE address from cluster-aware to local. The pre-fix failure
// narrowed EVERY address on EVERY node at once, which is what made a 50-node
// fleet admit 50x the configured limit.
func TestCHAOS111_AnOmittedIPKeepsItsLocalRateLimit(t *testing.T) {
	resetCHAOS111Accounting(t)
	limiter := newRateLimiter()
	limiter.Configure(4, time.Minute) // threshold clamps to 2
	limiter.SetClusterEnabled(true)

	// Flood past the export bound so this address is certain to be omitted:
	// every other IP is hotter.
	const victim = "198.51.100.77"
	for range 2 {
		if !limiter.AllowAuto(victim) {
			t.Fatal("priming the victim's local count")
		}
	}
	for i := range maxExportedHotIPs * 2 {
		ip := fmt.Sprintf("2001:db8:4:%x::%x", i>>16, i&0xffff)
		for range 3 {
			limiter.AllowAuto(ip)
		}
	}
	deltas, omitted := rateLimitWireDeltas(limiter)
	if omitted == 0 {
		t.Fatal("fixture did not exceed the export bound")
	}
	for i := range deltas {
		if deltas[i].IP == victim {
			t.Fatal("fixture error: the victim was not omitted, so this gate proves nothing")
		}
	}
	// Omitted from gossip, still locally limited: 2 already spent of 4.
	for i := range 2 {
		if !limiter.AllowAuto(victim) {
			t.Fatalf("request %d denied below the local limit", i)
		}
	}
	if limiter.AllowAuto(victim) {
		t.Fatal("an IP omitted from the gossip export escaped its LOCAL rate limit: the truncation is only safe because it does not")
	}
}

// ─── Operator surfaces ──────────────────────────────────────────────────────

// TestCHAOS111_OperatorSurfacesNameTheBound pins that the degradation is
// visible. Pre-fix, the only operator-facing signal was CHAOS-61's freshness
// WARN, which says "no Control Plane broadcast" — it names an OUTAGE, so an
// operator looks at Control Plane health and finds a healthy Control Plane
// burning CPU. Metrics and the API must distinguish the two causes.
func TestCHAOS111_OperatorSurfacesNameTheBound(t *testing.T) {
	resetCHAOS111Accounting(t)
	rlIngestOmittedTotal.Store(7)
	rlIngestOmittedNow.Store(3)
	rlTrackedIPsNow.Store(4242)

	body := renderMetrics(t)
	for _, want := range []string{
		`culvert_cluster_ratelimit_hot_ips_omitted_total{leg="export"}`,
		`culvert_cluster_ratelimit_hot_ips_omitted_total{leg="ingest"} 7`,
		`culvert_cluster_ratelimit_hot_ips_omitted_total{leg="broadcast"}`,
		`culvert_cluster_ratelimit_hot_ips_omitted{leg="ingest"} 3`,
		"culvert_cluster_ratelimit_tracked_ips 4242",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics is missing %q", want)
		}
	}

	out := httptest.NewRecorder()
	apiClusterRateLimits(out, withRole(httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/cluster/rate-limits", http.NoBody), RoleViewer))
	if out.Code != http.StatusOK {
		t.Fatalf("GET /api/cluster/rate-limits = %d", out.Code)
	}
	var status map[string]any
	if err := json.Unmarshal(out.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"hot_ips_per_node_bound", "hot_ips_broadcast_bound",
		"hot_ips_omitted_export", "hot_ips_omitted_ingest", "hot_ips_omitted_broadcast",
		"hot_ips_omitted_total",
	} {
		if _, ok := status[key]; !ok {
			t.Fatalf("GET /api/cluster/rate-limits is missing %q: %s", key, out.Body.String())
		}
	}
	if status["hot_ips_omitted_ingest"] != float64(3) {
		t.Fatalf("hot_ips_omitted_ingest = %v, want 3", status["hot_ips_omitted_ingest"])
	}
	if status["hot_ips_per_node_bound"] != float64(maxGossipHotIPsPerNode) {
		t.Fatalf("hot_ips_per_node_bound = %v, want %d", status["hot_ips_per_node_bound"], maxGossipHotIPsPerNode)
	}
}

// TestCHAOS111_OmissionLogIsRateLimited pins that a per-round degradation does
// not become a per-round log line. The gossip loop runs every 5 s on every
// node, and X-2 records the log sink as blocking the request goroutine when
// full, so an unbounded line here would turn a flood into a second amplifier.
func TestCHAOS111_OmissionLogIsRateLimited(t *testing.T) {
	resetCHAOS111Accounting(t)
	rlOmitLogged.Store(0)
	lines := captureLogger(t, func() {
		for range 50 {
			noteRateLimitHotIPsOmitted(&rlIngestOmittedTotal, &rlIngestOmittedNow, "ingest", "dp-1", 10, 4096)
		}
	})
	if got := strings.Count(lines, "hot-IP gossip"); got != 1 {
		t.Fatalf("50 omitting rounds produced %d log lines, want exactly 1 inside the %s interval:\n%s",
			got, rlOmitLogInterval, lines)
	}
	if rlIngestOmittedTotal.Load() != 500 {
		t.Fatalf("rate limiting the LOG also rate limited the COUNTER: total = %d, want 500", rlIngestOmittedTotal.Load())
	}
}

// TestCHAOS111_ARequesterAlwaysGetsTheClusterSumForItsOwnHotSet is the gate for
// the broadcast leg's safety argument, and it is the counterpart of
// TestCHAOS111_AnOmittedIPKeepsItsLocalRateLimit on the export leg.
//
// Bounding a reply is only acceptable because the entries that are DROPPED are
// addresses this node is not currently handling: every hot IP the requester
// itself reported is carried, so its next AllowClusterAware verdict for an
// address it is actually seeing still has the cluster-wide half of the count.
// A reply built purely from a fleet-wide hotness ranking would NOT have this
// property — a node whose own traffic is modest next to a flood elsewhere would
// receive a reply full of addresses it will never see.
func TestCHAOS111_ARequesterAlwaysGetsTheClusterSumForItsOwnHotSet(t *testing.T) {
	resetCHAOS111Accounting(t)
	agg := newTestRLAggregator()

	// A quiet node with a small hot set, and a flood everywhere else whose
	// counts are far hotter and whose cardinality dwarfs the reply bound.
	const quiet = "dp-quiet"
	quietIPs := make([]RateLimitDelta, 64)
	for i := range quietIPs {
		quietIPs[i] = RateLimitDelta{IP: fmt.Sprintf("198.51.100.%d", i), Count: 3}
	}
	agg.Update(quiet, quietIPs)
	// A peer that shares the quiet node's addresses, so each has a positive
	// cluster-wide remainder once the quiet node's own contribution is removed.
	peerIPs := make([]RateLimitDelta, len(quietIPs))
	for i := range peerIPs {
		peerIPs[i] = RateLimitDelta{IP: quietIPs[i].IP, Count: 2}
	}
	agg.Update("dp-peer", peerIPs)
	for n := range 10 {
		agg.Update(fmt.Sprintf("dp-flood-%02d", n), hotFixture(n, maxGossipHotIPsPerNode, 9000))
	}

	totals, omitted := agg.ClusterTotalsExcluding(quiet)
	if omitted == 0 {
		t.Fatal("fixture did not exceed the broadcast bound, so this gate proves nothing")
	}
	if len(totals) > maxBroadcastHotIPs {
		t.Fatalf("reply carried %d entries, over the bound %d", len(totals), maxBroadcastHotIPs)
	}
	// Every fixture IP has a positive remainder for the quiet node, so the
	// exact omission is the oracle's count minus what the reply carried. The
	// quiet node's own IPs rank below the candidates and are returned by pass
	// 1; counting them as omitted overstated lost coverage in the gauge.
	if want := len(naiveTotalsExcluding(agg, quiet)) - len(totals); omitted != want {
		t.Fatalf("omitted = %d, want %d: own-set IPs the reply carries must not be counted as omitted", omitted, want)
	}
	for i := range quietIPs {
		ip := quietIPs[i].IP
		if totals[ip] != 2 {
			t.Fatalf("%s = %d in the quiet node's reply, want its cluster remainder 2: a node must always "+
				"receive the cluster sum for every hot IP it reported itself, however large the flood elsewhere",
				ip, totals[ip])
		}
	}
}

// TestCHAOS111_TheBoundsRelationThatMakesPassOneSafe pins the coupling the
// own-set guarantee rests on, because it is implicit in the code.
//
// Pass 1 of ClusterTotalsExcluding is NOT itself bounded by
// maxBroadcastHotIPs: it adds every hot IP the requester reported. That is safe
// only because a requester's slot is bounded by maxGossipHotIPsPerNode and the
// reply bound is at least twice it — so pass 1 can never fill the reply and
// starve pass 2, and no requester's own set can be truncated. Shrinking
// maxBroadcastHotIPs relative to the per-node bound would break both
// properties silently, which is exactly the kind of change a constant invites.
func TestCHAOS111_TheBoundsRelationThatMakesPassOneSafe(t *testing.T) {
	if maxBroadcastHotIPs < 2*maxGossipHotIPsPerNode {
		t.Fatalf("maxBroadcastHotIPs (%d) must be at least twice maxGossipHotIPsPerNode (%d): "+
			"pass 1 of the reply is unbounded by design and would otherwise be able to fill the whole "+
			"reply, starving the fleet-hottest fill and breaking the guarantee that a requester always "+
			"receives the cluster sum for its own hot set",
			maxBroadcastHotIPs, maxGossipHotIPsPerNode)
	}
	if maxGossipHotIPsPerNode != maxExportedHotIPs {
		t.Fatalf("the Control Plane's ingest bound (%d) and the Data Plane's export bound (%d) must be the "+
			"same number, or a current node is truncated twice: once by itself and again by its peer",
			maxGossipHotIPsPerNode, maxExportedHotIPs)
	}
	if rlTotalsCacheTTL >= rlGossipInterval {
		t.Fatalf("rlTotalsCacheTTL (%s) must be well inside the gossip interval (%s), or a generation "+
			"serves rounds it has no data for", rlTotalsCacheTTL, rlGossipInterval)
	}
}

// TestCHAOS111_ANewlyReportedOwnIPGetsItsClusterSumInsideACachedGeneration
// pins the own-hot-set guarantee across the cache: an existing node that
// reports a NEW hot IP while the cached generation still holds its PREVIOUS
// slot must receive the cluster sum for that IP, even when it ranks below every
// cached fleet candidate. Pass 1 must select from the requester's LATEST keys,
// while still subtracting the slot the generation summed (an IP absent from
// that slot contributes nothing of the requester's own to gen.totals, so the
// remainder is exactly the peers' counts).
//
// Pre-fix, selection came from the generation's slot, so the new IP was not
// prioritized and, with 20,480 hotter fleet addresses filling the candidate
// ranking, it was dropped: a remote count of zero for an address the node is
// handling, i.e. a successful broadcast that silently lost cluster enforcement
// for it until the next rebuild.
func TestCHAOS111_ANewlyReportedOwnIPGetsItsClusterSumInsideACachedGeneration(t *testing.T) {
	resetCHAOS111Accounting(t)
	agg := newTestRLAggregator()

	const (
		requester = "dp-existing"
		newIP     = "198.51.100.250"
	)
	// The requester's PREVIOUS hot set, which the generation will hold.
	agg.Update(requester, []RateLimitDelta{{IP: "198.51.100.1", Count: 3}})
	// A peer already counting the address the requester is about to report.
	agg.Update("dp-peer", []RateLimitDelta{{IP: newIP, Count: 2}})
	// 20,480 fleet addresses, every one hotter than newIP, so the cached
	// candidate ranking (maxBroadcastHotIPs*rlBroadcastCandidateFactor) cannot
	// reach it.
	const floodNodes = 5
	for n := range floodNodes {
		agg.Update(fmt.Sprintf("dp-flood-%02d", n), hotFixture(n, maxGossipHotIPsPerNode, 9000))
	}
	if got := floodNodes * maxGossipHotIPsPerNode; got != 20_480 || got <= maxBroadcastHotIPs*rlBroadcastCandidateFactor {
		t.Fatalf("fixture: %d flood addresses must be 20,480 and exceed the %d cached candidates",
			got, maxBroadcastHotIPs*rlBroadcastCandidateFactor)
	}

	// Build the generation with the requester's previous slot.
	agg.ClusterTotalsExcluding(requester)

	// The requester reports newIP. It is a KNOWN node, so the cached
	// generation deliberately survives the update.
	agg.Update(requester, []RateLimitDelta{{IP: "198.51.100.1", Count: 3}, {IP: newIP, Count: 3}})
	if currentRLGeneration(agg) == nil {
		t.Fatal("fixture: a known node's update invalidated the generation, so this gate does not exercise the cache")
	}
	// Pin the generation inside its TTL so a slow (race/coverage) runner
	// cannot rebuild it and pass this gate without exercising the cache.
	gen := pinRLGeneration(t, agg)
	if _, inGen := gen.perNode[requester][newIP]; inGen {
		t.Fatal("fixture: the generation already holds the requester's new slot")
	}

	totals, _ := agg.ClusterTotalsExcluding(requester)
	if currentRLGeneration(agg) != gen {
		t.Fatal("fixture: the reply was served from a rebuilt generation, not the cached one")
	}
	if totals[newIP] != 2 {
		t.Fatalf("%s = %d in the requester's reply, want the peer's count 2: a hot IP the requester reported "+
			"must carry its cluster sum even when the cached generation predates that report", newIP, totals[newIP])
	}
	// The generation's own slot is still what is subtracted: the requester's
	// previously reported IP has no peer count, so it must stay absent.
	if c, ok := totals["198.51.100.1"]; ok {
		t.Fatalf("198.51.100.1 = %d in the requester's reply; only the requester reported it", c)
	}
	if len(totals) > maxBroadcastHotIPs {
		t.Fatalf("reply carried %d entries, over the bound %d", len(totals), maxBroadcastHotIPs)
	}
}
