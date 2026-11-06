package main

// cluster_ratelimit_budget.go — CHAOS-111. Bounds for the hot-IP gossip plane,
// and the cached generation that stops the Control Plane doing O(fleet x hot
// IPs) of work inside every SyncRateLimits call.
//
// THE FAILURE. SyncRateLimits is the one cluster RPC whose body is sized by
// HOSTILE traffic. A Data Plane exports one entry per "hot" IP, an IP is hot at
// HotThresholdPercent of the configured limit, and that threshold clamps to a
// floor of ONE — so at a tight configured limit (1-3 per window) every distinct
// source address seen in the window is exported, for the price of one request
// each. Nothing bounded the export, the Control Plane's per-node slot, the
// reply, or the work either side did per round. Measured on the pre-fix tree, a
// 50-node fleet at 50 000 distinct hot IPs per node:
//
//   - ONE ClusterTotalsExcluding call took 1.844 s and its reply 3.698 s to
//     marshal: 5.542 s for a single RPC against its own 5 s deadline
//     (dpTightCallDeadline), because the fleet total map was rebuilt from
//     scratch inside EVERY call, under ONE global mutex;
//   - a whole round therefore owed 50 x 5.5 s = ~277 s of serial work against
//     the 5 s gossip interval — a 55x oversubscription that cannot drain while
//     the traffic continues, since the work scales with what the traffic sets;
//   - Stats(), reached from the viewer-gated GET /api/cluster/rate-limits, took
//     1.736 s holding that same mutex, so an operator's dashboard refresh
//     competed with the data path's own ingest;
//   - the Control Plane retained 164.2 MiB of reachable heap at 50 x 100 000,
//     keyed by addresses the attacker chooses, pruned only when a NODE goes
//     quiet for two minutes and never by cardinality.
//
// And the end state is a SECURITY failure, not only an availability one. A
// failed or timed-out sync never calls ApplyRemoteCounts, the broadcast ages
// out, and CHAOS-61 — deliberately, correctly — stops consulting an expired
// broadcast, so every node degrades to LOCAL limiting. Measured: a limit of 10
// with no broadcast admitted 500 requests across a 50-node fleet, 50x the
// configured limit. The control is switched off by the flood it exists to stop,
// and the only operator-facing signal says "no Control Plane broadcast", which
// names an outage rather than an overload.
//
// THE RULE, AND WHERE IT CAME FROM. AU-50 found that a SyncRevocations request
// grows with the fleet, budgeted it below maxClusterInboundMsgSize, and wrote
// the general rule into that constant's own doc: "a new inbound RPC whose body
// can grow must be budgeted the same way rather than relying on this
// paragraph." SyncRateLimits was still named in the same doc's "all tiny" list.
// Citing a precedent is not applying it.
//
// THE DIVERGENCE FROM AU-50, AND WHY. A deferred revocation is sent on a later
// tick and the receiver merges additively, so AU-50 could rotate a backlog
// through successive messages and lose nothing. Rate-limit counts are the
// opposite shape: Update REPLACES a node's slot and ApplyRemoteCounts REPLACES
// the whole broadcast, both inside a window measured in seconds. Rotating would
// make an IP's cluster total oscillate between counted and zero every tick,
// which is worse than consistently omitting the coldest. So this plane
// TRUNCATES by hotness instead, and the safety argument is different too:
// an omitted IP keeps its LOCAL count and stays locally rate limited
// (AllowClusterAware sums localCount + remoteCount), so an omission narrows ONE
// address from cluster-aware to local, where the pre-fix failure narrowed EVERY
// address on EVERY node at once. There is no new fail-open path: every bound
// below replaces a state in which the plane carried nothing at all.

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/admission"
)

const (
	// maxGossipHotIPsPerNode is what the Control Plane will RETAIN from one
	// node's gossip. It equals the Data Plane's own export bound so a current
	// node is never truncated twice, and it is enforced here as well because
	// the sender is a peer: an older node predating the export bound, or an
	// enrolled node behaving badly, must not be able to size the Control
	// Plane's heap. N nodes x this bound is the aggregator's ceiling, which is
	// what makes the retained heap a function of FLEET SIZE — an operator
	// quantity — instead of traffic.
	maxGossipHotIPsPerNode = maxExportedHotIPs // 4096

	// maxBroadcastHotIPs bounds ONE reply. The bound that matters here is not
	// the 128 MiB frame the reply rides — it is the per-RPC MARSHAL, which is
	// what blew the 5 s deadline: 3.698 s of the measured 5.542 s was spent
	// encoding a 2.45 M-entry map. At ~44 bytes per IPv6 entry this bound is
	// ~0.3 MiB and ~8 ms, and it is twice the per-node export bound so a
	// requester's OWN hot set can never fill the reply on its own.
	maxBroadcastHotIPs = 2 * maxGossipHotIPsPerNode // 8192

	// rlBroadcastCandidateFactor sizes the cached candidate list as a multiple
	// of maxBroadcastHotIPs. Candidates are ranked by the total INCLUDING the
	// requesting node, because that one ranking is shared by every node and so
	// can be computed once per generation rather than per RPC; a candidate
	// whose only counts are the requester's own resolves to zero and is
	// skipped, and the slack absorbs those without the reply coming back
	// short. It is also what makes the pre-CHAOS-111 reply CONTENTS exact
	// whenever the fleet's distinct hot set fits maxBroadcastHotIPs.
	rlBroadcastCandidateFactor = 2

	// rlTotalsCacheTTL is how long one aggregation generation serves. The
	// gossip interval is 5 s and a broadcast is consulted under a freshness
	// window derived from the rate-limit window (clusterRemoteCountMaxAge), so
	// a second of age is immaterial to a verdict — while recomputing per RPC
	// instead of per second is precisely what made the plane collapse.
	rlTotalsCacheTTL = time.Second

	// rlNodeStaleAfter is how long a node's slot survives without an update.
	// Unchanged from the pre-fix behaviour; only the place it is applied moved
	// into the generation rebuild.
	rlNodeStaleAfter = 2 * time.Minute

	// rlGossipInterval is the Data Plane's hot-IP gossip cadence, named here
	// because the bounds above only make sense against it: a round that cannot
	// finish inside this interval is a plane that cannot keep up with its own
	// cadence, which is exactly the pre-CHAOS-111 state.
	rlGossipInterval = 5 * time.Second
)

// Omission accounting. Cumulative counters carry the magnitude; the present-
// tense gauges carry the CURRENT state and are rewritten on EVERY export,
// ingest and broadcast — including the ones that omit nothing, which is what
// clears them. AU-43's rule: a present-tense claim must name the value that
// clears it, and a cumulative counter can never clear.
var (
	rlExportOmittedTotal    atomic.Uint64
	rlIngestOmittedTotal    atomic.Uint64
	rlBroadcastOmittedTotal atomic.Uint64

	rlExportOmittedNow    atomic.Int64
	rlIngestOmittedNow    atomic.Int64
	rlBroadcastOmittedNow atomic.Int64
	rlTrackedIPsNow       atomic.Int64

	rlOmitLogged atomic.Int64
)

const rlOmitLogInterval = time.Minute

// noteRateLimitHotIPsOmitted charges n omitted hot IPs to a leg and emits the
// explanatory line at most once per interval across all legs. The present-tense
// gauge is written whatever n is, so a leg that stops omitting reports zero.
// node is peer-supplied on the Control Plane legs and is sanitized.
func noteRateLimitHotIPsOmitted(total *atomic.Uint64, now *atomic.Int64, leg, node string, omitted, bound int) {
	now.Store(int64(omitted))
	if omitted <= 0 {
		return
	}
	total.Add(uint64(omitted))
	ts := time.Now().UnixNano()
	prev := rlOmitLogged.Load()
	if prev != 0 && ts-prev < int64(rlOmitLogInterval) {
		return
	}
	if !rlOmitLogged.CompareAndSwap(prev, ts) {
		return
	}
	logger.Printf("WARN cluster rate limiting: hot-IP gossip %s for node %q exceeds its bound of %d; "+
		"%d hot IPs omitted this round (coldest first — each keeps its LOCAL rate limit, "+
		"only the cluster-wide half of its count is not applied)",
		leg, sanitizeLog(node), bound, omitted)
}

// writeClusterRateLimitBudgetMetrics renders the gossip-plane bounds on
// /metrics. The counters are the magnitude an alert rule takes a rate over; the
// gauges are the present-tense state, so a fleet that stops omitting reports 0
// rather than carrying a historical total forever.
func writeClusterRateLimitBudgetMetrics(w *strings.Builder) {
	fmt.Fprintf(w, "\n# HELP culvert_cluster_ratelimit_hot_ips_omitted_total Hot IPs left out of the cluster rate-limit gossip plane because a leg exceeded its bound (export: this Data Plane's gossip; ingest: what this Control Plane retained from one node; broadcast: what one reply carried). An omitted IP keeps its local rate limit; only the cluster-wide half of its count is not applied\n")
	fmt.Fprintf(w, "# TYPE culvert_cluster_ratelimit_hot_ips_omitted_total counter\n")
	fmt.Fprintf(w, "culvert_cluster_ratelimit_hot_ips_omitted_total{leg=\"export\"} %d\nculvert_cluster_ratelimit_hot_ips_omitted_total{leg=\"ingest\"} %d\nculvert_cluster_ratelimit_hot_ips_omitted_total{leg=\"broadcast\"} %d\n",
		rlExportOmittedTotal.Load(), rlIngestOmittedTotal.Load(), rlBroadcastOmittedTotal.Load())
	fmt.Fprintf(w, "# HELP culvert_cluster_ratelimit_hot_ips_omitted Hot IPs the MOST RECENT round of each leg left out. Rewritten every round including the ones that omit nothing, so this clears on its own when the hot set fits again\n")
	fmt.Fprintf(w, "# TYPE culvert_cluster_ratelimit_hot_ips_omitted gauge\n")
	fmt.Fprintf(w, "culvert_cluster_ratelimit_hot_ips_omitted{leg=\"export\"} %d\nculvert_cluster_ratelimit_hot_ips_omitted{leg=\"ingest\"} %d\nculvert_cluster_ratelimit_hot_ips_omitted{leg=\"broadcast\"} %d\n",
		rlExportOmittedNow.Load(), rlIngestOmittedNow.Load(), rlBroadcastOmittedNow.Load())
	fmt.Fprintf(w, "# HELP culvert_cluster_ratelimit_tracked_ips Distinct hot IPs this Control Plane is aggregating across the fleet in the current generation\n")
	fmt.Fprintf(w, "# TYPE culvert_cluster_ratelimit_tracked_ips gauge\nculvert_cluster_ratelimit_tracked_ips %d\n",
		rlTrackedIPsNow.Load())
}

// hottestDeltas selects the n hottest deltas and reports how many were left
// out, reusing the engine's bounded selector so sender and receiver agree on
// what "hottest" means and on how ties break.
func hottestDeltas(deltas []RateLimitDelta, n int) (kept []RateLimitDelta, omitted int) {
	sel := admission.NewHotSelector(n)
	for i := range deltas {
		sel.Offer(admission.HotCount{IP: deltas[i].IP, Count: deltas[i].Count})
	}
	chosen, omitted := sel.Result()
	kept = make([]RateLimitDelta, len(chosen))
	for i := range chosen {
		kept[i] = RateLimitDelta{IP: chosen[i].IP, Count: chosen[i].Count}
	}
	return kept, omitted
}

// hottestKeys returns at most n keys of totals, highest total first. Ties break
// on the key so a reply's contents depend only on the data, never on map
// iteration order.
func hottestKeys(totals map[string]int, n int) []string {
	sel := admission.NewHotSelector(n)
	for ip, count := range totals {
		sel.Offer(admission.HotCount{IP: ip, Count: count})
	}
	chosen, _ := sel.Result()
	keys := make([]string, len(chosen))
	for i := range chosen {
		keys[i] = chosen[i].IP
	}
	return keys
}
