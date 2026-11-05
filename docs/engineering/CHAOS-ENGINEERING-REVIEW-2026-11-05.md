# Chaos Engineering Review — 2026-11-05

## CHAOS-111 — The hot-IP gossip plane: the rate limiter that is switched off by the flood it exists to stop

**Date:** 2026-11-05
**Branch:** `claude/serene-cerf-y1t7c9`
**Baseline:** `origin/main` **ee0f2ab** (freshly fetched; `CHAOS-110` is the
highest id anywhere on main, and no open PR held a chaos id at claim time —
#1807, #1705, #1549, #1548, #1536, #1528, #1526).
**Id allocation:** `CHAOS-111` claimed in a committed placeholder row in
[the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) as commit one, before
any code was written, per that file's own convention and the 2026-09-25
amendment.
**Method:** evidence-first source review, then executed fault injection against
a build of the baseline through the production gRPC registration, the production
call options and the real aggregator. Every behavioural claim below was
observed; the commands and raw numbers are in §9. It closes the 2026-10-13
backlog's `X-6`.

---

## 1. Executive summary

`SyncRateLimits` is the one CP↔DP RPC whose **body is sized by hostile
traffic**. Every other inbound message is a fixed-shape report; this one carries
one entry per "hot" IP, and an IP is hot at `HotThresholdPercent` (50%) of the
configured limit — with a **floor of one**
([engine.go `ExportHotDeltasCapped`](../../internal/admission/engine.go)). So at
a tight configured limit (1–3 per window) *every distinct source address seen in
the window is exported, for the price of one request each.*

Nothing bounded any of it: not the export, not what the Control Plane retained
per node, not the reply, and not the work either side did per round.

**The finding is not that a message got large.** It is that the plane
**switches itself off**, and the thing that switches it off is the traffic it
exists to limit. Measured on the baseline, a 50-node fleet at 50,000 distinct
hot IPs per node:

| what | measured |
|---|---|
| one `ClusterTotalsExcluding` | **1.844 s** |
| marshalling its reply (2.45 M entries, 57.3 MiB) | **3.698 s** |
| **one RPC, total** | **5.542 s** — against its own **5 s** deadline (`dpTightCallDeadline`) |
| one whole round (50 nodes) | **~277 s** of serial work, against the **5 s** gossip interval |

The rebuild ran **inside every call**, under **one global mutex**
([controlplane.go `rateLimitAggregator`](../../controlplane.go)), so the
per-round cost was quadratic in fleet size in a quantity the attacker sets. A
55× oversubscription cannot drain while the traffic continues.

**And the end state is a security failure, not only an availability one.** A
failed or timed-out sync never reaches `ApplyRemoteCounts`, the broadcast ages
out, and CHAOS-61 — deliberately and correctly — stops consulting an expired
broadcast rather than enforcing a frozen snapshot of the past. Every node
therefore degrades to **local** limiting. Measured: a configured limit of 10
with no broadcast admitted **500 requests across a 50-node fleet — 50× the
limit.** The attacker both triggers the degradation and collects the multiplier.

Two more surfaces made it worse rather than visible:

- **The Control Plane's retained heap was attacker-keyed and uncapped** —
  **164.2 MiB** at 50 × 100,000, pruned only when a *node* goes quiet for two
  minutes and **never by cardinality**, on the node whose loss is a fleet-wide
  management outage.
- **`Stats()` walked every node's map under the same mutex** — **1.736 s** at
  50 × 50,000, reached from the viewer-gated `GET /api/cluster/rate-limits`. The
  panel that *reports* the overload competed with the data path's own ingest for
  the lock, so an operator refreshing the dashboard amplified the meltdown.

And the only operator-facing signal was CHAOS-61's freshness `WARN`: *"no
Control Plane broadcast within the window."* That sentence is true and it names
the **wrong cause** — an outage, not an overload — so an operator paged on it
checks Control Plane health and finds a healthy Control Plane burning a core.
There was no counter, no cap, no gauge and no alert anywhere on the plane.

### The precedent that was cited and not applied

`AU-50` found that a `SyncRevocations` request grows with the fleet, budgeted it
below `maxClusterInboundMsgSize`, and wrote the general rule into **that
constant's own doc**
([controlplane_snapshot.go:259](../../controlplane_snapshot.go)):

> *a new inbound RPC whose body can grow must be budgeted the same way rather
> than relying on this paragraph.*

`SyncRateLimits` is **named in the same doc's "all tiny" list**, four lines
above, and was still unbudgeted. This is the register's standing lesson —
*citing a precedent is not applying it* — with the sharpest instance yet: the
counter-example was in the same comment as the rule.

### Where this plane must diverge from AU-50, and why

A deferred revocation rides a later tick and the receiver merges **additively**,
so AU-50 could rotate a backlog through successive messages and lose nothing.
Rate-limit counts are the opposite shape: `Update` **replaces** a node's slot
and `ApplyRemoteCounts` **replaces** the whole broadcast, both inside a window
measured in seconds. Rotating would make an IP's cluster total oscillate
between counted and zero every tick — worse than consistently omitting the
coldest. So this plane **truncates by hotness**, and the safety argument is
different too, resting on two guarantees rather than on "it arrives later":

1. **An omitted export keeps its LOCAL limit.** `AllowClusterAware` sums
   `localCount + remoteCount`, so an omission narrows **one** address from
   cluster-aware to local. The pre-fix failure narrowed **every** address on
   **every** node at once.
2. **A requester always receives the cluster sum for every hot IP it reported
   itself.** The reply is built own-set first, then filled from the fleet's
   hottest — so a node never loses the cluster view for traffic it is actually
   handling, however large the flood elsewhere. A reply built from a fleet-wide
   ranking alone would not have this property.

**No new fail-open path exists anywhere in the change.** Every bound replaces a
state in which the plane carried *nothing at all*.

---

## 2. Failure scenarios

### 2.1 `Thousands of simultaneous connections` / `Mass reconnect storm` — the plane's own cost

**Trigger.** A distributed flood of distinct source addresses. Cost to the
attacker at a tight configured limit: **one request per address**. A single
ISP-assigned IPv6 /64 supplies 2^64 of them.

| | |
| --- | --- |
| **Current behavior (pre-fix)** | `ExportHotDeltas` returns one entry per qualifying IP. The CP stores every entry of every node, rebuilds the fleet total map inside every RPC under one global mutex, and marshals a reply bounded only by the 128 MiB frame. |
| **Expected behavior** | Bounded work per RPC and per round, bounded retained heap, and a counted degradation when the hot set exceeds what the plane can carry. |
| **Failure mode** | Self-inflicted CP saturation. One RPC at **5.542 s** against a **5 s** deadline; a round owing **277 s** against a **5 s** interval. The mutex queue grows without bound. |
| **Recovery path** | None while the traffic continues — the work scales with what the traffic sets. Automatic once the flood stops and entries age out of the window. |
| **Customer impact** | Config polls served late by a CP spending a core on map rebuilds; distributed rate limiting ineffective fleet-wide. |
| **Security impact** | **The one that matters.** Degraded to local limiting, an N-node fleet admits N× the configured limit. Measured 50× at N=50. |
| **Monitoring visibility** | Worse than none: the freshness `WARN` attributes an overload to a Control Plane outage. |

### 2.2 `Memory pressure` / `OOM` — the aggregator as an attacker-keyed map

`perNode[nodeID]` held whatever a node sent, for as many nodes as were enrolled.
**164.2 MiB** of reachable heap at 50 × 100,000 — reachable, which is the one
thing `GOMEMLIMIT` cannot reclaim, the same property CHAOS-109 measured for the
feed-ingest map. The prune is keyed on a **node** going quiet for
`rlNodeStaleAfter` (2 minutes) and never on cardinality, so a fleet that keeps
gossiping keeps every entry.

### 2.3 `API overload` — the diagnostic that was a second amplifier

`Stats()` built a set of every IP on every node while holding the aggregator
mutex: **1.736 s** at 50 × 50,000, from `GET /api/cluster/rate-limits` at
`RoleViewer`. A polling dashboard contributes one full fleet walk per refresh,
against the lock the data path's ingest needs. This is the same class as
CHAOS-110's observation that the surface reporting a degradation must not
participate in it.

### 2.4 `Broken upstream` / peer misbehaviour — the receiver trusted the sender

Bounding only the sender would have been insufficient and the fix does not do
it. A node predating the export bound, or an enrolled node behaving badly, can
send up to the full 16 MiB inbound frame — ~524,000 IPv4 or ~290,000 IPv6
entries — and the Control Plane retained all of it, multiplied by fleet size.
What the CP keeps is now the CP's own decision.

### 2.5 Already-correct behaviour, and why

Three things on this path were right and are unchanged; they are recorded so a
later round does not "fix" them.

- **An expired broadcast contributes zero** (CHAOS-61,
  `clusterCountStore.FreshCount`). This *is* the degradation that gave the
  attacker the multiplier, and it is still correct: the alternative is
  enforcing a frozen snapshot of timestamps that have all aged out, denying
  clients forever on counts that no longer exist. The defect was never that the
  broadcast expires — it was that the plane was so easy to stop.
- **The gossip round is panic-guarded and keeps the loop**
  ([controlplane_client.go `rateLimitGossipRound`](../../controlplane_client.go)).
  CHAOS-79's reasoning holds exactly: a goroutine that returns leaves the
  limiter cluster-enabled with nothing refreshing the broadcast — the frozen
  blackhole CHAOS-61 closed, manufactured by the recovery. Untouched.
- **Freshness is evaluated on every tick, including failed ones**, so the
  degraded state is reported *during* the outage that causes it. Untouched; this
  change adds a second cause to distinguish, it does not replace the first.

---

## 3. Risk matrix

| ID | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| RL-1 | Unbounded hot-IP export; message size chosen by traffic, threshold floors at one request per address | **HIGH** | **FIXED** — `MaxExportedHotIPs`, hottest-first | `internal/admission/engine.go`; §9.1 |
| RL-2 | Fleet total map rebuilt inside every RPC under one global mutex: 5.542 s per call against a 5 s deadline, ~277 s per 5 s round | **HIGH** | **FIXED** — one cached generation per `rlTotalsCacheTTL`, reply built outside the mutex | `controlplane.go`; §9.2 |
| RL-3 | Lost broadcast degrades the fleet to local limiting → N× the configured limit (measured 50×) | **HIGH** | **FIXED at the cause** (the plane no longer stops); the degradation itself is CHAOS-61 and stays | §9.4 |
| RL-4 | CP retained heap unbounded and attacker-keyed: 164.2 MiB at 50 × 100 000, never pruned by cardinality | **MED** | **FIXED** — per-node ingest bound; ceiling is now fleet size × bound | `controlplane.go` `Update`; §9.1 |
| RL-5 | Reply bounded only by the 128 MiB frame; 3.698 s of marshal per RPC | **MED** | **FIXED** — `maxBroadcastHotIPs`, own-set first then hottest fill | `controlplane.go`; §9.2 |
| RL-6 | `Stats()` walked the fleet under the data path's mutex from a viewer-gated endpoint (1.736 s) | **MED** | **FIXED** — served from the generation | `controlplane.go` `Stats`; §9.3 |
| RL-7 | No counter, cap, gauge or alert anywhere on the plane; the one signal named the wrong cause | **MED** | **PARTLY FIXED** — counters, present-tense gauges, a rate-limited line, API fields and two UI tiles with their own banner. **No alert**; see §8.1 | `cluster_ratelimit_budget.go`, `events.go`, `ui_cluster.go`, `static/index.html` |

---

## 4. Recovery assessment

**Automatic.** Every bound is evaluated per round against the current hot set,
so the plane recovers on the first round whose set fits — no operator action, no
restart, no latch. The present-tense gauges are rewritten on **every** round
including the ones that omit nothing, which is what clears them (AU-43's rule:
a present-tense claim must name the value that clears it). The cumulative
counters deliberately do **not** clear, because they are the magnitude a rate
alert is built on; both halves are gated, including the control that catches
"zero the counter" as the cheap way to pass the recovery gate.

**Manual.** None required. The bounds are constants, not operator settings —
see §8.4 for why that is deliberate and what it defers.

**Deterministic.** The chosen set depends only on the data: ties break on the IP
string, never on map iteration order, so the Control Plane and the Data Plane
reach the same answer about the same input and a gate asserting *which* entries
ride is not flaky by construction.

---

## 5. Operational impact

Before: a flood produced a healthy-looking Control Plane at 100% of a core, late
config polls, a 5 s RPC timing out, and a `WARN` naming an outage that was not
happening. Nothing in `/metrics` moved.

After: `culvert_cluster_ratelimit_hot_ips_omitted_total{leg=...}` carries the
magnitude per leg, `culvert_cluster_ratelimit_hot_ips_omitted{leg=...}` the
present-tense state, and `culvert_cluster_ratelimit_tracked_ips` the fleet's
distinct hot cardinality. `GET /api/cluster/rate-limits` reports both bounds and
all three omission gauges; the admin panel gains **Hot IPs Omitted (now)** and
**(total)** tiles plus a banner that names the *other* cause beside the existing
stale-broadcast one. One `WARN` line per minute at most, never per round —
deliberately, because `X-2` records the log sink as blocking the request
goroutine when full, so an unbounded line here would turn a flood into a third
amplifier.

**Interpretation for a runbook.** A sustained non-zero
`culvert_cluster_ratelimit_hot_ips_omitted` means *a distributed flood of
distinct source addresses*, not a misconfiguration. The omitted addresses are
the coldest and keep their local limits. The action is upstream (edge blocking,
ASN/prefix policy), not a Culvert setting.

---

## 6. Security impact

The control being protected is the **distributed** half of rate limiting: the
part that stops an attacker spreading across nodes to multiply the limit. That
is precisely the part the pre-fix plane lost under load, and it lost it to the
one input class that would be exploiting it.

What the change does **not** do, stated plainly: it does not make a flood
harmless, and it does not give the cluster-aware verdict to every address under
one. It guarantees that (a) the plane keeps running, (b) every address keeps its
local limit, and (c) each node keeps the cluster sum for the addresses it is
actually handling. The residual is in §10.

The client-visible behaviour is unchanged — the same `429`, no new header, no
new body — so nothing here discloses posture to the traffic that triggered it.
`sanitizeLog` + `%q` is applied to the peer-supplied node id on both Control
Plane legs; the Data Plane leg logs its own id.

---

## 7. Data-integrity impact

None. The gossip plane holds no persisted state: counts live in memory for one
window, the aggregator is rebuilt from what nodes send, and nothing on this path
writes a config version or a durable record. No wire-format change — the
`RateLimitGossip` / `RateLimitBroadcast` schemas are byte-identical, so a mixed
-version fleet interoperates in both directions: an old node's oversized gossip
is truncated by the new Control Plane (gated, §9.1), and an old Control Plane
receives a smaller message than it used to and replies as before.

---

## 8. Suggested improvements (left open, attributed rather than fixed)

### 8.1 A `cluster_ratelimit_degraded` alert (MED) — the highest-value remainder

The signal is now visible and **pages nobody**. The same shape CHAOS-110 left
open for `dpi_degraded`: an alert belongs beside the rule that owns it, and
wiring one from this plane is a decision about alert taxonomy (is a bounded
degradation an alert or a dashboard condition?) that belongs to the alerts
owner. The metric and its `_total` series are shaped so a rate rule can be
written today.

### 8.2 Charge the aggregation against a work budget, not a cadence (MED)

`rlTotalsCacheTTL` bounds how *often* the generation is rebuilt, which is what
removed the quadratic term. It does not bound how *expensive* one rebuild is —
that is bounded indirectly, by fleet size × `maxGossipHotIPsPerNode`. On a fleet
far larger than 50 nodes the rebuild grows linearly in node count. A proper fix
measures the rebuild and adapts the TTL. Not done: it changes how the budget is
*defined*, and the current ceiling is an operator quantity (how many nodes you
enrolled), not an attacker one.

### 8.3 Make the broadcast's top-K selection exact per requester (LOW-MED)

Candidates are ranked by the total **including** the requester, because one
ranking serves every node and so can be cached. Past `maxBroadcastHotIPs`
distinct fleet-wide, the fill pass is therefore an approximation of "the hottest
*remote* totals for this node" rather than exactly it. Below the bound the reply
is exact and identical to pre-fix contents (gated). Making it exact at every
scale means a per-requester ranking, which is the per-RPC cost this round
removed — so it is a trade, not an oversight.

### 8.4 Make the bounds operator settings (LOW)

They are constants, deliberately. A runtime-mutable bound on a security control
whose failure mode is "the control stops" is a new way to turn the control off,
and `conventions.md` is explicit that inventing a mutation endpoint for a
startup/security boundary is the wrong move — the recorded pattern is to surface
the deferral, which §5 does. If an operator need appears, the change is the API
endpoint, the `uiRoutes` entry and the UI surface together.

### 8.5 Narrow what a node exports to what it can still act on (LOW)

An IP at 100% of its local limit is already denied locally; gossiping it buys
the fleet information but changes no verdict on the exporting node. A hotness
window rather than a hotness floor would carry more useful entries per byte.
Speculative — it needs traffic data this round did not gather.

### 8.6 The per-IP client map itself is still unbounded in cardinality (pre-existing)

`PX-6` owns this and it is untouched here. The engine's client map grows with
distinct source addresses regardless of gossip; this round bounded what
*crosses the wire* and what the *Control Plane retains*, not what a Data Plane
tracks locally. Named so the fix is not over-read.

---

## 9. Measurements and commands

All numbers from a build of the baseline (`ee0f2ab`) on this container, one
vCPU class, via a throwaway harness driving the production aggregator, the
production registration (`startBufconnCP`) and the production call options
(`clusterClientCallOptions`). The harness was removed before the PR; the gates
that replace it are named in §9.5.

### 9.1 RED — the export, the frame and the retained heap (baseline)

```
wire cost per delta: v4=32 bytes {"ip":"203.0.113.47","count":64}
                     v6=56 bytes {"ip":"2001:db8:85a3:8d3:1319:8a2e:370:7348","count":64}

v4 gossip request: 400 000 deltas -> 12 849 801 bytes (12.25 MiB)  over 16 MiB: false
v6 gossip request: 300 000 deltas -> 17 400 035 bytes (16.59 MiB)  over 16 MiB: TRUE

configured limit=1..3  -> an IP is exported as hot at ONE request in the window
configured limit=100   -> at 50 requests

nodes=50 ips/node=100000 -> CP retained 164.2 MiB reachable heap
```

The threshold table is the reachability result: the flood does not need to be
expensive, because at a tight limit the hot set *is* the client set.

### 9.2 RED — the cost that blew the deadline (baseline)

```
nodes=10 ips/node= 50000 distinct | totals  244ms + marshal  439ms =  683ms per RPC (5s: ok)    | reply 10.3 MiB
nodes=25 ips/node= 50000 distinct | totals  833ms + marshal 1.565s = 2.398s per RPC (5s: ok)    | reply 27.6 MiB
nodes=50 ips/node= 50000 distinct | totals 1.844s + marshal 3.698s = 5.542s per RPC (5s: BLOWN) | reply 57.3 MiB, 2 450 000 entries

one gossip ROUND, 50 nodes at 100 000 hot IPs each:
  41.19s of SERIAL work under the single aggregator mutex (824ms per node)
```

The round figure above is at 100,000 IPs with **overlapping** sets (so the reply
stays small and the marshal term is absent). With the distinct sets of the row
above it, the same round owes 50 × 5.542 s ≈ **277 s** against a 5 s interval.

### 9.3 RED — the admin surface (baseline)

```
Stats() over 50 nodes x 50000 IPs: 1.736s holding the aggregator mutex
  (nodes=50 hot_ips=2500000) — one GET /api/cluster/rate-limits
```

### 9.4 RED — the consequence (baseline)

```
configured limit=10/window; broadcast absent on a 50-node fleet
  -> 500 requests admitted fleet-wide (50x the limit)
```

### 9.5 GREEN — the same workloads under the gates

```
$ go test . -run CHAOS111 -count=1
50-node round at 4096 hot IPs each: fixed 636ms, pre-fix shape 12.505s (19.7x)
ok  github.com/KidCarmi/Culvert  13.977s

$ go test ./internal/admission/ -run CHAOS111 -count=1
ok  github.com/KidCarmi/Culvert/internal/admission  0.032s
```

A 50-node round costs **636 ms** against the 5 s interval — 12.7 ms per call
against a 5 s deadline, a 390× margin — and the gate measures the **pre-fix
shape on the same fixture** in the same run and requires it to be at least 2×
worse, so a fast machine cannot report the fix as working on a tree where it is
not.

**Gates shipped.** `internal/admission/chaos111_hot_export_bound_test.go`:
`CHAOS111_ExportIsBoundedAndHottestFirst`,
`CHAOS111_ControlFittingHotSetIsExportedWholeAndUnchanged` (CONTROL — the
cheapest way to pass the first is to truncate aggressively),
`CHAOS111_ExportSelectionIsDeterministic`,
`CHAOS111_ControlExportRetainsWindowAccounting` (CONTROL — exporting is a READ;
a selector that consumed counts would un-limit every exported IP),
`CHAOS111_ExportStaysNilWhenTheLimiterIsNotArmed`,
`CHAOS111_HotSelectorUnboundedKeepsEverything`.
`cluster_ratelimit_budget_chaos111_test.go`:
`CHAOS111_GossipOverTheBoundStillSyncs` (end to end through the REAL 16 MiB
limits, its NEGATIVE CONTROL first proving the pre-fix unbounded request is
refused `ResourceExhausted`),
`CHAOS111_AWholeRoundStaysInsideTheGossipInterval` (with the pre-fix shape as an
in-run control), `CHAOS111_StatsDoesNotWalkTheFleet`,
`CHAOS111_ControlTotalsMatchThePreFixDefinition` (differential oracle),
`CHAOS111_GenerationIsSelfConsistentAcrossASlotReplacement`,
`CHAOS111_ANewNodeIsVisibleAtOnce`,
`CHAOS111_ControlStaleNodesArePrunedByTheGeneration`,
`CHAOS111_IngestBoundHoldsAgainstAPeerIgnoringIt`,
`CHAOS111_OmissionGaugeClearsWhenTheHotSetFitsAgain` (with the AU-43 control
that the cumulative counter survives recovery),
`CHAOS111_AnOmittedIPKeepsItsLocalRateLimit`,
`CHAOS111_ARequesterAlwaysGetsTheClusterSumForItsOwnHotSet`,
`CHAOS111_OperatorSurfacesNameTheBound`, `CHAOS111_OmissionLogIsRateLimited`.

### 9.6 Mutation tests — the gates have teeth

Nine mutations applied to the fixed tree, each run against the gates that should
catch it. **All nine RED**, none silently green:

| mutation | caught by |
|---|---|
| export bound removed | `ExportIsBoundedAndHottestFirst`, `ControlExportRetainsWindowAccounting` |
| CP ingest bound removed (trust the peer) | `IngestBoundHoldsAgainstAPeerIgnoringIt` |
| generation cache removed (rebuild per call) | `AWholeRoundStaysInsideTheGossipInterval` |
| own-set pass dropped (fleet ranking alone) | `ARequesterAlwaysGetsTheClusterSumForItsOwnHotSet` |
| the LIVE slot subtracted instead of the summed one | `GenerationIsSelfConsistentAcrossASlotReplacement` |
| new-node invalidation removed | `ANewNodeIsVisibleAtOnce` |
| cumulative counter zeroed on recovery | `OmissionGaugeClearsWhenTheHotSetFitsAgain` |
| present-tense gauge never cleared | `OmissionGaugeClearsWhenTheHotSetFitsAgain` |
| per-round log rate limit removed | `OmissionLogIsRateLimited` |

### 9.7 Checks run

See the PR description for the exact commands and their results at the pushed
SHA, including what was **not** run and why. A passing local check is not a
passing hosted gate.

---

## 10. Residual risk

- **A flood is still a flood.** Past `maxBroadcastHotIPs` distinct hot
  addresses fleet-wide, some addresses are limited locally only. The guarantees
  are that the plane keeps running, every address keeps its local limit, and a
  node keeps the cluster sum for what it is handling — not that every address
  retains the cluster-aware verdict. §8.3 and §8.5 are the ways to narrow this.
- **The degradation pages nobody** until §8.1 lands. It is on `/metrics`, the
  API and the panel; it is not an alert.
- **The rebuild is linear in fleet size.** A fleet far beyond 50 nodes
  re-introduces a cost this round only bounded indirectly (§8.2). The ceiling is
  an operator quantity now, which is the property that matters, but it is not a
  constant.
- **`PX-6` is untouched.** The Data Plane's own per-IP client map is still
  unbounded in cardinality; this round bounded the wire and the Control Plane's
  retained state (§8.6).
- **`rlTotalsCacheTTL` makes a broadcast up to one second staler** than the
  pre-fix reply. Immaterial against a 5 s cadence and a freshness window derived
  from the rate-limit window, and the arithmetic is self-consistent by
  construction (the generation subtracts the slot it summed, gated) — but it is
  a real, deliberate change to how current a reply is.
- **The bounds are untested above 50 nodes and 4096 IPs per node.** The gates
  run at that shape because it is where the baseline failed; larger fleets are
  reasoned about, not measured.
