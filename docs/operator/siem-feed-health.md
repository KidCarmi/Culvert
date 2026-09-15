# SIEM syslog feed health (CHAOS-66)

Operator runbook for Culvert's remote syslog / SIEM forwarding feed: what it
guarantees, how it fails, what each signal means, and what to do about it.

Design authority: `roadmap/CHAOS-ENGINEERING-REVIEW.md` §36.
Code: `internal/syslog/observability.go`, `syslog_health.go`.

---

## 1. What the feed carries

Two records leave this appliance over the syslog feed:

| Record | Producer | Also stored locally? |
|---|---|---|
| Admin audit trail | `recordAudit` → `WriteAudit` | **Yes** — the audit JSONL and the 500-entry in-memory ring |
| Request log | `recordRequest` → `WriteRequest` | **Yes** — the request-log JSONL |

Both have a node-local copy. That is the single most important fact in this
document: **a SIEM outage never destroys the record, it only interrupts the
copy that leaves the node.** Recovery is always possible from local state, and
that is why nothing here fails closed.

## 2. What the feed does and does not guarantee

Delivery is **best-effort, by design**. A slow or wedged collector costs a
counter, never proxy latency: lines are formatted by the caller, enqueued on a
bounded 2048-entry queue, and delivered by one drain goroutine that owns the
socket. A request goroutine never writes to the collector.

The consequences follow directly and are not defects:

- **Lost lines are never retransmitted.** There is no replay buffer beyond the
  bounded queue. A gap in the SIEM is recovered from the node's local audit
  log, not by the feed.
- **A full queue drops rather than blocks.** Blocking would put the collector
  on the request path, which is the thing this design exists to prevent.
- **Ordering is preserved** (one drain goroutine), but only among lines that
  were actually delivered.

## 3. The UDP limitation — read this before configuring a target

`udp://` is the **default** transport: an address with no scheme is treated as
UDP.

**On UDP, delivery cannot be confirmed and loss cannot be detected.** A
connected UDP socket to a collector that does not exist accepts every write.
Measured on the reference build: `InitSyslog` to a dead UDP collector
*succeeds*, 200 audit lines are written into the void, and the drop counter
stays at **zero**. No ICMP error surfaces on subsequent sends.

So for a UDP feed:

- `culvert_syslog_up 1` means **the socket is open**, not that the collector
  received anything.
- `culvert_syslog_delivery_confirmable` reports **0**, and the `syslog_feed`
  diagnostics row says so in words.
- A startup WARNING is logged once.

**If the audit trail needs delivery assurance, use `tcp://`.** Over TCP a
collector outage is detected, classified, counted, alerted and shown. This is a
property of UDP, not something the appliance can work around.

## 4. Signals

### Metrics (`/metrics`)

Emitted **only when a syslog target is configured** — a `culvert_syslog_up 0`
from a deployment that forwards to no SIEM would be indistinguishable from a
broken feed.

| Series | Meaning |
|---|---|
| `culvert_syslog_up` | 1 when configured and not in a failure episode |
| `culvert_syslog_degraded` | 1 when failing longer than 60s |
| `culvert_syslog_failing_seconds` | Length of the current failure episode |
| `culvert_syslog_last_delivery_timestamp_seconds` | When the transport last accepted a line (0 = never) |
| `culvert_syslog_drops_total{reason}` | Records lost, by bounded reason class |
| `culvert_syslog_delivery_confirmable` | 1 = TCP (loss observable), 0 = UDP (loss invisible) |
| `culvert_syslog_queue_capacity` | Bound the `queue_full` count should be read against |

**Suggested alerting rule:**

```
culvert_syslog_degraded == 1
```

Do **not** page on `culvert_syslog_up == 0` alone — it flips for a few seconds
during an ordinary collector restart. `degraded` carries the 60-second
threshold that makes it actionable.

Do **not** page on `culvert_syslog_drops_total` increasing without also
checking the reason — see the next section.

### Drop reason classes

The single most useful signal, because the four classes have **different
remediations**:

| Reason | What it means | What to do |
|---|---|---|
| `collector_unreachable` | Could not connect, or inside the reconnect backoff window | Fix the collector or the network path to it |
| `write_failed` | Connected, and the write failed — typically a collector that accepts and stops draining, or a peer reset | Same as above; check collector-side ingestion health |
| `queue_full` | Delivery is slower than this gateway's line rate | **Capacity, not reachability.** Either the collector is under-provisioned for this node, or delivery is stalled and this is the symptom — check whether the reachability classes are also moving |
| `writer_closed` | A send raced shutdown | Benign |
| `delivery_panic` | A panic was contained in the drain goroutine | A bug — capture the log line and report it |

Only `collector_unreachable` and `write_failed` open a failure episode. A full
queue is a capacity fact, not evidence about the collector, and must not page
as a SIEM outage.

### Diagnostics (`/api/diagnostics`, `syslog_feed` row)

| Status | Condition |
|---|---|
| ok | Not configured / healthy / UDP (with the limitation stated) |
| warn | Failing, but less than 60s — reconnecting on its own |
| **fail** | Failing longer than 60s — the centralized trail has a gap |

### `/healthz`

A `syslogFeed` object appears when the feed is failing or has ever dropped.
**It never fails the probe.**

### `/ready` and `/readyz`

**Nothing.** Deliberately. A node whose SIEM feed is down is a fully serving
gateway — policy, inspection, scanning and egress are unaffected. Failing
readiness would eject a healthy gateway from the load balancer over its logging
pipeline, turning a monitoring outage into a traffic outage.

### Alert

`siem_feed_down`, fired **once per episode**, cleared only by an observed
delivery. The Detail carries a bounded reason class and the loss count — never
the collector address, because `Dispatch` deduplicates on `event + Detail` and a
per-failure-unique Detail would evict real threat alerts from the retry queue.

**A new event name is silently unsubscribed on webhooks configured before this
release.** If you rely on webhook delivery, add `siem_feed_down` to the
relevant webhook's event list. The metric and the diagnostics row need no
subscription and are the primary surfaces.

### Log

Rate-limited to one line per 5 minutes during an episode, plus one recovery
line naming the suppressed count and the total loss:

```
SYSLOG: SIEM forwarding is FAILING (reason="collector_unreachable", 1423 lines lost so far) — ...
SYSLOG: SIEM forwarding RECOVERED after 4m12s (5109 lines lost in total during the episode, 2 suppressed log lines) — the lost records are NOT retransmitted; ...
```

## 5. Recovery

**Automatic.** The feed reconnects on a jittered ~5s window (±20%, so a fleet
whose shared collector returns does not reconnect in lockstep) and recovers with
no restart and no operator action the moment the collector is reachable again.

Recovery is declared on **observed evidence only** — one line the transport
accepted. Elapsed time never clears a degradation, because a feed that stopped
reporting failures by going quiet looks identical to a healthy one.

### Recovering the gap

Lost lines are not retransmitted. If the gap matters for compliance:

1. Establish the window from `culvert_syslog_failing_seconds` at its peak, or
   from the FAILING/RECOVERED log pair, which names the episode's duration and
   total loss.
2. Pull the same window from the node's **local** audit log — `GET /api/audit`
   or the audit JSONL under the data directory. It is unaffected by a SIEM
   outage.
3. In a cluster, note that the DP→CP audit push queue is a *separate* path with
   its own drop counter (`culvert_audit_cluster_push_drops_total`, CHAOS-61).
   A SIEM gap does not imply a cluster gap or vice versa.

### Manual verification

`POST /api/syslog/test` actively probes the collector. The diagnostics row is
deliberately side-effect-free and never dials.

## 6. Known limits (recorded, not defects to report)

- **UDP cannot report loss at all** — §3. The default transport.
- **Lines lost during an episode are gone from the SIEM**; the local audit log
  is the recovery source.
- **The feed is node-local.** Each node has its own collector connection,
  counters and episode state. A fleet-wide collector outage produces one alert
  per node.
- **`GET /api/syslog` can block briefly** against a wedged collector, because it
  reads `Format()`, which takes the engine's delivery mutex. The health plane
  itself never does — all of its accessors are atomic reads, so `/metrics`,
  `/healthz` and the diagnostics row stay responsive during exactly the fault
  they report.
