# SIEM / syslog feed delivery health (CHAOS-72)

Culvert forwards two streams to a remote syslog collector when one is
configured: every **audit event** (who changed what on the admin plane) and
every **request-log entry**. For many deployments the SIEM is the record of
record — the node-local audit JSONL is a `RotatingFile` capped at 50 MB with a
single archive, and is frequently never collected — so a collector that stops
receiving is a hole in the compliance trail, not a monitoring inconvenience.

This page covers what the node tells you about that feed, and what to do when
it says the feed is down.

---

## What changed in CHAOS-72

Before this sweep the node could tell you only whether it had **connected once,
at startup**. The `syslog_feed` operator-contract row was a function of two
strings fixed at init time, and for a collector that went away later it
reported:

> `ok` — remote syslog/SIEM forwarding is active

…while every event was being discarded. Measured against the pre-fix tree: 49
of 49 audit events dropped, row still `ok`, still "active".

Delivery loss reached exactly one place in the whole product — the `drops`
field of `GET /api/syslog`, an admin-only JSON blob — as a **cumulative**
counter with no time axis, so `drops: 40213` could not distinguish a feed that
is dark right now from one that healed last week. There was no Prometheus
series (so no alerting rule could exist), no `/healthz` field, no alert, and no
log line.

CHAOS-72 adds the delivery axis and wires it to every surface. It changes
nothing about what is sent or how.

---

## Surfaces

All of these appear **only when a collector is configured**. A node that
forwards nowhere emits no syslog series at all — a `culvert_syslog_up 0` on
such a node would be indistinguishable from a dark feed, and the paging rule
below is `== 0`.

"Configured" means **an operator asked for a collector**, not "a connection
succeeded". If the collector cannot be reached at boot, Culvert logs
`Syslog: connect failed … continuing without syslog` and keeps serving traffic
— and the series are still exported, reporting `culvert_syslog_up 0` /
`culvert_syslog_degraded 1` from the moment the intent is recorded. Nothing
retries a failed connect, so this state is terminal until you re-save the
target (`POST /api/syslog`) or restart; it is reported down immediately rather
than after the five-minute degradation window, because there is no transient
to wait out. The `syslog_feed` contract row has always reported this case as
`fail` ("configured but failed to connect"); until CHAOS-72's P1-F round the
metrics plane did not, so the documented `culvert_syslog_up == 0` rule could
not fire for precisely the feed that never came up.

The same applies to a **re-point that failed**: if a later target cannot be
connected, the writer stays pointing at the previous collector, and the feed is
reported down because the collector the operator currently wants is not being
served. The delivery counters keep their values in that state (they count real
events that never reached any SIEM, and resetting them would break `rate()`).

### Metrics (`/metrics`)

| Series | Meaning |
| --- | --- |
| `culvert_syslog_up` | `1` while the feed is delivering; `0` once it is degraded |
| `culvert_syslog_degraded` | the inverse, for rules that prefer to alert on `== 1` |
| `culvert_syslog_delivered_total` | events written to the collector socket |
| `culvert_syslog_drops_total` | **events lost and never replayed** |
| `culvert_syslog_panics_total` | events lost to a recovered panic in the delivery goroutine |
| `culvert_syslog_last_success_timestamp_seconds` | unix time of the last delivered event (`0` = never) |
| `culvert_syslog_stale_seconds` | seconds since the last delivered event |
| `culvert_syslog_queue_depth` | events queued for delivery (cap 2048) |

**Suggested rules**

```yaml
- alert: CulvertSiemFeedDown
  expr: culvert_syslog_up == 0
  for: 5m
  annotations:
    summary: "Culvert {{ $labels.instance }} is not delivering events to the SIEM"

- alert: CulvertSiemFeedLosingEvents
  expr: rate(culvert_syslog_drops_total[15m]) > 0
  for: 15m
  annotations:
    summary: "Culvert {{ $labels.instance }} is losing SIEM events (collector slower than the event rate)"
```

### Health (`/healthz`)

`syslogDrops` is added **only when non-zero** and **never fails the probe** —
the same contract `auditLogWriteErrors` and `auditClusterPushDrops` already
follow. A node whose SIEM feed is down is proxying perfectly; ejecting it from
the load balancer would convert a compliance gap into a traffic outage.

### Diagnostics (`GET /api/diagnostics`, `syslog_feed` row)

| Status | Condition |
| --- | --- |
| `ok` | not configured, or delivering cleanly |
| `warn` | delivering, but events have been dropped since startup |
| `fail` | **degraded**: events are being lost and nothing has been delivered for 5 minutes |
| `fail` | configured but never connected (the pre-existing boot-time branch, unchanged) |

### Alert

`syslog_feed_down` — fired **once per episode**, never per dropped event.
Subscribe to it on the Alert Webhooks panel ("SIEM/syslog feed not delivering
events"). The Detail carries a bounded reason class (`connect_failed`,
`write_failed`, `backoff`, `queue_full`, `closed`, `panic`, `flush_timeout`),
never the collector address or a transport error.

### Admin API

`GET /api/syslog` now returns `delivered`, `degraded`, `neverDelivered`,
`lastSuccessUnix`, `secondsSinceEvent`, `lastFailureReason`, `queueDepth`,
`queueCap` and `deliveryProvable` alongside the existing `drops` and `panics`.

---

## How degradation is decided

> **A loss is currently unresolved** *and* **nothing has been delivered for 5
> minutes.**

Both halves are required, and each one matters:

- **Unresolved, not historical.** The first half is "losses since the last
  successful delivery", not the cumulative drop count. A feed that dropped
  events last week and has been delivering since is healthy, and one transient
  loss must not mark it forever. (This was wrong in the first cut of the
  feature: keying on the cumulative counter meant a single old blip plus a
  quiet night reported a working SIEM feed as DOWN.)
- **A duration, not a count.** One dropped event is a transient the writer's
  reconnect state machine absorbs, and a busy gateway can overflow the
  2048-slot queue during a collector GC pause without anything being wrong.
  By the time 5 minutes have elapsed the writer has failed roughly sixty
  bounded reconnect attempts.
- **It cannot fire on an idle node.** A gateway with no traffic forwards
  nothing and therefore loses nothing, so the first half is false however old
  the last delivery is. Inventing a fault from silence is how a health plane
  loses its audience.

The transition is evaluated both when an event is lost and on an independent
30-second timer, so a collector that dies and is then followed by a quiet
period still pages: the alert does not depend on there being more traffic to
lose.

**Recovery is declared on observed evidence only** — one event that actually
reaches the collector. Elapsed time never clears it, because a feed that
stopped dropping because nothing is being logged looks identical to a feed that
started delivering again.

The honest cost of that rule: **a node whose collector you fixed while the node
was quiet stays reported as down until it delivers one event.** Use the probe
below to produce that evidence on demand.

---

## Confirming a collector by hand

```
POST /api/syslog/test        (admin)
```

```json
{ "ok": true, "outcome": "delivered", "message": "the collector accepted the test event" }
```

`outcome` is one of:

| Outcome | Meaning |
| --- | --- |
| `delivered` | the collector accepted **this** event (TCP only) |
| `sent` | the datagram left this host; UDP cannot confirm receipt |
| `dropped` | the event was lost before reaching the collector, with the reason |
| `unknown` | still queued after the 3-second probe window — retry |
| `unconfigured` | no collector is configured |

> Before CHAOS-72 this endpoint answered `{"ok": true, "message": "test message
> sent"}` unconditionally. Once delivery became asynchronous that confirmed
> only that a channel send had succeeded: it returned `ok` for a collector that
> had been dead for a week, while the diagnostics row pointed operators here to
> "confirm connectivity". A probe that cannot fail is worse than no probe.
>
> The outcome reported is that of **the probe's own message**, acknowledged by
> the delivery goroutine — not an inference from the node's overall delivery
> counters, which on a busy gateway would let another request's success be
> reported as the probe's.

---

## UDP cannot prove delivery

`udp://` is the **default** when the address omits a scheme
(`10.0.0.1:514` → `udp://10.0.0.1:514`).

A write to a connected UDP socket almost always succeeds whether or not
anything is listening — an ICMP port-unreachable surfaces, at best, on a
*later* write, and a collector that is silently discarding datagrams surfaces
nothing at all. On UDP, therefore:

- `culvert_syslog_delivered_total` means *this host sent the datagram*, not
  *the SIEM received it*.
- `culvert_syslog_up 1` is **not** evidence the SIEM has your events.
- The `syslog_feed` diagnostics row says so explicitly in its message, and
  `GET /api/syslog` reports `deliveryProvable: false`.

**If you need delivery evidence, use `tcp://`.** This is a property of the
protocol, not a limitation of the node.

---

## Remediation

1. **Check the collector is listening** on the configured host and port, and
   that the network path (firewall, route, NAT) is intact from this node.
2. **For `tcp://`, check the collector's connection limit.** Some SIEMs cap
   concurrent sources; a node that re-pointed repeatedly on older builds could
   leave phantom `ESTABLISHED` sessions behind (fixed in CHAOS-72 — see below),
   and those count against the cap.
3. **Re-save the target** (`POST /api/syslog`) or restart the proxy if the
   address itself is wrong. Re-saving reconnects immediately and resets the
   episode.
4. **Confirm with `POST /api/syslog/test`** and look for `outcome:
   "delivered"`. The diagnostics row clears on that event, not on time.
5. **Accept the gap.** Events dropped while the feed was down are **not
   replayed**. The node-local audit JSONL (`-audit-log`) is unaffected and is
   the only place those events still exist — collect it if the gap matters for
   an audit.

### If the feed never connected at boot

`syslog_feed` reads *configured but failed to connect*, `culvert_syslog_up` is
`0`, and no event has ever reached the collector. **Every audit and request
event produced since boot has been lost**, and the row names the count
(`N event(s) lost so far`) — as does `culvert_syslog_drops_total` and
`syslogDrops` on `/healthz`.

Until CHAOS-72 round 7 that loss was counted nowhere: the fan-outs skip when
no writer exists, so a Writer's counters could not hold a loss caused by there
being no Writer, and the compliance-loss series read `0` throughout the outage.
If you are reading a series from an older build, treat `0` here as *unknown*,
not as *nothing was lost*.

Nothing retries a failed boot dial, so this state does not clear on its own —
fix the address or the path and re-save the target (`POST /api/syslog`), which
reconnects immediately. The same count appears as `syslogDrops` on `/healthz`
and as `culvert_syslog_drops_total`; if you turn forwarding **off** instead,
counting stops there and the node reports the feature as absent again rather
than accruing losses it is not incurring.

### If the drop count rises while the feed keeps delivering

The row reports `warn` and the collector is reachable but slower than this
node's event rate: the 2048-slot queue overflows and the oldest arrivals are
refused (`lastFailureReason: "queue_full"`). Check the collector's ingest
capacity. Reducing what is forwarded — for example by turning off per-rule
traffic logging on high-volume allow rules — lowers the event rate at the
source.

---

## Related fix: the replaced-writer leak

`InitSyslog` used to overwrite the active writer without closing it, stranding
the previous one's delivery goroutine parked forever on an unreachable queue
while holding its collector socket **open**. Measured: one leaked goroutine and
one leaked file descriptor per re-init, with the connection to the abandoned
collector still `ESTABLISHED` at the far end.

This was not only an admin action. Startup configures syslog from YAML/flags
and then again from `admin_settings.json`, so **every boot** of an appliance
carrying both leaked one writer. Descriptor exhaustion is a recorded terminal
state for this product (WK-11 / PX-6).

The replacement is now released on every path — startup, persisted settings and
live re-point alike. The close is asynchronous by design: the collector being
replaced is, by the nature of the operation, the one the operator has decided is
broken, and waiting on it would let a dead SIEM stall the boot or the very
request that is fixing it.

---

## Related fix: the writer handle was not concurrency-safe

`globalSyslog` was a bare package-level pointer. The admin plane mutates it at
runtime (`POST /api/syslog` re-points or disables forwarding) while the request
path reads it — once per proxied request for the request log and once per admin
action for the audit feed — with no synchronisation. Confirmed under the race
detector.

It is now an atomic pointer, and the publication in `InitSyslog` is a single
swap so two concurrent re-points cannot both displace the same writer. There is
no operator-visible behaviour change; re-pointing the collector under load is
simply safe now where before it was undefined.

---

## Related

- `docs/operator/threat-feed-freshness.md` — the same freshness plane for
  threat intelligence (CHAOS-59)
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §13 (ST-8, local audit write loss) and
  §30 (CHAOS-61, DP→CP audit push drops) — the other two members of this
  compliance-record family
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §42 — the CHAOS-72 write-up
