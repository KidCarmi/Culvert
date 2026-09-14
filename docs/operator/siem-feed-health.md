# SIEM syslog feed health

*Applies to nodes with a configured syslog/SIEM target (`-syslog`,
`logging.syslog_addr` in `config.yaml`, or `POST /api/syslog`). On a node that
forwards nowhere every surface below reports the feature as absent and no
metrics are emitted.*

Culvert forwards audit events and request-log entries to a remote syslog
collector. Since CHAOS-66 the health of that feed is reported from **observed
delivery** — lines the collector socket actually accepted — rather than from
whether the connection succeeded once at startup. This page is what to do when
one of those surfaces goes non-green.

---

## What changed, and why the old signal was not enough

Before CHAOS-66 the `syslog_feed` diagnostics row reported exactly one fact:
whether `InitSyslog` connected when it ran. That is green for every way a feed
fails *after* boot — the collector is restarted, a firewall rule changes, the
collector's disk fills and it stops accepting, the VIP moves — which is every
way a feed fails in practice.

On **UDP it was green unconditionally**, and UDP is the default transport
(Culvert selects it whenever the target has no `tcp://` prefix). A UDP "connect"
resolves and binds a socket; it exchanges no packets, so it cannot fail for any
resolvable address. A collector that has never existed and one that is working
perfectly produced identical output.

Meanwhile the drop counter reached exactly one admin-only JSON blob
(`GET /api/syslog`) and nothing that scrapes — no metric, no `/healthz` field,
no alert, and not one log line, not even for the first dropped event.

---

## The states, and what each one means

| State | Meaning | Recovers by itself? | What you do |
|---|---|---|---|
| **disabled** | No syslog target is configured. | — | Nothing |
| **down** | A target is configured but nothing is serving it: the connection could not be established, or a later re-save to a new target failed and the previous collector is still the one in use. | No | Fix the target/network path and re-save it (`POST /api/syslog`) |
| **failing** | Delivery is failing right now, but for less than 60 s. | Usually — this is what a collector restart looks like | Wait. If it persists it becomes `degraded` |
| **degraded** | Delivery has been failing **continuously for more than 60 s**. Events are being lost. | Only when the collector comes back | Restore the collector and the path to it |
| **ready** | The collector has accepted at least one line and delivery is not failing. | — | Nothing |

The `failing`/`degraded` split is a **duration**, not a count, on purpose: a
busy gateway generates one line per proxied request, so a two-second collector
bounce is thousands of "failures" and must not page, while the same bounce on a
quiet node is two.

---

## Where it shows up

**`/api/diagnostics`** — the `syslog_feed` row (viewer role). It now reports how
many events have been delivered, how many were lost, the bounded failure reason
and how long the current failure run has lasted. `warn` while failing or while a
UDP feed has not yet delivered anything; `fail` while degraded or down.

**`/healthz`** (admin port) — a `syslogFeed` field, added **only** when a feed
is configured and something is wrong with it, plus `syslogFeedDrops`. The node
stays `ok`: a dead SIEM must not eject a serving gateway.

**Deliberately NOT on `/ready` or `/readyz`.** A node whose collector is
unreachable is proxying perfectly. Failing readiness over a log feed would
convert a monitoring outage into a traffic outage.

**`/metrics`** — emitted only on a node with a configured feed:

| Series | Meaning |
|---|---|
| `culvert_syslog_up` | `1` while the feed has delivered at least one event and is not degraded |
| `culvert_syslog_delivered_total` | Lines the collector socket accepted since startup |
| `culvert_syslog_drops_total` | Lines that never reached the collector since startup |
| `culvert_syslog_queue_full_total` | Subset of drops caused by the delivery queue overflowing rather than by the collector being unreachable |
| `culvert_syslog_degraded` | `1` while delivery has been failing past the threshold |
| `culvert_syslog_backoff_seconds` | Current reconnect backoff; `0` when delivery is succeeding |
| `culvert_syslog_last_success_age_seconds` | Seconds since the collector last accepted a line. **Omitted entirely until the first delivery** — a `0` there would read as "delivered just now" |

**`GET /api/syslog`** (admin) — `delivered`, `drops`, `queue_full`, `panics`,
`status`, `degraded`, `last_reason`, `unverifiable`.

**Alerts** — `siem_feed_degraded`, fired **once per episode** (not once per
dropped line). Subscribe to it in the webhook editor.

---

## Recommended alerting

Alert on **failure evidence**:

```
culvert_syslog_up == 0
```

That single gauge covers all three ways a configured feed is dark — no writer is
serving the operator's intent, nothing has ever been delivered, or delivery has
been failing past the degradation threshold. `culvert_syslog_degraded == 1` is
the narrower form if you want to page only on the third.

**Do not alert on `culvert_syslog_last_success_age_seconds` alone.** It is a
diagnostic, not a health signal: this feed's traffic is generated by proxied
requests, so on a quiet node the age grows past any threshold you pick while the
collector is perfectly healthy. An age-based rule pages on every idle period.
The age is useful *alongside* `up == 0` — it tells you when the feed actually
stopped — and for spotting a node whose traffic has stopped, which is a
different alert about a different thing.

This is the same limit as the missing active probe (SL-2 below): without a
heartbeat, "nothing has been delivered recently" and "nothing needed delivering
recently" are indistinguishable from the outside.

`culvert_syslog_queue_full_total` increasing while `culvert_syslog_up` is `1` is
a different problem again: the collector is reachable but slower than this node
generates events. That is a SIEM ingest-sizing question, not a connectivity one.

---

## The UDP caveat, stated plainly

**Over UDP, this node cannot prove your collector received anything.** There is
no acknowledgement in the protocol. Culvert reports what it knows:

- It counts lines the socket accepted (`delivered`).
- On most networks a connected UDP socket *does* surface ICMP port-unreachable
  from a dead collector on a subsequent write, so `drops` often moves anyway.
- Across a firewall that discards ICMP, it will not, and the row says so rather
  than claiming an active feed.

If your SIEM feed is a compliance control, use `tcp://`. TCP delivery failures
are observable, and every state in the table above becomes meaningful.

---

## Reconnect behaviour

A failed delivery arms a bounded exponential backoff: **1 s, doubling to a 60 s
ceiling, with ±20 % jitter**, reset only by a line the collector accepts.

The jitter matters for a fleet. The previous schedule was a flat 5 s with no
growth and no jitter, so every node re-dialled a collector that was by
hypothesis already overloaded at the same cadence, for as long as the outage
lasted. Recovery is bounded by the ceiling: a collector that comes back is
picked up within a minute at worst.

Retries are unbounded in **count** and bounded in **rate**. That does not
violate the standing "avoid infinite retries" rule, for the same reason it does
not for the intelligence feeds: the retry is never silent (onset logged
immediately, then at most one line per minute, then one recovery line naming the
suppressed count, with the magnitude in the counters), and a forwarder that
stopped retrying would leave the feed permanently dark after one transient
error.

---

## What is lost, and how to get it back

Events dropped during an outage are **not** recoverable from the collector —
syslog has no replay. They do still exist locally:

- Admin actions are in the node's audit log (`/api/audit`, and the durable
  JSONL file if a path is configured).
- Proxied requests are in the request log.

Export from those if the SIEM copy is required for an investigation covering the
outage window. The diagnostics row's operator action says this too.

---

## Log lines

| Line | Meaning |
|---|---|
| `WARN SIEM_FEED_DEGRADED: syslog delivery to … failing (reason=…, N consecutive, M events lost, retry in …)` | Onset, then at most one per minute |
| `SIEM_FEED_RECOVERED: syslog delivery to … resumed (M events lost during the outage, K further failure lines suppressed)` | Emitted on the first line the collector accepts after an episode |
| `ERROR syslog: recovered panic in delivery goroutine (line dropped)` | A delivery bug is being contained rather than crashing the gateway (CHAOS-24) |

The bounded reason classes are `connect_failed`, `connect_timeout`,
`dns_failure`, `write_timeout` and `write_failed`. The collector address appears
only in the log line, where it is already the operator's own configuration —
never in the alert payload (whose dedup key must stay bounded) and never on the
viewer-role diagnostics row.

---

## Known limits

- **UDP receipt is unverifiable** (above). Recorded, not fixed — it is a
  property of the protocol.
- **There is no store-and-forward.** The delivery queue is a 2048-line shock
  absorber, not a spool; a collector outage longer than that costs events. A
  durable spool is a design decision with its own disk-usage and ordering
  consequences, and is not part of this change.
- **`POST /api/syslog/test` is the only active probe.** Nothing dials the
  collector on a schedule, so a feed on a node with no traffic will sit at
  `ready` with a growing `last_success_age_seconds` rather than discovering the
  outage on its own.
