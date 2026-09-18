# SIEM / syslog forwarding health

*Applies to the remote syslog feed configured with `-syslog` / `syslog.addr` /
`POST /api/syslog`. Sweep reference: `roadmap/CHAOS-ENGINEERING-REVIEW.md` §36
(CHAOS-66).*

## The one thing to know first

**Connected is not delivering, and on UDP the appliance cannot tell the
difference at all.**

A UDP "connection" sends nothing. The kernel resolves the address, binds a
socket and reports success whether or not a collector exists, and every
subsequent write to an unreachable collector also succeeds — forever, with no
error the appliance could count. So on a `udp://` target:

- Culvert cannot detect that your SIEM stopped receiving events.
- The drop counter will read **0** during a total outage.
- No alert can fire, because nothing observes a failure.

This is a property of the transport, not of Culvert. It is why the
`syslog_feed` diagnostics row is **permanently amber on UDP**: the appliance is
telling you that a green reading would be the absence of evidence, not evidence
of delivery.

**If you need a SIEM feed whose health this appliance can report on, use
`tcp://`.** If you must stay on UDP, monitor the feed from the SIEM side —
Culvert cannot do it for you, and will not pretend to.

## Surfaces

### Diagnostics — the `syslog_feed` row

| Verdict | Meaning | Action |
|---|---|---|
| `ok` — not configured | No remote forwarding. | None. |
| `ok` — delivering (`N` lines delivered) | TCP target, collector accepting. | None. |
| `ok` — delivering, `N` lost in earlier episodes | Recovered from a past outage. | Check the gap against your SIEM's retention; lost lines are **not** replayed. |
| `warn` — UDP, delivery unverifiable | Working as far as can be known; loss is undetectable. | Switch to `tcp://`, or monitor from the collector. |
| `fail` — configured but failed to connect | The target never connected at startup. **Nothing retries this.** | Fix the target, then re-save (`POST /api/syslog`) or restart. |
| `fail` — FAILING for *D* | Delivery has been failing continuously past the threshold. | See *A collector outage* below. |

### Metrics

Emitted **only when a SIEM target is configured** — an appliance that does not
use the feature exports none of these, so `== 0` is a safe paging rule.

| Series | Meaning |
|---|---|
| `culvert_syslog_up` | 1 = a configured target with a live connection; 0 = configured but never connected. |
| `culvert_syslog_delivery_verifiable` | 1 = TCP (loss is observable); **0 = UDP (loss is NOT observable)**. |
| `culvert_syslog_delivering` | 1 = delivering; 0 = failing past the threshold. **Absent on UDP** — see below. |
| `culvert_syslog_delivered_total` | Lines the collector socket accepted. |
| `culvert_syslog_drops_total{reason}` | Lost lines by bounded class: `collector_down`, `queue_full`, `closed`, `flush_timeout`, `panic`. |
| `culvert_syslog_last_delivery_timestamp_seconds` | Unix time of the last accepted line (0 = never). |
| `culvert_syslog_consecutive_failures` | Collector-attributable losses since the last delivery. |

`culvert_syslog_delivering` is deliberately **not emitted on UDP**. A `1` there
would be a fiction and a `0` a false page; alert on
`culvert_syslog_delivery_verifiable == 0` instead if you want to be told that a
feed's health is unknowable.

Suggested rules:

```promql
# The feed is losing events right now (TCP targets only).
culvert_syslog_delivering == 0

# A configured target that never connected — nothing will retry it.
culvert_syslog_up == 0

# Sustained loss, including the "too slow" shape a liveness gauge misses.
rate(culvert_syslog_drops_total[15m]) > 0

# Optional posture check: a SIEM feed whose health cannot be reported.
culvert_syslog_delivery_verifiable == 0
```

### Alert

`siem_forwarding_failing` fires **once per episode**, after delivery has been
failing continuously for longer than the degraded threshold. It carries a
bounded reason class (never the collector address). It clears only when a line
is actually delivered — elapsed time never clears it.

Subscribe to it in **Settings → Alert Webhooks → SIEM forwarding failing**. It
is a new event name, so an existing webhook will **not** receive it until you
tick the box.

### Process log

The onset is logged immediately, then at most one line every 5 minutes, then one
recovery line naming how many were suppressed:

```
WARN syslog: SIEM forwarding failing (reason="write_failed", 412 consecutive lines lost) — events are NOT reaching the collector; the local audit log is unaffected; reconnecting every 5s
syslog: SIEM forwarding recovered — the collector is accepting events again (7 suppressed failure log lines during the episode)
```

## Playbooks

### A collector outage (`fail — FAILING for …`)

1. **The local record is intact.** Audit events are still written to this node's
   own audit JSONL and request log. Only the forwarded copy is affected — say so
   before anyone escalates a "we lost the audit trail" incident.
2. Check the collector: is it up, is it accepting connections on that port, did
   a firewall or route change? `POST /api/syslog/test` sends one line.
3. **Do nothing else.** Forwarding reconnects every 5 seconds and recovers on
   its own; the row and the metrics flip back on the first delivered line.
4. **Lines lost during the outage are NOT replayed.** If the gap matters for
   compliance, extract the window from this node's local audit log and ingest it
   into the SIEM out of band.

### `reason="queue_full"` — the collector is too slow

Different fault, different fix. The collector is reachable but cannot keep up
with this node's log rate, so the bounded in-memory queue overflows. Loss here
does **not** trip the outage alert, because the feed is not down.

Scale the collector, reduce this node's log volume, or move the target to a
less contended collector.

### `reason="panic"`

A delivery bug is being contained rather than crashing the gateway. It is a
code defect, not an infrastructure one — capture the process log line naming the
recovered panic and open an issue.

### A configured target that never connected

This is the one state that does **not** self-heal: `InitSyslog` runs once, and a
failed dial leaves forwarding off for the life of the process. Fix the target and
re-save it through `POST /api/syslog` (no restart needed), or restart the proxy.

This asymmetry — a boot failure is terminal, a runtime failure retries forever —
is recorded as an open posture item (§36.4, SL-7).

## What this feed is not

- **Not the audit trail.** It is a forwarded *copy*. The durable record is this
  node's local audit JSONL (`audit_log_persistence` row).
- **Not fail-closed.** Traffic is never blocked because a log collector is down;
  that would convert the SIEM's outage into yours.
- **Not on `/readyz`.** A node with a dead SIEM feed is a fully serving gateway
  and stays in the load balancer.
