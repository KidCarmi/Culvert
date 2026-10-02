# Cluster rate limiting under a Control Plane outage

**Applies to:** Data Plane nodes in a cluster with rate limiting enabled
(`-rate-limit-rpm` / `security.rate_limit_rpm` > 0; `-rate-limit` / `security.rate_limit`
remain supported deprecated aliases). Standalone proxies are unaffected —
they never consult cluster counts.

**Sections:** [What changed](#what-changed) · [The symptom this
prevents](#the-symptom-this-prevents) · [Surfaces](#surfaces) ·
[Alerting](#alerting) · [Recovery](#recovery) · [What is deliberately
left](#what-is-deliberately-left)

---

## What changed

Cluster-wide rate limiting works by gossip. Each Data Plane node reports its
"hot" IPs (those above 50% of the limit) to the Control Plane every 5 seconds;
the CP aggregates the fleet and broadcasts back, per IP, the total from *other*
nodes. The Data Plane then decides:

```
localCount + remoteCount >= limit  →  deny
```

`remoteCount` comes from the last broadcast the node received. Until CHAOS-61
that broadcast **never expired**. It is applied only on a *successful*
`SyncRateLimits` call, so the moment the Control Plane became unreachable the
last values froze in memory and kept being added to every local count for the
rest of the process lifetime.

A broadcast now expires after one rate-limit window (the default window is
60 seconds). This is arithmetic rather than a posture choice: `RemoteCounts` is
defined as the total *in the current window*, so a broadcast received at time
`T` describes request timestamps in `[T-W, T]`. Once `now > T+W`, every
timestamp it counted has aged out of the current window and its correct
contribution is zero. Serving the frozen value is not conservative — it is
wrong.

The Control Plane has always applied the same reasoning in the other direction:
it prunes any node that has not reported for two minutes, precisely so a dead
Data Plane's counts stop suppressing fleet traffic. Nothing applied it to a
dead Control Plane, which is the side that actually makes the allow/deny call
on live customer traffic.

## The symptom this prevents

An IP whose cluster-wide total was at or near the limit when the Control Plane
went away was **denied on this node permanently**:

* Client sees `429 Too Many Requests` (HTTP) or a dropped SOCKS5 connection.
* The node logs `RATE_LIMITED <ip>` per request — the IP, and nothing about why.
* Local traffic from that IP can be near zero. The denial has nothing to do with
  the client's current request rate.
* It cleared only when the Control Plane returned, or on process restart.

If you are investigating an old incident with that shape — a client blackholed
by rate limiting on a node whose own traffic was low, during or after a CP
outage — this was the cause.

## Surfaces

**Prometheus** (emitted only on a node where cluster rate limiting is *armed* —
a `0` on a standalone proxy would be indistinguishable from a healthy clustered
node). Armed means both halves of what the request path actually requires: the
Data Plane gossip loop is running **and** the rate limiter itself is enabled
(a limit > 0). A node with rate limiting off consults no remote count at all,
so it is never reported stale and emits none of these series:

| Series | Meaning |
|---|---|
| `culvert_cluster_ratelimit_remote_stale` | `1` while other nodes' counts are not being applied |
| `culvert_cluster_ratelimit_broadcast_age_seconds` | Age of the last applied broadcast; `-1` if none has ever arrived |
| `culvert_cluster_ratelimit_stale_episodes_total` | Fresh→stale transitions since startup (one long outage counts once) |

**Admin API** — `GET /api/cluster/rate-limits` adds `remote_counts_stale`,
`remote_counts_applied`, `remote_counts_age_secs`,
`remote_counts_max_age_secs`, `remote_counts_stale_episodes`.

Note that the pre-existing `remote_ips` field is the *size of the last received
broadcast* and says nothing about whether it is still being applied — the
freshness fields are what separate "no hot IPs anywhere in the fleet" from "a
broadcast this node stopped consulting".

**GUI** — Cluster → Distributed Rate Limiting shows a warning banner naming the
broadcast age while the state holds.

**Log** — one line at each transition, not one per gossip tick:

```
WARN cluster rate limiting: no Control Plane broadcast within the 1m0s window —
  other nodes' request counts are no longer applied on this node
  (local rate limits still enforced)
cluster rate limiting: Control Plane broadcast is current again —
  other nodes' request counts are being applied (stale episodes: 1)
```

## Alerting

There is deliberately **no new alert event**. A stale broadcast is always
caused by the Control Plane link, which already alerts and already shows on
`/ready` (`cp_poll`) and in the `DataPlane: GetConfig error` / `DataPlane:
SyncRateLimits error` log lines. Adding a second event for the same root cause
would give operators two names for one page.

Suggested Prometheus rule, if you want the *consequence* rather than the cause:

```yaml
- alert: CulvertClusterRateLimitDegraded
  expr: culvert_cluster_ratelimit_remote_stale == 1
  for: 10m
  annotations:
    summary: "{{ $labels.instance }} is enforcing local rate limits only"
    description: >-
      No Control Plane rate-limit broadcast within the window. Per-node limits
      still apply, so a client can now use the limit on EACH node rather than
      once across the fleet. Fix the Control Plane link.
```

## Recovery

Automatic and requires no operator action: the freshness state is *evaluated*
from the last-applied timestamp on every read, never latched. One successful
`SyncRateLimits` call clears it. There is nothing to reset, and a restart is
never required.

While it holds, the degradation is that the cluster-wide limit becomes a
per-node limit — a client can consume the full limit on *each* node instead of
once across the fleet. That is the correct trade against the alternative
(denying a client forever on data that has expired), and it is bounded by the
Control Plane outage.

## What is deliberately left

* **The window is the ceiling, and it is not configurable.** A knob here would
  only ever be used to widen the period over which expired counts are enforced.
  The window is already operator-controlled through the rate limit itself, and
  the expiry is derived from it rather than duplicated as a second constant.
* **`remote_ips` still reports the last broadcast's size, stale or not.** It
  answers "what did the CP last tell us", which is a useful diagnostic; the
  freshness fields answer "is it being applied". Changing `remote_ips` to zero
  when stale would destroy the first answer to give a second one that already
  exists.
* **A partitioned fleet still under-counts.** Nodes that *can* reach the CP see
  totals excluding any node that cannot. That is inherent to gossip aggregation
  and is not changed here.

## Related

* The Data Plane → Control Plane **audit push queue** drops its oldest unsent
  entries when full (Control Plane unreachable). That loss is now counted —
  `culvert_audit_cluster_push_drops_total`, and `auditClusterPushDrops` on
  `/healthz` when non-zero. Non-zero means the *centralized* audit trail has a
  gap; the local JSONL file on the node is unaffected. Restore the Control
  Plane link to stop the loss; entries already dropped are not recoverable from
  the CP side.
* `docs/operator/ha-lease-recovery.md` — the other "the Control Plane went away
  and the node never came back" family.
