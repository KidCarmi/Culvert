# Threat-feed freshness and recovery

**Applies to:** the URLhaus / OpenPhish threat-intelligence feed
(`internal/threatfeed`) and the UT1 community URL-category feed
(`internal/feedsync`).

Culvert downloads threat intelligence from public third-party origins on a
schedule. This runbook covers what happens when those origins are unreachable,
what you will see, and what (if anything) you need to do.

---

## The short version

**A feed outage does not stop the gateway and does not open a hole in policy.**
Threat-feed entries are an additive deny-list layered on top of default-deny
policy; when a sync fails, the last-known-good entries stay loaded and stay
enforced. Nothing is wiped, in memory or on disk.

**What degrades is freshness.** The gateway keeps blocking what it already
knows about, and stops learning about new campaigns until the feed recovers.

**Recovery is automatic.** A failed sync is retried on a bounded backoff
schedule and the feed returns to its normal cadence on the first clean round.
No operator action is required unless the condition persists.

---

## Cadence

| Feed | Normal interval | Retry after a failure | Origins |
|---|---|---|---|
| Threat feed (URLhaus + OpenPhish) | 6 h (`-feed-sync-interval`) | 5 min, doubling to 1 h | `urlhaus.abuse.ch`, `openphish.com` |
| UT1 category feed | 24 h | 15 min, doubling to 2 h | `raw.githubusercontent.com` (NethServer mirror) |

Both intervals carry a stable per-node jitter of ±10%, chosen once at startup.
That is deliberate: without it every node in a fleet that booted together would
fetch from the same third-party origin at the same instant forever, and the
usual answer to that is rate-limiting of your egress IP — which produces the
outage rather than preventing it.

The retry ceiling is always clamped below the normal interval, so a failing
feed converges on retrying at the ceiling and never generates more outbound
traffic than a healthy one.

---

## What you will see

### Metrics

Emitted only when the threat feed is configured — a node that does not run the
feed exports none of these, so `== 0` is a safe alerting rule.

| Series | Meaning |
|---|---|
| `culvert_threat_feed_last_success_timestamp_seconds` | Unix time of the last fully-clean sync (0 = never) |
| `culvert_threat_feed_stale_seconds` | Age of the intelligence; measured from startup when there has never been a successful sync |
| `culvert_threat_feed_sync_ok` | 1 when the most recent round fetched every source cleanly |
| `culvert_threat_feed_sync_failures_total` | Cumulative failed rounds |
| `culvert_threat_feed_consecutive_sync_failures` | Failed rounds since the last clean one |

The UT1 feed's equivalents are `culvert_category_feed_last_sync_timestamp_seconds`
and `culvert_category_feed_sync_failures_total`.

> **Note on `culvert_threat_feed_entries`.** This gauge is *not* a freshness
> signal. Because a failed source's entries are carried forward, the count is
> held at its last-good value: a feed that has not synced in three weeks reports
> the same number as one that synced ten minutes ago. Alert on
> `culvert_threat_feed_stale_seconds`, never on the entry count.

Suggested rules:

```promql
# Intelligence is stale (more than 2x the 6h interval).
culvert_threat_feed_stale_seconds > 43200

# This node has never successfully synced.
culvert_threat_feed_last_success_timestamp_seconds == 0

# The feed is failing right now.
culvert_threat_feed_sync_ok == 0
```

### Alert

`threat_feed_stale` fires **once per episode** — when the feed crosses the
staleness threshold, not on every failed round — and does not fire again until
an observed clean sync has cleared the episode. Its detail carries a bounded
class naming the failing sources (`urlhaus`, `openphish`, or
`urlhaus+openphish`), never the raw error text.

### Diagnostics

`GET /api/diagnostics` carries a `threat_feed` row:

| Row status | Condition |
|---|---|
| ok — "not configured" | The feed is not enabled on this node |
| ok — "starting up" | First sync has not completed yet, within the 30-minute grace |
| **warn** — "has NEVER synced" | Past the grace with no successful sync: this node is enforcing with **no threat-feed coverage** |
| **warn** — "last synced … ago" | Stale beyond 2× the interval; last-known-good entries are still enforced |
| ok — "fresh" | Healthy, with the cumulative transient-failure count for history |

### Not on `/readyz`

Feed staleness deliberately does **not** fail readiness. A node with stale
threat intelligence is a fully serving gateway — policy, category, DPI, AV and
CDR are all unaffected — and ejecting it from the load balancer would trade a
degraded control for lost capacity. The same judgement applies to the community
category store (`docs/operator/category-store-recovery.md`).

---

## Triage

### 1. Confirm which sources are failing

The `threat_feed` diagnostics row and the alert name the failing sources. The
server log carries the full cause (rate-limited to one line per 30 minutes,
with a recovery line naming how many were suppressed).

### 2. Check egress reachability from the node

```
curl -sI https://urlhaus.abuse.ch/downloads/text/
curl -sI https://openphish.com/feed.txt
```

Run this **from the node**, through whatever upstream proxy it is configured to
use. The most common causes, in order:

1. **An upstream proxy or firewall change** blocking the feed origins.
2. **Rate-limiting or a block from the provider.** These are free public feeds;
   a large fleet egressing from one NAT address can trip provider limits. If
   many nodes share an egress IP, consider fronting the feed with your own
   mirror and pointing nodes at it.
3. **A provider-side outage.** Nothing to do; the backoff recovers on its own.
4. **DNS failure** on the node.

### 3. Force a retry

The admin Security panel's manual sync (`POST /api/security-scan/feeds/sync`,
admin role) runs a round synchronously without waiting for the backoff timer,
and returns the updated feed status. Use it to confirm a fix rather than to
work around a persistent failure.

---

## The case that needs attention

**A node that has NEVER synced successfully** is materially different from a
stale one, and the row and the alert say so explicitly.

The feed syncs immediately at startup when its on-disk database is empty — a
fresh install, a re-imaged node, or one whose data volume was replaced. If that
first round fails, the node is enforcing with **no threat-feed coverage at
all** rather than with older coverage. Policy, category and scanning controls
are untouched, but the threat-intel deny-list is empty.

This is surfaced within 30 minutes rather than at 2× the sync interval, because
the remedy is usually a misconfiguration discovered at deploy time (egress not
opened for the new node, proxy credentials not provisioned) rather than a
provider outage.

A node in this state recovers by itself the moment the origins become
reachable; there is nothing to restart.

---

## Cluster deployments

Data-Plane nodes receive threat-feed entries from the Control Plane in the
config snapshot, in addition to running their own local sync. Entries imported
from the CP are tagged `cluster-sync` and are never replaced by a local sync, so
a DP whose own egress cannot reach the feed origins still receives coverage
through the CP. The staleness signals above describe that node's **local** sync
only; on a DP that intentionally has no direct feed egress, expect the
never-synced row and suppress the alert for those nodes.

---

## Related

- `docs/operator/category-store-recovery.md` — the community category store's
  own degradation and recovery.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §25 — the review that produced this
  behaviour, with the evidence and the rejected alternatives.
