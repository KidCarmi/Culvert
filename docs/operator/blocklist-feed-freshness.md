# Remote blocklist-feed freshness and recovery

**Applies to:** the operator-configured remote blocklist feeds
(`internal/blocklistfeed`) managed under **Policy → Blocklist → Feeds** and
`/api/blocklist/feed`.

These are *your* feeds, not the ones Culvert ships: you give it an HTTP(S) URL
serving a domain or `/etc/hosts`-format list, and a sync interval, and it merges
what the origin serves into this node's blocklist. This runbook covers what
happens when such an origin goes away, what you will see, and what to do.

For the built-in threat-intelligence and category feeds, see
[`threat-feed-freshness.md`](threat-feed-freshness.md) — the posture is the same
but the origins, intervals and series names differ.

---

## The short version

**A feed outage does not stop the gateway and does not open a hole in policy.**
Blocklist entries are an additive deny-list layered on top of the policy
engine's own default action. When a sync fails, everything already imported
stays loaded and stays enforced, in memory and on disk.

**What degrades is freshness, and on a deny control that is what matters.** The
gateway keeps blocking what the feed already told it about and stops learning
about anything added to the origin since the last clean round. Those newly-added
destinations are the ones you configured the feed to block, and during the
window they are *not* blocked.

**Recovery is automatic.** A failed round is retried on a bounded backoff
ladder — never at the full interval — and the feed returns to its normal cadence
on the first clean round. No operator action is needed unless the condition
persists.

**One case does not self-heal: a feed with auto-sync turned off.** Nothing will
ever sync it. See [Auto-sync off](#the-auto-sync-off-case) below.

---

## Cadence

| | Value |
|---|---|
| Default interval | 24 h (per feed; set it per feed in the GUI or as `interval` on the API) |
| Scheduler tick | 60 s — a feed added or edited at runtime is picked up within one tick |
| Retry after a failed round | bounded exponential backoff, clamped **below** the feed's own interval |
| Jitter | a stable per-feed offset, chosen once |
| Body/line budget | bounded; an origin that overruns it fails the round rather than importing a truncated list |

The interval is per feed, so the staleness threshold below is per feed too.

Jitter and the sub-interval retry ceiling are both deliberate. Without jitter,
every node in a fleet that booted together would fetch from the same origin at
the same instant forever, and the usual answer to that is rate-limiting of your
egress IP — which *produces* the outage. Without the ceiling, a failing feed
could retry faster than a healthy one syncs.

---

## What you will see

### Metrics

Emitted only when **at least one feed is configured** — a node with no feed
exports none of these, so `== 0` is a safe alerting rule. No series carries a
per-feed label: feed URLs routinely embed tokens and `/metrics` is commonly
scraped unauthenticated. Per-feed detail is on the role-gated
`/api/blocklist/feed`.

| Series | Meaning |
|---|---|
| `culvert_blocklist_feed_configured` | Feeds configured on this node |
| `culvert_blocklist_feed_autosync_enabled` | Of those, how many have a positive interval |
| `culvert_blocklist_feed_manual_never_synced` | Feeds with auto-sync **off** that have never synced — configured, contributing nothing, and nothing will sync them |
| `culvert_blocklist_feed_failing` | Feeds whose most recent *attempt* failed |
| `culvert_blocklist_feed_never_synced` | Auto-synced feeds with no successful sync on this node |
| `culvert_blocklist_feed_stale` | Auto-synced feeds with no success for over 2× their interval (or never, past the 15-minute startup grace) |
| `culvert_blocklist_feed_stale_seconds` | Age of the **oldest** auto-synced feed; measured from startup when it has never succeeded |
| `culvert_blocklist_feed_oldest_success_timestamp_seconds` | Unix time of the oldest last-success (**0** = at least one feed has never synced) |
| `culvert_blocklist_feed_sync_ok` | 1 when every feed's latest attempt succeeded and none is stale |
| `culvert_blocklist_feed_consecutive_sync_failures` | Largest consecutive-failure count across feeds (not persisted across restart) |

> **Note on `culvert_blocklist_size`.** This gauge is *not* a freshness signal.
> Feed imports are merge-only and the store is persisted, so a feed that has not
> fetched in three weeks leaves the blocklist exactly as large as one that
> fetched ten minutes ago — and a restart reloads it from disk. Alert on
> `culvert_blocklist_feed_stale_seconds` and `_stale`, never on the list size.

Suggested rules:

```promql
# A configured deny feed has stopped being refreshed.
culvert_blocklist_feed_stale > 0

# A feed has never synced on this node (no coverage from it at all).
culvert_blocklist_feed_never_synced > 0

# Something is failing right now.
culvert_blocklist_feed_sync_ok == 0

# Configured but unscheduled: nothing will ever sync these.
culvert_blocklist_feed_manual_never_synced > 0
```

`culvert_blocklist_feed_stale_seconds` is an absolute age across feeds with
possibly different intervals, so prefer the `_stale` counter for paging and use
`_stale_seconds` for the dashboard and for sizing how bad it is.

### Alert

`blocklist_feed_stale` fires **once per episode** — when a feed crosses the
staleness threshold, not on every failed round — and does not fire again until
every auto-synced feed has been *observed* fresh. Elapsed time never clears it:
a feed that has stopped reporting failures because nothing is running looks
identical to a healthy one.

Its detail carries counts, an age and an interval. It deliberately carries **no
feed URL and no error text**: the URL routinely embeds a token, and the error
embeds both the URL and an ephemeral port, which would defeat the alert store's
dedup window. The cause is on `/api/blocklist/feed` (`last_error`) and in the
server log.

Subscribe to it under **Alerts → Webhooks**: *"Blocklist feed stale (remote deny
list not refreshing)"*.

### Diagnostics

`GET /api/diagnostics` carries `blocklist_feed` rows. More than one can appear
at once, because the operator actions differ:

| Row | Condition |
|---|---|
| *(no row)* | No feed configured, or every feed fresh and succeeding |
| **warn** — "are stale" / "have NEVER synced" | Auto-synced feed past 2× its interval, or past the startup grace with no success |
| **warn** — "failed their latest sync" | The most recent attempt failed; already-imported entries still enforced |
| **warn** — "auto-sync turned off and have never been synced" | Configured but unscheduled — see below |

### Not on `/readyz`

Feed staleness deliberately does **not** fail readiness. A node with a stale
blocklist feed is a fully serving gateway — policy, categories, DPI, AV, CDR and
the threat feed are all unaffected, and the feed's already-imported entries are
still enforced. Ejecting it from the load balancer would trade a degraded
control for lost capacity.

---

## The auto-sync-off case

Setting a feed's interval to `off` (API: `"interval": "off"`, or `0`) disables
its schedule. The scheduler then **never** attempts it: it is synced only when
somebody uses **Sync Now**.

This is a supported configuration — it is how you pin a one-off import — but it
has a failure mode that looks like success. A feed in that state that has never
been synced is configured, listed in the GUI, and contributing *nothing*: there
is no attempt, so there is no error to see. That is why it has its own
diagnostics row and its own gauge rather than being folded into staleness, and
why it is deliberately **not** alerted on: you turned the schedule off, so
paging would be paging on your own configuration.

If you did not intend it, set an interval.

---

## Triage

### 1. Read the per-feed detail

```
curl -s -u <admin> http://127.0.0.1:9090/api/blocklist/feed | jq .
```

`last_error` carries the cause per feed, `last_sync` the last clean round, and
`imported_count` how much that feed has contributed. The server log carries the
failure cause too, rate-limited to one line per 30 minutes with a recovery line
naming how many were suppressed.

### 2. Check egress reachability to the origin, from the node

```
curl -sI <the feed URL>
```

Run it **from the node**, through whatever upstream proxy it is configured to
use. A feed URL that resolves to a private or loopback address is refused by the
SSRF guard at every sync, not only when you save it — so a host that *started*
resolving internally will fail every round with a guard error.

### 3. Confirm recovery

Use **Sync Now** for the feed, or:

```
curl -s -XPOST -u <admin> http://127.0.0.1:9090/api/blocklist/feed/sync \
  -d '{"url":"<the feed URL>"}'
```

A clean round clears `last_error`, advances `last_sync`, resets the backoff
ladder and — once every auto-synced feed is fresh — clears the alert episode.

---

## What is *not* covered

**Freshness is not durable across a restart.** The last-success timestamp lives
in memory: the admin settings persist only each feed's URL and interval. So
every boot starts at "never synced" until the first round lands (immediately, if
the origin is reachable), and a node that restarts frequently cannot be observed
as long-term stale. Making it durable means putting a value that changes on
every sync into the versioned configuration file, which would make each round
look like a configuration change; that trade-off is an open item rather than an
oversight.

**Removing a feed does not remove what it imported.** Feed merges never delete.
Entries carry per-feed attribution (`attributed_count` on the API), and removing
them is a blocklist edit, not a feed operation.
