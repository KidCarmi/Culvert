# Threat-feed freshness

**Applies to:** the local threat-intelligence feed (`internal/threatfeed`) — the
URLhaus and OpenPhish lists Culvert consults on every proxied request.
**Related:** `docs/operator/category-store-recovery.md` (the Layer-2 category
store), `docs/operator/scan-capacity-and-timeouts.md` (the body-scan pipeline).

---

## 1. What this control is, and why its age matters

Culvert keeps local copies of two public threat feeds and answers every request
from them offline:

- `CheckDomain` runs on **every** proxied request.
- `CheckURL` runs additionally on every plain-HTTP request.

Both are lock-free reads of an in-memory table refreshed on a background
schedule (default every 6 hours; `security.sync_interval` in YAML).

The content is the most perishable security data in the appliance. URLhaus and
OpenPhish entries turn over on a scale of hours — a malware distribution URL
that mattered last Tuesday is very often parked or taken down by Friday, and
the URL that matters today was not in last Tuesday's list at all. A feed frozen
a week ago is not "slightly behind"; it is a control that has quietly stopped
doing its job.

**Culvert never fails closed on feed age, and never will.** When a fetch fails,
the previous entries are carried forward and keep blocking (`carryForward`,
`internal/threatfeed`). That is deliberate: refusing traffic because a
third-party feed is down would convert someone else's outage into yours. The
cost of that choice is that a broken feed *looks* like a working one — which is
exactly what the surfaces below exist to fix.

---

## 2. How to tell whether the feed is current

### Prometheus (the paging surface)

| Series | Meaning |
|---|---|
| `culvert_threat_feed_stale` | `1` when the served intelligence is older than the staleness threshold. **This is the alerting rule: `== 1`.** |
| `culvert_threat_feed_staleness_seconds` | Age of the data currently being served. |
| `culvert_threat_feed_last_refresh_timestamp_seconds` | Unix time of the last sync that brought in entries from **any** source — the age of what is being served (`0` = never). |
| `culvert_threat_feed_sync_failures` | Consecutive rounds that fetched nothing from any source. |
| `culvert_threat_feed_sync_ok` | `1` when the most recent round fetched **every** source cleanly *and* at least one round has ever done so. A feed with one permanently-failing source sits at `0` here while still refreshing — see §3.1. |

**All five series are absent on a node with no threat feed configured.** That is
deliberate: a `culvert_threat_feed_stale 0` on an appliance that never had the
feature is indistinguishable from a healthy one, and the paging rule is `== 1`.
If you see no series at all, the feature is off — check `threat-feed-db` /
`security.enabled`.

`culvert_threat_feed_entries` (which predates this plane) is **not** a freshness
signal. Because entries are carried forward, it holds steady through an
arbitrarily long outage.

### Alerts

| Event | Fires when |
|---|---|
| `threat_feed_stale` | The served intelligence is older than the threshold. |
| `threat_feed_sync_failing` | Three consecutive rounds fetched nothing from any source. |
| `threat_feed_recovered` | The first good round after either of the above. |

Each fires **once per threshold crossing**, not per evaluation — a stale feed
pages you once, not every six hours for a month. The latches reset on restart,
so restarting a stale appliance re-fires the alert once (one reminder, not
silence).

Subscribe in **Alerts → Webhooks → Events**. The store filters on exact event
names, so a webhook that does not list these will not receive them.

### Admin UI / API

- **Diagnostics → Operator contract**, row `threat_feed`: a plain-language
  verdict plus the next step.
- `GET /api/security-scan/status`: `threat_feed_last_success`,
  `threat_feed_sync_ok`, `threat_feed_sync_error`, `threat_feed_entries`.

The `threat_feed` row is deliberately **warn, never fail**, and is deliberately
**not** on `/readyz`. A node serving carried-forward intelligence is still
enforcing policy, still scanning bodies, and still blocking every entry it
holds. Failing readiness would pull a working gateway out of a load-balancer
rotation and leave the traffic to egress with no gateway at all.

---

### 3.1 One source failing is not staleness

Staleness is measured from the last round that refreshed **any** source, not
from the last round in which **every** source fetched cleanly. The two differ
in a case that is ordinary rather than exceptional: one of two free public
feeds returning 403 or 429 indefinitely for your egress IP.

In that state the appliance is still getting fresh intelligence on every window
from the surviving source, so it is **not** stale and will not page you. What
you will see instead is `culvert_threat_feed_sync_ok 0` and the failing
source's error in `threat_feed_sync_error` — visible, worth fixing, not an
outage of the control.

`threat_feed_sync_failing` counts only rounds that fetched **nothing at all**,
for the same reason: holding a whole fleet at the retry floor against a service
that is already refusing it would make the problem worse, not better.

---

## 3. The staleness threshold

Stale means **four consecutive missed sync windows, with a floor of 24 hours**:

```
staleAfter = max(4 × sync_interval, 24h)
```

At the 6-hour default that is 24 hours. It is expressed in windows rather than
as a fixed duration because the interval is configurable: a fixed 24-hour
threshold would be meaningless on a deployment that syncs daily, and a
deployment syncing every five minutes would wait a full day to learn its feed
had died. The floor stops a short interval from paging on twenty minutes of a
public feed being slow, which is ordinary rather than an incident.

The threshold is a constant. There is no knob (recorded deferral — the same
posture as the release-catalog thresholds).

---

## 4. What the appliance does on its own

You should rarely need to intervene. Three behaviours recover automatically:

**A failed round retries in minutes, not hours.** A round that fetched nothing
schedules the next attempt on a bounded backoff (5 min, doubling to a 30 min
ceiling, never exceeding the configured interval), instead of waiting a full
window. A thirty-second resolver blip landing on the tick used to cost six
hours of frozen intelligence; it now costs five minutes. The retry is bounded
in **rate** and never in **attempts** — a feed down for a day is picked up
within thirty minutes of coming back.

**A stale appliance refetches at startup.** If the persisted data is older than
one sync interval, the feed fetches immediately at boot rather than waiting a
full window. This is what makes "restart it" a genuine remedy. A node restarted
shortly after a clean sync does *not* refetch (that would turn a rolling
upgrade into a synchronised burst against a free public service), and a
crash-looping process is floored to at most one boot fetch per 15 minutes.

**Every scheduled fetch is jittered ±10%.** A fleet that boots together does not
stay phase-locked against a shared upstream for the life of the deployment.

---

## 5. Runbook

### `threat_feed_stale` or `threat_feed_sync_failing` fired

1. **Confirm the blast radius.** Check `culvert_threat_feed_staleness_seconds`.
   Under a day or two, and with the retry loop running, this will very often
   clear itself before you finish reading this page.
2. **Read the cause.** The last fetch error is on the Diagnostics row and in
   `GET /api/security-scan/status` (`threat_feed_sync_error`), and the server
   log carries the per-source line (`ThreatFeed: URLhaus sync failed: …`).
3. **Match the cause to the fix:**

   | Symptom | Cause | Fix |
   |---|---|---|
   | `HTTP GET: dial tcp … i/o timeout` or DNS failure | The appliance cannot reach the feed hosts | Open egress to `urlhaus.abuse.ch` and `openphish.com` (HTTPS), or route them through the configured upstream parent proxy |
   | `HTTP 403` / `HTTP 429` from one source | That public feed is rate-limiting or blocking this egress IP | Usually transient. If persistent, the other source keeps refreshing and the round is not counted as a failure — see below |
   | `returned 0 entries` | An HTTP 200 maintenance page or an empty body | Treated as a failure on purpose (these feeds are never legitimately empty); the previous entries are kept |
   | `save to disk failed` | The data volume is full or read-only | Check the volume; the in-memory table is still current, but the data will not survive a restart |

4. **Force a refresh** once egress is fixed: **Security → Threat Feed → Sync
   Now**, or `POST /api/security-scan/feeds/sync`. A successful manual sync
   clears the alert immediately — it runs the same freshness evaluation the
   scheduled loop does.

### Only one of the two sources is failing

`threat_feed_sync_failing` counts rounds that fetched **nothing**. A round in
which URLhaus succeeded and OpenPhish 403'd refreshed real intelligence and is
not charged as a failure — otherwise one permanently-blocked source (an
ordinary steady state for a free public feed) would hold the whole fleet at the
retry floor forever, aimed at a service that is already refusing it.

You will still see the per-source error in `threat_feed_sync_error` and in the
log. If one source is permanently unavailable from your egress, that is worth
fixing, but it is not an outage of the control.

### The feed has never synced

`threat_feed` reports *"has never completed a sync"*. On a fresh appliance this
clears within a minute of boot. If it persists, the control has never been armed
at all: verify egress, then use **Sync Now** and read the error.

---

## 6. What is deliberately not done

- **No fail-closed on age.** Recorded owner decision. Refusing traffic because a
  third-party feed is stale converts someone else's outage into a full gateway
  outage, and the blocking value of week-old intelligence is far from zero.
  Age is reported, never enforced.
- **No `/readyz` row.** See §2.
- **No operator knob for the thresholds.** Recorded deferral, matching the
  release-catalog and SaaS-feed planes.
- **The retry cadence is not persisted.** A restart resets the backoff to the
  full interval, and the boot-freshness check covers the case that matters (an
  appliance that comes up holding old data). The durable record of *"how long
  since fresh data"* is the last-success timestamp, which **is** persisted.
- **Feed content is still not signed or verified.** URLhaus and OpenPhish are
  fetched over HTTPS from fixed hostnames with no signature check. That is an
  open register row (FD-4), not something this plane addresses.
