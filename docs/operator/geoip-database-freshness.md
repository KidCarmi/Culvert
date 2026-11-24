# GeoIP database freshness

**Applies to:** the MaxMind GeoLite2-Country database this node serves
destination-country lookups from, as reported under **Security → GeoIP
Database**, on `/api/diagnostics`, and as the `culvert_geoip_database_*`
metrics.

For the *resolution* side of GeoIP — the warmer, the bounded resolver pool and
what happens when a destination cannot be resolved to a country at all — see
[`geoip-resolution-health.md`](geoip-resolution-health.md). That page is about
whether a lookup **happens**. This page is about whether its answer is still
**true**.

---

## The short version

**Culvert never updates this file, and never re-reads it.** There is no
updater to fail, no schedule to miss and no credential to expire: the database
is a file an operator puts on disk, and Culvert opens it once at startup. That
makes this the one body of security intelligence in the product where going
stale is the *default state* rather than a failure mode.

**A stale database is invisible from every other signal.**

- `/ready`'s `geoip` row passes. It reports whether a reader is *loaded*, which
  a database from three years ago satisfies forever.
- The `geoip_database_for_rules` diagnostics row stays silent. It fires when
  **no** database is loaded — the opposite condition.
- `culvert_geo_policy_unresolved_total` does not move. It counts lookups that
  resolved to **nothing**, which is the failure mode of a *missing* database. A
  stale one resolves briskly and confidently to whatever country owned that
  prefix when the file was built.
- The `culvert_geo_warm_*` series all look healthy, because the resolution path
  *is* healthy. They measure how busy it is, not whether its data is current.

**A restart does not reveal it** — but a restart is, uniquely here, part of the
*fix*. See [Recovery](#recovery).

**What degrades is a security control, in the fail-open direction.** A
`destCountry` BLOCK rule is an enforcement decision. IP allocations move
between countries continuously — transfers between regional registries,
reassignments inside them, and the ordinary churn of cloud providers' pools.
Every prefix that changed hands since the build date is classified by this
gateway as the country that *used to* own it. So traffic you configured to be
blocked is allowed, and traffic you configured to be allowed is blocked. Both
directions are silent, and both are internally consistent: the request log
records the country Culvert believes, and the per-rule hit counters move
normally.

---

## What Culvert observes

| | Value |
|---|---|
| Source | the `build_epoch` in the `.mmdb` file's own MaxMind metadata — **not** the file's mtime |
| Read | once, when the database is opened at startup |
| Stale threshold | **90 days** since the build date |
| Alert | **none** — see [Why there is no alert](#why-there-is-no-alert) |

The build epoch is used rather than the file's modification time because mtime
answers the wrong question in both directions: a `cp -p` or a restore from an
archive preserves mtime across a real data update, and a `touch` changes it
across none.

The 90-day threshold is the one the admin panel has always used; this is now
judged in the process so that Prometheus and the GUI give the same answer, and
a test fails if the two drift apart. If you want tighter alerting, threshold
`culvert_geoip_database_age_seconds` yourself rather than changing the
constant. MaxMind republishes GeoLite2-Country twice a week, so 90 days is
roughly two dozen missed releases.

---

## Metrics

Emitted only when a database is actually loaded. A node with GeoIP not
configured — the default — exports **none** of them, rather than a row of
zeros that a fleet-wide `age > X` rule would be silently satisfied by.

| Series | Meaning |
|---|---|
| `culvert_geoip_database_loaded` | always `1` when present; `absent()` means GeoIP is not configured on this node, not that it is broken |
| `culvert_geoip_database_age_seconds` | age from the embedded build timestamp; `0` when the age cannot be measured — check `age_unknown` before trusting a `0` |
| `culvert_geoip_database_build_timestamp_seconds` | Unix build time (`0` when absent or unreadable) |
| `culvert_geoip_database_stale` | `1` when older than 90 days |
| `culvert_geoip_database_age_unknown` | `1` when the file carries no readable build epoch, or one dated in the future |

The family is deliberately **unlabelled** and carries no path: `/metrics` is
commonly unauthenticated when `metricsToken` is unset, and the configured
database path is a detail of your deployment's filesystem layout.

### What to page on

```
culvert_geoip_database_stale == 1
```

That is the condition with a consequence. Pair it with a lower-urgency rule on
the measurement gap, which is not evidence of staleness but does mean the
staleness check is not running:

```
culvert_geoip_database_age_unknown == 1
```

Reading `age_seconds` alone is the one mistake to avoid: it is `0` both for a
database built this morning and for one whose build epoch could not be read.

---

## Recovery

Fully manual, and it has **two** steps. This is the part that most often goes
half-done.

1. **Download a current `GeoLite2-Country.mmdb`** from MaxMind (a free account
   and a licence key are required) and put it at the configured path — the one
   shown under **Security → GeoIP Database**.
2. **Restart the proxy.** A loaded database is never re-read. `InitGeoDB` runs
   at startup only, and the one runtime load that exists (`TryDeferredLoad`)
   publishes only while *no* reader is loaded, so on a working node it does
   nothing by design. A rolling restart across the fleet is enough.

If you have done step 1 and not step 2, Culvert tells you so: the
`geoip_database_pending_restart` diagnostics row appears when the file on disk
carries a **newer** build than the database this process is serving. That row
means the download is done and the node is waiting on a restart — no further
download is needed.

> **Why not a live reload?** Because it is not safe to add casually, and the
> reason is recorded as GEO-1 (`internal/geoip/geoip.go`): the pointer swap is
> atomic, but closing the old reader `munmap`s the buffer an in-flight lookup
> may still be reading, which is a `SIGSEGV`/`SIGBUS` that Go's `recover()`
> cannot catch, leaving no log line and no crash record. Making the reader
> lifetime safe first is a design change, not a configuration one.

### Diagnostics rows you may see

| Row | Means |
|---|---|
| `geoip_database_age` | a database **is** loaded and is over the threshold, or its age cannot be measured at all |
| `geoip_database_pending_restart` | a newer file is on disk; restart to pick it up |
| `geoip_database_for_rules` | **no** database is loaded while enabled `destCountry` rules exist, so those rules match nothing |

The first two can appear together, and when they do both are true: the node is
still serving the old database *until* it restarts.

### If the age cannot be measured

`culvert_geoip_database_age_unknown == 1` has two causes, and the row's text
distinguishes them:

- **No readable build epoch.** Not a file MaxMind publishes — check for a
  truncated or hand-assembled download, and re-download.
- **A build timestamp in the future.** Check this node's clock and NTP first; a
  node running behind real time reports every database as future-dated. If the
  clock is right, the file's metadata is wrong.

Neither is reported as *fresh*, deliberately: a corrupt or hand-edited metadata
block must not be able to silence this plane permanently.

---

## Why there is no alert

Unlike ClamAV definitions
([`clamav-definition-freshness.md`](clamav-definition-freshness.md)), GeoIP
staleness fires no alert, and that is a decision rather than an omission.

An alert episode needs an event to clear on. ClamAV's clears on an *observed
newer database*, because something out of process is trying to update it. Here
nothing is: age is a monotone function of wall-clock time, so an episode could
only ever be closed by a human replacing the file. A condition that clears
solely on human action is a ticket, not a page — it would fire once per node
and then sit open for however long the maintenance takes.

The gauges above are the surface that was missing, and they let you set the
urgency that matches your own refresh habit in Alertmanager.

---

## What this plane deliberately does not do

- **It does not fail closed.** A node with an old GeoIP database is a fully
  serving gateway: policy, categories, DPI, YARA, CDR, the threat feed and the
  blocklist all apply. Refusing traffic, or dropping the node out of a
  load-balancer rotation, because a hand-maintained file is behind would turn a
  slow degradation into your outage.
- **It does not change readiness**, for the same reason.
- **It does no file I/O on a scrape.** Every series is read from the build
  timestamp already in memory. The on-disk comparison behind
  `geoip_database_pending_restart` runs only on `/api/diagnostics`, which is
  role-gated.
