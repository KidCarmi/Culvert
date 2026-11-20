# ClamAV virus-definition freshness

**Applies to:** the antivirus definitions the local ClamAV daemon serves, as
observed by Culvert and reported under **Security → Scanning**, on
`/api/diagnostics`, and as the `culvert_clamav_signature_*` metrics.

For the feeds Culvert itself fetches, see
[`threat-feed-freshness.md`](threat-feed-freshness.md) and
[`blocklist-feed-freshness.md`](blocklist-feed-freshness.md). This page is
different in one way that governs everything below.

---

## The short version

**Culvert does not update virus definitions.** `freshclam` does, inside the
ClamAV container, on its own schedule, with its own network egress. Culvert has
no hand on that process: it cannot trigger it, retry it, back it off, or
configure it. What Culvert can do — and now does — is *observe* the build date
`clamd` reports and tell you when it stops moving.

**A stale definition database is invisible from every other signal.** The
daemon stays reachable. It answers `PING`, answers `VERSION`, accepts every
body, scans it against the database it has, and returns a verdict. That verdict
is `CLEAN` for anything only a newer signature would catch. So:

- `/ready`'s `clamav` row passes.
- The `clamav_scan` diagnostics row stays silent (it reports *unreachable*).
- The `scan_clam_error` alert never fires (it reports *errors*).
- Compose's own `clamdscan --ping 3` healthcheck passes.
- `culvert_scan_sigdb_invalidations_total` does not move — but it does not move
  on a perfectly healthy node either, because it counts *changes*. It is not a
  freshness signal, and it must not be used as one.

**A restart does not fix it and does not reveal it.** The `clamav-db` volume is
persistent and `restart: unless-stopped` brings the daemon back with the same
database. Rebooting the host changes nothing.

**What degrades is specific.** Malware published since the database was built
is not detected, and those downloads are reported to your users as clean. This
is not a stale cache; it is a detection control quietly operating on old
knowledge.

---

## What Culvert observes, and how often

| | Value |
|---|---|
| Source | the third `/`-separated field of `clamd`'s `VERSION` reply (engine / database counter / **build date**) |
| Poll interval | 5 minutes (the signature watcher, which also flushes the verdict cache on a definition change) |
| Stale threshold | **48 hours** since the reported build date |
| Alert | `clamav_signature_stale`, once per episode |
| Cleared by | an observed *newer* database — never by elapsed time, and never by the daemon going quiet |

The 48-hour threshold is absolute rather than a multiple of a configured
interval, because `freshclam`'s cadence lives in another container and this
process cannot read it. Upstream ClamAV publishes daily (freshclam's own default
is twelve checks a day), so 48 hours is roughly two dozen missed opportunities —
not a quiet patch window. If you want tighter, alert on
`culvert_clamav_signature_age_seconds` directly rather than changing the
threshold.

---

## Metrics

Emitted only once an observation has landed, so a node with no local ClamAV
exports none of them (rather than a row of zeros that would read as a database
built in 1970).

| Series | Meaning |
|---|---|
| `culvert_clamav_signature_timestamp_seconds` | Unix build time of the database in use (0 = no readable date) |
| `culvert_clamav_signature_age_seconds` | its age; 0 when unreadable or future-dated — check the two flags below before trusting a 0 |
| `culvert_clamav_signature_stale` | 1 when older than 48 h |
| `culvert_clamav_signature_age_unknown` | 1 when the daemon answers but reports no readable build date |
| `culvert_clamav_signature_future_dated` | 1 when the reported build date is ahead of this node's clock |
| `culvert_clamav_signature_observation_age_seconds` | how old the *reading* is — grows without bound while the daemon is unreachable, freezing every series above |

The family is deliberately **unlabelled**: the engine string and database
counter are on the role-gated `/api/security-scan/status`, not on the scrape
endpoint, because as labels they would churn cardinality on every definition
update — several times a day on a *healthy* node.

### What to page on

```
culvert_clamav_signature_stale == 1
```

That is the condition with a consequence. Pair it with a lower-urgency rule on
the two measurement gaps, which are not evidence of staleness but do mean the
staleness check is not running:

```
culvert_clamav_signature_age_unknown == 1 or culvert_clamav_signature_future_dated == 1
```

Reading `age_seconds` alone is the one mistake to avoid: it is 0 both for a
database built a minute ago and for one whose date could not be read.

### Reading a frozen series

If `culvert_clamav_signature_observation_age_seconds` is large, every other
series in the family is a snapshot from that long ago. A daemon that has been
unreachable for a day reports the age its database had a day ago. The
unreachability itself is covered by the `clamav` readiness row, the
`clamav_scan` diagnostics row and the `scan_clam_error` alert; this plane
deliberately does not re-report it, so that one fault does not page under two
names.

---

## Recovery

**Automatic, once the updater works again.** Nothing in Culvert needs touching:
the next five-minute poll observes the newer database, the row clears, the
alert episode ends, and the verdict cache is flushed so cached `CLEAN` verdicts
computed under the old definitions are recomputed under the new ones
(this is the CHAOS-107 reconciliation, and it is why a definition update takes
effect for *already-seen* content too).

**There is no manual Culvert-side action, because there is nothing Culvert
owns.** Do not restart the proxy; it will come back and report the same thing.
Work on the ClamAV container.

### Checklist, in the order these actually fail

1. **Is the updater running at all?** `CLAMAV_NO_FRESHCLAMD=true` disables it
   and leaves a daemon that passes every health probe. In the shipped
   `docker-compose.yml` it is set to `false` — confirm nothing has overridden
   it.
   ```
   docker compose exec clamav ps aux | grep freshclam
   docker compose logs clamav | grep -i freshclam | tail -40
   ```
2. **Can the container reach the mirrors?** This is the common one, and it is
   self-inflicted more often than not: the ClamAV container's egress goes out
   the same network you deployed this gateway to control.
   ```
   docker compose exec clamav sh -c 'nslookup database.clamav.net && \
     wget -S -O /dev/null https://database.clamav.net/daily.cvd 2>&1 | head -20'
   ```
3. **Is the engine still supported?** End-of-life ClamAV engines are refused
   updates by the distribution network, which looks exactly like a network
   failure except that the logs say the installation is outdated. A pinned image
   tag ages into this state without anything changing on your side.
   ```
   docker compose exec clamav clamdscan --version
   docker compose logs clamav | grep -i -E 'outdated|obsolete|403' | tail
   ```
4. **Is there disk for the database?** A full `/var/lib/clamav` fails the
   update and keeps the old database loaded.
   ```
   docker compose exec clamav df -h /var/lib/clamav
   ```
5. **Force an update and watch it.**
   ```
   docker compose exec clamav freshclam --verbose
   ```
   Then confirm Culvert sees it — within five minutes, or immediately on the
   role-gated status endpoint:
   ```
   curl -sS -H "Cookie: $ADMIN_COOKIE" https://<node>/api/security-scan/status | \
     python3 -c 'import json,sys; print(json.load(sys.stdin).get("clamav_version"))'
   ```

### If the build date cannot be read (`_age_unknown`)

`clamdscan --version` should print three `/`-separated fields. A reply with only
one or two usually means **no database is loaded**, or that something other than
`clamd` is answering on the configured address. Culvert reports this as its own
row rather than guessing: an unreadable date is an inability to measure, not
evidence that the database is old, so it does **not** page.

### If the date is in the future (`_future_dated`)

The two clocks disagree. Put this node and the ClamAV host both on NTP.
Age checking resumes by itself once the reported date is no longer ahead of this
node's clock. Culvert reports age 0 and raises the flag rather than a negative
age, because a negative age would silently compare below every threshold and
pass the staleness check for as long as the skew lasted.

---

## What this plane deliberately does not do

- **It does not fail closed, and it does not fail readiness.** A node with stale
  definitions is a fully serving gateway: policy, categories, DPI, YARA, CDR,
  the threat feed and the blocklist all still apply, and ClamAV still catches
  everything its database knows. Blocking traffic, or pulling the node out of a
  load balancer, because a third-party updater is behind would turn a
  degradation into your outage. If you want the stricter posture, alert on the
  series and decide deliberately.
- **It does not dial the daemon from a scrape.** Every surface reads the
  five-minute watcher's cached observation. `/metrics` is commonly
  unauthenticated, and a scrape that could trigger a `VERSION` dial would let
  any scraper drive traffic at the daemon.
- **It does not observe a sidecar's definitions.** With body scanning delegated
  to the remote scan service, this process holds no local daemon to ask and the
  `/scan` protocol does not carry the sidecar's signature identity. Monitor the
  sidecar's own ClamAV directly.
