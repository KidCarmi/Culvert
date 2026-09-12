# GeoIP resolution health

*Applies to deployments with a MaxMind GeoLite2 database loaded (`-geoip-db`)
AND at least one access rule carrying a destination-country condition. With no
`.mmdb` loaded none of this runs and none of these series are exported.*

## What has to be true for a country rule to match

Deciding a country-scoped rule needs **two** cached facts:

| Fact | Cache | Filled by |
|---|---|---|
| hostname → public IP | `resolvedHostCache` (5 min TTL; 30 s for failures) | the resolution warmer |
| IP → country | `internal/geoip`'s cache (50 000 entries) | the resolution warmer |

The policy path itself is **cache-only**. It never resolves and never reads the
MaxMind file — it runs inside the request goroutine, which holds the client's
connection and a per-IP connection slot while it runs, and `net.LookupHost`
cannot be given a deadline. On a miss the rule **does not match** (fail-closed)
and an off-path warm is armed, so the *next* request for that host decides
normally.

The practical consequence: **the first request to a host whose country is not
yet cached does not match a country-scoped rule.** For an allow-rule that is a
block the user can clear by retrying. For a deny-rule the request falls through
to whatever lower-priority rule matches. This is expected behaviour, not a
fault; the counter below is how you tell expected from broken.

## Diagnostics panel

`GET /api/diagnostics` (and the admin GUI's Diagnostics panel) carries a
`geo_resolution` row summarizing the same state described below, so a
country-rule enforcement problem is visible without scraping `/metrics` or
reading the process log. It warns when the warm pool is saturated or when
unresolved evaluations are outpacing completed warms, and stays `ok`
(reporting cumulative counts) otherwise — including on an appliance with no
GeoIP database or no destination-country rules, where it simply reports that
no resolution has been attempted.

## Metrics

All six are exported only when a GeoIP database is loaded.

| Series | Type | Meaning |
|---|---|---|
| `culvert_geo_policy_unresolved_total` | counter | Country-rule evaluations that did not match because the country was unknown |
| `culvert_geo_warm_total` | counter | Resolutions started off the request path |
| `culvert_geo_warm_dropped_total` | counter | Warms refused — the resolution pool was full |
| `culvert_geo_warm_failed_total` | counter | Warms that found no usable public address |
| `culvert_geo_warm_saturated` | gauge | 1 while warms are being dropped |
| `culvert_geo_warm_inflight` | gauge | Warm resolutions running now |

### Reading them

**`culvert_geo_policy_unresolved_total` rising slowly** — normal. One increment
per host per cache lifetime is the designed cost of keeping DNS off the request
path.

**`culvert_geo_policy_unresolved_total` rising in step with request rate** —
enforcement is **not converging**: country-scoped rules are effectively not
matching. Check `warm_dropped_total` and `warm_failed_total` next.

```promql
# geo enforcement is not converging
rate(culvert_geo_policy_unresolved_total[5m]) > 1
```

**`culvert_geo_warm_saturated == 1`, or `warm_dropped_total` rising** — more
distinct destination hosts are being asked about than the 64-slot pool can
resolve, almost always because DNS is slow (each slot is held for the full
duration of its lookup — tens of seconds against a blackholed resolver). This
is a **degradation of policy enforcement**, not just of telemetry.

```promql
culvert_geo_warm_saturated == 1
```

**`warm_failed_total` rising with `dropped` flat** — resolutions are completing
but returning nothing usable: NXDOMAIN, or hosts that resolve only to private
addresses. Internal hostnames legitimately produce this; a step change does not.

## Log lines

Onset is logged immediately, then at most one line per minute, then one
recovery line naming how many were suppressed:

```
GeoIP: resolution pool saturated (64 in flight) — country-scoped policy rules will not match hosts whose country is not yet cached
GeoIP: resolution pool still saturated — 1 843 further warm requests dropped since the last line
GeoIP: resolution pool recovered (1 843 warm requests were dropped while saturated)
```

Recovery is reported on **observed evidence** — a warm that actually got a slot
— never because time passed.

## Triage

1. **Is DNS healthy from the appliance?** `dig` / `getent hosts` a destination
   that is being reported unresolved. Warm slots are held for the resolver's
   full budget, so a resolver at 5 s per answer caps the pool at ~13 hosts/s.
2. **Is the resolver reachable but slow?** Check `resolv.conf` `timeout` and
   `attempts`, and whether a nameserver in the list is dead — Go tries them in
   order, so one dead server in front costs every lookup its full timeout.
3. **Is the MaxMind database loaded and current?** `GET /api/geoip` reports
   `dbBuildDate` / `dbAgeDays` and any load error. An unloaded database means
   none of these series exist at all and country rules never match.
4. **Are the rules the ones you think?** A country-scoped rule that is not
   matching shows a zero hit count, which reads identically to "no traffic
   matched this rule". `culvert_geo_policy_unresolved_total` is what
   distinguishes the two.

## What this cannot tell you

The counter is process-wide, not per rule: it says *some* country-scoped rule
evaluated against an unknown country, not which one. Per-rule attribution would
put a label with operator-controlled cardinality on an unauthenticated
`/metrics` surface, so it was not added.

## See also

- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §28 — the failure analysis this design
  came from, including why the bound is a semaphore and not a deadline.
- `docs/operator/socks5-listener-health.md` — the same logging and
  recovery-on-evidence discipline on a different subsystem.
