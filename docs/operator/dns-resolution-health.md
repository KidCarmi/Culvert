# Destination-host DNS resolution — health, degradation and recovery

**Applies to:** any node with a GeoIP database loaded AND at least one enabled
access rule scoped by destination country (`DestCountry`). On a node with
neither, none of this runs and every surface below reports the feature as
unused.

**Finding:** CHAOS-57 · **Code:** `geoip.go` (resolver), `dns_health.go`
(health plane) · **Register:** `roadmap/CHAOS-ENGINEERING-REVIEW.md` §25

---

## 1. What this path is

Policy evaluation runs on the request goroutine. When a rule is scoped by
destination country, `matchDestNorm` calls `geo.LookupCached(host)`, which needs
the destination's IP address before it can ask the MaxMind database for a
country. That address comes from `resolveHost` — a process-wide cache in front
of the system resolver.

So a destination-country rule puts the customer's DNS infrastructure on the
critical path of every request that misses this cache.

## 2. What used to happen when DNS was slow or down

Three properties were missing, each reproduced against the pre-fix tree:

| Missing | Consequence |
|---|---|
| A deadline | The request goroutine sat in `net.LookupHost` for the operating system's budget — `resolv.conf` ships `timeout:5 attempts:2` per nameserver — holding a client connection and a per-IP connection-limiter slot. |
| Single-flight | 200 concurrent requests for one host produced **200** resolver invocations. During a brownout that is one blocked goroutine per request and one query per request aimed at the resolver that is already failing. |
| Stale serving | An expired entry was discarded outright, so the first expiry during an outage took every popular host cold within the same five-minute window. |

The third one is the security half. A `DestCountry` rule that cannot determine a
country does **not** match, and a rule that does not match is **skipped** —
evaluation continues to lower-priority rules. So a "block sanctioned countries"
rule silently stopped enforcing while a broad allow rule beneath it took over.
Geo blocking went dark, on a green dashboard, because DNS was slow.

Nothing on this path counted, logged or alerted a resolution failure.

## 3. What happens now

```
                 ┌─ fresh cache entry ─────────────► returned immediately
                 │
resolveHost(h) ──┼─ stale ADDRESS (< 1h past TTL) ─► returned immediately,
                 │                                    refresh runs behind it
                 │
                 └─ miss / expired failure / >1h ──► one bounded, single-flighted
                                                      resolution (2 s), shed when
                                                      the resolver pool is full
```

- **A host resolved within the last hour never blocks a request**, whatever the
  resolver is doing. That is the whole recovery story for an outage: your
  working set keeps matching geo rules. This applies to hosts that resolved
  **successfully**: a host whose lookup FAILED is retried on the normal negative
  TTL (30 s), never held at "no answer" for the stale window.
- **One resolution per host at a time.** Concurrent callers wait on the leader
  and inherit its answer and its deadline. Your resolver sees one query per
  host per refresh, not one per request.
- **Bounded pool (64 concurrent resolutions).** A client asking for thousands of
  distinct destinations is shed, not queued. Shed resolutions are *not* cached —
  a transient overload must not suppress a legitimate destination for a TTL.
- **A failed refresh never destroys a servable answer.** During an outage the
  stale address is the only thing keeping geo rules matching, so a negative
  result is not written over a positive one that is still inside the one-hour
  window.

## 4. Surfaces

**Metrics** (`/metrics`, emitted only once this node has resolved something):

| Series | Meaning |
|---|---|
| `culvert_dns_resolve_total` | resolutions attempted |
| `culvert_dns_resolve_failures_total` | resolver returned no answer |
| `culvert_dns_resolve_timeouts_total` | abandoned at the 2 s deadline |
| `culvert_dns_resolve_shed_total` | refused, resolver pool saturated |
| `culvert_dns_resolve_stale_served_total` | expired address served while refreshing |
| `culvert_dns_resolve_degraded` | 1 while geo-scoped rules are not matching |

**Page on `culvert_dns_resolve_degraded == 1`, not on a failure rate.** A gateway
sees a steady background of NXDOMAIN from user typos and malware beaconing to
sinkholed C2 domains. Those are counted but are deliberately excluded from the
degradation run — an authoritative "this name does not exist" is a resolver
working perfectly, and because the hostname is chosen by the client, counting it
would let any client fabricate your page on demand.

`culvert_dns_resolve_stale_served_total` is the **leading indicator**: it starts
moving as soon as refreshes stop completing, well before the degradation
threshold, and while everything is still being enforced correctly.

**Diagnostics** (`/api/diagnostics`): the `dns_resolution` row — `ok` when
unused or healthy, `warn` when degraded or shedding. Never `fail`: the gateway
is still proxying every request, and a resolver outage is fleet-wide by
construction, so a fail row would report a serving fleet as broken.

**Alerts:** the existing `dns_failure` event, `Source: "policy"`, fired **once
per degradation episode** and cleared only by an observed successful
resolution. The Detail is a bounded reason class (`timeout`, `nxdomain`,
`temporary`, `resolver_error`), never the raw error — the queried hostname is
client-chosen, and it must not reach an alert dedup key or a viewer-role
surface. The full error goes to a rate-limited log line.

**Not on `/readyz`.** Every node shares the customer's DNS, so failing readiness
would eject the entire fleet simultaneously over a dependency none of them can
fix by restarting. Same rule the `ca` and `cluster_ca` rows follow.

## 5. Runbook

**`culvert_dns_resolve_degraded == 1`**

1. This node has had no successful destination resolution for over a minute.
   Traffic is **still being proxied**. What has stopped is matching for rules
   scoped by destination country — treat any geo-based *block* rule as not
   enforcing for destinations outside the cached working set.
2. Check the node's resolver: `resolv.conf` contents, reachability of each
   nameserver, and whether the failure is DNS-specific or general egress loss.
3. The process log carries the cause (rate-limited to one line per 30 s, with a
   recovery line naming how many were suppressed). Grep for
   `DNS resolution failed`.
4. Recovery is automatic and requires no restart: one successful resolution
   clears the state, the metric returns to 0 and a recovery line is logged.
   Nothing needs to be re-warmed — cached entries were never discarded.

**`culvert_dns_resolve_shed_total` climbing**

The resolver pool is saturated: this node is being asked to resolve more
distinct destinations than the bound allows. That is usually one client
scanning or a DGA-beaconing infection, not a DNS problem. Identify the source in
the request log. Shed resolutions fail closed (geo-scoped rules do not match)
and the condition clears on its own as load drops.

## 6. Residual risk (owner-acknowledged)

- **An unresolvable destination still cannot match a geo rule in either
  direction.** For an *allow* rule that is fail-closed; for a *block* rule it is
  fail-open, and evaluation falls through to lower-priority rules. Making an
  unknown country match a block rule would deny every destination this node
  cannot resolve, trading a bounded security gap for an unbounded availability
  one — so the posture is unchanged, and the mitigation is the one-hour stale
  window (which removes the gap entirely for any recently-seen destination) plus
  the alert and the metric. Operators who need hard geo enforcement during a DNS
  outage should express it as an explicit deny rule rather than relying on
  fall-through.
- **With the cgo resolver Go cannot cancel an in-flight `getaddrinfo`.** The 2 s
  deadline reliably releases the *request goroutine*; the OS thread behind it is
  bounded instead by the Go runtime's own 500-thread cap on cgo lookups. The
  pure-Go resolver honours the deadline fully.
- **The stale window is one hour.** A destination whose address changes during a
  DNS outage longer than its remaining window is attributed to its previous
  address's country until resolution recovers. The address is used only for
  country attribution — the actual connection is dialled through the transport's
  own resolution, never this cache — and an IP's country changes on a timescale
  of months.
