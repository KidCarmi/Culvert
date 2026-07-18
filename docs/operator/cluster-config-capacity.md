# Cluster config-sync capacity, limits, and operations

This runbook covers the CP↔DP configuration-sync path at enterprise scale: the
per-slice and aggregate caps, the transport frame, the commit-time validation
that keeps the fleet fail-safe, and the day-2 procedures for the failure modes
this path can hit — a **frozen fleet** (over-cap publish rejected), a
**mixed-version rollout**, and a **memory-constrained or WAN-starved Data Plane**.

Culvert is standalone by default; everything here applies only when you run a
Control Plane (CP) that distributes config to Data Plane (DP) nodes.

## Capacity limits

The Control Plane distributes a single `ConfigSnapshot` to every DP. Each slice
of that snapshot has a hard cap; a snapshot over ANY cap is rejected wholesale
(never partially applied).

| Slice | Cap | Notes |
|---|---|---|
| `blocked_hosts` | 2,000,000 | domain blocklist; O(1) local match, cost-free at request time |
| `ip_list` | 2,000,000 | IP/CIDR filter list |
| `url_categories` (entries) | 200,000 | category **definitions**, not hosts |
| `url_category_hosts` (aggregate) | 2,000,000 | total hosts across all category entries |
| `threat_feed_urls` / `_domains` | 500,000 each | |
| `policy_rules` | 10,000 | |
| **aggregate host-scale entries** | **3,000,000** | sum of the host-scale slices; see below |
| **marshaled wire size** | **120 MiB** | the whole snapshot's serialized size |

Two cross-cutting bounds exist because the individual caps can pass while the
snapshot as a whole is too large to sync:

- **Aggregate (3M entries):** several individually-valid host-scale slices can
  sum past what fits in one transfer. `blocked_hosts + ip_list +
  ssl_bypass + pac_exclusions + rate_limit_exempt + dpi_patterns + threat_feed_*
  + threat_domain_allowlist + url_category_hosts` must be ≤ 3,000,000.
- **Byte budget (120 MiB):** counts can pass while long strings (max-length
  hostnames, long threat-feed keys) push the marshaled snapshot past the frame.

**Transport:** the CP↔DP gRPC frame is 128 MiB in the snapshot-carrying
direction and 16 MiB inbound. gzip compression of the config stream is
available but **opt-in and OFF by default** (`CULVERT_CLUSTER_GRPC_COMPRESSION`)
— the 128 MiB frame carries a full uncompressed snapshot without it.

## Commit-time validation (why the fleet fails SAFE)

The Control Plane validates a config **at publish time**. If a config exceeds any
cap or the byte budget, the publish is **rejected**: it is not distributed, and
the fleet keeps running the **last valid** snapshot. This is deliberate — a
security proxy must never fail *open* (stop distributing new blocks) silently.

A rejected publish is surfaced three ways:

1. A `config_snapshot_rejected` **alert** (subscribe a webhook to it).
2. A persistent **red banner** in the admin UI (dashboard, every tick).
3. The **config check**: Support → *Run config check* (`POST /api/diagnose/config`)
   shows `publish_rejected` + the named collection and timestamp.

### Recovery: "my fleet is frozen on stale config"

Symptom: the freeze banner is up, or `config_snapshot_rejected` fired, or
`/api/diagnose/config` returns `publish_rejected`.

1. Read the rejection reason — it names the offending collection and the limit,
   e.g. `blocked_hosts=2100000 exceeds cap 2000000`, `aggregate host-scale
   entries=3200000 exceeds cap 3000000`, or `wire size=… exceeds budget …`.
2. **Trim that collection** back under its cap. Common cause: an aggregated
   threat feed grew — prune feeds, tighten the domain allowlist, or split the
   list. The `culvert_config_snapshot_slice_entries{slice=…}` /
   `…_slice_cap{slice=…}` metrics show which slice is near its cap.
3. Trigger a republish (any config mutation republishes; or re-import).
4. Confirm: the banner clears, `publish_rejected` is empty, and DP nodes advance
   their config version. The freeze cannot self-resolve — it needs the trim.

The Control Plane's own local proxying is **unaffected** while frozen (its stores
hold the data); only fleet *distribution* is paused.

## Rollout order

Two changes in this area are rollout-order-sensitive. Get them wrong and specific
nodes go dark with an opaque error.

### gzip compression — CP-FIRST (if you enable it at all)

`CULVERT_CLUSTER_GRPC_COMPRESSION` is OFF by default and should stay off until
the **entire fleet** runs a build that registers the gzip codec.

- The Control Plane **always** accepts and echoes gzip once upgraded — enabling
  it on a DP is safe against an upgraded CP.
- **A DP that enables gzip against an un-upgraded or rolled-back CP fails EVERY
  RPC** with `Unimplemented` — a fleet-wide config-sync blackout.

**Procedure:** upgrade all CPs → upgrade all DPs → only then set
`CULVERT_CLUSTER_GRPC_COMPRESSION=true` on DPs. To roll back, unset it on DPs
first, then downgrade.

### Larger frame / caps — DP-FIRST for the frame

A new CP can publish a snapshot larger than an old DP's 4 MiB default frame,
which the old DP rejects with `ResourceExhausted`. Upgrade DPs before letting the
CP grow config past the old limits. Commit-time validation on the new CP cannot
detect an *old DP's* smaller frame, so this ordering is operational, not enforced.

## Memory sizing (GOMEMLIMIT)

Applying a large snapshot on a DP is a build-then-swap: the new blocklist maps
are built while the old maps are still live, on top of the unmarshaled input.
A 2M-host apply peaks **~410–470 MiB** of *reachable* memory for an instant.

Culvert sets a soft `GOMEMLIMIT` at startup to ~80% of the detected cgroup limit
(v2 `memory.max`, v1 `memory.limit_in_bytes`), unless you set `GOMEMLIMIT`
yourself. **Understand its scope:** the soft limit makes the GC reclaim *garbage*
(wire/decompression buffers, the input slice, the old maps after the swap)
harder as the heap grows — it **cannot** reclaim the reachable dual-map peak. It
buys headroom and turns a transient-garbage spike into GC pressure instead of an
OOM; it is **not** a substitute for sizing the node above the peak.

**Minimum DP memory by largest host-scale slice:**

| Largest slice | Minimum DP container memory |
|---|---|
| ≤ 500k | 512 MiB |
| ≤ 1M | 1 GiB |
| 2M (cap) | ≥ 2 GiB |

On Kubernetes, set the container memory *limit* (not just the request) so the
cgroup limit is real; Culvert reads it and sizes GOMEMLIMIT from it. In host mode
(no cgroup limit) GOMEMLIMIT is not auto-set — set it explicitly, or size the
host, for large configs.

## Cold start / thin-WAN Data Planes

The config-poll deadline scales with the last full snapshot size (base 15s +
size at a 512 KiB/s floor, capped 300s) so a large config on a slow link does
not time out and trigger spurious failover. A freshly restarted DP seeds this
from its on-disk last-good snapshot, so its first poll already budgets enough
time. Watch `culvert_dp_config_last_snapshot_bytes` alongside the
`culvert_dp_poll_duration_seconds` histogram to spot a WAN-starved node (large
bytes + long duration) before it flaps.

## Metrics & alerts

| Metric | Meaning |
|---|---|
| `culvert_config_snapshot_slice_entries{slice}` / `_slice_cap{slice}` | size vs cap for every capped slice + `aggregate_host_scale` + `url_category_hosts` (last published) |
| `culvert_dp_config_last_snapshot_bytes` | size of the last full snapshot a DP received |
| `culvert_dp_poll_duration_seconds` | DP→CP poll latency histogram (buckets to 120s) |

Suggested Prometheus alert rules:

```yaml
# A sync slice is approaching its cap (trim before it overflows).
- alert: CulvertConfigSliceNearCap
  expr: culvert_config_snapshot_slice_entries / culvert_config_snapshot_slice_cap > 0.8
  for: 10m
  labels: { severity: warning }

# The fleet is frozen: the CP rejected its own publish.
- alert: CulvertConfigPublishRejected
  expr: increase(culvert_alert_fired_total{event="config_snapshot_rejected"}[15m]) > 0
  labels: { severity: critical }

# A DP is WAN-starved: poll latency in the slow tail.
- alert: CulvertDPPollSlow
  expr: histogram_quantile(0.9, rate(culvert_dp_poll_duration_seconds_bucket[10m])) > 30
  for: 15m
  labels: { severity: warning }
```

(Adjust `culvert_alert_fired_total` to your alert-delivery metric; the
`config_snapshot_rejected` webhook is the authoritative signal.)

## Related

- `docs/operator/ha-lease-failover.md` — HA failover; a rejected publish now
  fails HA resync closed (a standby will not mark sync-OK on a dropped config).
- `CLAUDE.md` → *Key Environment Variables* — `CULVERT_CLUSTER_GRPC_COMPRESSION`.
