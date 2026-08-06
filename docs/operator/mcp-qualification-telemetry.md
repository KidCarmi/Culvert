# MCP Gateway Qualification Telemetry (QUAL-3)

This document describes the **durable Observe telemetry foundation** for the MCP
Agent Security Gateway. It is the operator-facing reference for
`mcp.gateway.qualification_telemetry`.

## What it is (and is not)

QUAL-3 composes the existing MCP durable-events machinery into the Gateway Observe
runtime: an **encrypted, capability-isolated event spool**, a **node-local
qualification archive exporter**, restart-safe export cursors, truthful telemetry
health, and low-cardinality metrics.

It is a **foundation**, not a finished SIEM integration or a completed Observe run:

- **Disabled by default.** Absence preserves QUAL-2 behavior (no event manager, no
  spool). No checked-in config enables it.
- **Observe-only.** No executor, upstream client, credential broker, or Policy is
  composed. No tool executes; no qualification/evidence clock starts.
- **Denials only, live.** With Policy still absent, only the **denial lane** commits
  on a live request (authentication/admission denials → durable P-DEN aggregates).
  Decision telemetry is truthfully reported as `pending_policy` - a decision event
  is committed only via the durable manager once a Policy provider exists.
- **Node-local archive, not a network SIEM.** The first exporter writes to a local,
  bounded, fsync-backed archive. QUAL-3 adds **no** network exporter.

## Configuration

```yaml
mcp:
  gateway:
    enabled: true
    # ... QUAL-1 TLS/mTLS/OAuth + QUAL-2 inventory settings ...
    qualification_telemetry:
      enabled: true
      node_id: "qual-node-1"
      data_dir: "/var/lib/culvert/mcp/telemetry"
      kek_file: "/var/lib/culvert/mcp/telemetry.kek"
      export:
        type: "local-qualification-archive"
        directory: "/var/lib/culvert/mcp/telemetry/archive"
        batch_size: 256
        max_retries: 3
        max_bytes: 1073741824   # 1 GiB
```

- **Startup-only**, node-local. Read once at startup; no hot reload, no admin-API
  upload, no second configuration source.
- **Gateway capability only.** Management is never activated.
- **Strict bounds.** `batch_size` ≤ 4096, `max_retries` ≤ 16, `max_bytes` ≤ 64 GiB;
  paths are traversal-checked. A `0` uses the documented default.

### KEK provider (key-at-rest)

`kek_file` is a **model-B `secret.Provider` KEK file** - a random 32-byte key
auto-generated `0600` on first use and stable across restarts. This is the same
key-at-rest primitive the cluster-CA / DP-node keys use.

- **No raw key** ever appears in YAML, CLI, or an environment variable, and the KEK
  is never derived from the node id, a password, or config text.
- A **wrong or unavailable** KEK fails closed - the sealed DEK cannot be opened, so
  the spool cannot decrypt and the listener does not bind. There is **no plaintext or
  memory-only fallback**.
- Restart with the **correct** KEK recovers the existing spool.
- **Backup boundary:** exclude the `kek_file` from any backup/snapshot that also
  contains `data_dir` - otherwise model B provides no protection against
  backup/snapshot exposure.

### Permissions

`data_dir`, `kek_file`'s directory, and the archive `directory` are created `0700`;
all telemetry files are written `0600`.

## Failure behavior (fail closed)

If telemetry is enabled but any prerequisite is invalid - missing `node_id` /
`data_dir` / `kek_file` / `export.directory`, an unsupported `export.type`, an unsafe
path, out-of-range bounds, an unavailable KEK, or a spool that will not open - the
Gateway listener **does not bind** (activation `invalid`, reason
`qualification_telemetry_invalid`). No partial manager or exporter is left running,
and the Secure Web Gateway path is unaffected. Bounded, secret-free reasons only -
never a path, key, or raw backend error.

## What durably happens on a live request

1. A seeded request that fails authentication/admission routes a denial into the
   isolated denial lane (`ObserveDenial`) - pre-identity failures carry **no tenant**;
   admission denials carry the authenticated tenant.
2. A background loop periodically flushes closed denial-aggregation windows into the
   encrypted **P-DEN** spool partition (append + fsync + checkpoint = durable commit).
3. Per-partition export loops read committed events and hand bounded batches to the
   archive exporter, which writes each batch atomically (fsync) and returns an
   all-or-nothing acceptance.
4. The durable **export cursor** advances only after the archive accepts the batch. A
   sink failure leaves the encrypted source spool intact and the cursor unadvanced
   (retryable). Retention never deletes unexported source evidence.

A **critical** event whose commit cannot complete fails the operation closed
(`BLOCKED_BY_DURABILITY`) - no action executes, no fake event appears, and the
failure is visible in health + metrics. An **ordinary** event that cannot persist is
counted as loss and never represented as committed or exported.

## Health

`GET /api/mcp/overview` gains a safe `telemetry` block and
`GET /api/mcp/health`'s per-capability durability is now real:

- `state`: `telemetry_not_configured` / `ready` / `invalid`.
- `encryption_available`, per-track `critical_state` / `denial_state` / `severity`,
  `recovery_state`.
- per-partition committed bytes/records/quota, critical-reserve headroom,
  `export_cursor`, `export_lag`.
- exporter: configured/ready, exported events, batches ok/failures, `saturated`,
  bytes used/max, last export time.
- `decision_telemetry: pending_policy`; `execution_enabled: false`.

Health never exposes a data-directory or archive path, provider/KEK identity, a raw
backend error, raw event content, or a tenant id in global health. A failed telemetry
read shows unavailable/degraded - never zero-as-healthy.

## Metrics

Low-cardinality `culvert_mcp_*` series on `/metrics` (labels are fixed enums only -
`capability`, `partition` ∈ {crit,ord,den}, `result` ∈ {ok,fail}, `track` - never a
tenant, principal, server, tool, event id, path, or free-form error):
`culvert_mcp_telemetry_ready`, `culvert_mcp_event_commits_total`,
`culvert_mcp_ordinary_loss_total`, `culvert_mcp_denial_loss_total`,
`culvert_mcp_denial_aggregates_total`, `culvert_mcp_spool_{bytes,records,quota_bytes}`,
`culvert_mcp_critical_reserve_free_bytes`, `culvert_mcp_export_{batches_total,events_total,saturated,lag}`,
`culvert_mcp_last_export_timestamp_seconds`, `culvert_mcp_degraded`.

## Shutdown

On graceful shutdown the telemetry loops stop **after** the MCP listeners stop
(so no new events are produced), a final denial flush + export drain runs, and the
encrypted spool is closed. Key material is released per the `secret.Provider`
contract.

## Backup / restore boundary

Back up `data_dir` (the encrypted spool + cursors) and the archive `directory` to
retain telemetry across host replacement. Keep the `kek_file` in a **separate**
backup domain from `data_dir`. This document does not deliver the full Observe
operational runbook or on-call ownership - those remain separate program
requirements.

## Remaining blockers for `READY TO BEGIN OBSERVE`

QUAL-3 does not make Observe begin. Still required: Policy composition for recorded
decisions; the request-time tenant-binding control before executing modes; live
tenant-isolation and hard-failure suites; a qualification build + artifact identity;
a defined qualification environment; monitoring dashboards; an executable Observe
runbook; and named on-call ownership. Production remains qualification-locked.
