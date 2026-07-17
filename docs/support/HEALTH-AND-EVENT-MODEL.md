# Culvert Health, Event Timeline, Incident & Debug Model

- **Status:** Proposed (design).
- **Depends on:** `diagnostics.go` `OperatorContract` (the seed), `SUPPORTABILITY-ARCHITECTURE.md`, `SUPPORT-BUNDLE-SPEC.md`.
- **Covers:** explainable health (§1–3), event timeline & correlation (§4), incident-scoped collection (§5), debug escalation levels (§6), metrics-for-diagnostics (§7), HA/cluster diagnostics & local-vs-cluster isolation (§8).

> **REVISION 2 (2026-07-13) — local/cloud split (cloud-first, ADR-0012).** This model spans both tiers. Read each section through the split below; the appliance **collects raw evidence**, the cloud **analyzes**:
> - **§1–3 Health (CHR):** the *lightweight* verdict/severity/remediation stays **local** (extends the existing `OperatorContract`; must survive cloud loss). Deep cause inference across history is **cloud**. The appliance emits CHRs as evidence; the cloud enriches them.
> - **§4 Timeline:** the appliance **emits raw operational event records** (config-version changes, failover, cert rotation, crash) into the bundle. The **correlated timeline is CONSTRUCTED IN THE CLOUD** (ADR-0012). The appliance does not build or persist a correlated timeline beyond a small local event log.
> - **§5 Incident scopes:** the *collection scope* (which collectors/probes + time window) is a **local** selection. The *diagnosis* per incident is **cloud**.
> - **§6 Debug levels:** **local** (bounded capture control) — unchanged.
> - **§7 Metrics:** **local** capture of bounded snapshots/window into the bundle; historical correlation is **cloud**.
> - **§8 Cluster:** the appliance does **collection** (its own posture; optionally fan-out gather of peer `/healthz`/status). The **local-vs-cluster discriminators and split-brain/drift/version-skew CORRELATION are computed IN THE CLOUD** across the case's node bundles. The three instrumentation additions (§8.1) are *local raw-fact emission*, not local analysis.
>
> Net: keep §1–3 (lightweight, local, cloud-independent) and the *collection* halves of §4/§5/§7/§8 on the appliance; the *analysis/correlation* halves are TAC Cloud responsibilities per `TAC-CLOUD-ARCHITECTURE.md`.

---

## 1. Component Health Record (CHR) — beyond green/red

`OperatorContractCheck` already gives `Code/Status/Message/OperatorAction`. The CHR **extends** it (additive — existing checks map forward unchanged) so health answers *why*, *since when*, *who's affected*, and *what to collect*:

```go
type ComponentHealthRecord struct {
    Component     string   `json:"component"`      // "ssl_inspection","upstream_pool","control_plane_link",…
    Code          string   `json:"code"`           // stable snake_case (== existing check codes where reused)
    Status        string   `json:"status"`         // ok|warn|fail  (unchanged vocabulary)
    Severity      string   `json:"severity"`       // info|minor|major|critical  (user-impact weighted)
    Confidence    string   `json:"confidence"`     // high|medium|low  (how sure the verdict is)
    LastSuccess   string   `json:"last_success"`   // RFC3339; "" if never
    FailingSince  string   `json:"failing_since"`  // RFC3339; "" when ok  → answers "since when"
    UserImpact    string   `json:"user_impact"`    // "TLS-inspected sites fail to load for all users"
    ProbableCause string   `json:"probable_cause"` // best-guess root cause
    CauseClass    string   `json:"cause_class"`    // config|capacity|dependency|software|environment|certificate|network|storage|policy
    Locality      string   `json:"locality"`       // local|dependency|cluster|unknown
    Evidence      []string `json:"evidence"`       // stable references (metric names, log markers, check codes) — NOT raw values
    Remediation   string   `json:"remediation"`    // == OperatorAction, kept
    Collectors    []string `json:"collectors"`     // collector IDs to trigger for this failure (links health→bundle)
    Message       string   `json:"message"`
}
```

Key additions and why:
- **`CauseClass`** directly answers the core objective "is this config, capacity, dependency, software, environment, certificate, network, storage, or policy?" Every CHR must set it.
- **`Locality`** is the local-vs-cluster/dependency discriminator (§8).
- **`Collectors`** turns a red health row into a one-click bundle: "collect exactly the evidence for *this* failure" — the bridge between the health model and incident scopes (§5).
- **`FailingSince`/`LastSuccess`** require a small **health-transition tracker** (the current model is snapshot-only) — a bounded in-memory record of each component's last status change, persisted lightly so "since when" survives a scrape but not necessarily a restart (documented limitation; the timeline §4 gives durable history).
- **`Confidence`** lets a probe-free posture check (`warn`, medium) coexist with a hard failure (`fail`, high) without overstating certainty.

`health explain` (CLI/API) returns the full CHR; the dashboard shows Status+Severity; the CSB `health.json` carries the CHR set.

---

## 2. Aggregation (component → node → cluster) without a misleading global light

The prompt's explicit hazard is "a single misleading global status." Rules:

- **Node verdict** = worst *gating* CHR (reuses `rollUpVerdict` semantics: any `fail` → fail, else any `warn` → warn), **but** the node health object always carries the **per-axis breakdown by `CauseClass`** so "degraded" is never opaque — a reader sees *which* class is red.
- **Severity ≠ status.** A `warn` posture check (e.g. `default_auth_open`) is `minor`; a `fail` on `ssl_inspection` is `critical`. The dashboard sorts by severity so a critical failure is never buried under benign warnings.
- **Cluster verdict** is a **matrix, not a scalar**: `{node → {verdict, role, failing_components}}` plus cluster-scope findings (split-brain, drift, quorum). There is deliberately **no single cluster green light** — a healthy leader with three lagging DPs is shown as such, not averaged into "yellow."
- **Suppression of cascades:** when a root cause is known (e.g. `control_plane_link=fail`), downstream CHRs that are *consequences* set `Confidence: low` and reference the root in `probable_cause`, so operators aren't sent chasing five symptoms of one cause (the existing diagnostics already do this for config-version cascades — generalized).

---

## 3. Health data sources (reuse map)

| CHR field | Sourced from |
|---|---|
| Status/Message/Remediation | `buildOperatorContract` checks (`diagnostics.go`) |
| `/readyz` gating | `handleReady` (`healthcheck.go`) |
| memory/goroutines | `/api/dashboard/health` (`ui_config.go:93-108`) |
| CA expiry, SSL degradation | `handleHealth` `ca_expires_days`, `ssl_inspection` |
| DP link / last-good snapshot | `checkDPLastGoodConfigSnapshot`, `dpControlPlanePollFailing` |
| HA posture | `/healthz` lease fields, `leaseHealth` |
| capacity signals | metrics (§7): saturation gauges, queue depths, latency histogram |

---

## 4. Operational Timeline — "what changed before the incident"

The single biggest observability gap is the absence of a correlated timeline. Design:

```go
type TimelineEvent struct {
    ID            string `json:"id"`             // ULID
    TS            string `json:"ts"`             // RFC3339 UTC
    Category      string `json:"category"`       // config|policy|restart|upgrade|failover|certificate|
                                                 //   resource|dependency|health|support|admin|crash
    Severity      string `json:"severity"`       // info|minor|major|critical
    Component     string `json:"component"`
    Summary       string `json:"summary"`        // redacted, human-readable
    Actor         string `json:"actor"`          // enriched identity (reuse ui_helpers actor), masked per profile
    CorrelationID string `json:"correlation_id"` // links related events across subsystems
    Detail        map[string]any `json:"detail"` // redacted
}
```

- **Ingestion (no new event bus needed):** the timeline is a **bounded, append-only ring + JSONL** (mirroring `internal/audit`) fed by *taps* on events that already occur — `saveConfigVersion` (config/policy changes, with actor+action already captured), shutdown/startup hooks (restart), release-dispatch verify (upgrade), `selfFence`/`leaseAutoPromote` (failover), CA rotation (certificate), alert fire (dependency/resource), audit writes (admin), and a new top-level panic recovery (crash — see §6/T-CRASH). No subsystem is re-plumbed; each tap is one line at an existing choke point.
- **Correlation ID:** reuse the existing `X-Request-ID`/W3C traceparent generator (`connlimit.go`) as the seed; support operations and their spawned collectors carry a shared `correlation_id`; a failover carries the epoch as its correlation key so all events of one failover group. Config changes reuse the config-version number as a natural correlation key.
- **Retention & indexing:** ring for live view (fast), JSONL for the bundle (durable, bounded with rotation — but with the **improved retention** of dated/compressed archives, fixing the single-`.1` limitation). Indexed by TS and Category for the "last N before incident T" query the bundle needs.
- **Privacy:** timeline entries are redacted at write (actor masked per profile, detail scrubbed); traffic-level events are **not** in the timeline (that's request logs) — the timeline is *operational* events only, keeping cardinality bounded and privacy tight.
- **The bundle question:** `events/timeline.jsonl` scoped to `[incident_time - window, incident_time]` is the literal answer to "what changed immediately before the incident," and `SUMMARY.md` surfaces the top 3.

---

## 5. Incident-scoped collection

A bundle should collect *relevant* evidence, not everything. An `IncidentScope` maps a failure class to a targeted collector set, tests, window, and (optionally) a temporary debug level with automatic stop conditions.

```go
type IncidentScope struct {
    ID           string        // "tls_inspection_failure"
    Title        string
    Collectors   []string      // collector IDs to run (superset of mandatory)
    Diagnostics  []string      // diagnose verbs to auto-run (e.g. diagnose tls)
    Window       time.Duration // evidence window (e.g. 30m)
    DebugLevel   DebugLevel    // temporary level during collection (default L0)
    AutoStop     StopSpec      // duration/disk/error stop conditions for any raised level
    Explanation  string        // user-facing "what this collects and why"
}
```

Catalog (initial):

| Scope | Key collectors / diagnostics | Window | Temp level |
|---|---|---|---|
| `authentication_failure` | auth diagnostics, IdP config (redacted), auth-rule shadow, recent auth_fail request logs, timeline(config/policy) | 30m | L1 |
| `tls_inspection_failure` | tls.json, decryption profiles, autoexclude stats, `diagnose tls <host>`, cert state, SSL-inspect logs | 30m | L2 |
| `website_unreachable` | `diagnose dns`, `diagnose tls`, `diagnose upstream`, policy dry-run, blocklist/threat-feed match, request logs for host | 15m | L1 |
| `slow_browsing` | latency histogram, upstream circuit state, worker saturation, conn limits, goroutine dump | 15m | L2 |
| `high_cpu` | goroutine dump, heap profile (gated), metrics window, scan-engine saturation | 10m | L3 |
| `disk_exhaustion` | `diagnose storage`, data-dir stat, logstore/retention state, largest-artifacts report (agent) | n/a | L1 |
| `update_failure` | release/catalog state, dispatch status, agent op logs, rollback history, `product.json` | n/a | L1 |
| `policy_mismatch` | policy dump + object-ref graph, `diagnose policy`, config-version diff, hit stats | n/a | L1 |
| `cdr_failure` | CDR pool state, `checkCDR`, sluice enrollment, recent CDR errors | 30m | L1 |
| `ha_inconsistency` | cluster fan-out, failover ring, lease posture, per-DP applied version, `diagnose cluster` | 60m | L1 |
| `certificate_deployment_failure` | CA rotation state, cluster rotation pending, per-node CA fingerprint, cert expiries | n/a | L1 |
| `standard` (no incident) | all mandatory + config/policy/logs/metrics/timeline | 30m | L0 |

Scopes are a **fixed in-binary registry** (a `data-view` picker in the GUI, a `--scope` flag in the CLI). Each scope's `Explanation` is shown before collection so the operator knows what's gathered and why. `AutoStop` guarantees any raised debug level reverts (§6).

---

## 6. Debug escalation levels (L0–L4)

| Level | Name | What it enables | Perf impact | Consent | Max duration | Auto-revert |
|---|---|---|---|---|---|---|
| **L0** | Health summary | CHRs, readiness, status — always on | none | none | ∞ | n/a |
| **L1** | Standard bundle | full standard collector set, INFO logs | negligible | operator | per-bundle | n/a |
| **L2** | Targeted enhanced | DEBUG logging for named subsystems, goroutine dump, host facts | low | admin | ≤ 60m | **mandatory watchdog** |
| **L3** | Verbose subsystem trace | per-subsystem verbose tracing, heap profile, bounded diagnostic capture (e.g. TLS handshake detail) | medium | admin + explicit sensitive-data warning | ≤ 30m | mandatory watchdog |
| **L4** | Engineering restricted capture | narrow, feature-flagged deep capture (e.g. bounded connection trace) | high | admin + break-glass + case_id | ≤ 15m | mandatory watchdog + hard cap |

**Safeguards (P9 — debug can never stay on by accident):**
- **Every level above L1 carries a TTL** set at enable time; there is **no "until disabled" state**. A background **watchdog** reverts to L0 at TTL expiry and audits it (`support.debug.auto_revert`). The watchdog survives restart by persisting `{level, expires_at}`; on boot, an expired or missing record forces L0.
- **Disk & duration stop conditions** (`AutoStop`): a raised level also reverts if the bundle/trace exceeds a disk budget or an error threshold — whichever fires first.
- **RBAC + audit:** enabling L2+ is admin-only, `auditEventDiff` (before/after level+ttl), and surfaced in the timeline (`category: support`).
- **Sensitive-data warning:** L3/L4 present an explicit warning that deeper capture may include more identifying data even after redaction; the operator must acknowledge.
- **Cleanup guarantee:** on revert, any subsystem toggled into verbose mode is returned to its prior state; temporary capture buffers are flushed into the (redacted) bundle or discarded. `TestDebugLevelCleanup` proves no verbose flag survives revert.
- **Performance protection:** L3/L4 tracing is rate-limited and bounded so it cannot starve the CONNECT/relay hot path; the level controller refuses to raise if the node is already resource-critical (a `high_cpu` incident collects at L3 only with explicit override).

---

## 7. Metrics for diagnostics (not just dashboards)

Metrics exist to *diagnose*, so the framework treats them as evidence:

- **Snapshot metrics:** `metrics/snapshot.prom` = a point-in-time `/metrics` scrape (Prometheus text), always in a bundle.
- **Incident-window metrics:** `metrics/window.json` = the 60-minute request-rate ring (`store.go:54-123`) + counter deltas over the incident window + the latency histogram buckets. This is the only in-process history today; the bundle captures it before it rolls off.
- **High-cardinality boundaries:** per-rule counters are already capped (`maxRuleMetrics=200`); `topHosts` is bounded (10k + decay). The bundle **never** expands cardinality — it captures the already-bounded series. Host/identity dimensions are masked per the redaction profile.
- **New saturation/queue-depth gauges (M1):** worker-pool saturation, scan-engine in-flight, SSE client count, logstore queue depth, relay goroutine count — small additive gauges that make capacity CauseClass diagnosable. Each is a scalar, bounded, `PUBLIC`.
- **Local vs bundled vs telemetry:** every metric is tagged in a registry with `{in_bundle: bool, local_only: bool, telemetry_eligible: bool}`. Bundled metrics are aggregate counts/gauges/histograms (no per-user/per-host raw). `local_only` metrics (e.g. anything carrying unmasked identity) never enter a bundle. `telemetry_eligible` is the *future* opt-in set (M7) and is a strict subset of bundled — decided per-metric, never by default (P6).
- **Correlation:** window metrics carry the same `correlation_id` window as the timeline so a latency spike lines up with the config change that caused it.

---

## 8. HA & cluster diagnostics — distinguishing local from cluster-wide

This is the crux for a distributed appliance. The audit found strong per-node signals but weak cross-node correlation. The model provides both the collectors and the **discriminator logic**.

### 8.1 Small instrumentation additions (M5, each independently shippable)
1. **Per-DP applied version in `MetricsReport`** (`controlplane.go:73-79`): add `applied_snapshot_version`, `applied_epoch`, `policy_version`, `ca_fingerprint`, `culvert_version` → CP can build a fleet lag/drift table.
2. **Populate `EnrolledNode.Version`** at enroll+heartbeat → version-skew observable.
3. **Failover/self-fence event ring** `{ts, from_role, to_role, reason, epoch}` on `/api/cluster/ha` → failover history, not just a counter.

### 8.2 Cluster CHRs (locality-aware)
| CHR component | Verdict logic | Locality |
|---|---|---|
| `node_identity` | role, cert-pinned serial present | local |
| `leader_state` | this node's role/term vs peers | cluster |
| `quorum` | etcd endpoint reachability probe (Culvert can't see quorum directly) | dependency |
| `config_lag` | this DP's applied version vs CP published version | local if only this DP lags; cluster if all lag |
| `config_drift` | applied version/hash reconciled across fleet (via §8.1.1) | cluster |
| `cert_drift` | per-node CA fingerprint vs CP; rotation pending list | local (one stale) vs cluster (rotation stuck) |
| `clock_skew` | compare node timestamps in heartbeat replies (new field) | environment |
| `version_skew` | `EnrolledNode.Version` spread (via §8.1.2) | cluster |
| `split_brain` | fan-out `/healthz` term/epoch; two leaders = split-brain | cluster |
| `partition` | which peers reachable from this node | network |
| `resource_imbalance` | per-node request/capacity spread by node group | cluster |

### 8.3 The discriminator (baked into `diagnose cluster` and the cluster bundle)
The five canonical questions and their tests (from the cluster audit), implemented as CHR logic so a bundle *labels* each finding local vs cluster-wide:
1. **"Is it just me?"** — this DP's `applied_snapshot_version` vs CP's published version. Only this DP behind ⇒ `local`; all DPs behind ⇒ `cluster`.
2. **"CP down or am I partitioned?"** — `dpControlPlanePollFailing` across nodes: one ⇒ local; all ⇒ cluster/CP.
3. **"Split-brain?"** — fan-out `/healthz`, compare `role`+`term`+`epoch`; two `leader`s ⇒ `cluster` critical. (Culvert does not self-alarm in legacy mode — the bundle bakes in the documented external check.)
4. **"Cluster CA drift?"** — per-node `caFingerprint` vs CP `/api/cluster/ca` + rotation pending; one stale ⇒ local renewal failure; all stale ⇒ CP rotation stuck.
5. **"Quorum / etcd?"** — independent probe of `-ha-etcd-endpoints`: self-fenced + etcd reachable ⇒ genuine loss; etcd unreachable ⇒ infra-local.

A cluster bundle is a **fan-out**: the requesting node collects its own bundle plus the *redacted* `/healthz`, `/api/cluster/status`, and applied-version of each reachable peer, then computes the discriminators and writes `cluster/correlation.json` with an explicit per-finding `locality`. Unreachable peers are recorded as `unavailable`, not fatal — a partition is itself a finding.

---

## 9. Traceability

| Prompt requirement | Where satisfied |
|---|---|
| Status/severity/confidence/last-success/failing-duration/impact/cause/evidence/remediation/collectors/locality | §1 CHR |
| Aggregate component→appliance→cluster; avoid single misleading status | §2 |
| Timeline correlating config/policy/restart/upgrade/failover/cert/resource/dependency/health/support/admin/crash | §4 |
| Incident scopes with collectors/tests/window/debug flags/auto-stop/cleanup/explanation | §5 |
| Debug levels L0–L4 with duration/disk/perf/consent/RBAC/audit/rollback/warnings/cleanup | §6 |
| Metrics snapshot/window/cardinality/retention/correlation/in-bundle vs local vs telemetry | §7 |
| HA/cluster diagnostics + local-vs-cluster isolation | §8 |
