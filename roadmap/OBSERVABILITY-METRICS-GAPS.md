# Observability Metrics Gaps — Discovery & Spec

**Status:** Discovery / spec only. **No production behavior changes in this PR.**
**Scope:** Map the four observability-metric follow-ups handed off from the
rollback-architecture / runtime-ownership discovery program and define, for each,
*what* to instrument, *how* to name it, *where* to wire it, the cardinality/privacy
guardrails, a test strategy, and a PR-split recommendation.

This document does **not** change `metrics.go`, add counters, or touch the rollback
surface, HA/`ConfigSnapshot`, CA-3 / key-at-rest, or any handler behavior. It is the
plan that the (separately-scoped) implementation PR(s) will execute against.

## 1. Source items

The four items are recorded verbatim in the per-domain discovery docs and were all
cross-referenced to "a single observability follow-up." This spec keeps them as one
inventory but recommends splitting the *implementation* into independent PRs (§7).

| ID | Domain | Source | One-line gap |
|----|--------|--------|--------------|
| **UC-6** | P6.1 URL Categories | `roadmap/URL-CATEGORIES-DISCOVERY.md:352` | No `culvert_categories_*` family; `FeedSyncer.Stats()` / `SaaSFeedSyncer.Stats()` are admin-API-only — can't alert on "feed sync stuck". |
| **SC-2** | P6.2 Scanning | `roadmap/SCANNING-DISCOVERY.md:456` | `HashCache.hits` / `.misses` are already measured and exposed via `Stats()`, but `metrics.go:265` discards them (`_, _, cacheSize := ...`); only `culvert_scan_cache_size` is rendered. |
| **CA-2** | P6.3 Root CA / TLS | `roadmap/ROOT-CA-DISCOVERY.md:402` | No `culvert_ca_*` / `culvert_tls_*` / `culvert_cert_*` family: no leaf-cache hit/miss, leaf-signing latency, CA-rotation counter, cluster-CA-rotation counter, enrollment-token consumed/expired counters, or heartbeat-disconnection counter. |
| **CL-9** | P6.4 Cluster | `roadmap/CLUSTER-RUNTIME-DISCOVERY.md:556` | No `culvert_cluster_*` / `culvert_ha_*` / `culvert_enrollment_*` family: no enrollment-failure, HA-failover, ClusterStore-save, rolling-update-progress, or DP-poll-latency signals. Operators rely on the audit ring + `apiClusterStatus` / `apiClusterHA` polling. |

None of UC-6 / SC-2 / CA-2 / CL-9 is a P6 blocker — all four discovery docs classify
them as observability/governance follow-ups, not correctness fixes.

## 2. Existing metrics conventions (the contract any new metric must follow)

Grounded in `metrics.go` and `cdr_metrics.go` (the canonical "add a metric family" example).

### 2.1 Naming
- **Namespace:** every metric is prefixed `culvert_`.
- **Counters:** suffix `_total` (e.g. `culvert_dpi_blocked_total`, `culvert_cdr_files_processed_total`).
- **Gauges:** no suffix, or a unit suffix (`culvert_blocklist_size`, `culvert_uptime_seconds`, `culvert_cdr_queue_depth`).
- **Histograms:** `_seconds` for durations; emit `_bucket{le=...}` / `_sum` / `_count` (see `latencyHistogram.WritePrometheus`, `metrics.go:210`).
- Every family ships a `# HELP` and `# TYPE` line.

### 2.2 Mechanism
- Metrics are **hand-rolled text exposition**, not a Prometheus client library.
- Hot-path increments use **package-level `int64` / `atomic.Int64`** (zero-alloc), e.g. `statDPIBlocked`, `statCDRClean`. Gauges read live state on scrape (`bl.Count()`, `rl.Limit()`).
- A scrape calls `handleMetrics` (`metrics.go:230`), which prints the core block then appends each extra family via a `WritePrometheus(w *strings.Builder)` helper:
  ```go
  ruleMet.WritePrometheus(&ruleMetBuf)
  latencyHist.WritePrometheus(&ruleMetBuf)
  cdrWritePrometheus(&ruleMetBuf)        // ← the pattern to follow
  fmt.Fprint(w, ruleMetBuf.String())
  ```
- **New families follow `cdr_metrics.go`:** a dedicated `<domain>_metrics.go` file holding package-level counters + a `domainWritePrometheus(w *strings.Builder)` helper, wired into `handleMetrics` with one append line. This keeps each function under `funlen`/`cyclop` and keeps `metrics.go` readable.

### 2.3 Cardinality & privacy (hard rules — already enforced in-repo)
`cdr_metrics.go:11` states the contract explicitly: *"Labels are deliberately
low-cardinality. No policy_version, no user_id, no filename, no destination host."*

Concrete guardrails the code already uses, and that every item below MUST honor:
- **No unbounded label values.** Per-rule hits cap at `maxRuleMetrics = 200` (`metrics.go:21,50`); CDR threat types cap at 64 (`cdr_metrics.go:69`).
- **No user-controlled strings as labels.** No domains, URLs, node IDs, tokens, cert fingerprints/serials, keys, user names, IPs, or filenames in labels — per the task rules and the existing CDR contract.
- **Where a label is unavoidable, it must be a fixed, code-defined vocabulary** (e.g. `status="clean|sanitized|blocked|unsupported"`). Any label value that originates from config or the network is sanitized with `strings.NewReplacer(\`\`,…)` AND bounded.
- **Prefer label-free counters/gauges.** Most of `metrics.go` is label-free; that is the default and the lowest-risk choice for all four items.

### 2.4 Endpoint & auth (unchanged by this work)
- `GET /metrics`, content-type `text/plain; version=0.0.4`.
- Optional Bearer token via `metricsToken` with `subtle.ConstantTimeCompare` (`metrics.go:231`). Empty = open (back-compat default). No change proposed.

### 2.5 Existing test pattern
`coverage_test.go` (`TestHandleMetrics_*`) drives `handleMetrics` with an
`httptest.NewRecorder`, asserts the status code, and asserts the body
`strings.Contains` the metric name. Counter tests set the package-level `stat*`
var, scrape, and assert the rendered value. This is the pattern all four items reuse.

## 3. UC-6 — URL-category subsystem metrics

**What needs observability.** Whether the UT1 category feed and the SaaS feed are
syncing. The data already exists: `FeedSyncer.Stats() (int64, time.Time, time.Duration)`
(`feedsync.go:182`) and `SaaSFeedSyncer.Stats() (url, lastSync, count, interval)`
(`saas_feed.go:135`), surfaced today only through admin endpoints. The operator-facing
gap is "feed sync stuck" — no scrapeable signal, no alertable staleness.

**Proposed metrics** (label-free gauges + counters; one new file `urlcat_metrics.go`):

| Metric | Type | Source | Meaning |
|--------|------|--------|---------|
| `culvert_category_db_entries` | gauge | `catStore` size | URLs/domains currently classified. |
| `culvert_category_feed_last_sync_timestamp_seconds` | gauge | `FeedSyncer.Stats()` lastSync (Unix secs; `0` = never) | UT1 feed freshness; alert on `time() - <metric> > threshold`. |
| `culvert_category_feed_entries` | gauge | `FeedSyncer.Stats()` count | Entries from the last UT1 sync. |
| `culvert_saas_feed_last_sync_timestamp_seconds` | gauge | `SaaSFeedSyncer.Stats()` lastSync | SaaS feed freshness. |
| `culvert_saas_feed_entries` | gauge | `SaaSFeedSyncer.Stats()` count | Entries from the last SaaS sync. |
| `culvert_category_feed_sync_failures_total` | counter | new `atomic.Int64`, incremented on the feed-sync error path | Sync error count; alert on rate. |

**Labels / cardinality.** None. All label-free. (Two feeds = two distinct metric
names rather than a `feed="ut1|saas"` label — matches the label-free majority and
avoids any temptation to widen the label later.)

**Where to wire.**
- Gauges: read live in a `urlcatWritePrometheus(w)` helper (no hot-path cost), appended in `handleMetrics`.
- `culvert_category_feed_sync_failures_total`: increment an `atomic.Int64` at the existing error-return sites inside the syncers' loops. This is the only hot-pathish addition and it's an error path, so it's cold.

**Security/privacy.** Feed URLs are config-controlled and MUST NOT appear as labels —
emit counts/timestamps only. No domain or category names in labels.

**Test strategy.** Unit-test `urlcatWritePrometheus` against a builder: seed
`catStore` / syncer stats, assert `# HELP`/`# TYPE` lines and rendered values; assert
the failure counter increments. Reuse the `coverage_test.go` scrape-and-`Contains`
pattern for the end-to-end `/metrics` path.

## 4. SC-2 — scan hash-cache hit/miss counters (smallest item)

**What needs observability.** Scan-cache effectiveness. The counters already exist and
are already collected on the hot path — `HashCache.hits` / `.misses` are `atomic.Int64`
(`hashcache.go:44-45`) and returned by `Stats() (int64, int64, int)` (`hashcache.go:102`).
`handleMetrics` already *calls* `Stats()` but discards the first two values:
```go
_, _, cacheSize := globalSecScanner.cache.Stats()   // metrics.go:265
```
Only `culvert_scan_cache_size` is rendered.

**Proposed metrics** (two label-free counters):

| Metric | Type | Source |
|--------|------|--------|
| `culvert_scan_cache_hits_total` | counter | `HashCache.Stats()` hits |
| `culvert_scan_cache_misses_total` | counter | `HashCache.Stats()` misses |

**Labels / cardinality.** None.

**Where to wire.** Capture the already-returned values
(`hits, misses, cacheSize := globalSecScanner.cache.Stats()`) in `handleMetrics` and
emit two more lines alongside the existing `culvert_scan_cache_size`. No new
collection, no hot-path change — purely rendering data that's already measured. This is
the one item small enough to live inline in `metrics.go` rather than a new file.

**Security/privacy.** Trivially safe — pure counts, no labels.

**Test strategy.** In a unit test, drive `globalSecScanner.cache` to a known
hit/miss state (or set a fresh `HashCache`), scrape `/metrics`, assert the body
contains both new metric names with the expected values. ~one test function.

## 5. CA-2 — CA / TLS / certificate metrics

**What needs observability.** Operators currently can't see "CA rotated" or "leaf
cache thrashing" without parsing logs. Note a **factual correction to the discovery
note**: `CertManager` (`ca.go:43`) has **no** hit/miss fields today — only `cache` and
`cacheOrder`. So leaf-cache hit/miss requires *adding* counters (unlike SC-2, where the
data already exists). This raises CA-2's effort above the "one-line" items.

**Proposed metrics** (new file `ca_metrics.go`; label-free):

| Metric | Type | Source / increment site |
|--------|------|--------|
| `culvert_cert_cache_hits_total` | counter | new `atomic.Int64`, incremented in `CertManager` leaf-cache lookup hit branch |
| `culvert_cert_cache_misses_total` | counter | incremented in the cache-miss / sign-new branch |
| `culvert_cert_cache_size` | gauge | `len(certMgr.cache)` under `RLock` at scrape |
| `culvert_cert_sign_duration_seconds` | histogram | wrap leaf-signing with a `latencyHistogram`-style observe (reuse the existing histogram type) |
| `culvert_ca_rotations_total` | counter | incremented in `CertManager.RotateIfNeeded` (`ca.go:428`) on a successful rotation |
| `culvert_cluster_ca_rotations_total` | counter | incremented in `clusterCA.RotateIfNeeded` (`enrollment.go:1135`) / `onRotate` path |

> The enrollment-token consumed/expired counters and the heartbeat-disconnection
> counter named in the CA-2 source row are **cluster/enrollment-domain** signals and
> are folded into **CL-9 §6** (`culvert_enrollment_*`) to avoid a split-brain ownership
> between the CA and cluster metric families. CA-2's scope is therefore the cert/CA
> rotation + leaf-cache + signing-latency signals above.

**Labels / cardinality.** None. **Explicitly excluded:** cert serials, fingerprints,
subjects/SANs, CA names, key material — none may appear as labels or metric values.
Rotation counters are plain increments; the *fact* of a rotation is the signal, not
*which* cert.

**Where to wire.**
- Cache hit/miss: the leaf-cache lookup in `CertManager` (the get-or-sign path). Increment under the existing lock or via atomics outside it.
- Signing latency: time the sign call; `Observe(seconds)` on a package `latencyHistogram`.
- Rotation counters: the success branch of `RotateIfNeeded` (root) and the cluster-CA rotate/`onRotate` path.

**Security/privacy.** Highest-sensitivity item. The whole point of the no-label rule is
here: a fingerprint/serial label would leak the cert identity timeline. Keep everything
label-free and count-only. No passphrase, key, or bundle bytes ever touch metrics. (This
is observability only — it does **not** implement CA-3 / key-at-rest, which is explicitly
out of scope.)

**Test strategy.** Unit-test `caWritePrometheus`: force a cache hit and a miss via the
public sign/get path, assert both counters move; call `RotateIfNeeded` in a test that
triggers rotation and assert `culvert_ca_rotations_total` increments; assert the signing
histogram emits `_bucket`/`_sum`/`_count`. Use the existing CA test fixtures.

## 6. CL-9 — cluster / HA / enrollment metrics (largest item)

**What needs observability.** Enrollment failures, HA failover events, ClusterStore
save cadence, rolling-update progress, and DP poll latency — today only visible via the
audit ring and `apiClusterStatus` / `apiClusterHA` polling.

**Proposed metrics** (new file `cluster_metrics.go`; label-free unless noted):

| Metric | Type | Source / increment site |
|--------|------|--------|
| `culvert_enrollment_tokens_consumed_total` | counter | success branch of `ClusterStore.ValidateAndConsumeToken` (`enrollment.go:237`) |
| `culvert_enrollment_failures_total` | counter | error branches of `ValidateAndConsumeToken` (expired/invalid/used) |
| `culvert_enrollment_nodes` | gauge | count of enrolled nodes at scrape |
| `culvert_enrollment_nodes_connected` | gauge | nodes with `Status=="connected"` at scrape |
| `culvert_heartbeat_disconnects_total` | counter | the connected→disconnected transition in `checkHeartbeats` (`enrollment.go:608`) |
| `culvert_cluster_store_saves_total` | counter | each `ClusterStore.Save()` (covers the "save frequency" ask) |
| `culvert_ha_failovers_total` | counter | HA failover transition site (`globalHA` state change) |
| `culvert_ha_role` | gauge | `0`=standby, `1`=active (fixed numeric encoding, not a label) |
| `culvert_cluster_update_in_progress` | gauge | `1` while `runClusterUpdate` is active, else `0` |
| `culvert_dp_poll_duration_seconds` | histogram | DP-side: time each `pollLoop` round-trip (`controlplane.go` poll path) |

**Labels / cardinality.** None. **Explicitly excluded:** node IDs, node names, source
IPs, token plaintext/hashes, gRPC addresses. Enrollment failure reasons stay as a single
counter — *do not* add a `reason=` label sourced from error text (unbounded). If a
reason breakdown is ever wanted, it must be a tiny fixed vocabulary in a follow-up, not
this PR.

**Where to wire.**
- Counters at the named transition sites (token consume/fail, heartbeat disconnect, save, failover).
- Gauges read live at scrape from `ClusterStore` / `globalHA` under their existing locks.
- `culvert_dp_poll_duration_seconds`: observe around the DP `pollLoop` RPC. **DP-side only** — this is local instrumentation of the poll call, **not** a `ConfigSnapshot` field and **not** an HA/sync change (those are out of scope).

**Security/privacy.** Cluster topology is sensitive; aggregate counts/gauges only. No
per-node series (that would make node count a cardinality vector and leak topology). The
`culvert_ha_role` gauge encodes role as a number, deliberately avoiding a `role=` label.

**Test strategy.** Unit-test `clusterWritePrometheus` against seeded `ClusterStore` /
`globalHA` state; drive `ValidateAndConsumeToken` success + expired paths and assert the
consumed/failure counters; simulate a connected→disconnected transition in
`checkHeartbeats` and assert `culvert_heartbeat_disconnects_total`. Histogram test mirrors
the latency-histogram test. Reuse `cluster_audit_test.go` fixtures
(`TestClusterTokenCreate_*`, `TestApplyConfigSnapshot_*`) for setup.

## 7. PR-split recommendation

The discovery docs suggested "one observability follow-up PR," but the four items differ
by an order of magnitude in surface area and risk. **Recommendation: split into four
independent implementation PRs**, smallest-first, each shippable alone with its own
tests. They share only the `WritePrometheus`-append convention and have no ordering
dependency.

| Order | PR | Item | Size | Risk | Rationale |
|-------|----|------|------|------|-----------|
| 1 | metrics-1 | **SC-2** | tiny | minimal | Data already collected; renders 2 discarded values. Inline in `metrics.go`. Lands the test scaffold the others copy. |
| 2 | metrics-2 | **UC-6** | small | low | Mostly scrape-time gauges from existing `Stats()`; one cold error counter. New `urlcat_metrics.go`. |
| 3 | metrics-3 | **CA-2** | medium | medium | Requires *adding* cache hit/miss counters (none exist) + signing histogram + rotation counters. New `ca_metrics.go`. Touches the leaf-cache hot path — review carefully. |
| 4 | metrics-4 | **CL-9** | medium-large | medium | Most increment sites (enrollment, heartbeat, HA, update, DP poll) across `enrollment.go` / `controlplane.go`. New `cluster_metrics.go`. Absorbs the enrollment/heartbeat counters cross-referenced from CA-2. |

Reasons for splitting rather than one mega-PR:
- **Blast radius / reviewability.** SC-2 and UC-6 are near-zero-risk; bundling them with
  the CA hot-path and cluster increment sites would force a heavyweight review on a
  trivial change.
- **Independent verifiability.** Each PR's metrics can be asserted in isolation; a
  failure in the CL-9 wiring shouldn't hold up the SC-2 one-liner.
- **Hot-path isolation.** CA-2 (leaf cache) and CL-9 (DP poll) are the only ones that
  touch performance-sensitive paths; keeping them separate makes the perf review precise.

Each implementation PR must also satisfy the standing repo rules: a `# HELP`/`# TYPE`
pair per family, label-free (or fixed-vocabulary) metrics only, and the
**GUI-parity** convention does not apply (metrics are scrape-only; there is no new CLI
flag or config knob — `/metrics` already exists). No rollback-surface, no
`ConfigSnapshot`, no `saveConfigVersion` changes are introduced by any of the four.

## 8. Out of scope (restated)

- No production behavior changes in *this* doc PR.
- No rollback-surface changes; no `configBackup` / `saveConfigVersion` edits.
- No HA / `ConfigSnapshot` changes (the DP-poll histogram is local DP instrumentation, not a synced field).
- No CA-3 / key-at-rest implementation; CA-2 is observability only.
- No `/metrics` auth changes; no new CLI flags.
- No unrelated cleanup.

## 9. References

- `metrics.go` — core exposition + `handleMetrics` (`:230`), per-rule (`:152`), latency histogram (`:210`), discarded cache stats (`:265`).
- `cdr_metrics.go` — canonical `<domain>_metrics.go` + `WritePrometheus` + low-cardinality contract (`:11`) + cap pattern (`:69`).
- `hashcache.go:44-45,102` — existing scan-cache hit/miss counters + `Stats()`.
- `feedsync.go:182`, `saas_feed.go:135`, `threatfeed.go:220` — feed `Stats()` sources.
- `ca.go:43,428` — `CertManager` (no hit/miss fields today), `RotateIfNeeded`.
- `enrollment.go:237,558,608,1135` — token consume, heartbeat monitor, disconnect transition, cluster-CA rotate.
- `controlplane.go:1182-1186,1396` — DP goroutines incl. `pollLoop`; `c.call`.
- Discovery sources: `URL-CATEGORIES-DISCOVERY.md:352` (UC-6), `SCANNING-DISCOVERY.md:456` (SC-2), `ROOT-CA-DISCOVERY.md:402` (CA-2), `CLUSTER-RUNTIME-DISCOVERY.md:556` (CL-9).
</content>
</invoke>
