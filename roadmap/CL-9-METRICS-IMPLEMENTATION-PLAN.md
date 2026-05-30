# CL-9 Metrics — Implementation Plan

**Status:** Discovery / spec only. **No production behavior changes in this PR.**
**Parent:** `roadmap/OBSERVABILITY-METRICS-GAPS.md` §6 (CL-9). The final item in the
observability backlog after SC-2 (#291), UC-6 (#292), and CA-2 (#293–#298).
**Scope:** Pin the exact code hooks, lock-ordering analysis, label-free privacy
review, per-metric test plan, and a small-PR split for the cluster / HA /
enrollment metrics — *before* any code is written.

This document changes no Go code. It is the plan the implementation PRs execute against.

## 1. Metrics under CL-9

| Metric | Type | Signal |
|--------|------|--------|
| `culvert_enrollment_tokens_consumed_total` | counter | Enrollment tokens successfully consumed. |
| `culvert_enrollment_failures_total` | counter | Token validation failures (invalid/used/expired/prefix/CIDR/persist). |
| `culvert_enrollment_nodes` | gauge | Enrolled nodes (all non-deleted). |
| `culvert_enrollment_nodes_connected` | gauge | Nodes currently `connected`. |
| `culvert_heartbeat_disconnects_total` | counter | `connected`→`disconnected` transitions. |
| `culvert_cluster_store_saves_total` | counter | `ClusterStore` persistence operations. |
| `culvert_ha_role` | gauge | HA role: `0`=disabled, `1`=leader, `2`=standby. |
| `culvert_ha_failovers_total` | counter | Standby→leader promotions. |
| `culvert_cluster_update_in_progress` | gauge | `1` while a rolling update is active, else `0`. |
| `culvert_cluster_update_completed_nodes` | gauge | Nodes at `complete` in the active update. |
| `culvert_cluster_update_total_nodes` | gauge | Nodes in scope for the active update. |
| `culvert_dp_poll_duration_seconds` | histogram | DP→CP config-poll RPC latency (DP-node only). |

All are **label-free**. The HA role and update-in-progress states are encoded as
**fixed numeric values**, never as a `role=`/`state=` label (prefer-label-free rule).

## 2. Enrollment token outcomes

`ClusterStore.ValidateAndConsumeToken` (`enrollment.go:237`) holds `cs.mu.Lock`
throughout and has **six failure returns** (invalid `:244`, used `:248`, expired
`:252`, prefix mismatch `:257`, CIDR mismatch `:264`, persist error `:276`) and
**one success return** (`return info, nil`, `:279`). Its sole caller is the
`Enroll` RPC handler (`controlplane.go:734`).

**Recommended hook: a named-return + single deferred increment inside the method**:

```go
func (cs *ClusterStore) ValidateAndConsumeToken(plaintext, nodeID, sourceIP string) (info TokenInfo, err error) {
    defer func() {
        if err != nil {
            statEnrollFailures.Add(1)
        } else {
            statEnrollTokensConsumed.Add(1)
        }
    }()
    ...
}
```

Why this over incrementing at the caller (`controlplane.go:735`): it captures **all**
six failure paths and the success path in **one** edit, is symmetric, and is
**directly unit-testable** by calling `ValidateAndConsumeToken` without standing up
the gRPC `Enroll` handler. The existing explicit `return TokenInfo{}, fmt.Errorf(...)`
/ `return info, nil` statements are unchanged — the named returns are assigned by
them, and the deferred func observes the result.

**Scope boundary (documented, intentional):** `failures` counts **token-validation**
failures only. Other `Enroll`-handler denials — rate-limit (`controlplane.go:723`),
duplicate node (`:728`), bad CSR / CN mismatch, CA-not-ready, SignCSR error — are
**not** counted here, keeping the counter's meaning crisp ("token outcomes"). A
broader "enrollment attempts/denials" counter, if ever wanted, is a separate
follow-up — out of CL-9 scope.

**Lock-ordering:** the deferred func runs after each explicit `cs.mu.Unlock()`
(the method unlocks before every return), and an `atomic.Int64.Add` acquires no
lock regardless — no ordering risk.

## 3. Node-count gauges

`ClusterStore` exposes `ListNodes()` (`enrollment.go:379`, allocates a copy under
`RLock`). For scrape-time gauges, add a small allocation-free reader:

```go
func (cs *ClusterStore) NodeCounts() (total, connected int) {
    cs.mu.RLock()
    defer cs.mu.RUnlock()
    for _, n := range cs.st.Nodes {
        total++
        if n.Status == "connected" {
            connected++
        }
    }
    return
}
```

`culvert_enrollment_nodes` = `total`; `culvert_enrollment_nodes_connected` =
`connected`. Status vocabulary is fixed (`connected`/`disconnected`/`revoked`/`draining`,
`enrollment.go:75`) but is **not** emitted as a label — two gauges instead, per the
prefer-label-free rule. **Lock-ordering:** brief `RLock` at scrape; the handler holds
no other lock.

## 4. Heartbeat disconnects

The single `connected`→`disconnected` transition is in `checkNodeLiveness`
(`enrollment.go:608-610`), which runs under `cs.mu.Lock` (held by `checkHeartbeats`,
`:582`). Hook:

```go
if elapsed > heartbeatTimeout && node.Status == "connected" {
    node.Status = "disconnected"
    statHeartbeatDisconnects.Add(1)   // ← CL-9
    changed = true
    ...
}
```

One increment per node transition (cumulative counter). **Lock-ordering:** atomic
add under `cs.mu` — no lock acquired by the atomic, no risk.

## 5. ClusterStore save cadence

**Confirmed chokepoint: `ClusterStore.saveLocked()` (`enrollment.go:170`), NOT
`Save()`.** `Save()` (`:163`) merely takes the lock and delegates to `saveLocked()`,
and **seven** call sites invoke `saveLocked()` directly, bypassing `Save()`: token
consume (`:274`), node add/remove (`:505`, `:525`), heartbeat persist (`:552`/`:595`),
HA-sync import (`:684`), plus the CP hold-lock path (`controlplane.go:820`).
Instrumenting `Save()` alone would undercount — this is the exact lesson from PR #289.
Increment a single `statClusterStoreSaves.Add(1)` inside `saveLocked()`.

**Lock-ordering:** every caller holds `cs.mu` when calling `saveLocked()`; the atomic
add acquires no lock — safe.

## 6. HA role + failover

`globalHA` (`ha.go:45`) is `*HAState` with `role string` ∈ {`""`, `"leader"`,
`"standby"`} guarded by `h.mu`.

- **`culvert_ha_role`** gauge: read `globalHA.Status().Role` (`ha.go:55`, takes
  `h.mu.RLock`) at scrape and map to a fixed code: `"" → 0`, `"leader" → 1`,
  `"standby" → 2`. Encoding the state as a number (not a `role=` label) keeps it
  label-free.
- **`culvert_ha_failovers_total`** counter: increment in `promote()` (`ha.go:244`)
  **after** `onPromote()` succeeds and the role is set to `"leader"` (`:253-255`).
  The initial `EnableAsLeader` (`:87`) is the designated-leader path, **not** a
  failover — it is **not** counted. One increment per promotion.

**Lock-ordering:** the role gauge takes `h.mu.RLock` at scrape; the failover atomic
add runs after `promote`'s `h.mu.Unlock` (and is lock-free regardless) — no risk.

## 7. Rolling-update progress

`clusterUpdateState` (`update_cluster.go:72`) is a package-global `ClusterUpdateState`
guarded by its own `mu sync.Mutex`, with `Active bool`, `Phase string`, and
`Nodes map[string]*NodeUpdateStatus` (`Status` ∈ a fixed vocabulary incl. `"complete"`).

All three update metrics are **pure scrape-time gauges — no hot-path increments**.
Add an allocation-light reader:

```go
func updateProgressGauges() (active bool, completed, total int) {
    clusterUpdateState.mu.Lock()
    defer clusterUpdateState.mu.Unlock()
    active = clusterUpdateState.Active
    total = len(clusterUpdateState.Nodes)
    for _, n := range clusterUpdateState.Nodes {
        if n.Status == "complete" {
            completed++
        }
    }
    return
}
```

- `culvert_cluster_update_in_progress` = `1` if `active` else `0`.
- `culvert_cluster_update_completed_nodes` = `completed`.
- `culvert_cluster_update_total_nodes` = `total`.

**Lock-ordering:** `clusterUpdateState.mu` is a plain `sync.Mutex`, so the scrape
reader briefly **blocks** the update orchestrator. It only reads fields and returns —
microseconds — and the handler holds no other lock, so there is no deadlock or
inversion risk. Hold the lock only for the read; do not call out under it.

## 8. DP poll latency (`culvert_dp_poll_duration_seconds`)

There **is** an obvious low-risk hook: `fetchAndApply` (`controlplane.go`) issues the
steady-state config poll via `raw, err := c.call(ctx, methodGetConfig, …)`. Time only
that primary call, observe on success:

```go
t0 := time.Now()
raw, err := c.call(ctx, methodGetConfig, json.RawMessage("{}"))
if err == nil {
    dpPollHist.Observe(time.Since(t0).Seconds())
}
```

Reuse the **generalized histogram from CA-2 PR2** (`newHistogram(name, help, buckets)`,
`metrics.go`) with RPC-appropriate buckets, e.g. `0.001, 0.0025, 0.005, 0.01, 0.025,
0.05, 0.1, 0.25, 0.5, 1, 2.5` seconds.

**Caveats to document:**
- This metric is **DP-node-only** — the `DataPlaneClient` runs on data-plane nodes;
  on a CP/standalone node the histogram simply renders zero observations. That is
  expected, not a bug.
- Time **only** the primary `methodGetConfig` call (steady-state poll), not the
  failover-retry `c.call` (`fetchAndApply` retry branch) — keeps the metric's meaning
  crisp and avoids double-counting during failover.
- **It is local DP instrumentation only — NOT a `ConfigSnapshot` field and NOT an HA
  change.** No cross-node propagation.
- **Lock-ordering:** `c.call`'s `c.conn` read is itself unsynchronized today
  (tracked separately as CL-R-10/CL-11 — *not* in scope here); the `Observe` we add is
  lock-free and holds nothing, so it introduces no new ordering risk.

Because it touches a different file (`controlplane.go`) and is DP-only, it is the
natural candidate to **split into its own PR** (see §11) or defer if reviewers prefer.

### 8.1 PR4 discovery findings (verified against `main`)

Discovery confirmed the §8 sketch is implementable cleanly and corrects one claim.
Findings:

- **Polling path (verified):** `pollLoop` (`controlplane.go:1189`, launched DP-only at
  `:1182` via `go c.pollLoop`) ticks `fetchAndApply`, whose **first statement** is the
  steady-state poll `raw, err := c.call(ctx, methodGetConfig, json.RawMessage("{}"))`.
  `c.call` (`controlplane.go`) wraps `conn.Invoke` with a fixed `5s` `context.WithTimeout`
  — so a single `c.call` is the complete request/response lifecycle for one poll.
- **Narrowest boundary:** wrap **only** the primary `methodGetConfig` `c.call` in
  `fetchAndApply` (the first line), not `fetchAndApply` as a whole (which also does
  `json.Unmarshal` + `validateConfigSnapshot` + `applyConfigSnapshot`) and **not** the
  failover-retry `c.call` in the error branch. This times exactly the CP round-trip.
- **Histogram reuse (verified):** the CA-2 PR2 generalization is in `main` —
  `newHistogram(name, help, buckets)` (`metrics.go:186`) + the lock-free `Observe`
  (`:217`) + per-instance `WritePrometheus` (`:237`). A package var
  `dpPollHist = newHistogram("culvert_dp_poll_duration_seconds", …, <buckets>)` reuses it
  directly; render via `dpPollHist.WritePrometheus` appended in `clusterWritePrometheus`
  (or `handleMetrics`). No new histogram code.
- **No labels / no identifiers required (verified):** the observation is a single
  `float64` duration. The poll carries no per-CP identity into the metric — `c.addrs` /
  `activeIdx` / `nodeID` stay out of it. No node IDs, hostnames, peer addresses, URLs, or
  labels are needed. Fully label-free.
- **Lock-ordering — correction to §8:** `c.call` reads `c.conn` **under `c.mu.Lock`**
  (snapshots `conn` then unlocks before `Invoke`), so the read is *not* unsynchronized at
  this call site (the CL-R-10/CL-11 concern is about other call sites and is out of
  scope). The `Observe` we add runs **after** `c.call` returns, holds no lock, and is
  lock-free — zero new ordering risk regardless.
- **Error semantics:** **observe on success only** (`if err == nil`). A failed poll
  (timeout / transport error) is not a latency sample — folding the 5s-timeout error
  into the histogram would distort the distribution. Failures are already visible via the
  existing `DataPlane: GetConfig error` log and the failover path; a separate
  `culvert_dp_poll_failures_total` counter is **out of PR4 scope** (note for a possible
  follow-up, not now).
- **Metric:** `culvert_dp_poll_duration_seconds` (histogram). Buckets tuned for an
  intra-cluster gRPC round-trip: `0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
  0.5, 1, 2.5` seconds (the 5s `c.call` timeout sits just past the top finite bucket, so
  near-timeout slow polls land in `+Inf`).
- **Exact observe location:** `controlplane.go`, `fetchAndApply`, around the **first**
  `c.call(ctx, methodGetConfig, …)`:
  ```go
  t0 := time.Now()
  raw, err := c.call(ctx, methodGetConfig, json.RawMessage("{}"))
  if err == nil {
      dpPollHist.Observe(time.Since(t0).Seconds())
  }
  ```
- **Test strategy:** `fetchAndApply` needs a live gRPC conn, so existing DP tests
  (`controlplane_snapshot_bounds_test.go:124`) deliberately exercise the *slice* logic
  rather than the whole method. Mirror that: (1) **unit** — drive `dpPollHist.Observe(...)`
  directly and assert `_count`/`_sum`/`_bucket` rendering and that `WritePrometheus` emits
  the `culvert_dp_poll_duration_seconds_*` family; (2) **render** — scrape `/metrics` and
  assert the family appears (zero observations on a CP/standalone node is valid); (3)
  **wiring** — verify the call-site edit in the PR diff/review rather than a full gRPC
  stub, OR add one `bufconn`-backed happy-path test if a lightweight CP stub is already
  available in the test helpers (optional — the histogram-level unit test is the
  load-bearing one). Counter/`_count` assertions use **deltas** for shuffle-safety; no
  sleeps.

**PR4 verdict:** measurable cleanly and safely. Single-line observe at one well-defined
boundary, reuses existing histogram infrastructure, fully label-free, success-only
semantics, no new lock-ordering risk. Recommend implementing as the final CL-9 slice.


## 9. Privacy / cardinality review (per hard rules)

| Metric | Identity data touched? | Verdict |
|--------|------------------------|---------|
| `enrollment_tokens_consumed_total` / `_failures_total` | token plaintext/hash, node ID, source IP all stay inside the method | ✅ plain counts, no label |
| `enrollment_nodes` / `_nodes_connected` | reads node map; emits only integer counts | ✅ no node IDs |
| `heartbeat_disconnects_total` | node ID logged (pre-existing) but never in the metric | ✅ plain count |
| `cluster_store_saves_total` | none | ✅ |
| `ha_role` | role mapped to `0/1/2` — no `role=` label, no peer addr | ✅ |
| `ha_failovers_total` | none | ✅ |
| `cluster_update_*` | reads update state; emits integers / `0|1` only — no node IDs, tags, or phase strings | ✅ no label |
| `dp_poll_duration_seconds` | a `float64` duration only — no CP addr, no version | ✅ no label |

**Excluded everywhere (hard rules):** node IDs, tokens, cert fingerprints, IPs,
hostnames, version tags, phase/status strings, peer addresses, any user-controlled
string. No CA-3/key-at-rest, no rollback/HA/`ConfigSnapshot` behavior change.

## 10. Per-metric test plan

All tests are local, **no network, no sleeps**. Counters/histograms assert on
**before/after deltas** (safe for atomics; not the audit-ring `len()` hazard).
Snapshot/restore any swapped globals (`globalClusterStore`, `globalHA`,
`clusterUpdateState`, `metricsToken`) in `t.Cleanup`, per the SC-2/UC-6/CA-2 pattern.

- **Enrollment consumed/failures** — fresh `ClusterStore` (`newTestClusterStore`),
  create a token, `ValidateAndConsumeToken(valid)` → consumed delta `1`;
  `ValidateAndConsumeToken("bad", …)` → failures delta `1`. (Unit-testable precisely
  because the increments live inside the method — §2.)
- **Node counts** — register nodes with mixed `Status`, assert `NodeCounts()` and the
  rendered `culvert_enrollment_nodes` / `_nodes_connected` (point global `certMgr`-style
  at the fixture store via `globalClusterStore` snapshot/restore).
- **Heartbeat disconnects** — register a `connected` node with `LastSeen` older than
  `heartbeatTimeout`, call `checkHeartbeats()`, assert the counter delta `1` and the
  node is now `disconnected`.
- **Store saves** — call a `saveLocked()`-routing mutation (e.g. `RegisterNode` +
  whatever persists, or drive `checkHeartbeats`) and assert the counter advanced;
  assert `Save()` also advances it (delegates to `saveLocked`).
- **HA role gauge** — set `globalHA` to leader/standby/disabled fixtures, scrape,
  assert `culvert_ha_role` renders `1`/`2`/`0`.
- **HA failovers** — drive `promote()` with a stub `onPromote` returning nil → delta
  `1`; with `onPromote` returning an error → delta `0` (failed promote not counted).
- **Update gauges** — set `clusterUpdateState` to a fixture with N nodes, K at
  `"complete"`, `Active=true`; scrape; assert `in_progress=1`, `completed_nodes=K`,
  `total_nodes=N`. Reset to `Active=false` → `in_progress=0`.
- **DP poll histogram** — drive `dpPollHist.Observe(...)` directly (or a fake
  `c.call`); assert `_count` delta and `_bucket`/`_sum` rendering. (Full
  `fetchAndApply` wiring needs a gRPC stub — keep the unit test at the histogram level
  and verify the call-site wiring in the PR.)
- **/metrics render** — one test scrapes `/metrics` and asserts all twelve families
  appear with their `# TYPE` lines.
- **Negative controls** — removing any increment fails its delta assertion; removing a
  render line fails the scrape assertion (the SC-2/CA-2 pattern).

## 11. Recommended implementation split

CL-9 is the largest item; split into **four** small, independently-shippable PRs.
They share only the `clusterWritePrometheus` append convention; no ordering
dependency (PR4 reuses the PR2 histogram type, already in `main`).

| PR | Scope | Files touched | Notes |
|----|-------|---------------|-------|
| **PR1** | Enrollment: `tokens_consumed_total`, `failures_total`, `nodes`, `nodes_connected` | `enrollment.go` (deferred increment + `NodeCounts`), new `cluster_metrics.go` (writer + counters), `metrics.go` (append), test | Lowest risk; pure enrollment surface. |
| **PR2** | Liveness + persistence: `heartbeat_disconnects_total`, `cluster_store_saves_total` | `enrollment.go` (2 increments: `checkNodeLiveness`, `saveLocked`), `cluster_metrics.go` (render), test | `saveLocked` is the confirmed chokepoint (#289). |
| **PR3** | HA + rolling update: `ha_role`, `ha_failovers_total`, `cluster_update_in_progress`/`_completed_nodes`/`_total_nodes` | `ha.go` (failover increment), `update_cluster.go` (`updateProgressGauges` reader), `cluster_metrics.go` (render), test | Gauges are scrape-only; one counter in `promote`. |
| **PR4** | DP poll latency: `dp_poll_duration_seconds` | `controlplane.go` (time the `methodGetConfig` call), `metrics.go` (wire `dpPollHist.WritePrometheus`), test | DP-node-only; reuses the PR2-generalized histogram. Deferrable / lowest priority. |

Each PR: a `# HELP`/`# TYPE` pair per family, label-free metrics only, no
rollback/HA/`ConfigSnapshot`/CA-3 changes, GUI-parity N/A (scrape-only, `/metrics`
already exists). Verification per PR: `go vet ./...`;
`go test -race -count=1 -timeout=15m ./...`; `go test -count=2 -shuffle=on -timeout=20m ./...`.

## 12. Key references

- `enrollment.go:237-280` — `ValidateAndConsumeToken` (success `:279`, six failure returns).
- `enrollment.go:163-170` — `Save()` → `saveLocked()` chokepoint; 7 direct `saveLocked` callers (`:274,:505,:525,:552,:595,:684`, `controlplane.go:820`).
- `enrollment.go:379` — `ListNodes` (basis for `NodeCounts`); `:75` node `Status` vocabulary.
- `enrollment.go:582-613` — `checkHeartbeats` / `checkNodeLiveness` (disconnect transition `:608-610`).
- `controlplane.go:734` — `Enroll` handler (sole `ValidateAndConsumeToken` caller).
- `ha.go:36-45` — `HAState` (`role` field, `globalHA`); `:55` `Status()`; `:87` `EnableAsLeader` (not a failover); `:244-255` `promote()` (failover site).
- `update_cluster.go:30-46,72` — `ClusterUpdateState` (`Active`, `Phase`, `Nodes`, `mu`); global `clusterUpdateState`.
- `controlplane.go` `fetchAndApply` — `c.call(ctx, methodGetConfig, …)` poll site.
- `metrics.go` — generalized `newHistogram(name, help, buckets)` (CA-2 PR2), `WritePrometheus` append pattern in `handleMetrics`.
- Spec parent: `roadmap/OBSERVABILITY-METRICS-GAPS.md` §6 (CL-9).
</content>
