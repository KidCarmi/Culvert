# CA-2 Metrics — Implementation Plan

**Status:** Discovery / spec only. **No production behavior changes in this PR.**
**Parent:** `roadmap/OBSERVABILITY-METRICS-GAPS.md` §5 (CA-2). SC-2 (#291) and UC-6 (#292) shipped; this plans CA-2.
**Scope:** Define exact code hooks, lock-ordering analysis, privacy guardrails, a per-metric test plan, and a 3-PR implementation split for the six CA-2 metrics — *before* any code is written.

This document changes no Go code. It is the plan the (separately-scoped) implementation PRs execute against.

## 1. Metrics under CA-2

| Metric | Type | Signal |
|--------|------|--------|
| `culvert_cert_cache_hits_total` | counter | Leaf-cert cache served a cached cert. |
| `culvert_cert_cache_misses_total` | counter | Leaf-cert cache lookup missed → had to sign. |
| `culvert_cert_cache_size` | gauge | Current number of cached leaf certs. |
| `culvert_cert_sign_duration_seconds` | histogram | Leaf-cert signing latency. |
| `culvert_ca_rotations_total` | counter | Root CA rotations (auto + manual). |
| `culvert_cluster_ca_rotations_total` | counter | Cluster CA rotations/imports (auto + manual). |

All are **label-free**. Confirmed against the existing conventions in `metrics.go` / `cdr_metrics.go` and the per-metric privacy review in §6.

> **Correction to the OBSERVABILITY-METRICS-GAPS.md note (carried from the P6.3 discovery):** `CertManager` has **no** hit/miss fields today — only `cache map[string]*certCacheEntry` and `cacheOrder []string` (`ca.go:43-49`). So cache hit/miss counters must be **added**, not merely surfaced. This is why CA-2 is "medium" effort, not a one-liner like SC-2.

## 2. The leaf-cert cache flow (`CertManager.GetCert`, `ca.go:599-645`)

```go
func (cm *CertManager) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    host := ...                                   // ServerName, host-only, "" → "unknown"
    now := time.Now()
    cm.mu.RLock()
    if entry, ok := cm.cache[host]; ok && now.Sub(entry.createdAt) < certCacheTTL &&
        (entry.cert.Leaf == nil || now.Before(entry.cert.Leaf.NotAfter)) {
        cm.mu.RUnlock()
        return entry.cert, nil                    // ← (A) CACHE HIT branch  (ca.go:610-614)
    }
    cm.mu.RUnlock()

    cert, err := cm.signLeaf(host)                // ← (B) SIGN  (ca.go:617)  [latency measured here]
    if err != nil {
        return nil, err                           //    sign failed
    }
    cm.mu.Lock()
    cm.cache[host] = &certCacheEntry{cert: cert, createdAt: now}  // ← (C) cache insert (ca.go:621-622)
    cm.cacheOrder = append(...)
    ... LRU eviction at certCacheMaxSize ...
    cm.mu.Unlock()
    return cert, nil
}
```

**Exact branches:**
- **Cache HIT** = (A), `ca.go:610-614` (entry present, within TTL, leaf not expired).
- **Cache MISS** = the fall-through after `cm.mu.RUnlock()` at `ca.go:615` (entry absent, **or** TTL-expired, **or** leaf-expired — all are misses). The decision to sign at (B) is the single point that defines a miss.

**Counter placement decision (mirror SC-2 / `HashCache`):** add `hits, misses atomic.Int64` **fields on `CertManager`** plus a `CacheStats() (hits, misses int64, size int)` method, exactly like `HashCache.Stats()` (`hashcache.go:102`). Increment:
- `cm.hits.Add(1)` in branch (A), before/after `RUnlock` (atomic — order vs the lock is irrelevant).
- `cm.misses.Add(1)` immediately after the `RUnlock` at `ca.go:615`, i.e. at the point we commit to signing — **independent of whether `signLeaf` then succeeds**. This gives the clean invariant `hits + misses == GetCert calls`, and "miss" means "the cache didn't serve it" (the cache-effectiveness signal operators want), not "signing succeeded".

`culvert_cert_cache_size` reads `len(cm.cache)` at scrape time. **Reuse the existing `CertCacheLen()` (`ca.go:648`)**, which already takes `cm.mu.RLock()` — or fold the size into `CacheStats()` under one `RLock`. Prefer folding into `CacheStats()` so the scrape takes the read lock once.

## 3. Signing latency (`culvert_cert_sign_duration_seconds`)

**Where to measure:** wrap the `signLeaf` call at the `GetCert` call site (`ca.go:617`), **not** inside `signLeaf`:

```go
t0 := time.Now()
cert, err := cm.signLeaf(host)
if err == nil {
    certSignHist.Observe(time.Since(t0).Seconds())   // observe successful signs only
}
```

Rationale: at this point no `cm.mu` is held (the `RUnlock` at `:615` already ran), so `Observe` (lock-free) introduces no lock-ordering interaction. Measuring at the call site keeps `signLeaf` itself untouched and times the full keygen + `x509.CreateCertificate` + PEM assembly. Observe **only on success** so a fast error path doesn't pile into the lowest bucket and skew the distribution; sign errors are already (will be) visible as `misses - hits`-style discrepancies and via logs.

### 3.1 Histogram type: reuse vs new — RECOMMENDATION

The existing `latencyHistogram` (`metrics.go:172`) is a proven lock-free histogram (atomic CAS sum, atomic per-bucket counts). Its `Observe` (`:190`) is fully generic. **The only blocker to reuse is that `WritePrometheus` (`:210`) hardcodes the metric name `culvert_request_duration_seconds`** and `newLatencyHistogram` (`:181`) hardcodes the request-latency bucket layout `[0.005 … 10]s`.

**Recommended: generalize the existing type (small, zero-behavior-change refactor).**
- Add `name string` and `help string` fields to `latencyHistogram`; have `WritePrometheus` emit those instead of the literal.
- Keep `newLatencyHistogram()` as a thin wrapper that constructs the request histogram with `name = "culvert_request_duration_seconds"` and the current buckets — so the existing metric renders **byte-for-byte identically** (guard this with a golden assertion in the PR).
- Add `newHistogram(name, help string, buckets []float64) *latencyHistogram` for the CA sign histogram.

Why this over a bespoke helper: avoids duplicating the subtle CAS-sum logic; one tested histogram implementation; the change to the existing metric is a pure rename-via-field with a golden test proving no output drift.

**Fallback (if reviewers want zero edits to the shared type):** add a minimal `ca_sign_histogram.go` with its own ~30-line lock-free histogram. Higher duplication, but fully isolates the existing request metric. Either is acceptable; the plan recommends the generalize path and notes this fallback.

**Bucket layout for signing:** ECDSA P-256 keygen + sign is typically sub-millisecond to a few ms, far below the request histogram's 5 ms first bucket. Use a finer low-end layout, e.g.:
```
0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1   (seconds)
```
so the bulk of observations land in distinguishable buckets rather than collapsing into `le="0.005"`.

## 4. Root CA rotation (`culvert_ca_rotations_total`)

Two success paths; `InitCA` itself is **overloaded** (startup `main.go:710`, `LoadOrInitCA` `ca.go:139`, and inside rotation `ca.go:445`), so **the counter must NOT live in `InitCA`** — that would count startup as a rotation. Increment at the two genuine rotation sites:

1. **Auto-rotation** — `CertManager.RotateIfNeeded` (`ca.go:428`): increment on the single success return `return true` at **`ca.go:470`** (after `InitCA`, secondary install, and optional `SaveCA`). No `cm.mu` held there (last unlock was `:455`); atomic add is safe.
2. **Manual/admin** — `apiCARotate` (`ui_security.go:1101`): increment after the successful `certMgr.InitCA()` (`:1160`), alongside the existing `auditEvent(r, "ca.rotate", …)` at **`ui_security.go:1169`**. Handler holds no CA lock; atomic add is safe.

(Custom-CA upload via `LoadCustomCA` (`ca.go:382`) is a *replacement* path, not wired to a counter here; if operators want it counted later it can be added as a third site, but it's out of the named CA-2 scope and the two rotation paths above are the canonical ones. Note and defer.)

## 5. Cluster CA rotation (`culvert_cluster_ca_rotations_total`)

**Single chokepoint: `clusterCA.ImportCA` (`enrollment.go:1013`).** Both rotation paths route through it:
- **Auto-rotation** — `clusterCA.RotateIfNeeded` (`enrollment.go:1135`) generates a new CA then calls `ca.ImportCA(newCertPEM, newKeyPEM)` (`enrollment.go:1185`).
- **Manual/admin** — `apiClusterCA` POST (`ui_cluster.go:305`) calls `globalClusterCA.ImportCA(...)` (`ui_cluster.go:343`).

`ImportCA` has exactly these two callers (verified) — it is genuinely "import/replace/rotate" only; `InitOrLoad` uses `loadFromPEM`, not `ImportCA`. **Increment a single atomic at the success return of `ImportCA`** (after the `onRotate` callback, `enrollment.go:~1077`, just before `return nil`). The increment sits under `defer ca.mu.Unlock()`, but an atomic add acquires no lock, so there is **no lock-ordering risk** (see §7).

**Semantic note:** the first-ever manual import (when `ca.cert == nil`, no prior cluster CA) will increment the counter. That is a CA change and counting it is acceptable; documented here so the test asserts deltas, not absolute "rotation #2".

## 6. Privacy / security review (per hard rules)

Every metric is reviewed against: no labels, no serials, no SANs/domains, no fingerprints, no key material, no subject names, no user-controlled strings.

| Metric | Identity data touched? | Verdict |
|--------|------------------------|---------|
| `culvert_cert_cache_hits_total` / `_misses_total` | The `host` (SNI) drives the cache key but is **never** emitted — counters are plain increments. | ✅ No label. **Hard constraint: `host` must never become a label** (cardinality + privacy). |
| `culvert_cert_cache_size` | `len(cm.cache)` integer only. | ✅ |
| `culvert_cert_sign_duration_seconds` | A `float64` duration only; the signed cert's serial/SAN/subject never leave `signLeaf`. | ✅ No label. |
| `culvert_ca_rotations_total` | Plain increment; the *fact* of rotation, not which cert. | ✅ |
| `culvert_cluster_ca_rotations_total` | Plain increment. Note `ImportCA` already logs a sanitized fingerprint to the **log** (`enrollment.go:1072`) — that is pre-existing and unrelated; the metric carries nothing. | ✅ |

Out of scope and untouched: **CA-3 / key-at-rest** (cluster CA key encryption), rollback surface, HA / `ConfigSnapshot`. This is observability only.

## 7. Lock-ordering analysis

All six are implemented with `atomic.Int64` / lock-free `Observe`, which acquire **no** mutex. Therefore none can participate in a lock cycle with `cm.mu` (CertManager) or `ca.mu` (clusterCA). Specifics:

- **hits** in branch (A): incremented while `cm.mu.RLock` is held — safe; an atomic op under a read lock takes no further lock. (May also be placed after `RUnlock`; functionally identical.)
- **misses** at `ca.go:615`: incremented with no lock held. Safe.
- **sign histogram** at `ca.go:617`: no lock held (post-`RUnlock`). Safe.
- **cache_size** at scrape: `CacheStats()`/`CertCacheLen()` takes `cm.mu.RLock()` briefly; the metrics handler holds no other lock, so no ordering risk.
- **root rotation counters**: `RotateIfNeeded` return (no lock held); `apiCARotate` (no CA lock held). Safe.
- **cluster rotation counter**: incremented inside `ImportCA` under `ca.mu` — but an atomic add introduces no lock acquisition, so it cannot deadlock or invert any ordering. Safe.

No new mutexes are introduced by any item.

## 8. Per-metric test plan

All tests are local crypto only — **no network, no sleeps**. Snapshot/restore any touched globals (`certMgr`, `globalClusterCA`, the sign histogram, `metricsToken`) in `t.Cleanup`, per the SC-2 / UC-6 pattern. Counter/histogram assertions use **before/after deltas** (safe for atomics; this is not the audit-ring `len()` hazard).

### PR 1 — cache hit/miss + size
- **Unit (`CacheStats`)**: fresh `cm := &CertManager{cache: map[string]*certCacheEntry{}}`; `cm.InitCA()`. `GetCert(&tls.ClientHelloInfo{ServerName:"a.test"})` → assert `misses==1, size==1`. Same host again → `hits==1, size==1`. New host `"b.test"` → `misses==2, size==2`. Assert via `cm.CacheStats()`.
- **Scrape**: snapshot/restore global `certMgr`, point it at the fixture, `handleMetrics` → assert body contains `culvert_cert_cache_hits_total`, `_misses_total`, `culvert_cert_cache_size` with expected values.
- **Negative control**: removing a render line / mis-wiring a counter fails the value assertion (proven the SC-2 way).
- Existing fixtures to reuse: `ca_test.go` already exercises `InitCA`/`GetCert`/`signLeaf`.

### PR 2 — signing latency histogram
- **Unit**: fresh `cm`, `InitCA`; capture `count0` from the sign histogram; call `GetCert` N times across **distinct** hosts (so each is a miss → sign); assert histogram `count == count0 + N` and `sum > 0`. Do **not** assert an exact latency (timing-dependent) — only that count/sum advance.
- **Render**: `WritePrometheus` (or scrape) emits `culvert_cert_sign_duration_seconds_bucket{le=…}`, `_sum`, `_count`.
- **If generalizing `latencyHistogram`**: add a **golden test** asserting the request histogram still renders `culvert_request_duration_seconds_*` exactly as before (no output drift from the name-field refactor).
- Reset/snapshot: the sign histogram is a package singleton; assert on **deltas** (atomics can't be cheaply zeroed), or construct a fresh `newHistogram(...)` in the unit test and exercise `Observe` directly.

### PR 3 — rotation counters
- **Root auto**: fresh `cm`, `InitCA` (10y expiry), then force near-expiry via `cm.caCert.NotAfter = time.Now().Add(24*time.Hour)`; `cm.RotateIfNeeded("", "")` (empty path skips `SaveCA` → no disk) → assert it returned `true` and `culvert_ca_rotations_total` delta `== 1`.
- **Root manual**: drive `apiCARotate` two-step. Step 1 (no `confirm`) returns a `confirmation_token`; step 2 posts `{confirm:true, confirmation_token:<tok>}` with an admin context (`context.WithValue(ctx, uiRoleKey{}, RoleAdmin)`, the established handler-test pattern). Assert delta `== 1`. (If the two-step flow proves heavyweight, assert the auto path in this PR and cover manual via the existing `apiCARotate` coverage test, noting the shared increment site.)
- **Cluster (covers both via `ImportCA`)**: fresh `ca := &clusterCA{dir: t.TempDir()}`, `InitOrLoad` to establish a CA; generate a fresh valid cluster-CA PEM pair in-test (the keygen/template in `RotateIfNeeded` `enrollment.go:1150-1182` is the template); `ca.ImportCA(certPEM, keyPEM)` → assert `culvert_cluster_ca_rotations_total` delta `== 1`. A second `ImportCA` → delta `== 2` (proves the chokepoint counts both auto and manual, which share this method). `enrollment_test.go` already exercises `ImportCA`.

## 9. Recommended implementation split

Three PRs, smallest-first, each independently shippable with its own tests. No ordering dependency beyond the optional shared-histogram refactor landing in PR 2.

| PR | Scope | Files touched | Notes |
|----|-------|---------------|-------|
| **PR 1** | `culvert_cert_cache_hits_total`, `_misses_total`, `culvert_cert_cache_size` | `ca.go` (fields + `CacheStats` + 2 increments), new `ca_metrics.go` (writer), `metrics.go` (one append line), test | Lowest risk; mirrors SC-2 exactly. |
| **PR 2** | `culvert_cert_sign_duration_seconds` | `ca.go` (wrap `signLeaf` call), `metrics.go` (generalize `latencyHistogram` **or** new `ca_sign_histogram.go`), `ca_metrics.go` (render), test + golden test | Touches the leaf-sign hot path and (optionally) the shared histogram — review carefully; golden test guards the existing metric. |
| **PR 3** | `culvert_ca_rotations_total`, `culvert_cluster_ca_rotations_total` | `ca.go` (`RotateIfNeeded` +1), `ui_security.go` (`apiCARotate` +1), `enrollment.go` (`ImportCA` +1), `ca_metrics.go` (render), test | Three increment sites across two CA scopes; all atomic. |

Each PR: a `# HELP`/`# TYPE` pair per family, label-free metrics only, no rollback/HA/`ConfigSnapshot`/CA-3 changes, GUI-parity N/A (scrape-only, `/metrics` already exists). Verification per PR: `go vet ./...`; `go test -race -count=1 -timeout=15m ./...`; `go test -count=2 -shuffle=on -timeout=20m ./...`.

## 10. Key references

- `ca.go:599-645` — `GetCert` (hit branch `:610-614`, miss/sign `:615-617`, cache insert `:621-643`).
- `ca.go:648` — `CertCacheLen` (existing locked size read).
- `ca.go:665-708+` — `signLeaf` (keygen + `x509.CreateCertificate`).
- `ca.go:428-471` — `RotateIfNeeded` (root auto-rotation, success `return true` at `:470`).
- `ui_security.go:1101-1171` — `apiCARotate` (manual root rotation; `InitCA` at `:1160`, audit at `:1169`).
- `ca.go:90` — `InitCA` (overloaded: startup + rotation — do **not** instrument here).
- `enrollment.go:1013-1078` — `clusterCA.ImportCA` (single cluster-rotation chokepoint; `onRotate` at `:1075`).
- `enrollment.go:1135-1191` — `clusterCA.RotateIfNeeded` (cluster auto-rotation → `ImportCA` at `:1185`).
- `ui_cluster.go:305-348` — `apiClusterCA` (manual cluster import → `ImportCA` at `:343`).
- `metrics.go:172-222` — `latencyHistogram` (type, generic `Observe` at `:190`, name-hardcoded `WritePrometheus` at `:210`).
- `hashcache.go:102` — `HashCache.Stats()` (the SC-2 instance-counter pattern to mirror for `CacheStats()`).
- Spec parent: `roadmap/OBSERVABILITY-METRICS-GAPS.md` §5 (CA-2).
</content>
