# P6.1 — URL Categories + Community BadgerDB Discovery

**Status:** Discovery only. No production code change, no tests.
**Scope:** `initURLCategories`, `catStore` (Layer 1), `communityDB` (Layer 2 — BadgerDB), `globalCategoryGroups`, `globalSaaSFeed`, the UT1 `FeedSyncer` goroutine.
**SPOF target:** none on the existing `RUNTIME-OWNERSHIP.md` SPOF list (Phase 6 is discovery-only by design — see §6 of the program doc); the relevant SPOF axis is the **detached goroutine** family (S4-class) and the **god-object init** family (S1-class).

---

## 0. Executive verdict

`initURLCategories` is a four-store init site (catStore + categoryGroups + SaaS feed + community BadgerDB) with one **correctly-parented** background goroutine (UT1 `FeedSyncer`) and one **detached** background goroutine (`globalSaaSFeed.syncLoop`) that survives `appLifecycleCancel()`. The community BadgerDB has an owned `Close()` path wired into the late-shutdown registry at `shutdownOrderCommunityDBClose=120` (PR #217 / P2.2). No persistent on-disk corruption surface was found — BadgerDB owns its own MVCC, `catStore.Save()` uses tmp+rename, and `categories.json` lives on the Tier-2 backup list.

Two pre-existing durability gaps **mirror prior P3 follow-up findings** and are NOT P6.1 scope:

1. `catStore.Save()` is atomic-via-rename but **not fsynced** (`policy.go:166–170`). Direct mirror of P3.1 follow-up #1 (`PACStore.Set`, `pac.go:82–86`) and P3.2a (`PolicyStore.Save`, fixed in PR #224).
2. `catStore.ReplaceAll()` mutates memory only and **does not persist** (`policy.go:187–197`). Direct mirror of P3.1 follow-up #3 (`FileProfileStore.ReplaceAll`, fixed in PR #222) and P3.2b (`policyStore.ReplaceAll`, fixed via caller-side `Save()` in PR #225 — the cluster-apply gap on a DP node).

One additional **runtime-ownership gap** worth filing for triage separately from P6.1:

3. `globalSaaSFeed.syncLoop` runs under `context.Background()` (allocated inside `Configure`, `saas_feed.go:73`) — **NOT** `appLifecycleCtx` — and `globalSaaSFeed.Stop()` is **never called during shutdown** (verified by grep). Concretely an S4-class detached goroutine that the S4 inventory missed. Behaviour is benign because the goroutine holds no DB handle and only mutates `catStore` via the same RWMutex hot-path readers use, but the lifecycle contract is asymmetric vs the UT1 `FeedSyncer`.

P6.1 is **discovery only**. None of the above warrant implementation in P6 itself. Items 1, 2, and 3 are filed in §10 alongside the other "uncovered, not P6.1 scope" findings, with explicit mirror references for sequencing.

What is **NOT** uncovered by this discovery:

- No undocumented persistence path beyond `categories.json` (Layer 1) and the BadgerDB directory (Layer 2).
- No hot-path race surface on the existing locks (`sync.RWMutex` on `catStore`, BadgerDB MVCC on `communityDB`).
- No `applyHotReload` coupling — categories are not in the SIGHUP path.
- No metric instrumentation (observability gap, not a correctness gap).

---

## 1. Component inventory

### 1.1 `initURLCategories(s *startupState)` — the startup site

Declared at `main.go:741–807`. Called at `main.go:190` between `initPolicy(s)` (step 26) and `initFileBlocking(s)` (step 28). The function performs four independent sub-inits:

| Sub-init | Lines | Side effect |
|---|---|---|
| Layer 1 catStore load | `main.go:744–751` | `catStore.Load(catPath)` from `s.fc.Proxy.URLCategoriesFile` (default `categories.json`); `logger.Fatalf` on error |
| UT1 name seeding | `main.go:753–773` | Adds empty `CategoryEntry` rows for every name in `ut1CategoryMap` so the GUI can list them; calls `catStore.Save()` once if any were added |
| Category groups load | `main.go:776–778` | `globalCategoryGroups.Load(filepath.Join(dataDir, "category_groups.json"))`; non-fatal |
| SaaS feed configure | `main.go:784` | `globalSaaSFeed.Configure(defaultSaaSFeedURL, 24*time.Hour)` — **spawns a detached goroutine** (see §3) |
| Community BadgerDB open | `main.go:789–806` | When `--cat-feed-db != ""`, opens BadgerDB and starts the UT1 `FeedSyncer` parented to `appLifecycleCtx` |

CLI flags read (`main.go:103–105, 253–255`):

| Flag | Field | Default |
|---|---|---|
| `--cat-feed-db` | `s.catFeedDB *string` | `""` (disabled) |
| `--cat-feed-url` | `s.catFeedURL *string` | `""` (falls through to `defaultUT1FeedURL` in `newFeedSyncer`) |
| `--cat-sync-interval` | `s.catSyncIntvl *string` | `""` (falls through to 24h) |

FileConfig fields read:

- `s.fc.Proxy.URLCategoriesFile` (used to override the default `categories.json` path).

### 1.2 `catStore` — Layer 1 (admin-managed, JSON-backed)

Declared at `policy.go:58–65` as a package global `var catStore = newCategoryStore(...)`. Carries:

- `mu sync.RWMutex` — protects all fields below.
- `entries []*CategoryEntry` — ordered slice; rebuilt on each mutator call.
- `index map[string]map[string]bool` — `lowercase(category) → lowercase(host) → present`; rebuilt on every mutation via `rebuildIndex()`.
- `path string` — set by `Load(path)`; nil-out makes `Save()` a no-op.

Persistence: `Save()` at `policy.go:156–171` — `json.MarshalIndent` → `os.WriteFile` to `path + ".tmp"` → `os.Rename`. Atomic-via-rename but **not fsynced**. (Pre-existing — see §10 finding #1.)

### 1.3 `communityDB` — Layer 2 (BadgerDB-backed, feed-managed)

Declared at `catdb.go:25–31`:

```go
type CommunityDB struct {
    db *badger.DB
}

var communityDB *CommunityDB
```

Nil when `--cat-feed-db == ""`. Opened via `openCommunityDB(dir)` at `catdb.go:36–48` with options:

- `WithValueLogFileSize(128 << 20)` — 128 MiB value-log files (default 1 GiB).
- `WithLogger(nil)` — suppress BadgerDB's internal logger to avoid double-logging.

The community DB has **no separate in-memory index**. All lookups go straight to BadgerDB via `Lookup(host)` (`catdb.go:75–98`), which walks `host` → `host[after first dot]` → … `tld` until it finds a key or runs out of labels.

### 1.4 `globalCategoryGroups` — sibling Layer-1 store

Declared in `policy.go` (separate file scope). Persisted to `category_groups.json` via its own `Save()`. **Distinct file**, distinct mutex. Out of P6.1 ownership analysis beyond noting it shares the `initURLCategories` init site.

### 1.5 `globalSaaSFeed` — Layer-1 supplemental syncer

Declared at `saas_feed.go:48–54`. Adds curated SaaS-category domains to `catStore` over time. Carries:

- `mu sync.Mutex` — protects `feedURL`, `interval`, `lastSync`, `lastCount`, `cancel`.
- `enabled atomic.Bool` — coarse on/off flag.
- `cancel context.CancelFunc` — cancels the goroutine spawned by the most recent `Configure(...)` call.
- `client *http.Client` — pre-configured with `ssrfSafeDialContext`.

**Goroutine lifetime gap** — see §3.

### 1.6 `FeedSyncer` — Layer-2 UT1 syncer

Declared at `feedsync.go:109–135`. Carries:

- `db *CommunityDB`
- `feedURL string`
- `syncInterval time.Duration`
- `lastSync atomic.Value` (stores `time.Time`)
- `totalDomains atomic.Int64`

No mutex; `lastSync` and `totalDomains` are atomic. `Start(ctx)` is the only entry point; **there is no `Stop()` method** — the goroutine exits on `ctx.Done()`.

---

## 2. Ownership graph (writers + readers)

### 2.1 Writers — startup phase (single-threaded, pre-listener-accept)

| Writer | Touches | Location | Order |
|---|---|---|---|
| `catStore.Load(catPath)` | `catStore.entries`, `.index`, `.path` | `main.go:748` → `policy.go:131` | step 27 in startup |
| Layer-1 UT1 seeding loop | `catStore.entries` (and `.Save()` once) | `main.go:753–773` | inside step 27 |
| `globalCategoryGroups.Load(...)` | `globalCategoryGroups.entries` | `main.go:776` | inside step 27 |
| `globalSaaSFeed.Configure(...)` | `globalSaaSFeed.feedURL`, `.interval`, `.cancel`, `.enabled` → spawns `syncLoop` | `main.go:784` | inside step 27 |
| `openCommunityDB(*s.catFeedDB)` | assigns package global `communityDB`; opens `*badger.DB` | `main.go:793` | inside step 27 |
| `s.feedSyncer.Start(appLifecycleCtx)` | spawns one ticker goroutine | `main.go:803–804` | inside step 27 |

**No order dependency between the four sub-inits.** UT1 seeding requires Layer-1 to be loaded first; the rest are independent.

### 2.2 Writers — runtime phase (post-listener-accept; concurrent with hot path)

| Writer | Touches | Trigger | Synchronisation |
|---|---|---|---|
| `apiURLCat` POST/PUT/DELETE | `catStore.Set` / `.Delete` (which call `.Save`) | Admin API (`ui_policy.go:476, 508, 529`) | `catStore.mu.Lock` (write lock on every mutator) |
| `apiURLCatHost` POST/DELETE | `catStore.AddHost` / `.RemoveHost` (which call `.Save`) | Admin API (`ui_policy.go:560, 577`) | `catStore.mu.Lock` |
| `globalSaaSFeed.Sync(ctx)` merge | `catStore.AddHost` per domain | SaaS-feed ticker every 24h | `catStore.mu.Lock` per `AddHost` call |
| `FeedSyncer.Sync()` | `communityDB.BulkWrite(entries)` (BadgerDB WriteBatch) | UT1-feed ticker every 24h (or `Sync()` triggered on startup when DB empty) | BadgerDB MVCC; no external lock |
| `controlplane.go applyConfigSnapshot` (DP side) | `catStore.ReplaceAll(snap.URLCategories)` | CP→DP poll (~5s heartbeat); HA standby loop (5s) | `catStore.mu.Lock` for the swap; **but no Save() afterward** — see §10 finding #2 |

Two runtime mutators (`apiURLCat`, `apiURLCatHost`) are also reachable from **backup restore** indirectly: `categories.json` is a Tier-2 artifact, so a restored file is picked up by `catStore.Load` on the next startup. The restore path itself does not write `catStore` at runtime.

### 2.3 Readers — proxy hot path (concurrent, every request)

| Reader | Reads | Location |
|---|---|---|
| `matchCategoryInStore(cat, host)` | `catStore.index` (under RLock) | `policy.go:910–986` |
| `matchCategory(cat, host)` Layer-2 fallback | `communityDB.Lookup(host)` (BadgerDB View) | `policy.go:916–919` |

Both are invoked from `Policy.Evaluate(...)` per request when a rule names a category.

### 2.4 Readers — admin UI / API (low-rate)

| Reader | Reads | Location |
|---|---|---|
| `apiURLCat` GET | `catStore.All()` plus `communityDB != nil` enrichment flag | `ui_policy.go:426–451` |
| `apiURLCatLookup` GET | `lookupHostCategory(host)` — checks both layers | `ui_policy.go:592–617` → `policy.go:927–960` |
| `apiCategoryGroups` GET | `globalCategoryGroups.All()` | `ui_policy.go` (group endpoints) |
| Cluster snapshot capture (`captureConfigSnapshot` CP side) | `catStore.All()` | `controlplane.go:1635–1636` |
| Backup capture | indirect via `categories.json` on disk; not via `catStore` at runtime | `backup.go:74` |

### 2.5 Cross-cluster sync

`ConfigSnapshot.URLCategories []CategoryEntry` (`controlplane.go:86`) carries the Layer-1 catStore over the wire CP→DP. The DP applier calls `catStore.ReplaceAll(snap.URLCategories)` (`controlplane.go:1502–1504`); the CP capture reads `catStore.All()` (`controlplane.go:1635–1636`).

Cap on inbound snapshot size: `maxSnapURLCategories = 200_000` (`controlplane.go:142, 171`). Snapshots exceeding the cap are rejected on the DP side.

**Layer 2 (`communityDB` / BadgerDB) is NOT in `ConfigSnapshot`.** Each DP node's BadgerDB is configured locally via its own `--cat-feed-db` flag and synced independently by its own `FeedSyncer`. Pre-existing design; out of P6.1 scope.

---

## 3. Goroutine ownership / lifecycle

Two background goroutines are spawned by `initURLCategories`. Their lifecycle contracts **differ**:

| Goroutine | Parent ctx | Cancel mechanism | Health |
|---|---|---|---|
| `FeedSyncer.Start(appLifecycleCtx)` — UT1 ticker | `appLifecycleCtx` (passed in at `main.go:804`) | `appLifecycleCancel()` via `app-lifecycle-cancel` early-shutdown hook (order 40) | ✅ Cancellable. Select on `<-ctx.Done()` at `feedsync.go:147–149`. |
| `globalSaaSFeed.Configure(...)` → `syncLoop` | **`context.Background()` allocated inside `Configure`** (`saas_feed.go:73`) | `globalSaaSFeed.Stop()` — **never called from any shutdown path** (grep result: only call sites are `Configure` and `admin_settings.go`'s reconfigure path) | ⚠ Detached. Goroutine survives `appLifecycleCancel()`. See §10 finding #3. |

**Detail on the UT1 goroutine's HTTP behaviour.** `FeedSyncer.Sync()` calls `downloadAndParse(url)` which builds the HTTP request with `context.Background()` (`feedsync.go:192`). The goroutine's select-on-ctx exits cleanly on cancel, but an **in-flight download** continues until `feedSyncHTTPTimeout` fires (or completion). Not a leak — the goroutine still terminates within the timeout — but worth noting as a corner case. This is **out of P6.1 scope to fix** because the resulting goroutine is bounded and the eventual termination is guaranteed.

**Detail on the SaaS goroutine's behaviour.** `globalSaaSFeed.syncLoop` is reconfigured by `admin_settings.go:164` whenever the operator changes the SaaS feed URL — which calls `Configure(...)`, which calls `Stop()` on the previous goroutine and spawns a new one. So in practice the goroutine count stays at one at steady state. The gap is **shutdown**, not steady-state.

---

## 4. Mutation authority map

The mutation authority on each store is summarized below. **No race-detector-flagged surface was found** under the current synchronization (RWMutex on `catStore`, MVCC on BadgerDB).

### 4.1 Startup writers — "configuration phase, single-threaded"

- `catStore.Load + Set` (UT1 seeding) — single-threaded; no concurrent reader yet.
- `globalCategoryGroups.Load` — same.
- `globalSaaSFeed.Configure` — spawns goroutine, returns; the spawned goroutine is the only concurrent actor afterward.
- `openCommunityDB` — single-threaded; no concurrent reader yet.

### 4.2 Runtime writers — "operator + feed mutation, concurrent with hot path"

| Path | Writes | Live races against |
|---|---|---|
| `apiURLCat` POST/PUT/DELETE | `catStore.entries` / `.index` / `.path` under `cs.mu.Lock` | Hot-path `matchCategoryInStore` (RLock) and the cluster CP-capture read (`catStore.All` RLock) — both block on the write |
| `apiURLCatHost` POST/DELETE | Same fields under `cs.mu.Lock` | Same; RWMutex makes this safe |
| `globalSaaSFeed.Sync` merge | `catStore.AddHost` under `cs.mu.Lock` per call | Same |
| `controlplane.go DP applier` | `catStore.ReplaceAll` under `cs.mu.Lock` | Same. Atomic full-table swap inside the lock; readers see either the old slice or the new one, never a torn intermediate |
| `FeedSyncer.Sync` | BadgerDB `WriteBatch` (`catdb.go:105–116`) | Hot-path `communityDB.Lookup` (`View`) — BadgerDB's MVCC guarantees readers see a consistent snapshot |

### 4.3 Mutation authority matrix

| Mutator | `catStore.entries` | `catStore.path` | `globalCategoryGroups` | `communityDB` (BadgerDB) | `globalSaaSFeed` state | Synchronised? |
|---|---|---|---|---|---|---|
| Startup: `initURLCategories` | ✓ | ✓ | ✓ | ✓ (open) | ✓ (configure) | N/A (single-threaded) |
| Admin: `apiURLCat` / `apiURLCatHost` | ✓ | – | – | – | – | ✅ `cs.mu` |
| Admin: `apiCategoryGroups` | – | – | ✓ | – | – | Owned by `globalCategoryGroups.mu` |
| Admin: SaaS-feed reconfigure | – | – | – | – | ✓ | ✅ `s.mu` |
| Cluster DP: `catStore.ReplaceAll` | ✓ (full swap) | – | – | – | – | ✅ `cs.mu` (write lock for full rebuild) |
| Feed: `globalSaaSFeed.Sync` | ✓ (per host) | – | – | – | `lastSync`, `lastCount` (under `s.mu`) | ✅ |
| Feed: `FeedSyncer.Sync` | – | – | – | ✓ (BulkWrite) | – | ✅ BadgerDB MVCC |
| Hot path: per-request | reads under RLock | – | reads under RLock | reads via View | – | ✅ |

**All concurrent writer/reader pairs are synchronised** by one of: `catStore.mu` (RWMutex), `globalCategoryGroups.mu`, `globalSaaSFeed.mu`, or BadgerDB MVCC. No torn-read surface identified.

---

## 5. Persistence / reload interactions

### 5.1 Persistence

| Store | On-disk artifact | Atomicity | Fsync? |
|---|---|---|---|
| `catStore` (Layer 1) | `categories.json` (default; overridable via `Proxy.URLCategoriesFile`) | tmp + `os.Rename` (`policy.go:166–170`) | ❌ no fsync — see §10 finding #1 |
| `globalCategoryGroups` | `category_groups.json` under `/data` | matches `catStore` pattern (separate file) | matches |
| `globalSaaSFeed` state | **not persisted** (`lastSync`, `lastCount` are in-memory) | N/A | N/A |
| `communityDB` (Layer 2) | BadgerDB directory under `--cat-feed-db` | BadgerDB WAL + LSM | BadgerDB owns fsync |
| `FeedSyncer` state | **not persisted** (`lastSync`, `totalDomains` are atomic in-memory) | N/A | N/A |

**Layer 1 + categoryGroups are on the Tier-2 backup list** (`backup.go:74`). Restore-from-backup writes the files on disk; the next startup reads them via `Load(path)`. Layer 2 (BadgerDB directory) is **not** part of the backup contract — DP nodes rebuild their community DB from the feed.

### 5.2 SIGHUP / hot reload

`applyHotReload(fc)` (`main.go:2249–2258`) **does not touch** any of: `catStore`, `globalCategoryGroups`, `globalSaaSFeed`, `communityDB`, `FeedSyncer`. URL-categories cannot be hot-reloaded via SIGHUP; the operator must restart for `Proxy.URLCategoriesFile` path changes or use the admin API for content changes.

### 5.3 Config-version rollback (`configversion.go`)

The `apiURLCat` / `apiURLCatHost` handlers **do not call `saveConfigVersion(...)`** after their mutations (verified by grep: `ui_policy.go:476, 508, 529, 564, 581` only call `auditEvent`). Compare to `apiCategoryGroups` at `ui_policy.go:372, 392, 417` which **do** call `saveConfigVersion`. Asymmetric and consistent with the `CLAUDE.md` invariant that config-mutating API handlers should snapshot via `saveConfigVersion`. Pre-existing — see §10 finding #4.

A rollback v3→v2 therefore restores category-group state but **not** the catStore. Operator-visible quirk, not a corruption risk.

### 5.4 Cluster sync (`controlplane.go ConfigSnapshot`)

| Field | Carried by ConfigSnapshot | DP apply | CP capture |
|---|---|---|---|
| `catStore` entries | ✅ `URLCategories []CategoryEntry` (`controlplane.go:86`) | `catStore.ReplaceAll(snap.URLCategories)` (`:1502–1504`) — **no `Save()` after the swap** — see §10 finding #2 | `snap.URLCategories = catStore.All()` (`:1635–1636`) |
| `globalCategoryGroups` | ⚠ verify out of P6.1 scope | ⚠ | ⚠ |
| `globalSaaSFeed` state | ❌ not carried | – | – |
| `communityDB` contents | ❌ not carried | – | – |
| `FeedSyncer` state | ❌ not carried | – | – |

The cluster-apply `ReplaceAll` gap exactly mirrors the P3.1#3 / P3.2b pattern: in-memory state is updated, but a DP restart between the heartbeat and the next admin mutation loses the cluster-pushed state. Pre-existing — see §10 finding #2.

---

## 6. Hot-path concurrency risks

| Risk | Severity | Description |
|---|---|---|
| **C-1**: `catStore` write/read race | LOW (resolved) | `sync.RWMutex` protects all mutators; the hot-path read takes RLock. No race surface in the current code. |
| **C-2**: `communityDB` write/read race | LOW (resolved) | BadgerDB MVCC: `BulkWrite` uses `WriteBatch`; `Lookup` uses `View`. Readers see a consistent snapshot regardless of in-flight writes. |
| **C-3**: `FeedSyncer.Sync` HTTP cancellation | LOW (benign) | The download HTTP request is built with `context.Background()` (`feedsync.go:192`); cannot be cancelled by `appLifecycleCancel()`. Timeout (`feedSyncHTTPTimeout`) bounds the wait. Not a leak; an in-flight download blocks goroutine exit for ≤ timeout. |
| **C-4**: `globalSaaSFeed.syncLoop` shutdown leak | LOW (benign behaviour, asymmetric contract) | Goroutine runs under `context.Background()` (not `appLifecycleCtx`) and `Stop()` is never called from any shutdown hook. At process exit the goroutine is torn down by the runtime; the gap is a contract asymmetry vs. UT1 `FeedSyncer` — see §10 finding #3. |
| **C-5**: `catStore.ReplaceAll` cluster apply does not persist | LOW (durability, not a race) | DP nodes restart with stale `categories.json` until the next admin-API mutation or the next `controlplane` heartbeat. Mirrors the resolved P3.1#3 / P3.2b pattern. |
| **C-6**: `catStore.Save()` not fsynced | LOW (durability under power loss) | Atomic-via-rename; survives mid-write crash. A power-loss between rename and fsync of the parent directory could lose the rename on some filesystems. Mirrors the resolved P3.2a pattern. |
| **C-7**: `apiURLCat*` mutations not snapshotted | LOW (operator-visible quirk) | `saveConfigVersion` not called. Asymmetric vs. `apiCategoryGroups`. Pre-existing. See §10 finding #4. |

**C-1 and C-2 are the structural hot-path risks** — both are already resolved by the existing synchronization. **No P6.1 finding requires a P5.3-style ownership refactor.** The synchronization model is sound; the gaps are durability + lifecycle contract, not races.

---

## 7. Shutdown interactions

- **UT1 `FeedSyncer`** — parented to `appLifecycleCtx` at `main.go:804`. Cancelled via the `app-lifecycle-cancel` early-shutdown hook (order 40, `runtime_shutdown_wiring_test.go` pinned ordering). In-flight HTTP request (built with `context.Background()`) continues until timeout but the goroutine exits cleanly.
- **`globalSaaSFeed.syncLoop`** — NOT parented to `appLifecycleCtx`. `Stop()` never called from any shutdown hook. Goroutine continues running through the shutdown sequence; OS-level teardown collects it at process exit.
- **`communityDB`** — closed via the late-shutdown registry at `shutdownOrderCommunityDBClose=120` (`main.go:1342`, registered at `:1472–1479`). Ordered between `syslog-close=110` and `request-log-close=130`. **No upstream-style `CloseIdleConnections` analog needed** — BadgerDB owns its internal goroutines (compaction, value-log GC) and `Close()` waits for them.
- **`catStore` / `globalCategoryGroups` / `globalSaaSFeed`** — no shutdown hook. State is already on disk (or in `categories.json` / `category_groups.json` via synchronous save-on-write); no final-flush required.

**Ordering invariant:** `appLifecycleCancel` (early, order 40) precedes `community-db-close` (late, order 120). The UT1 `FeedSyncer` goroutine therefore exits BEFORE the BadgerDB handle closes. Verified by reading the shutdown wiring at `main.go:1373–1374` (early) and `main.go:1472–1479` (late). Pinned by `runtime_shutdown_wiring_test.go`'s canonical-order tests.

---

## 8. Cross-cut: existing test coverage

| File | Coverage |
|---|---|
| `catstore_test.go` (~233 LOC) | `TestCategoryStore_All`, `_Set_*`, `_Delete_*`, `_AddHost_*`, `_RemoveHost_*`, `_Load_*`, `_Save_NoPath`. **No race tests; no `ReplaceAll` test exercising the cluster-apply path.** |
| `catdb_feedsync_test.go` (~527 LOC) | `TestOpenCommunityDB_CreateAndClose`, `TestCommunityDB_BulkWrite_And_Lookup`, `TestCommunityDB_Lookup_DomainWalking`, `TestCommunityDB_Lookup_TrailingDot`, `TestCommunityDB_Lookup_StopsAtTLD`, `TestCommunityDB_Stats`, `TestCommunityDB_BulkWrite_Empty`, `TestClassifyTarEntry`, `TestParseDomainFile_*`, `TestParseTarball_*`, `TestNewFeedSyncer_*`, `TestFeedSyncer_Stats_Initial`, `TestDownloadAndParse_*`, `TestFeedSyncer_Sync_Integration` (mock HTTP server). **No race interleaving of `Sync` with hot-path `Lookup`.** |
| `saas_feed_test.go` | SaaS-feed parsing + merge tests. **No goroutine-cancellation test for `Stop()`.** |
| `security_feedsync_audit_test.go` (~114 LOC) | Audit-event coverage for feed-sync admin operations. |

**Gaps relevant to a future implementation phase (NOT P6.1 scope; flagged for posterity):**

1. No test interleaves `apiURLCat` POST/PUT/DELETE with concurrent `matchCategoryInStore` calls under `-race`. The RWMutex makes this clean by construction, but a contract test would prove it.
2. No test asserts `catStore.ReplaceAll(...)` persists when the cluster-apply caller is expected to save. (Direct mirror of the test that PR #225 added for `policyStore.ReplaceAll`.)
3. No test asserts `globalSaaSFeed.Stop()` is wired into any shutdown contract. (Direct mirror of the P1 detached-resource ownership tests.)

---

## 9. Verdict on Phase 6 strategy

### 9.1 P6.1 — discovery
This document. **Complete.** No production code; no roadmap expansion; no speculative redesigns.

### 9.2 Implications for Phase 6 sequencing

- The four P6 discoveries (P6.1 URL categories, P6.2 scanning, P6.3 Root CA, P6.4 cluster) remain **independent**. P6.1 does not gate any of the others.
- **None of the findings in this discovery warrant an in-program Phase 6 implementation PR.** The race surfaces are resolved by existing synchronization. The three pre-existing durability / lifecycle gaps (§10 #1–#3) and the config-version asymmetry (§10 #4) belong in the same "tracked-separately follow-up" bucket as P3.1#1, P3.2c, and U-1…U-6 — not a new program phase.
- **P3.4 cluster heartbeat flush remains gated on P6.4 cluster discovery**, NOT on P6.1. P6.1 does not contribute material to the cluster-runtime mutation graph beyond confirming `URLCategories` flows through `ConfigSnapshot` with a `ReplaceAll` (no-persist) apply.

### 9.3 What this discovery does NOT recommend

- No `upstreamTransport`-style ownership refactor. The synchronization model is sound; the surface that would change under such a refactor (e.g. swapping `catStore` for `atomic.Pointer[*CategoryStore]`) would yield negligible benefit because the read path is already RWMutex-bounded and the mutation rate is low.
- No move of `catStore` / `globalCategoryGroups` / `globalSaaSFeed` off package globals. Same reasoning — the ownership story is already coherent; moving onto `startupState` would be churn without payoff.
- No expansion of `ConfigSnapshot` to carry `globalCategoryGroups` or `globalSaaSFeed` state. That is a cluster-feature decision, not a runtime-ownership decision.

---

## 10. Findings worth filing as deferred follow-ups (NOT P6.1 scope)

These are uncovered during this discovery but are out of P6.1's scope. They are noted here so they aren't lost; they should be triaged separately and may belong elsewhere (mirrors of resolved P3 follow-ups, or new P1-class items).

| ID | Finding | Pre-existing? | Mirror |
|---|---|---|---|
| **UC-1** | `catStore.Save()` is atomic-via-rename but not fsynced (`policy.go:166–170`). Switching to `atomicWriteFile` would bring durability up to `fileBlocker` / `policyStore` (post-P3.2a) parity. Small, mechanical. | Yes | P3.1 follow-up #1 (PAC `Set`); P3.2a (`PolicyStore.Save`, PR #224) |
| **UC-2** | `catStore.ReplaceAll(...)` mutates memory only and does not persist (`policy.go:187–197`). DP nodes restarted between a CP heartbeat and the next admin mutation lose the cluster-pushed catStore. Fix is **caller-side** `catStore.Save()` after `ReplaceAll(...)` in `applyConfigSnapshot` at `controlplane.go:1503`, matching CategoryStore's caller-side `Save()` convention (mirrors P3.2b's PolicyStore fix). **Gated on UC-1** so we don't amplify a non-atomic write across the cluster apply path. | Yes | P3.1 follow-up #3 (`FileProfileStore.ReplaceAll`, PR #222); P3.2b (PR #225) |
| **UC-3** | `globalSaaSFeed.syncLoop` runs under `context.Background()` (`saas_feed.go:73`) and `Stop()` is never called from any shutdown hook. Detached goroutine; S4-class lifecycle gap. The fix shape is small (own a `saasFeedRunner` with `Start(ctx) / Stop()`, parent on `appLifecycleCtx`, plus a no-op late-shutdown hook for symmetry) but the missing-call-site list is the actual hazard — adding the hook without updating `admin_settings.go:164`'s reconfigure path would race the new and old goroutines briefly. | Yes | P1.2 (`sseBroadcaster`, PR #211); P1.3 (upstream health-check, PR #212) |
| **UC-4** | `apiURLCat` POST/PUT/DELETE and `apiURLCatHost` POST/DELETE call `auditEvent(...)` but do **not** call `saveConfigVersion(...)`. Compare to `apiCategoryGroups` at `ui_policy.go:372, 392, 417` which call both. Asymmetric vs. the `CLAUDE.md` invariant for config-mutating API handlers. Pre-existing; rollback v3→v2 leaves the catStore at its current state. | Yes | None — this is a new finding in the same family as the U-* observations in P5.1 §10 |
| **UC-5** | `controlplane.go` `applyConfigSnapshot` does not `auditEvent(...)` the application of cluster-pushed categories on a DP node. Operators looking at the audit ring on a DP cannot tell whether a category change came from a local admin or from CP. Cosmetic; consistent with how other cluster-applied fields are handled today. | Yes | None |
| **UC-6** | No metrics instrumentation for the URL-category subsystem (`metrics.go` has no `culvert_categories_*` counter family). `FeedSyncer.Stats()` and `SaaSFeedSyncer.Stats()` are exposed only via admin endpoints. Observability gap; operators cannot alert on "feed sync stuck". | Yes | None |
| **UC-7** | `FeedSyncer.downloadAndParse` builds its HTTP request with `context.Background()` (`feedsync.go:192`); cannot be cancelled by `appLifecycleCancel()`. Termination is bounded by `feedSyncHTTPTimeout`. Cosmetic — the goroutine still exits cleanly. | Yes | None |

**None of UC-1 through UC-7 are required for P6 to advance.** They are observability + lifecycle hygiene rather than blockers. Sequencing suggestions:

- **UC-1 first** (independent, mechanical) — mirrors PR #224 exactly.
- **UC-2 after UC-1** — gated on UC-1 for the same reason P3.2b waited on P3.2a.
- **UC-3** independent of UC-1/UC-2 — can ship at any time; small contract surface.
- **UC-4 / UC-5** independent observability fixes; one-line additions per handler.
- **UC-6** is its own minor metrics PR; not blocking.
- **UC-7** is the lowest priority; the timeout already bounds the worst case.

---

## 11. References

- `main.go:103–105, 190, 253–255, 741–807, 1342, 1373–1374, 1472–1479` — flags, startup wiring, shutdown wiring.
- `policy.go:58–65, 131, 156–197, 200–284, 910–986` — `catStore` declaration, persistence, mutators, hot-path lookup.
- `catdb.go:24–116` — `communityDB` declaration, `openCommunityDB`, `Close`, `Lookup`, `BulkWrite`.
- `feedsync.go:109–198` — `FeedSyncer` declaration, `Start(ctx)`, `Sync`, `downloadAndParse`.
- `saas_feed.go:30–155` — `globalSaaSFeed` declaration, `Configure`, `Stop`, `syncLoop`, `Sync`.
- `ui_policy.go:372–617` — `apiCategoryGroups` (with `saveConfigVersion`), `apiURLCat`, `apiURLCatHost`, `apiURLCatLookup`.
- `controlplane.go:86, 142, 171, 1502–1504, 1635–1636` — `ConfigSnapshot.URLCategories`, cap, DP apply, CP capture.
- `backup.go:74` — Tier-2 backup inclusion of `categories.json`.
- `catstore_test.go`, `catdb_feedsync_test.go`, `saas_feed_test.go`, `security_feedsync_audit_test.go` — existing tests.
- `roadmap/RUNTIME-OWNERSHIP.md` §15 SPOF inventory; §3 Phase shape; §4 P6.1 entry; §5 "Recommended next PR".
- `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` — P5.1, template for this discovery doc.
