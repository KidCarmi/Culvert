# P6.2 — Scanning Runtime Ownership Discovery

**Status:** Discovery only. No production code change, no tests.
**Scope:** `initScanning`, the unified `SecurityScanner`, ClamAV INSTREAM client, the pure-Go YARA engine, DPI / `ContentScanner`, `HashCache`, `ThreatFeed` (URLhaus + OpenPhish), `RemoteScanner` sidecar client, the sidecar-side `ScanService` HTTP server, and the admin-API surface that mutates any of them.
**SPOF target:** none on the existing `RUNTIME-OWNERSHIP.md` SPOF list (Phase 6 is discovery-only by design — §6 of the program doc); the relevant SPOF axes are the **detached goroutine** family (S4-class) and the **god-object init** family (S1-class).

---

## 0. Executive verdict

`initScanning` is a six-component init site (`globalRemoteScanner` + `globalThreatFeed` + `globalSecScanner` (ClamAV + cache) + `globalYARA` + `globalScanExclusions` + optional `ScanService` sidecar) with one **correctly-parented** background goroutine (`globalThreatFeed.Start(appLifecycleCtx)`), one **owned** server goroutine (`ScanService.Start()`, registered as the `scan-svc-shutdown` late hook at `shutdownOrderScanSvcShutdown=60`), and a family of **per-scan ephemeral goroutines** (YARA / DPI regex timeout + ClamAV per-scan dial) that are bounded by their own timeout/semaphore primitives. **No active concurrent-corruption surface was found** — every store with mutable runtime state guards its hot path with `sync.RWMutex` or atomic primitives. **However, four classes of pre-existing gaps exist and are tracked separately** in §10: a wide config-versioning gap on the scanner admin API, a Prometheus instrumentation gap on hashcache hit/miss counters, complete absence of `applyHotReload` coupling, and the absence of `ScanService` / `RemoteScanner` from cluster `ConfigSnapshot`.

The most consequential finding, **SC-1** (**RESOLVED — PRs #272–#274; see §10 SC-1 for the final per-store table**), was that **only `apiContentScan` (DPI pattern add/remove) calls `saveConfigVersion`** — every other scanner-config admin handler emits `auditEvent` but not `saveConfigVersion`. The original framing split the handlers into "persistent-config mutations" (reasonable rollback-tier candidates) and "operational/transient actions" (not). The resolution refined this: a per-store triage (`roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md`) found the persistent-config group itself heterogeneous in risk class — DPI bypass hosts were extended into the rollback surface (PR #273), while YARA settings + scan exclusions are documented out-of-surface as D-sec and YARA rule files as D-ops (PR #274), because silently rolling those back would relax a security posture or fight the external-VCS workflow. This is structurally similar to the catStore-vs-categoryGroups asymmetry called out in P6.1 §10 UC-4, just wider in scope.

What is **NOT** uncovered by this discovery:

- No undocumented persistence path beyond the existing files (`yara/*.yar`/`.yara`, `scan_exclusions.json`, content-scan JSON, threat-feed DB).
- No hot-path race surface on the existing locks (`SecurityScanner.mu`, `YARARuleSet.mu`, `ContentScanner.mu`, `HashCache.mu`, `ThreatFeed.mu`, `RemoteScanner.mu`).
- No undocumented goroutine spawn site missing cancellation — every long-lived goroutine is either parented to `appLifecycleCtx` (threat feed) or owned by a shutdown hook (`ScanService`); short-lived per-scan goroutines exit on their own timeout channel.
- No SIGHUP integration on the scanner subsystem.
- No `applyHotReload` coupling on scanner state — operator must use the admin API or restart for any scanner-config change.

---

## 1. Component inventory

### 1.1 `initScanning(s *startupState)` — the startup site

Declared at `main.go:839–937`. Called at `main.go:194` between `initPolicy(s)` (step 26) and `initUpstreamProxy(s)` (step 28). The function performs six independent sub-inits, gated on operator config:

| Sub-init | Lines | Side effect |
|---|---|---|
| Remote scanner | `main.go:850` | `globalRemoteScanner.Init(remoteScanURL)` when `-scan-svc-url` is set |
| Threat feed | `main.go:860–861, 918–919` | `globalThreatFeed.Init(feedDB, syncInterval)` + `globalThreatFeed.Start(appLifecycleCtx)`; runs in either remote mode or local mode |
| Hash cache | `main.go:889` | `globalSecScanner.cache = newHashCache(maxEntries, ttl)` |
| ClamAV init | `main.go:890` | `globalSecScanner.Init(clamAddr, maxScanBytes)` — `NewClamAV(addr)` + one Ping; failure logged, non-fatal |
| YARA rules | `main.go:898–905` | `seedYARARules(yaraDir)` (copy `/app/yara` defaults if dir is empty) + `globalYARA.LoadDir(yaraDir)` |
| Scan exclusions | `main.go:911` | `globalScanExclusions.Load(scanExclPath)` |
| Sidecar `ScanService` | `main.go:925–935` | `NewScanService(svcListenAddr).Listen()` + `go s.scanSvc.Start()` when `-scan-svc-listen` is set |

CLI flags read (`main.go:229, 254, 257, 260, 261, 245, 247, 248, 249`):

| Flag | FileConfig fallback | Default |
|---|---|---|
| `-clamav-addr` | `secCfg.ClamAVAddr` | `""` (treated as `/var/run/clamav/clamd.sock` by `NewClamAV`) |
| `-yara-rules-dir` | `secCfg.YARARulesDir` | `""` (disables YARA) |
| `-threat-feed-db` | `secCfg.ThreatFeedDB` | `""` (disables persistent feed cache) |
| `-scan-svc-url` | `secCfg.ScanSvcURL` | `""` (local-mode scanning) |
| `-scan-svc-listen` | `secCfg.ScanSvcListen` | `""` (no sidecar listener) |
| (config-only) | `secCfg.Enabled`, `secCfg.SyncInterval`, `secCfg.CacheTTL`, `secCfg.CacheSize`, `secCfg.MaxScanMB` | per-field defaults at `main.go:854–886` |

Startup-state carry: only `s.scanSvc *ScanService` (`main.go:160`). All other scanner state lives on package globals.

### 1.2 `globalSecScanner` — unified `SecurityScanner`

Declared at `security_scan.go` (package global). Struct fields (`security_scan.go:80–91`):

- `mu sync.RWMutex` — guards `clam`, `clamStatusVal`, `clamStatusExpiry`, `enabled`.
- `clam *ClamAV` — set once via `Init`; never re-assigned at runtime.
- `cache *HashCache` — see §1.6.
- `maxBytes int64` — body-scan size cap.
- `enabled bool` — true after `Init`.
- `clamStatusVal string` / `clamStatusExpiry time.Time` — 30s-TTL ping cache exposed by `ClamAVStatus()` (`security_scan.go:315–342`).

Hot-path readers: `Enabled`, `BodyScanEnabled`, `MaxBytes`, `ClamAVStatus`, `CheckURL`, `CheckDomain`, `ScanBody` — all RLock-bounded except `ScanBody` which reads `clam` once under RLock and runs the actual scan outside the lock (intentional — see §6 risk SC-R-3).

### 1.3 `globalYARA` — `YARARuleSet`

Declared at `yara_scan.go:69`. Struct (`yara_scan.go:61–66`):

- `mu sync.RWMutex` — guards `rules`, `dir`, `warnings`.
- `rules []yaraCompiledRule` — pre-compiled rules; full slice replaced atomically under write lock by `LoadDir`.
- `dir string` — source directory path.
- `warnings []string` — parse/load warnings from the most recent `LoadDir`; surfaced via `apiSecYARARules` GET for admin visibility.

Runtime-tunable engine knobs (`yara_scan.go:432–436`), backed by `atomic.Bool` / `atomic.Int64`:

- `yaraEngineEnabledVar` (default true)
- `yaraMaxInflightVar` (default 50)
- `yaraTimeoutSecsVar` (default 5s)
- `yaraOnTimeoutVar` (`"fail_closed"` default, or `"fail_open_with_alert"`)
- `yaraOnSaturationVar` (same options)

### 1.4 `globalClam` (per-scan client) — `*ClamAV`

Created by `NewClamAV(addr)` (`clam.go:42–62`); stored on `globalSecScanner.clam`. Struct (`clam.go:28–32`):

- `network string` — `"unix"` or `"tcp"`.
- `addr string` — socket path or `host:port`.
- `timeout time.Duration` — 30s hardcoded (`clam.go:47`).

Connection model: **per-scan fresh dial** (`clam.go:101`), no pool. Concurrency cap: package-level `clamSem` (`clam.go:39`) — buffered channel of 4 with 5s acquire timeout (`clam.go:94–98`); on saturation returns the error `"scan queue full"`. No TLS, no auth — raw CLAMD INSTREAM only.

### 1.5 `dpiScanner` — `ContentScanner`

Declared at `scanner.go:57`. Struct (`scanner.go:35–47`):

- `mu sync.RWMutex`.
- `raw []string` — pattern source strings (for listing / persistence).
- `compiled []*regexp.Regexp` — pre-compiled regexes; atomically replaced by `Set` after every pattern in the new list compiles successfully.
- `path string` — optional JSON file path.
- `maxBytes int64` — per-response buffer cap (default 1 MiB).
- `bypassHosts map[string]bool` — per-host DPI bypass list (Tier 3.4); lowercase keys.

Load/Save: `Load(path)` (`scanner.go:87–`) reads the legacy array OR envelope (with bypass hosts); `Save()` (`scanner.go:130–150`) writes via tmp + rename.

### 1.6 `HashCache`

Type declared at `hashcache.go:39–46`:

- `mu sync.RWMutex`.
- `entries map[string]*hashCacheEntry` — SHA-256 hex → `ScanCacheResult`.
- `maxSize int` (default 10_000).
- `ttl time.Duration` (default 1h).
- `hits, misses atomic.Int64` — counters; exposed via `Stats()` (`hashcache.go:101–106`) but **not rendered to Prometheus** — see §10 SC-2.

Eviction policy (`hashcache.go:131–149`): on overflow, evict expired entries first; if still full, drop ~25% of remaining entries. **No background sweeper goroutine.** **Memory-only**, not persisted across restarts.

### 1.7 `globalThreatFeed`

Declared at `threatfeed.go:63–64`. Struct (`threatfeed.go:40–62`):

- `mu sync.RWMutex`.
- `enabled bool`.
- `urls map[string]feedEntry` / `domains map[string]feedEntry`.
- `allowlistedDomains map[string]bool` — Tier 3.1 exemption list (popular hosting platforms).
- `lastSync time.Time`, `syncInterval time.Duration` (default 6h).
- `totalEntries atomic.Int64` — metrics-side cache.

Feeds: URLhaus + OpenPhish (hardcoded URLs in `threatfeed.go`). Persistent JSON DB at `secCfg.ThreatFeedDB`.

### 1.8 `globalRemoteScanner`

Declared at `scan_remote.go:34`. Struct (`scan_remote.go:26–31`):

- `mu sync.RWMutex`.
- `baseURL string`.
- `client *http.Client` — created in `Init` with 60s scan-call timeout and a transport pool (32 idle / 16 per-host / 90s idle timeout).
- `enabled bool`.

Endpoints consumed: `POST /scan`, `GET /health`, `GET /status`. **Fail-open** on network or HTTP error (`scan_remote.go:81–141`); fires `scan_svc_down` alert via `remoteScanFailAlert`.

### 1.9 `s.scanSvc` — `*ScanService` (sidecar HTTP server)

The mirror of `RemoteScanner`. Created when `-scan-svc-listen` is set, owned by `startupState`, started via `go s.scanSvc.Start()` (`main.go:931`), and stopped via the `scan-svc-shutdown` late hook (`main.go:1426–1431`).

### 1.10 `globalScanExclusions`

Per-host / per-hash allowlists consulted by `ScanBody` before any expensive scanner runs (`security_scan.go` — Tier 3.3). Persisted at `scan_exclusions.json`.

---

## 2. Ownership graph (writers + readers)

### 2.1 Writers — startup phase (single-threaded, pre-listener-accept)

| Writer | Touches | Location |
|---|---|---|
| `globalRemoteScanner.Init(url)` | `.baseURL`, `.client`, `.enabled` under `mu.Lock` | `main.go:850` |
| `globalThreatFeed.Init(path, interval)` + `.Start(appLifecycleCtx)` | feed maps, syncer goroutine | `main.go:860–861, 918–919` |
| `globalSecScanner.cache = newHashCache(...)` | replaces hashcache | `main.go:889` |
| `globalSecScanner.Init(clamAddr, max)` | `.clam`, `.maxBytes`, `.enabled` under `mu.Lock` | `main.go:890` |
| `seedYARARules(yaraDir)` + `globalYARA.LoadDir(yaraDir)` | `.rules`, `.dir`, `.warnings` under `mu.Lock` | `main.go:898–905` |
| `globalScanExclusions.Load(path)` | hash/host maps | `main.go:911` |
| `NewScanService(addr).Listen()` + `go .Start()` | listener + goroutine | `main.go:925–935` |

Order dependency: cache must be created before `globalSecScanner.Init` reads it (current ordering at `main.go:889–890` is correct). Threat-feed start is intentionally late (`main.go:918`) so the goroutine is spawned only after the rest of the scanner state is consistent.

### 2.2 Writers — runtime phase (post-listener-accept; concurrent with hot path)

| Writer | Touches | Trigger | Synchronisation |
|---|---|---|---|
| `apiContentScan` POST add/remove | `dpiScanner.Set(...)` then `.Save()` | Admin API (`ui_security.go:298`) | `ContentScanner.mu.Lock`; **calls `saveConfigVersion` at `:339, :355`** |
| `apiContentScanBypass` PUT | `dpiScanner.SetBypassHosts(...)` | Admin API (`ui_security.go:882`) | `ContentScanner.mu.Lock`; `auditEvent` at `:902`; **no `saveConfigVersion`** |
| `apiSecFeedsSync` POST | `globalThreatFeed.Sync()` | Admin API (`ui_security.go:511`) | `ThreatFeed.mu.Lock`; `auditEvent` at `:527`; **no `saveConfigVersion`** |
| `apiDomainAllowlist` PUT | `globalThreatFeed.SetDomainAllowlist(...)` | Admin API (`ui_security.go:534`) | `ThreatFeed.mu.Lock`; **no `saveConfigVersion`** |
| `apiSecYARAReload` POST | `globalYARA.LoadDir(...)` + `globalSecScanner.cache.Clear()` | Admin API (`ui_security.go:566`) | atomic rule swap; `auditEvent` at `:590`; **no `saveConfigVersion`** |
| `apiSecYARARules` POST/PUT | `globalYARA.WriteRule(name, src)` (writes file then `LoadDir`) | Admin API (`ui_security.go:691, :753`) | atomic rule swap; `auditEvent` at `:753`; **no `saveConfigVersion`** |
| `apiSecYARARules` DELETE | `globalYARA.DeleteRule(name)` (deletes file then `LoadDir`) | Admin API (`ui_security.go:691, :778`) | atomic rule swap; `auditEvent` at `:778`; **no `saveConfigVersion`** |
| `apiSecYARASettings` PUT | atomic store on `yaraEngineEnabledVar` / `MaxInflight` / `TimeoutSecs` / `OnTimeout` / `OnSaturation` | Admin API (`ui_security.go:640`) | atomics only; `auditEventDiff` at `:675`; **no `saveConfigVersion`** |
| `apiSecScanExclusions` PUT | `globalScanExclusions.Replace(...)` | Admin API (`ui_security.go:838`) | exclusions `mu.Lock`; `auditEvent` at `:865`; **no `saveConfigVersion`** |
| `apiScanCache` DELETE | `globalSecScanner.cache.Clear()` or `.Evict(hash)` | Admin API (`ui_security.go:935`) | hashcache `mu.Lock`; `auditEvent` at `:964, :968`; legitimately no `saveConfigVersion` (transient state) |
| `controlplane.go applyConfigSnapshot` (DP side) | `dpiScanner.Set(snap.DPIPatterns)`, `globalThreatFeed.ImportFeedData(...)`, `globalThreatFeed.SetDomainAllowlist(...)` | CP→DP poll | RWMutex on each store; **no `Save()` on `dpiScanner` after the snapshot swap** — see §10 SC-3 |

**SaveConfigVersion summary**: of the 10 scanner-config mutating handlers, **only `apiContentScan` add/remove call `saveConfigVersion`**. Eight handlers emit `auditEvent`/`auditEventDiff` but do not snapshot. `apiScanCache` legitimately skips `saveConfigVersion` because the cache is transient. The eight non-DPI gaps are **structurally identical** to the P6.1 UC-4 asymmetry, just much wider in scope. See §10 SC-1.

### 2.3 Readers — proxy hot path (concurrent, every request)

| Reader | Reads | Location |
|---|---|---|
| `safeScanBodyWithCT(...)` (plain HTTP response) | `globalSecScanner.{Enabled, BodyScanEnabled, MaxBytes, ScanBody}` and `dpiScanner` for text bodies | `proxy.go:723–782` |
| SSL-inspected response scan | `globalRemoteScanner.Enabled()` → either `globalRemoteScanner.ScanBody(...)` or local `ScanBody` + `safeDPIScan` | `proxy.go:1441–1474` |
| Pre-request URL/domain check | `globalThreatFeed.CheckURL(...)`, `.CheckDomain(...)` (RLock-only) | `proxy.go:343–362` |
| DPI bypass check | `dpiScanner.IsBypassHost(host)` (RLock-only) | `scanner.go:188` |
| YARA `Match` (called by `ScanBody`) | `globalYARA.rules` snapshot under RLock | `yara_scan.go` |

### 2.4 Readers — admin UI / API (low-rate)

| Reader | Reads | Location |
|---|---|---|
| `apiSecScanStatus` GET | scanner + feed + cache stats | `ui_security.go:498` |
| `apiSecYARARules` GET | `globalYARA.Files()`, `.FileRules()`, `.Warnings()` | `ui_security.go:691` |
| `apiSecYARASettings` GET | `yaraSettingsMap()` (atomic loads) | `ui_security.go:640` |
| `apiSecScanExclusions` GET | exclusion lists | `ui_security.go:844` |
| `apiDomainAllowlist` GET | threat-feed allowlist | `ui_security.go:534` |
| `apiScanSvcConfig` GET | remote scan client config | `ui_security.go:910` |
| `apiScanCache` GET | hashcache stats | `ui_security.go:935` |
| `apiContentScan` GET | DPI pattern list | `ui_security.go:298` |
| `apiContentScanBypass` GET | DPI bypass list | `ui_security.go:888` |
| `metricsHandler` Prometheus output | `statClamBlocked`, `statYARABlocked`, `statThreatFeedBlocked`, `statDPIBlocked`, `globalThreatFeed.Stats()`, `globalSecScanner.cache.Stats()` (size only) | `metrics.go:258–334` |

### 2.5 Cross-cluster sync

`ConfigSnapshot` carries the **DPI patterns** + **threat-feed URLs/domains** + **threat-feed domain allowlist**. It does **NOT** carry:

- YARA rules.
- ClamAV address / config.
- HashCache contents.
- Scan exclusions.
- DPI bypass-host list.
- Remote scanner config (`-scan-svc-url`).
- ScanService listener address (`-scan-svc-listen`).

DP applier (`controlplane.go:1517–1562`):

- `dpiScanner.Set(snap.DPIPatterns)` — replaces patterns atomically. **No `dpiScanner.Save()` after the swap** — DP nodes lose cluster-pushed DPI patterns on restart until next heartbeat. Same UC-2 pattern as P6.1. See §10 SC-3.
- `globalThreatFeed.ImportFeedData(snap.ThreatFeedURLs, snap.ThreatFeedDomains)` — atomic map swap.
- `globalThreatFeed.SetDomainAllowlist(snap.ThreatDomainAllowlist)` — atomic list swap.

CP snapshotter (`controlplane.go:1644–1658`): mirror reads — `dpiScanner.List()`, `globalThreatFeed.ExportURLs()`, `globalThreatFeed.ExportDomains()`, `globalThreatFeed.DomainAllowlist()`.

Caps: `maxSnapThreatFeedURLs = 500_000`, `maxSnapThreatFeedDomains = 500_000` (`controlplane.go:149–150`). **No explicit cap on `DPIPatterns`** — the `Set` validator (every pattern must compile as a regex) bounds maliciously-large payloads, but no per-snapshot count limit.

---

## 3. Goroutine ownership / lifecycle

Scanning spawns goroutines in three distinct families. The lifecycle contract differs sharply across them.

### 3.1 Long-lived owned goroutines

| Goroutine | Spawn site | Parent ctx | Cancel mechanism | Health |
|---|---|---|---|---|
| `globalThreatFeed.Start(appLifecycleCtx)` — sync ticker | `threatfeed.go:111` | `appLifecycleCtx` | `appLifecycleCancel()` via `app-lifecycle-cancel` early hook (order 40) | ✅ Cancellable. Select on `<-ctx.Done()` at `threatfeed.go:119`. |
| `go s.scanSvc.Start()` — sidecar HTTP server | `main.go:931` | own listener | `scanSvc.Shutdown(ctx)` via late hook `scan-svc-shutdown` (order 60, `main.go:1426–1431`) | ✅ Cancellable. `(*http.Server).Shutdown` drains in-flight on the 30s late-phase ctx. |

### 3.2 Short-lived per-scan timeout goroutines

These run for the duration of a single regex or scan call and exit either when the operation completes or when their dedicated `time.After` channel fires. They are bounded by their own timeouts; they are not owned by any context and do not need shutdown hooks.

| Goroutine | Spawn site | Bound by |
|---|---|---|
| Body-scan timeout wrapper (runs `scanBodyInner`) | `security_scan.go:475` | 10s `scanBodyTimeout` (declared at `security_scan.go:55`) |
| DPI regex timeout (one per pattern match) | `scanner.go:259` (`matchDPIRegexWithTimeout`) | Per-call timeout |
| YARA regex timeout (one per pattern match) | `yara_scan.go:545` (`matchRegexWithTimeout`) | `yaraGetTimeoutSecs()` (default 5s) + `yaraMaxInflightVar` saturation cap (default 50) |
| ClamAV per-scan dial | `clam.go:101` | 30s hardcoded; gated by `clamSem` 4-slot semaphore at `clam.go:94–98` |

### 3.3 Detached ephemeral alert goroutines

| Goroutine | Spawn site | Notes |
|---|---|---|
| `go remoteScanFailAlert(...)` | `scan_remote.go:72` | Increments `statRemoteScanFail`, fires one webhook via `fireAlert`. Exits after the alert. Bounded by `fireAlert`'s own HTTP timeout. |

**No leaked-goroutine surface identified.** Every long-lived goroutine is either parented to `appLifecycleCtx` or owned by a shutdown hook; every short-lived goroutine is bounded by an explicit timeout. The pattern is sound — sharply better than the P6.1 UC-3 SaaS-feed gap (`globalSaaSFeed.syncLoop` under `context.Background()`).

---

## 4. Mutation authority map

The scanner subsystem has more independent mutators than any prior P6 discovery target. **No race-detector-flagged surface was found** under the existing synchronization.

### 4.1 Startup writers — "configuration phase, single-threaded"

All six sub-inits in §1.1 are sequential. No concurrent reader yet because the proxy listener hasn't started accepting.

### 4.2 Runtime writers — "operator + feed mutation, concurrent with hot path"

| Path | Writes | Live races against |
|---|---|---|
| `apiContentScan` add/remove | `dpiScanner.{raw,compiled}` under `mu.Lock` | Hot-path `safeDPIScan` / `IsBypassHost` (RLock) — RWMutex makes safe |
| `apiContentScanBypass` PUT | `dpiScanner.bypassHosts` under `mu.Lock` | Same |
| `apiSecFeedsSync` POST | `globalThreatFeed.{urls,domains,lastSync}` under `mu.Lock` | Hot-path `CheckURL` / `CheckDomain` (RLock) — safe |
| `apiDomainAllowlist` PUT | `globalThreatFeed.allowlistedDomains` under `mu.Lock` | Same |
| `apiSecYARAReload` POST | `globalYARA.{rules,dir,warnings}` full-slice swap under `mu.Lock` + `globalSecScanner.cache.Clear()` | Hot-path `globalYARA.Match` (RLock) — safe (in-flight Match completes against snapshotted slice) |
| `apiSecYARARules` POST/PUT/DELETE | YARA rule file on disk + `globalYARA.LoadDir(dir)` | Same — file write is tmp+rename atomic; in-memory swap is RWMutex-bounded |
| `apiSecYARASettings` PUT | atomic stores on engine knobs | Hot-path atomic loads — race-free by atomic primitives |
| `apiSecScanExclusions` PUT | exclusions maps under `mu.Lock` | Hot-path `IsHashExcluded` / `IsHostExcluded` (RLock) — safe |
| `apiScanCache` evict/clear | `HashCache.entries` under `mu.Lock` | Hot-path `Get`/`Set` — safe |
| `applyConfigSnapshot` (DP side) | `dpiScanner.Set(...)`, `globalThreatFeed.{ImportFeedData,SetDomainAllowlist}` | Same as the matching admin paths — atomic full-replace under write lock |

### 4.3 Mutation authority matrix

| Mutator | `dpiScanner` | `globalYARA` | `globalThreatFeed` | `HashCache` | `globalScanExclusions` | `globalSecScanner.{clam,enabled,maxBytes}` | Synchronised? |
|---|---|---|---|---|---|---|---|
| Startup: `initScanning` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | N/A (single-threaded) |
| Admin: `apiContentScan(Bypass)?` | ✓ | – | – | – | – | – | ✅ `mu.Lock` |
| Admin: `apiSec(FeedsSync\|DomainAllowlist)` | – | – | ✓ | – | – | – | ✅ `mu.Lock` |
| Admin: `apiSecYARA(Reload\|Rules\|Settings)` | – | ✓ | – | ✓ (Clear) | – | – | ✅ RWMutex / atomics |
| Admin: `apiSecScanExclusions` | – | – | – | – | ✓ | – | ✅ `mu.Lock` |
| Admin: `apiScanCache` | – | – | – | ✓ | – | – | ✅ `mu.Lock` |
| Cluster DP: `applyConfigSnapshot` | ✓ (Set, no Save) | – | ✓ (ImportFeedData + allowlist) | – | – | – | ✅ on each store |
| Feed: `globalThreatFeed.Sync` | – | – | ✓ | – | – | – | ✅ `mu.Lock` |
| Hot path: per-request | RLock | RLock | RLock | RLock/Lock | RLock | RLock | ✅ |

**All concurrent writer/reader pairs are synchronised** by one of: per-store `sync.RWMutex`, `atomic.Bool/Int64` for the YARA engine knobs, or BadgerDB MVCC (threat-feed DB I/O happens under `mu.Lock` in `Sync`). The lone fragile-looking surface is the `globalSecScanner.clam` reference read at `security_scan.go:492` under RLock followed by a network call outside the lock — this is intentional (you don't want to hold a mutex across a 30s ClamAV dial) and is safe today because `clam` is set once at startup and never re-assigned. See §6 risk SC-R-3.

---

## 5. Persistence / reload interactions

### 5.1 Persistence

| Store | On-disk artifact | Atomicity | Fsync? |
|---|---|---|---|
| `dpiScanner` | optional JSON at `dpiScanner.path` | tmp + `os.Rename` (`scanner.go:130–150`) | ❌ no fsync — matches P6.1 UC-1 pattern; see §10 SC-4 |
| `globalYARA` rule files | individual `.yar` / `.yara` files under `yaraDir` | per-file tmp + rename by `WriteRule` | ❌ no fsync |
| `globalScanExclusions` | `scan_exclusions.json` | `os.WriteFile` → tmp + `os.Rename` (`security_scan.go:159–185`) | ❌ no fsync |
| `globalThreatFeed` | JSON DB at `secCfg.ThreatFeedDB` | `os.WriteFile` → tmp + `os.Rename` (`threatfeed.go:416–440`, `saveToDisk`) | ❌ no fsync |
| `HashCache` | **not persisted** | N/A | N/A |
| `globalSecScanner` runtime fields | **not persisted** | N/A | N/A |
| `globalRemoteScanner` runtime fields | **not persisted** | N/A | N/A |
| YARA engine knobs (`yaraEngineEnabledVar` etc.) | **not persisted** to disk; held in `atomic.*` only | – | – |

Backup tier (`backup.go:81`): `scan_exclusions.json` is in the Tier-2 backup list. YARA rule files, threat-feed DB, and DPI pattern JSON are **not** in the standard backup contract — operators must restore them manually before restart. See §10 SC-7.

### 5.2 SIGHUP / hot reload

**`applyHotReload(fc)` (`main.go:2205–2260`) does not touch any scanner state.** Verified against the branch list in the function: blocklist, policy rules, default action, rate limit, IP filter mode, rewrite rules, upstream proxy pool. No YARA reload, no ClamAV reconnect, no threat-feed resync, no DPI pattern reload, no hashcache flush, no exclusions reload, no remote-scanner reinit.

**Implication:** scanner-config changes via the config YAML (ClamAV address, threat-feed DB path, YARA directory, scan size cap) require a process restart. Mutation via the admin API is the only runtime path. **Whether this is intentional design or simply unimplemented is not assessed by this discovery** — see §10 SC-5 for the observed-behaviour-only treatment.

### 5.3 Config-version rollback (`configversion.go`)

`apiContentScan` add/remove call `saveConfigVersion(sessionAdmin(r), "content_scan.add"|".remove")` at `ui_security.go:339, :355`. **Every other scanner-config admin handler does NOT call `saveConfigVersion`**, verified by `grep "saveConfigVersion" ui_security.go` returning only five hits (security, content_scan add/remove, fileblock add/remove).

Affected non-snapshotted mutations:

- `apiSecFeedsSync` (force threat-feed resync) — `ui_security.go:511`
- `apiSecYARAReload` — `ui_security.go:566`
- `apiSecYARARules` POST/PUT/DELETE — `ui_security.go:691, :725, :746, :761, :773`
- `apiSecYARASettings` PUT — `ui_security.go:640`
- `apiSecScanExclusions` PUT — `ui_security.go:838`
- `apiContentScanBypass` PUT — `ui_security.go:882`
- `apiDomainAllowlist` PUT — `ui_security.go:534`

A rollback v3→v2 therefore restores DPI patterns but leaves every YARA rule, every YARA setting change, every scan-exclusion update, every DPI bypass change, and every threat-feed allowlist change in place. **Audit trail is preserved** — every handler emits `auditEvent`/`auditEventDiff` — but the rollback tier is silent. See §10 SC-1.

### 5.4 Cluster sync (`controlplane.go ConfigSnapshot`)

| Field | Carried by ConfigSnapshot | DP apply | CP capture |
|---|---|---|---|
| DPI patterns | ✅ `DPIPatterns []string` | `dpiScanner.Set(snap.DPIPatterns)` (`controlplane.go:1518`) — **no `Save()` after** | `snap.DPIPatterns = dpiScanner.List()` (`:1644`) |
| Threat-feed URLs | ✅ `ThreatFeedURLs map[string]int64`; cap 500_000 | `globalThreatFeed.ImportFeedData(snap.ThreatFeedURLs, snap.ThreatFeedDomains)` (`:1557`) | `snap.ThreatFeedURLs = globalThreatFeed.ExportURLs()` (`:1656`) |
| Threat-feed domains | ✅ same | same | `snap.ThreatFeedDomains = globalThreatFeed.ExportDomains()` (`:1657`) |
| Threat-feed allowlist | ✅ `ThreatDomainAllowlist []string` | `globalThreatFeed.SetDomainAllowlist(snap.ThreatDomainAllowlist)` (`:1562`) | `snap.ThreatDomainAllowlist = globalThreatFeed.DomainAllowlist()` (`:1658`) |
| YARA rules / settings | ❌ not carried | – | – |
| ClamAV address | ❌ not carried | – | – |
| HashCache | ❌ not carried | – | – |
| Scan exclusions | ❌ not carried | – | – |
| DPI bypass list | ❌ not carried | – | – |
| `RemoteScanner` config | ❌ not carried | – | – |
| `ScanService` listener config | ❌ not carried | – | – |

The DPI cluster-apply gap (no `Save()` after `Set`) is structurally identical to the P6.1 UC-2 pattern (`catStore.ReplaceAll` / `globalCategoryGroups.ReplaceAll` without `Save()`). See §10 SC-3.

---

## 6. Hot-path concurrency risks

| Risk | Severity | Description |
|---|---|---|
| **SC-R-1**: `dpiScanner` / `globalYARA` / `globalThreatFeed` write/read race | LOW (resolved) | Per-store `sync.RWMutex`; mutators take write lock for an atomic full-slice or full-map replacement; readers take RLock. No race surface in the current code. |
| **SC-R-2**: `HashCache` Get/Set race | LOW (resolved) | `sync.RWMutex`. `hits`/`misses` are `atomic.Int64`. Eviction is on-demand inside `Set` under the write lock — no torn-read surface. |
| **SC-R-3**: `globalSecScanner.clam` read under RLock, scan runs outside lock | LOW (intentional + safe today) | `ScanBody` reads the `clam` pointer under RLock then releases the lock before running the actual ClamAV dial+scan. Safe because `clam` is assigned once at `Init` and never re-assigned. **Fragile to future hot-reload** that wants to swap the ClamAV address at runtime — that future PR would need to either build a fresh `*ClamAV` and swap-then-release (analogous to P5.3 `swapUpstreamTransport`), or hold the RLock for the duration of the scan (would block writers indefinitely under load — not viable). See §10 SC-6. |
| **SC-R-4**: YARA per-pattern regex goroutines exceed inflight cap | LOW (resolved) | `yaraMaxInflightVar` (default 50) gates new regex goroutines; saturation triggers fail-closed or fail-open-with-alert per `yaraOnSaturationVar`. Tested by `TestYARA_SaturationFailsClosed` (`yara_test.go`). |
| **SC-R-5**: ClamAV semaphore saturation | LOW (resolved) | `clamSem` (size 4) blocks new scans with a 5s acquire timeout; on timeout the scan errors out and is logged. Fail-open by design. |
| **SC-R-6**: per-scan timeout goroutine survives test process | LOW (benign) | `security_scan.go:475`, `scanner.go:259`, `yara_scan.go:545` spawn detached goroutines that exit on result-channel or `time.After`. Bounded; not part of the long-lived goroutine surface. |
| **SC-R-7**: `applyConfigSnapshot` DP-side `dpiScanner.Set` does not persist | LOW (durability, not a race) | Mirrors the P6.1 UC-2 cluster-apply pattern. DP nodes restart with stale DPI patterns until next heartbeat. See §10 SC-3. |
| **SC-R-8**: scanner-config admin mutations not snapshotted | LOW (operator-visible) | See §10 SC-1. |
| **SC-R-9**: `dpiScanner.Save()` and YARA `WriteRule`/`DeleteRule` not fsynced | LOW (durability under power loss) | Atomic-via-rename; mirrors P6.1 UC-1. See §10 SC-4. |

**No risk requires a P5.3-style ownership refactor.** The synchronization model is sound; the gaps are durability + observability + governance, not races.

---

## 7. Shutdown interactions

Owned hooks:

- `scan-svc-shutdown` at `shutdownOrderScanSvcShutdown=60` (`main.go:1336`, registered at `:1426–1431`). Sits between `rate-limit-cleanup-cancel=50` and `admin-ui-shutdown=70`. Calls `s.scanSvc.Shutdown(ctx)` (`scan_svc.go:102–107`), which wraps `(*http.Server).Shutdown(ctx)` on the 30s late-phase context. Drains in-flight sidecar `/scan` calls.

Implicit shutdown coupling:

- `globalThreatFeed.Start(appLifecycleCtx)` goroutine exits when the early-phase `app-lifecycle-cancel` hook (order 40) cancels `appLifecycleCtx`. **No dedicated `scan-` hook is needed** — the goroutine select-on-ctx is sufficient.
- Per-scan timeout goroutines (§3.2) exit on their own; do not gate process exit.
- `globalSecScanner.cache` is memory-only and needs no flush.

Missing / fragile (informational, NOT P6.2 scope):

- `globalRemoteScanner` has no `Shutdown()` method and no dedicated hook. The `*http.Client` is GC-released; idle keepalive connections to the sidecar persist until OS keepalive teardown. Mirrors the P5.1 §10 U-3 finding on `upstreamTransport.CloseIdleConnections()`. Benign in practice; flagged as §10 SC-9 for posterity.
- `*ClamAV` is a per-scan dial; no persistent connection to close.
- `globalThreatFeed`'s in-flight `Sync()` HTTP request continues until its own timeout when `appLifecycleCtx` is cancelled mid-download. Same pattern as the P6.1 UC-7 finding on UT1 `downloadAndParse`. Benign.

Shutdown ordering (informational, not a critical dependency): `appLifecycleCancel` (order 40) precedes `scan-svc-shutdown` (order 60) in the canonical hook table pinned by `runtime_shutdown_wiring_test.go`. As a side effect the threat-feed goroutine's `ctx.Done()` fires before the sidecar server stops, but the threat-feed subsystem and the `ScanService` sidecar are independent — neither depends on the other at shutdown — so this ordering is simple lifecycle sequencing, not a load-bearing invariant.

---

## 8. Cross-cut: existing test coverage

| File | Coverage |
|---|---|
| `scan_svc_test.go` | Sidecar `ScanService` HTTP handlers: `TestScanService_Health`, `_ScanClean`, `_ScanDPIBlock`, `_MethodNotAllowed`, `_Status`; remote-client suite: `TestRemoteScanner_*` (clean / blocked / fail-open / not-enabled / health / status / content-type); admin: `TestAPIScanSvcConfig`; status mapping: `TestSecScanStatusMap_*`; buffering decision: `TestBodyNeedsBuffering_RemoteScanner`; orchestration: `TestSafeScanBody_RemoteDelegation`. |
| `scanner_test.go` | DPI engine: `TestDecompressForScan_*` (identity / gzip / invalid gzip / brotli / gzip bomb); `TestScanner_*` (empty no-match / set+match / clean no-match / invalid pattern / add+remove / regex match / load+save). |
| `yara_test.go` | 70+ functions covering: parser (`TestParseYARASrc_*`, `_StringDef_*`, `_HexPattern_*`, `_Regex_*`, `_LiteralString_*`); rule set (`TestYARARuleSet_*`); boolean evaluator (`TestEvalBoolCondition_*`); regex timeout (`TestMatchRegexWithTimeout_*`); saturation (`TestYARA_SaturationFailsClosed`). |
| `yara_settings_test.go` | Admin API for runtime knobs: `TestYARASettings_DefaultsSecure`, `_PutRequiresAdmin`, `_RejectsInvalidRanges`, `_PersistsAndReloads`, `_FailOpenShowsDiagnosticsWarn`, `TestYARA_DisabledSkipsScanAndDiagnosticsWarn`. |
| `logger_ca_clam_test.go` | ClamAV protocol parsing: `TestParseClamResponse_*` (OK / Found / Error / Empty / Unexpected / MalformedFound); connection error: `TestClamAV_ScanConnectionRefused`. |
| `idp_geoip_secscan_test.go` | Threat-feed + body-scan integration: `TestSecurityScanner_CheckURL_EnabledFeed_{Hit,Miss}`, `CheckDomain_EnabledFeed_{Hit,Miss}`, `ScanBody_WithYARA`, `ScanBody_CachesClean`. |
| `rewrite_scanner_policy_test.go` | Statistics: `TestDPIBlock_IncrementsStat`. |

**Gaps relevant to a future implementation phase (NOT P6.2 scope; flagged for posterity):**

1. No test interleaves YARA `LoadDir` / `WriteRule` / `DeleteRule` with concurrent `Match` calls under `-race`. The RWMutex makes this clean by construction, but a focused contract test would prove it and pin the invariant.
2. No test covers DPI `applyConfigSnapshot` cluster-apply persistence symmetric to the P3.2b PolicyStore test added in PR #225.
3. No test asserts that `apiSecYARA*` / `apiSecScanExclusions` / `apiContentScanBypass` mutations produce a config snapshot — currently they don't, which is what SC-1 calls out, but if SC-1 is fixed a regression test should pin it.

---

## 9. Verdict on Phase 6 strategy

### 9.1 P6.2 — discovery
This document. **Complete.** No production code; no roadmap expansion; no speculative redesigns.

### 9.2 Implications for Phase 6 sequencing

- The four P6 discoveries (P6.1 categories, P6.2 scanning, P6.3 Root CA, P6.4 cluster) remain **independent**. P6.2 does not gate any of the others.
- **None of the findings in this discovery warrant an in-program Phase 6 implementation PR.** The race surfaces are resolved by existing synchronization. The nine deferred follow-ups (§10 SC-1…SC-9) — config-versioning coverage, Prometheus instrumentation, cluster-apply persistence, file-write durability, hot-reload coupling, future ClamAV-address swap design, backup-tier coverage, observability — belong in the same "tracked-separately follow-up" bucket as P3.1#1, P3.2c, U-1…U-6, and P6.1 UC-1…UC-8 — not a new program phase.
- **P3.4 cluster heartbeat flush** still gated on **P6.4 cluster discovery**, NOT on P6.2. P6.2 confirms the cluster ConfigSnapshot fields touched by scanning (DPI patterns + threat-feed data) and notes the matching cluster-apply gap, but the cluster-runtime ownership analysis itself is P6.4.

### 9.3 What this discovery does NOT recommend

- No `upstreamTransport`-style ownership refactor on `globalSecScanner.clam` today. SC-R-3 is intentional and safe; if a future PR wants runtime ClamAV-address mutation, see §10 SC-6 for the design considerations — but that's a separate program, not P6.
- No reshape of `globalYARA` / `dpiScanner` / `globalThreatFeed` / `HashCache` ownership. Each store already has a coherent RWMutex contract and a single mutation API.
- No `applyHotReload` coupling for scanning state. The current "admin API + restart" model is intentional and is consistent with how other expensive-to-rebuild subsystems are handled.
- No expansion of `ConfigSnapshot` to carry YARA rules / ClamAV config / hashcache state / exclusions / DPI bypass list. Those are cluster-feature decisions, not runtime-ownership decisions.
- No move of any scanner global onto `startupState`. Only `s.scanSvc` carries — and it has to, because the late shutdown hook needs the handle. The rest are correctly held as package globals.

---

## 10. Findings worth filing as deferred follow-ups (NOT P6.2 scope)

These were uncovered during this discovery but are out of P6.2's scope. They are noted here so they aren't lost; they should be triaged separately and may belong elsewhere (mirrors of resolved follow-ups, or new items in their own family).

| ID | Finding | Pre-existing? | Mirror |
|---|---|---|---|
| **SC-1** | **RESOLVED (PRs #272–#274).** Originally: scanner-config admin handlers do not call `saveConfigVersion`. The original Category A recommendation ("add `saveConfigVersion` to all 5 persistent-config handlers") was **superseded** by a per-store triage in `roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md` (PR #272 spec), which found the group heterogeneous in risk class — a blanket "extend surface" would have been wrong on three of the five scanner stores. Resolution: <br/><br/>**PR #272** — decision/spec doc. **PR #273** — `dpiScanner.bypassHosts` surface extension (direction B): added `configBackup.ContentScanBypassHosts` (`json:"contentScanBypassHosts"`, no omitempty), capture via `dpiScanner.BypassHosts()`, apply merged into the single `content_scan.json` Save (patterns validated first to avoid mixed state), `saveConfigVersion` added to `apiContentScanBypass` PUT, plus a `diffConfigs` entry for dry-run accuracy. **PR #274** — documented out-of-surface decisions for the remaining scanner stores (YARA settings + scan exclusions as D-sec; YARA rule files as D-ops) with inline guard comments. <br/><br/>**Final per-store decision table:** <br/><br/>• `dpiScanner.patterns` (`apiContentScan` POST/DELETE) → **already correct** — in surface since the original `ContentScanPatterns` field; calls `saveConfigVersion`. <br/>• `dpiScanner.bypassHosts` (`apiContentScanBypass` PUT) → **on-surface, correct** (PR #273). <br/>• YARA settings (`apiSecYARASettings` PUT) → **D-sec, out-of-surface** — rollback could un-harden `yara_on_timeout` / `yara_on_saturation` / `yara_enabled`. <br/>• YARA rule files (`apiSecYARARules` POST/PUT/DELETE) → **D-ops, out-of-surface** — filesystem rule files, typically externally VCS-managed; not JSON-blob admin state. <br/>• scan exclusions (`apiSecScanExclusions` PUT) → **D-sec, out-of-surface** — trust-elevation lists; rollback could re-add a removed exclusion (same shape as `auth.password_change`). <br/>• runtime triggers (`apiSecFeedsSync`, `apiSecYARAReload`, `apiScanCache` evict/clear) → **E, runtime-only** — not config mutations; correctly skip `saveConfigVersion`. <br/><br/>**Note — `apiDomainAllowlist` PUT** (threat-feed domain allowlist) was listed under this finding's original Category A but is a **threat-feed store, not a scanner store**; it was OUT of scope for the scanner spec (PRs #272–#274) and remains a separate, still-open item. See `CONFIG-VERSIONING-TRIAGE.md` §4.2 for its current classification. | Yes — RESOLVED | P6.1 UC-4 (RESOLVED PR #269) |
| **SC-2** | `HashCache.hits` / `.misses` counters exist (`hashcache.go:44–45`) and are exposed via `Stats()`, but the Prometheus handler at `metrics.go:265` discards them: `_, _, cacheSize := globalSecScanner.cache.Stats()`. Only `culvert_scan_cache_size` is rendered. Adding `culvert_scan_cache_hits_total` and `culvert_scan_cache_misses_total` is a one-line addition per counter in `metrics.go` and gives operators the cache-effectiveness signal that's already being measured. | Yes | P6.1 UC-6 (no `culvert_categories_*` metrics family) |
| **SC-3** | `controlplane.go applyConfigSnapshot` calls `dpiScanner.Set(snap.DPIPatterns)` at `:1518` without `dpiScanner.Save()` after. DP nodes restarted between a CP heartbeat and the next admin mutation lose the cluster-pushed DPI patterns. Threat-feed `ImportFeedData` and `SetDomainAllowlist` have the same shape but threat-feed has its own internal `Sync()` to disk on the schedule, so the gap is narrower for that store. **Group with P6.1 UC-2** in the cluster-apply-persistence follow-up; both are caller-side `Save()` after `ReplaceAll`/`Set`. **Hard-gated on SC-4** so we don't amplify a non-fsynced write across the cluster apply path — the same gating logic P6.1 UC-2 uses with P6.1 UC-1. | Yes | P6.1 UC-2; P3.1#3 (`FileProfileStore.ReplaceAll`, PR #222); P3.2b (PR #225) |
| **SC-4** | Four scanner-subsystem `Save` paths use `os.WriteFile` → tmp + `os.Rename` — atomic-via-rename but **not fsynced**. **Verified evidence:** (a) `dpiScanner.Save()` at `scanner.go:130–150`; (b) `globalYARA.WriteRule` at `yara_scan.go:317–353` (per-file tmp+rename via `os.WriteFile` / `os.Rename`); (c) `globalScanExclusions.Save()` at `security_scan.go:159–185`; (d) `globalThreatFeed.saveToDisk()` at `threatfeed.go:416–440`. All four are direct mirrors of the resolved P3.2a (PR #224) and the still-pending P3.1#1 + P6.1 UC-1 — same shape, same `atomicWriteFile` fix. **Group with P6.1 UC-1** in a single durability-hardening follow-up covering catStore.Save + globalCategoryGroups.Save + the four scanner paths above. **Unverified persistence paths:** none remaining — every scanner store with on-disk state has a verified Save path. Do NOT recommend hardening any path not in (a)–(d). | Yes | P6.1 UC-1; P3.1#1 (PAC `Set`); P3.2a (`PolicyStore.Save`, PR #224) |
| **SC-5** | **Observed behaviour:** `applyHotReload(fc)` (`main.go:2205–2260`) does not touch any scanner state — no YARA reload, no ClamAV reconnect, no threat-feed resync, no DPI pattern reload, no exclusions reload. Operators changing scanner config via the YAML file must either use the admin API at runtime or restart the process. **No explicit evidence in code or commit history was found one way or the other on whether this is intentional design or simply unimplemented**; the doc records the behaviour, not the intent. Worth recording because (a) it's surprising for operators arriving from the rate-limit / rewrite / upstream subsystems that *do* hot-reload, and (b) any future "hot-reload everything" effort would need to consider scanner state carefully — most scanner-config mutations are expensive to rebuild. No action recommended now. | Yes | None (behaviour recorded; intent not assessed) |
| **SC-6** | `globalSecScanner.clam` is set once at `Init` and never re-assigned. The hot path reads it under RLock then releases the lock before the actual ClamAV dial+scan (`security_scan.go:492`). Safe today; **fragile to a future feature** that wants runtime ClamAV-address mutation. If that feature ever lands, the design will need to mirror P5.3's `swapUpstreamTransport` pattern — build a fresh `*ClamAV` and atomic-swap-then-release — not in-place field mutation. Recording the design constraint so a future PR doesn't accidentally introduce the race. | Pre-existing design constraint | P5.3 `swapUpstreamTransport` ownership model |
| **SC-7** | Backup tier (`backup.go:81`) includes `scan_exclusions.json` but **not** YARA rule files, the threat-feed DB, or the DPI pattern JSON. Operators must restore those manually before restart. Asymmetric vs. the URL-category tier (P6.1 §5.1 confirmed `categories.json` and `category_groups.json` are both in Tier-2). May or may not be intentional — YARA rule files are large and threat-feed DB can be rebuilt from the source feed. Worth a triage decision rather than a unilateral fix. | Yes | P6.1 §5.1 (Tier-2 backup contract) |
| **SC-8** | No per-rule audit on body scan results. ClamAV / YARA / threat-feed blocks emit `culvert_clamav_blocked_total` / `culvert_yara_blocked_total` / `culvert_threat_feed_blocked_total` counters (`metrics.go:316–326`) but no `auditEvent` per block. The request-level `recordRequest(..., "SCAN_BLOCKED", ...)` does land in the request log. This is consistent with how policy blocks are handled (per-policy audit is opt-in) but worth recording for operators who want per-virus-name visibility in the audit ring. | Yes | None |
| **SC-9** | `globalRemoteScanner.client *http.Client` has no shutdown release. Idle keepalive connections to the sidecar persist until OS-level keepalive teardown. Benign in practice (mirror of P5.1 §10 U-3 finding on `upstreamTransport`). If addressed, the fix is a one-line `globalRemoteScanner.client.CloseIdleConnections()` in a new late-shutdown hook between `scan-svc-shutdown=60` and `admin-ui-shutdown=70`. | Yes | P5.1 §10 U-3 |

**None of SC-1 through SC-9 are required for P6 to advance.** They are governance + durability + observability + design-constraint hygiene rather than blockers. Sequencing suggestions:

- **SC-4 first** (independent, mechanical) — fold into the same durability-hardening follow-up as P6.1 UC-1.
- **SC-3 after SC-4** — **hard-gated** on SC-4 (see SC-3 row); fold into the same cluster-apply-persistence follow-up as P6.1 UC-2.
- **SC-1 — RESOLVED (PRs #272–#274).** Triaged per-store via `roadmap/SCANNER-ROLLBACK-EXTENSION-SPEC.md` rather than a blanket "add `saveConfigVersion` everywhere": DPI bypass hosts extended into the rollback surface (PR #273); YARA settings + scan exclusions documented out-of-surface as D-sec, YARA rule files as D-ops (PR #274); DPI patterns were already correct; runtime triggers stay Category E. See the SC-1 row above for the full per-store table.
- **SC-2** independent; minor metrics PR.
- **SC-7** independent; backup-tier triage decision (not a unilateral PR).
- **SC-5 / SC-6 / SC-8 / SC-9** record-only; no action recommended.

---

## 11. References

- `main.go:97, 160, 194, 229, 245–249, 254, 257, 260–261, 839–937, 1307, 1336, 1418, 1426–1431, 2205–2260` — globals, flag parsing, startup wiring, shutdown wiring, hot-reload entrypoint.
- `security_scan.go:55, 71–91, 269–520, 544, 612` — `SecurityScanner` declaration, `Init`, `ScanBody`, `scanBodyInner`, `scanBodyTimeout`, `decompressForScan`, `safeScanBodyWithCT`, `logScanLimitExceeded`.
- `scanner.go:35–47, 57, 68, 87–188, 259, 275–288` — `ContentScanner` declaration, `Set`, `Load`, `Save`, `SetBypassHosts`, `IsBypassHost`, `matchDPIRegexWithTimeout`.
- `yara_scan.go:50–55, 61–66, 69, 75–198, 317–353, 432–473, 540–548` — `YARARuleSet`, `LoadDir`, `WriteRule`, `DeleteRule`, engine knobs, `matchRegexWithTimeout`.
- `clam.go:28–32, 39, 42–62, 68–86, 92–142` — `ClamAV` struct, `clamSem`, `NewClamAV`, `Ping`, `Scan`.
- `hashcache.go:32–46, 73–149` — declaration, `Get`, `Set`, `Evict`, `Clear`, `Stats`, eviction logic.
- `threatfeed.go:40–63, 106–198` — `ThreatFeed` declaration, `Init`, `Start`, `Sync`, `CheckURL`, `CheckDomain`, allowlist.
- `scan_remote.go:26–141` — `RemoteScanner` declaration, `Init`, `ScanBody`, `remoteScanFailAlert`.
- `scan_svc.go:75–107` — sidecar `ScanService.Start`, `Shutdown`.
- `proxy.go:343–362, 723–782, 1441–1474` — pre-request URL/domain checks, plain-HTTP body scan, SSL-inspect body scan.
- `controlplane.go:149–150, 1517–1562, 1644–1658` — `ConfigSnapshot` scanner fields, DP applier, CP capture.
- `ui_security.go:298–910, 935–981` — admin API surface (DPI, threat-feed, YARA, exclusions, cache, remote-scan).
- `metrics.go:258–334` — Prometheus rendering for scanner counters.
- `backup.go:81` — scan-exclusions backup-tier inclusion.
- Tests: `scan_svc_test.go`, `scanner_test.go`, `yara_test.go`, `yara_settings_test.go`, `logger_ca_clam_test.go`, `idp_geoip_secscan_test.go`, `rewrite_scanner_policy_test.go`.
- `roadmap/RUNTIME-OWNERSHIP.md` §15 SPOF inventory; §3 Phase shape; §4 P6.2 entry; §5 "Recommended next PR".
- `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` (P5.1) and `roadmap/URL-CATEGORIES-DISCOVERY.md` (P6.1) — format baselines.
