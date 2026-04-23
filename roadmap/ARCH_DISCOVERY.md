# ARCH_DISCOVERY.md — Phase 0

**Scope:** read-only discovery of `main.go` on branch `claude/refactor-main-extraction` (commit `5b35724`). No code changes.

**Inputs:** three parallel discovery agents (Coupling & State, Startup Flow, Side-Effects & Lifecycle). Their raw outputs are preserved verbatim below. The Lead Architect synthesis at the end distils the findings into a dependency-graph overview, state-ownership map, critical path, top-5 risks, and safe/high-risk refactor zones.

**Goal of this phase:** ensure PR3 has a complete and honest picture of what `main()` touches before proposing a target architecture. Phase 1 (target architecture, `resolvedConfig`, boundaries) is **not** started.

---

## Executive summary

- `main()` is now 42 lines calling 35 private `initX(s *startupState)` functions and three orchestrators (`buildAndStartProxyServer`, `installSignalHandlers`, `runProxyUntilShutdown`).
- The ordering is shaped by **three implicit buses** rather than explicit dependencies: `s.fc` (god-object config), `logger` (used by every step post-step-7), and `appLifecycleCtx` (parent of every cancellable goroutine).
- 35+ package-level mutable singletons are touched during init. Most (≈28) have internal locking. Seven are **unprotected** after startup (`caRuntime`, `pacDefaultProxyPort`, `revocationFilePath`, `uiExtraSANs`, `trustForwardedHeaders`, `metricsToken`, `syslogConfigured`, `updaterURL`, `clusterDBPathGlobal`, `dataDir`, `uiCfg*`) — safe only because they are write-once-before-serving and reads happen from goroutines with a happens-before edge through the channel that accepts the first incoming request.
- Init has **23 cancellable background goroutines** (all parented to `appLifecycleCtx`) and **5 detached non-cancellable goroutines** (SSE broadcaster, SOCKS5 listener, admin UI, upstream health-check, SIGHUP reload). All 5 are pre-existing; none were introduced by PR2.
- **No architectural regressions introduced by PR2.** The extraction preserved startup order, shutdown order, and side effects byte-for-byte. Every asymmetry cataloged below existed before PR2.

---

## Lead Architect — Dependency graph overview

The three agents' raw analyses (below) reveal that Culvert's startup collapses into a **spine + fan-out** shape:

```
SPINE (critical path, cannot be reordered)
  parseFlags
    └─> loadFileConfigAndFlags        [writes s.fc + derived scalars]
          └─> initLogger              [writes package global `logger`]
                └─> initLifecycleContext   [writes appLifecycleCtx]
                      │
                      ├─── 28 init functions fan out here, each
                      │    consuming the spine + its own slice of s.fc
                      │
                      ├─> initPolicy                 [writes policyStore]
                      │     │
                      │     └─> initRewriteAndDefaultAction  [reads len(policyStore.List())]
                      │     └─> initPersistentAdminState     [RestoreHitCounts writes PolicyRule.HitCount]
                      │
                      ├─> initUpstreamProxy          [mutates upstreamTransport]
                      │     └─> initMTLSAndOCSP      [mutates upstreamTransport again]
                      │
                      ├─> initCluster                [reads s.enrolledConfig, clusterInsecure]
                      │
                      └─> initScanning               [6-global fan-in]
                           └─> (scanSvc sidecar)
            │
            ↓
  startAdminUI   [reads ALL hydrated stores + s.geoDBVal]
            ↓
  buildAndStartProxyServer   [reads s.pPort, s.authU]
            ↓
  installSignalHandlers      [spawns SIGHUP goroutine]
            ↓
  runProxyUntilShutdown      [reads s.scanSvc, s.rlCleanupCancel, s.logCloser; references ~15 globals for graceful stop]
```

**Observations:**

1. **Only 5 edges are truly HARD-DATA between siblings** (per Startup Flow agent):
   - step 1 → step 5 (flag pointers → derived scalars)
   - step 5 → step 7 (lPath/lMaxMB/LogFormat → logger)
   - step 8 → step 8a (appLifecycleCancel → `defer`)
   - step 21 → step 25 (policyStore → default-action decision)
   - step 27 → step 29 (upstreamTransport mutation chain)

   Plus two less-obvious ones:
   - step 21 → step 32 (policyStore rules → RestoreHitCounts target)
   - step 4 → step 17 (s.enrolledConfig → cluster DP startup)

2. **The other 25+ edges are SOFT** — the current ordering is by convention. In principle those init steps form an unordered set that could run concurrently, bottlenecked only by (a) shared use of `logger`, (b) `log.Fatalf` exit-on-error, and (c) the implicit assumption that every earlier step has already run.

3. **`s.fc` is the single largest coupling surface**: 25 init functions dereference at least one field of `s.fc`. Any change to `FileConfig` cascades through every init.

4. **`runProxyUntilShutdown` is a secondary god-node**: it reads ~15 distinct globals plus four `startupState` shutdown-carry fields. Its correctness depends on every init function having run and every background goroutine being reachable via `appLifecycleCtx` or an explicit handle.

---

## Lead Architect — State ownership map

State touched during startup classifies into five layers:

### Layer A — CLI/config inputs (read-only after parse)

The 54 flag pointers on `startupState` and the `*FileConfig` at `s.fc`. Written once by `parseFlags` + `loadFileConfigAndFlags`, never mutated afterwards. Owned by `main()` for the lifetime of the process.

### Layer B — Process-lifetime singletons (write-once, deref-many)

Initialised during startup, never reassigned at runtime. Most are safe to read from any goroutine because the write happens-before every request-handling goroutine is spawned.

- `logger` (main.go:40) — written by `initLogger`; read everywhere.
- `appLifecycleCtx`, `appLifecycleCancel` (main.go:45-46) — written by `initLifecycleContext`; context is immutable; cancel is called during shutdown.
- `clusterInsecure`, `clusterDBPathGlobal`, `dataDir` — write-once config flags.
- `caRuntime`, `pacDefaultProxyPort`, `revocationFilePath`, `uiExtraSANs`, `trustForwardedHeaders`, `metricsToken`, `syslogConfigured`, `updaterURL` — write-once config knobs read by runtime code.
- `uiCfgGeoIPDB`, `uiCfgLogFile`, `uiCfgLogMaxMB`, `uiCfgLogFormat` — UI surface config.
- `requestLogWriter`, `requestLogCloser`, `requestLogFilePath` — request log plumbing.

These are **unprotected plain values**. The safety rests entirely on the happens-before established by `main()` completing its init phase before spawning server goroutines.

### Layer C — Mutable domain stores (self-locking)

The actual state of the system. All have internal mutexes and tolerate concurrent access. Written during init AND continuously at runtime (via UI, CP sync, feed syncers, etc.). `main()` only sets paths and populates initial contents.

- Auth surface: `cfg` (Config, RWMutex), `sessionRevoked`, `idpRegistry`.
- Network policy: `ipf`, `rl`, `connLimiter`, `bl`, `blFeedSyncer`, `sslBypass`.
- Policy engine: `policyStore`, `rewriter`, `catStore`, `globalCategoryGroups`, `globalSaaSFeed`, `communityDB`.
- File/content: `fileBlocker`, `globalProfileStore`, `dpiScanner`.
- Security scanning: `globalSecScanner`, `globalYARA`, `globalScanExclusions`, `globalThreatFeed`, `globalRemoteScanner`.
- TLS surface: `certMgr`, `globalOCSP`, `upstreamTransport` (shared `*http.Transport`; in-place mutated).
- Cluster: `globalClusterStore`, `globalHA`, `globalConfigStore`.
- Observability: `globalOTLP`, `globalOTLPTraces`, `globalAlertStore`.
- Admin: `globalNodeGroups`, `globalBandwidth`, `pacStore`.
- CDR: `cdrInstances`, `cdrPolicyStore`.

### Layer D — Cancellable goroutines (parented to `appLifecycleCtx`)

Background workers that will exit cleanly on graceful shutdown. 18+ goroutines total; all rely on the single `appLifecycleCancel()` call in `runProxyUntilShutdown`. See the Lifecycle agent's table for the full list.

### Layer E — Detached goroutines (no cancellation path)

The 5 exceptions — SSE broadcaster, SOCKS5 listener, admin UI `http.Server`, upstream health-check loop, SIGHUP reload goroutine. They rely on process exit. See "Top-5 risks" and "High-risk zones" below.

### startupState shutdown-carry fields

Four locals on `startupState` outlive init and are consumed during shutdown:

- `s.logCloser` — read by `runProxyUntilShutdown`.
- `s.rlCleanupCancel` — read by `runProxyUntilShutdown`.
- `s.scanSvc` — read by `runProxyUntilShutdown` for sidecar shutdown.
- `s.feedSyncer` — **dead carry**. Agent 1 flagged: assigned in `initURLCategories` but never subsequently read. `.Start(appLifecycleCtx)` is called in-place at assignment. Preserving it costs nothing; removing it is a PR3 simplification candidate.

---

## Lead Architect — Startup critical path

The longest chain that cannot be reordered without behavior change (derived from Startup Flow agent):

```
parseFlags                       # flag pointers populated
  ↓
loadFileConfigAndFlags           # s.fc + derived scalars
  ↓
initLogger                       # package global logger
  ↓
initLifecycleContext             # appLifecycleCtx ready
  ↓
defer appLifecycleCancel()       # panic safety in main()
  ↓
initAuth                         # cfg singleton populated (used by everything downstream)
  ↓
initPolicy                       # policyStore.Load — MUST run before…
  ↓
…initRewriteAndDefaultAction     # …because it reads len(policyStore.List()) for the default action
  ↓
initUpstreamProxy                # mutates upstreamTransport.TLSClientConfig via pool
  ↓
initMTLSAndOCSP                  # mutates upstreamTransport.TLSClientConfig AGAIN (cert + OCSP wrapper)
  ↓
initPersistentAdminState         # RestoreHitCounts writes to PolicyRule.HitCount of rules loaded by initPolicy
  ↓
startAdminUI                     # spawns admin UI goroutine; reads every hydrated store
  ↓
buildAndStartProxyServer         # constructs proxy http.Server (no listen yet)
  ↓
installSignalHandlers            # signal channels + SIGHUP goroutine
  ↓
runProxyUntilShutdown            # ListenAndServe goroutine + block on SIGINT/SIGTERM
```

**Hard-fatal steps on this path** (any failure aborts everything downstream):

- `loadFileConfigAndFlags` — `log.Fatalf` on YAML parse error.
- `initLogger` — `log.Fatalf` on logger setup.
- `initPolicy` — `logger.Fatalf` on policy file parse.
- `runProxyUntilShutdown` — `logger.Fatalf` on `ListenAndServe` unexpected error.

**Hard-fatal steps on non-critical branches** (failure aborts the process but the path above could in principle have run before them):

- `runEnrollmentMode` — `log.Fatalf` on enrollment failure.
- `initCluster` — `logger.Fatalf` on CP gRPC bind failure.
- `initBlocklist` — `logger.Fatalf` on blocklist load (non-NotExist) error.
- `initURLCategories` — `logger.Fatalf` on catStore / BadgerDB open error.
- `initUIAccessPolicy` — `log.Fatalf` on IdP profiles load error.
- `initPAC` — `log.Fatalf` on PAC config load error.
- `initSSLBypassAndDPI` — 4 `logger.Fatalf` sites on pattern load/set errors.
- `initLegacyAuthProviders` — `log.Fatalf` on LDAP/OIDC provider init error.
- `initAuth` — `log.Fatalf` on `SetAuth` error.

The large number of `log.Fatalf` sites (~15) means **any proposal to parallelise init must first confront the exit-on-error semantics**. Half-init + fatal-exit from one goroutine while peers are still initialising leaks half-open resources: scan sidecar listener, CA file handle, community BadgerDB, CP gRPC server, feed syncer goroutines.

---

## Lead Architect — Top 5 architectural risks

### Risk #1 — `s.fc` is a god-object

- 25 init functions dereference at least one field of `s.fc` (`*FileConfig`).
- Every YAML schema change transitively affects every init. No compile-time firewall between "policy config" and "scanning config" and "cluster config" — they all live on one struct.
- Refactor cost of ANY future domain extraction is dominated by this: a domain-owner can't take its slice of config without reference to the full `FileConfig` or a manual subset copy.
- **Severity: HIGH.** This is the single biggest blocker to clean domain boundaries.
- Mitigation direction (Phase 1): introduce a `resolvedConfig` per domain (auth, policy, scanning, cluster, CDR, observability, network, runtime) that each domain owns. Each domain builds its slice once at startup; `main()` wires them.

### Risk #2 — Shared-mutation of `upstreamTransport`

- `initUpstreamProxy` (step 27) passes `s.fc` to `initUpstreamPool`, which mutates `upstreamTransport` in place.
- `initMTLSAndOCSP` (step 29) mutates the same `upstreamTransport` again (`TLSClientConfig.Certificates`, `ConfigureTransportOCSP`).
- The serial ordering is **enforced only by convention + comments**. No type prevents a future edit from calling them in the wrong order.
- **Severity: MEDIUM.** Latent — current tests don't exercise the wrong order.
- Mitigation direction: construct `upstreamTransport` once from a pure `UpstreamConfig` struct, with mTLS + OCSP supplied as inputs; swap the built transport into `upstreamPool` atomically. No post-hoc in-place mutation.

### Risk #3 — 5 detached goroutines with no shutdown path

1. **SSE broadcaster** (`initBackgroundServices`) — bare `for range ticker.C`. Severity LOW.
2. **SOCKS5 listener** (`initSOCKS5`) — bare `ln.Accept()` loop; listener handle is lost. Severity MEDIUM (in-flight SOCKS5 tunnels are not drained by the 15 s tunnel-drain).
3. **Admin UI `http.Server`** (`startAdminUI`) — no `Shutdown` handle. Severity MEDIUM (in-flight OIDC callbacks / SSE streams are closed abruptly).
4. **Upstream health-check loop** (`initUpstreamPool`) — no context. Severity LOW.
5. **SIGHUP reload goroutine** (`installSignalHandlers`) — bare `for range sighup`. Severity LOW.
- **Aggregate severity: MEDIUM.** Two of the five (SOCKS5, admin UI) have observable impact on clean shutdown.
- Mitigation direction: each detached goroutine is assigned an owner domain with a stoppable handle; shutdown sequence invokes each owner's `Stop(ctx)` in a deterministic order.

### Risk #4 — `log.Fatalf` scattered across 15+ init sites

- Each fatal site is safe today because init is serial: a fatal from any step stops the process before the next step starts.
- Any future parallelisation of independent init steps is **unsafe** until these are converted to returning `error`. Otherwise one goroutine's fatal while a peer is mid-init leaks half-open resources (file handles, listeners, goroutines).
- **Severity: MEDIUM** (architectural tax on future evolution, not a runtime bug today).
- Mitigation direction: init functions return `error`; `main()` collects errors and decides exit vs continue vs retry. Backwards-compatible: current "fatal on any error" behavior is preserved by a simple `if err != nil { log.Fatalf }` in `main()`.

### Risk #5 — No final Save on shutdown for 15 mutable stores

- `catStore`, `globalScanExclusions`, `fileBlocker`, `globalProfileStore`, `policyStore`, `sslBypass`, `dpiScanner`, `bl`, `globalNodeGroups`, `globalBandwidth`, `globalCategoryGroups`, `sessionRevoked`, `cfg` UI users, `cdrInstances`, `cdrPolicyStore`, `globalClusterStore`, `auditCloser` — all rely on save-on-write.
- In practice, every mutating API call saves immediately → usually safe.
- Edge case: `globalClusterStore` heartbeat/liveness state is mutated in-memory between scheduled saves; on SIGKILL-timeout those transitions are lost. `auditCloser` file handle is leaked on abrupt exit.
- **Severity: LOW** for most stores; **MEDIUM** for clusterStore heartbeat and audit log handle.
- Mitigation direction: a generic `shutdownSaver` registry; each store registers itself and the shutdown path flushes all of them before the context-timeout deadline.

---

## Lead Architect — Safe refactor zones vs high-risk zones

Classification rubric: coupling surface (globals touched), goroutine spawn, external I/O, fatal-exit sites, cross-init dependencies.

### SAFE zones (LOW risk for domain extraction)

Each of these is a self-contained slice: writes disjoint global(s), reads a small named subset of `s.fc`, no runtime goroutine (or one that is cleanly parented to `appLifecycleCtx`), no fatal-exit in the hot path.

| Init function | Touches globals | Goroutines | External I/O |
|---|---|---|---|
| `initUIExtras` | `uiExtraSANs`, `trustForwardedHeaders` | none | none |
| `initMetricsToken` | `metricsToken` | none | none |
| `initSession` | `sessionRevoked`, `revocationFilePath`, session TTL | none | revocations file |
| `initGeoIP` | GeoIP DB pointer | none | GeoIP mmdb file |
| `initPAC` | `pacStore`, `pacDefaultProxyPort` | none | `pac_config.json` |
| `initFileBlocking` | `fileBlocker`, `globalProfileStore` | none | fileblock/fileprofiles JSON |
| `initSSLBypassAndDPI` | `sslBypass`, `dpiScanner` | none | SSL bypass / content scan JSON |
| `initRewriteAndDefaultAction` | `rewriter`, default-policy-action | none | none |
| `initLegacyAuthProviders` | `cfg.provider` | none | (LDAP/OIDC dials on use, not init) |
| `initUIAccessPolicy` | `uiAllowList`, `proxyBaseURL`, `idpRegistry` | none | IdP profiles JSON |
| `initMTLSAndOCSP` | `upstreamTransport.TLSClientConfig`, `globalOCSP` | none | client cert files |

**These are the right candidates to pick off into domain packages first.** Each becomes a pure constructor that takes a small `resolvedConfig` slice and returns its store + any shutdown hook.

### MEDIUM-risk zones

Multiple globals or a goroutine, but the coupling is still tractable.

| Init function | Why medium |
|---|---|
| `initLogger` | Writes `logger`; every step after it depends on the package-global → any rewire requires a careful migration of all `logger.Printf` sites. |
| `initObservability` | 5 globals (syslog, OTLP, OTLP-traces, audit, request-log); opens persistent files but has no runtime goroutines of its own. |
| `initAuth` | Mutates the `cfg` singleton which is read by auth logic across the codebase. Requires extracting `cfg` itself to a domain before this becomes "safe". |
| `initBlocklist` | One store + one optional goroutine tied to `appLifecycleCtx`. Straightforward once the blocklist domain is carved. |
| `initConnAndRateLimit` | Three globals + one cancellable goroutine. `rl` is sharded-mutex; `ipf` is simple. |
| `initPolicy` + `initRewriteAndDefaultAction` + `RestoreHitCounts` | Three init steps feeding one store; must be carved as a unit. |

### HIGH-risk zones

Many globals, goroutines, or external gRPC/network; touching them demands careful sequencing and more test coverage. Leave for later in PR3+.

| Init function | Why high |
|---|---|
| `initCluster` + `enableControlPlane` + `startDataPlane` + HA | 7+ globals, **8 goroutines**, CP gRPC bind, DP dials, HA standby/leader flip, reads `clusterInsecure` + `s.enrolledConfig`. Order-sensitive with TLS/insecure decision. |
| `initScanning` | **6 globals**, 2 goroutines (threat feed + sidecar), 98-line body, 5 `nestif` warnings from lint. Largest single init function. |
| `initCDR` | External gRPC dial + TOFU pinning + health poller goroutine + two persistent stores. |
| `initURLCategories` | catStore + groups + SaaS feed + BadgerDB + UT1 seeding + `feedSyncer` goroutine. |
| `initRootCA` | CA bundle encryption, env-var passphrase, auto-rotation goroutine, `caRuntime` unprotected global. |
| `initUpstreamProxy` + `initMTLSAndOCSP` | Two steps mutating the same `*http.Transport`. See Risk #2. |
| `runProxyUntilShutdown` | Reads 15+ globals + 4 startupState fields. Shutdown ordering is byte-sensitive. |
| `startAdminUI` + `startUI` goroutine | No Shutdown handle (Risk #3). |
| `initSOCKS5` | Detached goroutine with no cancellation (Risk #3). |

### Implicit "do not touch yet" coupling

- `logger` is written once, read 100s of times. Replacing it with a per-domain logger is a codebase-wide refactor; defer to a separate PR.
- `appLifecycleCtx` / `appLifecycleCancel` are the backbone of cancellation. Any change to how they are created/owned affects every cancellable goroutine.
- `upstreamTransport` is a shared `*http.Transport` used by the proxy hot path, OCSP, and outbound HTTP clients. Refactor requires a single construction site with defined inputs.

### Recommended PR3 entry point

Extract **one** safe-zone slice first — suggest `initFileBlocking` OR `initSSLBypassAndDPI` — as a pilot for the `resolvedConfig` + domain-package pattern. Validate the pattern end-to-end (including CI + qa-gate) before widening the scope.

---

# Appendix — Raw agent outputs

The three discovery agents' outputs are preserved verbatim below for traceability.

## Coupling & State

### 1. `startupState` field inventory

| Field | Type | Writer(s) | Reader(s) | Class |
|---|---|---|---|---|
| `configPath` | `*string` | `parseFlags` | `handleOneShotCommands`, `loadFileConfigAndFlags`, `installSignalHandlers` (SIGHUP closure) | cross-init |
| `proxyPort` | `*int` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `uiPortFlag` | `*int` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `user` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `pass` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `blockFile` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `logFilePath` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `logMaxMB` | `*int` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `tlsCert` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `tlsKey` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `rateLimitRPM` | `*int` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `ipMode` | `*string` | `parseFlags` | `loadFileConfigAndFlags` | cross-init |
| `socks5Port` | `*int` | `parseFlags` | `initSOCKS5` | cross-init |
| `metricsTok` | `*string` | `parseFlags` | `initMetricsToken` | cross-init |
| `cpGRPCAddr`, `cpGRPCCert`, `cpGRPCKey`, `cpGRPCCA` | `*string` | `parseFlags` | `initCluster` | cross-init |
| `haJoin`, `haToken` | `*string` | `parseFlags` | `initCluster` | cross-init |
| `dpCPAddr`, `dpNodeID`, `dpCert`, `dpKey`, `dpCA` | `*string` | `parseFlags` | `initCluster` | cross-init |
| `policyFile` | `*string` | `parseFlags` | `initPolicy` | cross-init |
| `caPath` | `*string` | `parseFlags` | `initRootCA` | cross-init |
| `auditLog` | `*string` | `parseFlags` | `initObservability` | cross-init |
| `requestLogPath`, `requestLogMaxMB` | `*string`/`*int` | `parseFlags` | `initObservability` | cross-init |
| `syslogAddr`, `syslogFormat` | `*string` | `parseFlags` | `initObservability` | cross-init |
| `otlpEndpoint` | `*string` | `parseFlags` | `initObservability` | cross-init |
| `uiAllowIP` | `*string` | `parseFlags` | `initUIAccessPolicy` | cross-init |
| `sessionHrs` | `*int` | `parseFlags` | `initSession` | cross-init |
| `geoIPDB` | `*string` | `parseFlags` | `initGeoIP` | cross-init |
| `clamavAddr`, `yaraRulesDir`, `threatFeedDB` | `*string` | `parseFlags` | `initScanning` | cross-init |
| `uiUsersFile` | `*string` | `parseFlags` | `handleOneShotCommands`, `initAuth` | cross-init |
| `fileProfilesFile` | `*string` | `parseFlags` | `initFileBlocking` | cross-init |
| `uiNoTLS` | `*bool` | `parseFlags` | `startAdminUI` | cross-init |
| `catFeedDB`, `catFeedURL`, `catSyncIntvl` | `*string` | `parseFlags` | `initURLCategories` | cross-init |
| `enrollURL` | `*string` | `parseFlags` | `runEnrollmentMode` | cross-init |
| `clusterDB` | `*string` | `parseFlags` | `initCluster` | cross-init |
| `clusterInsecureFlag` | `*bool` | `parseFlags` | `setInsecureFlag` | cross-init |
| `revocationsFile` | `*string` | `parseFlags` | `initSession` | cross-init |
| `scanSvcListen`, `scanSvcURL` | `*string` | `parseFlags` | `initScanning` | cross-init |
| `updaterURLFlag` | `*string` | `parseFlags` | `initBackgroundServices` | cross-init |
| `uiSANsFlag` | `*string` | `parseFlags` | `initUIExtras` | cross-init |
| `trustFwdHeaders` | `*bool` | `parseFlags` | `initUIExtras` | cross-init |
| `resetPwUser` | `*string` | `parseFlags` | `handleOneShotCommands` | cross-init |
| `cdrEnabledFlag`, `cdrEndpointFlag`, `cdrFailModeFlag`, `cdrProfileFlag`, `cdrModeFlag`, `cdrTimeoutFlag`, `cdrMaxSizeFlag`, `cdrFingerprintFlag`, `cdrCertsDirFlag` | mixed | `parseFlags` | `initCDR` | cross-init |
| `fc` | `*FileConfig` | `loadFileConfigAndFlags` | ≥25 init functions — **god-object hub** | cross-init |
| `pPort` | `int` | `loadFileConfigAndFlags` | `initAuth`, `initPAC`, `buildAndStartProxyServer` | cross-init |
| `uPort` | `int` | `loadFileConfigAndFlags` | `initAuth`, `startAdminUI` | cross-init |
| `lPath` | `string` | `loadFileConfigAndFlags` | `initLogger`, `startAdminUI` | cross-init |
| `blPath` | `string` | `loadFileConfigAndFlags` | `initBlocklist` | cross-init |
| `lMaxMB` | `int` | `loadFileConfigAndFlags` | `initLogger`, `startAdminUI` | cross-init |
| `authU` | `string` | `loadFileConfigAndFlags` | `initAuth`, `initLegacyAuthProviders`, `buildAndStartProxyServer` | cross-init |
| `authP` | `string` | `loadFileConfigAndFlags` | `initAuth` | cross-init |
| `cert` | `string` | `loadFileConfigAndFlags` | `startAdminUI` | cross-init |
| `key` | `string` | `loadFileConfigAndFlags` | `startAdminUI` | cross-init |
| `rlRPM` | `int` | `loadFileConfigAndFlags` | `initConnAndRateLimit` | cross-init |
| `ipModeVal` | `string` | `loadFileConfigAndFlags` | `initConnAndRateLimit` | cross-init |
| `enrolledConfig` | `*dpEnrollmentConfig` | `runEnrollmentMode` | `initCluster` | cross-init |
| `geoDBVal` | `string` | `initGeoIP` | `startAdminUI` | cross-init |
| `logCloser` | `interface{Close() error}` | `initLogger` | `runProxyUntilShutdown` | shutdown-carry |
| `rlCleanupCancel` | `context.CancelFunc` | `initConnAndRateLimit` | `runProxyUntilShutdown` | shutdown-carry |
| `feedSyncer` | `*FeedSyncer` | `initURLCategories` | — (**dead carry**; `.Start` was already called in-place) | transient |
| `scanSvc` | `*ScanService` | `initScanning` | `runProxyUntilShutdown` | shutdown-carry |

### 2. Package-global inventory (startup-touched)

| Global | File:Line | Type | Init writer(s) | Readers | Locking | Notes |
|---|---|---|---|---|---|---|
| `logger` | main.go:40 | `*log.Logger` | `initLogger` | every init after it + all runtime | write-once; ptr deref | |
| `cfg` | store.go:1085 | `*Config` | `handleOneShotCommands`, `initAuth`, `initLegacyAuthProviders` | whole codebase | internal RWMutex | live-mutable via UI |
| `appLifecycleCtx` | main.go:45 | `context.Context` | `initLifecycleContext` | 9 init functions + runtime | immutable after creation | write-once |
| `appLifecycleCancel` | main.go:46 | `context.CancelFunc` | `initLifecycleContext` | `main` (defer), `runProxyUntilShutdown` | none | write-once |
| `ipf` | security.go:151 | `*IPFilter` | `initConnAndRateLimit`, `applyHotReload` | request path, UI | internal mutex | live-mutable |
| `rl` | security.go:277 | `*rateLimiter` | `initConnAndRateLimit`, `applyHotReload`, cleanup goroutine | request path | sharded mutex (64) | live-mutable |
| `bl` | store.go:538 | `*Blocklist` | `initBlocklist`, `applyHotReload`, feed syncer | request path, UI | internal RWMutex | live-mutable |
| `blFeedSyncer` | main.go:49 | `*BlocklistSyncer` | `initBlocklist` (both branches) | UI handlers | none on ptr | live-mutable (UI reassigns) |
| `certMgr` | ca.go:59 | `*CertManager` | `initRootCA` | handlers, UI | internal RWMutex | live-mutable |
| `caRuntime` | ca.go:63 | `struct{path,passphrase string}` | `initRootCA` | CA rotation API | **none — unprotected** | write-once |
| `policyStore` | policy.go:375 | `*PolicyStore` | `initPolicy`, `applyHotReload` | `initRewriteAndDefaultAction`, request path, UI | internal RWMutex | live-mutable |
| `catStore` | policy.go:65 | `*categoryStore` | `initURLCategories` | request path, UI | internal mutex | live-mutable |
| `globalCategoryGroups` | categorygroup.go:51 | `*CategoryGroupStore` | `initURLCategories` | request path, UI | internal mutex | live-mutable |
| `globalSaaSFeed` | saas_feed.go:48 | `*SaaSFeedSyncer` | `initURLCategories` | UI toggle, goroutine | internal mutex | live-mutable |
| `communityDB` | catdb.go:31 | `*CommunityDB` | `initURLCategories` | request path, `runProxyUntilShutdown` | none on ptr | write-once |
| `fileBlocker` | fileblock.go:23 | `*FileBlocker` | `initFileBlocking` | request path, UI | internal mutex | live-mutable |
| `globalProfileStore` | fileprofile.go:29 | `*FileProfileStore` | `initFileBlocking` | policy eval, UI | internal mutex | live-mutable |
| `sslBypass` | policy.go:1011 | `*SSLBypassMatcher` | `initSSLBypassAndDPI` | CONNECT handler, UI | internal mutex | live-mutable |
| `dpiScanner` | scanner.go:57 | `*ContentScanner` | `initSSLBypassAndDPI` | scan pipeline, UI | internal mutex | live-mutable |
| `rewriter` | rewrite.go:63 | `*Rewriter` | `initRewriteAndDefaultAction`, `applyHotReload` | request path, UI | internal mutex | live-mutable |
| `globalRemoteScanner` | scan_remote.go:34 | `*RemoteScanner` | `initScanning` | scan pipeline | internal mutex | write-once |
| `globalSecScanner` | security_scan.go:97 | `*SecurityScanner` | `initScanning` | handlers, scan pipeline | internal mutex | write-once |
| `globalYARA` | yara_scan.go:69 | `*YARARuleSet` | `initScanning` | scan pipeline, UI | internal mutex | live-mutable |
| `globalScanExclusions` | security_scan.go:123 | `*ScanExclusionStore` | `initScanning` | scan pipeline, UI | internal mutex | live-mutable |
| `globalThreatFeed` | threatfeed.go:64 | `*ThreatFeed` | `initScanning` | handlers, UI | internal mutex | live-mutable |
| `globalClusterStore` | enrollment.go:113 | `*ClusterStore` | `initCluster`, `enableControlPlane` | gRPC handlers, UI | internal RWMutex | live-mutable |
| `globalHA` | ha.go:45 | `*HAState` | `initCluster`, `runProxyUntilShutdown` | HA goroutines, UI | `mu sync.Mutex` | live-mutable |
| `globalConfigStore` | controlplane.go:136 | `*ConfigStore` | `enableControlPlane` (indirect) | DP pullers | internal mutex | live-mutable |
| `globalOCSP` | ocsp.go:42 | `*OCSPChecker` | `initMTLSAndOCSP` | transport pipeline | internal mutex | write-once |
| `globalOTLP` | otlp.go:45 | `*OTLPExporter` | `initObservability` | metrics emitter | internal mutex | write-once |
| `globalOTLPTraces` | otlp_traces.go:67 | `*OTLPSpanExporter` | `initObservability` | tracing | internal mutex | write-once |
| `globalAlertStore` | alerts.go:121 | `*AlertStore` | indirect via retry loop | alert goroutine, UI | internal mutex | runtime-mutable |
| `globalNodeGroups` | nodegroup.go:40 | `*NodeGroupStore` | `initPersistentAdminState` | CP/DP sync, UI | internal mutex | write-once ptr |
| `globalBandwidth` | bandwidth.go:52 | `*BandwidthManager` | `initPersistentAdminState` | request path, UI | internal mutex | write-once ptr |
| `cdrInstances` | cdrstore.go:90 | `*CDRInstanceRegistry` | `initCDR` | CDR client, UI | internal mutex | live-mutable |
| `cdrPolicyStore` | cdrpolicy.go:134 | `*CDRPolicyStore` | `initCDR` | scan pipeline, UI | internal mutex | live-mutable |
| `connLimiter` | connlimit.go:49 | `*ConnLimiter` | `initConnAndRateLimit` | request path | internal mutex | write-once |
| `idpRegistry` | auth_idp.go:119 | `*IdPRegistry` | `initUIAccessPolicy` | auth handlers, UI | internal mutex | live-mutable |
| `pacStore` | pac.go:44 | `*PACStore` | `initPAC` | `/proxy.pac`, UI | internal mutex | live-mutable |
| `pacDefaultProxyPort` | pac.go:35 | `int` | `initPAC` | `/proxy.pac`, UI | **none** | write-once |
| `sessionRevoked` | session.go:68 | `*revocationList` | `initSession` | session validation, API | internal mutex | live-mutable |
| `revocationFilePath` | session.go:168 | `string` | `initSession` | LoadRevocations/SaveRevocations | **none** | write-once |
| `uiExtraSANs` | tls.go:23 | `[]string` | `initUIExtras` | `selfSignedTLS()` via `startUI` | **none** | write-once |
| `trustForwardedHeaders` | store.go:1531 | `bool` | `initUIExtras` | request helpers | none | write-once |
| `metricsToken` | metrics.go:226 | `string` | `initMetricsToken` | `/metrics` handler | none | write-once |
| `syslogConfigured` | ui_config.go:648 | `string` | `initObservability` | UI config panel | none | write-once |
| `updaterURL` | update.go:69 | `string` | `initBackgroundServices` | update checker, UI | none | write-once |
| `clusterInsecure` | controlplane.go:840 | `bool` | `setInsecureFlag` | cluster dial helpers | none | write-once |
| `clusterDBPathGlobal` | main.go:50 | `string` | `initCluster` | UI / API | none | write-once |
| `dataDir` | main.go:53 | `string` | default `/data` | 4 init functions | none | constant |
| `uiCfgGeoIPDB` | ui.go:29 | `string` | `startAdminUI` | `ui_security.go` | none | write-once |
| `uiCfgLogFile` | ui.go:30 | `string` | `startAdminUI` | `ui_config.go` | none | write-once |
| `uiCfgLogMaxMB` | ui.go:31 | `int` | `startAdminUI` | `ui_config.go` | none | write-once |
| `uiCfgLogFormat` | ui.go:32 | `string` | `startAdminUI` | `ui_config.go` | none | write-once |
| `upstreamTransport` | proxy.go:961 | `*http.Transport` | `initMTLSAndOCSP` + `initUpstreamPool` | proxy request pipeline | **none — in-place mutation** | mutated at startup only |
| `requestLogWriter` | store.go:147 | `io.Writer` | `initObservability` (via `initRequestLog`) | request path | **none** | write-once |
| `requestLogCloser` | store.go:148 | `io.Closer` | `initObservability` | `runProxyUntilShutdown` | none | write-once |
| `requestLogFilePath` | store.go:149 | `string` | `initObservability` | paginated reads | none | write-once |

### 3. Hidden-coupling hotspots

Top-5 init functions by global touches:

1. **`initCluster`** — 7+ globals: `clusterRole`, `clusterDBPathGlobal`, `globalClusterStore`, `globalHA`, `appLifecycleCtx`, plus transitively `globalConfigStore`, `clusterInsecure`. Reads `s.enrolledConfig` (from `runEnrollmentMode`). **Invariants**: `appLifecycleCtx` ready; `setInsecureFlag` already ran; `logger` initialised.
2. **`initScanning`** — 6 globals: `globalRemoteScanner`, `globalSecScanner`, `globalYARA`, `globalScanExclusions`, `globalThreatFeed`, + `s.scanSvc` + `appLifecycleCtx`. **Invariants**: `logger` initialised; `dataDir` writable.
3. **`initURLCategories`** — 5 globals: `catStore`, `globalCategoryGroups`, `globalSaaSFeed`, `communityDB`, + `s.feedSyncer` + `appLifecycleCtx`. **Invariants**: logger ready; `dataDir` writable.
4. **`initObservability`** — 5 globals: `globalOTLP`, `globalOTLPTraces`, `syslogConfigured`, `requestLogWriter`/`requestLogCloser`/`requestLogFilePath` + audit log. **Invariant**: `logger` ready.
5. **`initRootCA`** — 3 globals + implicit: `certMgr`, `caRuntime`, `appLifecycleCtx`. **Invariants**: `appLifecycleCtx` exists; `CULVERT_CA_PASSPHRASE` env set if encryption wanted; `logger` ready.

(Honourable mention: `runProxyUntilShutdown` itself reads ~15 globals during graceful stop — a secondary coupling hotspot distinct from startup.)

### 4. Dependency graph (text form)

```
parseFlags                       ROOT
handleOneShotCommands            → parseFlags
setInsecureFlag                  → parseFlags
runEnrollmentMode                → parseFlags, setInsecureFlag
loadFileConfigAndFlags           → parseFlags
initUIExtras                     → parseFlags, loadFileConfigAndFlags
initLogger                       → loadFileConfigAndFlags
initLifecycleContext             ROOT
initAuth                         → parseFlags, loadFileConfigAndFlags, initLogger, handleOneShotCommands
initSession                      → parseFlags, loadFileConfigAndFlags, initLogger
initObservability                → parseFlags, loadFileConfigAndFlags, initLogger
initGeoIP                        → parseFlags, loadFileConfigAndFlags, initLogger
initUIAccessPolicy               → parseFlags, loadFileConfigAndFlags, initLogger
initPAC                          → loadFileConfigAndFlags, initLogger
initLegacyAuthProviders          → loadFileConfigAndFlags, initLogger, initAuth
initMetricsToken                 → parseFlags, loadFileConfigAndFlags, initLogger
initCluster                      → parseFlags, loadFileConfigAndFlags, runEnrollmentMode, setInsecureFlag, initLifecycleContext, initLogger
initConnAndRateLimit             → loadFileConfigAndFlags, initLifecycleContext, initLogger
initBlocklist                    → loadFileConfigAndFlags, initLifecycleContext, initLogger
initRootCA                       → parseFlags, loadFileConfigAndFlags, initLifecycleContext, initLogger
initPolicy                       → parseFlags, loadFileConfigAndFlags, initLogger
initURLCategories                → parseFlags, loadFileConfigAndFlags, initLifecycleContext, initLogger
initFileBlocking                 → parseFlags, loadFileConfigAndFlags, initLogger
initSSLBypassAndDPI              → loadFileConfigAndFlags, initLogger
initRewriteAndDefaultAction      → loadFileConfigAndFlags, initPolicy, initLogger
initScanning                     → parseFlags, loadFileConfigAndFlags, initLifecycleContext, initLogger
initUpstreamProxy                → loadFileConfigAndFlags, initLogger
initCDR                          → parseFlags, loadFileConfigAndFlags, initLifecycleContext, initLogger
initMTLSAndOCSP                  → loadFileConfigAndFlags, initLogger, initUpstreamProxy
initBackgroundServices           → parseFlags, loadFileConfigAndFlags, initLifecycleContext, initLogger
initSOCKS5                       → parseFlags, loadFileConfigAndFlags
initPersistentAdminState         → initLifecycleContext, initPolicy
startAdminUI                     → parseFlags, loadFileConfigAndFlags, initGeoIP
buildAndStartProxyServer         → loadFileConfigAndFlags, initLogger
installSignalHandlers            → parseFlags, initLogger
runProxyUntilShutdown            → initLifecycleContext, initLogger, initCluster, initConnAndRateLimit, initScanning, initURLCategories, initObservability, initLogger, buildAndStartProxyServer
```

## Startup Flow

### 1. Ordered call map

| # | Function | Description | Start precondition | End postcondition |
|---|---|---|---|---|
| 1 | `parseFlags` (main.go:151) | Register CLI flags + `flag.Parse()`; populate 54 pointers on `startupState`. | none | all flag pointers non-nil |
| 2 | `handleOneShotCommands` (L152) | `--reset-password` → mutate ui_users.json + `os.Exit(0)`. | step 1 | process exited OR confirmed not in reset mode |
| 3 | `setInsecureFlag` (L153) | `clusterInsecure = *s.clusterInsecureFlag`. | step 1 | global set |
| 4 | `runEnrollmentMode` (L154) | If `--enroll` set, runs enrollment and stores `s.enrolledConfig`. May `log.Fatalf`. | step 3 (TLS mode) | `s.enrolledConfig` either nil or fully populated |
| 5 | `loadFileConfigAndFlags` (L155) | Parse YAML into `s.fc`; resolve CLI-vs-file precedence. May `log.Fatalf`. | step 1 | `s.fc != nil`; all derived scalars set |
| 6 | `initUIExtras` (L156) | Write `uiExtraSANs`, `trustForwardedHeaders`. | step 5 | globals populated |
| 7 | `initLogger` (L157) | Build rotating logger; stash closer on `s.logCloser`. May `log.Fatalf`. | step 5 | package global `logger` set — **required by every later step** |
| 8 | `initLifecycleContext` (L158) | `appLifecycleCtx, appLifecycleCancel = context.WithCancel(Background())`. | none semantic | `appLifecycleCtx` ready |
| 8a | `defer appLifecycleCancel()` (L159) | Panic safety: guaranteed cancel on main() return. | step 8 | shutdown cancellation guaranteed |
| 9 | `initAuth` (L161) | `cfg.ProxyPort`, `cfg.UIPort`, `SetAuth`, load UI users. May `log.Fatalf`. | step 5, step 7 | `cfg` populated |
| 10 | `initSession` (L162) | Session HMAC, revocations, TTL. | step 5, step 7 | session subsystem ready |
| 11 | `initObservability` (L163) | Syslog, OTLP, audit log, request log. | step 5, step 7 | observability wired |
| 12 | `initGeoIP` (L164) | Open MaxMind DB; store `s.geoDBVal`. | step 5, step 7 | `s.geoDBVal` set |
| 13 | `initUIAccessPolicy` (L165) | UI allowlist, base URL, IdP registry. May `log.Fatalf`. | step 5, step 7 | UI access rules ready |
| 14 | `initPAC` (L166) | Load `pac_config.json`; set `pacDefaultProxyPort`. May `log.Fatalf`. | step 5, step 7 | `pacStore` populated |
| 15 | `initLegacyAuthProviders` (L167) | LDAP / OIDC-introspection provider. May `log.Fatalf`. | step 9 (cfg) | `cfg.provider` set if configured |
| 16 | `initMetricsToken` (L168) | Set `metricsToken`. | step 5, step 7 | global set |
| 17 | `initCluster` (L169) | Cluster DB load; CP gRPC bind; HA standby/leader; DP startup. May `logger.Fatalf`. | step 3, 4, 5, 7, 8 | cluster/HA/DP runtime alive |
| 18 | `initConnAndRateLimit` (L170) | ConnLimit, IPFilter, RateLimit + cleanup goroutine. | step 5, 7, 8 | limiters configured; goroutine running |
| 19 | `initBlocklist` (L171) | Load blocklist file; optional feed syncer goroutine. May `logger.Fatalf`. | step 5, 7, 8 | `bl` populated; `blFeedSyncer` set |
| 20 | `initRootCA` (L172) | Root CA load/init; `caRuntime`; auto-rotation goroutine. | step 5, 7, 8 | `certMgr` ready or failed |
| 21 | `initPolicy` (L173) | Load policy rules JSON. May `logger.Fatalf`. | step 5, 7 | `policyStore` populated |
| 22 | `initURLCategories` (L174) | catStore + groups + SaaS feed + BadgerDB + UT1 seed + feed syncer. May `logger.Fatalf`. | step 5, 7, 8 | category stores ready; `communityDB` open |
| 23 | `initFileBlocking` (L175) | `fileBlocker`, `globalProfileStore`. | step 5, 7 | populated |
| 24 | `initSSLBypassAndDPI` (L176) | `sslBypass`, `dpiScanner`. May `logger.Fatalf`. | step 5, 7 | populated |
| 25 | `initRewriteAndDefaultAction` (L177) | Rewrite rules + default action (reads `policyStore.List()`). | step 21, step 5, 7 | `rewriter`, `defaultPolicyAction` set |
| 26 | `initScanning` (L178) | ClamAV + YARA + threat feed + sidecar. | step 5, 7, 8 | scanners configured; `s.scanSvc` set |
| 27 | `initUpstreamProxy` (L179) | `initUpstreamPool(s.fc)` — mutates `upstreamTransport`. | step 5 | `upstreamTransport` configured |
| 28 | `initCDR` (L180) | CDR flags + stores + client + health poller. | step 5, 7, 8 | CDR live if enabled |
| 29 | `initMTLSAndOCSP` (L181) | mTLS client cert + OCSP on `upstreamTransport`. | step 27, step 7 | upstream transport fully configured |
| 30 | `initBackgroundServices` (L182) | SSE + alert retry + update checker + cluster-update recovery. | step 7, 8 | all live |
| 31 | `initSOCKS5` (L183) | Optional SOCKS5 listener goroutine. | step 5, 7 | listener accepting (if enabled) |
| 32 | `initPersistentAdminState` (L184) | Config versioning + node groups + bandwidth + hit counters + admin settings. | step 8, step 21 | admin state hydrated |
| 33 | `startAdminUI` (L185) | `uiCfg*` + `go startUI(...)`. | step 12 + all prior stores | admin UI listening |
| 34 | `buildAndStartProxyServer` (L187) | Construct proxy `*http.Server` (no listen). | step 5, 9, 7 | `proxySrv` ready |
| 35 | `installSignalHandlers` (L188) | SIGINT/SIGTERM/SIGHUP + reload goroutine. | step 1, 7 | `quit` returned |
| 36 | `runProxyUntilShutdown` (L189) | `go proxySrv.ListenAndServe()` + block + graceful shutdown. | step 34, 35, all prior init | process exits cleanly |

### 2. Dependency classification (per edge)

| Edge | Class | Reason |
|---|---|---|
| 1 → 2 | HARD-DATA | `*s.resetPwUser`, `*s.uiUsersFile` |
| 2 → 3 | IMPLICIT | only meaningful if step 2 did not `os.Exit` |
| 3 → 4 | HARD-DATA | `runEnrollment` consults `clusterInsecure` for TLS |
| 4 → 5 | SOFT | no data flow from enrollment into config load |
| 5 → 6 | HARD-DATA | reads `s.fc.Proxy.UISANs`, `TrustForwardedHeaders` |
| 6 → 7 | SOFT | logger doesn't use UI SANs |
| 7 → 8 | SOFT | ordering convention only |
| 8 → 8a | HARD-RESOURCE | defer needs non-nil cancel |
| 8a → 9 | IMPLICIT | `initAuth` uses `logger` (real dep is step 7) |
| 9 → 10 | SOFT | session is unrelated to cfg auth ports |
| 10 → 11 | SOFT | observability is independent of session |
| 11 → 12 | SOFT | GeoIP has no data dep on obs |
| 12 → 13 | SOFT | UI access policy independent of GeoIP |
| 13 → 14 | SOFT | PAC independent of UI allowlist |
| 14 → 15 | SOFT | real dep is 15 → cfg (step 9) |
| 15 → 16 | SOFT | metrics token independent of auth providers |
| 16 → 17 | SOFT | cluster init reads only flags/config |
| 17 → 18 | SOFT | rate limit unrelated to cluster |
| 18 → 19 | SOFT | blocklist unrelated to rate limit |
| 19 → 20 | SOFT | root CA unrelated to blocklist |
| 20 → 21 | SOFT | policy unrelated to CA |
| 21 → 22 | SOFT | categories independent of policy |
| 22 → 23 | SOFT | file blocking unrelated to catStore |
| 23 → 24 | SOFT | SSL bypass / DPI independent of fileBlocker |
| 24 → 25 | HARD-DATA | step 25 reads `len(policyStore.List())` (set in step 21) |
| 25 → 26 | SOFT | scanning reads `s.fc.SecurityScan` only |
| 26 → 27 | SOFT | upstream reads `s.fc.Upstream.Proxies` |
| 27 → 28 | SOFT | CDR doesn't touch upstream |
| 28 → 29 | SOFT | real hard dep is 27 → 29 (both mutate `upstreamTransport`) |
| 29 → 30 | SOFT | background services unrelated to upstream TLS |
| 30 → 31 | SOFT | SOCKS5 independent of SSE/alerts |
| 31 → 32 | HARD-DATA | `RestoreHitCounts` writes `PolicyRule.HitCount` (real dep 21 → 32) |
| 32 → 33 | HARD-DATA | UI renders all stores; reads `s.geoDBVal` from step 12 |
| 33 → 34 | SOFT | proxy struct is independent of UI goroutine |
| 34 → 35 | SOFT | signal handler captures nothing from proxy |
| 35 → 36 | HARD-RESOURCE | `runProxyUntilShutdown` takes `proxySrv` + `quit` |

### 3. Critical path

Longest chain that cannot be reordered without behavior change:

1. `parseFlags` — defines flag pointers consumed by every later step.
2. → `loadFileConfigAndFlags` — dereferences flag pointers; writes `s.fc` + derived scalars.
3. → `initLogger` — reads `s.lPath`, `s.lMaxMB`, `s.fc.LogFormat`; assigns package global `logger`.
4. → `initLifecycleContext` — creates `appLifecycleCtx`/`appLifecycleCancel`.
5. → `defer appLifecycleCancel()` — needs non-nil cancel.
6. → `initAuth` — uses logger; populates `cfg`.
7. → `initPolicy` — reads `s.policyFile`; loads `policyStore`.
8. → `initRewriteAndDefaultAction` — reads `len(policyStore.List())` (main.go:909) to choose default allow vs deny.
9. → `initUpstreamProxy` — mutates `upstreamTransport` via `initUpstreamPool`.
10. → `initMTLSAndOCSP` — mutates the same `upstreamTransport` again (main.go:1125-1136).
11. → `initPersistentAdminState` — `RestoreHitCounts()` copies counts into rules loaded by step 7.
12. → `startAdminUI` — reads `s.geoDBVal` (from `initGeoIP`) + every hydrated store.
13. → `buildAndStartProxyServer` — sequential.
14. → `runProxyUntilShutdown` — `ListenAndServe` goroutine + shutdown sequence.

**Hard-fatal sites on this path** (failure aborts all downstream steps):
- `loadFileConfigAndFlags` (L5), `initLogger` (L7), `initPolicy` (L21), `runProxyUntilShutdown` (L36).

**Hard-fatal sites on non-critical branches**: `runEnrollmentMode`, `initCluster`, `initBlocklist`, `initURLCategories`, `initUIAccessPolicy`, `initPAC`, `initSSLBypassAndDPI`, `initLegacyAuthProviders`, `initAuth`.

### 4. Parallelization candidates (diagnostic only — not a proposal)

**Group A — pure file loaders, disjoint stores**: `initBlocklist`, `initRootCA`, `initPolicy`, `initURLCategories`, `initFileBlocking`, `initSSLBypassAndDPI`. Could run concurrently in principle; blocked today by (a) shared `logger.Fatalf` semantics that `os.Exit` mid-goroutine, (b) `initRewriteAndDefaultAction` must wait for `initPolicy`. **Risk: MEDIUM.**

**Group B — observability wiring**: `initObservability`, `initMetricsToken`, `initGeoIP`. Disjoint globals; fail-non-fatal. **Risk: LOW.**

**Group C — network listeners**: `initSOCKS5`, `initBackgroundServices` (multiple internal goroutines), scan-sidecar within `initScanning`. Already goroutine-based. **Risk: LOW.**

**Group D — CDR + scanning**: `initScanning` || `initCDR` (both goroutine-based; disjoint). `initMTLSAndOCSP` CANNOT parallelise with `initUpstreamProxy` (shared `upstreamTransport` write). **Risk: LOW/MEDIUM.**

**Group E — UI access config**: `initUIExtras`, `initUIAccessPolicy`, `initPAC`, `initSession`, `initMetricsToken`. Disjoint globals. **Risk: LOW.**

**Blocked from parallelization**:
- step 21 || step 25 (read-after-write on `policyStore.List()`).
- step 21 || step 32 (`RestoreHitCounts` writes rule counts).
- step 27 || step 29 (shared `upstreamTransport` write).
- step 17 branches on `s.enrolledConfig` + `clusterInsecure` → serial after steps 3, 4.
- step 33 `startAdminUI` — fan-in point for all stores.

## Side-Effects & Lifecycle

### 1. Side-effects inventory

| Function | Files opened | Network listeners / dial-on-init | Goroutines spawned | Env vars read | os.Exit paths |
|---|---|---|---|---|---|
| `parseFlags` | — | — | — | — | flag.Parse may `os.Exit` on bad flag |
| `handleOneShotCommands` | RW `/data/ui_users.json` (or `--ui-users-file`) | — | — | — | `os.Exit(0)` on success; `os.Exit(1)` ×3 |
| `setInsecureFlag` | — | — | — | — | — |
| `runEnrollmentMode` | writes cert/key/CA PEMs + `dp_enrollment.json` | dials CP HTTP/gRPC during `runEnrollment` | — | — | `log.Fatalf` on failure |
| `loadFileConfigAndFlags` | reads YAML config | — | — | — | `log.Fatalf` on parse error |
| `initUIExtras` | — | — | — | — | — |
| `initLogger` | opens rotating log at `s.lPath` | — | rotating logger may spawn internal goroutine | — | `log.Fatalf` on setup error |
| `initLifecycleContext` | — | — | — (creates ctx/cancel only) | — | — |
| `initAuth` | reads `*uiUsersFile` | — | — | — | `log.Fatalf` on SetAuth error |
| `initSession` | reads `*revocationsFile` | — | — | `CULVERT_SESSION_SECRET` (via `initSessionSecret`) | panic on bad env (inside `initSessionSecret`) |
| `initObservability` | opens audit JSONL + rotating request log | dials syslog UDP/TCP; configures OTLP HTTP client | — | — | — |
| `initGeoIP` | opens MaxMind mmdb | — | — | — | — |
| `initUIAccessPolicy` | reads `IdPProfilesFile` | — | — | — | `log.Fatalf` on IdP load error |
| `initPAC` | RW `pac_config.json` | — | — | — | `log.Fatalf` on PAC load error |
| `initLegacyAuthProviders` | — | (LDAP/OIDC dial on use, not init) | — | — | `log.Fatalf` on config error |
| `initMetricsToken` | — | — | — | — | — |
| `initCluster` | RW `cluster.json`; reads `enrollmentConfigFile`; HA config | **CP gRPC bind + `srv.Serve` goroutine**; DP dials + **5 DP goroutines** (`pollLoop`, `metricsLoop`, `rateLimitGossipLoop`, `revocationSyncLoop`, `auditPushLoop`) + `dpCertRenewalLoop`; `globalHA.StartAsStandby` → `standbyLoop`; `globalClusterStore.StartHeartbeatMonitor` | 8 goroutines total | — | `logger.Fatalf` on CP bind; `logger.Fatalf` in `startDataPlane` on client creation |
| `initConnAndRateLimit` | — | — | rate-limit cleanup goroutine (`rlCtx` child of `appLifecycleCtx`); cancel stored on `s.rlCleanupCancel` | — | — |
| `initBlocklist` | reads `s.blPath` | HTTP GET on feed URL (inside goroutine) | `blFeedSyncer.Start(appLifecycleCtx)` | — | `logger.Fatalf` on load error |
| `initRootCA` | RW CA bundle at `caPathVal` | — | `StartCAAutoRotation(appLifecycleCtx, …)` — detached via ctx.Done | **`CULVERT_CA_PASSPHRASE`** | — (warnings only) |
| `initPolicy` | reads `polPath` | — | — | — | `logger.Fatalf` on load error |
| `initURLCategories` | RW `categories.json`; BadgerDB at `*catFeedDB`; RW `category_groups.json`; `catStore.Save()` on seed | — | `feedSyncer.Start(appLifecycleCtx)` if `catFeedDB` set | — | `logger.Fatalf` on catStore / BadgerDB open |
| `initFileBlocking` | RW `fileblock.json` + `fileprofiles.json` | — | — | — | — |
| `initSSLBypassAndDPI` | RW SSL bypass file + content scan file | — | — | — | `logger.Fatalf` ×4 |
| `initRewriteAndDefaultAction` | — | — | — | — | — |
| `initScanning` | RW `scan_exclusions.json`; threat feed DB file; seedYARARules reads `/app/yara` | **scan sidecar TCP listener** (`ss.server.Serve` goroutine) | `globalThreatFeed.Start(appLifecycleCtx)`; scan sidecar goroutine (detached, no ctx) | — | — |
| `initUpstreamProxy` | — | — | **upstream health-check goroutine** (main.go:1553) — detached, `for range t.C`, **NO context cancellation** | — | — |
| `initCDR` | RW `/data/cdr_instances.json`, `/data/cdr_policies.json`; `/data/cdr_enabled` sentinel | `initCDRClient` dials Sluice gRPC with TOFU | `startCDRHealthPoller(appLifecycleCtx)` | — | — |
| `initMTLSAndOCSP` | reads client cert/key files | — | — | — | — (log-only) |
| `initBackgroundServices` | reads alert-retry file; writes `/data/version.txt`, `/data/updater_token.txt` | — | **SSE broadcaster** (no ctx, runs forever); `startAlertRetryLoop(appLifecycleCtx)`; `startUpdateChecker(appLifecycleCtx)`; `recoverClusterUpdate()` inline | — | — |
| `initSOCKS5` | — | **`go startSOCKS5(port)`** binds `:port`, unbounded `Accept` loop | SOCKS5 accept loop — **detached, NO ctx, NO shutdown** | — | `logger.Fatalf` on listen error |
| `initPersistentAdminState` | reads config_versions dir + node_groups.json + bandwidth.json + hit_counters.json + admin_settings.json | — | `startHitCounterPersistence(appLifecycleCtx, …)` with **final Save on Done** | — | — |
| `startAdminUI` | reads cert/key files if provided; generates self-signed TLS in memory otherwise | **`go startUI(...)`** binds HTTP(S) on `s.uPort` | admin UI goroutine — **detached, NO explicit Shutdown** | `CULVERT_PUBLIC_IP` (via `selfSignedTLS`) | `logger.Fatalf` inside `startUI` ×3 |
| `buildAndStartProxyServer` | — | — (listener deferred) | — | — | — |
| `installSignalHandlers` | — | — | **SIGHUP reload goroutine** — `for range sighup`, **never terminates** | — | — |
| `runProxyUntilShutdown` | closes logCloser, requestLogCloser, communityDB, globalSyslog on shutdown | `go proxySrv.ListenAndServe()` binds `:s.pPort` | proxy server goroutine — stopped by `proxySrv.Shutdown` | — | `logger.Fatalf("Proxy error…")` on unexpected server error |

### 2. Background-service lifecycle table

| Service | Started by | Cancellation signal | Stopped by | Symmetric? |
|---|---|---|---|---|
| Rate-limit cleanup | `initConnAndRateLimit` | `rlCtx` (child of `appLifecycleCtx`) | `s.rlCleanupCancel()` **and** `appLifecycleCancel()` in `runProxyUntilShutdown` | YES |
| Blocklist feed syncer | `initBlocklist` → `blFeedSyncer.Start(appLifecycleCtx)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| CA auto-rotation | `initRootCA` → `StartCAAutoRotation(appLifecycleCtx, …)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| URL-category BadgerDB feed syncer | `initURLCategories` → `feedSyncer.Start(appLifecycleCtx)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()`; BadgerDB itself closed at L1340 | YES |
| Threat feed syncer | `initScanning` → `globalThreatFeed.Start(appLifecycleCtx)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| Scan microservice sidecar | `initScanning` → `go s.scanSvc.Start()` | — (uses `http.Server.Shutdown`) | `s.scanSvc.Shutdown(ctx)` at L1308 (30 s) | YES |
| CDR client | `initCDR` → `initCDRClient` | explicit `shutdownCDRClient` | `shutdownCDRClient()` at L1294 (before `appLifecycleCancel`) | YES |
| CDR health poller | `initCDR` → `startCDRHealthPoller(appLifecycleCtx)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| **SSE broadcaster** | `initBackgroundServices` → `startSSEBroadcaster()` | **none — bare `for range ticker.C`** | **never** — process exit | **NO** |
| Alert retry loop | `initBackgroundServices` → `go startAlertRetryLoop(appLifecycleCtx)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| Update checker | `initBackgroundServices` → `go startUpdateChecker(appLifecycleCtx)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| Hit-counter persistence | `initPersistentAdminState` → `startHitCounterPersistence(appLifecycleCtx, …)` | `appLifecycleCtx.Done()` — performs **final Save on Done** | `appLifecycleCancel()` | YES |
| **SOCKS5 listener** | `initSOCKS5` → `go startSOCKS5(port)` | **none — bare `ln.Accept()`** | **never** — listener handle lost | **NO** |
| **Admin UI (`startUI`)** | `startAdminUI` → `go startUI(...)` | **none — blocking `ListenAndServe[TLS]`; `*http.Server` not exported** | **never** | **NO** |
| Proxy server | `runProxyUntilShutdown` `go proxySrv.ListenAndServe()` | `proxySrv.Shutdown(ctx)` | `proxySrv.Shutdown(ctx)` at L1311 + tunnel drain (L1318) | YES |
| **SIGHUP reload loop** | `installSignalHandlers` (L1255) | **none — `for range sighup`; channel never closed** | **never** | **NO** |
| CP gRPC server | `initCluster` → `enableControlPlane` → `go srv.Serve(ln)` | `srv.GracefulStop()` | `StopControlPlaneGRPC()` at L1289 (before `appLifecycleCancel`) | YES |
| Cluster heartbeat monitor | `enableControlPlane` → `StartHeartbeatMonitor(appLifecycleCtx.Done())` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| HA leader/standby loop | `initCluster` | `h.stopCh` + `ctx.Done` | `globalHA.Stop()` at L1286 | YES |
| DP loops (poll/metrics/rate-limit/revocation/audit + cert renewal) | `initCluster` → `startDataPlane` → `dpClient.Run(ctx, …)` + `go dpCertRenewalLoop(ctx, …)` | `appLifecycleCtx.Done()` | `appLifecycleCancel()` | YES |
| **Upstream health-check loop** | `initUpstreamProxy` → `initUpstreamPool` (L1553) `go func() { for range t.C … }()` | **none — no context** | **never** | **NO** |

Persistent-store save-on-shutdown:
- `catStore` saved mid-init (UT1 seeding); not on shutdown.
- 15 stores rely on save-on-write: `globalScanExclusions`, `fileBlocker`, `globalProfileStore`, `policyStore`, `sslBypass`, `dpiScanner`, `bl`, `globalNodeGroups`, `globalBandwidth`, `globalCategoryGroups`, `sessionRevoked`, `cfg` UI users, `cdrInstances`, `cdrPolicyStore`, `globalClusterStore`. No final Save on shutdown.
- Hit counters: **only store** with explicit final Save on `ctx.Done`.
- `auditCloser` / `auditLogFile`: assigned at init but **not closed** in `runProxyUntilShutdown`.

### 3. Symmetry audit

All findings below are present on commit `5b35724`. PR2 is mechanical extraction only; every asymmetry is **PRE-EXISTING** unless stated otherwise.

1. **SSE broadcaster has no stop path.** `startSSEBroadcaster` spawns a detached goroutine with `time.NewTicker(1s)` + bare `for range ticker.C`. **Severity: LOW** — cheap, exits with process. **PRE-EXISTING.**
2. **SOCKS5 listener has no shutdown.** `startSOCKS5` binds inside the goroutine and loops `ln.Accept()`; listener handle is lost; never closed. New SOCKS5 CONNECTs may still be accepted after proxy server is stopped; not drained by the 15 s tunnel-drain loop. **Severity: MEDIUM.** **PRE-EXISTING.**
3. **Admin UI `http.Server` is never shut down.** `startAdminUI` spawns `go startUI(...)` but the `*http.Server` is local inside `startUI`; no package-level handle. In-flight SSE/long-poll connections closed abruptly by process exit. **Severity: MEDIUM.** **PRE-EXISTING.**
4. **SIGHUP goroutine never exits.** Bare `for range sighup`; channel never closed; `signal.Stop` never called. **Severity: LOW.** **PRE-EXISTING.**
5. **Upstream health-check goroutine has no cancellation.** Inside `initUpstreamPool` (main.go:1553) — `for range t.C` with no context. **Severity: LOW.** **PRE-EXISTING.**
6. **Audit log file (`auditCloser`) is never closed.** `runProxyUntilShutdown` closes `requestLogCloser`, `logCloser`, `globalSyslog`, `communityDB` — **not** `auditCloser`. On SIGKILL timeout, last batch could be lost; however `auditLog` writes are synchronous JSONL appends so in practice each entry is already on disk — the leak is the OS file handle, not data. **Severity: MEDIUM.** **PRE-EXISTING.**
7. **Persistent admin stores rely on save-on-write only.** 15 stores (listed above) have no shutdown Save. Save-on-write makes this LOW in practice. `globalClusterStore` heartbeat/liveness transitions that occur in-memory between the last `saveLocked` and shutdown can be lost. **Severity: LOW** for most; **MEDIUM** for clusterStore heartbeat. **PRE-EXISTING.**
8. **Scan service `Start` goroutine swallows errors.** `go func() { if err := s.scanSvc.Start(); err != nil { logger.Printf(...) } }()`; no external coordination if `Serve` fails post-`Listen`. `s.scanSvc.Shutdown(ctx)` guards `ss.server == nil` so shutdown is safe. **Severity: LOW.** **PRE-EXISTING.**
9. **`s.scanSvc.Shutdown` runs after `appLifecycleCancel`.** Order in `runProxyUntilShutdown`: L1297 cancels lifecycle; L1308 shuts down sidecar. If sidecar handlers ever use `appLifecycleCtx` for internal work, contexts are already cancelled. Today's handlers don't. **Severity: LOW.** **PRE-EXISTING.**
10. **`runEnrollment` happens pre-logger.** Uses stdlib `log.Fatalf`, not `logger.Fatalf`; output bypasses the rotating logger. **Severity: LOW** (cosmetic). **PRE-EXISTING.**
11. **PR2 observation (not a leak).** Extraction did not introduce new goroutines or file opens. `appLifecycleCtx`/`appLifecycleCancel` are now assigned inside `initLifecycleContext` with the `defer appLifecycleCancel()` kept in `main()` for panic safety (main.go:159, 365). **No new asymmetry introduced by PR2.**

No unaccounted init-time side effect or resource was found beyond the items above.
