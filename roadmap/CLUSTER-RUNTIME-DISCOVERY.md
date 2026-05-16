# P6.4 — Cluster Runtime Ownership Discovery

**Status:** Discovery only. No production code change, no tests.
**Scope:** `initCluster`, `enableControlPlane`, `startDataPlane`, `globalClusterStore` (enrollment + node trust + revocations), `globalConfigStore` (CP config publish), `globalHA` (HA leader/standby), CP/DP gRPC lifecycle, heartbeat monitor, every long-lived cluster goroutine, the `applyConfigSnapshot` DP-side apply path (the centerpiece for P3.4), HA bundle replication, rolling-update orchestrator (`runClusterUpdate`), and the admin-API surface that mutates any of them.
**SPOF target:** none on the existing `RUNTIME-OWNERSHIP.md` SPOF list (Phase 6 is discovery-only by design); the relevant SPOF axes here are the **detached goroutine** family (S4-class), the **mutable global state** family (S1-class), and the **state durability** family (S7-class — P3.4 territory).
**This discovery unblocks P3.4** (cluster heartbeat flush). Per `RUNTIME-OWNERSHIP.md` §4, P3.4 is **lab-required** and was gated on this discovery merging.
**Already-shipped scope to NOT re-cover:** P6.3 owns the Root CA + cluster CA + CP/DP TLS plumbing (`buildServerTLS`, `cpTLSConfig`, `globalClusterCA` rotation, `rebuildCPCertPool`, HA `CACertPEM`/`CAKeyEncrypted` bundle fields, deprecated `CAKeyPEM` plaintext fallback). P6.4 references those files where the cluster runtime crosses them but does not re-analyze them.
**Out of P6 scope** (per `RUNTIME-OWNERSHIP.md` §2): S8 backup/restore of `cluster.json` and the cluster CA bundle — owned by D1.3 / D1.6.

---

## 1. Executive verdict

`initCluster` (`main.go:597–668`) is a small dispatcher: depending on flags + `fc.Cluster.*` fields, the node either stays standalone, joins HA as a standby (via `globalHA.StartAsStandby` at `ha.go:135` → `enableControlPlane` on promotion), promotes itself to Control Plane (`enableControlPlane` at `main.go:1766–1792` → `StartControlPlaneGRPC` at `controlplane.go:974` + `globalClusterStore.StartHeartbeatMonitor` at `enrollment.go:567`), or enrolls as a Data Plane (`startDataPlane` at `main.go:1986–2008` → `DataPlaneClient.Run` at `controlplane.go:1181` which spawns five background loops + `dpCertRenewalLoop` at `main.go:2006`). Shutdown ordering across the cluster domain is **clean**: `ha-stop=10`, `control-plane-grpc-stop=20`, `cdr-client-shutdown=30`, `app-lifecycle-cancel=40` are all in the early-shutdown registry (`main.go:1324–1327, 1356–1376`), and `app-lifecycle-cancel` is the gate that drains every DP / HA / heartbeat goroutine via `appLifecycleCtx.Done()`.

**The single most important finding for P3.4 is the per-store breakdown of `applyConfigSnapshot` at `controlplane.go:1443–1612`.** Of the 21 sub-stores mutated when a DP node receives a `ConfigSnapshot` from its CP (or when an HA standby applies a bundle from its leader), **only `policyStore` and `pacStore` persist** after the apply (verified: `policyStore.Save()` at `controlplane.go:1491` per the shipped P3.2b fix; `pacStore.Set` internally persists per `pac.go`). **Every other store mutates memory only.** Concretely: `bl`, `ipf`, `rl`, `sslBypass`, `catStore`, `globalProfileStore`, `rewriter`, `dpiScanner`, `connLimiter`, `globalThreatFeed`, `globalBandwidth`, `globalCategoryGroups`, `fileBlocker`, `globalOTLP`, `globalNodeGroups`, plus the `sessionSecret` and CA-fingerprint direct writes, all lose state on DP restart between heartbeats. This is the consolidated P3.4 work surface — see §8 for the full table.

**Two candidate concurrent-mutation surfaces are flagged for follow-up evidence rather than classified as safe.** First, P6.3 CA-7 (`cpTLSConfig.cfg.ClientCAs` swap vs stdlib TLS handshake read) is already filed and remains unverified under `-race`. Second, **CL-R-10 (new this discovery)**: `DataPlaneClient.c.conn` is read by `c.call()` at `controlplane.go:1396` **without** taking `c.mu`, while `c.connect()` writes `c.conn = conn` at `:1151` (called from `c.failover()` under `c.mu.Lock` at `:1162`). Five long-lived DP goroutines (`pollLoop`, `metricsLoop`, `rateLimitGossipLoop`, `revocationSyncLoop`, `auditPushLoop`) all invoke `c.call()` concurrently. If a failover swaps `c.conn` while a sibling loop is mid-`call`, this is an unsynchronized read/write under the Go memory model — same shape as the CA-7 concern. Needs a focused race test before being classified as safe (see §10 risk row + §13 CL-11). **The remaining surfaces** (per-store RWMutex on each `applyConfigSnapshot` sub-store, `ClusterStore.mu` for enrollment, `globalHA.mu` for HA state) are sound. **Seven classes of pre-existing gaps are tracked separately** in §13: the consolidated P3.4 apply-then-persist gap; the absence of `saveConfigVersion` from every cluster admin handler (parallel of P6.3 CA-1); the `runClusterUpdate` detached orchestrator goroutine spawned without a parent context; the absence of split-brain prevention in HA failover; three non-durable persistence paths (`ha_config.json`, `dp_enrollment.json`, `cluster_update.json`); `ClusterStore.Save()` using RLock instead of Lock (acknowledged in source as "worth re-evaluating in a follow-up"); and the new CL-R-10 race candidate above.

**Two intentional-but-undocumented behaviors** are recorded for visibility: there is no background HA-leader replication push loop (standby pulls; leader is passive on `HASync` RPC), and `applyHotReload` does not touch any cluster state.

What is **NOT** uncovered by this discovery:

- No undocumented persistence path beyond `cluster.json`, `ha_config.json`, `dp_enrollment.json`, `cluster_update.json`, the cluster-CA pair, and the `config_versions/v{N}.json` rollback directory.
- No undocumented mutation surface — every cluster admin handler is in `ui_cluster.go` or `update_cluster.go`.
- No undocumented long-lived goroutine — every persistent goroutine listed in §5 has a documented spawn site and cancellation path.
- No undocumented inbound RPC — the gRPC service is `culvert.ControlPlane` with handlers in `controlplane.go`.

---

## 2. Component inventory

### 2.1 `initCluster(s *startupState)` — the startup dispatcher

Declared at `main.go:597–668`. Called from the `main()` startup sequence; sets `clusterRole.role = "standalone"` at `main.go:599` as the default. Reads flags / `fc.Cluster.*` fields and dispatches:

| Branch | Trigger | Action |
|---|---|---|
| Standalone | no `--cp-grpc-addr`, no `--dp-cp-addr`, no `--ha-join` | default — no further cluster init |
| HA Standby | `--ha-join` + `--ha-token` both present | `globalHA.StartAsStandby(...)` at `main.go:624`, with `enableControlPlane` as the promotion callback |
| Control Plane | `--cp-grpc-addr` set OR `fc.Cluster.Role == "control-plane"` | `initClusterCA(clusterDBPath)` + `enableControlPlane(...)` at `main.go:1778–1779` |
| Data Plane | `--dp-cp-addr` set (or persisted `dp_enrollment.json` from prior enrollment) | `startDataPlane(appLifecycleCtx, addr, nodeID, certFile, keyFile, caFile)` at `main.go:644–667` |

Position in the startup ordering: `initCluster(s)` is at `main.go:597`; it loads `globalClusterStore` from disk at `main.go:606` before the dispatch.

### 2.2 `enableControlPlane(grpcAddr, certFile, keyFile, caFile, clusterDBPath string) error`

Declared at `main.go:1766–1792`. Re-entrant guard at `:1770` (returns error if already CP). Side effects:

- `initClusterCA(clusterDBPath)` at `:1778` — bootstraps the cluster CA if missing (P6.3 territory).
- `StartControlPlaneGRPC(grpcAddr, certFile, keyFile, caFile)` at `:1779` (declared at `controlplane.go:974`) — listens, spawns `go srv.Serve(ln)` at `controlplane.go:1033`.
- Stores `clusterRole.{role, grpcAddr, certFile, keyFile, caFile}` at `:1784–1788` under `clusterRoleMu` lock.
- `globalClusterStore.StartHeartbeatMonitor(appLifecycleCtx.Done())` at `:1789` (declared at `enrollment.go:567`) — spawns the heartbeat ticker goroutine.

Safe to call from admin API (`apiClusterMode` at `ui_cluster.go:50`) — same code path as the boot-time call.

### 2.3 `startDataPlane(ctx context.Context, addr, nodeID, certFile, keyFile, caFile string)`

Declared at `main.go:1986–2008`. Sets `clusterRole.role = "data-plane"` at `:1987`, constructs `*DataPlaneClient` via `NewDataPlaneClient(...)` at `:1999`, stores it on `activeDPClient atomic.Pointer[DataPlaneClient]` (declared at `controlplane.go:1402`) at `:2003`, sets `clusterRoleIsDP.Store(true)` at `:2004`, and calls `dpClient.Run(ctx, 30*time.Second)` at `:2005`. `Run` spawns FIVE long-lived goroutines (see §5). Additionally spawns `go dpCertRenewalLoop(ctx, ...)` at `:2006` for cluster-CA rotation–triggered cert renewal.

### 2.4 `globalClusterStore` — `*ClusterStore`

Declared at `enrollment.go:113–119`. Struct (`enrollment.go:106–111`):

- `mu sync.RWMutex`.
- `st ClusterState` (declared at `enrollment.go:47–53`): `Nodes map[string]*EnrolledNode`, `Tokens map[string]*EnrollToken`, `Revoked []RevokedCert`, `Version int64`, `CARotation *CARotationState`.
- `path string` — typically `/data/cluster.json` (or `--cluster-db` override).
- `heartbeatCount int` — throttles disk writes; persists every 10th heartbeat per `UpdateNodeSeen` at `enrollment.go:360–376`.

Per-record types: `EnrolledNode` at `enrollment.go:68–79`, `EnrollToken` at `enrollment.go:82–92`, `RevokedCert` at `enrollment.go:95–101`. Tokens are stored as SHA-256(plaintext) hex; plaintext never persists.

### 2.5 `globalConfigStore` — `*ConfigStore`

Declared at `controlplane.go:204`. Struct (per call-site inspection at `:207–`):

- `mu sync.RWMutex`.
- `snap ConfigSnapshot` — the current snapshot.
- `version int64` — incremented on every `Update`.
- `subs []chan struct{}` — subscriber channels, notified on each update.

In-memory publish hub. **Does NOT persist to disk** itself; the `config_versions/v{N}.json` rollback directory is written by `saveConfigVersion(actor, action)` (per CLAUDE.md and configversion.go convention) which is a separate, CP-admin-initiated path.

### 2.6 `clusterRole` + `clusterRoleMu`

Declared at `controlplane.go:449–460`:

```go
var (
    clusterRoleMu sync.RWMutex
    clusterRole   struct {
        role     string // "standalone", "control-plane", "data-plane"
        grpcAddr string
        nodeID   string
        grpcSrv  *grpc.Server
        certFile string
        keyFile  string
        caFile   string
    }
)
```

Used as the single source of truth for "what mode is this node in." Read by `apiClusterStatus` (`ui_cluster.go:14`) and the gRPC server registration logic. Written by `initCluster`, `enableControlPlane`, `startDataPlane`.

**Lock convention — NOT uniform.** Most writers and readers route through `clusterRoleMu` (`enableControlPlane` at `main.go:1767–1768` takes `Lock` + `defer Unlock`; `apiClusterStatus` and the diagnostics path use `RLock`). **Exceptions exist:** (a) `StartControlPlaneGRPC` writes `clusterRole.grpcSrv = srv` at `controlplane.go:1031` **without** taking `clusterRoleMu` — the write is **transitively protected** because the sole caller is `enableControlPlane` at `main.go:1779` which holds the lock; (b) `StopControlPlaneGRPC` reads `clusterRole.grpcSrv` at `controlplane.go:1044, :1046` **also without** taking `clusterRoleMu`, relying on the shutdown-order invariant that no concurrent writer can run (`StopControlPlaneGRPC` is invoked from the `control-plane-grpc-stop=20` early hook, after `enableControlPlane` has released its lock and well before any other mutation path could fire). See §10 CL-R-6 for the risk assessment.

### 2.7 `globalHA` — `*HAState`

Declared at `ha.go:45`. Struct (per `ha.go:30–43`):

- `mu sync.RWMutex`.
- `role string` — `"leader"`, `"standby"`, or empty.
- `token string` — 32-byte random, base64-encoded HA token (generated at `ha.go:316–328`).
- `peerAddr string` — leader's address if standby, standby's if leader.
- `since time.Time` — role-acquired timestamp.
- `stopCh chan struct{}` — closed by `Stop()` (`ha.go:269–276`) to signal standby loop exit.

### 2.8 `activeDPClient` — `atomic.Pointer[DataPlaneClient]`

Declared at `controlplane.go:1402`. Holds the DP node's gRPC client when running as DP. Set in `startDataPlane` at `main.go:2003`; consumed by HA standby to discover the current leader's address during failover.

### 2.9 `ClusterUpdateState` — rolling-update progress

Declared at `update_cluster.go:29–46`. Holds per-node update status and the orchestrator state machine (phases `canary`/`canary_soak`/`updating_dps`/`updating_cp`/`complete`/`failed`/`halted`/`cp_rolled_back`/`auto_rollback`). Persisted to `/data/cluster_update.json` via `persist()` at `:78–94`.

---

## 3. Ownership graph

### 3.1 Startup writers — single-threaded, pre-listener-accept

| Writer | Touches | Location |
|---|---|---|
| `initCluster` | `clusterRole.role/.nodeID` + dispatches to one of the next three | `main.go:599–668` |
| `globalClusterStore.Load(path)` | `globalClusterStore.{st, path}` under `mu.Lock` | `main.go:606` → `enrollment.go:122` |
| `enableControlPlane` | `clusterRole.{role,grpcAddr,certFile,keyFile,caFile}` under `clusterRoleMu.Lock`; starts gRPC server + heartbeat monitor | `main.go:1766–1792` |
| `startDataPlane` | `clusterRole.role/.grpcAddr/.nodeID`; `activeDPClient` atomic; spawns 5 + 1 goroutines | `main.go:1986–2008` |
| `globalHA.StartAsStandby` | `globalHA.{role,token,peerAddr,since,stopCh}` under `mu.Lock`; spawns standby loop | `ha.go:118–135` |
| `globalHA.EnableAsLeader` | same fields | `ha.go:80–115` |
| `recoverClusterUpdate` (if `cluster_update.json` shows in-progress update on boot) | re-spawns `runClusterUpdate` orchestrator | `update_cluster.go:884–` |

### 3.2 Runtime writers — post-listener-accept; concurrent with hot path

| Path | Writes | Trigger | Synchronisation |
|---|---|---|---|
| `apiClusterMode` POST | `enableControlPlane(...)` → mode promotion at runtime | Admin API (`ui_cluster.go:50`) | `clusterRoleMu.Lock` for state assignment; `auditAdd(action="cluster.enable-cp")` at `:94` |
| `apiClusterTokenCreate` POST | `globalClusterStore.GenerateToken(...)` → `Save()` | Admin API (`ui_cluster.go:143`) | `ClusterStore.mu.Lock`; `auditEvent(action="enrollment.token_created")` at `:208` |
| `apiClusterTokens` DELETE | `globalClusterStore.DeleteToken(hash)` → `Save()` | Admin API (`ui_cluster.go:106`) | `ClusterStore.mu.Lock` |
| `apiClusterRevoke` POST | `globalClusterStore.RevokeNode(nodeID, reason)` → `Save()` | Admin API (`ui_cluster.go:234`) | `ClusterStore.mu.Lock`; `auditEvent(action="enrollment.node_revoked")` at `:271` |
| `apiClusterCA` POST (P6.3 territory) | `globalClusterCA.ImportCA(certPEM, keyPEM)` | Admin API (`ui_cluster.go:279`) | covered by P6.3 |
| `apiClusterLabels` POST | `globalClusterStore.SetNodeLabels(nodeID, labels)` → `Save()` | Admin API (`ui_cluster.go:335`) | `auditEvent(action="cluster.labels")` at `:449` |
| `apiClusterDrain` POST | `globalClusterStore.SetNodeDraining(nodeID, draining)` → `Save()` | Admin API (`ui_cluster.go:471`) | `auditEvent` at `:484` with action `cluster.drain` or `cluster.undrain` |
| `apiClusterHA` POST | `globalHA.EnableAsLeader(peerAddr)` or `globalHA.Stop()` | Admin API (`ui_cluster.go:516`) | `globalHA.mu.Lock` |
| `apiClusterUpdate` POST | `startClusterUpdate(targetTag, initiator, budget)` → `go runClusterUpdate()` | Admin API (`update_cluster.go:917`, `:272`, `:313`) | `auditEvent(action="cluster_update.start")` at `:983` |
| Heartbeat monitor `UpdateNodeSeen` | mutates `EnrolledNode.{LastSeen, Status}` under `mu.Lock`; `Save()` every 10th call | DP gRPC `Heartbeat` RPC | `ClusterStore.mu.Lock` |
| Enrollment `ValidateAndConsumeToken` | marks token consumed; persists | DP `Enroll` RPC | `ClusterStore.mu.Lock`; persists at `enrollment.go:274` |
| DP `applyConfigSnapshot` (the P3.4 surface) | 21 sub-store mutations | DP heartbeat poll + HA standby sync | per-store RWMutex; **only `policyStore` and `pacStore` persist after** — see §8 |
| HA standby `syncFromLeader` | `globalClusterStore.ImportFullState(...)`, `globalClusterCA.ImportCASilent(...)`, `applyConfigSnapshot(bundle.Config)` | 5s ticker (`ha.go:148`) | each store's lock; **applyConfigSnapshot has NO version guard** — P3.2c |
| `runClusterUpdate` orchestrator | mutates `ClusterUpdateState` + node-status fields | `apiClusterUpdate` POST | `ClusterUpdateState.mu sync.Mutex` |

**`saveConfigVersion` coverage on cluster admin handlers: ZERO.** Verified by `grep "saveConfigVersion" ui_cluster.go update_cluster.go` returning no hits. Every cluster admin mutation is in the audit ring but **absent from the config-version snapshot tier**. Parallels P6.3 CA-1 exactly. See §13 CL-1.

### 3.3 Hot-path readers — proxy-side

| Reader | Reads | Location |
|---|---|---|
| Hot-path policy / blocklist / rate-limit / DPI etc. | the 21 sub-stores that `applyConfigSnapshot` populates | proxy.go (per-store hot paths) |
| `clusterRole.role` reads (audit, admin API, diagnostics) | `clusterRole` under `clusterRoleMu.RLock` | `controlplane.go`, `ui_cluster.go`, `diagnostics.go` |
| `clusterRoleIsDP.Load()` (atomic) | mode-aware behaviour switches | various |

### 3.4 Inbound gRPC RPC readers

| Reader | Reads | Location |
|---|---|---|
| `GetConfig` RPC | `CurrentConfigSnapshot()` at `controlplane.go:1616–1688` | called by every DP every 30s; line `:938` for HASync |
| `Heartbeat` RPC | updates `globalClusterStore` via `UpdateNodeSeen` | every 30s per DP |
| `Enroll` RPC | validates + consumes token, signs CSR via `globalClusterCA.SignCSR` | per enrolling DP, once |
| `RenewCert` RPC | signs new CSR; ships new cluster CA cert | per DP on rotation |
| `HASync` RPC | builds `HAStateBundle` (cluster state + CA + Config) | called by standby every 5s |
| `PushMetrics` / `PushAudit` / `PushRevocation` / etc. | reads in addition to writes | per DP, various cadences |

---

## 4. Runtime mutation authority map

The cluster runtime is multi-writer in a way prior P6 surfaces are not — admin API, heartbeat monitor, HA standby sync, and the DP poll loop all mutate state concurrently. Synchronization is per-store rather than global.

### 4.1 Mutation authority matrix

| Mutator | `globalClusterStore.st` | `globalConfigStore.snap` | `globalHA` | `clusterRole` | `applyConfigSnapshot` sub-stores | `ClusterUpdateState` | Synchronised? |
|---|---|---|---|---|---|---|---|
| Startup: `initCluster` + dispatch | ✓ (Load) | – | ✓ | ✓ | – | ✓ (recover) | N/A (single-threaded) |
| Admin: token/node CRUD | ✓ | – | – | – | – | – | ✅ `ClusterStore.mu` |
| Admin: `apiClusterMode` | – | – | – | ✓ | – | – | ✅ `clusterRoleMu` |
| Admin: `apiClusterHA` | – | – | ✓ | – | – | – | ✅ `globalHA.mu` |
| Admin: `apiClusterUpdate` | – | – | – | – | – | ✓ | ✅ `ClusterUpdateState.mu` |
| Admin: any config mutator (e.g. policy upload) → `globalConfigStore.Update(...)` | – | ✓ | – | – | – | – | ✅ `globalConfigStore.mu` |
| CP gRPC: `Heartbeat` RPC | ✓ (UpdateNodeSeen) | – | – | – | – | – | ✅ |
| CP gRPC: `Enroll` / `RenewCert` | ✓ | – | – | – | – | – | ✅ |
| DP poll: `applyConfigSnapshot` | – | – | – | – | ✓ (21 stores) | – | per-store RWMutex |
| HA standby: `syncFromLeader` | ✓ (ImportFullState) | – | – | – | ✓ (via applyConfigSnapshot) | – | per-store RWMutex |
| Auto-rotation ticker (P6.3 territory) | – | – | – | – | – | – | – |
| Hot path: per-request | RLock | RLock (via subscribers) | RLock (admin status only) | RLock | per-store RLock | – | ✅ |

### 4.2 The cluster-specific concurrency surfaces

**SC-R-A: HA standby `applyConfigSnapshot` vs concurrent admin API mutator.** When the standby's 5s sync ticker fires and the leader's `HASync` returns a bundle whose `Config` contains, say, an old policy set, the standby calls `applyConfigSnapshot(bundle.Config)` at `ha.go:238`. Meanwhile, an admin on the (now-promoted, post-failover) same node could be issuing a policy mutation. Each sub-store's `ReplaceAll` / `Set` is atomic under its own write lock, but **the apply path is not transactional**: a reader between the policy swap and the bandwidth swap sees a half-applied snapshot. This is the same pre-existing pattern P6.2 §6 documented for DP scanner state. **Severity: LOW under steady-state** (rare interleaving); **future-fragility: MEDIUM** because the failure mode is silent and only appears under load.

**SC-R-B: `ClusterStore.Save()` uses RLock, allowing concurrent `Save()` calls.** Confirmed in source comment at `enrollment.go:159–162`:

> *"Uses RLock so concurrent admin-handler Save() calls do not block each other. atomicWriteFile keeps each write atomic on its own (unique tmp + rename), but switching to Lock for stronger serialization is worth re-evaluating in a follow-up."*

The atomicity is per-file (tmp + rename); two concurrent `Save()`s race only on which one's tmp file wins the rename. The on-disk JSON is always a complete state snapshot from one writer; the **loser's mutations are NOT lost** because the in-memory state is shared (last writer to acquire the marshal-time RLock + atomic-rename wins; both mutators' changes are present in `cs.st` before either marshals). Acknowledged as a future-fragility item in source. See §13 CL-6.

**SC-R-C: gRPC server accept loop vs `StopControlPlaneGRPC`.** `srv.GracefulStop()` at `controlplane.go:1046` drains in-flight RPCs before closing the listener. No race on `clusterRole.grpcSrv` pointer because the stop is single-threaded via the shutdown hook. **Severity: LOW (resolved).**

**SC-R-D: `cpTLSConfig.cfg.ClientCAs` swap vs stdlib TLS handshake read.** Already filed by P6.3 as **CA-7** (unverified under `-race`); not re-covered here.

---

## 5. Goroutine lifecycle ownership

Every long-lived cluster-domain goroutine and how it terminates.

### 5.1 CP-side goroutines

| Goroutine | Spawn site | Parent ctx | Cancellation | Shutdown hook |
|---|---|---|---|---|
| gRPC server accept loop | `go func() { srv.Serve(ln) }` at `controlplane.go:1033` | none (listener-bound) | `srv.GracefulStop()` in `StopControlPlaneGRPC` (`:1046`) | `control-plane-grpc-stop=20` at `main.go:1361–1364` |
| Heartbeat monitor | inside `globalClusterStore.StartHeartbeatMonitor(done)` at `enrollment.go:567–580` | `appLifecycleCtx.Done()` channel passed in | `<-done` select branch | implicit via `app-lifecycle-cancel=40` at `main.go:1373–1376` |
| Cluster-CA + Root-CA rotation ticker (P6.3 territory) | `ca.go:514–525` invoked from `main.go:721` | `appLifecycleCtx` | same | same |

### 5.2 DP-side goroutines (5 spawned by `DataPlaneClient.Run` + 1 by `startDataPlane`)

| Goroutine | Spawn site | Parent ctx | Cancellation |
|---|---|---|---|
| `pollLoop` (config sync) | `go c.pollLoop(ctx, interval)` at `controlplane.go:1182` | `ctx` from `startDataPlane` → `appLifecycleCtx` | `<-ctx.Done()` |
| `metricsLoop` | `go c.metricsLoop(ctx)` at `controlplane.go:1183` | same | same |
| `rateLimitGossipLoop` | `go c.rateLimitGossipLoop(ctx)` at `controlplane.go:1184` | same | same |
| `revocationSyncLoop` | `go c.revocationSyncLoop(ctx)` at `controlplane.go:1185` | same | same |
| `auditPushLoop` | `go c.auditPushLoop(ctx)` at `controlplane.go:1186` | same | same |
| `dpCertRenewalLoop` | `go dpCertRenewalLoop(ctx, ...)` at `main.go:2006` | same | same; also listens on `caRotationNotify` for immediate renewal |

All six are parented to `appLifecycleCtx` and exit cleanly via the order-40 cancel.

### 5.3 HA goroutines

| Goroutine | Spawn site | Parent ctx | Cancellation |
|---|---|---|---|
| HA standby loop (`h.standbyLoop`) | `go h.standbyLoop(ctx, ...)` at `ha.go:135` | `ctx` from `StartAsStandby(...)` → `appLifecycleCtx` | `<-ctx.Done()` at `ha.go:167` AND `<-h.stopCh` at `ha.go:169`; redundant cancellation paths |
| HA leader replication push loop | — | — | **Does not exist.** Leader is passive on `HASync`. The standby pulls every 5s (`ticker := time.NewTicker(5 * time.Second)` at `ha.go:148`). |

`globalHA.Stop()` at `ha.go:269–276` is called from the `ha-stop=10` early hook (`main.go:1356–1359`). It closes `h.stopCh` under `h.mu.Lock`, then sets `h.stopCh = nil`. **Does NOT wait for the standby loop to acknowledge exit** (fire-and-forget). The loop exits within one tick because both `<-ctx.Done()` and `<-h.stopCh` are in the same select.

### 5.4 Rolling-update orchestrator — **detached, no parent context**

| Goroutine | Spawn site | Parent ctx | Cancellation |
|---|---|---|---|
| `runClusterUpdate` | `go runClusterUpdate()` at `update_cluster.go:313` | **none** | **No explicit cancellation path.** Loop exits on its own state-machine completion or on `Halt` signal via `ClusterUpdateState` mutation. |
| Per-request fire-and-forget sidecar trigger | `go func() { ... }` at `update_cluster.go:244`, commented `#nosec G118 — detached goroutine must outlive the gRPC request` | none (intentionally) | exits after one HTTP POST to local updater sidecar |

`runClusterUpdate` is the only long-lived cluster goroutine **not parented to `appLifecycleCtx` or owned by a shutdown hook**. This is structurally identical to P6.1 UC-3 (`globalSaaSFeed.syncLoop`). See §13 CL-3.

The per-request goroutine at `update_cluster.go:244` is intentionally detached per its `#nosec` comment — short-lived; not a leak surface.

---

## 6. Shutdown sequencing

The cluster domain occupies four of the five early-phase shutdown slots.

| Order | Hook name | Source line | What it does |
|---|---|---|---|
| 10 | `ha-stop` | `main.go:1356–1359` | calls `globalHA.Stop()` (`ha.go:269–276`) — closes `stopCh`, sets nil; fire-and-forget |
| 20 | `control-plane-grpc-stop` | `main.go:1361–1364` | calls `StopControlPlaneGRPC()` (`controlplane.go:1043–1049`) — `srv.GracefulStop()` drains in-flight RPCs before listener close |
| 30 | `cdr-client-shutdown` | `main.go:1368–1371` | non-cluster (CDR scanner connection close); included here only because it sits in the same early-phase window |
| 40 | `app-lifecycle-cancel` | `main.go:1373–1376` | calls `appLifecycleCancel()` — cancels `appLifecycleCtx`, draining heartbeat monitor + all 6 DP goroutines + HA standby loop + DP cert renewal + Root-CA rotation ticker |
| 50 | `rate-limit-cleanup-cancel` | `main.go:1325` | non-cluster |

**Lifecycle ordering (informational, not a critical dependency)**: `ha-stop` → `gRPC-stop` → `app-lifecycle-cancel` means the standby loop and gRPC server both stop *before* the DP goroutines exit via context cancel. As a side effect, the gRPC server is unavailable for the brief window before order 40 fires, but no cluster-domain code reads from the loops after `ha-stop` runs. Same caveat as P6.2 §7: simple lifecycle sequencing, not a load-bearing invariant.

**Drain semantics:**

- `srv.GracefulStop()` waits for **all** in-flight RPCs to complete before returning. No timeout argument — under sustained load this could block the early-phase indefinitely. **Severity: LOW** (operator-visible quirk; in practice in-flight RPCs are bounded by their own deadlines). Pre-existing.
- `globalHA.Stop()` does NOT wait for the standby loop to ack exit. **Severity: LOW** (standby loop is cooperative; exits in ≤1 tick = 5s); pre-existing.
- DP goroutines exit on `appLifecycleCtx.Done()`; per-RPC contexts are derived from `ctx` and inherit the cancel.

**State flush gaps at shutdown:**

- `ClusterStore` is NOT flushed at shutdown — last write was from the heartbeat monitor (every 10th tick) or the most recent admin mutation. Anything mutated in-memory since the last `Save()` is **lost on shutdown** if the next Save tick hasn't fired. See §13 CL-2.
- `globalHA` state is NOT flushed at shutdown beyond what `saveHAConfig` already wrote at `EnableAsLeader` / `StartAsStandby` time. The standby's most recent successfully-applied snapshot is in-memory only.
- `globalConfigStore` is NOT persisted (it's the in-memory publish hub; persistence is via `saveConfigVersion` at admin-API time, not at shutdown).

---

## 7. Persistence / durability / fsync semantics

| Artifact | Writer | Primitive | Atomicity | Fsync? |
|---|---|---|---|---|
| `cluster.json` (`globalClusterStore`) | `cs.saveLocked()` at `enrollment.go:170–179` | `atomicWriteFile(cs.path, data, 0o600)` at `:178` | ✅ unique tmp + fsync(file) + rename + fsync(parent dir) per `main.go:2093–2147` | ✅ |
| `cluster-ca.crt`, `cluster-ca.key` (cluster CA) | InitOrLoadCA save / ImportCA save | `atomicWriteFile` at `enrollment.go:806, :809, :1059, :1062` | ✅ same | ✅ |
| `ha_config.json` (HA leader/standby config) | `saveHAConfig(cfg)` at `ha.go:294–299` | `os.WriteFile(path, data, 0o600)` at `:299` | ❌ no tmp+rename, no fsync | ❌ |
| `dp_enrollment.json` (DP persisted enroll config) | `persistEnrollCerts(...)` at `main.go:1944–1972` | `os.WriteFile(enrollmentConfigFile, ecJSON, 0o600)` at `main.go:1972` — **no tmp+rename, no fsync** | ❌ (plain write, can leave truncated file on crash) | ❌ |
| `cluster_update.json` (rolling update progress) | `s.persist()` at `update_cluster.go:78–94` | `os.WriteFile(tmp, ...)` at `:87` → `os.Rename(tmp, ...)` at `:91` — **atomic-via-rename but NOT fsynced** | ✅ atomic | ❌ |
| `config_versions/v{N}.json` (rollback tier) | `saveConfigVersion(actor, action)` per CLAUDE.md | covered by `configversion.go` (not in P6.4 scope) |  |  |
| `HAStateBundle` (RPC payload) | — | **not persisted** (ephemeral; standby applies live then it's gone) | N/A | N/A |
| `globalConfigStore.snap` | — | **not persisted** (in-memory publish hub) | N/A | N/A |
| `EnrolledNode.LastSeen` / `Status` updates (heartbeat) | `UpdateNodeSeen` → `Save()` every 10th call (`enrollment.go:360–376`) | `atomicWriteFile` via `Save` | ✅ | ✅ |

**Backed-up artifacts (P6.3 §5.1):** `cluster.json`, `cluster-ca.crt`, `cluster-ca.key`, plus the Root CA bundle — all in the **Tier-1 required** section of `defaultBackupArtifacts` at `backup.go:60–66`. `ha_config.json`, `dp_enrollment.json`, and `cluster_update.json` are NOT in the backup tier list — see §13 CL-7.

**Comment-level acknowledgment of the RLock-for-Save design:** Source code at `enrollment.go:159–162` reads verbatim: *"Uses RLock so concurrent admin-handler Save() calls do not block each other. atomicWriteFile keeps each write atomic on its own (unique tmp + rename), but switching to Lock for stronger serialization is worth re-evaluating in a follow-up."* This is a documented future-fragility item, not a discovered defect. See §13 CL-6.

---

## 8. Config propagation / `applyConfigSnapshot` / rollback interactions — **the P3.4 surface**

This is the centerpiece of P6.4. `applyConfigSnapshot(snap ConfigSnapshot)` is declared at `controlplane.go:1443–1612` and is invoked from two call sites:

1. DP heartbeat poll path: `DataPlaneClient.fetchAndApply` at `controlplane.go:~1204–1250` calls `applyConfigSnapshot(snap)` after `GetConfig` returns.
2. HA standby sync path: `h.syncFromLeader` at `ha.go:200–241` calls `applyConfigSnapshot(bundle.Config)` at `ha.go:238`.

### 8.1 Per-store breakdown (the P3.4 work surface)

For each sub-store mutated by `applyConfigSnapshot`, this table records the mutator method, whether `.Save()` is called on the DP node after, whether the mutator itself persists, and whether a P3.4-style durability gap exists.

| Store | Mutator | Line | `.Save()` after? | Mutator persists? | P3.4 gap? | Prior finding |
|---|---|---|---|---|---|---|
| `bl` (blocklist) | new Blocklist + Add loop | `controlplane.go:1463–1466` | NO | memory only | YES | new gap |
| `ipf` (IP filter) | new IPFilter + Add loop | `:1469–1476` | NO | memory only | YES | new gap |
| `rl` (rate limiter) | `rl.Configure(...)` | `:1480` | NO | memory only | YES | new gap |
| Default policy action | `setDefaultPolicyAction(...)` | `:1484–1486` | NO | memory only | YES | new gap |
| `policyStore` | `policyStore.ReplaceAll(snap.PolicyRules)` | `:1490` | **YES** at `:1491` | ✅ | NO | **P3.2b shipped (PR #225)** |
| `sslBypass` | `sslBypass.Set(...)` | `:1495–1499` | NO | memory only | YES | new gap |
| `catStore` | `catStore.ReplaceAll(snap.URLCategories)` | `:1503` | NO | memory only | YES | **P6.1 UC-2** |
| `globalProfileStore` | `globalProfileStore.ReplaceAll(...)` | `:1508` | NO | memory only | YES | new (mirror of P3.1#3 shape) |
| `rewriter` | `rewriter.SetRules(...)` | `:1513` | NO | memory only | YES | new gap |
| `dpiScanner` | `dpiScanner.Set(snap.DPIPatterns)` | `:1518` | NO | memory only | YES | **P6.2 SC-3** |
| `connLimiter` | `connLimiter.Enable(...)` | `:1525` | NO | memory only | YES | new gap |
| `lastSeenCAFingerprint` | atomic store on `lastSeenCAFingerprint atomic.Value` | `:1538` | N/A | N/A (detection only — triggers `caRotationNotify`) | N/A | — |
| `updateDPAddresses` | DP-side leader-list update | `:1543` | N/A | derived | N/A | — |
| `pacStore` | `pacStore.Set(...)` | `:1547–1553` | **implicit** — `pacStore.Set` calls Save internally | ✅ | NO | shipped (verify via `pac.go` `Set` impl) |
| `globalThreatFeed` | `ImportFeedData(...)` + `SetDomainAllowlist(...)` | `:1557, :1562` | NO | memory only (feed-DB sync is on its own ticker, independent of `applyConfigSnapshot`) | YES | new gap (parallels P6.2 §5.4 cluster-apply note) |
| `sessionSecret` (HMAC) | direct package-global assignment | `:1566–1574` | NO | memory only | YES (security-sensitive — see §11) | new gap |
| `globalBandwidth` | `globalBandwidth.ReplaceAll(...)` | `:1577–1579` | NO | memory only | YES | new gap |
| `globalCategoryGroups` | `globalCategoryGroups.ReplaceAll(...)` | `:1582–1584` | NO | memory only | YES | **P6.1 UC-2** |
| `fileBlocker` | `ClearAll() + Add` loop | `:1587–1592` | NO | memory only | YES | new gap |
| `globalOTLP` | `Configure(...)` or `Stop()` | `:1595–1603` | N/A (runtime state, not config) | derived | N/A | — |
| `globalNodeGroups` | `globalNodeGroups.ReplaceAll(...)` | `:1606–1608` | NO | memory only | YES | new gap |

**Summary for P3.4:** of the **21** stores touched by `applyConfigSnapshot`, **2 already persist** (`policyStore.ReplaceAll` + `policyStore.Save()` shipped as P3.2b; `pacStore.Set` persists internally), **3 are detection-only or runtime-state** (`lastSeenCAFingerprint`, `updateDPAddresses`, `globalOTLP`), and **16 are pure memory-only**. P3.4 is the consolidated follow-up for those 16. See §13 CL-1.

### 8.2 Snapshot size caps

Declared at `controlplane.go:137–155` (per agent inventory, line-precise constants):

| Constant | Limit |
|---|---|
| `maxSnapBlockedHosts` | 200_000 |
| `maxSnapIPList` | 200_000 |
| `maxSnapPolicyRules` | 10_000 |
| `maxSnapSSLBypassPatterns` | 10_000 |
| `maxSnapURLCategories` | 200_000 |
| `maxSnapFileProfiles` | 1_000 |
| `maxSnapFileBlockExtensions` | 10_000 |
| `maxSnapRewriteRules` | 5_000 |
| `maxSnapDPIPatterns` | 5_000 |
| `maxSnapCPAddresses` | 100 |
| `maxSnapPACExclusions` | 10_000 |
| `maxSnapThreatFeedURLs` | 500_000 |
| `maxSnapThreatFeedDomains` | 500_000 |
| `maxSnapDomainAllowlist` | 10_000 |
| `maxSnapBandwidthPolicies` | 1_000 |
| `maxSnapNodeGroups` | 1_000 |
| `maxSnapCategoryGroups` | 1_000 |

Validated by `validateConfigSnapshot` at `controlplane.go:161–191`. **A snapshot exceeding any single cap is rejected wholesale** — no partial application. DP logs the violation and continues with the previously-applied snapshot.

### 8.3 Rollback (`config_versions/v{N}.json`) vs `ConfigSnapshot`

These are **two distinct mechanisms** with overlapping schema:

- **`saveConfigVersion(actor, action)`** is CP-admin-initiated: every config-mutating admin handler should call it (per CLAUDE.md) to capture a numbered snapshot into `/data/config_versions/v{N}.json` for rollback. **However**: §13 CL-1 documents that cluster admin handlers do NOT call this, just as P6.3 documented for CA admin handlers.
- **`ConfigSnapshot` (RPC payload)** is the CP→DP propagation envelope. DP nodes do NOT see versioned snapshots — they only see the latest live `globalConfigStore.snap`.

A rollback v3→v2 at the CP rewrites `globalConfigStore.snap` to the v2 contents and DP nodes pick that up on their next poll. **The DP applies the rolled-back snapshot using the same `applyConfigSnapshot` path** — so the P3.4 durability gaps apply equally to rollback as to normal config propagation.

### 8.4 P3.2c HA-layer version-guard reference

Per `roadmap/RUNTIME-OWNERSHIP.md` §4 P3.2c, the HA standby loop calls `applyConfigSnapshot(bundle.Config)` every 5s without a version guard. Verified in current source:

- 5s ticker at `ha.go:148`.
- `applyConfigSnapshot(bundle.Config)` at `ha.go:238`.

**This is referenced, not re-discovered.** P3.2c remains a non-blocking optimization (current behavior is correct, just wasteful — every 5s the standby reapplies an unchanged snapshot, paying ~16 atomic writes if P3.4 ever installs Save calls).

---

## 9. Hot reload (`applyHotReload`) interactions

**`applyHotReload(fc *FileConfig)` does NOT touch any cluster state.** Verified against the function body at `main.go:2205–2270`: only mutates `bl`, `policyStore`, `rl`, `ipf`, `rewriter`, `upstreamPool`, and the default-action / rate-limit fields. Specifically:

- No `globalClusterStore` reload.
- No `globalHA` mode toggle.
- No `clusterRole` change.
- No `globalConfigStore.Update(...)` call.
- No `saveConfigVersion(...)` call.
- No gRPC server restart.

**Operator implication:** SIGHUP does not propagate cluster state changes to DPs. Cluster-config mutations route through the admin API or restart. **Observed behaviour, not assessed intent** — mirror of P6.2 SC-5 and P6.3 CA-6. See §13 CL-8.

---

## 10. Race / concurrency analysis

| Surface | Sync mechanism | Severity | Notes |
|---|---|---|---|
| **CL-R-1**: `globalClusterStore` admin mutation vs heartbeat `UpdateNodeSeen` | `ClusterStore.mu.Lock` for state mutation; `Save()` uses RLock | LOW (resolved) | Both go through the lock for in-memory mutation; the `Save` RLock is for marshal-only |
| **CL-R-2**: Two concurrent `Save()` calls on `ClusterStore` | RLock-bounded (`enrollment.go:159–162` comment acknowledges) | LOW | Last writer's `atomicWriteFile` rename wins; both mutators' in-memory changes are present in the marshaled state because they preceded their respective `Save` |
| **CL-R-3**: DP `applyConfigSnapshot` vs admin API mutation on same DP | per-store RWMutex on each sub-store | LOW–MEDIUM | Apply path is not transactional across stores; readers can see half-applied snapshot. Same shape as P6.2 §6. Future-fragility, not a current correctness defect under steady-state |
| **CL-R-4**: HA standby `syncFromLeader` vs admin mutation (during failover) | each sub-store's lock | LOW | Same shape as CL-R-3; the standby is not yet promoted, so admin mutations to the would-be-promoted node are unusual |
| **CL-R-5**: gRPC server accept loop vs `StopControlPlaneGRPC` | `srv.GracefulStop()` is internally race-safe | LOW (resolved) | stdlib guarantees |
| **CL-R-6**: `clusterRole` reads vs `enableControlPlane` write | mostly `clusterRoleMu sync.RWMutex`; two unlocked exceptions | LOW (relies on lifecycle invariant) | `enableControlPlane` (`main.go:1767–1791`) takes `Lock`. **Exceptions:** (a) `StartControlPlaneGRPC` writes `clusterRole.grpcSrv = srv` at `controlplane.go:1031` **without** taking the lock — sole caller is `enableControlPlane` so transitively protected; (b) `StopControlPlaneGRPC` reads `clusterRole.grpcSrv` at `controlplane.go:1044, :1046` **without** the lock — relies on shutdown ordering (`control-plane-grpc-stop=20`) running after `enableControlPlane` returns and before any other mutation. **Both exceptions are race-safe today** because of single-caller / shutdown-ordering invariants, **not** because the lock is held. Fragile to future refactor that adds a second caller to either function. Recording for posterity — see §13 CL-12. |
| **CL-R-7**: `cpTLSConfig.cfg.ClientCAs` swap vs handshake | (deferred to P6.3 CA-7) | UNVERIFIED | Already filed; not re-covered here |
| **CL-R-8**: `runClusterUpdate` orchestrator vs admin mutations to `ClusterUpdateState` | `ClusterUpdateState.mu sync.Mutex` | LOW (resolved) | The orchestrator goroutine is the only writer outside admin handlers |
| **CL-R-9**: HA leader↔standby split-brain | none | MEDIUM (operator-visible) | See §11; structurally unmitigated |
| **CL-R-10**: `DataPlaneClient.c.conn` unsynchronized read in `c.call()` vs failover write in `c.connect()` | partial — write is locked, read is not | **UNVERIFIED — potential race; needs race-test confirmation.** | `c.call()` at `controlplane.go:1396` reads `c.conn.Invoke(...)` **without** taking `c.mu`. `c.connect()` writes `c.conn = conn` at `:1151`; called from `c.failover()` at `:1162–1169` which **does** take `c.mu.Lock`. Five long-lived DP goroutines (`pollLoop`, `metricsLoop`, `rateLimitGossipLoop`, `revocationSyncLoop`, `auditPushLoop`, spawned by `DataPlaneClient.Run` at `controlplane.go:1182–1186`) all invoke `c.call()` concurrently. If a failover swaps `c.conn` while a sibling loop is mid-`call`, this is an unsynchronized read/write under the Go memory model — same shape as P6.3 CA-7. **No current test exercises failover concurrent with in-flight `c.call()`**; race-test confirmation is the deferred follow-up. See §13 CL-11. |

**One unverified concurrent-mutation surface (CL-R-10) and one lock-convention exception worth tracking (CL-R-6).** Neither is a current correctness defect under the existing lifecycle invariants, but both are future-fragility items: CL-R-10 needs a focused race test (see §13 CL-11); CL-R-6's `StartControlPlaneGRPC` / `StopControlPlaneGRPC` unlocked accesses would race if a second caller is ever added to either function (see §13 CL-12). The remaining cluster stores have coherent lock contracts; other gaps in §13 are about durability (P3.4), governance (`saveConfigVersion`), goroutine ownership (`runClusterUpdate`), persistence atomicity (`ha_config.json` + `dp_enrollment.json` + `cluster_update.json`), and operational properties (split-brain), not races.

---

## 11. Cluster / HA ownership risks

### 11.1 Split-brain on HA failover — operator-visible, structurally unmitigated

**Scenario:** network partition between HA leader and standby. After 3 consecutive failures of the 5s `HASync` poll (15s wall-clock), the standby promotes itself via `h.promote()` and runs its `onPromote` callback (which is `enableControlPlane`). The original leader, if still alive but unreachable to the standby, **continues running as CP** because it has no liveness check on the standby.

**Result:** two active leaders, each accepting admin mutations, each pushing their own `ConfigSnapshot` to whichever DPs they can reach. The cluster state diverges silently.

**Mitigations in place:** **none.** No quorum, no external arbiter (e.g. etcd lease), no fencing of the original leader's gRPC port, no DP-side "I see two leaders" alert.

**Resolution on rejoin:** when the partition heals, **the standby's most recent state wins** for `ClusterState` (because the original leader's RPC connection to the standby may be re-established). The precise behavior of rejoin (who wins what, when, how admin mutations made on the partition-loser side are reconciled) **is unverified behavior — requires a focused partition-resolution integration test (deferred to CL-4 follow-up)**. Admin mutations on the partition-loser side between failover and rejoin are silently discarded.

**Operator-visible:** YES. Admin issues `apiClusterStatus` from each side and gets two different `role: "leader"` responses. No alert is fired. See §13 CL-4.

### 11.2 DP gRPC connection drop mid-apply

**Scenario:** DP poll receives a fresh `ConfigSnapshot`; `applyConfigSnapshot` is mid-execution; the underlying gRPC connection drops. The per-poll context (`ctx`) is cancelled.

**Behaviour:** `applyConfigSnapshot` does NOT check `ctx.Done()` inside the apply loop — once the function is invoked, every sub-store mutation runs to completion. The connection drop affects the *next* poll, not the current apply.

**Result:** the DP is in a consistent state with respect to the snapshot it started applying; the next poll (30s later) brings a fresh snapshot.

**Severity:** LOW (resolved). Pre-existing; not a finding.

### 11.3 ConfigSnapshot exceeds size caps

**Scenario:** CP pushes a snapshot with `len(snap.BlockedHosts) > 200_000`. `validateConfigSnapshot` at `controlplane.go:161–191` rejects the entire snapshot.

**Behaviour:** DP logs the validation error and continues with the previously-applied snapshot. **No partial apply.**

**Severity:** LOW (resolved). Operator-visible (admin logs surface the rejection).

### 11.4 Token expiry mid-enrollment

**Scenario:** admin generates an enrollment token with 24h TTL; a DP attempts to enroll 25h later.

**Behaviour:** `ValidateAndConsumeToken` (`enrollment.go:237–280`) checks `ExpiresAt`, returns error, DP logs failure. Token is left in `ClusterStore.st.Tokens` until the heartbeat monitor's GC pass evicts it.

**Severity:** LOW (resolved). Operator must regenerate the token.

### 11.5 HA bundle plaintext-key fallback path

Already filed by P6.3 as **CA-4**. Referenced for cross-cut completeness; not re-covered.

### 11.6 `runClusterUpdate` interaction with HA failover

**Scenario:** rolling-update is in progress (`clusterUpdateState.phase = "updating_dps"`); HA failover happens; the new leader has no notion of the in-progress update.

**Behaviour: unverified — requires integration test (deferred to CL-5 follow-up).** `recoverClusterUpdate()` at `update_cluster.go:884` is called at boot from a persisted `cluster_update.json`. The new leader (which promoted from standby) **may not have a fresh copy of `cluster_update.json`** because `ha_config.json` is the only HA-replicated config-file (and even that is best-effort `os.WriteFile`). If the standby's local `cluster_update.json` is stale, the new leader either resumes from a stale checkpoint or starts a fresh state. **No explicit coordination between rolling-update orchestrator and HA failover.** See §13 CL-5.

---

## 12. Existing test coverage

| File | Coverage summary |
|---|---|
| `cluster_audit_test.go` | ~16 tests: `TestConfigSnapshot_FullPolicySync`, `TestPolicyStore_ReplaceAll`, `TestCategoryStore_ReplaceAll`, `TestFileProfileStore_ReplaceAll`, `TestClusterStore_SetNodeLabels`, `TestAPIClusterLabels`, `TestClusterStore_SetNodeDraining`, `TestAPIClusterDrain`, `TestAPIClusterMetrics`, `TestApplyConfigSnapshot_FullPolicy`, `TestApplyConfigSnapshot_PolicyRulesPersist`, `TestClusterRevoke_SanitizedLogs`, `TestClusterTokenCreate_TTLCap`, `TestClusterTokenCreate_NodePrefixValidation`, `TestClusterMode_GRPCAddrValidation`, plus more. |
| `cluster_features_test.go` | Policy/category/file-profile sync across CP→DP, node draining lifecycle, HA status reporting. |
| `coldstart_clusterca_test.go` | Cluster CA initialization, fingerprint computation, import validation. |
| `coldstart_clusterstore_test.go` | `ClusterStore` Load/Save round-trip, node registration, token generation, revocation persistence. |
| `enrollment_test.go` | Token generation/validation/consumption, enrollment rate limiting (5/min/IP), CSR validation, node registration. |
| `enroll_util_test.go` | ClusterStore helpers, expired-token GC, revocation list management. |
| `ha_test.go` | HA state transitions, token verification, `ha_config.json` persistence, sync bundle creation, HA key encryption + decryption. |
| `phase6_test.go` | Cross-domain P6 integration tests (audit, features, security). |
| `update_cluster_test.go` | Rolling update state transitions, error-budget enforcement, canary/soak phases. |
| `controlplane_extra_test.go` | gRPC server lifecycle, snapshot version monotonicity. |
| `controlplane_snapshot_bounds_test.go` | Every `maxSnap*` cap exercised; oversized fields rejected. |
| `controlplane_getconfig_security_test.go` | `GetConfig` RPC RBAC + tenant isolation. |
| `controlplane_verifynodecert_security_test.go` | Node cert serial verification against the revocation list. |

**Race / shuffle coverage:** CI runs all of the above under `-race -count=1 -timeout=15m` per CLAUDE.md plus the `-shuffle=on -count=2` determinism gate. PR #241 (post-P6.3) fixed a real shuffle flake (`TestLoadAuth_LoadsUIUsersFromFile`) using whitebox state snapshot/restore.

**Gaps relevant to future implementation phases (NOT P6.4 scope; flagged for posterity):**

1. No test interleaves admin API mutation with `applyConfigSnapshot` under `-race`. The per-store RWMutex makes this clean by construction; a focused contract test would pin the invariant.
2. No HA split-brain integration test (see §11.1). Split-brain is unmitigated and untested.
3. No test asserts that `runClusterUpdate` mid-rollout survives an HA failover (see §11.6).
4. No P3.4 contract test exists for the consolidated apply-then-persist pattern.

### 12.1 Test isolation risks observed in the cluster domain

Per CLAUDE.md "Test-authoring pitfalls" and the PR #241 lesson, the following patterns in cluster-domain tests are worth flagging but not fixing in P6.4:

1. **Global state mutation with `defer` cleanup** (`cluster_audit_test.go` and similar): tests assign `globalClusterStore = newTestClusterStore(t)` and restore via `defer`. Reliable IF the test reaches the defer setup; fragile if a panic in setup leaks state. The PR #241 idiom (`t.Cleanup` + whitebox snapshot/restore, bypassing production APIs) is the established replacement pattern.
2. **`clusterRole.role` mutation** without `t.Cleanup` in some places (per agent inventory; line refs unverified). If a test fails between setting `clusterRole.role = "control-plane"` and its `defer` reset, subsequent tests see the polluted role.
3. **Tests that don't isolate per-test cluster DB paths**: assumed to use `t.TempDir()` but not exhaustively verified.

No specific test in this list is currently flaking under `-count=2 -shuffle=on`. Recording for visibility — they are candidates for the same whitebox-restore pattern PR #241 established if any of them surface under future tightening.

---

## 13. Deferred follow-ups (NOT P6.4 scope)

These were uncovered during this discovery but are out of P6.4's scope. They are noted here so they aren't lost; they should be triaged separately or are explicitly slated for P3.4.

| ID | Finding | Risk class | Mirror |
|---|---|---|---|
| **CL-1** | **The P3.4 work surface.** `applyConfigSnapshot` (`controlplane.go:1443–1612`) mutates 21 sub-stores on every DP poll and HA standby sync. **Only 2 (`policyStore` + `pacStore`) persist after the apply.** 16 stores are pure memory-only and lose state on DP restart: `bl`, `ipf`, `rl`, default-action, `sslBypass`, `catStore`, `globalProfileStore`, `rewriter`, `dpiScanner`, `connLimiter`, `globalThreatFeed`, `sessionSecret`, `globalBandwidth`, `globalCategoryGroups`, `fileBlocker`, `globalNodeGroups`. See §8.1 for the full table with line refs. **This is exactly the P3.4 mandate.** P3.4 is **lab-required** per `RUNTIME-OWNERSHIP.md` §4 and gated on this discovery — now unblocked. The P3.4 PR should: (a) install caller-side `.Save()` after each mutator that has a persistable store, (b) hard-gate on the corresponding durability follow-ups already filed (P6.1 UC-1, P6.2 SC-4, etc.) before invoking `.Save()` on a non-fsynced path, and (c) consider whether `sessionSecret` deserves the same treatment given its security sensitivity. | current correctness — DP restart loses 16-store state until next heartbeat | P3.2b (policy `Save()` after `ReplaceAll`, PR #225); P3.1#3 (`FileProfileStore.ReplaceAll`, PR #222) |
| **CL-2** | **`ClusterStore` is not flushed at shutdown.** Last write is the 10th-tick heartbeat throttle (`enrollment.go:374`) or the most recent admin mutation. State mutated in-memory since the last `Save()` is **lost** if shutdown comes before the next throttle. Fix shape (deferred): add a `cluster-store-flush` late hook that calls `globalClusterStore.Save()` (already uses `atomicWriteFile`). | current correctness — heartbeat throttle window | P3.1 follow-up class |
| **CL-3** | **`runClusterUpdate` orchestrator is detached.** Spawned at `update_cluster.go:313` as `go runClusterUpdate()` with no parent context and no shutdown hook. Mirror of P6.1 UC-3 (`globalSaaSFeed.syncLoop`). Possible fix shapes (deferred to follow-up): (a) parent the goroutine to `appLifecycleCtx`; (b) add a `cluster-update-stop` late shutdown hook that cleanly halts the orchestrator. Exact design out of P6.4 scope. | lifecycle — orchestrator survives `appLifecycleCancel`; persisted state recovers next boot | P6.1 UC-3 (`globalSaaSFeed.syncLoop`) |
| **CL-4** | **HA split-brain is structurally unmitigated.** No quorum, no lease, no fencing. Standby promotes after 15s of `HASync` failures; original leader continues running. Both sides accept admin mutations during partition. **Resolution-on-rejoin behaviour is unverified — requires a focused partition-resolution integration test** (induce partition + admin mutations on both sides + heal + observe which side's state wins; see §11.1). **This is a real operational risk** but the fix is non-trivial (introduce an external arbiter, or a DP-quorum-based fencing protocol). Out of P6.4 scope; flagged for a dedicated HA-hardening design discussion. The integration test itself can land as a smaller standalone PR even before any hardening fix. | operator-visible — silent state divergence under network partition | None — first-time recording |
| **CL-5** | **`runClusterUpdate` does not coordinate with HA failover.** If a failover happens mid-update, the new leader's view of `cluster_update.json` may be stale (the file is local, not HA-replicated). The orchestrator may resume from a stale checkpoint or start fresh. **Behaviour is unverified — requires an integration test** that triggers HA failover during `runClusterUpdate`'s `updating_dps` phase and asserts on the new leader's recovery path (see §11.6). Out of P6.4 scope; flagged for the same HA-hardening design discussion as CL-4. | operator-visible — rolling update behavior under failover | None |
| **CL-6** | **`ClusterStore.Save()` uses RLock instead of Lock.** Acknowledged in source comment at `enrollment.go:159–162` as *"worth re-evaluating in a follow-up"*. Both mutators' in-memory changes are present in the marshaled state, but the in-source comment flags it as a future-fragility item. No action recommended in P6.4 — the existing comment is sufficient signal for any future tightening. | future-fragility (acknowledged in source) | None |
| **CL-7** | **Three cluster-domain on-disk paths are not durable:** (a) `ha_config.json` via plain `os.WriteFile` at `ha.go:299` — no tmp+rename, no fsync; (b) `dp_enrollment.json` via plain `os.WriteFile` at `main.go:1972` — no tmp+rename, no fsync; (c) `cluster_update.json` via tmp + `os.Rename` at `update_cluster.go:87, :91` — atomic-via-rename but **not fsynced**. Compared to `cluster.json` (and the cluster CA pair) which use `atomicWriteFile`, these three are non-durable. **Severity ordering:** (a) and (b) are the more serious — a crash mid-write can leave a truncated file on disk (vs. the rename-based (c) which is at least atomic). Fix shape: route all three through `atomicWriteFile`. **Hard-gate sequencing:** independent of P3.4 — can ship at any time. Group with P6.1 UC-1 / P6.2 SC-4 / P6.3 CA-3 in a single durability-hardening follow-up if convenient. | durability — power-loss / mid-write crash on any of three paths can leave truncated or stale files | P6.1 UC-1; P3.2a (`PolicyStore.Save`, PR #224) |
| **CL-8** | **Zero cluster admin handlers call `saveConfigVersion`.** Verified by `grep "saveConfigVersion" ui_cluster.go update_cluster.go` returning **zero** hits. Twelve+ mutating handlers emit `auditEvent` but the rollback tier is silent for: mode promotion (`apiClusterMode`), token CRUD (`apiClusterTokenCreate`, `apiClusterTokens` DELETE), node revocation (`apiClusterRevoke`), label updates (`apiClusterLabels`), drain (`apiClusterDrain`), HA enable/disable (`apiClusterHA`), CA import (`apiClusterCA` POST — covered by P6.3 CA-1 already), and rolling update (`apiClusterUpdate`). Parallel of P6.3 CA-1 exactly. **Recommended treatment:** triage decision, NOT a unilateral fix. Some handlers are operational (HA enable/disable, mode promotion) where a config-rollback should arguably NOT silently revert a topology change; others (label updates, revocations) are more clearly snapshot-worthy. Group with P6.1 UC-4 + P6.2 SC-1 + P6.3 CA-1 in a single config-versioning-coverage triage. | governance — rollback tier silent on cluster-topology mutations | P6.1 UC-4; P6.2 SC-1; P6.3 CA-1 |
| **CL-9** | **No `culvert_cluster_*` / `culvert_ha_*` / `culvert_enrollment_*` Prometheus metrics.** No counter for enrollment failures, HA failover events, ClusterStore save frequency, rolling-update progress, or DP poll latency. Operators currently rely on the audit ring and `apiClusterStatus` / `apiClusterHA` polling. Group with P6.1 UC-6 + P6.2 SC-2 + P6.3 CA-2 in a single observability follow-up PR. | observability | P6.1 UC-6; P6.2 SC-2; P6.3 CA-2 |
| **CL-10** | **`applyHotReload` does not touch cluster state** (`main.go:2205–2270`). **Observed behaviour; intent not assessed by this discovery.** Operators changing cluster config via the YAML file (e.g. `fc.Cluster.GRPCAddr`) must restart the process; admin API is the only runtime path. Mirror of P6.2 SC-5 and P6.3 CA-6. **No action recommended; recording for visibility.** | record-only | P6.2 SC-5; P6.3 CA-6 |
| **CL-11** | **`DataPlaneClient.c.conn` unsynchronized read in `c.call()` (`controlplane.go:1396`) vs failover write in `c.connect()` (`:1151`, called from `c.failover()` under `c.mu.Lock` at `:1162`).** Five long-lived DP goroutines (`pollLoop`, `metricsLoop`, `rateLimitGossipLoop`, `revocationSyncLoop`, `auditPushLoop`, spawned by `DataPlaneClient.Run` at `:1182–1186`) all invoke `c.call()` concurrently. A failover that swaps `c.conn` while a sibling loop is mid-`call` is an unsynchronized read/write under the Go memory model. **Whether this trips `-race` in practice is unverified** — no current test exercises failover concurrent with in-flight `c.call()` across multiple DP goroutines. **Deferred follow-up: focused race test** — drive concurrent `c.call()` from N goroutines while a separate goroutine calls `c.failover()`, under `go test -race -count=1`. If `-race` flags the surface, candidate fix shapes (deferred to the follow-up PR after the test result): (a) wrap `c.call()`'s `c.conn` read in `c.mu.RLock()`/`RUnlock()` for the duration of the snapshot (not for the duration of the RPC); (b) replace `c.conn *grpc.ClientConn` with `atomic.Pointer[grpc.ClientConn]` (mirror of P5.3 `swapUpstreamTransport`). Choice between (a) and (b) belongs in the follow-up. | future-fragility — race-detector-clean today is unverified | P5.3 `swapUpstreamTransport`; P6.3 CA-7 |
| **CL-12** | **`clusterRole.grpcSrv` is accessed without `clusterRoleMu` in two places**: (a) `StartControlPlaneGRPC` writes `clusterRole.grpcSrv = srv` at `controlplane.go:1031` — the sole caller (`enableControlPlane` at `main.go:1779`) holds the lock, so the write is **transitively protected**; (b) `StopControlPlaneGRPC` reads `clusterRole.grpcSrv` at `controlplane.go:1044, :1046` — relies on the shutdown-ordering invariant that the early-phase hook (`control-plane-grpc-stop=20`, `main.go:1362`) runs after `enableControlPlane` has released its lock and before any other mutation can fire. **Both exceptions are race-safe today** under the current lifecycle invariants, but the safety is invariant-based, not lock-based — fragile to a future refactor that adds a second caller to `StartControlPlaneGRPC` (e.g. a runtime "restart gRPC" admin endpoint) or that moves `StopControlPlaneGRPC` to a different shutdown phase. Fix shape (deferred): take `clusterRoleMu` inside `StartControlPlaneGRPC` and `StopControlPlaneGRPC` explicitly; the inner Lock would be a no-op recursion in `enableControlPlane`'s caller path **except that `sync.RWMutex` is not re-entrant**, so the simpler fix is to move the assignment up into `enableControlPlane` (under the lock it already holds) and pass `srv` back from `StartControlPlaneGRPC` as a return value. **No action recommended now; recording the convention exception so future refactors don't accidentally introduce a race.** | future-fragility — invariant-based safety, not lock-based | None — first-time recording |

**None of CL-1 through CL-12 are required for P6 to advance.** CL-1 is the P3.4 work surface (now unblocked); CL-2 / CL-3 / CL-7 are mechanical follow-ups that can be grouped with existing durability / observability PRs; CL-4 / CL-5 require dedicated HA-hardening design (and standalone integration tests, which can ship even before any fix); CL-11 is a focused race test (highest-priority follow-up); CL-12 / CL-6 / CL-8 / CL-9 / CL-10 are governance / observability / record-only.

Sequencing suggestions:

- **CL-11 (DataPlaneClient.c.conn race test)** is the highest-priority follow-up: it's a focused race test, not an architecture change. Independent of all other items. Result of the test informs whether a swap-pattern refactor is needed (P5.3 mirror).
- **CL-1 (P3.4 itself)** — this is the lab-required PR the discovery was designed to unblock. Hard-gated on the per-store durability follow-ups already filed (P6.1 UC-1, P6.2 SC-4, etc.) for any store whose `Save()` is not yet fsynced.
- **CL-3 (`runClusterUpdate` ownership)** — small, independent; can ship at any time.
- **CL-2 (cluster-store shutdown flush)** — small, independent.
- **CL-7 (three non-durable persistence paths)** — group with the durability-hardening follow-up covering P6.1 UC-1 / P6.2 SC-4 / P6.3 CA-3 — none of those have shipped yet, so a single PR could cover all four.
- **CL-4 / CL-5 (HA split-brain + update coordination)** — dedicated HA-hardening design discussion; the integration tests called out in the entries can ship as smaller standalone PRs even before any fix.
- **CL-8 / CL-9 (config versioning + metrics)** — group with the cross-discovery governance + observability PRs.
- **CL-12 (`clusterRole` unlocked-exception fragility)** — record-only today; only escalates if a future PR adds a second caller to `StartControlPlaneGRPC` or relocates `StopControlPlaneGRPC`.
- **CL-6 / CL-10** — record-only.

---

## 14. What not to touch

- No `upstreamTransport`-style ownership refactor on `globalClusterStore`, `globalHA`, or `clusterRole`. Each has a coherent RWMutex / Mutex contract and a single mutation API.
- No expansion of `ConfigSnapshot` to carry cluster-CA cert material — DPs already learn about rotation via the `CAFingerprint` field and renew via the dedicated `RenewCert` RPC (P6.3 territory).
- No removal of the deprecated `HAStateBundle.CAKeyPEM` plaintext fallback (P6.3 CA-4) — that requires a coordinated cluster-upgrade protocol.
- No removal of the per-store ownership of `applyConfigSnapshot` — the mutation pattern (each store owns its own lock, no global apply-time transaction) is intentional and matches P6.1/P6.2/P6.3 conventions.
- No re-discovery of the P6.3 CA-7 race (`cpTLSConfig.cfg.ClientCAs`).
- No re-discovery of the P3.2c HA standby version-guard (already filed).
- No new long-lived goroutines or shutdown hooks in this PR. Discovery only.
- No changes to the shutdown order constants (`shutdownOrderHAStop=10`, `shutdownOrderControlPlaneGRPCStop=20`, etc.) — they are pinned by `runtime_shutdown_wiring_test.go`'s canonical-order tests.
- No changes to gRPC server / client construction or TLS config — those are P6.3 territory.

---

## 15. References

- `main.go:597–668` — `initCluster` dispatch.
- `main.go:1324–1327` — early shutdown order constants (`shutdownOrderHAStop=10`, `shutdownOrderControlPlaneGRPCStop=20`, `shutdownOrderCDRClientShutdown=30`, `shutdownOrderAppLifecycleCancel=40`).
- `main.go:1356–1376` — early shutdown hook registration (`ha-stop`, `control-plane-grpc-stop`, `cdr-client-shutdown`, `app-lifecycle-cancel`).
- `main.go:1753–1761` — `initClusterCA` (cluster-CA bootstrap; P6.3 territory).
- `main.go:1766–1792` — `enableControlPlane`.
- `main.go:1986–2008` — `startDataPlane` + DP cert renewal goroutine spawn.
- `main.go:2093–2147` — `atomicWriteFile` implementation (full fsync semantics with documented graceful skip on `EINVAL`/`ENOTSUP`/`EOPNOTSUPP`).
- `main.go:2205–2270` — `applyHotReload` (does NOT touch cluster state).
- `controlplane.go:70–123` — `ConfigSnapshot` field declaration.
- `controlplane.go:137–155` — `maxSnap*` size cap constants.
- `controlplane.go:161–191` — `validateConfigSnapshot`.
- `controlplane.go:204` — `globalConfigStore` declaration.
- `controlplane.go:449–460` — `clusterRoleMu` + `clusterRole` declaration.
- `controlplane.go:974` — `StartControlPlaneGRPC`.
- `controlplane.go:1033` — `go func() { srv.Serve(ln) }()` gRPC server accept loop spawn.
- `controlplane.go:1043–1049` — `StopControlPlaneGRPC` (`srv.GracefulStop`).
- `controlplane.go:1181–1187` — `DataPlaneClient.Run` (spawns 5 goroutines).
- `controlplane.go:1182–1186` — DP goroutine spawn lines (`pollLoop`, `metricsLoop`, `rateLimitGossipLoop`, `revocationSyncLoop`, `auditPushLoop`).
- `controlplane.go:1204–1250` — `fetchAndApply` (DP poll → `applyConfigSnapshot`).
- `controlplane.go:1402` — `activeDPClient atomic.Pointer[DataPlaneClient]`.
- `controlplane.go:1443–1612` — `applyConfigSnapshot` (the P3.4 surface).
- `controlplane.go:1490–1491` — `policyStore.ReplaceAll` + `Save` (only store that persists after apply on the policy path; P3.2b shipped).
- `controlplane.go:1616–1688` — `CurrentConfigSnapshot` (CP-side capture).
- `enrollment.go:47–53` — `ClusterState` struct.
- `enrollment.go:68–101` — `EnrolledNode`, `EnrollToken`, `RevokedCert` types.
- `enrollment.go:106–119` — `ClusterStore` + `globalClusterStore`.
- `enrollment.go:122–155` — `Load`.
- `enrollment.go:157–179` — `Save` + `saveLocked` (with RLock comment at `:159–162`).
- `enrollment.go:178` — `atomicWriteFile(cs.path, data, 0o600)`.
- `enrollment.go:237–280` — `ValidateAndConsumeToken`.
- `enrollment.go:344–376` — `RegisterNode` + `UpdateNodeSeen` (10th-tick heartbeat persistence).
- `enrollment.go:567–580` — `StartHeartbeatMonitor`.
- `enrollment.go:806–809, :1059–1062` — cluster-CA `atomicWriteFile` save (P6.3 territory; cited for cross-cut).
- `ha.go:30–45` — `HAState` + `globalHA`.
- `ha.go:80–115, :118–135` — `EnableAsLeader`, `StartAsStandby`.
- `ha.go:135` — `go h.standbyLoop(...)` spawn.
- `ha.go:138–197` — standby loop (`ticker := time.NewTicker(5 * time.Second)` at `:148`).
- `ha.go:200–241` — `syncFromLeader` (calls `applyConfigSnapshot(bundle.Config)` at `:238`).
- `ha.go:269–276` — `Stop` (closes `stopCh`).
- `ha.go:294–299` — `saveHAConfig` (uses `os.WriteFile`, not `atomicWriteFile`).
- `ui_cluster.go:14–37` — `apiClusterStatus`.
- `ui_cluster.go:50–103` — `apiClusterMode` (with `auditAdd action="cluster.enable-cp"` at `:94`).
- `ui_cluster.go:106–141` — `apiClusterTokens` (GET + DELETE).
- `ui_cluster.go:143–218` — `apiClusterTokenCreate` (with `auditEvent action="enrollment.token_created"` at `:208`).
- `ui_cluster.go:221–231` — `apiClusterNodes`.
- `ui_cluster.go:234–276` — `apiClusterRevoke` (with `auditEvent action="enrollment.node_revoked"` at `:271`).
- `ui_cluster.go:279–333` — `apiClusterCA` (P6.3 territory; `auditEvent action="cluster.ca"` at `:321`).
- `ui_cluster.go:335–470` — `apiClusterLabels` (with `auditEvent action="cluster.labels"` at `:449`).
- `ui_cluster.go:471–515` — `apiClusterDrain` (with `auditEvent` at `:484`).
- `ui_cluster.go:516–580` — `apiClusterHA`.
- `update_cluster.go:29–46` — `ClusterUpdateState` struct.
- `update_cluster.go:78–94` — `persist` (`cluster_update.json`).
- `update_cluster.go:244` — intentionally-detached per-request sidecar trigger goroutine (`#nosec G118`).
- `update_cluster.go:272–315` — `startClusterUpdate` (spawns `go runClusterUpdate()` at `:313`).
- `update_cluster.go:317–` — `runClusterUpdate` orchestrator body.
- `update_cluster.go:884–` — `recoverClusterUpdate` (boot-time resume).
- `update_cluster.go:917–` — `apiClusterUpdate`.
- `update_cluster.go:983` — `auditEvent action="cluster_update.start"`.
- `backup.go:60–66` — Tier-1 backup inclusion of `cluster.json`, `cluster-ca.crt`, `cluster-ca.key` (P6.3 §5.1; cited for cross-cut).
- `roadmap/RUNTIME-OWNERSHIP.md` §2 (S8 out-of-scope clarification), §3 Phase shape, §4 P6.4 entry + P3.4 entry + P3.2c reference, §5 "Recommended next PR".
- `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` (P5.1), `roadmap/URL-CATEGORIES-DISCOVERY.md` (P6.1), `roadmap/SCANNING-DISCOVERY.md` (P6.2), `roadmap/ROOT-CA-DISCOVERY.md` (P6.3) — format baselines.
- `roadmap/D1.3a-backup-design.md`, `roadmap/D1.6-maintenance-agent-design.md` — backup/restore ownership of cluster artifacts (out of P6 scope).
