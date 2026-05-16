# P6.3 — Root CA / TLS / Certificate Runtime Ownership Discovery

**Status:** Discovery only. No production code change, no tests.
**Scope:** `initRootCA`, `CertManager` (MITM Root CA + leaf-cert LRU cache), `clusterCA` (cluster-issuance CA), `ClusterStore` (enrollment tokens + node trust + revocations), CP/DP gRPC TLS plumbing (`buildServerTLS` / `buildClientTLS` + `cpTLSConfig` + rotation callback), admin-UI self-signed TLS, and the admin-API surface that mutates any of them.
**SPOF target:** none on the existing `RUNTIME-OWNERSHIP.md` SPOF list (Phase 6 is discovery-only by design — §6 of the program doc). **S8 (`/data` dir + Root CA bundle as deployment SPOFs) is explicitly out of scope across the whole program** per `RUNTIME-OWNERSHIP.md` §2 — owned by D1.3 backup/restore (`roadmap/D1.3a-backup-design.md`) and D1.6 Maintenance Agent (`roadmap/D1.6-maintenance-agent-design.md`). The relevant SPOF axes here are the **detached goroutine** family (S4-class) and the **god-object init** family (S1-class).
**Already-shipped scope to NOT re-cover:** P5.3 owns the upstream-direction `*http.Transport` (mTLS + OCSP overlay on `upstreamOpTLSCfg`). P6.3 references those files where the trust flow crosses them but does not re-analyze them.

---

## 0. Executive verdict

`initRootCA` is a small init site (one call into `CertManager.LoadOrInitCA` or `.InitCA` plus a single background goroutine spawn), but the Root-CA / TLS subsystem it owns is the **broadest trust-surface in the codebase**. It spans four independent CA-grade ownership scopes:

1. **MITM Root CA** (`certMgr`, `ca.go:59`) — generates leaf certs for SSL-inspection on the proxy hot path, with a 10k-entry / 1h-TTL LRU cache and dual-CA overlap on rotation.
2. **Cluster CA** (`globalClusterCA`, `enrollment.go:705`) — signs DP-node client certs and is presented as the trust anchor for CP↔DP gRPC; **distinct CA**, not the MITM CA.
3. **Enrollment trust store** (`globalClusterStore`, `enrollment.go:113`) — tokens, enrolled-node registry, revocations, CA-rotation progress tracking.
4. **Admin-UI TLS** (self-signed, generated fresh each startup by `selfSignedTLS` at `tls.go:28–107`) — server-only TLS for the admin HTTP listener.

**One unverified concurrency surface (CA-R-3, see §6 + §10 CA-7)**: `rebuildCPCertPool` writes `cpTLSConfig.cfg.ClientCAs` under `cpTLSConfig.mu.Lock`, but the stdlib TLS handshake reads `tlsCfg.ClientCAs` without that lock. The Go memory model classifies this as a data race regardless of write width; whether it trips `-race` in practice is unverified because no current test exercises rotation concurrently with a TLS handshake. A focused race test is needed before this surface can be classified as safe. The remaining in-memory state is well-synchronized: every CA-grade store guards its hot path with `sync.RWMutex`, the leaf-cert cache uses a lock-bounded LRU, the cluster-CA `onRotate` callback chain serializes rotation through `clusterCA.mu` + `cpTLSConfig.mu`, and the upstream mTLS template (P5.3 territory) routes through `swapUpstreamTransport` exclusively. **Seven classes of pre-existing gaps are tracked separately** in §10: the CA-R-3 race-test gap above; a **complete** config-versioning gap on every CA admin handler (`grep "saveConfigVersion" ui_security.go` returns five hits, none of which are CA-related); a Prometheus metrics gap (no `culvert_ca_*` / `culvert_tls_*` / `culvert_cert_*` counters); the absence of any `applyHotReload` coupling for CA / TLS state; the absence of CA bundles from `ConfigSnapshot` (DP nodes learn about cluster-CA rotation via the `CAFingerprint` field, not the cert material itself); the cluster-CA private key being stored **unencrypted** on disk (vs. the Root CA's PBKDF2 + AES-256-GCM); an HA-bundle deprecated-plaintext fallback path that warrants explicit demarcation; a `caRuntime.passphrase` in-memory retention note (operational tradeoff for admin-API rotation); and an `apiCertsUpload target=ui` operator-visible UX gap (validates but neither persists nor applies).

What is **NOT** uncovered by this discovery:

- No hot-path race surface on the existing locks (`CertManager.mu`, `clusterCA.mu`, `cpTLSConfig.mu`, `ClusterStore.mu`).
- No undocumented goroutine spawn site missing cancellation — both long-lived background loops (CA-rotation ticker, heartbeat monitor) take an explicit `context.Context` and exit on `<-ctx.Done()`.
- No undocumented persistence path — `ca.bundle`, `cluster-ca.crt`, `cluster-ca.key`, and `cluster.json` are the four on-disk artifacts; all four are in the Tier-1 backup list at `backup.go:62–65`.
- No undocumented mutation surface — `apiCARotate`, `apiCertsUpload`, `apiCACacheClear` are the three CA-mutating admin endpoints (plus `apiOCSPConfig` which is P5.3 territory, not P6.3).

**Backup / restore ownership** (cert material on disk, passphrase handling, restore semantics) is explicitly **out of P6 scope** per the program doc — D1.3 / D1.6 own it. This discovery records the on-disk artifacts but does not recommend changes to their handling.

---

## 1. Component inventory

### 1.1 `initRootCA(s *startupState)` — the startup site

Declared at `main.go:696–722`. Called at `main.go:188`, before `initURLCategories` (step 27 at `:190`) and `initScanning` (step 28 at `:194`). The function reads:

- `CULVERT_CA_PASSPHRASE` env var (`main.go:701`).
- CA bundle path from `*s.caPath` (CLI flag `-ca-path`) falling back to `s.fc.Proxy.CAPath` config (`main.go:702`).

Flow:

- `caPathVal != ""` → `certMgr.LoadOrInitCA(caPathVal, caPassphrase)` (`main.go:704`); on first boot generates + saves, otherwise decrypts + loads.
- `caPathVal == ""` → `certMgr.InitCA()` (`main.go:710`) — in-memory only, no persistence; warning logged.
- Stashes path + passphrase onto the `caRuntime` global so admin-API rotation can save back to the same location (`main.go:717–718`).
- If `certMgr.Ready()` returns true, spawns the background rotation goroutine via `StartCAAutoRotation(appLifecycleCtx, caPathVal, caPassphrase)` (`main.go:721`).

Startup-state carry: **none** — all CA state lives on package globals. No `s.ca*` fields.

Optionality: CA is optional. Empty `-ca-path` keeps the process running with in-memory CA and a logged warning; SSL-inspection still works but no persistence across restarts.

### 1.2 `certMgr` — MITM Root CA + leaf cache

Declared at `ca.go:59`:

```go
var certMgr = &CertManager{cache: map[string]*certCacheEntry{}}
```

Struct (`ca.go:43–57`):

- `mu sync.RWMutex` — guards every field below.
- `caCert *x509.Certificate` — Root CA cert; ECDSA P-256, 10-year validity, `KeyUsageCertSign | KeyUsageCRLSign`, `BasicConstraintsValid=true`, `IsCA=true`.
- `caKey *ecdsa.PrivateKey` — Root CA private key.
- `keyProvider KeyProvider` — optional external signer interface (HSM/KMS extensibility).
- `cache map[string]*certCacheEntry` — hostname → entry. Capacity 10_000 (`ca.go:36`), TTL 1h (`ca.go:37`).
- `cacheOrder []string` — insertion order for LRU eviction (10% drop when over capacity).
- `secondaryCACert *x509.Certificate` / `secondaryCAKey *ecdsa.PrivateKey` / `secondaryExpiry time.Time` (`ca.go:54–56`) — old CA retained during the 30-day rotation overlap window.

Encryption constants (`ca.go:79–86`):

- Magic header: `"PSCA"` (4 bytes).
- PBKDF2 iterations: `pbkdf2Iter = 600_000` (`ca.go:83`) — NIST SP 800-132 (2024) recommendation.
- PBKDF2 salt: 32 bytes (per-save random).
- AES-GCM nonce: 12 bytes (per-save random).
- Cipher: AES-256-GCM, key derived via PBKDF2-SHA256.

### 1.3 `caRuntime` — runtime-saved CA params

Declared at `ca.go:63–66`. Holds `path` and `passphrase` so the admin-API rotation handler can re-save to the operator's chosen location without re-reading flags. Plain struct under no lock (single-writer at startup at `main.go:717–718`, read-only thereafter).

**Security-sensitive ownership note (not a P6.3 fix; recorded for visibility — see §10 CA-8):** the CA passphrase is retained as a plaintext string field on the `caRuntime` struct for the lifetime of the process. This is consumed exclusively by the admin-API rotation path (`apiCARotate` → `certMgr.SaveCA(caRuntime.path, caRuntime.passphrase)`), and the design tradeoff is that **admin-API CA rotation works at runtime without re-prompting**. The cost is that a process memory dump or live-debugging attach after startup discloses the passphrase, which would let an attacker decrypt the on-disk `ca.bundle`. Mitigations available today: (a) `CULVERT_CA_PASSPHRASE` is an env var, not a flag, so it isn't visible in `ps`; (b) the bundle decryption is computationally bounded by 600_000 PBKDF2 iterations, so possession of `ca.bundle` alone without the passphrase remains hard. This is an operational tradeoff, not a defect; the alternative (re-prompt on every rotation) would prevent unattended cluster operation. Recorded for the security-review audit trail.

### 1.4 `globalClusterCA` — cluster-issuance CA

Declared at `enrollment.go:705`:

```go
var globalClusterCA = &clusterCA{}
```

Struct (`enrollment.go:693–703`):

- `mu sync.RWMutex`.
- `cert *x509.Certificate`, `key *ecdsa.PrivateKey`, `certPEM []byte` — primary CA + cached PEM encoding.
- `dir string` — persistence directory (holds `cluster-ca.crt` + `cluster-ca.key`).
- `secondaryCert *x509.Certificate`, `secondaryPEM []byte`, `secondaryExp time.Time` — dual-CA overlap state (parallels the Root-CA secondary).
- `onRotate func()` — callback installed by `buildServerTLS` (`controlplane.go:1777`) so `ImportCA` / `RotateIfNeeded` / `cleanupSecondaryCA` can rebuild the gRPC server's `ClientCAs` pool.

**Distinct from the MITM Root CA.** Different cert, different key, different validity period (10y self-signed via the cluster-CA template). The cluster CA's private key is stored **unencrypted** on disk at `<dir>/cluster-ca.key` (vs. the Root CA's PBKDF2 + AES-256-GCM bundle). See §10 finding CA-3.

### 1.5 `globalClusterStore` — enrollment + revocation registry

Declared at `enrollment.go:113`. Struct (`enrollment.go:106–111`):

- `mu sync.RWMutex`.
- `st ClusterState` — declared at `enrollment.go:47`; carries `Nodes map[string]*EnrolledNode`, `Tokens map[string]*EnrollToken`, `Revoked []RevokedCert`, plus CA-rotation progress tracking fields.
- `path string` — JSON persistence at `cluster.json`.
- `heartbeatCount int` — used to throttle disk writes (saves every 10th heartbeat under normal conditions).

Tokens are stored as `SHA-256(token)` hex; plaintext token bytes never persist.

### 1.6 `cpTLSConfig` — gRPC server TLS config holder

Declared at `controlplane.go:1712–1718`:

```go
var cpTLSConfig struct {
    mu      sync.Mutex
    cfg     *tls.Config
    baseCAF string
}
```

Held under its own `sync.Mutex`. Populated by `buildServerTLS` on CP startup (`controlplane.go:1768–1772`) and re-read by `rebuildCPCertPool` (`controlplane.go:1723–`) when `globalClusterCA.onRotate` fires.

### 1.7 `globalOCSP` — upstream OCSP cache

Declared at `ocsp.go:42`. **Already covered by P5.3** (`upstreamOpTLSCfg` + `ConfigureTransportOCSP` route through `swapUpstreamTransport`). Mentioned here only for completeness — the OCSP checker is consumed for **upstream** TLS validation, not for OCSP responses Culvert serves to clients. **Culvert does NOT serve OCSP responses for its own Root CA; leaf certs carry no AIA OCSP responder extension and no CRL distribution point.** See §10 finding CA-5.

### 1.8 `pendingCARotation` — two-step confirmation slot

Declared at `ui_security.go:18–23`. Holds a 60s-TTL token to gate the destructive rotation path: step 1 issues a token, step 2 redeems it. Under its own `sync.Mutex`.

### 1.9 Admin-UI TLS

Built by `selfSignedTLS()` (`tls.go:28`). Fresh ECDSA P-256 key on every process start, validity -1h … +10y. SANs assembled from (a) the always-present `127.0.0.1` / `::1` / `localhost`, (b) auto-detected local interface IPs, (c) the `CULVERT_PUBLIC_IP` env var, (d) the `-ui-san` flag, and (e) cloud metadata IMDS queries (AWS / GCP / Azure, 2s timeout each). The returned `*tls.Config` is consumed by `startUI` (`main.go:1133`). Replacement requires process restart — `apiCertsUpload target=ui` only validates the PEM material.

---

## 2. Ownership graph (writers + readers)

### 2.1 Writers — startup phase (single-threaded, pre-listener-accept)

| Writer | Touches | Location |
|---|---|---|
| `certMgr.LoadOrInitCA(path, passphrase)` or `.InitCA()` | `certMgr.{caCert,caKey,cache,cacheOrder}` under `mu.Lock` | `main.go:704, 710` → `ca.go:90–148` |
| `caRuntime.path = ...; caRuntime.passphrase = ...` | plain struct fields | `main.go:717–718` |
| `StartCAAutoRotation(appLifecycleCtx, ...)` | spawns one ticker goroutine | `main.go:721` → `ca.go:512–525` |
| `selfSignedTLS()` | returns a fresh `*tls.Config` consumed by `startUI` | `tls.go:28` → `main.go:1133` |
| `globalClusterCA.InitOrLoadCA(dir)` (when CP enabled) | `globalClusterCA.{cert,key,certPEM,dir}` under `mu.Lock` | `enrollment.go` → invoked from `enableControlPlane` |
| `globalClusterStore.Load(path)` (when CP enabled) | `globalClusterStore.st` under `mu.Lock` | `enrollment.go` → invoked from `enableControlPlane` |
| `buildServerTLS(certFile, keyFile, caFile)` (when CP enabled) | populates `cpTLSConfig` + wires `globalClusterCA.onRotate = rebuildCPCertPool` | `controlplane.go:1745–1781` |
| `StartHeartbeatMonitor(appLifecycleCtx.Done())` | spawns heartbeat goroutine | `enrollment.go:567–580`, invoked from `enableControlPlane` |

### 2.2 Writers — runtime phase (post-listener-accept; concurrent with hot path)

| Writer | Touches | Trigger | Synchronisation |
|---|---|---|---|
| `apiCARotate` POST (confirmed) | `certMgr.InitCA()` then `SaveCA(caRuntime.path, ...)` | Admin API (`ui_security.go:1040`) | `CertManager.mu.Lock` on rotation; **`auditEvent` only** at `ui_security.go:1108` — no `saveConfigVersion` |
| `apiCertsUpload target=mitm` | `certMgr.LoadCustomCA(certPEM, keyPEM)` + `certMgr.ClearCache()` | Admin API (`ui_security.go:253`) | `CertManager.mu.Lock`; `auditEvent` only at `:283` |
| `apiCertsUpload target=ui` | **validation only** via `certMgr.ParseTLSPair(certPEM, keyPEM)`; no persistence | Admin API (`ui_security.go:253`) | none required; restart required to apply |
| `apiCACacheClear` POST | `certMgr.ClearCache()` | Admin API (`ui_security.go:1027`) | `CertManager.mu.Lock`; `auditEvent` only at `:1036` |
| Auto-rotation ticker | `certMgr.RotateIfNeeded(...)` + `certMgr.cleanupSecondaryCA()` + `globalClusterCA.RotateIfNeeded()` | 24h ticker | `CertManager.mu.Lock` / `clusterCA.mu.Lock` |
| `globalClusterCA.ImportCA(...)` / `.RotateIfNeeded()` / `.cleanupSecondary()` | cert/key fields under `clusterCA.mu.Lock`; persists `cluster-ca.crt/.key`; triggers `onRotate` callback → `rebuildCPCertPool` | Admin API + auto-rotation ticker | `clusterCA.mu.Lock` followed by `cpTLSConfig.mu.Lock` |
| `globalClusterStore` mutations (token consume, node update, revocation, CA rotation progress) | `ClusterState` fields | Enrollment RPC, heartbeat, admin API | `ClusterStore.mu.Lock` |
| HA standby restore (`ha.go:223–227`) | `globalClusterCA.ImportCASilent(certPEM, keyPEM)` after decrypting key via `haDecryptKey(CAKeyEncrypted, token)` | HA promote | `clusterCA.mu.Lock` |
| HA standby restore deprecated path (`ha.go:230–232`) | `globalClusterCA.ImportCASilent(...)` with plaintext `CAKeyPEM` | HA bundle with legacy plaintext key field | same | 

**`saveConfigVersion` coverage:** verified by `grep "saveConfigVersion" ui_security.go` → only `apiSecurity` (`:217`), `apiContentScan` add/remove (`:339, :355`), and `apiFileblock` add/remove (`:396, :411`). **Zero CA admin handlers call `saveConfigVersion`.** Every CA mutation is in the audit ring but absent from the config-version snapshot tier. See §10 finding CA-1.

### 2.3 Readers — proxy hot path (concurrent, every request)

| Reader | Reads | Location |
|---|---|---|
| MITM TLS handshake `GetCertificate` callback | `certMgr.cache` (RLock) → on miss, `signLeaf(host)` (Lock for cache fill) | `ca.go:599–645`, wired into `proxy.go:1219` |
| `signLeaf(host)` | `certMgr.caCert`, `.caKey`, `.secondaryCACert` for chain construction | `ca.go:665–716` |

### 2.4 Readers — CP/DP gRPC

| Reader | Reads | Location |
|---|---|---|
| gRPC accept loop | TLS handshake reads `cpTLSConfig.cfg.{Certificates, ClientCAs, ClientAuth, MinVersion}` | stdlib `crypto/tls` driven by `controlplane.go:1033` `srv.Serve(ln)` |
| DP gRPC dial | TLS handshake reads `tlsCfg.{Certificates, RootCAs, MinVersion}` from `buildClientTLS` | `controlplane.go:1783–1797` |
| Enrollment RPC handler | reads `globalClusterStore.st.Tokens`, signs CSR via `globalClusterCA.SignCSR(...)` | `controlplane.go:700–780` |
| `verifyNodeCert` (every authenticated RPC) | reads enrolled-node registry + revocation list | `controlplane.go:542–570` |

### 2.5 Readers — admin API (low-rate)

| Reader | Reads | Location |
|---|---|---|
| `apiCACert` GET | `certMgr.CACertPEM()` + `.CACertInfo()` | `ui_security.go:226–249` |
| `apiCAStatus` GET | cache size/max/TTL, leaf validity, rotation overlap, key provider, secondary metadata | `ui_security.go:981–1007` |
| `apiCADownload` GET | `certMgr.CACertPEM()` | `ui_security.go:1009–1025` |
| `apiCAKeyProvider` GET | `certMgr.keyProvider` name | `ui_security.go:1113` |
| `apiOCSPConfig` GET | `globalOCSP.{Enabled, CacheLen}` (P5.3 territory) | `ui_security.go:1134` |
| Backup capture | reads on-disk `ca.bundle`, `cluster-ca.crt`, `cluster-ca.key`, `cluster.json` directly | `backup.go:62–65` |

### 2.6 Cross-cluster sync (`controlplane.go ConfigSnapshot`)

`ConfigSnapshot` carries `CAFingerprint string` (`controlplane.go:79`) — the SHA-256 hex of the cluster CA cert. **Cert material itself is NOT in the snapshot.** DP nodes track the most recently observed fingerprint via `lastSeenCAFingerprint atomic.Value` (`controlplane.go:1434–1436`), and when the snapshot's fingerprint differs they trigger a `RenewCert` RPC (`controlplane.go:1529–1538`). The RenewCert response contains the new cluster CA cert (`controlplane.go:779`, `CAPEM`).

HA leader→standby uses a separate path. `HAStateBundle` (`controlplane.go:837–`) carries `CACertPEM string` (`:843`) and `CAKeyEncrypted string` (encrypted with the HA token via PBKDF2 + AES-256-GCM). A deprecated `CAKeyPEM string` plaintext field also exists for backwards compatibility (`ha.go:230–232`). See §10 finding CA-4.

**MITM Root CA is NOT carried by `ConfigSnapshot` and is NOT in any HA bundle.** Each node has its own MITM Root CA (or none); cluster sync does not unify it.

---

## 3. Goroutine ownership / lifecycle

Two long-lived goroutines are spawned by the CA/TLS subsystem. Both take an explicit context and exit on cancellation.

| Goroutine | Spawn site | Parent ctx | Cancel mechanism | Health |
|---|---|---|---|---|
| `StartCAAutoRotation(appLifecycleCtx, caPath, passphrase)` — 24h ticker | `ca.go:514–525`, invoked from `main.go:721` | `appLifecycleCtx` | `appLifecycleCancel()` via `app-lifecycle-cancel` early-shutdown hook (order 40) | ✅ Cancellable. **Handles BOTH Root CA AND Cluster CA rotation in the same loop** — invokes `certMgr.RotateIfNeeded(...)`, `certMgr.cleanupSecondaryCA()`, AND `globalClusterCA.RotateIfNeeded()` at `ca.go:523–525`. |
| `StartHeartbeatMonitor(appLifecycleCtx.Done())` — 30s ticker | `enrollment.go:567–580`, invoked from `enableControlPlane` | `appLifecycleCtx.Done()` channel | same | ✅ Cancellable. Marks unreachable nodes as `disconnected` after configurable timeout, GCs expired tokens + revocations. |

Plus one gRPC server goroutine:

| Goroutine | Spawn site | Cancellation |
|---|---|---|
| `go srv.Serve(ln)` — gRPC accept loop | `controlplane.go:1033` | `StopControlPlaneGRPC()` calls `srv.GracefulStop()` (`:1046`); registered as `control-plane-grpc-stop` early shutdown hook (order 20). |

**No detached / unparented goroutine was found in the CA/TLS subsystem.** Sharply better than the P6.1 UC-3 SaaS-feed gap (`globalSaaSFeed.syncLoop` under `context.Background()`).

The cloud-metadata IMDS queries inside `selfSignedTLS()` (`tls.go:28–107`) run synchronously during startup; they do NOT spawn background goroutines and are bounded by per-cloud 2s timeouts. No leak surface.

---

## 4. Mutation authority map

The CA/TLS subsystem has more independent ownership scopes than any prior P6 target. **No race-detector-flagged surface was found** under the existing synchronization.

### 4.1 Startup writers — "configuration phase, single-threaded"

All writers in §2.1 are sequential. No concurrent reader yet because the proxy / admin-UI / gRPC listeners haven't started accepting.

### 4.2 Runtime writers — "operator + ticker mutation, concurrent with hot path"

| Path | Writes | Live races against |
|---|---|---|
| `apiCARotate` confirmed | `certMgr.{caCert,caKey,secondaryCACert,secondaryCAKey,secondaryExpiry,cache,cacheOrder}` under `mu.Lock`; persists to disk under `caRuntime.path` | MITM `GetCertificate` (RLock) — RWMutex makes safe. In-flight leaf signings complete against the snapshotted `caCert`/`caKey`. |
| `apiCertsUpload target=mitm` | same + `ClearCache()` | same |
| `apiCACacheClear` | `certMgr.{cache,cacheOrder}` under `mu.Lock` | same |
| Auto-rotation ticker | `certMgr.*` + `globalClusterCA.*` under their respective `mu.Lock`s | MITM hot path + gRPC TLS handshakes — both RWMutex-bounded |
| `globalClusterCA.ImportCA` / `.RotateIfNeeded` / `.cleanupSecondary` | cert/key fields under `clusterCA.mu.Lock`; persists `cluster-ca.crt/.key`; triggers `onRotate` callback → `rebuildCPCertPool` swaps the `ClientCAs` pool on the live `cpTLSConfig.cfg` under `cpTLSConfig.mu.Lock` | gRPC TLS handshakes reading `cpTLSConfig.cfg.ClientCAs` — `tls.Config` field write is **inside a single `cpTLSConfig.mu.Lock` boundary**, but the stdlib TLS handshake reads the field without taking that lock. **See §6 risk CA-R-3.** |
| HA standby `ImportCASilent` (encrypted path) | `clusterCA.{cert,key,certPEM,dir}` under `mu.Lock` after `haDecryptKey` | same as `ImportCA` |
| HA standby `ImportCASilent` (deprecated plaintext path) | same | same; security boundary: token isn't required for trust on the cluster CA — see §10 CA-4 |
| `globalClusterStore` mutations | `ClusterState` fields under `mu.Lock`; persists `cluster.json` | heartbeat read path + admin API reads — RWMutex-bounded |

### 4.3 Mutation authority matrix

| Mutator | `certMgr.caCert/Key` | `certMgr.cache` | `globalClusterCA` | `globalClusterStore` | `cpTLSConfig.cfg` | Synchronised? |
|---|---|---|---|---|---|---|
| Startup: `initRootCA` + `enableControlPlane` | ✓ | ✓ | ✓ | ✓ | ✓ | N/A (single-threaded) |
| Admin: `apiCARotate` | ✓ | ✓ (cleared on InitCA) | – | – | – | ✅ `CertManager.mu` |
| Admin: `apiCertsUpload target=mitm` | ✓ | ✓ (cleared) | – | – | – | ✅ |
| Admin: `apiCACacheClear` | – | ✓ | – | – | – | ✅ |
| Admin: enrollment / token / revocation handlers | – | – | – | ✓ | – | ✅ `ClusterStore.mu` |
| Admin: cluster-CA import | – | – | ✓ | – | ✓ (via `onRotate`) | ✅ `clusterCA.mu` + `cpTLSConfig.mu` |
| Auto-rotation ticker | ✓ | ✓ | ✓ | – | ✓ (via `onRotate`) | ✅ each store's mu |
| Heartbeat monitor | – | – | – | ✓ (node state, GC) | – | ✅ |
| Enrollment RPC | – | – | – | ✓ (token consume, node register) | – | ✅ |
| HA standby `ImportCASilent` | – | – | ✓ | – | ✓ (via `onRotate`) | ✅ |
| Hot path: per-request | RLock | RLock/Lock-on-miss | – | – | tls handshake read | ✅ |
| Hot path: gRPC handshake | – | – | RLock (`AllCACertsPEM`) for pool build | – | tls handshake read | ✅ |

**All concurrent writer/reader pairs are synchronised** by one of: per-store `sync.RWMutex`, `cpTLSConfig.mu sync.Mutex`, or the `onRotate` callback chain. The one nuance is the stdlib TLS handshake reading `cpTLSConfig.cfg.ClientCAs` without the `cpTLSConfig.mu` lock — see §6 CA-R-3.

---

## 5. Persistence / reload interactions

### 5.1 Persistence

| Store | On-disk artifact | Atomicity | Encryption at rest |
|---|---|---|---|
| `certMgr` Root CA | `ca.bundle` at `caRuntime.path` | `SaveCA` writes via `atomicWriteFile(cleanPath, data, 0o600)` at `ca.go:174`. The helper (defined at `main.go:2093`) performs: unique tmp file in same dir → `f.Write` → `f.Chmod` → `f.Sync()` (file fsync, `:2114`) → `f.Close` → `os.Rename` → `os.Open(dir)` + `d.Sync()` (best-effort parent-dir fsync, with documented graceful skip on `EINVAL`/`ENOTSUP`/`EOPNOTSUPP`). | ✅ AES-256-GCM, key derived via PBKDF2-SHA256 with 600_000 iterations; magic header `"PSCA"` + version byte + iter count + 32-byte salt + 12-byte nonce + ciphertext (`ca.go:79–86, 150–`) |
| `certMgr` leaf cache | **not persisted** (memory-only) | N/A | N/A |
| `globalClusterCA` | `cluster-ca.crt` + `cluster-ca.key` under `<dir>/` | InitOrLoadCA save uses `atomicWriteFile` at `enrollment.go:806` (cert) and `:809` (key); ImportCA save uses `atomicWriteFile` at `enrollment.go:1059` (cert) and `:1062` (key). Same fsync semantics as the Root-CA path. | ❌ **plaintext on disk** — see §10 CA-3 |
| `globalClusterStore` | `cluster.json` | `Save` writes via `atomicWriteFile(cs.path, data, 0o600)` at `enrollment.go:178`. Same fsync semantics. | ❌ plaintext (token hashes are SHA-256 — never plaintext) |
| Admin-UI TLS cert | **not persisted** — regenerated on every process start by `selfSignedTLS()` | N/A | N/A |
| `globalOCSP` cache | **not persisted** (P5.3 territory) | N/A | N/A |
| Upstream mTLS template | **not persisted** (P5.3 territory) | N/A | N/A |

Backup tier coverage (`backup.go:60–66`): `ca.bundle`, `cluster-ca.crt`, `cluster-ca.key`, `cluster.json` all listed as `Required: true, OptionalFirstRun: true` in the **Tier-1 required** section (commented `// ── Tier 1 — required, but all first-run-optional in practice`). **All four are Tier-1 backed** — `Required: true` is the per-artifact source of truth for tier classification. Restore semantics (`CULVERT_CA_PASSPHRASE` matching, cluster-CA key trust-on-restore, etc.) are owned by D1.3 / D1.6 per `RUNTIME-OWNERSHIP.md` §2 — **out of P6 scope**.

### 5.2 SIGHUP / hot reload

**`applyHotReload(fc)` does not touch any CA / TLS state.** Verified against the branch list in `main.go:2205–2270`: blocklist, policy rules, default action, rate limit, IP filter mode, rewrite rules, upstream proxy pool. No Root-CA reload, no Cluster-CA reload, no admin-UI TLS reload, no `cpTLSConfig` rebuild, no enrollment-store reload.

**Observed behaviour, not assessed intent.** Restart is required for: rotating the admin-UI self-signed cert, replacing the operator-provided gRPC server cert (the `-cp-grpc-cert` / `-cp-grpc-key` flags), or picking up an externally-modified `ca.bundle`. All other CA/TLS mutations route through the admin API. See §10 finding CA-6.

### 5.3 Config-version rollback (`configversion.go`)

`grep "saveConfigVersion" ui_security.go` returns five hits at `:217, :339, :355, :396, :411` — none of them are in CA handlers. The four CA-mutating admin endpoints (`apiCARotate`, `apiCertsUpload`, `apiCACacheClear`, plus the P5.3-owned `apiOCSPConfig`) emit `auditEvent` but do **not** call `saveConfigVersion`. A rollback v3→v2 therefore leaves the CA exactly as it was — which is **probably correct** for the rotation case (you don't want a config rollback to silently revert your CA), but is at minimum worth recording so the asymmetry is intentional rather than accidental. See §10 finding CA-1 for the per-handler classification.

### 5.4 Cluster sync (`controlplane.go ConfigSnapshot`)

| Field | Carried by ConfigSnapshot | DP apply | CP capture |
|---|---|---|---|
| `CAFingerprint string` | ✅ (`controlplane.go:79`) | DP compares against `lastSeenCAFingerprint atomic.Value` (`:1434–1436`); on change, triggers `RenewCert` RPC (`:1529–1538`) | `snap.CAFingerprint = fp` at `controlplane.go:579, :1626` |
| Cluster CA cert PEM | ❌ not in `ConfigSnapshot` | – (DP receives cert in `Enroll` / `RenewCert` response: `CAPEM string` at `:779`) | – |
| Cluster CA key | ❌ not in `ConfigSnapshot` | – | – |
| Enrollment tokens | ❌ not in `ConfigSnapshot` | – (tokens are per-CP secret state) | – |
| Enrolled nodes / revocations | ❌ not in `ConfigSnapshot` | – (per-CP authority over node trust) | – |
| Root CA (MITM) | ❌ not carried in any cluster path | – | – |
| Admin-UI TLS | ❌ not carried | – | – |

HA leader→standby uses `HAStateBundle` (`controlplane.go:837–`) which carries `CACertPEM` + `CAKeyEncrypted` (encrypted via HA token, PBKDF2 + AES-256-GCM) plus a deprecated `CAKeyPEM` plaintext fallback (`ha.go:230–232`). Standby promotion calls `globalClusterCA.ImportCASilent(certPEM, keyPEM)`.

---

## 6. Hot-path concurrency risks

| Risk | Severity | Description |
|---|---|---|
| **CA-R-1**: `certMgr` write/read race | LOW (resolved) | `sync.RWMutex`. Leaf-signing reads `caCert` / `caKey` under RLock; rotation / cache-clear take the write lock. Cache LRU eviction is bounded inside the same write lock. No torn-read surface. |
| **CA-R-2**: leaf-cache miss → sign → fill race | LOW (resolved) | `GetCertificate` upgrades RLock → Lock only after the miss; concurrent misses on the same host produce redundant signings but the cache fill is last-write-wins and both are valid certs. No correctness gap. |
| **CA-R-3**: `cpTLSConfig.cfg.ClientCAs` swap vs stdlib TLS handshake read | **UNVERIFIED — potential race; needs race-test confirmation.** | `rebuildCPCertPool` (`controlplane.go:1723–1743`) writes `cpTLSConfig.cfg.ClientCAs = pool` (line `:1741`) under `cpTLSConfig.mu.Lock` (taken at `:1724`). The stdlib TLS handshake reads `tlsCfg.ClientCAs` directly **without taking `cpTLSConfig.mu`**. <br/><br/>**Earlier draft of this doc classified the surface as "resolved, pointer-sized writes are atomic." That reasoning is unsafe under the Go memory model** — unsynchronized read/write to the same memory location is undefined behavior regardless of word size; the race detector will flag it, and the Go compiler can theoretically perform optimizations that break C-style "atomic pointer write" assumptions. <br/><br/>Whether this surface trips `-race` in practice depends on whether any current test exercises `rebuildCPCertPool` concurrently with an in-flight TLS handshake. **No such test exists today** — `coldstart_clusterca_test.go` covers `ImportCA` semantics but not concurrent handshake activity; `controlplane_*_test.go` covers RPC behavior but not the rotation-during-handshake interleaving. **A focused contract test is needed before this surface can be classified as race-safe.** See §10 CA-7. |
| **CA-R-4**: `globalClusterCA.onRotate` callback fires while another rotation is in progress | LOW (resolved) | Both `ImportCA` and `RotateIfNeeded` take `clusterCA.mu.Lock` for the duration of the swap, then call `onRotate` after `Unlock`. `rebuildCPCertPool` takes `cpTLSConfig.mu.Lock` independently. Two near-simultaneous rotations serialize through `clusterCA.mu`. |
| **CA-R-5**: cache size > 10_000 LRU eviction | LOW (resolved) | Eviction is on-demand inside `GetCertificate`'s cache-fill path under the write lock. ~10% drop when over capacity. No background sweeper goroutine. |
| **CA-R-6**: dual-CA overlap expiry race | LOW (resolved) | `cleanupSecondaryCA` runs in the same 24h ticker as rotation (`ca.go:524`). If the secondary expires between ticks, leaf-signing still constructs the chain correctly because `signLeaf` reads `secondaryCAExpiry` and skips the secondary when expired. |
| **CA-R-7**: HA standby decrypt-then-import race | LOW (resolved) | Single sequential path on standby: `haDecryptKey` → `ImportCASilent` → `onRotate` → `rebuildCPCertPool`. No concurrent writer during HA promotion. |

**No risk requires a P5.3-style ownership refactor.** Six of the seven surfaces are resolved by existing synchronization. **CA-R-3 is the one open item:** the `cpTLSConfig.cfg.ClientCAs` write-vs-stdlib-read pair is unverified under `-race` because no current test exercises rotation concurrently with a TLS handshake. The fix — if `-race` confirms a race — is to either replace the field-mutation pattern with a swap of `cpTLSConfig.cfg` itself (mirror of the P5.3 `swapUpstreamTransport` design), or to use a `GetConfigForClient` callback so the handshake reads via a method that can take the mutex. Both are non-trivial; deferring to a focused follow-up after a race-test result. See §10 CA-7.

---

## 7. Shutdown interactions

Owned hooks:

- `control-plane-grpc-stop` (early, order 20) — calls `StopControlPlaneGRPC()` (`controlplane.go:1043–`), which invokes `srv.GracefulStop()` to drain in-flight RPCs.
- `app-lifecycle-cancel` (early, order 40) — cancels `appLifecycleCtx`, which fires:
  - `StartCAAutoRotation` goroutine exit via `<-ctx.Done()` (`ca.go:520`).
  - `StartHeartbeatMonitor` goroutine exit via `<-done` (`enrollment.go:573`).

No dedicated `ca-*` or `cluster-ca-*` late hook exists, and **none is needed**: the leaf cache is memory-only, no in-flight signing operation holds resources beyond a per-handshake `*tls.Certificate`, and the persisted bundles (`ca.bundle`, `cluster-ca.crt`, `cluster-ca.key`, `cluster.json`) are already on disk via synchronous save-on-write. There is no equivalent of `scanSvc.Shutdown` for the CA subsystem because there is no in-process server-side resource to drain.

Lifecycle ordering (informational): `control-plane-grpc-stop=20` precedes `app-lifecycle-cancel=40` precedes any late hook. As a side effect the gRPC server stops accepting before the CA-rotation ticker exits, but the dependency is not load-bearing — neither path holds a lock the other needs.

---

## 8. Cross-cut: existing test coverage

| File | Coverage |
|---|---|
| `ca_test.go` | `InitCA`, `SaveCA` / `LoadCA` round-trip, `LoadOrInitCA` first-boot path, `LoadCA` wrong-passphrase failure, `SaveCA` with empty passphrase (plain-PEM mode), `signLeaf` basic cert generation. |
| `ca_rotation_test.go` | `StartCAAutoRotation`, `RotateIfNeeded`, `RecordNodeRenewed`, persistence of rotation state, `cleanupSecondaryCA`, dual-CA overlap chain construction. |
| `enrollment_test.go` | Token generation / validation / consumption / TTL / CIDR restriction / nodeID prefix, node registration, revocation, heartbeat, CA-rotation tracking on the ClusterStore. |
| `enroll_util_test.go` | `ClusterStore` Load/Save, node list/update, token list/delete, revocation list, GC of expired tokens + revocations. |
| `controlplane_extra_test.go` | Enrollment RPC, RenewCert RPC, config-sync bounds, HA state bundle round-trip. |
| `controlplane_verifynodecert_security_test.go` | Node cert serial verification against the revocation list. |
| `controlplane_getconfig_security_test.go` | `CAFingerprint` propagation through the config snapshot. |
| `controlplane_snapshot_bounds_test.go` | `ConfigSnapshot` size caps (`maxSnap*` constants). |
| `coldstart_clusterca_test.go` | Cluster CA `InitOrLoadCA`, dual-CA `ImportCA`, secondary cleanup. |
| `mtls_ocsp_startup_test.go` | P5.3 territory; `loadMTLSAndOCSP`, client-cert loading, OCSP enable/disable. |
| `upstream_transport_race_test.go` / `upstream_transport_swap_test.go` | P5.3 race + swap tests on `upstreamOpTLSCfg`. |

CI runs all of the above under `-race -count=1 -timeout=15m` per CLAUDE.md.

**Gaps relevant to a future implementation phase (NOT P6.3 scope; flagged for posterity):**

1. No test interleaves `apiCARotate` / `apiCertsUpload target=mitm` with concurrent MITM `GetCertificate` calls under `-race`. The RWMutex makes this clean by construction, but a focused contract test would prove it.
2. No test interleaves `globalClusterCA.ImportCA` with concurrent gRPC handshakes (the CA-R-3 surface). The `*x509.CertPool` pointer-write semantics make this safe, but a contract test would pin it.
3. No test pins the `apiCARotate` "no `saveConfigVersion`" contract — currently no handler calls it, which is plausibly intentional, but if CA-1 is fixed in either direction (call it / explicitly mark it as out-of-band) a regression test should pin the decision.

---

## 9. Verdict on Phase 6 strategy

### 9.1 P6.3 — discovery

This document. **Complete.** No production code; no roadmap expansion; no speculative redesigns.

### 9.2 Implications for Phase 6 sequencing

- The four P6 discoveries (P6.1 ✅, P6.2 ✅, P6.3, P6.4) remain **independent**. P6.3 does not gate any of them.
- **None of the findings in this discovery warrant an in-program Phase 6 implementation PR.** The race surfaces are resolved by existing synchronization. The six deferred follow-ups (§10 CA-1…CA-6) are governance + durability + observability hygiene, not blockers.
- **Backup / restore ownership of the on-disk CA artifacts is out of P6 scope per `RUNTIME-OWNERSHIP.md` §2** — D1.3 / D1.6 own it. This discovery records the on-disk artifacts but does not recommend changes to their handling.
- **P3.4 cluster heartbeat flush** still gated on **P6.4 cluster discovery**, NOT on P6.3.

### 9.3 What this discovery does NOT recommend

- No `upstreamTransport`-style ownership refactor on `certMgr` or `globalClusterCA`. Both have coherent RWMutex contracts and single mutation APIs.
- No move of CA state onto `startupState`. The package globals work; the only carry that would be needed (`caRuntime.path` + `caRuntime.passphrase`) is already a tiny holder.
- No `applyHotReload` coupling for CA / TLS state. Observed behaviour recorded; intent not assessed.
- No expansion of `ConfigSnapshot` to carry CA cert material. The `CAFingerprint`-then-`RenewCert` pattern is intentional and correct; expanding the snapshot would create a much larger trust-distribution surface.
- No removal of the deprecated `HAStateBundle.CAKeyPEM` plaintext field. That decision belongs in an HA-specific PR with explicit backwards-compat analysis — not a sweeping P6 refactor.
- No re-discovery of the P5.3 upstream mTLS / OCSP path. That ownership refactor shipped in PR #237; the trust flow here references it.

---

## 10. Findings worth filing as deferred follow-ups (NOT P6.3 scope)

These were uncovered during this discovery but are out of P6.3's scope. They are noted here so they aren't lost; they should be triaged separately and may belong elsewhere (mirrors of resolved follow-ups, or new items in their own family).

| ID | Finding | Pre-existing? | Mirror |
|---|---|---|---|
| **CA-1** | No CA admin handler calls `saveConfigVersion`. Verified by `grep "saveConfigVersion" ui_security.go` returning only `apiSecurity` (`:217`), `apiContentScan` add/remove (`:339, :355`), `apiFileblock` add/remove (`:396, :411`). Four CA-mutating handlers route only through `auditEvent`: `apiCARotate` (`:1040–1110`, audits `ca.rotate_requested` + `ca.rotate`), `apiCertsUpload` (`:253–295`, audits `certs.upload_mitm` + `certs.upload_ui`), `apiCACacheClear` (`:1027–1038`, audits `ca.cache_clear`), and `apiOCSPConfig` (`:1134–1177`, P5.3 territory). **Classification (parallels P6.2 SC-1):** <br/>• **Category A — persistent-CA mutations (reasonable `saveConfigVersion` candidates):** `apiCARotate` confirmed step, `apiCertsUpload target=mitm`. These change the operator-authoritative cert material and are arguably rollback-tier events — but they may also be the kind of mutation an operator *never* wants a config rollback to silently revert. Triage decision required, not a unilateral fix.<br/>• **Category B — operational/transient (probably should NOT snapshot):** `apiCACacheClear` (transient memory state), `apiCARotate` unconfirmed step (token issuance only), `apiCertsUpload target=ui` (validation only — no persistence).<br/>**Recommended treatment:** open an explicit triage discussion before any code change. The asymmetry with `apiContentScan` (which *does* snapshot) is real, but a CA rotation snapshotting itself into a rollback-tier event is a non-trivial semantic decision. | Yes | P6.1 UC-4 (`apiURLCat` / `apiURLCatHost`); P6.2 SC-1 (scanner admin handlers) |
| **CA-2** | No Prometheus metrics for CA operations. `metrics.go` exposes `culvert_clamav_blocked_total`, `culvert_yara_blocked_total`, `culvert_scan_cache_size`, etc., but no `culvert_ca_*` / `culvert_tls_*` / `culvert_cert_*` family. Specifically missing: leaf cache hit/miss rate (the cache fields exist on `certMgr` but are not surfaced), leaf signing latency, CA rotation event counter, cluster-CA rotation counter, enrollment-token consumed/expired counters, heartbeat monitor disconnection counter. Operators currently have no way to detect "CA rotation happened" or "leaf cache thrashing" without parsing logs. **Group with P6.1 UC-6 and P6.2 SC-2** in a single observability follow-up. | Yes | P6.1 UC-6; P6.2 SC-2 |
| **CA-3** | `globalClusterCA` private key is stored **unencrypted** on disk at `<dir>/cluster-ca.key`. Compare to the MITM Root CA at `caRuntime.path` which is AES-256-GCM + PBKDF2 (600_000 iterations) under `CULVERT_CA_PASSPHRASE`. The cluster CA is the trust anchor for every DP node's gRPC client cert — compromise of the file gives an attacker the ability to mint cluster-trusted DP certs. **Whether this is intentional design or a deferred hardening item is not assessed by this discovery.** The fix is non-trivial: it would require either (a) a second passphrase env var (`CULVERT_CLUSTER_CA_PASSPHRASE`?) which doubles the operator's key-management surface, or (b) reusing `CULVERT_CA_PASSPHRASE` for both (simpler but cross-couples two trust scopes). The decision belongs in an HA + enrollment design PR, not a unilateral hardening. **No action recommended now; recording for visibility.** | Yes | None — first time this gap is recorded |
| **CA-4** | `HAStateBundle` carries the cluster-CA private key via two paths: the current `CAKeyEncrypted string` field (encrypted with the HA token, PBKDF2 + AES-256-GCM; decrypted at `ha.go:223–227`) AND a deprecated `CAKeyPEM string` plaintext fallback (`ha.go:230–232`). The plaintext field is consumed when present — a leader running a pre-encrypted-bundle build pushes plaintext to a standby running the new build, and the standby accepts it. **The deprecated path is a known backwards-compat affordance, not a security gap per se**, but it is worth documenting explicitly because (a) it crosses the trust boundary (HA token is no longer required to learn the cluster CA private key on the plaintext path), and (b) there's no protocol-version negotiation that surfaces "this peer is on the old format." Removal of the plaintext path requires a coordinated cluster upgrade; recording as a future-fragility item rather than a current correctness risk. | Yes | None — recording for visibility |
| **CA-5** | Culvert-issued leaf certs (MITM) do NOT carry an AIA OCSP responder extension or a CRL distribution point. Culvert does not serve OCSP responses for its own Root CA. Clients verifying a Culvert-signed leaf rely on whatever path validation the OS / browser trust store provides — but because the Root CA is normally installed manually (operator-provisioned trust), there is no online revocation check on a per-leaf basis. Combined with the 24-hour leaf validity (`ca.go:686`) and the 10-year Root CA validity (`ca.go:104`), the practical revocation story is "rotate the Root CA via `apiCARotate` and rely on the 30-day dual-CA overlap." **This is a design property, not a defect.** Recording explicitly because operators arriving from a public-CA mental model may expect OCSP / CRL behaviour that isn't there. | Yes | None — design property recorded |
| **CA-6** | `applyHotReload(fc)` (`main.go:2205–2270`) does not touch any CA / TLS state — no Root-CA reload, no cluster-CA reload, no admin-UI TLS rebuild, no `cpTLSConfig` repopulate. **Observed behaviour; intent not assessed by this discovery.** Restart is required for: rotating the admin-UI self-signed cert (without using `apiCertsUpload target=ui` which only validates), replacing the operator-provided gRPC server cert (the `-cp-grpc-cert` / `-cp-grpc-key` flags), or picking up an externally-modified `ca.bundle`. All CA admin-API paths work at runtime; only YAML-config-driven CA changes need a restart. Worth recording because (a) it's surprising for operators arriving from the rate-limit / rewrite / upstream subsystems that *do* hot-reload, and (b) any future hot-reload effort would need to consider CA state carefully — most CA mutations have significant security side-effects. **No action recommended now; recording for visibility.** | Yes | P6.2 SC-5 (same observation for scanner state) |
| **CA-7** | `rebuildCPCertPool` (`controlplane.go:1741`) writes `cpTLSConfig.cfg.ClientCAs` under `cpTLSConfig.mu`; stdlib TLS handshake reads `tlsCfg.ClientCAs` without that mutex. **Potential data race under the Go memory model regardless of pointer-write width.** No current test exercises rotation concurrently with a TLS handshake (`coldstart_clusterca_test.go` covers `ImportCA` semantics but not concurrent handshakes; `controlplane_*_test.go` covers RPC behaviour but not rotation-during-handshake interleaving). **Deferred follow-up: focused race test** — call `globalClusterCA.ImportCA(...)` (or directly invoke `rebuildCPCertPool`) in one goroutine while N goroutines drive `tls.Dial` against the gRPC listener, under `go test -race -count=1`. If `-race` flags the surface, the fix is one of: (a) replace `cpTLSConfig.cfg.ClientCAs = pool` with a swap of `cpTLSConfig.cfg` itself (the P5.3 `swapUpstreamTransport` pattern), or (b) populate `cpTLSConfig.cfg.GetConfigForClient = func(...) (*tls.Config, error) { ... }` so the handshake reads the pool via a method that can take `cpTLSConfig.mu`. Both fixes are non-trivial; defer the design choice to the follow-up PR after the race test produces a result. | Yes (latent) | P5.3 `swapUpstreamTransport` ownership model |
| **CA-8** | The CA passphrase is retained as a plaintext string on the `caRuntime` struct (`ca.go:63–66`, populated at `main.go:717–718`) for the lifetime of the process. Required to keep admin-API CA rotation working at runtime (`apiCARotate` calls `certMgr.SaveCA(caRuntime.path, caRuntime.passphrase)`). **Operational tradeoff, not a defect.** Process memory dump or live-debugger attach after startup discloses the passphrase; mitigations are that `CULVERT_CA_PASSPHRASE` is an env var (not visible in `ps`) and that bundle decryption requires 600_000 PBKDF2 iterations even with `ca.bundle` exfiltrated. The alternative (re-prompt on every rotation) would prevent unattended cluster operation. **No action recommended now; recorded for the security-review audit trail.** | Yes | None |
| **CA-9** | `apiCertsUpload target=ui` (`ui_security.go:287–294`) **validates the cert+key pair but neither persists it to disk nor applies it to the running admin-UI listener.** The handler returns `200 OK` with a "restart required to activate" note, but **there is no documented mechanism for the uploaded material to actually become the UI cert on the next startup** — the admin UI's cert path is set at startup via the `-tls-cert` / `-tls-key` CLI flags (or `proxy.tls_cert` / `proxy.tls_key` YAML fields), consumed at `ui.go:104–112`. Operators must manually write the validated PEMs to the paths pointed at by those flags, then restart. **This is operator-visible UX/security ownership confusion**: the admin uploads a cert via the API, gets a success response, and yet nothing about the running listener (or the next startup, absent the manual file copy) changes. The fix is a design decision rather than a mechanical one: either (a) persist the uploaded material to a known path that `selfSignedTLS` / `startUI` will pick up on restart, with explicit operator documentation; or (b) make `target=ui` swap the running listener's TLS config (would require holding a `*http.Server` handle that can be told to replace its `TLSConfig` — non-trivial because `http.Server` doesn't support live `TLSConfig` swap, would need `GetConfigForClient`); or (c) explicitly remove `target=ui` from the API and document that UI cert rotation is restart-only. **No action recommended now; recorded as a UX/security ownership gap, not a config-versioning item.** | Yes | None |

**None of CA-1 through CA-9 are required for P6 to advance.** They are governance + observability + design-property documentation rather than blockers — with one exception (CA-7) that warrants a test, not an implementation refactor. Sequencing suggestions:

- **CA-7** (cpTLSConfig race test) is the highest-priority follow-up: it's a focused race test, not an architecture change. Independent of all other items. Result of the test informs whether a swap-pattern refactor is needed.
- **CA-2** (metrics) independent; group with P6.1 UC-6 and P6.2 SC-2 in a single observability follow-up PR.
- **CA-1** (config versioning) requires a **triage decision**, not a mechanical fix — open a design discussion before any code change. May be group-able with P6.1 UC-4 and P6.2 SC-1 if the triage outcome is "snapshot persistent-config mutations."
- **CA-3** (cluster-CA key plaintext) requires a design-level decision about cross-passphrase coupling; not a unilateral PR.
- **CA-4** (HA plaintext-key fallback) requires a coordinated cluster-upgrade protocol; not a quick fix.
- **CA-9** (apiCertsUpload target=ui UX gap) requires a UX design decision (persist / live-swap / remove); not a unilateral PR.
- **CA-5** (no OCSP/CRL for Culvert-issued certs) record-only.
- **CA-6** (hot-reload coverage) record-only.
- **CA-8** (passphrase in-memory retention) record-only.

---

## 11. References

- `main.go:188, 696–722, 701, 717–718, 721, 1133, 1436–1444, 2205–2270` — startup wiring, runtime CA holder, admin-UI cert consumption, shutdown wiring, hot-reload entrypoint.
- `ca.go:29–66, 79–86, 90–148, 150–205, 269–327, 356–377, 401, 409–471, 482–525, 599–716` — `CertManager` declaration, encryption constants, `InitCA` / `LoadOrInitCA` / `SaveCA` / `LoadCA`, leaf cache, rotation, secondary cleanup, `GetCertificate`, `signLeaf`, `ClearCache`.
- `enrollment.go:47, 106–113, 567–580, 693–705` — `ClusterState`, `ClusterStore`, heartbeat monitor, `clusterCA` struct, `globalClusterCA`.
- `controlplane.go:70–123, 79, 542–570, 579, 700–780, 779, 837–848, 843, 1033, 1043–1049, 1434–1454, 1502–1538, 1529–1538, 1626, 1712–1735, 1745–1797` — `ConfigSnapshot.CAFingerprint`, `verifyNodeCert`, Enroll RPC, RenewCert response, `HAStateBundle`, gRPC server / stop, DP applier fingerprint check, `cpTLSConfig`, `rebuildCPCertPool`, `buildServerTLS`, `buildClientTLS`.
- `tls.go:21–141` — `selfSignedTLS()` admin-UI cert generation, SAN auto-detection.
- `ha.go:209–232` — HA standby `ImportCASilent` paths (encrypted + deprecated plaintext fallback).
- `ocsp.go:37–42` — `globalOCSP` (P5.3 territory; referenced only for trust-flow completeness).
- `backup.go:60–66` — Tier-1 backup inclusion of `ca.bundle`, `cluster-ca.crt`, `cluster-ca.key`, `cluster.json` (the Tier-1 section comment is at `:60`; the four artifacts are at `:62–65`).
- `ui_security.go:18–23, 217, 226–249, 253–295, 339, 355, 396, 411, 981–1007, 1009–1025, 1027–1038, 1040–1110, 1113, 1134–1177` — `pendingCARotation`, every `saveConfigVersion` site (none CA-related), and the seven CA-touching admin handlers.
- Tests: `ca_test.go`, `ca_rotation_test.go`, `enrollment_test.go`, `enroll_util_test.go`, `controlplane_extra_test.go`, `controlplane_verifynodecert_security_test.go`, `controlplane_getconfig_security_test.go`, `controlplane_snapshot_bounds_test.go`, `coldstart_clusterca_test.go`, `mtls_ocsp_startup_test.go`, `upstream_transport_race_test.go`, `upstream_transport_swap_test.go`.
- `roadmap/RUNTIME-OWNERSHIP.md` §2 (S8 out-of-scope clarification), §3 Phase shape, §4 P6.3 entry, §5 "Recommended next PR".
- `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` (P5.1), `roadmap/URL-CATEGORIES-DISCOVERY.md` (P6.1), `roadmap/SCANNING-DISCOVERY.md` (P6.2) — format baselines.
- `roadmap/D1.3a-backup-design.md`, `roadmap/D1.6-maintenance-agent-design.md` — backup/restore ownership.
