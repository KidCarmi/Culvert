# Culvert Runtime Ownership & Startup Decoupling Program

**Status:** design / roadmap. No code changes implied by this document.
**Scope:** runtime-layer ownership underneath the already-shipped startup spine. Does **not** touch the 11 SAFE-zone startup slices already extracted under PR3 (see `ARCH_DISCOVERY.md` "Pilot status — shipped").
**Companion docs:** `roadmap/ARCH_DISCOVERY.md` (state-of-the-world), `roadmap/PHASES.md`, `CLAUDE.md` "Startup slices" entry.

---

## 1. Main goal

Eliminate implicit runtime ownership in Culvert by converting each detached server, background loop, mutable startup resource, and config-coupled init path into a small, owned, shutdown-aware slice with an explicit owner type, an explicit construction site, and an explicit teardown contract — without introducing a framework, without introducing package-wide DI, and without re-extracting anything already covered by the ARCH_DISCOVERY safe-zone pilots. Work ships as small, individually reviewable PRs, ordered so that contract/test work and detached-goroutine ownership ship first (travel-friendly), state durability and god-object reduction follow, and high-risk domains (cluster, CDR, scanning, Root CA, upstream transport rewrite) are gated behind discovery-only PRs.

---

## 2. SPOF inventory (stable IDs — cite these in PR descriptions)

| ID | SPOF | Where | Severity |
|---|---|---|---|
| **S1** | `FileConfig` / `s.fc` god-object dereferenced by 25+ init funcs | `main.go` startupState + every `initX` | HIGH |
| **S2** | Global `logger` bus | `main.go:40` | LOW (intentional, not a target) |
| **S3** | Global `appLifecycleCtx` / `appLifecycleCancel` | `main.go:45–46` | LOW (intentional, not a target) |
| **S4** | Detached goroutines without shutdown path: **S4.AdminUI**, **S4.SSE**, **S4.SOCKS5**, **S4.UpstreamHealth**, **S4.SIGHUP** | `startAdminUI`, `events.go:73`, `socks5.go:16`, `main.go:1590`, `main.go:1248` | MEDIUM |
| **S5** | `runProxyUntilShutdown` god-node (~15 globals + 4 carry fields) | `main.go:1269` | MEDIUM |
| **S6** | `upstreamTransport` shared mutation across `initUpstreamProxy` + `initMTLSAndOCSP` | `main.go:1013`, `main.go:1113` | MEDIUM |
| **S7** | ~15 mutable stores rely on save-on-write; no final shutdown flush; audit-log file handle leaks on SIGKILL-timeout | various | LOW–MEDIUM |
| **S8** | `/data` dir + Root CA bundle as deployment SPOFs | `main.go:53`, `initRootCA` | HIGH (out of scope here — owned by D1.3 / D1.6) |
| **S9** | `log.Fatalf` scattered across ~15 init sites | various `init*` | MEDIUM (latent; not a target this program) |
| **S10** | `s.feedSyncer` dead carry on `startupState` | `main.go:159` | LOW (cosmetic) |

Out of scope across the whole program: **S2, S3, S8, S9.** Maintenance Agent (`cmd/culvert-maint`, `packaging/culvert-maint`, systemd, sudoers, D1.6) is also out of scope.

---

## 3. Phase shape

| Phase | Theme | Risk | Travel-friendly? | Gating |
|---|---|---|---|---|
| **0** | Lock current reality (contract + this roadmap) | LOW | ✅ | none |
| **1** | Own detached runtime resources (S4.\*) | LOW–MEDIUM | ✅ | P0 |
| **2** | Minimal shutdown registry + ordered teardown tests (S5) | LOW–MEDIUM | ✅ | P1 |
| **3** | State durability / final flush (S7) | LOW–MEDIUM | ✅ for low-risk stores; lab needed for cluster | P2 + per-domain discovery |
| **4** | Reduce `FileConfig` god-object — MEDIUM-risk slice extraction (S1) | MEDIUM | mostly | P0 + P2 |
| **5** | `upstreamTransport` SPOF (S6) | MEDIUM | discovery yes, rewrite needs lab | P4 |
| **6** | High-risk domains: discovery only (cluster, CDR, scanning, Root CA, URL categories) | LOW (docs); HIGH if implemented | docs ✅, impl ❌ | P5 |

`[travel-ok]` PR-title prefix is allowed for any PR whose surface is unit-test only (no E2E/lab needed). PRs that require a lab are marked **lab-required** below and must NOT carry `[travel-ok]`.

---

## 4. PR list

Each PR is sized for one Claude Code implementation pass + human review (~200–400 LOC net diff plus tests). Every PR description must cite the SPOF ID(s) it targets and copy its "What not to touch" verbatim into the PR body.

### Phase 0 — Lock current reality

#### P0.1 — Pin the extracted-slice convention
- **Status:** DONE / in-flight via PR #207; once #207 merges, this phase is complete. **Do not expand** with AST purity checks now — over-reach for the convention layer.
- **Targets:** discovery hygiene (covers nothing on the SPOF list directly).

#### P0.2 — Adopt this roadmap as a stable source of truth `[travel-ok]`
- **This PR.** Adds `roadmap/RUNTIME-OWNERSHIP.md` plus a one-line pointer in `CLAUDE.md` "Roadmap" entry.
- **Acceptance:** future Claude sessions can navigate Phases 1–6 by SPOF ID without re-deriving the inventory.
- **What not to touch:** any Go code; the 11 shipped startup slices; `ARCH_DISCOVERY.md` (already current).

---

### Phase 1 — Own detached runtime resources

> **Status:** ✅ **COMPLETE.** All five S4 detached-runtime resources are now owned, cancellable, and stoppable.
>
> Merged PRs:
> - **#210** — P1.1 Admin UI graceful shutdown handle (`adminUIServer`)
> - **#211** — P1.2 SSE broadcaster shutdown (`sseBroadcaster`)
> - **#212** — P1.3 Upstream health-check context plumbing (`runUpstreamHealthCheckLoop`)
> - **#213** — P1.4 SIGHUP reloader (`sighupReloader`)
> - **#214** — P1.5 SOCKS5 listener ownership (`socks5Server`)
>
> **Deliberately deferred:** in-flight SOCKS5 tunnel drain (per-conn 30 s deadlines remain the stop signal for active tunnels; graceful drain lands with the Phase 2 registry).
>
> **Next step:** **P2.1 — minimal `Shutdownable` + `shutdownRegistry`** (≤80 LOC of production code, no call sites yet). Not a broad runtime framework, not package-wide DI — just the smallest type that lets P2.2 wire the five P1 owners plus the ~10 existing teardown calls into one ordered table.

Each PR introduces a small ownership shape — owner type, returned server handle, or cancellable helper loop — that gives the detached resource an explicit lifecycle and a testable shutdown/exit signal. **No registry yet** — the registry is Phase 2 once we have ≥3 concrete owners. Order is deliberate: Admin UI first, because it is the most useful **reference implementation** for owned server shutdown (real `*http.Server`, real in-flight requests).

#### P1.1 — Admin UI graceful shutdown handle (`adminUIServer`) `[travel-ok]`
- **Status:** ✅ DONE — merged in PR #210.
- **Targets:** S4.AdminUI.
- **Objective:** `startUI` returns `*http.Server` (or a small `adminUIServer` wrapper); `startAdminUI` retains the handle on `startupState`; shutdown calls `srv.Shutdown(ctx)` instead of letting the goroutine die abruptly. **Reference implementation for the rest of Phase 1.**
- **Files:** `ui.go`, `main.go` (`startAdminUI`, `runProxyUntilShutdown`, `startupState`).
- **Tests:** unit test that boots `startUI` against `:0`, makes one request, calls `Shutdown(ctx)`, asserts nil return inside deadline.
- **Risk:** LOW. In-flight SSE streams get cut off — call out in the PR body.
- **Acceptance:** no implicit goroutine death on the UI path; explicit `Shutdown` call lands before `proxySrv.Shutdown`; D0 / C1 / C1.5 / C2 / C2c / C4 suites untouched and green.
- **What not to touch:** route registration, middleware chain, RBAC, C2/C2c/C4 metadata.

#### P1.2 — SSE broadcaster shutdown (`sseBroadcaster`) `[travel-ok]`
- **Status:** ✅ DONE — merged in PR #211.
- **Targets:** S4.SSE.
- **Objective:** wrap the bare `for range ticker.C` in `events.go:73` in an `sseBroadcaster` with `Start(ctx)` / `Stop()`. Single-line call-site change in `initBackgroundServices`.
- **Files:** `events.go`, `main.go` (`initBackgroundServices`).
- **Tests:** start with `context.WithCancel`, cancel, assert exit < 100 ms (`goleak`-style or `WaitGroup`).
- **Risk:** LOW.
- **Acceptance:** no bare `for range ticker.C` in `events.go`; existing SSE tests green.
- **What not to touch:** SSE hub, dashboard payload, websocket upgrade.

#### P1.3 — Upstream health-check context plumbing `[travel-ok]`
- **Status:** ✅ DONE — merged in PR #212.
- **Targets:** S4.UpstreamHealth.
- **Objective:** the bare goroutine in `initUpstreamPool` (`main.go:1590`) selects on `appLifecycleCtx.Done()`, matching the rate-limit cleanup pattern.
- **Files:** `main.go` (`initUpstreamPool`), possibly `upstream.go` (`HealthCheck` may take `ctx`).
- **Tests:** 50 ms interval, cancel parent, assert exit; `upstream_test.go` green.
- **Risk:** LOW.
- **Acceptance:** ticker goroutine respects cancellation; reload path unchanged.
- **What not to touch:** `applyUpstreamProxy`, circuit breaker, transport mutation (S6 territory — Phase 5).

#### P1.4 — SIGHUP ownership (`sighupReloader`) `[travel-ok]`
- **Status:** ✅ DONE — merged in PR #213.
- **Targets:** S4.SIGHUP.
- **Objective:** wrap the bare `for range sighup` (`main.go:1248`) in `sighupReloader{configPath, applyHotReload}` with `Start(ctx)` / `Stop()`.
- **Files:** `main.go` (`installSignalHandlers`).
- **Tests:** inject fake signal channel, send a value, assert `applyHotReload` invoked; cancel ctx, assert exit.
- **Risk:** LOW.
- **What not to touch:** `applyHotReload` semantics, hot-reload tests.

#### P1.5 — SOCKS5 listener ownership (`socks5Server`) `[travel-ok]`
- **Status:** ✅ DONE — merged in PR #214. **In-flight SOCKS5 tunnel drain is deliberately deferred** — active tunnels still rely on their per-conn 30 s deadlines from `handleSOCKS5`. Graceful drain (with `activeConns`-style tracking) is a Phase 2 follow-up.
- **Targets:** S4.SOCKS5.
- **Objective:** `startSOCKS5` becomes a constructor returning `socks5Server{ln, …}` with `Start()` / `Stop(ctx) error`. `Stop` closes the listener; the accept loop treats the resulting error as "stopped".
- **Files:** `socks5.go`, `main.go` (`initSOCKS5`, `runProxyUntilShutdown`, `startupState`).
- **Tests:** bind `:0`, dial once, send valid greeting, `Stop()`, assert listener closed and accept loop exited; `socks5_test.go` green.
- **Risk:** MEDIUM. **Listener-close path only.** In-flight SOCKS5 tunnels still rely on per-conn deadlines, not graceful drain — mention in PR body and CHANGELOG; the drain-with-`activeConns` follow-up is deferred.
- **What not to touch:** `handleSOCKS5` body, IP filter, rate limiter, plugin chain.

---

### Phase 2 — Minimal shutdown registry

> **Status:** ✅ **COMPLETE.** `shutdownRegistry` exists and is tested; `runProxyUntilShutdown` uses early + late registries.
>
> Merged PRs:
> - **#216** — P2.1 minimal `shutdownRegistry` (type + tests; no call sites)
> - **#217** — P2.2 wire registry into shutdown path with early/late split
>
> **Shape pinned by P2.2:**
> - Early hooks (orders 10–50): `globalHA.Stop`, `StopControlPlaneGRPC`, `shutdownCDRClient`, `appLifecycleCancel`, `s.rlCleanupCancel`. Run under `context.Background()` — no shutdown budget.
> - The 30 s shutdown ctx is created at the original boundary: **after** rate-limit cleanup cancel, **before** `scanSvc.Shutdown`. `defer cancel` runs at the end.
> - Late hooks (orders 60–140): `scanSvc.Shutdown`, `shutdownAdminUI`, `socks5Server.Stop`, `proxySrv.Shutdown`, `drainActiveTunnels`, `globalSyslog.Close`, `communityDB.Close`, `requestLogCloser.Close`, `s.logCloser.Close`. Run under the fresh 30 s ctx.
> - Tunnel drain remains 15 s time-driven (own `time.After` + 500 ms ticker), independent of the parent ctx — preserved exactly.
> - Per-hook log strings, best-effort error suppression, and Admin UI 5 s / SOCKS5 2 s sub-contexts are all byte-equivalent to the pre-PR body.
>
> **Next step:** **P3.2 — policy store / node groups / bandwidth durability** (S7). P3.1 closed out as discovery — see entry below; PAC, fileBlocker, and profile store already rely on synchronous save-on-write and did not need shutdown flush hooks.

#### P2.1 — Define `Shutdownable` + `shutdownRegistry` (no behaviour change) `[travel-ok]`
- **Status:** ✅ DONE — merged in PR #216.
- **Targets:** S5.
- **Objective:** introduce `Shutdownable` + `shutdownRegistry` with `Register(name, order, fn)` and `RunAll(ctx)`. **No call sites use it yet.**
- **Files:** `runtime_shutdown.go` (new), `runtime_shutdown_test.go` (new).
- **Tests:** ordering, per-hook timeout, error aggregation, idempotency.
- **Risk:** LOW. ≤80 LOC of production code.
- **What not to touch:** `runProxyUntilShutdown`.

#### P2.2 — Wire P1.\* owners into the registry; rewrite `runProxyUntilShutdown` body to call `RunAll`
- **Status:** ✅ DONE — merged in PR #217. Body now uses two registries (early/late) so the 30 s budget is byte-equivalent to the pre-PR scope.
- **Targets:** S5.
- **Objective:** register P1.1–P1.5 owners plus the existing teardown calls (`globalHA.Stop`, `StopControlPlaneGRPC`, `shutdownCDRClient`, `appLifecycleCancel`, `s.rlCleanupCancel`, `s.scanSvc.Shutdown`, `proxySrv.Shutdown`, `globalSyslog.Close`, `communityDB.Close`, `requestLogCloser.Close`, `s.logCloser.Close`) with explicit `order`. Body shrinks to ~10 lines: register, block on quit, run all.
- **Tests:** registry ordering test on a stub set; existing tunnel-drain stays inline inside the proxy `Stop` hook.
- **Risk:** MEDIUM — only PR in Phases 0–2 that meaningfully reshapes shutdown. Mitigation: byte-equivalent order; only the wiring shape changes.
- **Acceptance:** no `goleak`-style goroutine leaks; P2.3 ordering test green.
- **What not to touch:** tunnel-drain timing (15 s), `appLifecycleCancel` semantics.

#### P2.3 — Shutdown order + timeout test suite `[travel-ok]`
- **Status:** ⚖️ **Folded into PR #217.** The canonical-order test surface (`TestRegisterEarlyShutdownHooks_OrderMatchesCanonical`, `TestRegisterLateShutdownHooks_OrderMatchesCanonical`, `TestEarlyAndLateShutdownHooks_OrdersDoNotOverlap`, `TestRegisterShutdownHooks_OrdersAreStrictlyAscending`, `TestRunShutdownSequence_EarlyCtxHasNoDeadline_LateCtxDoes`) shipped with P2.2 and pins the ordering + budget contracts the P2.3 spec called for. A separate per-hook *timeout* suite is **not** required today — Admin UI (5 s) and SOCKS5 (2 s) sub-contexts are owned by their respective hooks and are pinned by their P1.1 / P1.5 tests; the late phase shares one 30 s budget. If a future PR adds a hook with its own per-hook timeout contract, that PR can add its own focused test.
- **Targets:** S5.
- **Objective:** pin canonical ordering + per-step timeout budget so future refactors can't silently drift.
- **Files:** `runtime_shutdown_order_test.go` (new).
- **Tests:** golden table of `(name, order)`; per-hook timeout; invariant that `appLifecycleCancel` precedes `proxySrv.Shutdown`; `s.logCloser.Close` runs last; mutation-test sanity (swapping any two adjacent rows must fail).
- **Risk:** LOW.

---

### Phase 3 — State durability / final flush

All PRs target S7. Travel-friendly except **P3.4** (cluster).

#### P3.1 — Discovery closeout: PAC, fileBlocker, profile store already save-on-write `[travel-ok]`
- **Status:** ✅ **DISCOVERY COMPLETE / SCOPE-CORRECTED.** No production code changes — no shutdown flush hooks added, no `Save(ctx)` wired into the registry, no shutdown order changes, no on-disk format changes.
- **Targets:** S7 (low-severity portion).
- **Finding:** PAC and fileBlocker already have complete synchronous save-on-write persistence; flush-on-shutdown would be pure redundancy. The profile store has one narrow persistence gap (`ReplaceAll` mutates memory only), but flushing it on shutdown would paper over a deeper non-atomicity issue in `saveLocked` rather than fix it. Net: broad shutdown-flush hooks are intentionally NOT added in P3.1.
- **Per-store summary:**
  - **PAC** (`pac.go`): every external mutation goes through `PACStore.Set`, which writes synchronously via tmp+rename (atomic, but not fsynced — see follow-up #1).
  - **fileBlocker** (`fileblock.go`): every external mutation goes through `Add`/`Remove`/`ClearAll`, which call `save()` synchronously via `atomicWriteFile` (fsynced + atomic). Already the most durable of the three.
  - **profile store** (`fileprofile.go`): UI mutations save synchronously via `Create`/`Update`/`Delete`. **`ReplaceAll` does not persist** — see follow-ups #2 and #3.
- **What not to touch:** on-disk JSON formats; `Load` semantics; persistence architecture (no DB, no abstraction layer); shutdown ordering; the audit-log / request-log file handles (P3.3); any `Save(ctx)` wiring into `runtime_shutdown.go`.

##### P3.1 follow-up work (tracked separately, NOT P3.1 itself)

These are pre-existing durability issues uncovered by the P3.1 discovery. They are **intentionally split into future dedicated PRs** rather than silently hardened under P3.1:

1. **`PACStore.Set` is atomic-via-rename but not fsynced** (`pac.go:82–86`). Switching the write path to `atomicWriteFile` would bring durability up to fileBlocker's level (fsync(file) + tmp + rename + best-effort fsync(parent dir)). Small, mechanical change. Independent of #2 and #3 — can ship at any time.
2. **`FileProfileStore.saveLocked` uses plain `os.WriteFile`** (`fileprofile.go:96–105`). Not atomic, not fsynced — a crash mid-write can leave a truncated/empty `fileprofiles.json`. Switching to `atomicWriteFile` is the **prerequisite** for any further work on this store. Separate PR.
3. **`FileProfileStore.ReplaceAll` does not persist** (`fileprofile.go:122–131`). Cluster-pushed profile updates on a DP node are kept in memory only until the next `Create`/`Update`/`Delete` triggers a save. The fix is one call to `s.saveLocked` inside `ReplaceAll`. Separate PR, **gated on follow-up #2** so we are not amplifying a non-atomic write across the cluster apply path.

**Preferred future sequencing:**
- **(a) follow-up #2 first** — harden `FileProfileStore.saveLocked` durability via `atomicWriteFile`.
- **(b) then follow-up #3** — persist `ReplaceAll` once the underlying write is atomic.
- Follow-up #1 (PAC `Set`) is independent of the profile-store chain and can ship at any time.

#### P3.2 — Discovery closeout: node groups + bandwidth already complete; policy store has two split follow-ups `[travel-ok]`
- **Status:** ✅ **DISCOVERY COMPLETE / SCOPE-CORRECTED.** No production code changes — no shutdown flush hooks added, no `Save(ctx)` wired into the registry, no shutdown order changes, no on-disk format changes.
- **Targets:** S7 (low-severity portion).
- **Finding:** Two of the three stores are already fully durable; the third (policy store) has two pre-existing gaps that exactly mirror what P3.1 fixed for the file-profile store. Flush-on-shutdown would be pure redundancy for node groups and bandwidth, and would not address either of the policy-store gaps (atomicity is per-write; the cluster-apply gap is at the source). Net: shutdown flush hooks are intentionally NOT added in P3.2.
- **Per-store summary:**
  - **NodeGroupStore** (`nodegroup.go`): every mutator (`Add`, `Delete`, `ReplaceAll`) calls `saveLocked` synchronously, which uses `atomicWriteFile` (fsynced + atomic). Already complete.
  - **BandwidthManager** (`bandwidth.go`): every mutator (`Add`, `Delete`, `ReplaceAll`) calls `saveLocked` synchronously, which uses `atomicWriteFile`. Token-bucket counters are intentionally transient and re-base from elapsed time on restart — persisting them would be wrong. Already complete.
  - **PolicyStore** (`policy.go`): caller-side Save convention (UI handlers explicitly call `policyStore.Save()` after every mutation; verified at `ui_policy.go:726, 768, 792, 820, 856, 967`, `ui_config.go:418`, `configversion.go:349`). Two gaps — see P3.2a and P3.2b below.
- **What not to touch:** on-disk JSON formats; `Load` semantics; policy matching / `Evaluate` / `sortLocked` / `DetectConflicts`; node-group label-match semantics; bandwidth enforcement / token-bucket math / `AllowBytes` / `FindPolicy`; persistence architecture; shutdown ordering; any `Save(ctx)` wiring into `runtime_shutdown.go`.

##### P3.2 follow-up work (tracked separately, NOT P3.2 itself)

These are pre-existing policy-store durability issues uncovered by the P3.2 discovery. They are **intentionally split into future dedicated PRs** rather than bundled under P3.2:

- **P3.2a** — **`PolicyStore.Save()` main-file write uses plain `os.WriteFile` + `os.Rename`** (`policy.go:458, 461`). Atomic via the rename guarantee on POSIX same-fs, but **not fsynced**. The companion `saveMeta` (line 434) already uses `atomicWriteFile`; the main file does not. The existing test `TestPolicyStore_SaveMeta_NoTmpLeak` (`policy_test.go:826–838`) explicitly notes this as the "out-of-scope old temp+rename pattern". Switching the main write to `atomicWriteFile` brings the policy store up to the same durability level as the node-group, bandwidth, and file-profile stores. **Mirror of P3.1 follow-up #2** (which shipped as PR #221). Separate PR.
- **P3.2b** — **`policyStore.ReplaceAll` is not persisted by the cluster apply path** (`controlplane.go:1490`). DP nodes that receive a CP-pushed rule set via `applyConfigSnapshot` keep the new rules in memory only; on restart, `Load` reads stale data until the next heartbeat re-converges. Fix is **caller-side** (`policyStore.Save()` immediately after `policyStore.ReplaceAll(...)` in `applyConfigSnapshot`), respecting PolicyStore's existing convention that mutators don't save internally — every UI handler already does this explicitly. **Mirror of P3.1 follow-up #3** (which shipped as PR #222) — different shape: caller-side rather than internal save. Separate PR, **gated on P3.2a** so we are not amplifying a non-fsynced write across the cluster apply path.

**Preferred future sequencing:**
- **(a) P3.2a first** — harden `PolicyStore.Save()` durability via `atomicWriteFile`.
- **(b) then P3.2b** — persist `ReplaceAll` (caller-side) in `applyConfigSnapshot` once the underlying write is fully atomic-durable.

#### P3.3 — Final-flush opt-in: config versioning, audit log handle, request log handle `[travel-ok]`
- **Files:** `configversion.go`, `logger.go` (audit/request portions), `runtime_shutdown.go`.
- **Tests:** must respect the audit-ring saturation pitfall (see CLAUDE.md "Test-authoring pitfalls"): assert on entry **content** with a unique discriminator, not on `len(auditGet())` deltas.
- **Risk:** LOW.
- **Acceptance:** audit-log file handle no longer leaks on SIGKILL-timeout (Risk #5 from ARCH_DISCOVERY).

#### P3.4 — Final-flush opt-in: cluster store heartbeat — **lab-required**
- **Targets:** S7 (MEDIUM-severity portion).
- **Gate:** **only after P6.4 cluster discovery is merged.**
- **Files:** `enrollment.go`, `controlplane.go`.
- **Risk:** MEDIUM — touches cluster runtime; coordinate with HA leader/standby flip.

---

### Phase 4 — Reduce `FileConfig` god-object (MEDIUM slices)

All follow the established `<domain>_startup_config.go` + `<domain>_startup.go` + `<domain>_startup_test.go` convention from PR3. Targets S1.

#### P4.1 — Extract `initBlocklist` `[travel-ok]`
- **Files:** `blocklist_startup.go`, `blocklist_startup_config.go`, `blocklist_startup_test.go`, `main.go`.
- **Risk:** MEDIUM. One blocklist syncer goroutine parented to `appLifecycleCtx`; live-mutable store.
- **What not to touch:** `applyHotReload`, `bl.Load` semantics, blocklist feed cadence.

#### P4.2 — Extract `initConnAndRateLimit` `[travel-ok]`
- **Files:** `connlimit_startup.go`, `connlimit_startup_config.go`, `connlimit_startup_test.go`, `main.go`.
- **Risk:** MEDIUM. Keep `s.rlCleanupCancel` carry until Phase 2 registry consumes it.
- **What not to touch:** `applyHotReload` rate-limit path, sharded mutex internals.

#### P4.3 — Extract `initObservability` `[travel-ok]`
- **Files:** `observability_startup.go`, `observability_startup_config.go`, `observability_startup_test.go`, `main.go`.
- **Risk:** MEDIUM. Coordinate with P3.3 so close paths stay correct.
- **What not to touch:** audit ring, audit-completion C2c contract.

#### P4.4 — Extract `initAuth`
- **Gate:** only after the startup slice contract is merged and the auth slice scope is explicitly verified in the PR description.
- **Files:** `auth_startup.go`, `auth_startup_config.go`, `auth_startup_test.go`, `main.go`.
- **Risk:** MEDIUM. `cfg` is the auth singleton, also UI-mutable.
- **Acceptance:** D0 auth safety, `pkce_ui2_test.go`, `auth_oidc_test.go` green.
- **What not to touch:** `cfg` itself (live-mutable; out of god-object scope).

---

### Phase 5 — `upstreamTransport` SPOF

Targets S6.

#### P5.1 — Discovery only: document `upstreamTransport` mutation graph `[travel-ok]`
- **Files:** `roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md` (new). No production code.
- **Output:** mutators (`initUpstreamPool`, `loadMTLSAndOCSP`/`ConfigureTransportOCSP`, runtime hot-reload paths), readers (proxy hot path, OCSP, alerts, threat feed sync), proposed single constructor signature.

#### P5.2 — Contract tests pinning current ordering `[travel-ok]`
- **Files:** `upstream_transport_contract_test.go` (new).
- **Tests:** assert mTLS certs + OCSP wrapper both present after init; informational test for wrong-order case (`t.Skip` with reason until P5.3).

#### P5.3 — Single-constructor `upstreamTransport` (assign-once) — **lab-required**
- **Gate:** P5.1 + P5.2 merged + lab smoke.
- **Files:** `upstream.go`, `mtls_ocsp_startup.go`, `main.go`.
- **Risk:** MEDIUM-HIGH.
- **Acceptance:** single construction site; no post-hoc mutation; `coldstart_*` green; race-free.

---

### Phase 6 — High-risk domains (**discovery only**)

The program ships only the discovery PR for each. Implementation PRs are out of scope here and must be planned separately, after discovery, with their own gating.

#### P6.1 — Discovery: `initURLCategories` + community BadgerDB `[travel-ok]`
Output: `roadmap/URL-CATEGORIES-DISCOVERY.md`.

#### P6.2 — Discovery: `initScanning` `[travel-ok]`
Output: `roadmap/SCANNING-DISCOVERY.md`.

#### P6.3 — Discovery: `initRootCA` + `caRuntime` `[travel-ok]`
Output: `roadmap/ROOT-CA-DISCOVERY.md`. Coordinate with D1.3 backup/restore + D1.6 Maintenance Agent — explicitly carve out what this program does NOT change.

#### P6.4 — Discovery: `initCluster` + `enableControlPlane` + `startDataPlane` + HA `[travel-ok]`
Output: `roadmap/CLUSTER-RUNTIME-DISCOVERY.md`. **Required gate for P3.4.**

---

## 5. Recommended next PR

Phases 1 and 2 are complete (PRs #210–#214 for Phase 1, PRs #216–#217 for Phase 2). P3.1 closed out as discovery (see P3.1 entry above; follow-ups #2 and #3 shipped as PRs #221 and #222). P3.2 also closed out as discovery — see the P3.2 entry above; node groups and bandwidth are already fully durable, and the policy-store gaps are split into P3.2a and P3.2b. The next implementation PR is:

- **P3.2a — harden `PolicyStore.Save()` main-file write via `atomicWriteFile`** `[travel-ok]`. Mechanical change in `policy.go` (replace the `os.WriteFile` + `os.Rename` pair at lines 458, 461 with a single `atomicWriteFile` call) plus focused tests in `policy_test.go` mirroring PR #221's shape. Prerequisite for P3.2b.

Phase 3 is **state durability**, not more shutdown refactor. The shutdown registry from Phase 2 is the wiring substrate; Phase 3 only adds opt-in `Save(ctx)` hooks where the discovery proves a real durability gap. **Not** a re-architecting of persistence — the on-disk format and `Load()` paths are untouched.

---

## 6. Explicit non-goals

- Re-extract any of the 11 shipped SAFE-zone startup slices (`fileblock`, `inspection_rules`, `geoip`, `pac`, `mtls_ocsp`, `ui_extras`, `legacy_auth_providers`, `rewrite_default_action`, `ui_access_policy`, `metrics_token`, `session`).
- Touch Maintenance Agent work (`cmd/culvert-maint`, `packaging/culvert-maint`, systemd, sudoers, D1.6).
- Touch backup/restore (D1.3a, D1.3b.1, D1.3b.2a, D1.3b.2b) or the operator contract (D1.5).
- Introduce a framework, plugin runtime, or DI container.
- Replace `package main` with sub-packages.
- Replace the global `logger` (S2) or the global `appLifecycleCtx` (S3).
- Re-architect `/data` placement, persistence layout, or Root CA encryption (S8).
- Convert `log.Fatalf` sites (S9) — flagged for a separate follow-up if needed.
- Refactor admin UI route registration, C2/C2c/C4 metadata enforcement, or `uiRoutes` invariants.
- Modify the audit ring's bounded-size contract (CLAUDE.md test-authoring pitfall).
- Implement any Phase 6 domain — discovery docs only.

---

## 7. Risks and review strategy

### Risks

| Risk | Likelihood × Impact | Mitigation |
|---|---|---|
| P2.2 registry rewires shutdown order subtly | MEDIUM × MEDIUM | P2.3 ordering test runs with the same PR; P2.2 keeps byte-equivalent order; release-gate `goleak` run. |
| P4 god-object slices break `applyHotReload` | MEDIUM × MEDIUM | Each P4 PR keeps the in-place mutation site; only the *startup* read of `s.fc` moves; hot-reload tests stay green. |
| P5.3 transport rewrite causes silent OCSP regression | LOW × HIGH | P5.2 contract test gates the merge; lab smoke required. **Do not start during travel.** |
| P3.4 cluster-heartbeat flush races with HA leader flip | MEDIUM × MEDIUM | Gate behind P6.4 cluster discovery; lab required. |
| Audit-ring saturation under `-shuffle=on` (CLAUDE.md pitfall) | MEDIUM × LOW | Every audit-touching test asserts on entry **content** with a unique discriminator; reviewer checklist item. |

### Review strategy

- **Per PR:** description must (1) cite the SPOF row ID(s), (2) copy the "What not to touch" list verbatim, (3) be `[travel-ok]` or **lab-required** in the title prefix.
- **Required green:** `go test -race -count=1`, C1 / C1.5 / C2 / C2c / C4, plus a goleak-style assertion or equivalent bounded wait/stop test on any PR that adds or removes a goroutine owner.
- **Determinism gate:** any new test must pass under `-count=2 -shuffle=on`.
- **Phase boundaries:** before opening the next phase's first PR, update this document's checklist (if added) so phase progress is visible to future Claude sessions.
