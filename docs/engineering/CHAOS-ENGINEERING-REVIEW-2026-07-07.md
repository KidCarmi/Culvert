# Culvert Chaos Engineering Review — 2026-07-07

> **Owner:** Chaos Engineering routine · **Status:** Point-in-time review (repeatable)
> **Method:** Delta review over `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-07-05.md`
> (tree at `ea0f2ff`). Five parallel failure-domain audits (storage/persistence ·
> networking/upstream/DNS/TLS · cluster/CP-DP/HA · auth/IdP/session/CA ·
> lifecycle/resources/workers/updates), this time covering the areas the prior review
> deliberately skipped (OIDC/SAML flows, `update_cluster.go`, shutdown internals,
> memory-bound analysis). Prior findings were re-checked at HEAD; new findings continue
> the CHAOS-NN series at CHAOS-22.
> **Companion change:** two fixes ship with this review (see "Fixed in this change").

---

## Executive Summary

Since the 2026-07-05 review, **none of the 21 open CHAOS findings were addressed**
(interim work was secret-containment and maint-agent hardening). This run fixes the two
smallest high-leverage ones (CHAOS-02, CHAOS-04) and re-confirms the rest still hold at
HEAD. The new audit passes surface **three themes the prior review under-weighted**:

1. **Protection that exists on paper but is not wired.** The upstream circuit breaker is
   dead code — `RecordFailure`/`RecordSuccess` are never called from any production path,
   so the advertised fast-trip protection does not run (CHAOS-22). Same shape: session
   revocations have an export/merge API "for gRPC gossip" that nothing calls, so logout
   on node A leaves the cookie valid on nodes B/C until natural expiry (CHAOS-24), and
   the documented "cert_expiry fired on startup if ≤30 days" alert does not exist in code
   (CHAOS-30).
2. **Resource exhaustion that one client can trigger.** Scanned responses buffer up to
   5 MB each and gzip decompression can expand to 64 MB per request; the per-IP
   connection limiter is **off by default** and there is no global connection or
   scan-concurrency cap — N concurrent large downloads is a remote OOM (CHAOS-26). The
   SSL-inspect path has no deadline on the client/upstream TLS handshakes or the
   first-byte `Peek` (only the post-handshake loop has the 60s deadline), leaving a
   handshake-slowloris window (CHAOS-32).
3. **Shutdown and rollback trust their happy path.** The early shutdown phase runs with
   **no time budget**, and `GracefulStop()` on the CP gRPC server blocks until all
   in-flight RPCs finish — one wedged RPC hangs SIGTERM forever, and the second SIGTERM
   is ignored because the signal channel is only read once (CHAOS-25, CHAOS-36).
   Config-version rollback (`applyConfigBackup`) discards every store `Save()` error and
   returns nothing — a disk failure mid-rollback reports success and leaves mixed
   old/new state on disk (CHAOS-27).

**Fixed in this change:** CHAOS-02 (SOCKS5 uncovered by the per-IP connection limiter)
and CHAOS-04 (OCSP responder outage cached as a revocation for 1h), each with regression
tests.
**Top remaining risks:** CHAOS-01 (CP version reset — still the worst silent failure),
CHAOS-22 (dead circuit breaker), CHAOS-24 (revocation not cluster-honored), CHAOS-26
(scan-buffer OOM), CHAOS-06 (CA load fail-open), CHAOS-25 (unbudgeted shutdown hang).

---

## Fixed in this change

### F1 — SOCKS5 sessions now count against the per-IP connection budget (CHAOS-02) · HIGH
- **Was:** `handleSOCKS5` checked the IP filter and rate limiter but never touched
  `connLimiter`, while the HTTP/CONNECT path acquires a per-IP slot for the lifetime of
  each request (`proxy.go:611-615`). One client IP could open thousands of concurrent
  SOCKS5 tunnels under the rate-limit burst budget, each pinning two goroutines and two
  FDs indefinitely (no idle deadline — CHAOS-03, still open) — single-IP resource
  exhaustion the HTTP listener is explicitly hardened against.
- **Fix:** `connLimiter.Acquire(clientIP)` at SOCKS5 session entry, released when the
  handler (and therefore the relay) ends — symmetric with `handleRequest`. Refused
  sessions log `SOCKS5 CONN_LIMITED` and record a `CONN_LIMITED` request-log entry
  (the HTTP path's refusal is a bare 503; the SOCKS5 wire protocol has no pre-greeting
  error reply, so the connection closes silently on the wire but is now visible in the
  feed).
- **Tests:** `socks5_connlimit_test.go` — with a limit of 1, a second concurrent session
  from the same IP is refused before negotiation; a completed session releases its slot
  and a fresh connection negotiates normally.
- **Residual:** the limiter is still **disabled by default** (`internal/connlimit`
  `Acquire` returns true when not enabled) — this fix makes the budget cover SOCKS5
  when the operator enables it; it does not change the default posture (see CHAOS-26).

### F2 — OCSP responder outage no longer cached as a 1-hour revocation (CHAOS-04) · MED-HIGH
- **Was:** all-responders-unreachable returns "revoked" (fail-closed — correct posture)
  but `cacheResult` stored that verdict for the full 1h `cacheTTL`, identical to a
  genuine revocation. A seconds-long responder blip hard-failed all inspected TLS to the
  affected upstream(s) for an hour after recovery.
- **Fix:** `checkResponders` now returns `(revoked, indeterminate)`; an indeterminate
  (outage) verdict is still fail-closed but cached with a 2-minute
  `indeterminateCacheTTL`, so recovery tracks the dependency, not the cache. The error
  message distinguishes "revocation status indeterminate (all responders unreachable)"
  from "certificate is revoked" so operators can tell an outage from a real revocation
  in the logs.
- **Tests:** `internal/ocsp/ocsp_indeterminate_test.go` — unreachable responder fails
  closed with the indeterminate error; the cached verdict carries the short TTL, not the
  1h revocation TTL; `cacheResult` honors caller-supplied TTLs.

---

## Status of prior findings (2026-07-05 → this review)

| ID | Status at `ea0f2ff` | Notes |
|---|---|---|
| CHAOS-01 | **OPEN — re-verified** | `ConfigStore.version` still in-memory only (`controlplane_snapshot.go`); DP gate still `snap.Version > lastVersion`. Still the top silent cluster failure. |
| CHAOS-02 | **FIXED in this change** | See F1. |
| CHAOS-03 | OPEN | No idle deadline on raw relays; stale SOCKS5 struct comment (`socks5.go:19-21`) still claims per-conn deadlines for in-flight tunnels. |
| CHAOS-04 | **FIXED in this change** | See F2. |
| CHAOS-05/07 | OPEN — re-verified | Corrupt `ui_users.json` / `cluster.json` still silently reset to empty and get overwritten; revoked-cert amnesia unchanged (`store.go:672-694`, `cluster_startup.go:32-33`). |
| CHAOS-06 | OPEN — re-verified | `rootca_startup.go:40-45` still log-and-continue; inspect-matched CONNECTs route to bypass when `certMgr.Ready()` is false (`proxy_tunnel.go:230-236`). No alert, no readiness signal. |
| CHAOS-08–21 | OPEN | No interim changes touched these paths. CHAOS-13's double-increment (`fetchAndApply` + `backoff()` both bump `failCount`) re-confirmed. |

---

## New findings — Risk Matrix (CHAOS-22 …)

| ID | Sev | Domain | Title | Verified |
|---|---|---|---|---|
| CHAOS-22 | HIGH | Upstream | Circuit breaker is dead code: `RecordFailure`/`RecordSuccess` never called from production paths | agent |
| CHAOS-23 | HIGH | Upstream | Health probe hardcoded to `detectportal.firefox.com`; one external-endpoint outage marks every upstream unhealthy → silent all-direct fallback (compounds CHAOS-11) | agent |
| CHAOS-24 | HIGH | Sessions | Session revocation never propagates across the cluster (`ExportRevocations`/`MergeRevocations` unwired); logout on node A leaves the cookie valid on B/C | agent |
| CHAOS-25 | HIGH | Lifecycle | Early shutdown phase has no time budget; CP `GracefulStop()` with a wedged RPC hangs SIGTERM forever (elevates the prior review's "low-risk residual") | agent |
| CHAOS-26 | HIGH | Memory | Scan buffering (5 MB body / 64 MB decompress per request) with connlimit off-by-default and no global connection or scan-concurrency cap → remote OOM | agent |
| CHAOS-27 | HIGH | Config | `applyConfigBackup` discards every store `Save()` error and returns nothing — rollback reports success after a partial-durability apply | agent |
| CHAOS-28 | MED | Storage | No data-directory lock: two instances on one `/data` silently last-writer-wins corrupt every store (only the KEK has the `os.Link` race guard) | agent |
| CHAOS-29 | MED | Auth | `CULVERT_SESSION_SECRET` invalid → boot **panic/crash-loop**; the same mistake in config → silent random key (full fleet logout). Divergent handling of the same error | agent |
| CHAOS-30 | MED | CA | No proactive CA-expiry alert (`internal/alerts/store.go:17` documents a startup alert that does not exist); rotation failures unalerted; `signLeaf` keeps minting leaves under an expired root | agent |
| CHAOS-31 | MED | Lifecycle | No `recover()` on handler-spawned goroutines (`go fireAlert(...)`, geo tracker, detached update goroutines) — one panic in any of them kills the process | agent |
| CHAOS-32 | MED | TLS | SSL-inspect pre-loop phases (upstream handshake, first-byte `Peek`, client handshake — `proxy_tunnel.go:489,522,566`) have no deadline after Hijack; handshake-slowloris pins goroutine + upstream conn | agent |
| CHAOS-33 | MED | Storage | Admin settings persist via fire-and-forget `go SaveAdminSettings()` — mutation APIs return 200 regardless of whether the save landed; setting silently vanishes on restart | agent |
| CHAOS-34 | MED | Updates | `recoverClusterUpdate` maps `updating_cp` → **complete** (optimistic: any CP restart mid-phase reports success); HA CP handoff uses fixed sleeps, never verifies the standby took leadership | agent |
| CHAOS-35 | MED | Auth | Lockout/rate-limit maps keyed by attacker-controlled username/IP have no hard cap — janitor-only bounding every 5 min (memory spike window) | agent |
| CHAOS-36 | MED-LOW | Lifecycle | Second SIGTERM/SIGINT ignored (signal channel read exactly once) — an operator cannot expedite a slow/hung shutdown short of SIGKILL | agent |
| CHAOS-37 | MED-LOW | Storage | Request-completion path does synchronous disk writes (reqlog/audit JSONL) — slow/stalled disk couples request latency to disk latency; audit failures additionally uncounted (CHAOS-19) | agent |
| CHAOS-38 | LOW-MED | Cluster | CA rotation + `CleanupSecondary` orphans a DP that was offline during the overlap window (cannot reconnect, cannot re-enroll) — compounds CHAOS-12 | agent |
| CHAOS-39 | LOW-MED | CA | Cert cache has no singleflight: concurrent misses duplicate leaf signing; burst-created entries expire together (synchronized re-sign herd) | agent |
| CHAOS-40 | LOW | Startup | `--enroll` boot is fatal on unreachable CP (`log.Fatalf`, `main.go:465-474`) — CP flap + fleets that bake `--enroll` into unit files = correlated restart-loop. (Already-enrolled DPs boot fine with CP down — verified.) | HV |
| CHAOS-41 | LOW | Auth | PKCE/SAML state stores evict an **arbitrary** entry when full (1000) — legitimate in-flight browser logins dropped under login flood (mitigated: allocation is browser-client-gated) | agent |
| CHAOS-42 | LOW | Updates | Updater self-update failure leaves the updater sidecar down with no rollback/retry — the cluster loses its update channel until manual recovery | agent |
| CHAOS-43 | LOW | OCSP | Posture inconsistency: fail-closed on responder outage but fail-**open** when the issuer cert can't be resolved from the chain (`internal/ocsp/ocsp.go:140-142`) | agent |

`HV` = hand-verified this review; `agent` = domain-audit evidence with file:line, not independently re-verified.

**Correction to an agent claim:** the lifecycle audit reported "CP will not boot when
etcd is unreachable." Hand-verification shows `armHALease` (`cluster_startup.go:152`) is
fatal only on **malformed** lease config (TTL floor, bad TLS material); the etcd client
is constructed lazily, so an unreachable etcd at boot yields denied-leadership, not a
crash — exactly the documented ADR-0005 posture. The fatal path is real but narrower
than reported.

---

## Detailed notes on the high-severity new findings

### CHAOS-22 — Upstream circuit breaker never runs
`internal/upstream/upstream.go:70-102` defines the breaker; `Next()` gates on
`up.CB.Allow()`. A repo-wide search finds **no production caller** of
`RecordFailure`/`RecordSuccess` — only the definitions and tests (which call them
directly, so the unit suite passes while the integration doesn't exist). Real request
failures through `pool.ProxyFunc()` (`upstream.go:262`) never open the breaker; the only
thing that can eject a broken upstream is the 30s external health probe — which brings
in CHAOS-23. Latent second bug for when it IS wired: half-open `Allow()` returns true to
**every** concurrent caller (`upstream.go:83-85`), so recovery releases a thundering
herd at a still-degraded upstream. **Fix shape:** record failures/successes in the
transport path (or the health loop's real-request observations) and single-probe
half-open; or delete the breaker and stop advertising it.

### CHAOS-23 — Health probe = third-party SPOF, feeding a fail-open fallback
`const healthCheckURL = "http://detectportal.firefox.com/success.txt"`
(`internal/upstream/upstream.go:273`) is fetched through each parent proxy every 30s. If
that one endpoint is blocked/down/rate-limited, every upstream is marked unhealthy and
`ProxyFunc` returns nil → **direct connections** (CHAOS-11's fail-open), silently
bypassing the parent-proxy egress/DLP boundary. No alert fires on the all-direct
transition. **Fix shape:** operator-configurable probe URL (GUI parity per convention),
alert + metric on pool-empty transitions, and a `fail_mode: open|closed` pool option.

### CHAOS-24 — Logout doesn't log out (cluster)
Revocation is per-node in-memory (`internal/session/session.go:130-174`);
`applySnapshotSessionSecret` syncs only the signing key
(`controlplane_snapshot.go:418-434`). `ExportRevocations`/`MergeRevocations` are
described as "for gRPC gossip" but have **no non-test caller**. Because the HMAC key IS
synced, a revoked cookie verifies everywhere else until TTL expiry (default 8h).
Deprovisioning an admin is not effective fleet-wide. **Fix shape:** carry revocations in
`ConfigSnapshot` (they are small, TTL-bounded) or wire the existing merge API into the
heartbeat/poll path — the registry-walled snapshot surface (`config_surfaces.go`) is the
natural place to declare it.

### CHAOS-25 — Un-budgeted early shutdown phase
`runShutdownSequence` (`main_shutdown.go:22-39`) runs the early hook registry with
`context.Background()` — the 30s late budget starts only afterwards. The early phase
contains `StopControlPlaneGRPC()` → `GracefulStop()` (`controlplane_server.go:663-668`),
which blocks until all in-flight RPCs and connections finish. One wedged DP stream =
SIGTERM hangs forever; combined with CHAOS-36 (second signal ignored) the only recovery
is SIGKILL, which skips the tunnel drain and cluster-store flush. **Fix shape:** race
`GracefulStop` against a timer and fall back to `Stop()` (the standard pattern), and/or
give the early phase its own budget; honor a second signal as immediate-exit.

### CHAOS-26 — Aggregate scan-buffer memory is unbounded
Each scanned response is read fully into memory up to `MaxBytes` (5 MB default,
`internal/secscan/secscan.go:217`) and `decompressForScan` may expand to
`MaxDecompressBytes` = 64 MB (`secscan.go:48`; call sites `proxy_http.go:178-184`,
`proxy_tunnel.go:817-826`). YARA has an inflight cap; the ClamAV/decompress buffering
does not, the per-IP connlimit is **disabled unless configured**, and there is no global
ceiling. N concurrent gzip-bomb-ish downloads → N×64 MB → OOM-kill. **Fix shape:** a
global semaphore around scan buffering (the `clamSem`/`yaraGetMaxInflight` pattern
already in-tree), and consider enabling a generous default connlimit.

### CHAOS-27 — Rollback swallows persistence failures
`applyConfigBackup` (`configversion.go:274-405`) applies ~10 stores sequentially; every
`Save()` return value is discarded and the function returns nothing, so the rollback API
answers 200 even if every disk write failed. Disk-full mid-apply leaves in-memory state
fully new but on-disk state mixed old/new — a restart reloads the Frankenstein. The
dpiScanner block already shows the right pattern (validate → mutate → single envelope
save, `:338-363`). **Fix shape:** collect and return per-store save errors; surface a
partial-apply warning in the API response and fire an alert.

---

## Recovery assessment (delta)

| Scenario | Automatic recovery | Manual recovery | Gap |
|---|---|---|---|
| One IP floods SOCKS5 tunnels | ✅ after this change (slot budget, when limiter enabled) | — | limiter default-off; idle reaping (CHAOS-03) still missing |
| OCSP responder blip | ✅ after this change (≤2 min) | — | closed |
| Parent-proxy health-probe endpoint outage | ❌ silent all-direct egress (CHAOS-23) | operator notices via logs only | no alert/metric on pool-empty |
| Upstream fails real requests but passes probe | ❌ breaker never trips (CHAOS-22) | remove upstream via API | breaker unwired |
| Admin logout / deprovision (cluster) | ❌ other nodes honor cookie ≤ TTL (CHAOS-24) | rotate session key (fleet logout) | revocation sync unwired |
| Wedged RPC during SIGTERM | ❌ hangs forever (CHAOS-25) | SIGKILL (skips drain/flush) | early-phase budget missing |
| Concurrent large compressed downloads | ❌ OOM-kill → restart (CHAOS-26) | enable connlimit, lower MaxBytes | no global scan/conn cap |
| Disk failure during config rollback | ❌ reports success, mixed state (CHAOS-27) | re-apply version after disk fixed | errors swallowed |
| Two instances on one /data | ❌ silent LWW corruption (CHAOS-28) | operator discipline | no dir lock |
| CP restart (CHAOS-01) | ❌ unchanged since last review | restart every DP | still no signal |

## Operational / Security / Data-integrity impact

- **Security impact concentrates in fail-open-by-omission:** the dead breaker + probe
  SPOF feed the already-known direct-egress fallback (CHAOS-11/22/23); revocation
  non-propagation (CHAOS-24) means session kill-switches don't work fleet-wide; CA
  load/expiry paths (CHAOS-06/30) still degrade the core inspection control on a log
  line. None of these announce themselves.
- **Availability impact:** CHAOS-25/26/31 are the process-killers (hang, OOM, panic in a
  spawned goroutine). CHAOS-29's env-typo panic is a crash-loop at boot — the one place
  the tree fails *loud* where quiet degradation would arguably be safer.
- **Data integrity:** the write side stayed strong (AtomicWrite everywhere that
  matters); the gaps are orchestration-level — rollback partial-apply (CHAOS-27),
  fire-and-forget settings save (CHAOS-33), no multi-instance guard (CHAOS-28).
- **Monitoring:** the recurring theme from 07-05 stands — the failure path has no
  counter. New instances: pool-went-empty, scan-buffer saturation, revocation-sync
  (n/a), rollback partial-apply.

---

## Verified resilient (new positive checks this run)

- **No startup fail-open window:** blocklist/policy/rewrite load synchronously before
  the proxy listener starts (`main.go:196-213`, listener at `:991-995`); DP applies its
  persisted last-good snapshot before serving. (The known CHAOS-18 ordering race between
  cluster snapshot and later local-store inits still stands — different issue.)
- **Background-loop hygiene:** every audited loop (CA rotation, threat-feed sync, SSE,
  heartbeat, janitors, hit-counter persister, SIGHUP reloader) is context-parented and
  stops its ticker; final-save-on-cancel where it matters (`metrics.go:119-131`).
- **Bounded in-memory structures:** audit ring 500, reqlog ring 5000, hashcache
  size+TTL bounded, per-rule metrics 200, SSE hub 256 clients / 4-deep queues with
  eviction + per-frame deadlines, plain-HTTP request body 64 MB cap.
- **Heartbeat liveness is DP-clock-skew immune:** `LastSeen` is stamped with CP-local
  time on receipt (`enrollment.go:378`, `:636`); only a CP-clock jump distorts it.
- **HA lease (ADR-0005) posture re-confirmed:** unreachable etcd at boot = lazily denied
  leadership (not fatal — see correction above); confirmed-loss self-fence; `WriteAllowed`
  fail-closed; DP epoch ratchet incl. zombie-shape rejection (`ha_fencing.go:94-137`).
- **Release auto-seed fail-closed re-confirmed:** any staged-verify error leaves the
  installed catalog untouched; move-aside swap restores on rename failure
  (`release_autoseed.go:49-122`).
- **2026-07-05 fixes holding:** threat-feed carry-forward, syslog write deadline +
  backoff, rotation-archive preservation, AtomicWrite migration, geo-tracker semaphore —
  all present at HEAD with their regression tests green.
- **JWKS stale-key fallback** (`auth_oidc_flow.go:132-157`) and **TOTP ±30s skew**
  (`internal/totp/totp.go:20`) are deliberate, documented availability trades — correct.

---

## Suggested improvements (priority order)

1. **CHAOS-01** — persist/seed the CP `ConfigStore` version or hash-gate DP applies. S-M. *(Carried — still #1.)*
2. **CHAOS-22 (+ half-open single-probe)** — wire `RecordFailure`/`RecordSuccess` into the transport path, or delete the breaker. S.
3. **CHAOS-24** — sync session revocations via `ConfigSnapshot` (registry-walled) or wire the existing merge API. S-M.
4. **CHAOS-26** — global scan-buffer semaphore; revisit connlimit default. S.
5. **CHAOS-25 + CHAOS-36** — budget the early shutdown phase (`GracefulStop` vs timer → `Stop()`); honor the second signal. S.
6. **CHAOS-23** — configurable probe URL + pool-empty alert; `fail_mode` option (folds CHAOS-11). S.
7. **CHAOS-06/30** — CA load-failure + expiry + rotation-failure alerts; readiness signal; optional `inspection.required` fail-closed mode. S.
8. **CHAOS-27** — propagate rollback save errors to the API response + alert. S.
9. **CHAOS-05/07** — quarantine-don't-overwrite corrupt `ui_users.json`/`cluster.json` (the `readVersionFloor` fail-closed pattern is the in-tree model). S.
10. **CHAOS-31** — shared `recover()` wrapper for handler-spawned goroutines. XS.
11. **CHAOS-29** — make env vs config secret handling consistent (both fail loud, or both fall back with an alert). XS.
12. **CHAOS-32** — arm deadlines around the inspect-path handshakes/Peek (the `stallDetectReadCloser` pattern). S.
13. **CHAOS-03/13/14/19/20** — carried from 2026-07-05, unchanged sizes.

## Required tests (for the follow-up fixes)

- Circuit breaker integration: a parent proxy that accepts TCP but fails requests trips
  the breaker via the real transport path; half-open admits exactly one probe (CHAOS-22).
- Cross-node revocation: revoke on A → B rejects the cookie within one sync period (CHAOS-24).
- Shutdown fault-injection: wedged gRPC stream during SIGTERM → process exits within
  budget; second SIGTERM forces immediate exit (CHAOS-25/36).
- Memory bound: N concurrent max-size compressed downloads hold ≤ cap bytes of scan
  buffer (CHAOS-26).
- Rollback disk-fault: injected `Save()` failure mid-`applyConfigBackup` surfaces in the
  API response (CHAOS-27).
- Panic isolation: a panicking handler-spawned goroutine does not kill the process (CHAOS-31).
- Carried from 2026-07-05: CP-restart staleness (CHAOS-01), idle-relay reaper (CHAOS-03),
  corrupt-store quarantine (CHAOS-05/07), CA-load alert/readiness (CHAOS-06).
- Shipped in this change: `socks5_connlimit_test.go` (2 tests),
  `internal/ocsp/ocsp_indeterminate_test.go` (3 tests).

## Residual risk

- Findings marked `agent` carry file:line evidence but were not all independently
  re-verified; the one claim hand-verification overturned this run (etcd-fatal-at-boot)
  is documented above — treat the rest with the same skepticism before acting.
- Severity of CHAOS-22/23 depends on deployment shape: sites that don't use parent
  proxies are unaffected; sites that use them as a security boundary should treat the
  pair as HIGH.
- This review did not deep-dive: the maintenance-agent sudo boundary (D1.6c/P1.4), the
  bootstrap/enrollment UX surface, plugin-engine failure modes, or Sigstore verifier
  edge cases (P2b). Natural next passes.
- The two fixes alter failure-path behavior only (a refused SOCKS5 session that
  previously exhausted resources; a shorter cache TTL for an outage verdict); happy
  paths are unchanged. Full `go test ./...` run before merge; Lane A enforces the
  coverage contracts.
