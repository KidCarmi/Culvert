# Chaos engineering review — 2026-10-13

Reviewer: Culvert Chaos Engineer (automated round). Base revision `77c0c58`
(`main`), clean worktree. Scope: failure modes of the cluster control/data
plane, persistence, background workers, lifecycle and the data-plane request
path.

This round is recorded separately from
[CHAOS-ENGINEERING-REVIEW.md](CHAOS-ENGINEERING-REVIEW.md) because it closes
three defects and opens a prioritized backlog; the risk-matrix rows it touches
are named inline so the main review stays the index.

---

## 1. Executive summary

Culvert's resilience posture is, on the whole, unusually strong for its size:
`fileutil.AtomicWrite` is a real single durable-write chokepoint with a
write-failure observer plane behind it, `internal/feedsched` is a correct
cadence engine, the shutdown registry is bounded and panic-contained, and the
HA fencing epoch is enforced on the puller side with a persisted data-plane
ratchet. Most of what a chaos review would normally find has already been found
and closed here, and the prior rounds' reasoning is recorded well enough to
build on.

The three defects fixed in this round are therefore not gaps in coverage. They
are **inversions**: in each case a mechanism that exists specifically to make a
failure survivable made it worse.

1. **CHAOS-72 (CRITICAL) — HA standby→leader promotion self-deadlocks.**
   `enableControlPlane` held the `clusterRoleMu` *write* lock while building the
   initial config snapshot, and that snapshot reads the same (non-reentrant)
   `RWMutex` through `buildCPAddressList`. The guard that was meant to make this
   unreachable — `buildCPAddressList`'s HA-disabled early return — is open on
   exactly the promotion path, because a standby's role makes
   `HAStatus.Enabled` true for its whole stint. **Every** promotion path
   (manual, legacy auto-failover, planned handoff, lease-arbitrated) reaches it.
   The node never promotes, and because the wedged goroutine keeps the write
   lock, every reader behind it wedges too: diagnostics, the health surfaces,
   the PAC mutation gate and the support bundle. A fleet that loses its leader
   is left with no control plane *and* no way to diagnose why. **Verified
   empirically** (a probe under the write lock blocked indefinitely; see §2.1).

2. **CHAOS-71 (HIGH) — the data plane's backoff against its control plane was
   defeated three ways at once.** The consecutive-failure streak was
   incremented twice per failed poll (once by `pollConfig`, once by `backoff`),
   so the documented `2s, 4s, 8s, …, 60s` ladder was really **`4s, 16s, 60s`** —
   the ceiling on the third failed poll instead of the sixth — and the
   documented "3 consecutive failures" failover gate tripped on the **second**.
   Worse, `failover()` cleared the streak on a successful *dial*, so an HA pair
   that answered TCP while failing `GetConfig` (overloaded, fenced out, or
   timing out an oversized snapshot) held every data plane on the ladder's low
   rungs **forever**, flapping between control planes every few polls. And
   nothing — neither the ladder nor any of the five CP-facing tickers — was
   jittered or phase-offset, so a fleet that failed together retried together
   and reconnected in one instant. **Verified empirically** (observed ladder and
   failover point; see §2.2).

3. **CHAOS-73 (MEDIUM) — an unbounded per-peer-IP map on the control plane.**
   `unenrolledConfigPull.attempts` grows one permanent entry per distinct source
   address that ever attempts a pre-enrollment config pull, with no TTL, no cap
   and no sweep. Its structurally identical sibling `enrollRateLimit` *has* a
   janitor, wired into the shared cleanup loop, whose own doc comment names this
   exact hazard. The fix was never carried across. **Verified by direct source
   read** (no cleanup function for it exists anywhere in the tree).

Beyond these, the round opened a backlog of 29 further findings across
durability, retry shaping, resource exhaustion and lifecycle. They are recorded
in §4 with explicit verification status, because several are consequential
enough that an owner decision — not a drive-by patch — is the right next step.
Two are flagged for near-term attention: a **CP-restart-mid-CA-rotation fleet
lockout** (§4.1) and an **unauthenticated log/block-page write amplification on
the default configuration** (§4.3).

**Honest limits of this round.** Findings 1–3 are reproduced by tests that fail
on the pre-fix revision. Everything in §4 marked *delegated* was produced by
parallel reviewers and is **not** independently reproduced; the three items
marked *source-verified* I read myself. No full-module or hosted CI result for
the PR's SHA is claimed — see §9.

---

## 2. Failure scenarios (the three closed this round)

### 2.1 CHAOS-72 — promotion self-deadlock

| | |
|---|---|
| **Trigger** | Any HA standby→leader promotion: operator clicks promote (`POST /api/cluster/ha/promote`), legacy auto-failover, planned handoff, or lease-arbitrated auto-promotion. |
| **Current behavior (pre-fix)** | `HAState.promote` → `onPromote` → `enableControlPlane` takes `clusterRoleMu.Lock()`, then evaluates `CurrentConfigSnapshot()` → `buildCPAddressList()` → `clusterRoleMu.RLock()`. `sync.RWMutex` is not reentrant: the read lock blocks on the goroutine already holding the write lock and never wakes. |
| **Expected behavior** | Promotion completes, or fails with a reported error. |
| **Failure mode** | Permanent deadlock in the admin HTTP handler goroutine, **holding a process-global write lock**. |
| **Recovery path** | None in-process. Restart the node. |
| **Automatic recovery** | None. The CHAOS-56 shutdown watchdog abandons the `ha-stop` hook so shutdown still completes — that is the only thing that stops this from also hanging SIGTERM. |
| **Customer impact** | A leader failure becomes a fleet-wide control-plane outage. Data planes keep enforcing their last-known-good snapshot (so traffic flows) but receive no config, no policy and no revocation updates until a human intervenes. |
| **Security impact** | Policy and revocation changes silently stop propagating fleet-wide. A session revoked during the window is never gossiped; a blocklist or rule change never lands. The fleet drifts from intended posture with no enforcement gap that monitoring would notice. |
| **Operational impact** | Severe and self-concealing. Every `clusterRoleMu` reader wedges behind the stuck writer — `/healthz`, diagnostics, the PAC mutation gate, and the **support bundle**, i.e. the break-glass evidence path an operator would reach for is exactly what is unavailable. |
| **Data integrity impact** | None directly; the snapshot is never published, so no partial state is written. |
| **Monitoring visibility** | **Worse than none.** The surfaces that would report it are the ones that block. The promotion request never returns. |
| **Why it escaped testing** | The only existing test that calls `enableControlPlane` (`cluster_audit_test.go`) runs with HA **disabled**, so `buildCPAddressList` takes its `nil` early return and the reentrancy never fires. The guard being conditional on HA is precisely what made the test vacuous. |
| **Residual risk after fix** | The invariant "nothing may build a config snapshot while holding `clusterRoleMu`" is now enforced by a test on the lock itself, not only on this caller. A *new* caller could still reintroduce it; see §10. |

### 2.2 CHAOS-71 — DP→CP retry cadence

| | |
|---|---|
| **Trigger** | Any control-plane unavailability: restart, rolling upgrade, HA failover, node reboot, overload, or an oversized snapshot timing out. |
| **Current behavior (pre-fix), measured** | Single CP, successive failed polls: `failCount` 2, 4, 6, 8 and delays **4s, 16s, 60s, 60s**. Two CPs: failover on the **2nd** consecutive failure; thereafter the redial reset the streak, so the client settled into a permanent `2s, 8s, 2s, 8s, …` cycle with a **failover on every other poll**, and **never reached the 16s rung, let alone the 60s ceiling**. |
| **Expected behavior** | `2s, 4s, 8s, 16s, 32s, 60s`, converging on the ceiling; failover every 3rd consecutive failure; delays decorrelated across the fleet. |
| **Failure mode** | (a) convergence latency up to 60s after only ~3 polls on a single-CP deployment; (b) on every HA deployment, a *permanent* ~5s-average poll cadence plus a fresh gRPC connection every other poll against a control plane that is already failing — congestion-collapse fuel, and exactly the "spurious failover churn against a healthy leader" the snapshot-scaled call deadline was introduced to avoid; (c) fleet-synchronized retry and one-instant mass reconnect on recovery. |
| **Recovery path** | Automatic on the first successful poll (`resetBackoff`). |
| **Customer impact** | Degraded, not down: a data plane keeps enforcing its last-known-good snapshot. The cost is config convergence latency and, in a fleet, a control plane that is harder to bring back than it should be. |
| **Security impact** | Policy, blocklist and revocation updates converge late. Bounded by the ladder, but on an HA deployment the pathological case is sustained load on the control plane rather than a long gap. |
| **Operational impact** | A control-plane restart in a large fleet is noisier and slower to settle than designed. Log flood: one line per failure per loop per node. |
| **Monitoring visibility** | Partial, and misleading: `dpMarkCPPollFailing` and `dpPollHist` exist, but the backoff log line itself reported the wrong rung ("backing off 4s (failure #2)" on the *first* failed poll), so an operator could not reconstruct the real cadence from it. |
| **Severity tempering (verified)** | The P0-3 `KnownVersion` sentinel means an *unchanged* config poll returns a small "unchanged" reply rather than the full (up to ~60 MiB) snapshot, so the recovery herd is only expensive when config actually changed. gRPC's own transport backoff keeps the *dial* from hot-looping. Both materially reduce the blast radius, and neither addresses the ladder or the jitter. |
| **Residual risk after fix** | The cold-start poll is deliberately **not** staggered (see §10); the four telemetry loops still have no backoff at all (§4.2, not fixed here). |

### 2.3 CHAOS-73 — unbounded per-peer-IP throttle map

| | |
|---|---|
| **Trigger** | Any peer that can reach the control plane's gRPC port issuing a pre-enrollment `GetConfig` / `GetConfigDelta`. |
| **Current behavior (pre-fix)** | `unenrolledConfigPull.attempts[ip]` is pruned only on *that same IP's* next pull. One request from an address that never returns leaves a permanent entry. |
| **Expected behavior** | Aged-out entries swept periodically, as `enrollRateLimit` already is. |
| **Failure mode** | Unbounded memory growth keyed by attacker-chosen source address (an IPv6 sweep needs one request per entry). |
| **Recovery path** | Process restart only, pre-fix. |
| **Customer impact / security impact** | Slow memory exhaustion of the control plane — the node whose loss is a fleet-wide management outage. Not a privilege or data issue. |
| **Monitoring visibility** | None specific; shows up only as RSS growth. |
| **Residual risk after fix** | Same as its sibling: the sweep runs every 5 minutes against a 1-minute window, so up to 5 minutes of distinct-IP accumulation is still possible between sweeps. That interval is a pre-existing, reviewed choice and is not changed here. |

---

## 3. Risk matrix — this round

Severity is impact × reachability on a **supported default deployment**.

| ID | Finding | Severity | Status | Evidence |
|----|---------|----------|--------|----------|
| CHAOS-72 | HA promotion self-deadlocks on `clusterRoleMu`; wedged writer blocks health/diagnostics/PAC/support | **CRITICAL** | **FIXED** | `main.go` `enableControlPlane`, `controlplane_snapshot.go` `buildCPAddressList`; empirical |
| CHAOS-71a | Failure streak double-incremented → wrong ladder (`4s/16s/60s`) and failover on the 2nd failure | **HIGH** | **FIXED** | `controlplane_client.go` `backoff`/`pollConfig`; empirical |
| CHAOS-71b | Redial cleared the streak → HA deployments never back off; permanent CP flapping | **HIGH** | **FIXED** | `controlplane_client.go` `failover`; empirical |
| CHAOS-71c | No jitter on the ladder, no phase offset on five CP-facing tickers → fleet lockstep + mass reconnect (instantiates registered **WK-13 / HA-11**, P2) | **MEDIUM** | **FIXED** | `controlplane_client.go`; empirical |
| CHAOS-72b | The snapshot a promoted leader publishes names the **dead** peer and not itself, and `updateDPAddresses` REPLACES a DP's failover list rather than merging — so a DP that had just found the new leader overwrote its working address with the dead one | **HIGH** | **FIXED** | `main.go` `enableControlPlane`; raised by Codex review of PR #1618, mechanics source-verified |
| CHAOS-72c | `updateDPAddresses` replaced `c.addrs` without re-resolving `activeIdx`, which indexes it; a shrinking list left the index past the end and `reconnectActive` — the **certificate-renewal redial** — panicked on it | **HIGH** | **FIXED** | `controlplane_client.go`; empirical (`index out of range [1] with length 1`) |
| CHAOS-73 | `unenrolledConfigPull.attempts` unbounded per peer IP; sibling has a janitor | **MEDIUM** | **FIXED** | `controlplane_server.go`; source-verified |

Registered rows this round touches: **WK-13** (jitter on every feed/poll ticker)
and **HA-11** are now closed *for the cluster control/data plane*. They remain
open for `internal/blocklistfeed` and `internal/otlp` — see §4.2.

---

### 3.1 Two defects the CHAOS-72 fix uncovered

Worth recording as a method note, not just as rows. CHAOS-72 was a deadlock, and
a deadlock is a *perfect* mask: the promotion path never reached its own publish,
so two further defects downstream of that publish had never executed on this
path. Fixing the hang made both live at once, and the Codex review of the PR
caught the first within minutes of it becoming reachable.

- **CHAOS-72b** — `buildCPAddressList` composes the DP failover list from the HA
  peer address and `clusterRole.grpcAddr`, and `grpcAddr` is deliberately
  assigned only *after* the listener binds ("only set role after gRPC is
  successfully started"). For a promoting standby the peer is **the leader that
  just died**, so the published list named the dead node and omitted the one
  taking over — and `updateDPAddresses` replaces a DP's list rather than merging
  into it, so a data plane that had just reached the new leader would overwrite
  its working address with the dead one and have nothing live left to redial.
  Fixed by republishing once the role fields are committed, outside the write
  lock (inside it would be CHAOS-72 again), and only when the list actually
  changed so ordinary non-HA startup does not spend a config version on a no-op.

- **CHAOS-72c** — found while fixing 72b, and worse. `activeIdx` is an index
  *into* `c.addrs` naming the address the live connection holds, and
  `updateDPAddresses` replaced the slice without re-resolving it.
  `reconnectActive` indexes it directly, and its `len == 0` guard does not cover
  an index past a *non-empty* slice — so a shrinking list panicked with
  `index out of range [1] with length 1`. `reconnectActive` is the
  certificate-renewal redial, which runs unattended on a healthy node, and the
  one-element list CHAOS-72b published is exactly the shrink that triggers it.
  Fixed by re-resolving by **address** rather than clamping the index: clamping
  also stops the panic but silently re-points the client at a different control
  plane than the one its connection actually holds.

The lesson for the backlog in §4: a fix that unblocks a path can promote latent
defects downstream of it into live ones. Any work on L-1/L-5 (listeners that
exit or die silently) should expect the same, and should look at what has never
actually run past the failure being fixed.

---

## 4. Backlog opened by this round (NOT fixed)

Each row carries its verification status. **Nothing below is reproduced unless
it says source-verified or empirical**; the `delegated` rows come from parallel
reviewers and are leads to confirm, not established defects. They are recorded
rather than patched because most need an owner decision about posture, or a
change wider than a chaos round should make unreviewed.

### 4.1 Durability and state corruption

| ID | Finding | Sev | Status |
|----|---------|-----|--------|
| D-1 | **CP restart mid-CA-rotation locks the whole DP fleet out.** The dual-CA overlap (`secondaryCert`/`secondaryPEM`/`secondaryExp`) is reported to be memory-only with no load path from disk, while `cluster.json` durably records "rotation in progress, N nodes pending". A CP restart inside the overlap would leave the client-CA pool holding only the new CA, failing mTLS for every DP still presenting an old-CA cert — self-inconsistent and invisible. The only on-disk copy of the old CA is written by a plain `os.WriteFile` with the error discarded. | **HIGH** | delegated |
| D-2 | Six `support/` writers use `WriteFile`+`Rename` with **no fsync** and a **fixed `.tmp` name**, bypassing the `AtomicWrite` chokepoint — so ENOSPC/EROFS there is invisible to the storage-health plane, and loaders silently reset to defaults (upload `not_enabled`, empty TAC roster, queue entries vanishing). | **MED** | delegated |
| D-3 | A delivered support bundle's terminal state is persisted non-durably *before* the sealed blob is deleted → a bundle that was delivered can be re-reported as failed, or **re-uploaded** to the TAC gateway on a second consent-free egress. | **MED** | delegated |
| D-4 | `writeBundleState` takes no mutex and uses a per-bundle shared fixed temp path → two concurrent approvals can tear `state.json`, which fails closed to `PENDING` and drops the case-ID binding that prevents retention eviction mid-upload and case redirection. | **MED** | delegated |
| D-5 | The audit JSONL has **no fsync** anywhere (and rotation does unlink+rename with no parent-dir fsync), so a config change is durable while its "who changed what" record is not. ENOSPC *is* counted and alerted; only power-loss durability is missing. | **MED** | delegated |
| D-6 | `RevokeUser` state (`r.users`) is never exported by `ExportRevocations`, so it is **neither persisted nor gossiped** — a defense-in-depth layer that silently stops working across a restart. Impact is capped by a real backstop: a `local`-provider session whose subject is absent from the durable roster is already rejected. | **LOW** | **source-verified** |
| D-7 | CDR's runtime-enabled sentinel and initial enrollment cert writes are non-atomic behind a **fail-open** control, so a reverted toggle or a truncated PEM silently disables sanitization. | **MED** | delegated |
| D-8 | Policy `.meta` sidecar write failure is unguarded in the rules-landed-then-meta-failed direction, so the published policy version can regress while rule content changed. | **LOW** | delegated |

### 4.2 Retry, backoff and cadence

| ID | Finding | Sev | Status |
|----|---------|-----|--------|
| R-1 | **Four of the five DP→CP loops have no backoff at all** — metrics, rate-limit gossip (5s), revocation sync (3s) and audit push (10s) each `continue` on error and retry at full rate for the whole outage (~0.6 RPC/s/node) plus a log line per failure. Deliberately **not** bundled into CHAOS-71: the gossip loop's freshness evaluation is coupled to its tick by CHAOS-61, and revocation/audit delay has security and compliance meaning, so changing their cadence needs a posture decision rather than a mechanical fix. | **MED** | delegated (loops' structure source-verified while fixing CHAOS-71) |
| R-2 | **Hidden retry — effective MCP upstream timeout is 3× the configured one.** The request deadline is created *inside* the per-attempt round trip under a retry loop with no delay between attempts, so a stalled upstream occupies ~90s against a configured 30s budget and sends 3 POSTs where 1 was budgeted. | **MED** | delegated |
| R-3 | `internal/blocklistfeed` is the one feed never migrated to `internal/feedsched`: `lastAttempt` is stamped on the error path too, so a failed sync is not retried for a full interval (default 24h), with no jitter against a third-party origin, and its fetch uses `context.Background()` so it is not cancellable at shutdown. **This is the live remainder of registered WK-13.** | **MED** | delegated |
| R-4 | The alert webhook retry pass is not interruptible (no ctx check inside the per-item loop) and each delivery is parented to `context.Background()`, so a blackholed webhook with a full 500-item queue can keep delivering and writing the retry queue to disk long after lifecycle cancellation. | **MED** | delegated |
| R-5 | `internal/otlp` exporters never back off and their push interval is unjittered — a fleet sustains a failing collector's overload at full rate and stays in phase forever. **WK-13 remainder.** | **LOW** | delegated |
| R-6 | `acquireLeaseForResume` retries with bare `time.Sleep` on the **pre-listener boot path**, so SIGTERM cannot interrupt up to 45s of it. Hard-bounded by deadlines, and the background sibling (`ha_lease_recovery.go`) is correct — only the boot-path loop is not. | **LOW** | delegated |
| R-7 | MCP telemetry export retry is flat (constant 50ms × 16), not exponential — ~16 attempts/sec sustained against a down sink. Bounded in count and ctx-aware. | **LOW** | delegated |

### 4.3 Resource exhaustion

| ID | Finding | Sev | Status |
|----|---------|-----|--------|
| X-1 | **Unauthenticated log + block-page write amplification on the default config.** `r.URL.Path` is never length-bounded (only the *authority* is, by CHAOS-69), while the default file-block extension list makes the branch fire on a stock install: ~1 MiB in → ~1 MiB to the process log plus a ~5 MiB HTML-escaped block page buffered and written back, repeatable as fast as a client can upload, with the three front-door limiters all shipping disabled. This is the already-registered **PX-22** row, instantiated with an amplification factor. | **HIGH** | delegated |
| X-2 | `internal/logsink`'s bounded channel **blocks the request goroutine** when full, and its stated memory budget assumes a line cap that only governs pool return — the queued buffer is the full line length. With X-1 or X-3 the real ceiling is ~4096 × 1 MiB. A slow container log consumer alone can convert into proxy-wide request stalls. | **HIGH** | delegated |
| X-3 | `SSL_INNER` logs an unbounded inner request path on every inspected request; H1 is incidentally bounded by its reader size but **H2 is not** (1 MiB header budget × 32 concurrent streams). With `LogFullURI` the same value is retained in a ring bounded in *entries*, not bytes. | **MED** | delegated |
| X-4 | Scan-path decompression expands a buffered prefix to up to 64 MiB **before** any scanner admission gate, with no semaphore or memory budget for the buffering stage, so N concurrent responses multiply freely. A related CDR path presizes from a peer-reported size with the cap checked only after appending. | **HIGH** | delegated |
| X-5 | `internal/scanner` spawns one goroutine per DPI scan with no in-flight cap and abandons it on timeout, holding the body until the match finishes — uncounted and uncapped. Its direct twin in `internal/yara` solves exactly this with a counted, fail-closed in-flight cap. | **MED** | delegated |
| X-6 | Cluster hot-IP gossip exports one entry per tracked IP with no cap, under the same shard lock the request path takes, against a 16 MiB inbound frame cap justified on the assumption these RPCs are tiny — so a high-cardinality flood makes every `SyncRateLimits` fail, silently degrading the fleet to local-only limiting exactly when cluster counting matters. (Stale-counts-fall-back-to-local is a *deliberate* documented exception; the new fact is that the flood's own cardinality induces it.) | **MED** | delegated |
| X-7 | The session revocation token map has no sweep unless a revocations file or cluster mode is configured; where a file *is* configured, every logout marshals and fsyncs the whole list, making a login/logout loop O(N²) bytes fsynced. | **MED** | delegated |

### 4.4 Lifecycle

| ID | Finding | Sev | Status |
|----|---------|-----|--------|
| L-1 | **A CP gRPC bind failure is still fatal** (`logFatalf`), before the proxy, admin UI and `/healthz` exist — so a port held by a draining predecessor, an interface race, or a dropped bind capability becomes an unattended crash loop that takes the fleet's management plane with it. This is the last instance of the class CHAOS-57 closed for the admin UI and CHAOS-66 for SOCKS5; the recorded "the proxy must exit loudly" exception does not cover it. | **HIGH** | **source-verified** |
| L-2 | SOCKS5 begins accepting before GUI-persisted IP-filter / rate-limit / per-IP-connection settings are applied, so a GUI-configured appliance has a **fail-open** window (widening with `/data` latency) in which blocked source IPs are proxied. YAML/CLI-configured fleets are unaffected; the HTTP proxy and the MCP gateway are not affected (the latter is fail-closed). | **HIGH** | delegated |
| L-3 | SIGTERM/SIGINT are unhandled for the whole of startup — including after SOCKS5 and the admin UI are already serving and the badger-backed stores are open — so a mid-boot orchestrator cancel kills the process with no flush hooks. Damage is bounded by the existing quarantine-on-next-boot posture and synchronous audit writes. | **MED** | delegated |
| L-4 | `logFatalf` bypasses the shutdown registry entirely, including from the live proxy serve loop, so a lost listening socket severs in-flight tunnels with no accounting and closes the stores uncleanly. The *exit posture* is a recorded owner decision; exiting via `os.Exit` rather than signalling `quit` is the defect. | **MED** | delegated |
| L-5 | Two listeners die silently with no retry, alert, metric or health row: the **CP gRPC serve loop** (after which every surface still reports a healthy CP while no DP receives config) and the **scan sidecar**. Contrast the admin UI and SOCKS5, which have the full treatment. | **HIGH** | **source-verified** (CP gRPC half: the serve goroutine's only reaction to `Serve` returning is one `logger.Printf`; no role demotion, no rebind, and no CP-gRPC health surface exists anywhere in the tree). Scan sidecar half: delegated. |
| L-6 | Five background workers lack the repo's own per-round panic guard (SSE broadcaster — every second, over the widest set of mutable globals in the binary; support retention janitor, whose boot sweep is synchronous; support upload worker; debug-level watchdog; decryption-trend sampler), so a panic in a round terminates the gateway. | **MED** | delegated |
| L-7 | Lifecycle handles built to be awaited are discarded (hit-counter persistence `done`, SSE `Done()`, SIGHUP reloader `Done()`), and MCP telemetry loops are parented to `context.Background()` 25 lines after the same file argues they must not be. Loss mode is a missed checkpoint, not corruption. | **LOW** | delegated |

---

## 5. Recovery assessment

**What recovers deterministically today** (verified while reviewing, named so it
is not re-reported as missing):

- **Durable-write failure** → `fileutil.AtomicWrite`'s observer plane counts
  every failure, logs the first, degrades the diagnostics storage row, exports a
  metric and fires a rate-limited alert; recovery requires an *observed*
  successful write, not elapsed time.
- **State-file corruption** → quarantine-don't-overwrite: the corrupt file is
  renamed aside, an alert fires, `/readyz` carries a row, and the condition
  re-surfaces across boots. Read errors deliberately do not quarantine.
- **Badger `.sst` corruption** (the uncatchable-panic class) → poison marker +
  flock-gated quarantine + classifier; degrade, never exit.
- **Interrupted restore** → the boot guard refuses to start and prints the exact
  recovery commands.
- **CA load failure** → bounded retry campaign that never mints, latch cleared
  only on evidence, with metrics and a fail-open banner.
- **Shutdown** → three bounded phases, a reserved flush budget, a per-hook
  watchdog with a guaranteed minimum slice, panic containment, an `entered`
  handshake so a hook body is never skipped, and second-signal escalation. The
  envelope-versus-container-stop-grace relationship is pinned by a test.
- **Tunnel drain** → honours both the drain window and the phase deadline,
  re-fires GOAWAY, force-closes on either bound with a bounded settle so byte
  accounting still reaches the request log, and fences late establishment.
- **Fencing** → epoch stamped on authority-bearing writes, verified on the
  **puller** side, with a DP-side ratchet persisted across restarts.

**What does not recover, after this round:**

- **L-1 / L-5**: a control plane whose gRPC listener fails to bind exits; one
  whose serve loop dies afterwards stays "healthy" forever. Neither has the
  rebind-and-report treatment two other listeners already have. These are the
  most load-bearing recovery gaps left.
- **D-1**: a CP restart inside a CA rotation window has, as reported, no
  recovery path short of re-enrolling every data plane.
- **R-3**: a blocklist feed that fails once waits a full interval, with no
  retry and no health-visible staleness pressure.

---

## 6. Operational impact

The recurring operational theme of this round is **signal inversion**: three of
the four most serious items are failures whose own monitoring is what breaks.
CHAOS-72 wedges the health, diagnostics and support-bundle surfaces an operator
would use to diagnose it. L-5's dead CP serve loop leaves every surface
reporting a healthy control plane. CHAOS-71's backoff log line reported a rung
the code was not using.

For the three fixes: CHAOS-72 turns a hung promotion into a completed one, so
the existing HA surfaces report truthfully again. CHAOS-71 makes the backoff log
line match reality and makes a control-plane restart in a large fleet settle
smoothly instead of as a synchronized burst — the recovery is quieter, and the
log flood during an outage decays. CHAOS-73 removes an unbounded growth source
on the node whose loss is a management outage.

No new operator-facing configuration is introduced, so there is no GUI/API
parity obligation for this change.

---

## 7. Security impact

None of the three fixes changes a security posture, a default, or a policy
decision; all three restore intended behavior.

- **CHAOS-72** is the most security-relevant: during the deadlock, policy,
  blocklist and session-revocation changes stop propagating fleet-wide while
  every node continues to serve traffic and report healthy. That is posture
  drift with no visible enforcement gap. The fix closes it.
- **CHAOS-71** shortens the window in which a fleet enforces stale policy after
  a control-plane blip, and stops a data plane from hammering a struggling
  control plane — which is the resource a fleet's security posture depends on.
- **CHAOS-73** removes a remotely-driven unbounded allocation on the control
  plane. It does not change the throttle's *decision*, only the sweeping of
  aged-out state, so the exfiltration throttle the map exists for is unchanged.

The fencing epoch, RBAC, audit-then-version ordering, SSRF guards and
sanitization paths are untouched. `sanitizeLog` + `%q` discipline is preserved
in every log line this change goes near. The highest-severity *security*
findings of the round are in §4 and remain open: L-2 (fail-open SOCKS5 window),
X-1/X-4 (unauthenticated amplification), D-7 (fail-open CDR), D-1 (fleet
lockout).

---

## 8. Suggested improvements (prioritized)

Ordered by expected harm reduced per unit of review risk.

1. **L-1 + L-5 — finish the listener-resilience pattern.** Give the CP gRPC
   listener the rebind-with-backoff + alert + `/readyz` row + gauge treatment
   that the admin UI and SOCKS5 already have, and make the serve loop's exit
   demote the reported role instead of leaving a phantom control plane. This is
   the single highest-value remaining change: the pattern, the health plane and
   the precedent all already exist, so it is largely mechanical.
2. **D-1 — persist the dual-CA overlap.** Confirm the reported gap, then load
   the secondary CA from disk at boot and make `backupCAFiles` go through
   `AtomicWrite` so the operator's only recovery copy is durable and its failure
   is visible.
3. **X-1 / X-2 / X-4 — bound the three amplifiers.** Cap the logged/rendered
   request path (PX-22's open product decision, now with an amplification factor
   attached), bound the line length `logsink` will queue, and put the
   decompression stage behind the same kind of admission gate its downstream
   scanners already have.
4. **L-2 — close the SOCKS5 fail-open window.** Apply GUI-persisted admission
   settings before any listener accepts, or gate SOCKS5 accept on an
   admission-ready latch. A fail-open window on a security gateway should not
   depend on `/data` latency.
5. **R-3 — migrate `internal/blocklistfeed` onto `internal/feedsched`.** This is
   the live remainder of WK-13 and the package was written for exactly it;
   `internal/otlp` (R-5) is the same argument, lower stakes.
6. **R-1 — decide the telemetry-loop posture** (backoff versus full-rate retry
   for revocation/audit/gossip during a CP outage), then implement it. Needs the
   decision first because of the CHAOS-61 freshness coupling.
7. **L-6 — apply `runGuarded` to the five unguarded workers.** Mechanical, and
   the doctrine is already written down.
8. **R-2 — move the MCP request deadline outside the retry loop** so the
   configured budget is the whole-request budget.

A standing recommendation: **add a lock-ordering check for `clusterRoleMu`.**
CHAOS-72 was a non-reentrancy bug hidden behind a conditional guard, which is
the shape static review misses and a test only catches if it sets up the
condition. The test added here pins the premise as well as the behavior, but a
broader "no snapshot build under `clusterRoleMu`" assertion would generalize.

---

## 9. Suggested PR — what this round actually changes

**Title:** `fix(cluster): HA promotion deadlock, DP→CP backoff ladder, unbounded peer map (CHAOS-71/72/73)`

**Changed scope** (3 source files, 3 new test files; no behavior outside the
cluster control/data plane):

- `main.go` — `enableControlPlane`: build the config snapshot *before* taking
  `clusterRoleMu`. Pure-read hoist; the idempotency guard and role transition
  stay atomic inside the write lock, and CHAOS-01's arm-before-publish ordering
  is preserved.
- `controlplane_client.go` — `backoff` no longer increments the streak (one
  writer) and jitters its delay; `failover` no longer clears the streak; the
  failover gate is re-crossed every `dpFailoverAfterFailures` instead of tested
  once; the ladder is extracted as a pure function; a one-time per-loop phase
  offset staggers all five CP-facing tickers (never the cold-start poll).
- `controlplane_server.go` + `connlimit_startup.go` — a sweep for
  `unenrolledConfigPull.attempts`, wired into the existing shared cleanup loop
  exactly as its sibling is (and the loop's doc comment brought back in sync
  with what it actually ticks).
- `CHANGELOG.md` — an `### Unreleased / Fixed` entry for all three.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` — the standing register's head gains a
  pointer to this round, and the **WK-13** row is re-stated as partially closed
  with its live remainder named, so the index stays accurate.

**Explicitly not in scope:** every §4 item. Four of the five DP loops' missing
backoff (R-1) is deliberately excluded despite being in the same file — see its
row for why.

---

## 10. Required tests — and what they pin

All three fixes have regression tests that **fail on the pre-fix revision**,
which was verified by re-introducing each defect individually.

**CHAOS-71** (`controlplane_client_cadence_chaos_test.go`, 13 tests):
the documented ladder as a pure function including its clamps; one streak
increment per failed poll; failover on the 3rd consecutive failure, not the 2nd;
a sustained outage converging on the ceiling with failover at the gate's cadence
rather than per poll; a **negative control** that a successful poll still clears
the streak (without which a "fix" that never cleared it would pass everything
else); jitter decorrelating 200 nodes while staying inside ±10% so it spreads
the ladder without reshaping it; the no-jitter fallback that every cadence
assertion depends on; the constructor actually installing jitter (the whole
property is one struct field from being silently absent); stagger bounded by
both `dpStartupStaggerMax` and the loop's own interval, and actually spread;
stagger and backoff both yielding to cancellation; the gossip loop disarming
when cancelled *during* the stagger; the cold-start poll never being staggered;
and the backoff log line reporting the real rung.

**CHAOS-72** (`cluster_promote_deadlock_chaos_test.go`, 3 tests): that
`buildCPAddressList` really does take `clusterRoleMu` — pinning the *premise*,
so a refactor cannot make the guards vacuous the way the original guard was;
that `enableControlPlane` reaches a decision rather than hanging while HA
reports Enabled; and that `clusterRoleMu` readers stay live afterwards, which is
the blast-radius property.

Two test-design notes worth carrying forward:

- The reproduction is deliberately performed from *another* goroutine. An
  earlier draft took the write lock and called `buildCPAddressList` on one
  goroutine; that goroutine can never be recovered, so it held a process-global
  lock for the rest of the test binary and poisoned the two tests after it. A
  chaos test must not inflict the outage it is describing on its own suite.
- The promotion test uses a well-formed address that cannot be served, so the
  call gets *past* the deadlock point (which precedes the listen) and then
  fails, binding no port and never setting the role. An empty address would
  have returned from the argument check before reaching the snapshot — it would
  have passed pre-fix and guarded nothing.

**CHAOS-73** (`controlplane_unenrolled_pull_janitor_chaos_test.go`): aged-out
entries swept, live entries retained, and the throttle's decision unchanged
across a sweep.

**Checks run for this change**, with results:

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet .` | pass (clean) |
| `go test -run 'TestChaos71\|TestChaos72\|TestChaos73' .` | pass, 19 tests |
| `go test -run 'TestCluster\|TestControlPlane\|TestDataPlane\|TestDP\|TestHA\|TestChaos0\|TestChaos5\|TestChaos6\|TestChaos7' .` | pass, 105s |
| `python3 docs/agent-context/check.py` | pass (static integrity) |
| Pre-fix regression check | each defect re-introduced individually; the matching tests fail, and the CHAOS-72 case wedges the test binary until its own timeout panic — the deadlock end to end |
| `golangci-lint run` | **could not run locally.** The pre-installed binary is 2.5.0 built with go1.25 and aborts with `package requires newer Go version go1.26`, identically on packages this change does not touch. CI's pinned action is the authority. |
| `go test -race -run 'TestChaos71\|TestChaos72\|TestChaos73' .` | pass, clean under `-race` |
| `go test .` (serial, whole root package, 468s) | 10 failures, **all pre-existing and environmental** — see below |
| `go test -race ./...` | **not run** |

The 10 full-suite failures are all IdP tests (`TestIdPRegistry_*`,
`TestAPIIdP*`) failing with `idp oidc issuer: URL must be https:// and must not
point to a private address`. Their fixture uses `https://example.com` and its
own comment states it relies on that host resolving to a public address so the
fail-closed DNS check in `validateExternalURL` passes. This sandbox has no
outbound DNS (`getent hosts example.com` returns nothing), so the guard
correctly refuses. **Confirmed not caused by this round:** the identical three
failures reproduce on the parent revision `77c0c58` in a clean worktree, and the
change touches no SSRF, URL-validation, IdP or auth code. They are an artefact
of the review environment, not a finding and not a regression.

Two gaps stated plainly: the full-module race-detector run was not executed
here, and local lint could not run at all for the toolchain reason above. The
Fast PR Gate, the hosted `golangci-lint` job and CodeQL for the PR's SHA are the
authority on both. A passing local check is not a passing merge gate.

**Tests this round did NOT write:** nothing in §4. Several of those would need
fault-injection harnesses that already exist in-tree (write-failure observers,
commit-between-renames injection) and would be worth building out per item.

---

## 11. Residual risk

**After the three fixes:**

- **The cold-start config poll is still a fleet-synchronized burst.** This is a
  deliberate trade, not an oversight: a node with no last-known-good snapshot
  enforces nothing until its first poll lands, so delaying it to smooth a
  one-time boot burst would trade a security property for load. Every
  *subsequent* poll is staggered. A fleet booting simultaneously still issues
  one simultaneous `GetConfig` each — tempered, but not eliminated, by the
  P0-3 unchanged-version sentinel.
- **There is no server-side admission control on DP→CP RPCs.** Only enrollment
  is rate-limited; `GetConfig`, `PushMetrics`, `SyncRateLimits`,
  `SyncRevocations` and `PushAuditEvents` are not. Client-side jitter reduces
  the herd but cannot bound it. A CP-side limiter is the structural answer and
  is a larger design change than a chaos round should make.
- **Jitter is ±10%**, matching `internal/feedsched` for consistency. It spreads a
  60s retry over 12s: a large improvement over exactly-simultaneous, but for a
  very large fleet a wider or full-jitter scheme would spread better. Widening
  it is a tuning decision with convergence-latency consequences on the 2s rung.
- **CHAOS-73 inherits its sibling's 5-minute sweep against a 1-minute window**,
  so bounded accumulation between sweeps remains. Pre-existing and reviewed.
- **CHAOS-72's invariant can be reintroduced** by any new caller that builds a
  config snapshot under `clusterRoleMu`. The test pins the premise, which makes
  the failure loud, but does not prevent a new caller.

**Standing, from §4:** the review's own highest residual risks are not the items
fixed here. They are L-1/L-5 (a control plane that exits on a bind failure or
dies silently afterwards), X-1/X-2/X-4 (unauthenticated amplification reachable
on a default configuration), L-2 (a fail-open admission window on SOCKS5), and
D-1 (a CP restart mid-CA-rotation locking out the fleet). Three of those four
are reported from delegated review and should be independently reproduced before
they are sized.

Finally, an honest note on **method**: this round's three fixes were found by
reading and then *running* the code — the ladder arithmetic and the deadlock
were both wrong in ways that inspection had already walked past more than once
in this file's history. The §4 backlog is wider but shallower precisely because
it was not executed. Reproduce before sizing.
