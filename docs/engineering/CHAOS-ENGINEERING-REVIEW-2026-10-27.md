# Chaos Engineering Review — 2026-10-27

## CHAOS-102 — The pre-posture accept window: what does a listener serve between `bind(2)` and the operator's posture?

**Scope.** Every listener the process opens, asked one question from the
SIMULATE list's *unexpected startup order* row: **between the moment its socket
is bound and the moment the operator's persisted admission posture is
installed, what does it serve?** The subject is the boot ORDER, not any one
subsystem, so the sweep covers all six listeners in the tree — the HTTP/HTTPS
proxy, SOCKS5, the admin UI, the CP gRPC server, the MCP gateway and the scan
sidecar.

**Origin.** The row the
[2026-10-18 sweep](CHAOS-ENGINEERING-REVIEW-2026-10-18.md) verified and left
open as *"REPORTED (verified, not fixed): SOCKS5 accepts before the admission
posture is restored"*, carried forward unchanged by the
[2026-10-26 sweep](CHAOS-ENGINEERING-REVIEW-2026-10-26.md) §11. That sweep
declined the fix for a specific and correct reason — the remedy it had in mind
changes startup ownership — and this sweep's contribution is a fix that does
not. The generalization from one listener to the class is what turned up the
negative half, which is the part worth keeping.

Id claimed in a committed register placeholder row as commit one, checked
against `origin/main` rather than the working tree, per
`roadmap/CHAOS-ENGINEERING-REVIEW.md` §0 and its 2026-09-25 amendment.

---

## 1. Executive Summary

**Of the six listeners in the process, exactly one is bound before the
operator's admission posture is installed, and it relays. The other five are
correct, and four of them are correct for the same reason — they start after
`initPersistentAdminState`. The primary data path already has the property that
the optional one lacked, which is what makes this a defect and not a posture.**

| Listener | Bound at | Posture installed at | Window |
|---|---|---|---|
| HTTP/HTTPS proxy | `runProxyUntilShutdown` (last stmt of `main`) | `initPersistentAdminState` | **none** |
| **SOCKS5** | **`initSOCKS5` (stmt 40)** | **`initPersistentAdminState` (stmt 41)** | **the whole of stmt 41** |
| Admin UI | `startAdminUI` (stmt 49) | — | none |
| MCP gateway | `initMCPRuntime` (stmt 43) | — | none |
| CP gRPC | `initCluster` (stmt 24) | n/a — mTLS + its own limiter | none (verified, §2.2) |
| Scan sidecar | `initScanning` (stmt 35) | n/a — reads no persisted posture | none (verified, §2.3) |

### The one that relays

`main.go` binds the optional SOCKS5 listener at `initSOCKS5` and restores the
GUI-persisted admission posture on the **next line**, at
`initPersistentAdminState` → `LoadAdminSettings` → `applyAdminSecurity`.
`startSOCKS5` deliberately blocks until the first `bind(2)` resolves and then
returns ([socks5_bind.go](../../socks5_bind.go) `startSOCKS5`), so the socket
is bound **and the accept loop is serving** while `main` is still on that next
line.

`handleSOCKS5` consults exactly three globals, and `applyAdminSecurity`
([admin_settings.go](../../admin_settings.go)) writes exactly those three:

| Gate | Pre-posture value | Effect |
|---|---|---|
| `ipf.Allowed` | mode `""` | admits **every** source IP (`internal/admission`: unconfigured allows) |
| `rl.AllowAuto` | unconfigured | no rate limit |
| `connLimiter.Acquire` | disabled | no per-IP connection cap |

With no `-ip-filter-mode` and no YAML `ip_filter_mode` — **the normal case when
the operator built the allowlist in the GUI** — `applyAdminSecurity` is the
only writer of all three, and it gates on `s.IPFilterMode != ""`. So a SOCKS5
client connecting in that window is admitted from **any** source IP,
unrate-limited, uncapped, and relayed to an arbitrary TCP destination. The
regression gate measures it directly: against the real listener with the real
handler and the owners in their pre-posture state, **the session negotiates**.

### The window is the storage volume's latency, and that is the point

`loadPersistentAdminState` does not reach `LoadAdminSettings` until it has run
`probeStorageWritability` (create + write + close + unlink a probe file),
`initConfigVersioning`, three store constructions, `globalAlertStore.Init`,
`loadHitCounters` + `RestoreHitCounts`, and a `saveHitCounters` — an atomic
write with an fsync of the file and its parent directory.

Measured on this container's volume:

| Step | Cost |
|---|---|
| `probeStorageWritability` | 34 µs |
| `saveHitCounters` (one fsynced atomic write) | **639 µs** |
| SOCKS5 sessions one client can complete, serially | **7,625/s** ≈ 7.6 per ms |

So on a healthy volume the window is ≈1 ms and admits a handful of sessions
from one client, more from many. The number that matters is the other one:
**every item in that prefix is I/O on `/data`**, the volume whose failure the
SIMULATE list names four separate ways — *disk full*, *disk read-only*, *slow
filesystem*, *permission denied*. An fsync latency of 1 s is an ordinary
degraded-disk symptom, not an exotic fault, and it makes this window ~1 s wide:
thousands of unfiltered sessions, and the *more* degraded the node, the
*longer* it relays. The worst case for this defect is reached by faults the
register already tracks under other ids.

It compounds with *mass reconnect storm*, also on the SIMULATE list. Every
SOCKS5 client in a fleet redials a restarted gateway at once, which is exactly
when the window is open.

### Why the fix is a gate and not a reorder

The 2026-10-18 sweep named the remedy — move `initSOCKS5` down beside
`startAdminUI` — and declined it, correctly. That changes when the bind is
attempted and therefore when SOCKS5 listener health is first reported, and
`AGENTS.md` is explicit that *"optional-listener failure must not become a new
primary data-plane termination path."* Reordering a boot sequence whose own
comment says the order is load-bearing, to fix a millisecond window, is a bad
trade.

A gate separates the two concerns. [socks5_posture_gate.go](../../socks5_posture_gate.go)
is armed by `initSOCKS5` immediately **before** `startSOCKS5` and released by
`loadPersistentAdminState` immediately **after** `LoadAdminSettings` returns.
The bind happens where it happened, `socks5ListenerState` reports it at the
same point in boot, startup ownership is untouched, and the single thing that
changes is that a connection arriving inside the window is refused instead of
relayed. **Prefer fail closed**, with the ordering property stated precisely:
armed strictly before the socket exists, released strictly after the restore
has run, so there is no interleaving in which the listener is accepting and the
gate is not armed.

### The two judgment calls, both recorded rather than assumed

**The zero value is open, and that is not fail-open.** An unarmed gate means
"no boot ever opened this window", not "the posture is unknown". The two
populations with an unarmed gate are the `socks5_port: 0` appliance (no
listener at all — nothing to refuse) and this package's ~1,500 test files,
which bind admission owners directly and never run `main`'s boot sequence.
Defaulting to CLOSED would make the gate's correctness depend on every test
remembering to release it, and **a gate that everything has to opt out of is a
gate that gets opted out of in production too.** The arm is one line, next to
the only statement in the tree that creates the window.

**The release is unconditional on the OUTCOME.** `LoadAdminSettings` has three
early returns that never reach `applyAdminSecurity` — file absent (first run),
file unreadable (EACCES/EIO), file present but corrupt (quarantined) — and in
each the admission posture stays at its compiled default for the life of the
process. Holding the listener closed for those would be tempting and wrong:
that outcome is pre-existing, deliberate, and already surfaced by **three**
independent surfaces (an explicit *"every GUI-saved admin setting is using its
default until the file is readable and the node is restarted"* log line, the
`state_file_corrupt` alert, and a `/readyz` fail row — the CHAOS-05/07
quarantine posture). This gate closes *"the restore has not run **yet**"*,
which is a race. It deliberately does not take on *"the restore ran and
failed"*, which is a posture decision for the owner. §10 carries it as residual
risk.

---

## 2. Failure scenarios

### BW-1 — SOCKS5 relays unfiltered between bind and posture install (MEDIUM) — **FIXED**

| | |
|---|---|
| **Current behavior (pre-fix)** | `initSOCKS5` binds and the accept loop serves; `handleSOCKS5` consults `ipf`/`rl`/`connLimiter`, all at compiled defaults, all admitting. Any source IP is relayed to an arbitrary TCP destination. |
| **Expected behavior** | A listener does not enforce a posture it does not have. Refuse until it does. |
| **Failure mode** | Unfiltered, unrate-limited, uncapped admit on the SOCKS5 data path. Not a crash — a silent authorization bypass. |
| **Trigger** | Every boot of a node with `socks5_port > 0`. No fault required. |
| **Window** | The `initPersistentAdminState` prefix: ≈1 ms measured on a healthy volume (639 µs of it one fsync), ~1 s on a volume with 1 s fsync latency. Admits ~7.6 sessions/ms serially. |
| **Automatic recovery** | Yes — the window closes when `applyAdminSecurity` runs. The exposure is bounded, not persistent. |
| **Customer impact** | An off-allowlist client reaching the internet through the gateway, for the length of the window, with no record that the allowlist was not consulted. |
| **Security impact** | The IP filter is the FIRST admission gate of an inline security gateway. Reduced by SOCKS5 being opt-in (`socks5_port: 0` default) and by the window being short on a healthy node; raised by the window widening exactly as the node degrades. |
| **Monitoring visibility (pre-fix)** | **None.** `recordRequest` logged the session as an ordinary SOCKS5 request. Nothing distinguished "admitted by the allowlist" from "admitted because there was no allowlist yet". |
| **Fix** | `socks5PostureHeld()` checked first in `handleSOCKS5` — before `connLimiter`, because `connLimiter` is itself one of the uninstalled globals. Refuse, count, record `NOT_READY`. |

### BW-2 — The refusal had no surface (LOW, observability) — **FIXED**

A window that refuses connections and says nothing is the ST-8 / RT-1 shape in
a third place. The window is milliseconds on a healthy volume, so by the time
anyone asks, the log line that reported it has rotated — `fileutil.RotatingFile`
is capped at 50 MB with one archive, and CHAOS-54 measured this same accept loop
overwriting the entire retained history in a couple of seconds. The counter, not
the line, is the durable evidence.

Added:

- `culvert_socks5_posture_refused_total` — cumulative, survives the release.
- `culvert_socks5_posture_pending` — 1 while the window is open; what a scrape
  taken *during* a slow boot shows.
- One log line per boot naming the missing gates and pointing at the counter;
  one summary line at release, **only if** something was refused.

Both series are emitted only when `sk.Configured`, the documented
socks5/cluster_ca gauge precedent: `posture_pending 0` on a node that never had
SOCKS5 is indistinguishable from a healthy one and the paging rule is `== 1`.

### BW-3 — CP gRPC binds 17 statements earlier and is fine (verified, no change)

`initCluster` (stmt 24) binds the CP gRPC listener — the earliest listener in
the process, 17 statements before the posture restore. It has no window:
`grep` over `cp_grpc*.go` and `controlplane_server.go` finds **no** reference to
`ipf`, `rl.Allow*` or `connLimiter`. Its admission is mTLS against the cluster
CA (installed inside `initCluster` itself, before the bind) plus
`enrollRateLimit`, whose limits are compiled-in constants and not operator-
persisted. Different trust boundary, self-contained, correct.

### BW-4 — The scan sidecar binds early and is fine (verified, no change)

`initScanning` (stmt 35) binds the scan sidecar
([scanning_startup.go](../../scanning_startup.go) `startScanServiceSidecar`),
also before the posture restore. It has no window either, for a narrower
reason: its only size-relevant input is `maxScanBufferBytes()`, which reads
`dpiScanner`/`globalSecScanner` — both configured by `initSSLBypassAndDPI` and
`initScanning`, **before** the bind — and `admin_settings.go` never writes
either. Checked because CHAOS-101 is a finding about this exact sidecar's
buffer window and a posture window on top of it would have compounded; it does
not exist.

### BW-5 — The primary data path's absence of a window is load-bearing, and now walled

`buildAndStartProxyServer` only *constructs* the server; the listener is opened
by `runProxyUntilShutdown`'s `ListenAndServe`, the last statement of `main`.
That asymmetry is the whole argument that BW-1 is a defect — and nothing
enforced it. A refactor that moved the bind into `buildAndStartProxyServer`
would give the **primary** HTTP/HTTPS plane the same window on a far larger
blast radius, silently. §9's `TestCHAOS102_Wall_PrimaryDataPathHasNoPrePostureWindow`
is where that now fails.

---

## 3. Risk matrix

| Id | Scenario | Likelihood | Customer | Security | Data integrity | Auto recovery | Visibility (pre-fix) | Status |
|---|---|---|---|---|---|---|---|---|
| BW-1 | SOCKS5 relays unfiltered in the boot window | Every boot with SOCKS5 on (opt-in) | Low–Med | **Medium** (unfiltered admit, first gate bypassed) | None | Yes (ms–s) | **None** | **FIXED** |
| BW-2 | The refusal/window has no counter, gauge or line | Follows BW-1 | Low | Low | None | n/a | **None** | **FIXED** |
| BW-3 | CP gRPC pre-posture window | — | — | — | — | — | — | **No window (verified)** |
| BW-4 | Scan sidecar pre-posture window | — | — | — | — | — | — | **No window (verified)** |
| BW-5 | A future bind moves into `buildAndStartProxyServer` | Low | **High** | **High** | None | Yes | None | **Walled** |
| BW-6 | A corrupt/unreadable settings file leaves the posture at defaults permanently | Low | Med | **Medium** | None | No (restart) | **3 surfaces** | **Pre-existing, reported (§11)** |
| BW-7 | A DP node's CP-pushed admission posture is clobbered at boot by local/GUI posture | Med on DP nodes | Low | Med | None | No (`config_unchanged`) | Partial | **Reported (§11)** |

---

## 4. Recovery assessment

- **Automatic.** BW-1 self-heals at `applyAdminSecurity`, which is why it is a
  window and not an outage. The fix does not change that; it changes what is
  served inside it. The gate is released by the same statement that installs
  the posture, so recovery is the same event it always was.
- **Deterministic.** The gate is two atomic stores on one word, in a fixed
  order, from `main`'s single-threaded boot path. There is no retry, no timer,
  no backoff and nothing to tune — so there is no new broken-backoff or
  hidden-retry surface. The release is idempotent and a release without an arm
  is a no-op (the `socks5_port: 0` appliance), both pinned by
  `TestCHAOS102_GateLifecycleIsIdempotent`.
- **No manual step** is introduced. A node whose window refused connections
  needs nothing done to it; the clients reconnect, and the counter records what
  happened.
- **Explicit ownership.** The arm sits in `initSOCKS5` — the only statement
  that creates the window — and the release in `loadPersistentAdminState`, the
  function whose doc comment already owns the probe → versioning → stores →
  admin-settings-LAST ordering contract. Neither is a new owner.
- **The one unrecoverable path is unchanged by design**: a gate armed and never
  released would be a permanently dead listener. `TestCHAOS102_Wall_ThePostureRestoreReleasesTheGate`
  is the gate on the gate — it fails if the release is deleted *or* moved
  before the `LoadAdminSettings` call it must follow.

---

## 5. Operational impact

- **Steady state: nothing.** One `atomic.Bool` load, first in `handleSOCKS5`,
  on a word written at most twice in the life of the process and therefore
  resident in every core's cache. Zero allocations, pinned by
  `TestCHAOS102_ReleasedGateIsOneAtomicLoad`.
- **During the window**, a client sees its connection closed before the
  method-selection reply instead of being relayed. That is the same shape the
  handler already uses for `IP_BLOCKED` and `RATE_LIMITED` — close without a
  reply — so no new client-visible protocol behavior is introduced. SOCKS5
  clients retry; the window is ms.
- **Two new `/metrics` series**, both inside the existing
  `if sk := socks5ListenerState(); sk.Configured` block, so the ordinary
  appliance's scrape is byte-for-byte unchanged.
- **At most two new log lines per boot**, and zero on a healthy boot that
  refused nothing — "the window closed with no connections in it" is the
  expected outcome and logging it would train operators to read past the line
  that matters.
- **No new operator setting**, so the GUI/API parity rule in
  `docs/agent-context/conventions.md` does not attach: there is no admin API
  endpoint, `uiRoutes` entry or UI surface to add. A counter and a gauge are
  not configuration.
- **Alerting.** No new alert. `socks5_listener_down` is the listener's alert and
  this is not the listener being down. A ms-wide window that self-heals is a
  counter to scrape, not a page to send; if an operator wants one, the gauge
  and the counter are both there and the paging rule is the documented `== 1`.

---

## 6. Security impact

- **The fix closes an authorization bypass**, narrow in time and gated behind
  an opt-in listener, on the first admission gate of an inline security
  gateway. The posture it restores is the operator's own allowlist — the thing
  a Secure Web Gateway exists to apply.
- **Fail closed, in the direction the project's rules name.** The refusal costs
  a client a retry; the admit costs the operator their perimeter. The
  asymmetry is not close.
- **No new trust boundary, no new parser, no new network path.** The gate reads
  one bool and the handler closes a socket. The refusal's log line is the one
  place client-controlled data enters, and it goes through `sanitizeLog` + `%q`
  per CWE-117 — pinned by an assertion on the quoted form, in the same test
  file, alongside this listener's existing log-injection suite.
- **The window was invisible**, which is the worse half. Pre-fix, a session
  admitted because there was no allowlist yet was recorded by `recordRequest`
  as an ordinary SOCKS5 request, indistinguishable from one the allowlist
  approved. The audit trail did not lie, exactly — it recorded the session
  truthfully — but nothing anywhere said the gate had not been consulted.
- **Not changed, deliberately**: the posture on a corrupt or unreadable
  settings file (BW-6). That is a fail-open outcome, it is loudly surfaced, and
  turning it into a listener outage is the owner's call, not a rider on a race
  fix. §11.

---

## 7. Data-integrity impact

None. The gate writes no file, takes no lock held by anything else, and
persists nothing. It adds two atomic stores to the boot path and one atomic
load to the SOCKS5 request path. No wire format, no persisted schema, no audit
record and no config version is touched, so there is nothing here to be
corrupted by a crash, a power loss or a rollback — and `saveConfigVersion` is
correctly not involved, because nothing configurable changed.

---

## 8. What shipped

| File | Change |
|---|---|
| [socks5_posture_gate.go](../../socks5_posture_gate.go) | **New.** The gate: arm / release / held / count, the refusal line, and the test reset. Carries the full argument for why a gate rather than a reorder, why the zero value is open, and why the release is unconditional. |
| [socks5.go](../../socks5.go) | `handleSOCKS5` refuses, counts and records `NOT_READY` when the gate is held — checked FIRST, before `connLimiter`. The IP-filter + rate-limit pair is extracted to `socks5SourceDenied` to hold the function's complexity at its pre-change measurement (§8.1). |
| [main.go](../../main.go) | `initSOCKS5` arms the gate before `startSOCKS5`. |
| [persistent_admin_state_startup.go](../../persistent_admin_state_startup.go) | `loadPersistentAdminState` releases the gate after `LoadAdminSettings`. |
| [metrics.go](../../metrics.go) | `culvert_socks5_posture_pending` + `culvert_socks5_posture_refused_total`, inside the existing `sk.Configured` block. |
| [socks5_posture_gate_chaos_test.go](../../socks5_posture_gate_chaos_test.go) | **New.** 10 gates — §9. |

### 8.1 The lint measurement the gate convention exists for

`docs/agent-context/conventions.md` warns that `cyclop`, `funlen` and
`gocognit` attribute to a function's DECLARATION line, so
`--new-from-rev` **cannot** see a function a change made more complex, and asks
for a full-tree pass compared against the same measurement on the base. That
is not a formality here — it caught two real regressions in this change that
the gate's own `--new-from-rev` command reported as `0 issues`:

| Function | Base | With the naive change | Shipped |
|---|---|---|---|
| `handleSOCKS5` | `funlen` 72 > 50 | **`cyclop` 16 > 15 — a NEW finding** | `funlen` 72 > 50 (identical) |
| `handleMetrics` | `gocognit` 45 | **`gocognit` 47** | `gocognit` 45 (identical) |

`handleSOCKS5` sat exactly ON the cyclop threshold, so one `if` crossed it.
The fix is the one the conventions ask for — a coherent helper, not a
suppression: `socks5SourceDenied` takes the two gates keyed on the **source
address**, which compose as a predicate because neither needs per-connection
cleanup.

Two things about that extraction are load-bearing and were nearly got wrong:

- **The connection limit stays in `handleSOCKS5`.** It hands back a slot whose
  `Release` is deferred for the tunnel's whole lifetime, so it cannot move into
  a predicate.
- **The pair stays exactly where it was, AFTER the connection limit.** The
  first draft hoisted `ipf`/`rl` above `connLimiter.Acquire`, which reads as a
  harmless reordering and is not: **`rl.AllowAuto` COUNTS the attempt**, so a
  connection the connection limiter refuses would have begun consuming a
  rate-limit token it never consumed before. Only the new posture gate is
  inserted; the relative order and side-effect sequence of the three
  pre-existing gates is byte-for-byte what it was.

`handleMetrics` was over its threshold already, so the gauge's `if` moved out
of the scrape site into `socks5PosturePendingGauge()`, which returns the
rendered 0/1. The scrape site is a plain format argument and the function's
measurement is unchanged.

### What was deliberately NOT done

- **`initSOCKS5` was not moved.** §1. It would change startup ownership and
  when listener health is first reported, against an explicit `AGENTS.md` rule,
  to fix a millisecond window.
- **No `/readyz` row and no `/api/diagnostics` row.** Both would be
  permanently green from the first scrape of a running node onward, because
  the window is over before anything can poll them — a row that can only ever
  report "fine" trains operators to skip it. The counter is the honest surface
  for a condition that is already in the past by the time anyone looks, and the
  gauge covers the live case.
- **No general "boot posture" latch for the whole process.** Tempting, and
  wrong at this scope: four of the six listeners are correct because of where
  they sit in `main`, which is a stronger guarantee than a flag they would have
  to remember to read. The wall in §9 pins that ordering instead.
- **`LoadAdminSettings`'s three failure returns were not re-posture'd.** §1,
  §11.

---

## 9. Required tests

All in `socks5_posture_gate_chaos_test.go`. Every one of them was run against
the pre-fix code with the fix surgically removed (the handler check and the
arm), and the three that must fail, do — reproduced below.

| Gate | What it pins |
|---|---|
| `TestCHAOS102_PrePostureWindow_RefusedWhenHeld_AdmittedWhenReleased` | **The differential oracle.** Same listener, same unconfigured owners, gate the only variable: released ⇒ negotiates (the pre-fix behavior, measured), held ⇒ refused, released again ⇒ serves without a rebind. |
| `TestCHAOS102_RefusalsAreCountedAndTheFirstIsLogged` | 4 refusals ⇒ count 4, exactly ONE log line, the line names the missing gates and the counter, and the client address is `%q`-quoted (CWE-117). |
| `TestCHAOS102_ReleaseOnAQuietBootSaysNothing` | A healthy boot logs nothing. |
| `TestCHAOS102_GateLifecycleIsIdempotent` | Double arm, double release, release-without-arm (the `socks5_port: 0` appliance), the count surviving the release, and the summary emitted once — by the release that held the gate, not the second one. |
| `TestCHAOS102_MetricsExposeTheWindow` | `posture_pending 1` while held, `0` after, `refused_total` cumulative across the release, both only when `sk.Configured`. |
| `TestCHAOS102_Wall_NoListenerServesBeforeThePostureIsClosed` | **The regression wall**, written to accept EITHER remedy: passes if `initPersistentAdminState` precedes `initSOCKS5` (the reorder) OR if `initSOCKS5` arms the gate (shipped). Fails only on a boot where the listener serves and nothing closes the window — the exact pre-fix state. |
| `TestCHAOS102_Wall_ThePostureRestoreReleasesTheGate` | The gate on the gate: the release exists AND follows `LoadAdminSettings`. A release moved earlier reopens the window; a release deleted kills the listener forever. |
| `TestCHAOS102_Wall_NegativeControls` | Four synthetic boot shapes + two arm-detection shapes, proving the wall's own AST helpers can FAIL. Without these an always-passing wall would report the defect fixed forever. |
| `TestCHAOS102_Wall_PrimaryDataPathHasNoPrePostureWindow` | BW-5: `buildAndStartProxyServer` must not listen, and the proxy/admin-UI/run-until-shutdown statements must stay after the posture restore. |
| `TestCHAOS102_ReleasedGateIsOneAtomicLoad` | Zero allocations on the steady-state path, which is what makes §5's cost claim checkable rather than asserted. |

The pre-existing `IP_BLOCKED` / `RATE_LIMITED` / `CONN_LIMITED` behavior moved
into `socks5SourceDenied` is covered by the suites that already owned it —
`socks5_connlimit_test.go` (CHAOS-02), `socks5_test.go`,
`controlplane_snapshot_ipf_race_test.go` (RISK-030) and
`controlplane_admission_ownership_test.go` — all re-run under `-race` after the
extraction, which is what makes "the gate order is unchanged" a verified claim
rather than a reading of the diff.

### Pre-fix run (the fix removed, nothing else changed)

```
--- FAIL: TestCHAOS102_PrePostureWindow_RefusedWhenHeld_AdmittedWhenReleased
    CHAOS-102: a SOCKS5 session negotiated while the persisted admission posture
    was still pending — the gateway is relaying unfiltered in the boot window
--- FAIL: TestCHAOS102_RefusalsAreCountedAndTheFirstIsLogged
--- FAIL: TestCHAOS102_Wall_NoListenerServesBeforeThePostureIsClosed
    CHAOS-102 regression: main() calls initSOCKS5 (stmt 40) BEFORE
    initPersistentAdminState (stmt 41) and initSOCKS5 no longer arms the
    pre-posture gate. [...] Either arm the gate again or move initSOCKS5 after
    initPersistentAdminState
```

The other seven pass pre-fix, correctly: they pin the gate's own mechanics and
the listeners that never had a window, none of which the fix's removal changes.

### The premise is asserted, not assumed

The oracle opens by asserting that an unconfigured `ipf` admits and an
unconfigured `rl` admits, and `t.Fatal`s with *"premise gone … re-derive the
finding before relaxing this gate"* if either stops being true. If a future
change to `internal/admission` made an unconfigured filter deny by default,
BW-1 would be gone and this sweep's whole argument with it — and that should
fail loudly rather than pass quietly, which is the failure mode an
always-passing wall has.

### Test hygiene

`armPostureGateForTest` registers `resetSOCKS5PostureGateForTest` through
`t.Cleanup` before arming, per the conventions' global-test-cleanup rule
(`setupProxyTest` resets at test START and restores nothing afterwards). The
logger capture is registered **before** `startSOCKS5Listener` because
`t.Cleanup` is LIFO and the listener's cleanup drains in-flight handlers — the
reverse order is a real `-race` failure, as `socks5_log_injection_test.go`
already records. Asserted on unique content, never on counts of shared state.

---

## 10. Residual risk

- **The window is closed, not eliminated.** A connection arriving in it is
  still refused rather than served, so a client that happens to dial during a
  restart on a badly degraded volume sees a failure instead of a (wrongly)
  successful session. That is the intended trade and the honest one: the
  alternative is relaying it unfiltered.
- **The gate does not cover a posture restore that RAN AND FAILED** (BW-6,
  §11). Deliberate, argued in §1 and in the file's doc comment: that condition
  is permanent rather than racy, already surfaced three ways, and turning it
  into a listener outage is a posture change for the owner.
- **The zero value is open.** An unarmed gate admits, which is correct for the
  `socks5_port: 0` appliance and for every test, and would be wrong if a future
  second bind site forgot to arm. The wall in §9 covers the one that exists
  today; a new SOCKS5 bind site would need a new arm, which is why the arm sits
  on the line immediately above `startSOCKS5` rather than somewhere general.
- **`recordRequest` is still called for a refused connection.** Intentional —
  it is how `IP_BLOCKED` and `RATE_LIMITED` behave, and the record is the only
  per-connection trace of the window — so a reconnect storm inside a long
  window writes one history entry per refused connection. That is the same
  bounded ring every other action string writes into, at a rate the pre-fix
  code already paid for the sessions it admitted, so there is no new growth
  path; it is simply not a NEW surface either.
- **One log line per boot is a per-BOOT budget, not per-window.** A process
  that crash-loops logs one line per boot, which is the right magnitude, and
  the counter resets with the process. A crash-loop's evidence is the restart
  count, not this line.
- **The measurements are this container's volume.** 639 µs for a fsynced
  atomic write is a healthy number; the operational claim that matters (the
  window widens exactly as the volume degrades) follows from the prefix being
  I/O, not from that constant. An appliance on a contended datastore should be
  expected to be much worse, and the gauge is what shows it.

---

## 10a. Verification

Run at this change's tree, with the compiler from `go.mod`'s `toolchain`
(go1.27.3) and the linter version `pr-fast-gate.yml` installs (v2.15.0), built
with that toolchain:

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet .` | clean |
| `go test -count=1 .` (full root package) | **ok, 588 s** |
| `go test -race -count=1 -run 'CHAOS102\|SOCKS5\|socks5\|RISK030\|Admission\|IPFilter\|RateLimit' .` | **ok, 75 s** |
| `go test -count=2 -shuffle=on -run 'CHAOS102\|SOCKS5\|socks5' .` | ok |
| `golangci-lint run --timeout=10m --new-from-rev origin/main` (the gate's own command) | **0 issues** |
| `golangci-lint run ./...` full tree, diffed against the same measurement on `origin/main` | **174 issues both sides; no finding names a function this change touches** (§8.1) |
| `python3 docs/agent-context/check.py` | clean |
| `python3 docs/agent-context/check.py --diff-base origin/main` | clean, 0 changed guidance paths |
| Pre-fix differential run (fix surgically removed) | **3 gates fail with the defect's own message** (§9) |

**Not run, and why.** `go test ./internal/...` — this change touches only
package main and adds no internal dependency; `golangci-lint run ./...`
compiled every package in the module, which covers the build half. The
hosted aggregate CI for this exact SHA has not run: a passing local check is
not a passing merge gate.

## 11. Reported, not fixed

- **BW-6 — a corrupt or unreadable `admin_settings.json` leaves the admission
  posture at its compiled default for the life of the process.**
  `LoadAdminSettings`'s three early returns — absent (first run, correct),
  unreadable (EACCES/EIO), corrupt (quarantined) — never reach
  `applyAdminSecurity`, so `ipf` mode stays `""` and admits every address until
  the file is fixed and the node restarted. This is **fail-open on the first
  admission gate**, and unlike BW-1 it is not a window — it is the whole
  process lifetime. It is *not* a silent failure: the read-error path logs
  "every GUI-saved admin setting is using its default until the file is
  readable and the node is restarted", the corrupt path fires
  `state_file_corrupt` and records a `/readyz` fail row, and
  `noteResidualQuarantine` re-surfaces it on later boots. Left unchanged
  because making it fail closed is a posture decision with a real cost (a
  gateway that stops serving on a damaged state file), the existing posture is
  deliberate and documented (CHAOS-05/07), and a race fix is not the occasion
  to change it. **Owner decision.**
- **BW-7 — a DP node's CP-pushed admission posture is clobbered at boot.**
  `initCluster` (stmt 24) → `startDataPlane` → `applyDPLastGoodConfigSnapshot`
  → `applySnapshotAdmission` installs the CP's posture via `ipf.Replace`. Then
  `initConnAndRateLimit` (stmt 25) re-applies local YAML/flag posture with
  `SetMode` + `AddAll` when `ip_filter_mode` is set, and `applyAdminSecurity`
  (stmt 41) re-applies the node-local GUI-persisted posture on top — so the
  node enforces local posture over the CP's, and because the CP's
  `config_unchanged` sentinel means an unchanged config version is not
  re-applied, **it never self-heals.** This is the admission half of the shape
  the 2026-10-18 sweep registered as the open half of CHAOS-18 (which recorded
  only the *default policy action*); verified here as the same defect in the
  same boot order for `ipf`/`rl`. Not fixed: which source wins on a DP node is
  a precedence decision across `docs/agent-context/errata.md`'s "explicit
  configuration wins" and the CP's authority over enrolled nodes, and it is the
  same owner decision CHAOS-18's open half is already waiting on. **Verified,
  attributed, open.**
- **Feed clients still dial without `ssrf.SafeDialContext`**, and **the open
  half of CHAOS-18**, carried forward unchanged from the 2026-10-26 sweep §11.
  Neither is a boot-order defect; neither is in scope here.
