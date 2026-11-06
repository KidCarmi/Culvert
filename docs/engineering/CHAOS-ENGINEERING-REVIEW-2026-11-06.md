# Chaos Engineering Review — 2026-11-06

## CHAOS-112 — The per-IP connection limiter's configuration plane: a cap nobody configured, that nothing reports

**Date:** 2026-11-06
**Branch:** `claude/serene-cerf-it754q`
**Baseline:** `origin/main` **b05d649** (freshly fetched; `CHAOS-111` is the
highest id anywhere on main, and no open PR held a chaos id at claim time —
#1815, #1814, #1705, #1549, #1548, #1536, #1528, #1526).
**Id allocation:** `CHAOS-112` claimed in a committed placeholder row in
[the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) as commit one, before
any code was written, per that file's own convention and the 2026-09-25
amendment.
**Method:** evidence-first source review across four parallel bounded
investigations (per-IP connection accounting, the account-lockout plane, audit
durability, the live-event plane), every claim then re-traced at the source by
the author before it was acted on. The behavioural numbers in §9 were measured
against the real production functions on a build of this tree; the mutation
runs in §9.6 were applied to the fixed tree and each one's verdict recorded.

---

## 1. Executive summary

`conn_limit_enabled` is the one admission surface this repository's own
config-surface registry declares **not** cluster-synced. `conn_limit_max_per_ip`
beside it **is** cluster-synced. The Data Plane had exactly one primitive for
applying either — `ConnLimiter.Enable` — and it writes **both**.

So every Data Plane that applied any configuration snapshot turned per-source-IP
connection limiting **on**, at whatever cap the field carried, whether or not
its operator had ever configured it. Measured through the real publisher and the
real apply:

| | |
|---|---|
| A Control Plane whose operator never configured the limiter publishes | `max_conns_per_ip=1024` |
| The pre-fix apply left that Data Plane at | `Enabled()=true`, cap **1024** |
| The operator then turns the limiter **off** on the Control Plane; the DP applies again | `Enabled()=true`, cap **50** |

That last row is the sharpest one. The operator's *disable* reached the fleet as
**"tighten the cap to 50 and stay on"**, because `Disable` clears only the flag
and keeps the cap, and the publisher reads the cap. There is no `Disable()` on
any CP→DP path at all, so the intended remedy could not be expressed.

**The field cannot be read as an enablement signal either, and that is the root
cause rather than a detail.** `ConnLimiter.MaxPerIP()` answers with a cap while
limiting is off — correctly, so that an operator's configured value survives an
off/on cycle and `GET /api/connlimit` renders it rather than a misleading `0` —
so the publisher `snap.MaxConnsPerIP = connLimiter.MaxPerIP()` **can never emit
zero.** The registry records this binding's empty-value semantics as
`semSkipIfZero`, "zero value keeps live state". That guard is unreachable by
construction: no real publisher can take it.

**The second half is what let the first run on a live fleet.** The per-IP
connection-limit refusal in `handleRequest` was a bare `http.Error` and a
`return`:

- no request-history row,
- no `statBlocked`,
- no log line,
- nothing in `/metrics`, `/healthz` or any alert.

It is the **only** front-door gate in that function with no per-event
observability. The IP filter and the rate limiter immediately below it each
write a row *and* a line; its own SOCKS5 twin — whose comment claims symmetry
with this very path — writes both. Measured over 200 refusals: `statBlocked`
delta **0**, `CONN_LIMITED` rows **0**, log lines **0**.

A node refusing traffic over a cap nobody configured therefore produced a bare
`503` that appeared nowhere, and the only way to discover the cap existed was to
poll that one node's viewer-gated `GET /api/connlimit` and notice it contradicted
the Control Plane. The direction of the enforcement error is fail-**closed**,
which is exactly why it survived: nothing was insecure, so nothing complained.

### The precedent that was recorded and not applied

`config_surfaces.go` exists *because* apply-path empty-value semantics drift —
its own type doc says so: *"This is the axis that actually drifts — diffConfigs
must mirror applyConfigBackup's nil-guards or dry-run rollback lies to the
operator."* The registry correctly recorded that `conn_limit_enabled` is not
cluster-synced and that the cap's apply is `semSkipIfZero`. Both records are
accurate statements of intent, and neither was true of the code. The registry is
a description, not an enforcement mechanism, and this is the first instance
where a row's `Apply` semantics were **unreachable** rather than merely
mismatched.

### Rider: a separate security defect, a separate domain

The same sweep's lockout-plane investigation found an unrelated and more serious
defect, fixed here as a clearly separated rider (§3, RD-1): the public login
endpoint's first-run bootstrap branch minted a **tier-2 trusted-IP bypass
grant** from a login it had not verified. §8.6 explains why it rides along
rather than waiting for its own round.

---

## 2. Failure scenarios

### 2.1 `Configuration corruption` / `Control Plane unavailable` — enforcement the operator did not ask for

**Trigger.** A Data Plane enrols and applies its first snapshot. No fault
required, no attacker, no unusual configuration: this is the normal path on
every clustered deployment, and the per-IP connection limiter ships **disabled**
(register row `PX-6`), so "nobody configured it" is the default state.

| | |
| --- | --- |
| **Current behavior (pre-fix)** | `if snap.MaxConnsPerIP > 0 { connLimiter.Enable(snap.MaxConnsPerIP) }`. The field is always non-zero because `MaxPerIP()` always answers with a cap. `Enable` writes the cap **and** the enabled flag. |
| **Expected behavior** | The snapshot carries a cluster-synced **cap**; enablement is node-local, as the registry records. Applying the cap must not move the flag in either direction. |
| **Failure mode** | Silent enforcement divergence between the Control Plane's own state and every Data Plane's. The CP's `GET /api/connlimit` reports `enabled:false`; every DP reports `enabled:true`. |
| **Recovery path** | None through the intended surface. No CP→DP path calls `Disable`, and the operator's disable publishes the retained cap, which the pre-fix apply read as "stay on, tighter". The only remedies were a per-node admin API call or a restart. |
| **Customer impact** | One large NAT egress, a CI fleet behind one address, or a load generator past the cap receives `503 Too Many Connections`. On the default cap that is 1024 concurrent in-flight requests from one source address. |
| **Security impact** | None directly — the error is fail-closed. The impact is on the operator's model of what the fleet enforces, which is a security property in its own right: a control nobody configured is a control nobody is monitoring. |
| **Monitoring visibility** | Zero, by §2.3. |

### 2.2 `Configuration rollback` — the disable that arrives as a tightening

Worth separating, because it is not the same bug reported twice. An operator who
*had* configured the limiter at 50, decided it was wrong, and turned it off on
the Control Plane published `max_conns_per_ip=50` from a limiter whose flag was
now clear. The pre-fix apply enabled every Data Plane at **50** — tighter than
the 1024 they had been running — in direct response to the action intended to
remove the cap. Measured; the row is in §1 and the raw output in §9.2.

This is the shape that would reach a support ticket as *"we turned the
connection limit off and our egress got worse"*, with the CP's own panel
agreeing that the limiter is off.

### 2.3 `Silent failures` — the one gate that wrote nothing

**Trigger.** Any refusal over the per-IP cap on the HTTP/CONNECT path.

| | |
| --- | --- |
| **Current behavior (pre-fix)** | `http.Error(w, "Too Many Connections", 503); return`. The limiter's internal `rejected` counter advanced, reachable only as a process-lifetime, **unattributed** `rejectedTotal` on the viewer-gated `GET /api/connlimit`. |
| **Expected behavior** | The treatment its two neighbours and its SOCKS5 twin already have: an attributed request-history row, the blocked counter, and a narrative log line. |
| **Failure mode** | A firing admission gate with no telemetry. No metric existed, so no alert rule could be written — the `PX-18` shape, one subsystem over. No attribution existed, so an operator could see that *something* was capped but not *which source*. The affected client's `503` appeared in no request history, so a support ticket had no server-side correlate. |
| **Operational impact** | This is the half that made §2.1 survivable for as long as it did. |
| **Monitoring visibility** | None. `/metrics` carried nothing about this limiter at all — not its refusals, not its cap, not whether it was enabled. |

### 2.4 Already-correct behaviour, and why

Recorded so a later round does not "fix" them. Each was traced at the source
during this sweep.

- **The slot discipline itself is clean.** Both production `Acquire` call sites
  put the `defer Release` on the next statement, with nothing between that can
  return or panic, and the panic guard is registered *before* it so LIFO runs
  the release first during unwinding. Every terminal branch of a tunnel blocks
  inside the handler (`bidiRelayCounted` joins both relay goroutines;
  `http2.Server.ServeConn` blocks for the tunnel's life; `socks5Relay` joins
  both directions), so the per-request slot really does cover a tunnel's
  lifetime, bounded at worst by `tunnelIdleTimeout`'s hard close. No leak and no
  permanent per-IP denial exists on any path examined.
- **`Release` cannot underflow.** It is presence-guarded and deletes at `n <= 1`
  rather than decrementing, so no negative value is representable, and the
  reject path never commits a count at all so a refusal leaves no residue.
  Pinned by `TestRelease_StrayReleaseIsASafeNoOp` and
  `TestAcquire_RepeatedRejectionLeavesNoResidue`.
- **`Disable` keeping the cap is right.** It is the reason `MaxPerIP()` can
  never answer zero, which is the root cause above — but the alternative is
  worse: an operator who toggles limiting off and on would lose their configured
  value, and `GET /api/connlimit` would render `0` for a cap that is merely
  dormant. The defect was never that the cap persists; it was inferring
  enablement from it. Pinned deliberately by
  `TestCHAOS112_DisablePreservesTheConfiguredCap`, which fails if a later change
  makes `MaxPerIP` report zero while disabled — at which point the publisher,
  the apply, the admin API's rendering and the admin-settings round-trip all
  have to be revisited together.
- **`semSkipIfZero` is the right recorded semantics and stays.** The finding is
  that no publisher could reach it, not that zero should start meaning something
  new. An older Control Plane, or a snapshot with the field absent, must still
  leave a node's cap alone — gated by `TestCHAOS112_ControlZeroCapKeepsLiveState`
  and `TestCHAOS112_SetMaxPerIPIgnoresANonPositiveCap`.
- **MCP is a separate owner, not a parity gap.** The gateway binds its own
  listener and enforces per-session fairness through its own session manager;
  root `AGENTS.md` is explicit that MCP listener fairness is not the core IP
  limiter.

---

## 3. Risk matrix

| ID | Finding | Severity | Status | Evidence |
|---|---|---|---|---|
| CL-1 | CP→DP snapshot apply **enables** per-IP connection limiting on every Data Plane at the default cap, on a fleet where nobody configured it; `conn_limit_enabled` is declared node-local and the apply wrote it | **HIGH** | **FIXED** — `SetMaxPerIP`, cap-only apply | `controlplane_snapshot.go`, `internal/connlimit/connlimit.go`; §9.2 |
| CL-2 | A Control-Plane **disable can never propagate**, and arrives as a *tightening*: the publisher emits the retained cap and no CP→DP path calls `Disable` | **HIGH** | **FIXED at the cause** (the apply no longer enables, so there is nothing to un-propagate). Whether enablement *should* be cluster-synced is an owner decision — §8.1 | `controlplane_snapshot.go`; §9.2 |
| CL-3 | `MaxPerIP()` can never return 0, so the wire field cannot signal "off" and the binding's recorded `semSkipIfZero` is unreachable by construction | **MED** (root cause of CL-1/CL-2) | **FIXED** — the apply no longer infers enablement from the cap; the property is now pinned deliberately | `internal/connlimit/connlimit.go`; §9.1 |
| CL-4 | The HTTP/CONNECT refusal is the only front-door gate in `handleRequest` with no row, no counter, no line and no metric — nothing to alert on, no attribution | **MED** (and the reason CL-1 survived) | **FIXED** — attributed row + `statBlocked` per refusal, rate-limited line, five `/metrics` series | `connlimit_observability.go`, `proxy.go`, `metrics.go`; §9.3 |
| CL-5 | Shard-map **capacity** is never reclaimed: 11.9 MiB retained after 500 000 distinct sources fully drained, while `ActiveIPs()` reads 0. `Release`'s doc claims the map "stays bounded by LIVE clients" — true of cardinality, false of the heap | **MED** | **REPORTED, NOT FIXED** — §8.2 | `internal/connlimit/connlimit.go`; §9.4 |
| RD-1 | **Rider, separate domain.** The public login endpoint's bootstrap branch minted a 30-day tier-2 trusted-IP **bypass** grant from an unverified login, keyed by an attacker-chosen username and IP; invisible to `GET /api/auth/lockouts` and not cleared by `ResetUser` | **HIGH** | **FIXED** — `ClearFailures`; the branch keeps the tier-1 clear and gets none of the bypass | `ui_auth.go`, `internal/lockout/lockout.go`; §4.2, §9.5 |

---

## 4. Recovery assessment

### 4.1 CL-1 … CL-4

**Automatic.** The fix is evaluated on every apply, so the first snapshot a
Data Plane receives after the upgrade restores its node-local enablement to
whatever the operator actually set — the startup resolver's value, the persisted
admin settings, the admin API, or a config import. No operator action, no
restart, no latch.

**Upgrade-visible, and stated plainly because it is a behaviour change.** A
Data Plane that had been silently enabled by the pre-fix apply **stops**
enforcing the cap once it applies a snapshot from the fixed binary, unless its
own node-local configuration asks for it. That is the correct state — it is what
the operator configured — but on a fleet that had unknowingly been running with
a 1024/IP cap it is a real change in admission behaviour, and the new
`culvert_connlimit_enabled` gauge is what makes it observable rather than
another silent flip. An operator who *wants* the cap enables it where enablement
lives: the startup configuration, the admin API, or admin settings.

**Manual.** None required. The cap is still cluster-synced, so a node that
enables locally adopts the fleet's value rather than its own boot value —
deliberately, and gated by
`TestCHAOS112_ControlDisabledLimiterKeepsItsCapThroughAnApply`.

**Deterministic.** The apply's outcome depends only on the snapshot's cap and
the node's own flag; no ordering, no clock, no map iteration.

### 4.2 RD-1 (the rider)

**Automatic, and complete by construction.** Lockout state is in-memory only, so
upgrading to the fixed binary is itself the remediation for any grant a running
process had already minted — a restart clears all three maps. That is why the
fix does not add a retroactive "clear trust grants at setup-complete" step: it
would only matter for an in-place upgrade that does not restart the process,
which does not exist. Stated so the omission is not read as an oversight.

**The residual recovery gap is pre-existing and recorded, not introduced.** Even
with every grant now earned, a trust grant is still invisible to
`GET /api/auth/lockouts` (`Snapshot` reports active locks, not grants) and
cleared by no operator action (`ResetUser` deliberately leaves trust alone).
That matters for an *earned* grant too — an admin whose workstation address is
later compromised holds a tier-2 bypass for up to 30 days that no operator can
revoke. See §8.3.

---

## 5. Operational impact

Before: a clustered fleet enforced a per-source-IP connection cap that no
operator had configured and no surface reported. `/metrics` said nothing about
this limiter — not its refusals, not its cap, not whether it was on. Refused
requests produced a `503` that reached no request history, no counter and no log
line, so the gate's own firing was undetectable; the only disagreement an
operator could observe was between the Control Plane's `GET /api/connlimit` and
a Data Plane's, one node at a time, if they thought to compare them.

After:

- `culvert_connlimit_enabled` answers *"is this node enforcing a per-IP
  connection cap?"* fleet-wide, which is the query that had no answer at all.
  It is the series an operator should alert on after this change: a non-zero
  value on a node whose configuration does not ask for one is now visible
  instead of silent.
- `culvert_connlimit_max_per_ip` reports the cap **whether or not** limiting is
  enabled, so the cluster-synced value is inspectable before anyone enables it
  locally — which is also what makes a CP/DP divergence legible rather than
  inferable.
- `culvert_connlimit_active_ips`, `culvert_connlimit_rejected_total` (both
  protocol paths) and `culvert_connlimit_http_refused_total` (this path's own
  charge) can be reconciled: a gap between the last two is SOCKS5 refusals.
- Every refusal writes an **attributed** `CONN_LIMITED` request-history row, so
  an operator can see *which source* is being capped — the thing an aggregate
  counter structurally cannot tell them, and the thing the SOCKS5 twin already
  provided.
- One narrative log line per minute at most, carrying the number suppressed
  since the last one.

**Interpretation for a runbook.** `culvert_connlimit_enabled 1` on a node whose
own configuration does not enable connection limiting now means a local
configuration source set it — not a Control Plane push. A rising
`culvert_connlimit_http_refused_total` with a flat `culvert_connlimit_active_ips`
is one source at its cap; both rising is a broad connection surge. The refused
source addresses are in the request history as `CONN_LIMITED`.

### Why the log line is rate-limited and the row is not

The SOCKS5 twin logs one line per refusal, which is tolerable because it fires
once per **session**. `handleRequest` fires once per **request**, and the
register is specific about what an unbounded per-request line costs on this
path: `X-2` records `internal/logsink`'s bounded queue as **blocking the caller**
when full, and `CHAOS-54` measured that exact shape at 7.68 M attempts / 300 ms
with one line each — ~40 MB/s into a 50 MB rotating log that erased its own
diagnostic history in seconds. A line per refused request would have made a
per-IP cap a proxy-wide latency amplifier, i.e. a third defect inside the
mitigation. `CHAOS-111` reached the same conclusion for its own omission line.

The row has no such hazard: it lands in a bounded ring at the same cost as any
other blocked request's row, and it is the half that carries attribution. So the
row is unconditional and the line is gated, and the gate stamps with `monoNanos`
rather than the wall clock, so a backwards NTP step cannot latch it shut
(`CHAOS-83`/`CHAOS-84`).

---

## 6. Security impact

**CL-1 … CL-4 are not a security regression and the write-up should not inflate
them.** The enforcement error was fail-**closed**: nodes applied a cap nobody
asked for, which refuses traffic rather than admitting it. Nothing was exposed,
no control was weakened, and no attacker gains anything.

What *is* a security property is the second-order one: an admission control that
nobody configured is an admission control that nobody is monitoring, tuning or
reasoning about, and for as long as its refusals were invisible there was no way
to discover it was there. The register's standing position is that a degradation
must be visible from the plane that is degrading; this gate was the one
front-door control with no such surface.

**RD-1 is a genuine security defect, in the other direction.** A tier-2
trusted-IP grant is an exemption from the account-wide lock, which exists
specifically to see what tier 1 cannot — a flood that rotates source addresses.
An unauthenticated caller inside the first-run bootstrap window could mint one
for a username and an address it chose, the grant outlived the window (nothing
in `apiSetupComplete` resets the limiter), it appeared in no operator surface,
and no operator action cleared it. With `trustMaxIPs = 8` addresses per username
and tier 1 still capping each address at `MaxAttempts` per `Window`, the
exemption buys an attacker a sustained guessing rate against the account tier
that no amount of account locking can stop, while a separate botnet keeps tier 2
tripped for every honest address.

The rule it broke was already written down twice in this tree: `apiSetupComplete`
states it for itself — *"there is no `RecordSuccess` here to ever build a trust
grant that would bypass it"* — and `ui_basic_auth.go` enforces it for its own
non-submission re-checks (`SEC-BASICAUTH-5`, which guards the success record as
the *more serious half*). The login handler's bootstrap branch was the remaining
caller recording a success it had not verified, and it sat one line above a
branch whose entire comment is about a pre-setup artifact outliving the window.

No new fail-open path exists anywhere in this change. Every edit either removes
enforcement nobody configured, adds telemetry, or removes an unearned
exemption.

---

## 7. Data-integrity impact

None. No persisted format changes and no wire format changes: `MaxConnsPerIP`
keeps its field number, its type and its recorded `semSkipIfZero` semantics, so
a mixed-version fleet interoperates in both directions — an old Control Plane
publishes exactly what it did before and a new Data Plane applies it as a cap;
a new Control Plane publishes exactly what it did before and an old Data Plane
applies it as it always did (i.e. with the defect, which is a property of the
*receiver*). `admin_settings.json`'s `ConnLimitEnabled` / `ConnLimitMaxPerIP`
round-trip is untouched, as is the config-backup representation, so export,
import and rollback are unchanged. Nothing on either path writes a config
version, and the config-surface registry's rows are accurate about the code for
the first time rather than being edited to match it.

The rider touches only in-memory limiter state, which is non-durable by design.

---

## 8. Suggested improvements (left open, attributed rather than fixed)

### 8.1 Decide whether per-IP connection limiting should be cluster-synced at all (MED) — the highest-value remainder

This round made the code match the registry: the cap is fleet-managed,
enablement is node-local. That is a coherent contract and it is the one already
written down, but it is probably not the one an operator expects from a
Control Plane — "I turned the connection limiter off for the fleet" currently
has no fleet-wide expression at all, and §2.2 shows the pre-fix code answering
that intent with a tightening.

Making enablement cluster-synced is a **product decision**, not a mechanical
fix: it means a node's local admin-API setting is overwritten at the next poll,
which is right for a centrally-managed fleet and wrong for a node an operator is
debugging. It needs a `ConfigSnapshot` binding on the `conn_limit_enabled` row,
`semAlwaysReplace` semantics on it, a publisher that emits the operator's intent
rather than a retained cap, and an apply that can `Disable`. `conventions.md` is
explicit that inventing a cluster-wide mutation for a node-local security
boundary is the wrong unilateral move; the recorded pattern is to surface the
deferral, which §5's runbook note does.

### 8.2 Reclaim the shard maps' capacity (MED) — CL-5

Go maps never shrink their tables, so the per-shard maps keep their high-water
capacity for the process lifetime. Measured against the real package: after
500 000 distinct source addresses had been acquired and **fully released**,
11.9 MiB stayed resident with `ActiveIPs()` reading 0 (§9.4). `Release`'s own
doc claims the map "stays bounded by LIVE clients, not by every client ever
seen", which is true of `len()` and false of the heap — the `PX-24` shape, one
subsystem over, and the residue half of `PX-6`.

Not fixed here, deliberately, for two reasons. The remedy belongs on `Release` —
the proxy hot path — where the natural shape (rebuild a shard's map once it
drains to zero above some high-water floor) adds an allocation to a function
this tree has already tuned twice and gated with structural walls
(`TestWall_ReleaseTakesTheShardLockExactlyOnce`). And
`connlimit_footprint_test.go` currently **relies** on the retention: it warms
20 000 entries, releases them, and measures a re-acquire as near
allocation-free, with a comment that says it is warming "to their final
capacity". So the fix has to change an existing benchmark's premise as well as
the hot path, which is its own decision and should not ride along with a
configuration-plane change.

Operator view meanwhile: an unexplained permanent RSS step after a
high-cardinality incident, with the subsystem's own `activeIPs` gauge reading a
healthy 0, so nothing attributes the memory to the limiter.

### 8.3 Make trusted-IP grants visible and revocable (MED) — pre-existing, surfaced by the rider

Independent of RD-1 and true of *earned* grants too: a tier-2 trusted-IP grant
is an authentication-bypass allowance with a 30-day TTL that appears in no
operator surface and is cleared by no operator action. `Snapshot()` returns
active locks; `ResetUser` deliberately leaves trust alone; `Cleanup` prunes only
past `TrustTTL`. An admin whose workstation address is later compromised holds
that bypass for up to a month and the operator cannot revoke it short of a
restart.

The fix is a listing field plus a revocation action, which under
`conventions.md` means the admin API endpoint, the `uiRoutes` entry and a UI
surface together — a new operator action on the authentication plane, which is
an owner decision rather than a rider. `EntryCount`'s doc has been corrected in
this change to stop asserting a premise the code did not enforce.

### 8.4 An alert for the connection-limit posture (LOW-MED)

The signal is now visible and pages nobody — the same shape `CHAOS-110` left
open for `dpi_degraded` and `CHAOS-111` for `cluster_ratelimit_degraded`. The
series are shaped so a rule can be written today
(`culvert_connlimit_enabled` as a posture assertion,
`rate(culvert_connlimit_http_refused_total[5m])` as a firing rate), but which of
those is an alert and which is a dashboard condition belongs to the alerts
owner.

### 8.5 The HTTP path's slot is per-REQUEST, not per-connection (LOW, pre-existing)

The package header already says so. The consequence worth recording: idle
connections that never complete a request are counted by nothing and are bounded
only by the listener's `ReadTimeout`. So "connections per IP" is a slight
misnomer for the HTTP path and an accurate name for the SOCKS5 path, and a
deployment relying on it to bound *sockets* rather than *in-flight requests* is
relying on something it does not do. Untouched here.

### 8.6 Why RD-1 rode along, and what did not

Three findings from this sweep's other investigations are recorded in §10 rather
than fixed, because each is a different domain with its own owner and its own
posture questions. RD-1 is the exception: an unauthenticated path that mints a
non-revocable, invisible authentication-bypass grant is not something to leave
open for a day when the fix is one call site plus one owner primitive, and it
is strictly safety-increasing with no availability risk (its controls prove a
genuine login still earns its grant, so `RISK-012`'s lockout-as-DoS protection
is intact). It is in its own commit and is reviewable independently of the rest.

---

## 9. Measurements and commands

All numbers from a build of this tree on this container, through the real
production functions — the real publisher expression
(`connLimiter.MaxPerIP()`), the real `applyConfigSnapshot`, the real
`handleRequest`, and the real `internal/connlimit` package — via a throwaway
harness that was removed before the PR. The gates that replace it are named in
§9.5.

### 9.1 The root cause: the wire field cannot signal "off"

```
fresh limiter:               Enabled()=false  MaxPerIP()=1024
after Enable(50)+Disable():  Enabled()=false  MaxPerIP()=50
CP publishes max_conns_per_ip=1024 from a limiter it is NOT using
```

`MaxPerIP()` answers with a cap in both disabled states, so
`snap.MaxConnsPerIP = connLimiter.MaxPerIP()` is always non-zero and the
binding's recorded `semSkipIfZero` guard is unreachable.

### 9.2 CL-1 and CL-2: what the apply did with it

```
PRE-FIX  apply: DP Enabled()=true  cap=1024   (operator configured nothing)
POST-FIX apply: DP Enabled()=false cap=1024

PRE-FIX: operator disables on the CP, DP applies again -> DP Enabled()=true cap=50
```

The second line is the fix: the cluster cap is **recorded** (so enabling locally
later adopts the fleet's number) and enforces nothing. The third line is CL-2 —
the operator's disable reaching the fleet as a tightening.

### 9.3 CL-4: what an operator could see when the unasked-for cap fired

200 requests from one source holding all 1024 of its slots, driven through the
real handler for the post-fix row and through the verbatim pre-fix branch for
the other:

```
PRE-FIX  cap=1024 held=1024  refused 200/200  statBlocked delta=0    CONN_LIMITED rows=0    log lines=0
POST-FIX cap=1024 held=1024  refused 200/200  statBlocked delta=200  CONN_LIMITED rows=200  log lines=1
```

Identical refusal behaviour; the difference is entirely in what is observable.
One log line for 200 refusals is the rate limit working.

### 9.4 CL-5: the capacity that is never reclaimed (measured, not fixed)

Real package, `HeapAlloc` after two forced GCs, with the key slice's own cost
subtracted:

```
n=100 000  active=0  peak=3 500 232 B   after full drain=296 184 B     (3.0 B/peak IP)
n=500 000  active=0  peak=27 904 704 B  after full drain=11 907 504 B  (23.8 B/peak IP)
```

The per-IP figure is not linear because Go grows map tables in powers of two —
the 500 000 case lands just past a doubling, the 100 000 case well before one.
The honest statement is the absolute one: **11.9 MiB retained after 500 000
distinct sources fully drained, with `ActiveIPs()` reading 0.** The IP key bytes
themselves *are* reclaimed; what survives is table capacity.

### 9.5 Gates shipped

`connlimit_cluster_apply_chaos112_test.go` (the apply):
`CHAOS112_SnapshotDoesNotEnableADisabledLimiter` (primary),
`CHAOS112_ControlSnapshotUpdatesTheCapOfAnEnabledLimiter` (CONTROL — dropping
the field would un-sync a surface the registry declares synced),
`CHAOS112_SnapshotNeverFlipsEnablementInEitherDirection` (the invariant, over
both starting states),
`CHAOS112_ControlZeroCapKeepsLiveState` (semSkipIfZero stays),
`CHAOS112_ControlDisabledLimiterKeepsItsCapThroughAnApply` (CONTROL — a
recorded cap must enforce nothing, and must still be recorded).

`internal/connlimit/chaos112_setmaxperip_test.go` (the primitive):
`CHAOS112_SetMaxPerIPNeverTouchesEnablement`,
`CHAOS112_SetMaxPerIPIgnoresANonPositiveCap` (the control **no root gate can
reach** — see §9.6 M3),
`CHAOS112_SetMaxPerIPIsTheCapAcquireEnforces`,
`CHAOS112_SetMaxPerIPOnADisabledLimiterEnforcesNothing`,
`CHAOS112_DisablePreservesTheConfiguredCap` (pins the root-cause property
deliberately, so changing it is a decision).

`connlimit_refusal_observability_chaos112_test.go` (the telemetry):
`CHAOS112_HTTPConnLimitRefusalIsObservable` (row asserted by UNIQUE client IP,
never a length delta — the request ring is bounded — and it asserts the row's
METHOD and HOST, not merely its existence: a row that says a source was capped
without saying what it was asking for is not the attribution its two
neighbouring gates provide),
`CHAOS112_ConnLimitRefusalLogIsRateLimited` (two-sided: some line, far fewer
than one per refusal),
`CHAOS112_ConnLimitRefusalLogResumesAfterTheInterval` (the RECOVERY half — a
gate that only ever suppresses is indistinguishable from one that latched shut,
which is precisely the CHAOS-83/84 failure for an elapsed-time check, so it must
be shown to reopen AND to carry the magnitude it suppressed),
`CHAOS112_MetricsExposeTheConnLimiterPosture`,
`CHAOS112_MetricsReportADisabledLimiterAsZero` (the AU-43 half: a present-tense
gauge must name the value that clears it),
`CHAOS112_ControlSOCKS5RefusalKeepsItsRow` (the twin is not levelled down).

`auth_bootstrap_trust_grant_chaos112_test.go` (RD-1, the rider):
`CHAOS112Rider_BootstrapWindowLoginMintsNoTrustGrant` (primary; asks through
the limiter's real `Check` decision rather than reading internals),
`CHAOS112Rider_ControlAVerifiedLoginStillMintsItsGrant` (CONTROL — deleting the
call would pass the primary gate and destroy `RISK-012`'s lockout-as-DoS
protection),
`CHAOS112Rider_ControlAWrongPasswordMintsNoGrant`,
`CHAOS112Rider_BootstrapWindowStillClearsItsOwnPairCounter` (the half the
window keeps: a first-run operator must not lock themselves out of the window
they are standing in).

No wall-clock ratio gate is added, so nothing here belongs in the `benchgate`
job and that job's package list is unchanged.

### 9.6 Mutation tests — the gates have teeth

Twenty-one mutation runs over twenty distinct mutations, each applied to the
fixed tree and run against the gates that should catch it. **Every distinct
mutation is caught**, none silently green — and the one useful negative is
recorded rather than hidden: M3 escaped every ROOT gate, which is why the
owner-package file exists at all, and M3b is that same mutation re-run against
the gates it motivated.

| mutation | caught by |
|---|---|
| M1 apply uses `Enable` (the verbatim pre-fix shape) | `SnapshotDoesNotEnableADisabledLimiter`, `SnapshotNeverFlipsEnablement*` |
| M2 apply drops the cluster-synced cap entirely | `ControlSnapshotUpdatesTheCapOfAnEnabledLimiter`, `ControlDisabledLimiterKeepsItsCap*` |
| M3 `SetMaxPerIP` resets to the default on a zero cap | **nothing at root** — the caller's `> 0` guard makes it unreachable; this is why the owner-package file exists. Caught there as M3b |
| M3b the same, against the owner gates | `SetMaxPerIPIgnoresANonPositiveCap` |
| M3c `SetMaxPerIP` also sets the enabled flag | `SetMaxPerIPNeverTouchesEnablement` |
| M3d `Disable` also clears the cap | `DisablePreservesTheConfiguredCap` |
| M4 the refusal writes nothing (the pre-fix branch) | `HTTPConnLimitRefusalIsObservable`, `ConnLimitRefusalLogIsRateLimited` |
| M5 the narrative line is written on EVERY refusal | `ConnLimitRefusalLogIsRateLimited` |
| M6 the line is suppressed forever after the first | `ConnLimitRefusalLogIsRateLimited` |
| M7 `statBlocked` is not charged | `HTTPConnLimitRefusalIsObservable` |
| M8 no attributed request-history row | `HTTPConnLimitRefusalIsObservable` |
| M9 the `/metrics` posture block is removed | both metrics gates |
| M10 the enabled gauge is hardcoded to 1 | `MetricsReportADisabledLimiterAsZero` |
| M11 the posture gauges report the wrong cap | `MetricsExposeTheConnLimiterPosture` |
| M12 the row drops its method/host attribution | `HTTPConnLimitRefusalIsObservable` |
| M13 the resumed line stops reporting the suppressed count | `ConnLimitRefusalLogResumesAfterTheInterval` |
| M14 the log gate never reopens | `ConnLimitRefusalLogResumesAfterTheInterval` |
| R1 (rider) the pre-fix shape: `RecordSuccess` above the `preSetup` branch | `BootstrapWindowLoginMintsNoTrustGrant` |
| R2 (rider) the cheap fix: drop the success record entirely | `ControlAVerifiedLoginStillMintsItsGrant` |
| R3 (rider) the bootstrap branch records nothing at all | `BootstrapWindowStillClearsItsOwnPairCounter` |
| R4 (rider) `ClearFailures` delegates to `RecordSuccess` | `BootstrapWindowLoginMintsNoTrustGrant` |

M3 is the useful one to record: it escaped every root gate and is the reason the
owner-package file was written rather than assumed unnecessary.

### 9.7 Lint, measured both ways — and the one that mattered

The diff-scoped run the Fast gate uses is clean:

```
$ golangci-lint run --timeout=25m --new-from-rev origin/main
0 issues.
```

That result alone would have been misleading, which is exactly what
`conventions.md` warns about: `cyclop`, `funlen` and `gocognit` attribute to a
function's **declaration** line, so `--new-from-rev` cannot see a function a
change made more complex. The full-tree comparison against the same measurement
on the base found one:

```
handleMetrics: cognitive complexity 45 (base b05d649)  ->  46 (first draft)
```

`handleMetrics` is already over the `gocognit` threshold of 30, so the finding
was pre-existing and the diff-scoped run reported nothing — and the change made
it worse by one anyway. The `/metrics` block was extracted into
`connLimitWritePrometheus`, after which the full-tree measurement is **identical
to the base**: same 174 issues, same per-linter totals, and no function's
measured complexity changed.

```
$ diff <(base complexity findings) <(head complexity findings)
IDENTICAL: no function's measured complexity changed vs the base
$ diff <(base per-linter totals) <(head per-linter totals)
IDENTICAL totals
```

Recorded because it is the second time this repository's own convention has
caught something a reviewer reading the diff would not have: the first draft of
this sweep's gates also failed
`TestSnapshotApplyFixture_Wall_EveryApplyCallerBindsFreshOwners`, because the
apply mutates `ipf` and `rl` in place (RISK-030) and a root test that reaches it
must bind fresh owners or leak a cleared filter into whatever runs next.

### 9.8 Checks run

See the PR description for the exact commands and their results at the pushed
SHA, including what was **not** run and why. A passing local check is not a
passing hosted gate.

---

## 10. Adjacent domains swept, recorded and not fixed

Three findings from this sweep's other bounded investigations. Each was traced
to the source; each belongs to a different owner and carries its own posture
question, so each is recorded with evidence rather than fixed here. They are
listed in the order I would fix them.

### 10.1 The dashboard tick schedules credential re-verification in LOCKSTEP (MED–HIGH, new)

`apiEvents` re-checks a stream's credentials every `sseRevalidateEvery = 60`
**received broadcast messages**. Every client receives the *same* `Broadcast`,
so every stream opened inside one tick window reaches 60 on the **same**
broadcast round. For a stream authenticated with HTTP Basic the re-check reaches
`VerifyUIUser` → `bcrypt.CompareHashAndPassword` at `DefaultCost`, so the cost
does not spread across the minute: it arrives as an N-wide simultaneous burst,
scheduled by the dashboard ticker rather than by any arriving request. It is the
only bcrypt in the binary that runs with **no client request in flight** — an
idle, byte-silent TCP connection keeps buying one bcrypt per 60 ticks forever.

Every bound that might govern it is structurally absent on that path: the
per-IP Basic failure budget is exempt by design for a liveness re-check
(`SEC-BASICAUTH-5`, correctly — a re-check is not a guess), the two-tier lockout
refuses only an already-locked pair and a correct password never locks,
`apiLimiter` exempts GET, and `internal/authcost` — the governor `CHAOS-57`
added for exactly this cost — has **one** production call site,
`verifyAuthFrom` on the proxy plane; `VerifyUIUser` is ungoverned. The hub's
256-slot cap is process-global with no per-identity share, and `apiEvents`
requires only `RoleViewer`.

The register's own scope note for `CHAOS-57` says *"The admin UI login path is
untouched. `VerifyUIUser` also runs bcrypt … but is bounded by the brute-force
lockout (`loginLimiter`)."* That is not true for a **valid** credential, which
is the case this path exercises every time.

Why not fixed here: the cheap half (derive each connection's re-check deadline
from its own clock with jitter instead of a count of a globally shared message
sequence) is small and clearly right, but the half that bounds the aggregate
cost is a posture decision about the admin plane — routing `VerifyUIUser`
through `authCostAdmit` makes a re-check *refusable*, and what a refused
re-check should do (cut the stream, defer it, or wait) is a trade between
revocation latency and dashboard availability that belongs to the auth owner.
Pinned by nothing today: no test references `sseRevalidateEvery` outside its own
file.

Also noted on that plane, both minor: a stream cut by mid-stream revocation
produces no log line, audit entry or counter, so an operator cannot confirm a
revocation reached the streaming plane; and there is no staleness gauge for the
broadcaster and no alert on the eviction or rejection counters. By contrast the
payload side is in good shape and should not be "fixed" — the tick's two shared
locks are not on the request path, the payload is marshalled once and shared by
reference, and nothing in it scales with traffic or client input (`TopCountries`
is capped at 15 over the MMDB country set).

### 10.2 A compliance export silently substitutes different data (MED, new)

`audit.GetPersistent` returns `Get(), 0` on **any** read error — the raw
in-memory ring, newest-first, ignoring `offset`, `limit`, `fromTS` **and**
`toTS`. Its consumer is the compliance export: `format=csv|json` defaults
`source` to `file` precisely because "the point is capturing history beyond the
in-memory ring". So an auditor requesting a date-bounded export over a volume
returning EIO, or after a permissions change, receives **HTTP 200** with an
attachment containing up to 500 recent entries from outside the requested range
— no error, no marker, no counter (`WriteErrors()` is unrelated and stays 0).

The sharpest part is that it needs no fault at all: the rotation path renames
`audit.jsonl` and recreates it, so there is a window where the live path does
not exist, reachable once per 50 MB of audit volume. In the interactive path the
substitution at least *looks* wrong (500 entries beside `"total": 0`); in the
export path there is nothing to notice.

This is **not** the registered half of `ST-8`, which records only that
`GetPersistent` re-reads the whole file per query. It manufactures misleading
evidence under an ordinary transient, which is the failure mode `ST-8` was
written to prevent. The fix is a contract change — the read error has to reach
the handler so it can answer 503 rather than 200 — which means an API behaviour
change and an OpenAPI update, so it is its own change.

### 10.3 `D-5` confirmed open, with its direction corrected (MED, registered)

The 2026-10-13 backlog's `D-5` (audit JSONL has no fsync) is accurate verbatim
at this revision: no `Sync`, no `O_SYNC`, no parent-directory fsync and no
`AtomicWrite` anywhere in the audit write path, while the config-version write
beside it goes through `fileutil.AtomicWrite` (temp fsync + rename + parent-dir
fsync). The durability asymmetry is real.

Two corrections worth recording. **The write is fully synchronous** — there is
no queue, no worker and no `bufio` between `auditEvent` and `write(2)` — so
SIGTERM, SIGKILL, `logFatalf` and `os.Exit` lose **nothing** from the local
JSONL; only a machine-level fault inside the writeback window does. That caps
the severity and matches the row's MED rating. And `D-5`'s own headline example
*understates* the case: for a versioned mutation the config-version envelope is
itself a durable actor/action record, so an auditor is not left with nothing.
The sharpest instance is the opposite set — the audited-but-deliberately
**unversioned** paths (`auth.password_change`, `auth.logout`, the CDR
hygiene/revoke paths pinned by their own no-versioning regressions) — where the
unsynced JSONL is the **sole** durable record of who did it.

One adjacent, unregistered item in the same file: `RotatingFile`'s rotation
discards both the `Remove` and the `Rename` error, so if `audit.jsonl.1` cannot
be unlinked or replaced the rotation silently no-ops, the reopen re-stats the
full size, and every subsequent write re-enters rotation — the 50 MB cap
permanently defeated with no counter, log line, metric or health row, because
the `write` itself succeeds. The **reopen** half of the same function gets the
full `ST-8` treatment. Low likelihood, unprincipled asymmetry, no test.

---

## 11. Residual risk

- **Whether enablement should be fleet-managed is still undecided** (§8.1). This
  round made the code match the registry; it did not establish that the registry
  records the contract an operator wants. "Turn the connection limiter off for
  the fleet" still has no expression.
- **A fleet that had been silently enabled changes behaviour on upgrade**
  (§4.1). The new state is the configured one, and the new gauge makes it
  visible, but it is a real admission change on nodes whose operators never knew
  the cap was there.
- **The capacity residue is unfixed and now measured** (§8.2 / CL-5): 11.9 MiB
  after 500 000 drained sources, with the subsystem's own gauge reading 0.
- **The posture pages nobody** until §8.4 lands. It is on `/metrics`, in the
  request history and in the API; it is not an alert.
- **Trusted-IP grants remain invisible and non-revocable** (§8.3). The rider
  stops unearned ones being minted; it does not give an operator a way to see or
  revoke an earned one.
- **The HTTP path's slot is per-request** (§8.5), so this limiter does not bound
  idle sockets and never did.
- **The three adjacent findings in §10 are open**, and §10.1 is the one I would
  fix next: it is a self-inflicted CPU burst on the management plane, reachable
  from `RoleViewer` with one credential and no further traffic.
- **The gates run at small fixtures.** The apply gates are exact rather than
  statistical, but the observability gates drive 200 refusals on one goroutine;
  no gate exercises the refusal path under concurrency, and the retention
  measurement stops at 500 000 sources.
