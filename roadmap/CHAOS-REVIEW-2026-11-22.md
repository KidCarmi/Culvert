# Chaos review — 2026-11-22

Revision at start: `155df09` (clean worktree). Scope chosen by *absence of
coverage*: the 130 `*chaos*` files in the tree already carry CHAOS-01…126, so
this round swept the packages those rounds never reached — `internal/mcp`
(~52 kLOC, zero chaos files), `internal/upstream`, `internal/storeguard`,
`internal/reqlog`, `internal/lockout`, `internal/identcache`,
`internal/bandwidth`, `internal/sse` — rather than re-litigating a closed row.

One defect is FIXED here (CHAOS-127). Everything else is recorded with
file/line evidence and left to its owner, because each remaining item either
changes a data-path concurrency primitive, adds a background loop, or settles a
posture question — none of which belongs in a sweep. That split follows the
CHAOS-75/WK-22 precedent §51.5 already sets.

---

## 1. Executive summary

**Fixed in this round.** `storeguard`'s poison-marker branch kept a resolved
breadcrumb forever when the store it accused was absent, and the next open that
found a directory at that path quarantined the **healthy replacement** and let
`pruneQuarantines` delete the genuine corruption evidence. Measured, not
inferred (§2.1). It is a data-integrity defect on the boot path of the request
history store and the URL-category store, and the correct behaviour was already
implemented, reasoned and tested seventeen lines away in the fault branch of the
same `switch` — so this is a consistency fix, not a posture change.

**The sharpest open row is in `internal/mcp/events`,** which is also the single
largest subsystem in the repository with no chaos coverage at all. Three
defects compose into one permanent, **restart-surviving** wedge of the MCP
Gateway's entire write/destructive path, reachable by ordinary steady-state
traffic rather than by a hostile peer: the critical-durability breaker has no
production closer, the spool tier that would reclaim P-CRIT space can never
match because nothing marks a segment exported, and the one graded early-warning
signal before saturation is discarded on the commit path. The MCP gateway is
**disabled by default** (`config.example.yaml:277`), which is what keeps this
off the top of the risk matrix — it is an opt-in-feature outage, not a
default-config one.

**The `internal/upstream` pool has no automatic recovery path in the shipped
default configuration.** An `unhealthy` probe verdict is one of three
independent gates on parent-proxy eligibility, and it is the only one nothing
clears on its own: the periodic health loop that would re-probe is armed only at
startup and only when `health_interval > 0`, which the shipped example config
leaves empty. The documented remedy is the manual probe, and that handler is not
panic-safe — the asymmetry is explicit, because the periodic round *is*
contained with `obs.SafeCall` under a comment that names this exact
consequence.

**What is already right is worth recording,** because three of the eight areas
swept came back clean and should not be re-swept: see §8.

---

## 2. Failure scenarios

### 2.1 CHAOS-127 — a resolved poison marker destroys its healthy replacement (FIXED)

`internal/storeguard/storeguard.go`, `recoverBeforeOpen`. The fault branch
handles an absent store explicitly:

> *"The faulted store is already gone … so the condition the marker records is
> resolved. Keeping the marker would report a phantom recovery on every start."*

and clears it (gated by `TestOpen_RecordedFaultForAMissingStoreIsCleared`). The
poison branch in the same `switch` had no such case. It fell through to
`ApplyQuarantine`, which records an absent directory as a **skip**
(`rec.Skipped = "no store directory present"`), and the skip is precisely what
makes the marker clearing at the end of the function conditional
(`if !rec.Quarantined { return nil }`). So the marker survived.

Sequence, with the pre-fix control run measured in a throwaway probe:

| step | state | pre-fix outcome |
|---|---|---|
| 1 | start dies inside `badger.Open` | `.opening.<pid>-<ns>` left behind |
| 2 | next start quarantines `hist` → `hist.corrupt.T1`, then dies before the marker removal (`pruneQuarantines` `RemoveAll`s a multi-GB older copy first, so the window is not microscopic) | marker + evidence both on disk |
| 3 | next open: marker present, directory absent | `trigger=poison_marker quarantined=false skipped="no store directory present"`, **marker kept**; Badger `MkdirAll`s a fresh store and history accumulates normally |
| 4 | next open (a restart — *or the admin history-store toggle seconds later*) | `trigger=poison_marker` **`quarantined=true`**, the HEALTHY store renamed to `hist.corrupt.T2`; `MaxQuarantinedCopies` is 1, so `pruneQuarantines` deletes `hist.corrupt.T1` — original evidence survived = **false** |

Equivalent crash-free trigger: an operator deletes the store directory to
reclaim space while a stale marker sits beside it.

Affected stores: `logstore` (request history — a retained compliance artifact,
runtime-reachable without a restart via `enableLogStore` → `openLogStore` →
`logstore.OpenResilientTTL`) and `catdb` (URL categories — cost is a full feed
rebuild). The package's own stated contract is *"quarantine the evidence, do
not overwrite it"*.

A second-order half: when a poison marker **and** a fault marker both exist and
the directory is gone, the `switch` takes the poison branch, so the fault
branch's clearing never ran either — the fault marker alone would then
quarantine the replacement at the following open. Closed in the same fix.

### 2.2 MCP critical-durability breaker has no production closer (OPEN, High)

`internal/mcp/events/state/state.go:191-204` opens the breaker on one commit
failure and persists it; `:168-172` gates every critical write on
`StateNormal`. The only exit is `BeginRecovery` → `FinalizeRecovery`, reachable
only from `Manager.RecoverProbe` (`internal/mcp/events/probe.go:15`) — and
`RecoverProbe` has **zero production callers** (verified directly: the only
non-test hit in the tree is its own definition). `state.go:144-145` restores
`m.critical` verbatim from `degraded_state.json`, and the fail-toward-critical
branch at `:156` catches only `StateUnknown`/`StateRecovering`, so a restart
does not clear it.

One transient ENOSPC, fsync error or quota rejection during any write-class
`tools/call` therefore refuses every subsequent write and destructive call
(`decide.go:60-63` → `ReasonEventDurabilityDegraded`) for the life of the data
directory. Reads and discovery keep working, so the gateway looks alive. The
only remedy is an operator deleting `degraded_state.json`.

The health surface actively misreports it: `recoveryStateLabel`
(`mcp_telemetry_health.go:142-145`) returns `"clean"` when `RecoveryAttempts ==
0`, and because the probe never runs that counter is permanently 0 — so the
admin Durability panel reads `recovery_state: "clean"` beside
`critical_state: critical_durability_degraded`.

Contrast, and the reason this is a finding rather than a recorded exception:
`internal/mcp/execution/recovery.go:457-464` documents in terms that
`RecoverAttempts` "has NO production caller", states the precondition for
wiring it, and pins that precondition with a test. `RecoverProbe` and
`MarkExported` carry no such note. An undocumented absence is a gap; a
documented one is a decision.

### 2.3 P-CRIT spool segments are never reclaimable, so §2.2 fires unaided (OPEN, High)

`sg.exported = true` is assigned in exactly one place, `Spool.MarkExported`
(`internal/mcp/events/spool/reclaim.go:100`), which has **zero production
callers** (verified). The reclamation order (`reclaim.go:31-37`) requires
`exported == true` for the P-CRIT tier, so sealed P-CRIT segments are never
deleted and P-CRIT grows monotonically. The hook built for this —
`export.AckFunc`, commented *"so the caller can advance a durable cursor and
mark segments exported"* — is also unwired; production reimplements the step in
`mcp_telemetry.go` (`exportStep`) with its own cursor store and never tells the
spool. At Gateway defaults (SpoolMaxBytes 512 MiB, CriticalReserve 128 MiB,
16 MiB segments) `admitLocked` eventually refuses with
`ReasonEventQueueSaturated` → `onCommitFailure` → the permanent wedge in §2.2.
`Stats.OldestUnexportedNano` is pinned to the oldest segment forever for the
same reason.

### 2.4 The graded warning before that saturation is discarded (OPEN, Medium)

`internal/mcp/events/spool/spool.go:244-247` calls `s.reclaimLocked(...)` on the
commit path and **discards its return value**. That return is `stuck`,
documented at `reclaim.go:17-20` as the condition *"which the caller maps to
critical-durability-degraded (EVENT-MODEL.md §4b.4)"*. Reclamation still runs
inline on every commit; only the verdict is thrown away, so the documented
§4b.4 graded transition never fires and the first symptom of §2.3 is the hard,
unrecoverable refusal.

### 2.5 Upstream pool: no automatic clearing path for a probe verdict (OPEN, Medium-High)

`eligible()` (`internal/upstream/upstream.go:233-241`) requires
`credentialEligible() AND (unprobed OR healthy) AND CB.Allow()`. The breaker
self-heals; the probe verdict does not. The only non-test writer of a verdict is
`HealthCheck` (`upstream.go:926`, verified by grep), driven only by the periodic
loop or an operator `POST /api/upstream/health`. The loop is armed only at
startup and only when `health_interval > 0`
(`upstream_pool_startup.go:32-35`), and `config.example.yaml:190` ships
`health_interval: ""` — *empty = disabled*. The SIGHUP reload path calls
`Configure` + `applyUpstreamProxy` and never starts the loop, so there is no
in-process way to arm it.

An operator who clicks *Check health* while a parent is still down — which
`diagnostics_upstream_egress.go:48` tells them to do — writes `unhealthy`. When
the parent recovers, nothing re-probes it: no request is ever sent through it,
so the breaker is never even consulted. If it was the last parent, plain-HTTP
traffic egresses **DIRECT**, bypassing the enterprise parent-proxy chain, until
a human clicks again.

Two mitigations are real and should temper the severity: the all-ineligible
state is **not** silent — `checkUpstreamEgress` raises a WARN operator-contract
row naming the bypass, alongside the `upstream_pool_down` alert and the
`culvert_upstream_direct_fallback_active` metric. And a *partial* outage
(one parent stuck unhealthy while another serves) is invisible, but costs
redundancy rather than enforcement.

### 2.6 The advertised recovery lever is not panic-safe (OPEN, Medium)

`ui_upstream.go:195-196` runs `HealthCheck` and then `EndManualProbe()` with no
`defer`, while `BeginManualProbe`'s own contract (`upstream.go:313`) says *"An
admitted run MUST be closed with EndManualProbe."* `net/http` recovers a
handler panic per connection, so the process survives and `manualInflight`
stays `true` for its lifetime: every later POST answers `429 probe_in_flight`
and `ManualProbeInFlight()` reports a phantom run forever. Combined with §2.5
that is the permanent loss of the only recovery lever in the default config.

The asymmetry is the evidence that this is an oversight rather than a choice —
`upstream.go:1020-1023` contains the periodic round precisely because of this
consequence:

> *"CHAOS-24: contain the ROUND. This loop is what closes a tripped breaker, so
> if it dies the pool can never recover a parent proxy and egress stays on the
> direct fail-open path indefinitely."*

### 2.7 Half-open admits unbounded concurrency (OPEN, Medium)

`internal/upstream/upstream.go:44-46` declares `circuitHalfOpen` as *"probing —
allow one request"*; `:109-111` is `case circuitHalfOpen: return true`, to every
caller, with no single-flight token. A healthy probe cannot close the breaker
either — `HealthCheck` never touches `up.CB` (verified by reading it end to
end), so only real client traffic can.

Against a black-holing parent (accepts TCP, never answers) with defaults
`threshold: 5`, `timeout: 60s`: the breaker opens, traffic correctly fails open
to DIRECT and is fast; 60 s later the first `Allow()` CASes to half-open, and
from that instant until the first failure lands ~30 s later
(`upstreamRequestTimeout`, `ResponseHeaderTimeout`) **every** proxied
plain-HTTP request enters the black hole, hangs 30 s and returns 502 — then
`RecordFailure` re-stamps `openedAt` and the cycle repeats indefinitely.

**This one is deliberately not fixed here, and the reason is itself a finding.**
The obvious fix — a single-flight token released by `RecordSuccess`/
`RecordFailure` — introduces a wedge of exactly the class this review exists to
find: any admitted request that never records an outcome strands the token and
pins the breaker open forever. A correct fix needs a self-healing bound (e.g.
one admission per grace window, keyed off a `halfOpenAt` stamp) so a lost
outcome cannot wedge it. That is a data-path concurrency decision for the owner.

### 2.8 Culvert's own whole-exchange cap is charged to the parent's breaker (OPEN, Medium)

`upstream.go:869-890` deliberately excludes `context.Canceled` and deliberately
counts timeouts — and `breaker_wiring_test.go:123-128` pins "slow parent =
failing parent", so the policy is a decision. But the deadline that reaches
`Record` includes Culvert's **own** fixed 30 s cap (`proxy_http.go:43`,
`:215`), whose documented scope covers the response-body read. Five consecutive
plain-HTTP bodies that each take over 30 s (a large package mirror) therefore
open the breaker on a parent that never misbehaved, and with a single-parent
pool all traffic egresses DIRECT for the open window. Untested in that
direction: the existing gate synthesizes the error rather than expiring the cap
on a healthily streaming body.

### 2.9 `storeguard` crash-loop protection can switch itself off silently (OPEN, Medium)

`BeginAttempt` (`internal/storeguard/storeguard.go`) is best-effort by design,
and correctly so — failing to arm must not stop the store opening. But every
failure path returns a zero `OpenAttempt` and discards the reason, `openGuarded`
ignores the result, and `Recovery` has no field that can express *"no
breadcrumb was armed for this open"*. The marker is a **sibling**, written in
the parent directory, so a container layout with a root-owned `0755` parent and
a chowned store subdirectory gives `EACCES` on the marker while `badger.Open`
on the store succeeds. From then on every start runs with zero poison-marker
protection, reporting `Recovery{Trigger: TriggerNone}` — indistinguishable from
a healthy protected open. Same outcome on a parent out of inodes, or a mount
without advisory locking. The defect is the missing **signal**, not the policy;
a `Recovery.MarkerArmed bool` would let the two callers log it once at startup.

### 2.10 Identity-cache deadlines are measured in running time (OPEN, Low-Medium)

`internal/identcache/identcache.go:289-300` tests expiry with
`time.Now().Before(e.expiry)` where both operands carry monotonic readings, so
the comparison is pure elapsed-**running**-time. For a TTL that is fine; this
deadline is not a TTL. `auth_oidc.go:448-462` clamps the entry's expiry to the
introspected token's own `exp` — an absolute instant — and `monotime.go` states
the rule directly: *"A stamp that must survive a restart or cross a node
boundary is an ABSOLUTE instant and belongs on the wall clock"*, noting that a
monotonic reading does not advance while the machine is suspended.

So after a VM suspend / snapshot restore, a cached `ok=true` verdict for a
token that expired during the outage is served for up to the entry's remaining
TTL of running time — contradicting the clamp's own stated contract that *"a
cached 'yes' can never outlive the credential it was derived from"*. Bounded by
one cache TTL, and the local bcrypt cache on the same engine has an
`authRevision` check the token caches have no analogue for. Not reachable by the
existing chaos technique: a wall-clock step cannot push a monotonic-bearing
`time.Time` into the future, which is why CHAOS-83/84 both missed the class.
`identcache` has no clock seam (unlike `authstate`'s `NewWithClock`), so a
deterministic gate needs one. **Note the mirror image: the same semantics make
`internal/lockout` fail CLOSED across a suspend — locks persist longer — and
that half must not be "fixed" by moving lockout to the wall clock.**

### 2.11 Lockout maps have no total cap (OPEN, Medium, availability)

`internal/lockout/lockout.go:191-196` keys `pairs` and `accounts` on
unauthenticated caller-chosen data, and the package says so itself at `:500-505`:
`MaxUsernameKeyLen` bounds each key and `Cleanup` bounds retention, *"but
nothing here bounds how many a caller may create — that is the callers' job."*
No caller enforces a total: both login paths bound **rate per IP** (60/min),
and the janitor cannot evict before `Window` elapses, giving ~15 min retention.
A credential-stuffing botnet using one distinct username per attempt trips
neither tier and allocates two entries per attempt: ~1,800 entries (~0.7 MB) per
attacking IP at the ceiling, so ~10k sources is multi-GB. There is a gauge
(`culvert_login_limiter_entries`) but no cap, alert or shedding.

The in-memory-only restart behaviour **is** documented as deliberate
(`lockout.go:38-43`, and the operator doc calls it the break-glass), but both
texts frame the restart as an *operator* action; neither considers an attacker
inducing one to clear a lock. Given the lock is 15 minutes, rank this on the
memory exhaustion, not the reset.

### 2.12 Bandwidth token bucket starves any rate below one transfer unit (OPEN, Low — latent)

`internal/bandwidth/bandwidth.go` caps `tokens` at `maxTokens`, and
`newTokenBucket` sets `maxTokens = refillRate`. A bucket can never admit a call
larger than its capacity, so any single `consume(n)` with `n > rate` is refused
**forever**, not throttled. Measured directly: a 1000 B/s policy asked for
32 KiB (the `io.Copy` buffer size class) saturates at `tokens=1000.0` and
returns false on every attempt, with 10 s of simulated accrual between calls.
Every existing test keeps the ask at or below capacity, so the case is
unexamined rather than accepted; the API and `ReplaceAll` both admit a 1 B/s
policy (no `minimum` in `openapi.yaml`).

Latent today because `AllowBytes`/`FindPolicy` have **no caller on the request
path** — the PX-7 row (`bandwidth_health.go`) already tells operators that
configured QoS does not enforce. It is recorded because PX-7 says the policies
are stored and synced *"for a future enforcement release"*, and this is a trap
laid for that release: a 1 KB/s policy would blackhole a node group instead of
slowing it. Fix shape: floor the bucket **capacity** (not the rate) at a named
`MaxTransferUnit`, leaving the starting balance at one second of rate so no
policy gains a startup burst. Drafted and measured during this round, then held
back to keep this PR to one topic.

Also recorded, same file: `Add` rejects `MaxBytesPerSec < 0` but `ReplaceAll`
(the CP→DP sync path, `controlplane_snapshot.go:1781`) validates nothing, so a
negative rate pushed from the control plane becomes "unlimited" rather than a
refusal, and duplicate names / F10 priority conflicts the local API would reject
are accepted. **Checked and cleared:** `ReplaceAll` resetting every bucket is
*not* a per-poll limiter reset — `GetConfig` returns an unchanged sentinel and
the DP returns before `applyConfigSnapshot` when the version has not advanced,
so a rebuild happens only on a real config change.

### 2.13 Lower-severity rows

* **`reqlog.ReadPersistent`** allocates a fixed 40,000-element (~8 MB) parse
  buffer on every cache miss regardless of file size and then retains it for the
  life of the process (`internal/reqlog/reqlog.go:257-258`, `:282-292`); error
  and `IsNotExist` returns never populate the cache, so a persistently failing
  read re-pays `Sync()` + re-open per poller. GC/latency pressure, not an OOM
  path; one-line fix (`slices.Clip`, or size the `make` from the file size).
* **`hashcache.SetTTLUnless`** invokes a caller-supplied `keep` callback while
  holding the cache's exclusive write lock (`hashcache.go:184-191`). The only
  production caller is pure, so there is no live defect, but the doc comment
  never states the constraint, and one future `keep` that touches the cache
  self-deadlocks while holding the write lock and wedges the whole scan path.
  Documenting the constraint is the right fix — snapshot-and-re-verify reopens
  the race the function exists to close.
* **`internal/authstate`** never received the generation-marker half of
  `identcache`'s PR #1633 fix (`authstate.go:245`, `:313-318` vs
  `identcache.go:495`'s `e.pos == b.head`), whose own comment names authstate as
  sharing "the identical trap". Latent only: both production stores key on 128
  bits of CSPRNG output, so key reuse is not constructible. Worth closing (one
  `pos` field) before any caller-influenced key is added.
* **`events.Manager.Close`'s `domain.closed`** is written and never read, so the
  contract line *"Close stops accepting work"* is false; `Spool` has no `Close`
  at all, making `mcp_telemetry.go:347`'s comment inaccurate. Low practical
  impact, but it is the declared-control-with-no-enforcement shape the repo's
  anti-drift walls exist to catch.

---

## 3. Risk matrix

| # | Risk | Likelihood | Impact | Status |
|---|---|---|---|---|
| C127 | A resolved poison marker quarantines the healthy replacement store and `pruneQuarantines` deletes the genuine evidence | Medium (any crash in the quarantine window; or an operator deleting the directory beside a stale marker) | High (loss of a retained compliance artifact + destruction of the corruption evidence) | **FIXED** — measured, §2.1 |
| M-1 | MCP critical-durability breaker has no production closer; one commit failure wedges every write/destructive call, across restarts | Medium **given MCP is enabled** (one ENOSPC/fsync/quota event); MCP is off by default | High (permanent write-path outage; health row reports `clean`) | **OPEN** — §2.2 |
| M-2 | Sealed P-CRIT segments are never reclaimable, so M-1 fires from ordinary traffic volume alone | Medium-High given MCP enabled (time + volume) | High (same wedge, self-inflicted) | **OPEN** — §2.3 |
| M-3 | `reclaimLocked`'s `stuck` verdict discarded on the commit path, so the documented §4b.4 graded warning never fires | High given M-2 | Medium (no early warning; first symptom is the hard wedge) | **OPEN** — §2.4 |
| U-1 | An `unhealthy` probe verdict has no automatic clearing path in the shipped default config; a recovered parent stays ineligible | Medium (operator probes during an outage, `health_interval` unset) | Medium-High (parent-proxy chain bypassed → DIRECT egress; **visible** via `checkUpstreamEgress` + alert + metric) | **OPEN** — §2.5 |
| U-2 | A panic in the manual probe strands `manualInflight`, permanently destroying the only recovery lever in the default config | Low (needs a panic in `HealthCheck`) but the repo already judged that path panic-prone (CHAOS-24) | Medium-High (compounds U-1 into restart-only recovery) | **OPEN** — §2.6 |
| U-3 | Half-open admits unbounded concurrent traffic instead of one probe: ~30 s total plain-HTTP stall per breaker cycle against a black-holing parent, forever | Medium (any black-holing parent) | Medium (recurring availability loss on a parent already known dead) | **OPEN** — §2.7; a naive fix introduces a worse wedge |
| U-4 | Culvert's own 30 s whole-exchange cap is charged to the parent's breaker, so large legitimate downloads eject a healthy parent | Low-Medium (needs 5 consecutive >30 s bodies) | Medium (self-inflicted egress-control bypass) | **OPEN** — §2.8; policy is deliberate, this interaction is not |
| S-2 | `BeginAttempt` failing to arm is silent and unreportable, switching off crash-loop protection with no signal | Low-Medium (a plausible container permission layout) | Medium (the permanent crash loop this package exists to break) | **OPEN** — §2.9 |
| A-1 | Identity-cache token-`exp` clamp defeated across a VM suspend / snapshot restore (running-time deadline) | Low (needs a suspend/restore) | Medium (expired/revoked token honoured for ≤ one cache TTL; fail-OPEN) | **OPEN** — §2.10 |
| L-1 | Lockout maps have no total entry cap; distributed stuffing with distinct usernames exhausts memory | Low-Medium (needs a botnet) | Medium (OOM; the restart then clears all lockout state) | **OPEN** — §2.11 |
| B-1 | Token bucket permanently denies any single call larger than the configured rate | n/a today (no caller) | Low now, High for the planned enforcement release (a slow policy blackholes instead of throttling) | **OPEN** — §2.12, measured |

---

## 4. Recovery assessment

| scenario | automatic recovery | manual recovery |
|---|---|---|
| C127 (pre-fix) | none — the marker never expired | delete the stale `.opening.*` marker by hand; the destroyed evidence is unrecoverable |
| C127 (post-fix) | **yes** — the marker is cleared at the first open that finds the store gone; a removal that fails refuses to open a replacement rather than leave one to be destroyed | none needed |
| M-1 / M-2 | **none, and a restart does not help** — the degraded state is persisted and restored verbatim | operator deletes `degraded_state.json` |
| U-1 | none in the default config | `POST /api/upstream/health`, or set `health_interval` and restart |
| U-2 | none | process restart |
| U-3 | partial — the breaker re-opens after the first failure, but the cycle repeats indefinitely | fix or remove the parent |
| S-2 | none — indistinguishable from a healthy open | none available; the condition is invisible |
| A-1 | yes — bounded by one cache TTL after resume | none needed |
| L-1 | the OOM kill itself, which also clears all lockout state | restart |

The pattern worth naming: **four of these are "no automatic recovery, and the
persisted state survives the restart you would reach for"** (C127, M-1/M-2,
U-1, U-2). That is the shape this round kept finding, and it is the shape the
repo's own CHAOS-24 comment already articulated for the periodic health loop.

---

## 5. Operational impact

* **C127:** an operator loses retained request history with no warning and,
  worse, loses the evidence needed to diagnose the original corruption. The
  recovery row reports a quarantine that *looks* like correct behaviour.
* **M-1:** the admin Durability panel reports `recovery_state: "clean"` while
  every write is refused — the single most misleading surface found this round.
* **U-1/U-2:** the bypass itself is **visible** (`checkUpstreamEgress` WARN row,
  `upstream_pool_down` alert, `culvert_upstream_direct_fallback_active`), so an
  operator with the Diagnostics page is not blind. What is missing is that the
  advertised remedy can be permanently unavailable, and that a *partial* loss of
  parents is reported nowhere.
* **S-2:** an operator cannot distinguish "protected" from "unprotected", which
  makes the protection untrustworthy rather than merely absent.
* **B-1:** PX-7 already warns that QoS policies do not enforce; nothing warns
  that a rate below one transfer unit would blackhole rather than throttle once
  they do.

---

## 6. Security impact

* **C127** destroys forensic evidence of a storage fault — an integrity and
  investigability loss, not a confidentiality one. No authentication,
  authorization or policy decision changes.
* **U-1 / U-4** are the security-relevant upstream rows: both end with
  plain-HTTP traffic egressing **DIRECT**, bypassing the enterprise
  parent-proxy chain that an organization may rely on for logging, DLP or
  egress filtering. The posture is a deliberate fail-open (PX-2/CHAOS-11); the
  defect is that it can be entered and then never left.
* **A-1** is a genuine fail-open on a credential path: a revoked or expired
  bearer token is honoured after a resume for up to one cache TTL. Bounded, but
  it contradicts the clamp's own written contract.
* **L-1** chains memory exhaustion into the loss of all brute-force state;
  ranked on the exhaustion because the lock window is only 15 minutes.
* **M-1/M-2** fail **closed** (writes are refused), which is the right
  direction — the defect is availability and the absence of recovery, not a
  bypass.

---

## 7. Suggested improvements, in the order I would do them

1. **Wire a bounded `RecoverProbe` tick** into `telemetryRuntime.Start` beside
   `flushLoop` (§2.2). This alone converts a permanent outage into a
   self-healing one, and it is the highest-value change available in the tree.
2. **Call `sp.MarkExported(part, segID)` after `cursors.Advance` succeeds** in
   `exportStep`, or adopt `export.Pump` with `OnAck` wired to it (§2.3).
3. **Consume `reclaimLocked`'s `stuck` return in `Commit`** and map it to
   `OnCriticalCommitFailure` per EVENT-MODEL.md §4b.4 (§2.4).
4. **Fix `recoveryStateLabel`** so `RecoveryAttempts == 0` with a degraded
   critical track cannot report `"clean"` (§2.2).
5. **`defer upstreamPool.EndManualProbe()`** in `apiUpstreamHealth` (§2.6) —
   one line, no posture change, and it protects the only recovery lever the
   default config has. *This is the smallest high-value fix in the report.*
6. **Decide the probe-verdict recovery posture** (§2.5): either expire a stale
   `unhealthy` verdict so the breaker governs again (deterministic, no new
   goroutine, degrades to the pre-probe behaviour), or arm the health loop with
   a default interval, or let SIGHUP arm it. This is a posture choice, which is
   why it is not taken here.
7. **Bound half-open admissions with a self-healing window** (§2.7), *not* a
   bare single-flight token.
8. **Add `Recovery.MarkerArmed`** and log it once at startup (§2.9).
9. **Give `identcache` a clock seam and an absolute-instant deadline** for the
   `exp`-clamped entries (§2.10), leaving `lockout` on monotonic.
10. **Floor the bandwidth bucket capacity at a named `MaxTransferUnit`** before
    enforcement is wired, and validate `ReplaceAll` the way `Add` validates
    (§2.12).

---

## 8. Already resilient — verified, do not re-sweep

* **SSE fan-out and handler.** The hub caps connections, evicts slow clients
  and counts both (`internal/sse/sse.go`); the handler sets a per-frame write
  deadline via `http.NewResponseController` (`sseWriteTimeout`, 10 s) under a
  comment naming the half-open-TCP peer exactly, returns on a closed channel
  rather than busy-spinning, and revalidates auth mid-stream. The
  goroutine-and-FD leak I went looking for is closed.
* **MCP request path (`runtime/`, `execution/`).** `ReadHeaderTimeout` 5 s;
  the request deadline is pushed down to the socket with
  `SetReadDeadline` so a stalled POST body cannot hold a worker slot;
  `limitListener` caps sockets; `connBudget` caps per-connection in-flight
  requests against HTTP/2 amplification. All four `limits` bounds are enforced
  at the growth site (`MaxSessions`, `MaxOutstandingPerSession`,
  `MaxTotalOutstanding` via a CAS loop, `SessionTTL` via a real `sweepLoop`
  reaper). Session ids are server-minted from `crypto/rand`. Slot
  increment/decrement pairing holds on every exit path including
  `ctx.Done()`. A `limits_ownership_test.go` AST wall forces every bound to
  declare `enforcedHere`/`delegated`/`reserved` with a reason.
* **`internal/mcp/limits`** is immutable, hard-capped and fully validated.
* **Upstream transport mutation safety.** Every production mutation goes
  through `swapUpstreamTransport` and returns a *new* transport from
  `cloneTransport`; the `upstreamOpTLSCfg` template is mutated only under
  `upstreamTransportWriteMu` and never published. No violation of the
  conventions rule anywhere in the tree.
* **`internal/upstream` retries and black-hole timeouts.** No retry loop and no
  hidden re-dial exists at all. `TLSHandshakeTimeout` 10 s,
  `ResponseHeaderTimeout` 30 s, a 30 s request context, and the probe path
  carries both `client.Timeout` and a context deadline with
  `DisableKeepAlives`. A corrupt upstream config fails closed to an unpublished
  pool and is surfaced by a dedicated latched WARN row — I filed that as a
  silent bypass first and then disproved it.
* **`internal/reqlog` locking and panic containment.** Three lock orders, no
  cycle, no lock held across I/O, and `publishDeferredSink` exists specifically
  to avoid straddling `writerMu`. `drainLoop` is guarded per *round* with
  `obs.ReportPanic` — the one case `internal/obs/guard.go` calls out by name.
* **`internal/keyedmutex` / `internal/writerlock`.** Refcounting is exactly
  correct (an entry cannot be replaced while `refs > 0`, and each refcount
  reaches 0 once). `writerlock.Take` turns a read-only volume, `EACCES` or
  `ENOSPC` into `Undetermined` + `Cause` and never into `Held`, non-blocking,
  so a live holder cannot hang startup.
* **`internal/hashcache` capacity.** Keyed on the SHA-256 of attacker-supplied
  content but hard-capped: map and expiry heap cannot desync, so the cap cannot
  be bypassed.
* **Clock skew across the auth packages.** No wall-clock `int64` interval
  anywhere in `lockout`/`authstate`/`identcache`/`authcost`, so the CHAOS-84
  negative-elapsed class does not apply; TOTP necessarily uses the wall clock
  and fails **closed** under a rollback (every candidate ≤ `lastCounter` is
  skipped). §2.10 is the one direction left, and it points the other way.
* **`buildOperatorContract`.** The side-effect contract is explicit and
  bounded: no writes, cached/atomic/RLock reads plus enumerated bounded
  read-only file access, and at most one coalesced ClamAV ping with a bounded
  wait. The health endpoint cannot hang on a dependency.
* **`fileutil.AtomicWrite`.** The CHAOS-45 failure-and-success observer seam
  means the dozen error-discarding `Save()` call sites cannot fail silently.

---

## 9. Required tests

Shipped with this round (`internal/storeguard/poison_missing_store_chaos127_test.go`),
all four RED on the pre-fix tree and green after:

| gate | property |
|---|---|
| `TestChaos127_AbandonedMarkerForAMissingStoreIsCleared` | a marker whose store is gone is cleared, not reported as a phantom recovery |
| `TestChaos127_StaleMarkerDoesNotQuarantineTheRebuiltStore` | end to end: the rebuilt store survives the next open **and** the original evidence is not pruned |
| `TestChaos127_UnclearableMarkerForAMissingStoreStopsRecovery` | a marker that cannot be removed refuses to open a replacement, matching `clearFault`'s contract |
| `TestChaos127_FaultMarkerBesideAResolvedPoisonMarkerIsAlsoCleared` | the shadowed fault marker is cleared too, so it cannot quarantine the replacement by itself |

Pre-fix control run, measured: open 1 →
`trigger=poison_marker quarantined=false skipped="no store directory present"`,
marker kept; open 2 → `quarantined=true`, healthy store renamed to
`store.corrupt.<T2>`, original evidence survived = **false**.

Owed by the open rows:

* MCP: a gate that the production telemetry runtime calls `RecoverProbe`, and
  one that a degraded domain returns to normal without operator action; a gate
  that `exportStep` marks a segment exported after a cursor advance; a
  saturation gate driving P-CRIT to the high watermark and asserting the §4b.4
  graded transition fires before the hard refusal.
* Upstream: a gate that a panicking manual probe leaves the latch released and a
  second POST admissible (needs an injectable probe seam in `main`, the pattern
  `rewriteIdentityAtomicWrite` already uses); a gate that a second concurrent
  `Allow()` in half-open is refused; a gate that a >30 s body through a healthy
  parent does not open the breaker.
* `storeguard`: an arming-failure gate asserting the new `MarkerArmed` signal.
* `identcache`: a clock seam, then a suspend-equivalent gate (a wall-clock step
  cannot express this fault).
* `bandwidth`: the oversized-ask gate, plus a long-run average-rate gate proving
  the capacity floor does not inflate throughput.

---

## 10. Residual risk

**The fix in this round is narrow by choice.** It closes the missing-directory
case in the poison branch. It does **not** change the best-effort marker
removal at the end of `recoverBeforeOpen`, which runs after a *successful*
quarantine: if that `os.Remove` fails there, the surviving marker will
quarantine the fresh replacement at the next open — the same destructive shape,
reached by a different route. It is left because the accused directory has
genuinely been moved aside by then, the removal is of a file in a directory the
process just wrote to, and converting it to fatal changes the outcome of a
quarantine that otherwise succeeded. Recorded so the asymmetry is a decision.

**`MaxQuarantinedCopies = 1` is what turns a wrong quarantine into data
destruction.** The constant is deliberate and reasoned ("a host that keeps
producing corruption must not fill the volume with evidence"), and this round
does not revisit it — but it is worth stating plainly that with a single
retained copy, *any* future bug that quarantines a healthy store destroys the
previous evidence. A floor that never prunes the OLDEST copy while a newer one
was created in the same process lifetime would decouple the two, and is a
cheaper insurance policy than auditing every future quarantine trigger.

**The MCP rows are the real residual risk of this report, not of this PR.**
They are three unwired production hooks whose absence composes into a permanent
write-path outage, in the one large subsystem with no chaos coverage. This round
verified the two load-bearing claims directly (`RecoverProbe` and
`MarkExported` each have exactly one non-test occurrence — their own
definition) and confirmed the contrast that makes them gaps rather than
decisions: `execution/recovery.go:457-464` documents its own unwired state and
pins the precondition, while these two carry no such note. They are not fixed
here because each needs a new background loop or a change to the export
protocol's ack semantics, under an owner who holds EVENT-MODEL.md.

**Severity is bounded by MCP being disabled by default**, and that bound is
load-bearing in the risk matrix above. If a release ever enables the MCP
gateway by default, M-1/M-2 become default-config outages and should be treated
as release blockers.

**Two findings in this report are latent rather than live** (§2.12 bandwidth,
§2.13 authstate), and both are recorded precisely because the right time to fix
a trap is before the caller that springs it is written. Neither should be
presented as a current customer-facing defect.
