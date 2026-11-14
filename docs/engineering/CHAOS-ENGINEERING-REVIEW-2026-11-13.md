# Chaos Engineering Review — 2026-11-13

*Round claimed and based on 2026-11-13 (`origin/main` `feb11e8`); verification
and this write-up completed 2026-11-14. Dated by the claim, as the register's
other rounds are.*

## CHAOS-119 — The containment plane's reporting boundary: a shutdown drain that can kill the shutdown, five rounds nothing counted, and a cap half the size of its own label set

**Scope.** The SIMULATE list's *Silent failures*, *SIGTERM*, *Unexpected
restart*, *Power loss*, *Recovery failures*, *Monitoring visibility* and
*Logging quality* rows, applied to the **panic-containment plane itself** — not
whether a background fault is contained (CHAOS-24/105/116/117/118 answered
that), but whether an operator can see that it happened, and what the one
remaining unguarded detached goroutine costs.

**Status.** Fixed, in three parts. §2 closes CHAOS-118 §7.1. §4 closes
CHAOS-118 §7.2 and its residual risk `4`. §3 is a new finding this round's own
gate forced out. §5 records what was reached and not fixed, including
CHAOS-118 §7.3, which remains open with a reason.

**Closes.** CHAOS-118 §7.1 (the `telemetryRuntime.Close` drain goroutine);
CHAOS-118 §7.2 and residual risk `4` (the mechanical discovery gate).
CHAOS-118 §7.3 and §7.4 are untouched and remain open as written.

---

## 1. Executive summary

Line references are at the base revision `origin/main` `feb11e8`.

Five rounds of this family have established one rule: Go terminates the process
on an unrecovered panic in **any** goroutine, so every detached background round
runs under `runGuarded`. That rule is about **containment**. This round asked
the question one step downstream — *and then what does the operator see?* — and
the answer was "nothing", in three different ways, each with a different cause.

**CHAOS-119a (HIGH) — the one detached goroutine still outside the guard is in
the worst place it could be: inside a graceful shutdown, at a hook that runs
before every durability flush.**

`telemetryRuntime.Close` (`mcp_telemetry.go:315`) does its final denial flush,
its full export drain and its manager close inside its own bare `go func()`.
The drain calls `t.drainPartition` → `t.exportStep` — **the same `exportStep`
that `exportLoop` has guarded under `crashComponentMCPTelemetryExport` since
CHAOS-118**, whose own comment says it "reads the encrypted spool and calls out
to the archive exporter, both fed by data this process does not author". The
identical call was contained on the periodic path and process-fatal on the
shutdown path.

What a panic there costs is set by *where in the shutdown sequence it lands*.
`mcp-telemetry-drain` is registered at order **66**. Everything from 67 to 140
was still unrun:

| Order | Hook | What a process death at 66 costs |
|---|---|---|
| 67 | policy-learning flush | lazily-flipped session state lost |
| 70 | admin UI shutdown | no quiesce |
| 80 / 90 | SOCKS5 + proxy listener stop | abrupt |
| 94 / 95 | tunnel establish fence, H2 GOAWAY | no fence, no GOAWAY wave |
| **100** | **tunnel drain** | **every in-flight client tunnel severed instead of drained** |
| 110-140 | syslog, community DB, log store, request log, **audit log**, log closer | the FLUSH hooks |

Those last ones are not incidental. `shutdownFlushBoundary` exists because
CHAOS-56 carved a reserve for them, and `main_shutdown.go:205-209` says why:
"abandoning one costs durability or leaves a store the next boot has to
quarantine". A panic did not *abandon* them — it skipped them.

And it is worse than a hook that crashes, because the goroutine is **detached**
while `Close` selects on the shutdown budget. If the hook is abandoned on its
deadline, `Close` returns, the sequence advances, and the orphan goroutine is
still inside `drainPartition` or `mgr.Close()` with no guard. The panic then
lands during an *unrelated later hook* — the tunnel drain, or the audit-log
close — so the crash is attributed to whatever happened to be running.

Measured, by reverting the fix (mutation A in §6): the test binary dies with
`SIGSEGV`. That is the whole finding; there is no in-process "before"
assertion to make, because the before state is a dead process.

**CHAOS-119b (MED) — five background rounds were contained by a bespoke
`recover()` that logs, so the containment was real and the reporting was
absent.**

The crash plane is not decoration: `recordCrash` is what moves
`culvert_crash_records_total{component}`, stores the bounded `lastCrash` record
the support bundle and the health surface export, and writes the system-actor
audit entry. CHAOS-118's residual risk `1` says so directly — "the crash
counters **are** the signal". These five rounds never reached it:

| Round | File | What a silently panicking round meant |
|---|---|---|
| `refreshLoopTick` | `release_refresh.go:72` | catalog refresh **and**, through `runRefresh`, the freshness watchdog both frozen |
| `staleWatchdogTick` | `release_refresh.go:123` | on a disabled-fetch (air-gapped) or break-glass appliance, the **sole** driver of `release_catalog_stale` — the CHAOS-23 defect, reachable again |
| `saasFeedScheduler.runTick` | `saas_feed_scheduler.go:162` | a feed whose parse panics every round backs off to its ceiling, indistinguishable from an unreachable origin |
| `ConfigStore.retryCPAddrPublish` | `cp_addr_publish.go:582` | **worker-level** recover: one panic ends republication for the whole episode |
| `retryLeadershipResume` | `cluster_startup.go:195` | **worker-level** recover; its own log line states the cost — "the node stays HA-gated until restarted" |

The last two are the CHAOS-105 anti-pattern by construction — a recover at the
top of the worker, not around one round — and both are deliberate, because each
clears a latch on the way out. What was not deliberate is that neither left any
evidence distinguishing "the retry stopped because it succeeded" from "the
retry stopped because it died". For the HA one that distinction is the whole
operator question: a node serving with no write authority until someone
restarts it.

**CHAOS-119c (MED) — and then the gate for §3 found that even a correctly
reported component could be suppressed, because the sink's label cap was half
the size of its own fixed label set.**

`maxCrashLabels` was **32** (`crashguard.go:57`). A source enumeration over the
module counts **56** distinct fixed component labels at the base revision — 24
over the cap before this round added anything, and **63** after it. The cap's own comment explains it as a defence
against a "flood of dynamic components" — and Culvert has none:
`crashRecord.Component` calls itself a "fixed enum" and it is, every call site
passing a compile-time constant or literal.

Past the cap the two overflow behaviours are **not** equivalent, which is what
makes this a reporting defect rather than a metrics nicety:

- `crashCounter.record` (`crashguard.go:310`, the fold at :315) **folds** the label into
  `"other"`. The series survives; attribution is lost.
- `crashThrottleAllow` (`crashguard.go:178`) **suppresses** outright: no crash
  record, no crash log line, no audit entry. Only the unlabeled total and
  `culvert_crash_records_suppressed_total` move.

Slots are **first-crash-wins and never pruned**, so on a long-lived node the 32
go to whichever components crash most often — in practice the request-path ones
(`proxy`, `admin`, `socks5-relay`, `tunnel-relay`, `geo`, `dpi-match`,
`yara-match`) — and the components that lose their record are the rare,
high-severity background rounds this family has spent five rounds adding. That
is exactly inverted from what an operator needs, and every round that adds a
component makes it likelier.

**CHAOS-119d (MED) — the registry this family depends on is no longer
hand-written.**

CHAOS-118 §7.2 asked for "a **mechanical** discovery gate — one that finds
every `go`-detached loop in the package and fails if it is not registered", and
its residual risk `4` put the honest version plainly: "Eleven workers are
registered because eleven were noticed." This round built it, and the gate
immediately justified itself twice:

- It found `Refresher.RunTicker` (`release_catalog_refresher.go:156`): a round
  loop driving a verify → persist → publish cycle over third-party catalog
  bytes, with **no containment and no production caller**. Its own doc says
  "the CALLER decides whether to run it in a goroutine", so it is a trap armed
  for whoever wires it next. Guarded now, while guarding it still costs
  nothing.
- Its own first draft searched the loop's *text* for `ticker.C` and missed
  **thirteen** loops that name their ticker `t`. That is why the shipped
  version matches the select **arm** structurally. A gate built on a naming
  habit is a gate that passes by accident.

---

## 2. CHAOS-119a — the shutdown drain

### 2.1 What changed

`Close`'s goroutine is now three guarded stages rather than one bare sequence,
and the staging is the design decision, not an implementation detail:

```go
drainPanicked := runGuarded(crashComponentMCPTelemetryDrain, func() {
    t.mgr.FlushDenialsForce(evmodel.CapGateway)
})
for _, part := range gatewayPartitions {
    if runGuarded(crashComponentMCPTelemetryDrain, func() { t.drainPartition(ctx, part) }) {
        drainPanicked = true
    }
}
var closeErr error
if runGuarded(crashComponentMCPTelemetryDrain, func() { closeErr = t.mgr.Close() }) { ... }
done <- closeErr
```

Three properties, each of which a plausible simpler fix would have lost:

1. **Per stage, not per sequence.** `mgr.Close()` is the durability-critical
   step — it performs its own final per-domain denial flush and closes the
   encrypted spool. One guard around the whole sequence would let a fault in
   the force-flush, or in *one* partition's drain, skip it. (Mutation B2, §6.)
2. **Per partition, not per loop.** One partition's fault costs that
   partition's pending batches, which stay committed in the spool and export on
   the next start. It does not cost the other partitions' drains. (Mutation B.)
3. **`done` is answered on every path.** A stage that panicked without sending
   would park the hook until the shutdown context expired — starving exactly
   the hooks the hook's own comment says it exists to protect ("honor the
   shutdown budget so later hooks are never starved").

### 2.2 Why the CHAOS-105 objection does not apply here

CHAOS-105 argues against a whole-worker recover because it converts a loud
crash into a silent permanent stall: the loop RETURNS and never ticks again.
This sequence is **one-shot and terminating**. There is no next tick to lose,
so there is no stall to convert a crash into — which is why a staged recover is
the right shape here and the wrong shape in `retryLeadershipResume`.

### 2.3 Fail-closed, not fail-quiet

The drain reports failure rather than a clean shutdown. A graceful-shutdown log
line that claims success while evidence stayed unexported is the silent-failure
shape this round is about. Nothing is lost: the spool is durable and
`exportStep` advances the cursor only after the archive durably accepts a whole
batch, so pending batches export on the next start.

---

## 3. CHAOS-119b — containment without reporting

Each of the five rounds keeps its existing `recover()`, its existing log line
and its existing outcome semantics, and additionally calls `recordCrash` under
its own component. The diff is deliberately that small: the containment
decisions were already correct and reviewed (CHAOS-R1, CHAOS-23, and the
latch-clearing contracts in the two worker-level cases), so this round changes
what is *reported*, not what is *contained*.

`recordCrash` is safe to call from inside a recover, which is the precondition
for adding it to five live loops: it has its own inner recover and can never
re-panic, it increments the counter before it throttles, and it is
per-component rate-limited at one heavy emit per second so a deterministically
panicking round cannot flood the SIEM or evict the shared audit ring.

The two worker-level recovers are left worker-level. Converting them to
per-round guards would change their exit contracts — `retryCPAddrPublish`
clears `retrying` so a later failure starts a fresh loop, and
`retryLeadershipResume` leaves the node HA-gated on purpose — and that is a
behaviour change needing its own round, not a rider on a reporting fix. What
they get here is the evidence they lacked.

---

## 4. CHAOS-119d — the mechanical gate

`chaos119_round_loop_registry_test.go` discovers background round loops from the
AST and fails on one it does not recognise. The direction is the point: the
inventory is now checked against the tree, where before the tree was checked
against the inventory.

**The shape it matches.** A `for` containing a `select` with ≥2 communication
clauses, where one arm is a cancellation receive (a call to a method named
`Done`, or a receive from a `stop`/`quit`/`shutdown` identifier) and another is
a timer receive (a receive from a `.C` field, a `.C()` clock-seam accessor, or
`time.After`/`time.Tick`). Both arms are required: a cancellation arm alone is
a wait, and a timer arm alone is a loop nothing can stop — a different defect
with its own gates.

**What it deliberately does not cover.** Every detached goroutine. The package
has 93 `go` statements, most of them request-scoped relays and alert fan-outs
already served by their own planes (`proxyCrashGuard`, `recoverGoroutine`, the
relay defer). A 43-row exemption list for those would be churn, and a gate
people delete is worth less than a narrow one they keep. The honest boundary is
therefore: **round loops are now discovered mechanically; other detached
goroutines are not**, and §5.2 records that.

**It fails both ways.** An unregistered discovered loop fails; a registered row
the pass no longer finds fails too, so a renamed or deleted loop cannot leave a
stale row behind. It also carries its own negative control
(`TestCHAOS119_DiscoveryPassRejectsAnUnguardedLoop`), which writes a synthetic
ticker loop to a temp directory and asserts the pass finds it — because a
discovery gate that cannot be shown to find anything makes every other
assertion in the file vacuous.

**36 round loops are registered**, each naming the guard token its body must
contain, so the chain from loop to containment is written down rather than
inferred. Rows that are not detached name the caller that owns containment
instead (a shutdown hook whose registry recovers per hook; an inner retry whose
every caller is already inside a guarded round).

---

## 5. Also reached this round, NOT fixed

**5.1 `feedsched.Config.OnPanic` is defined, documented and wired by nobody.**
`internal/feedsched/feedsched.go:196` declares `OnPanic func(v any)` —
"invoked when a round panics, before it is charged as a failure" — and
`round()` calls it at line 381. A tree-wide search finds **zero** production
call sites that set it, so every panicking feed round falls to the `obs.Warnf`
branch, which does not reach `reportPanic` and therefore does not reach the
sink. This is a latent seam rather than a live defect, and the reason is worth
recording: the two loops that matter already wrap their own `Run` in
`obs.SafeCall` (`feedsync.go:413`, `threatfeed.go:306`), which *does* reach the
sink, so `feedsched`'s recover is a second-level backstop that production
rarely reaches. It becomes a live gap the moment a feed is added without that
wrapper — which is exactly how CHAOS-108 found `blocklistfeed` outside the
scheduler the package doc claimed covered it.

**5.2 `feedsched.Run` calls `RunNow` outside any guard.**
`Run` consults `s.cfg.RunNow()` before entering `loop`, and for `feedsync` that
closure is `func() bool { return fs.db.Stats() == 0 }` — a BadgerDB call. A
panic there is process-fatal and outside both the round guard and the
`obs.SafeCall` inside `Run`. Narrow (one handle read) and not fixed here
because it belongs to `internal/feedsched`'s own contract, not to main's crash
plane; recorded for the round that takes the scheduler.

**5.3 CHAOS-118 §7.3 — the mechanical §8.2a lock-pairing audit — remains
open.** §4's gate covers *discovery* of round loops; it says nothing about
whether a guard placed over a critical section strands a mutex. That gate needs
a call-graph walk asserting "for every registered worker, no lock acquired in
its round's call graph is released by a bare trailing `Unlock`", which is a
different and larger build than the one here, and it has its own correctness
question (resolving a defer's owning scope — CHAOS-118 residual `5`). The two
gates belong in the same family and not in the same round.

**5.4 CHAOS-118 §7.4 is unchanged.** `UpdateNodeSeen` and `RegisterNode` still
release `cs.mu` with a trailing `Unlock`. Still not reached from a guarded
round, so the trap still does not apply.

**5.5 The non-loop detached goroutines are still found by reading.** §4's gate
is scoped to round loops by design (§4). The 43 `go` statements whose target
does not obviously reach a guard within two hops were triaged by hand this
round and are covered by their own planes, but that triage is a reading, not a
gate.

---

## 6. Mutation results

Every assertion in this round was falsified before it was trusted.

| # | Mutation | Caught by | Result |
|---|---|---|---|
| A | revert `Close` to the bare unguarded sequence (the pre-fix shape) | `TestCHAOS119_ShutdownDrainPanicIsContainedReportedAndBounded` | test binary dies with `SIGSEGV` — the defect, reproduced |
| B | hoist the per-partition guard outside the loop | `TestCHAOS119_DrainIsStagedSoManagerCloseStillRuns` | `crash records = 1, want >= 3` |
| B2 | skip `mgr.Close()` when the drain panicked, returning the same sentinel | `TestCHAOS119_ManagerCloseStageIsGuardedAndUnconditional` | caught — see below |
| C | drop `recordCrash` from `refreshLoopTick` | `TestCHAOS119_EveryContainedRoundReportsIntoTheCrashPlane` | caught, both assertions |
| D | restore `maxCrashLabels` to 32 | `TestCHAOS119_FixedCrashLabelSetFitsTheCardinalityCap` | `63 fixed labels but maxCrashLabels is 32` |
| E | unguard `exportLoop` | `TestCHAOS119_EveryRegisteredRoundLoopHonoursItsGuard` | caught |
| F | add a synthetic unregistered ticker loop | `TestCHAOS119_EveryBackgroundRoundLoopIsRegistered` + its own negative control | caught |

**Mutation B2 is the one worth recording, because it falsified this round's own
first design.** The staging test originally claimed that the returned error's
identity proved `mgr.Close()` had run — "the drain sentinel is produced only by
the branch reached after a successful manager-close stage". A mutant that
skipped stage 3 and returned the *same string* from an earlier branch passed
that test. The claim was false, so it is withdrawn: there is no observable of a
closed `events.Manager` from outside `internal/mcp/events` (`closed` is written
and never read, and the final denial flush has nothing left to commit once
stage 1 has force-flushed the open window). Stage 3's execution is therefore
pinned **structurally** — its own guarded, unconditional stage, with no `return`
between the drain and it — and the review says so rather than implying the
behavioural test covers it. Same honest framing as CHAOS-118 residual `3`.

---

## 7. Residual risk

1. **`maxCrashLabels` is now 128 and the invariant is a gate, not a design.**
   Nothing in the sink *derives* the cap from the label set; a test asserts the
   set fits. That is the right trade — the cap must stay a hard bound for a
   genuinely dynamic label, which is what it is for — but it means the gate is
   the only thing standing between a future round and a silently suppressed
   component. The gate fails loudly and names the remedy, which is the best
   available answer short of making the component type a closed enum.

2. **A node that has already burned 128 slots loses records the same way.** The
   fix moved the ceiling above the known fixed set with headroom; it did not
   remove the ceiling, and the throttle map is still never pruned. A caller
   that derives a component name from request data would still exhaust it — and
   would still be right to be failed closed. No such caller exists today
   (§3's enumerator counts fixed labels precisely because it cannot count
   dynamic ones), and nothing asserts one is never added.

3. **The contained shutdown drain is a new reachable state.** Before this
   round a panicking drain killed the process; now it returns an error and the
   shutdown continues. That is strictly better for the 74 hook-orders
   downstream, and it does mean a node can complete a "graceful" shutdown with
   pending MCP evidence unexported. The error is returned and logged, the crash
   record names `mcp_telemetry_drain`, and the evidence itself is durable in the
   encrypted spool — but **no alert rule ships on the crash counters**, which is
   CHAOS-116 residual `4`, CHAOS-117 residual `5` and CHAOS-118 residual `1`,
   now recorded for a fourth round. The series is cumulative and the rule
   belongs with the operator's alerting; that it keeps being recorded rather
   than fixed is itself the finding.

4. **The five §3 rounds can still fail forever while the node reports
   healthy.** Reporting a contained panic is not the same as acting on one.
   `retryLeadershipResume` in particular still leaves a node HA-gated until an
   operator restarts it; what changed is that the operator can now find out why
   from a counter and a record instead of one log line. The recovery path is
   unchanged and is still a restart.

5. **The discovery gate matches a shape, and a loop can leave the shape.** A
   round loop rewritten to wait on a `time.Timer` stored in a struct field read
   through a method other than `C`, or to take its cancellation from a
   differently-named channel, would stop being discovered — and the gate's
   both-ways check would then flag the row as stale rather than flag the loop as
   unguarded, which is the less useful of the two failures. The shipped matcher
   covers every shape in the tree (verified: 36 loops, three of which the
   textual first draft missed), and the honest statement is that it covers the
   shapes that exist, not every shape that could.
