# Chaos Engineering Review — 2026-11-08

## CHAOS-114 — The scan sidecar that will not stay: a flap is invisible to every signal built for a socket that will not come back

**Scope.** The SIMULATE list's *unexpected restart*, *OOM*, *ClamAV
unavailable* and *broken retries* rows, aimed at the supervision surface
CHAOS-113 shipped the day before.

**Status.** One defect found, reproduced on this tree before any fix, fixed.
Two further findings are about the FIX rather than the defect: the remedy
CHAOS-113 §10.4 prescribed for this gap is, measured, nearly a no-op, and the
obvious step after it introduces a regression that pages forever on a slow
redeploy. Both are recorded with their measurements, because the prescription
was this register's own and a later round would otherwise take it on trust.

**Closes.** CHAOS-113 §8.7 / §10.4 — that round's own recorded residual risk
`4`, which it called "the sharpest remaining gap and it is in this round's own
design".

---

## 1. Executive summary

CHAOS-113 gave the scan sidecar's listener everything the other three
listeners have: a rebind ladder, an `up` gauge, bind and serve-exit counters,
an operator-contract row, a `/healthz` word, a report-only `/ready` row and a
subscribable alert. Every one of those surfaces was keyed on one predicate:

```go
func (s scanSvcListenerSnapshot) Unavailable() bool {
        if !s.Configured || s.Bound || s.Stopped {
                return false
        }
        return s.FailingFor >= scanSvcUnavailableAfter
}
```

*Not bound, for longer than the threshold.* That is the right predicate for a
socket that **will not come back**. It is blind to a socket that **will not
stay**.

A flapping sidecar — one that binds, serves for a moment and dies, over and
over — binds **successfully on every cycle**. So:

- `Unavailable()` short-circuits on `s.Bound` and reads healthy for the whole
  of every serve generation, and
- `maybeAlertScanSvcDown` is only ever called from `scanSvcBindOnce`'s
  **failure** path, which a flap never reaches at all.

**Measured on this tree before any fix**, replaying what
`superviseScanSvcListener` does for a sidecar whose serve dies after 10 ms,
twenty cycles across ~10 minutes of virtual time:

```
alerts fired            = 0
serve_exits             = 20
/healthz word mid-serve = ready in 20/20 samples
listener_up=1 mid-serve = 20/20 samples
final FailingFor        = 30s (threshold 30s)
```

and per cycle, sampling the contract row both inside the serve generation and
inside the backoff gap:

```
cycle | backoff |  row mid-serve  |  row in the gap  | up(gap) | alerts
    1 |      1s |              ok |             warn |       1 | 0
    2 |      2s |              ok |             warn |       1 | 0
    3 |      4s |              ok |             warn |       1 | 0
    4 |      8s |              ok |             warn |       1 | 0
    5 |     16s |              ok |             warn |       1 | 0
    6 |     30s |              ok |             fail |       0 | 0
    7 |     30s |              ok |             fail |       0 | 0
    8 |     30s |              ok |             fail |       0 | 0
```

Read that table carefully, because the `fail` in the right-hand column is the
trap. For the first ~31 seconds — the five cycles it takes the ladder to climb
to its ceiling — **every surface reads healthy or self-healing**, from every
sampling position. From cycle 6 the gap-sampled row reads `fail` and `up`
reads `0`, but only because the `30 s` backoff ceiling happens to equal the
`30 s` unavailability threshold, and `jitterScanSvcBackoff` spreads the real gap
across `22.5–37.5 s`, so even at the ceiling the gap-sampled row is `warn` on
roughly half the cycles. The mid-serve column is `ok` in every row of the
table. And the `alerts` column is `0` in every row of the table, forever,
because no code path evaluates the alert when the bind succeeds.

**The consequence is not an unavailable surface.** It is the fail-open posture
at the far end, firing on every gap. `internal/secscan`'s `remoteScanFail`
classifies an unreachable sidecar as a transport fault and forwards the body
**UNSCANNED** (WK-2b, the recorded owner decision). So a sidecar crash-looping
on a ClamAV socket failure or an OOM kill means **every node pointed at it
forwards unscanned traffic through every gap, indefinitely**, while the
sidecar's own host reports `ready` on `/healthz`, `1` on
`culvert_scan_svc_listener_up`, an `ok` diagnostics row and an `ok` `/ready`
row to any scrape that lands inside a serve — and pages nobody, ever.

This is the same shape as CHAOS-113's own Defect 3 (an alert that structurally
could not fire because nothing could subscribe to it) one level down: an alert
that can be subscribed to, on a condition no code path evaluates.

### The two findings about the fix

**CHAOS-113 §10.4's prescription is nearly a no-op.** It read: *"move the
`firstFailure`/`alerted` reset out of `noteScanSvcBound` and into the post-serve
path, gated on the same `scanSvcServeStableAfter` the ladder already uses."*
Implemented and measured: a slow redeploy still read `row=ok up=1
healthz=ready` an hour in, and a flap still read healthy for the whole of every
serve generation. The reason is the line above — `Unavailable()`
short-circuits on `s.Bound`, so what `firstFailure` holds is irrelevant to
every mid-serve reader. The prescription was necessary but nowhere near
sufficient, and taken alone it would have shipped as a fix that changed
nothing. §2.2.

**The obvious step after it pages forever.** Dropping the `s.Bound` arm so that
a bound-but-unstable sidecar counts as unavailable, *in combination with* the
prescription above, makes a **slow redeploy** page for the life of the process.
Measured: a predecessor holding the port for 45 s opens an episode that nothing
closes, and the row then reads `fail`, `up` reads `0` and `/healthz` reads
`down` **an hour into a serve that is perfectly healthy**. §2.3.

So the flap is tracked as **its own episode**, and `Unavailable()` keeps its
documented contract untouched. The new predicate requires three consecutive
serve generations that each died before proving stable, over at least the same
`30 s` threshold the siblings use, and clears the moment a generation proves
stable — including while that generation is still running. Those three
conditions are not defensive padding; each one is pinned by a control gate
whose mutation survived the first version of this round's suite (§9.3).

---

## 2. Failure scenarios

### 2.1 `Unexpected restart` / `OOM` / `ClamAV unavailable` — the sidecar that binds and dies

| | |
|---|---|
| **Current behavior (pre-fix)** | `0` alerts over ~10 min; `/healthz` = `ready` and `culvert_scan_svc_listener_up` = `1` in 20/20 mid-serve samples; contract row `ok` mid-serve, `warn` in the gap for the first ~31 s, `fail` in the gap only once the ladder reaches a ceiling that happens to equal the threshold. |
| **Expected** | A sidecar that cannot keep a serve generation alive is reported unhealthy from every sampling position, and pages once. |
| **Failure mode** | Silent failure. Not a missing signal — a signal that actively reports health while the control it covers is off. |
| **Recovery** | Automatic rebind already worked and was never the gap; the ladder correctly retains and doubles for a sub-stable serve (`scanSvcBackoffAfterServe`), so the loop settles at one attempt per 30 s rather than spinning. The damage was bounded in rate, not in kind. |
| **Manual recovery** | Not reachable: nothing told an operator to attempt one. `culvert_scan_svc_serve_exits_total` climbed monotonically and was the only true signal, which is why CHAOS-113 §10.4 named it as the thing to alert on meanwhile. |
| **Customer impact** | None directly on this node — it proxies its own traffic normally. |
| **Security impact** | The one that matters. Every caller pointed at this address forwards response bodies **UNSCANNED** on every gap (`remoteScanFail`, fail-open, WK-2b). Unbounded in duration, because nothing ends it. |
| **Data integrity** | None. |
| **Monitoring visibility** | Reported healthy. Worse than absent. |
| **Logging quality** | Adequate and the only honest surface: one `ScanSvc: serve loop … ended … rebinding` line per cycle, at the ladder's rate. It did not say how long the generation had lasted, which is the one number that distinguishes a flap from a lost socket; it does now. |
| **Alert quality** | Structurally unreachable. |

### 2.2 The prescribed remedy, measured

CHAOS-113 §10.4's prescription, implemented alone — `noteScanSvcBound` no
longer clears `firstFailure`/`alerted`:

```
healthy serve,       1s in: row=ok    up=1 healthz=ready
healthy serve,      30s in: row=ok    up=1 healthz=ready
healthy serve,     2m0s in: row=ok    up=1 healthz=ready
healthy serve,   1h0m0s in: row=ok    up=1 healthz=ready
```

That is the **slow-redeploy** probe (45 s of `EADDRINUSE`, then a serve that
lasts), and the right answer — but it is the right answer for the wrong reason:
`Unavailable()` returns false because `s.Bound` is true, not because the
episode closed. The identical reason makes the prescription invisible to a
flap. A round that had implemented it and run only a redeploy control would
have shipped it green.

### 2.3 The regression the next step introduces

The prescription **plus** dropping the `s.Bound` short-circuit, on the same
slow-redeploy probe:

```
healthy serve,       1s in: row=fail  up=0 healthz=down
healthy serve,      30s in: row=fail  up=0 healthz=down
healthy serve,     2m0s in: row=fail  up=0 healthz=down
healthy serve,   1h0m0s in: row=fail  up=0 healthz=down
```

An hour into a healthy serve, on a node whose only sin was a predecessor that
took 45 seconds to let go of a port. `firstFailure` is never cleared and
nothing in the snapshot knows the serve has since proven anything, so the page
never ends. This is the exact asymmetry `scanSvcUnavailableAfter` was given a
threshold for in the first place (CHAOS-66 on SOCKS5, CHAOS-113's own
`TestChaos113_ControlNeverBoundInsideThresholdDoesNotPage`), reintroduced
through a different door.

Note what the two probes together establish: dropping the `Bound` arm **alone**
is a no-op on this tree, because the bind-time reset already makes it
redundant. The regression needs both halves. That matters for the gate design
in §9.3 — a single-mutation proof would have shown the control passing and
concluded, wrongly, that it was not load-bearing.

### 2.4 `Clock skew` / `clock rollback` / `NTP failure` — already handled, and why

Checked because the flap verdict is entirely time-based and a new time-based
predicate is exactly where CHAOS-83's defect would reappear. It does not.

Every instant this round stores is a `time.Time` taken from `scanSvcHealthNow`
(`= time.Now`), and every elapsed value is computed with `Time.Sub` inside
`scanSvcListenerState`. A `time.Time` from `time.Now` carries a **monotonic**
reading, and `Sub` between two such values uses it, so an NTP correction, a VM
suspend/resume or a manual `date` change cannot make `ServingFor`,
`UnstableFor` or `FailingFor` jump or go negative. That is the idiom the
CHAOS-83 wall exists to enforce; the defect it was written for is
`time.Now().UnixNano()` followed by `time.Unix(0, n)`, which **discards** the
monotonic reading, and this round introduces no such round-trip.
`monotime_chaos_test.go`'s AST wall passes on this tree (§9.2).

The one residual wrinkle is a process that is **restarted** by a clock change
rather than affected by one — monotonic readings do not survive a restart — and
there the flap run starts empty, which is correct: a fresh process has not yet
observed an unstable generation.

---

## 3. Risk matrix

| | Likelihood | Impact | Detection (pre-fix) | Residual |
|---|---|---|---|---|
| Sidecar crash-loops on scanner-engine init (ClamAV socket, YARA compile) | **Moderate** — the init path runs on every serve generation and depends on a socket and a rule set that are both operator-supplied | **High** — fleet-wide fail-open, unbounded duration | **None** | Low: paged in ~31 s, `flapping` on three surfaces |
| Sidecar OOM-killed under scan load | Moderate — a sidecar's whole job is buffering bodies | High, same | None | Low, same |
| Container supervisor restart loop around the sidecar | Low–moderate | High, same | None | Low, same |
| Slow redeploy misreported as a crash loop | n/a pre-fix | Medium — wrong remedy on a security control | n/a | Low: §2.3's regression is gated, and the flap verdict needs three sub-stable generations a redeploy cannot produce |
| One-off lost socket misreported as a crash loop | n/a pre-fix | Medium — pages on the fault the supervisor heals | n/a | Low: gated by the exit count (§9.3 mutation D) |

---

## 4. Recovery assessment

**Automatic recovery was never broken and is unchanged.** The supervisor's
bind → serve → rebind loop, its bounded ladder, its jitter and its retention of
the ladder across a sub-stable serve all behaved correctly through every
reproduction in this round. What was broken was exclusively the **verdict** —
the conclusion drawn about a loop that is recovering and failing in equal
measure.

That is worth stating plainly because it sets what this round could and could
not fix. A flap is not a recovery failure; it is a recovery that keeps
succeeding at something that keeps dying. No supervision policy available here
fixes the sidecar process. The deliverable is that the condition is now named,
paged, routed to the right remedy, and distinguishable from the two faults it
previously looked like.

**Manual recovery** is now reachable, and routed by shape. The flap row
deliberately does **not** go through `scanSvcBindRemedy`: every string there is
about a bind that failed, and in this fault the bind succeeded every time.
Sending an operator to check `scan_svc.listen` for a port conflict when the
port is bindable on every cycle is a wrong page on a fail-open security
control, which is worse than a vague one. The flap remedy names the sidecar
process, the two engine-init failures that produce this shape, the OOM case and
the counter that carries the rate. `docs/operator/scan-svc-listener-health.md`
is the runbook, and it is also the fourth of four — the other three listeners
each had one and this one did not.

---

## 5. Operational impact

**Before.** A sidecar host in a crash loop was indistinguishable, on every
surface the product exposes, from a healthy one — provided the scrape landed
inside a serve generation, which it does for part of every cycle. The only true
signal was `culvert_scan_svc_serve_exits_total`, which an operator had to know
to graph.

**After.** `culvert_scan_svc_listener_up == 0` — the documented paging rule,
unchanged — now covers both shapes, so an existing alert starts working without
being edited. `culvert_scan_svc_listener_flapping` routes the page: the port
versus the process. `culvert_scan_svc_unstable_serves` is the current run and
returns to `0` when a generation lasts, which makes it the thing to graph
beside the monotonic counter. All of them remain **absent** on a node that
never asked for a sidecar, so `up == 0` can still never fire from an ordinary
proxy.

**Alert volume.** One page per episode, not per cycle. A flap at the ceiling
cycles every ~30 s, which is exactly the alert store's dedup window, so the
latch rather than the dedup is what holds — `TestChaos114_FlapAlertFiresOncePerRun`
drives 40 cycles and asserts `1`. The latch clears only when a serve generation
proves stable, so a sidecar that settles and flaps again next week pages again.

**No new subscription surface.** The flap reuses the existing
`scan_svc_listener_down` event with the bounded detail `flapping` rather than
introducing a new event. An operator who subscribed to *"this node cannot serve
scans"* wants to hear about a sidecar that dies every two seconds, and
CHAOS-113 §8.1 already measured what an unsubscribable event is worth: it never
fires. The detail keeps the two causes from suppressing each other inside the
`event:detail` dedup window, and stays a bounded class — never the raw bind
error, which embeds the listen address and would produce a key that cannot
dedup.

---

## 6. Security impact

The posture is unchanged and remains the recorded owner decision: a sidecar
that is not answering means its callers fail **OPEN** (WK-2b). This round does
not touch that and could not: the decision lives at the caller.

What changes is the duration of the window in which it fires unobserved. It was
unbounded. It is now ~31 seconds to a page, from a sampling position that no
longer matters.

The flap row, the `/healthz` word and the two new gauges all say so in the
terms an operator needs: the row states *"every caller pointed here is
forwarding bodies UNSCANNED (fail-open) through every gap"*, because an
operator reading *"scan sidecar flapping"* must not have to know the far end's
posture to understand that scanning is off.

**Information exposure.** The flap verdict reaches two unauthenticated
surfaces, and both carry only what the existing ones do. `/healthz` gets the
single word `flapping`, no more revealing than the `down` already there.
`/ready` on the proxy port gets a fixed per-branch string naming no address,
no error class and no count; the rate, the address and the remedy stay on the
role-gated diagnostics row, the alert and the logs — the division CHAOS-113
established for the same reason.

---

## 7. The fix

### 7.1 A separate episode, and why

`scan_svc_listener.go` gains a flap run beside the unavailability episode:

```go
boundSince    time.Time     // when the CURRENT serve generation bound
unstableSince time.Time     // start of the current run of sub-stable generations
unstableExits int64         // how many
flapAlerted   bool          // one page per run
```

`noteScanSvcServeEnded` now takes the generation's duration and makes one
decision with it:

```go
if served >= scanSvcServeStableAfter {
        // cleared, including the latch: a sidecar that worked properly for a
        // minute may page again if it starts flapping later.
        scanSvcListener.unstableSince = time.Time{}
        scanSvcListener.unstableExits = 0
        scanSvcListener.flapAlerted = false
        return
}
scanSvcListener.unstableExits++
if scanSvcListener.unstableSince.IsZero() {
        scanSvcListener.unstableSince = now.Add(-served)
}
```

`served` is compared against `scanSvcServeStableAfter` — the **same** constant
`scanSvcBackoffAfterServe` already uses for the same judgement. One definition
of "stable", so the ladder and the alert can never disagree about whether a
serve counted.

The run is dated from the generation's **start**, not its end. Without that a
sidecar dying every 20 s never accumulates an age at all, because each exit
re-dates the run to the present.
`TestChaos114_FlapRunAgeIsDatedFromTheGenerationStart` pins it.

### 7.2 The predicate

```go
func (s scanSvcListenerSnapshot) Flapping() bool {
        if !s.Configured || s.Stopped {
                return false
        }
        if s.UnstableExits < scanSvcFlapMinExits || s.UnstableFor < scanSvcUnavailableAfter {
                return false
        }
        return !(s.Bound && s.ServingFor >= scanSvcServeStableAfter)
}
```

Three conditions, each load-bearing and each with a control gate:

1. **`scanSvcFlapMinExits` (3) consecutive sub-stable generations.** One exit
   followed by a generation that lasts is the one-off lost socket CHAOS-113's
   supervisor exists to heal; calling that a flap pages on a healed fault.
   Three is the smallest count one fault plus one retry cannot reach. It also
   decides **which** FAIL row a sustained outage gets: without it, one short
   serve followed by a five-minute stuck bind reports `FLAPPING` and hands the
   operator the crash-loop remedy for what is actually a port conflict
   (§9.3 mutation D).
2. **The run is at least `scanSvcUnavailableAfter` (30 s) old.** The same
   threshold the siblings use, so a brief stumble is not a page. Because the
   ladder puts the third exit at ~7 s, this is what actually sets the time to
   page.
3. **The current generation has not itself proven stable.** Without this arm the
   run only resets when a generation *ends*, so a sidecar that flapped five
   times and has since served for three hours keeps paging for those three
   hours (§9.3 mutation C).

`Unavailable()` is untouched, and now carries a comment recording §2.3's
measurement so the `s.Bound` arm is not "simplified" away by a later round.

### 7.3 The verdict is evaluated where the fault is

```go
noteScanSvcServeEnded(class, served, scanSvcHealthNow())
logger.Printf("ScanSvc: serve loop on %q ended after %s (%s): %v — rebinding", ...)
maybeAlertScanSvcFlapping()
```

On the **serve-exit** path. This is the other half of the defect and the half
no bind-failure gate can reach, because in this fault the bind succeeds on
every cycle. The log line gained the generation's duration, which is the one
number that tells a flap from a lost socket when reading a log after the fact.

### 7.4 Surfaces

| Surface | Change |
|---|---|
| `checkScanSvcListener` | new `Flapping()` arm, ahead of both `Unavailable()` and `!Bound`, delegating to `scanSvcFlappingRow`. Leads with the rate rather than a duration, and does not route through `scanSvcBindRemedy`. |
| `scanSvcListenerStatus` | `flapping`, ordered before `down` as the more specific and more actionable word. Enum is now `disabled / stopped / flapping / down / degraded / ready`. |
| `appendScanSvcReadinessCheck` | `fail` with a fixed string. Pre-fix this landed on `snap.Bound` → `"ok"` whenever the probe arrived mid-generation. Still report-only. |
| `metrics.go` | `up`/`down` account for a flap, so the documented `up == 0` rule covers it; new `culvert_scan_svc_listener_flapping` and `culvert_scan_svc_unstable_serves` gauges; `up`/`down` HELP text updated. |
| `scanSvcListenerState` | one clock read for all three derived durations, so `FailingFor`, `ServingFor` and `UnstableFor` are measured from the same instant — the inconsistency this struct's single mutex exists to prevent. |

---

## 8. Suggested improvements not taken

**8.1 The caller still has no contract row.** A node that fails open because
its configured sidecar is unreachable reports a clean diagnostics report; every
signal in this round lives on the sidecar's host. Carried forward unchanged
from CHAOS-113 §8.3, and it is now the most valuable remaining item in this
area: a fleet can be failing open with one red node and twenty green ones.

**8.2 Ten alert events remain unsubscribable from the UI.** Pinned by
`alerts_gui_parity_chaos_test.go`, not fixed. Unchanged from CHAOS-113 §8.1.
This round deliberately added no eleventh event.

**8.3 The flap verdict is not exported to the cluster.** A Control Plane cannot
see that a Data Plane's sidecar is flapping; `/healthz` and `/metrics` are
per-node. Out of scope and a design question, not a defect.

**8.4 `classifyScanSvcBindError` is still a third copy** of the errno switch
`socks5_health.go` and `admin_ui_health.go` carry. Converging the three remains
a real improvement and remains out of scope for a chaos round, for the reason
CHAOS-113 recorded: both existing copies are load-bearing for hardened rows
with their own tests.

**8.5 A flap detector keyed on accumulated downtime in a rolling window** would
catch shapes this one does not — notably a sidecar whose generations last 59 s,
just under `scanSvcServeStableAfter`, which needs three exits and therefore
~3 minutes to page. That is the correct amount of patience for a sidecar that
is serving 59 seconds out of every 60, so the gap is recorded rather than
closed. A rolling window is also materially more state for a surface whose
readers are sampled at human rates.

---

## 9. Verification

### 9.1 Gates added

`scan_svc_flap_chaos_test.go` (11 gates, package `main` — the sidecar's own
supervision is root-owned cross-domain wiring):

**Defect gates**
- `TestChaos114_FlappingSidecarPages` — 20 flap cycles fire exactly 1 alert
  with detail `flapping`. Pre-fix measurement: 0.
- `TestChaos114_FlapIsVisibleMidServe` — sampled strictly **inside** a serve
  generation ten cycles in: `Flapping()` true, `Unavailable()` still false
  (the §2.3 contract), `/healthz` = `flapping`, row `fail` naming both the
  fault and the fail-open consequence, `up 0` / `down 1` / `flapping 1`,
  `/ready` row `fail`, and the remedy not routed through the bind strings.
- `TestChaos114_FlapAlertFiresOncePerRun` — 40 cycles → 1 alert; a stable
  generation clears the latch; a second run → 2.
- `TestChaos114_RealSupervisorReachesTheFlapVerdict` — the **production**
  supervisor, with its real sleeps, reaching the verdict on the serve-exit
  path. The deterministic gates replay the loop body; this one proves that is
  the sequence production performs.
- `TestChaos114_FlapRunAgeIsDatedFromTheGenerationStart` — the run's age
  includes the generation's own duration, and `scanSvcFlapMinExits+2` exits
  inside a millisecond are still not a flap.

**Controls**
- `TestChaos114_ControlOneOffSocketLossIsNotAFlap` — an hour-long generation
  that loses its socket and is replaced by one that lasts: 0 alerts, `ready`,
  row `ok`, `flapping 0`. Plus `scanSvcFlapMinExits-1` sub-stable generations,
  still 0.
- `TestChaos114_ControlSingleExitThenAStuckBindIsNotAFlap` — one short
  generation then a five-minute stuck bind gets the **down** row and the
  **port-conflict** remedy, not the flap row. This is the gate that makes the
  exit count load-bearing, and it exists because mutation D survived without it.
- `TestChaos114_ControlSlowRedeployNeverPages` — 45 s of `EADDRINUSE` pages
  once (correctly), then a serve that lasts reads `ready` / row `ok` / `up 1`
  at 1 s, 30 s, 2 min and 1 h in, with no further alert.
- `TestChaos114_ControlStableServeEndsTheFlap` — still flapping at
  `scanSvcServeStableAfter - 1s` into the recovering generation; clear two
  seconds later and three hours later.
- `TestChaos114_ControlGracefulStopIsNotAFlap` — a `Shutdown` mid-flap: not
  flapping, `stopped`, row `ok`, no `/ready` row.
- `TestChaos114_ControlUnconfiguredSidecarHasNoFlapSurface` — neither new
  gauge appears on a node that never ran a sidecar.

One existing CHAOS-113 gate was updated for the `served` argument
(`TestChaos113_ControlRebindingSidecarDoesNotPage`), passing
`scanSvcServeStableAfter` — faithful to that gate's own stated premise, "a
sidecar that HAS served", and it leaves no flap-run state behind at all.

### 9.2 Results (local, this SHA)

```
go vet .                                                          clean
gofmt -l <changed files>                                          clean
go test -run 'TestChaos114' -count=1 .                            ok   (11/11)
go test -run 'TestChaos11[34]|TestScanSvc' -count=1 .             ok   6.8s
go test -run 'Metric|Diagnostic|Health|Ready|Readiness|
  OperatorContract|Alert|ScanSvc|Chaos11[34]|Contract' -count=1 .  ok   26.4s
go test -race -run 'TestChaos114|TestChaos113|TestScanSvc' .      ok   45.9s
go test -run 'Chaos83|Monotime' -count=1 .                        ok   (the
                                   monotonic-clock AST wall — see §2.4)
python3 docs/agent-context/check.py                               ok
```

### 9.3 Mutation testing — where the first version of this suite was not load-bearing

Each mutation was applied to the fixed tree and the whole CHAOS-114 suite run
against it. Two survived the first version of the suite, which is recorded here
rather than quietly fixed, because a surviving mutation is a gate that would not
have caught the regression it was written for.

| | Mutation | Caught by | Verdict |
|---|---|---|---|
| **A** | `maybeAlertScanSvcFlapping()` removed from the serve-exit path (the pre-fix alert reality) | `RealSupervisorReachesTheFlapVerdict` only | Caught. The deterministic gates call it inside their replayed loop body, so they cannot see this — which is exactly why the integration gate exists. |
| **B** | `Flapping()` always false (the pre-fix read surfaces) | 6 gates | Caught. |
| **C** | the "current generation has proven stable" arm removed | `ControlStableServeEndsTheFlap` | Caught: *"a serve generation that has proven stable still reports Flapping() — the verdict latches for the life of the serve"*. |
| **D** | `scanSvcFlapMinExits` lowered to 1 | **nothing — SURVIVED** | `ControlOneOffSocketLossIsNotAFlap` cannot see it: its long generation *clears* the run, so the count is never exercised. Closed by adding `ControlSingleExitThenAStuckBindIsNotAFlap`, which now fails on this mutation with the flap row and the wrong remedy quoted. |
| **E** | `Unavailable()` stops short-circuiting on `s.Bound` | **nothing — SURVIVED, and correctly** | A genuine no-op on this tree: the bind-time reset already makes that arm redundant, so §2.3's regression needs **both** halves. Re-run as **E+F** with §10.4's prescription applied too, it is caught by 3 gates including the slow-redeploy control. The single-mutation result would have suggested the control was not load-bearing; it is, against the real two-part change. |

### 9.4 Not run, and why

**The full `go test -count=1 .` for package `main` was not run.** The package is
1557 files (449 non-test) with timing and benchmark gates; the hosted gate owns that run, and
CHAOS-113 §9.x records two cancelled attempts at it rather than a stale pass.
The suites above were run on the **final** tree, including the ones most likely
to overlap this change's surfaces — metrics rendering, diagnostics, `/healthz`,
readiness, the alert parity wall and the API-contract conformance suites, all of
which the `Contract|Metric|Diagnostic|Health|Ready|Alert` filter reaches.

**`golangci-lint` was not run locally.** The container's binary is older than
this module's language version and panics on it — the repository's own recorded
cause of "local lint is unavailable" — and installing the gate's pinned version
built with the `go.mod` toolchain was not attempted in this round's budget. The
changed code was written against the conventions the gate enforces, and the
specific ones in reach here are: application `logger.Printf` (the one log line
changed is already `logger.Printf` with `sanitizeLog` + `%q` on the address, both
preserved); no new outbound I/O, so no SSRF guard or `noctx` surface; no new
suppressions; `scanSvcFlappingRow` extracted so `checkScanSvcListener` gains one
switch arm rather than growing (its cyclomatic complexity goes from ~6 to ~7
against the configured threshold of 15). The `cyclop`/`funlen`/`gocognit`
blind spot the conventions warn about — attribution to a function's
**declaration** line, which `--new-from-rev` cannot see — applies to
`noteScanSvcServeEnded` and `scanSvcListenerState`, both of which grew; both
remain short and single-branch-depth, but **this is not measured locally and the
hosted gate is what will measure it.**

**No stress or long-duration run.** The flap condition is defined over tens of
seconds of sidecar lifetime, and the gates drive a virtual clock to reach it.
The one gate that runs the real supervisor takes ~3.4 s of real sleeping and is
scheduler-dependent in its timing, though not in its verdict; it carries a 45 s
deadline and reports the full state on failure.

A passing local check is not a passing hosted gate. These are local results for
this SHA.

---

## 10. Residual risk

1. **The posture is still fail-open**, and that is the top of this list for the
   second round running. A supervised, alerting, self-rebinding sidecar that is
   genuinely down or flapping still means the fleet forwards unscanned bodies.
   This round shortens the unobserved window from unbounded to ~31 s; it does
   not close the window itself. §6.
2. **The caller is still silent.** The node that actually fails open reports a
   clean diagnostics report. §8.1. This is now the sharpest gap in this area,
   and unlike the one this round closed it is not in a surface this register
   introduced — it is in the surface that bears the consequence.
3. **A 59-second flap takes ~3 minutes to page.** Deliberate: three exits is
   the right amount of patience for a sidecar serving 59 seconds out of every
   60. Recorded in §8.5 with the rolling-window alternative and why it was not
   taken.
4. **The flap verdict cannot distinguish a crash-looping sidecar from an
   external supervisor restarting it on purpose.** A container orchestrator in
   a tight redeploy loop produces the same three sub-stable generations and
   pages, with a remedy pointing at the sidecar's log — which will show clean
   shutdowns rather than a crash. The log line's new duration field is what
   lets an operator tell them apart, and the remedy names "a supervisor restart
   loop" as one of the causes to check. Closing this properly needs the
   sidecar's exit *reason*, which `Serve` returning `ErrServerClosed` versus a
   dead socket does partially carry and this round does not plumb through.
5. **`scanSvcServeStableAfter` (60 s) now has two jobs.** It gated the backoff
   ladder's reset; it now also decides what counts toward a flap run. That
   reuse is deliberate — one definition of "stable", so the two cannot
   disagree — but it means a future change to the ladder's patience silently
   changes the flap threshold. The constant's comment says so; a reader who
   changes it without reading the comment will not be warned by a test, because
   both behaviours are correct at any value.
6. **The integration gate depends on the scheduler.** Its verdict does not, but
   its 45 s deadline does. The nine deterministic gates carry the behavioural
   contract and need no scheduler, which is why both shapes are present — the
   same division CHAOS-113 §10.6 recorded for its `-race` gate.
