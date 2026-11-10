# Chaos Engineering Review — 2026-11-09

## CHAOS-115 — The shared scanner has no admission plane: the sidecar's heap is sized by the network, and when it dies the whole fleet fails open

**Scope.** The SIMULATE list's *thousands of simultaneous connections*,
*memory pressure*, *OOM*, *mass reconnect storm*, *network latency* and
*ClamAV unavailable* rows, aimed at the **caller/sidecar pair** rather than at
the sidecar's socket — the plane CHAOS-113 and CHAOS-114 did not look at
because both were about a listener that would not come back or would not stay.

**Status.** One defect found, reproduced on this tree before any fix, fixed. A
second defect was found **by** the fix's own test — the caller's refusal log
names the wrong remedy for a capacity refusal — and is fixed in the same round,
because the first fix is what makes that line reachable on a shipped
deployment. A third finding is about this round's own first design: the wait
bound it claimed does not exist, which the test caught and the code comment now
states correctly.

**Closes.** The residual-risk item that has been carried forward for three
rounds in a weaker form — CHAOS-113 §8.3 → CHAOS-114 §8.1 / residual risk `2`,
"the caller is still silent" — but **not** in the shape those rounds proposed.
See §7.1: the caller is no longer silent about this condition because the
condition now has a bounded, counted, fail-closed outcome, rather than because
a diagnostics row was added to narrate a fail-open one.

---

## 1. Executive summary

The scan sidecar is the deployment the CHAOS-52 runbook **recommends** as the
remedy for in-process scanner faults, and `scan_svc.go`'s own doc comment
offers "shared scanning: multiple proxy instances sharing one scanner" as a
reason to run it. That makes it a deliberate, fleet-wide single point of
failure for one specific control: content scanning.

Its `/scan` handler began like this:

```go
atomic.AddInt64(&statScanSvcRequests, 1)
start := time.Now()

maxBytes := scanSvcWindow()
data, truncated, err := readScanWindow(r.Body, maxBytes)
```

`readScanWindow` buffers up to `window+1` bytes into this process's heap.
Nothing above it bounded how many handlers could be inside that call at once.
The sidecar's buffered-body exposure was therefore

```
open_connections x (window + 1)
```

with `open_connections` set by **whatever the network delivered** — not by any
configured capacity, not by the engines' concurrency, not by a memory budget.
Every other listener in the tree has some admission control in front of it; the
proxy listener has the per-IP connection limiter CHAOS-112 worked on. This one
had none, and it is the one whose per-request cost is the operator's whole scan
window.

**Measured on this tree before any fix.** Callers that declare a
`Content-Length` and then stall one byte short, so each handler parks inside
`readScanWindow` holding what it has buffered — the SIMULATE list's *network
latency* / *packet loss* / *slow filesystem* shape, and the cheapest way to hold
a handler open without an engine seam:

```
window = 1 MiB

slow callers | handlers buffering concurrently | sidecar heap delta
          64 |                              64 |           75.8 MiB
         192 |                             192 |          244.5 MiB
```

Linear, at ~1.27x the window per request — `io.ReadAll` grows by doubling, so a
request transiently holds the old buffer and the new one. The concurrency is not
capped at any value; those two rows are the two sizes that were measured, not a
ceiling being approached.

Extrapolated to the shipped **5 MiB** default that is ~1.2 GiB at 192
concurrent callers, and to a **20 MiB** fleet ~4.9 GiB. No malice is needed to
get there. A shared sidecar's concurrency is the **sum over every node pointed
at it**, so twenty proxies each serving ten concurrent large downloads is 200,
and none of the twenty knows what the other nineteen are asking for.

**Why this was worse than an ordinary memory bug.** The failure is a cascade in
which the security control is the thing that collapses:

1. Aggregate download traffic drives the sidecar's heap past its container
   limit. The OOM killer takes the **process**, not the listener.
2. CHAOS-113's supervisor cannot help: it rebinds a dead socket inside a living
   process. There is no living process.
3. Every node pointed at the address takes `internal/secscan`'s fail-**OPEN**
   branch (`remoteScanFail`, recorded owner decision WK-2b) and forwards bodies
   **unscanned**, fleet-wide, at the moment traffic is heaviest.
4. On restart the queued storm arrives immediately and repeats. That is the
   crash-loop shape CHAOS-114's flap detector pages for, with a remedy that
   names "an OOM kill" among the causes to check but cannot name what caused it.

So the pre-fix posture was: **scanning switches itself off, under load, by
succeeding at accepting work.** `internal/clamav` has had a four-slot semaphore
since long before any of this, specifically so that a busy node refuses rather
than drowns. The HTTP layer in front of it spent an unbounded resource before
reaching it.

**The fix needed no new posture and no caller change, because the caller's half
was already complete, tested — and unreachable.** `scanOnce` has classified
HTTP 429 as `remoteOutcomeCapacity` since CHAOS-52: fail **closed**, counted as
saturation rather than as a fault, with the local path's timeout vocabulary and
the existing `scan_timeout` alert, gated by
`TestChaos_SidecarCapacityRefusalFailsClosed`. Its comment says the quiet part
out loud:

> The shipped sidecar never emits 429 today; a load balancer or a third-party
> scanner in front of it can, and classifying it correctly costs nothing.

This round makes the shipped sidecar emit it. One bounded gate, acquired
**before** the body is read, refusing the overflow with 429. No wire field, no
new alert event, no new posture, no change in `internal/secscan`'s decision
logic.

**After the fix**, same harness, 32 stalled callers through 4 slots, measured
under the `benchgate` tag where the process is quiet (§9):

```
peak handlers buffering = 4         (was 32)
sidecar heap delta      = 5.0 MiB   (was 36.4 MiB)
```

5.0 MiB on three consecutive runs, to one decimal place.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Post-fix behavior |
|---|---|---|---|
| 1 | Aggregate download burst across a shared sidecar | Heap grows with open connections; OOM; **fleet-wide fail-open** | Bounded at `slots x (window+1)`; overflow refused 429 → **fail-closed** |
| 2 | Slow/lossy callers stall mid-body | Each stalled caller holds a window-sized buffer indefinitely (to `ReadTimeout`, 60 s) | Each stalled caller holds a **slot**; the rest wait with their bodies in the kernel, where TCP flow control pushes back for free |
| 3 | Operator widens `security.max_scan_mb` | Per-request cost multiplies; exposure multiplies silently | Slot count **narrows** proportionally; the ceiling is held, and both numbers are published |
| 4 | Unauthenticated third party posts to `:8484` | Unbounded buffers for the cost of opening connections | Bounded; refusals counted and logged with the peer |
| 5 | Sidecar OOM-restarts into the same storm | Immediate repeat; CHAOS-114 pages at the flap, remedy points at the sidecar's log | The storm is refused rather than absorbed, so the restart is not re-triggered by the same cause |
| 6 | Sidecar saturated but serving | Every listener signal reads `ready`; no saturation signal exists at all | `culvert_scan_svc_inflight` pinned at `slots`, `culvert_scan_svc_at_capacity_total` rising, caller's `culvert_remote_scan_saturated_total` rising |
| 7 | Caller reads the saturation log | "remote scan did not complete within 10s" — false, and points at a slow scanner | "sidecar reported itself at capacity … add sidecar capacity rather than investigating a fault" (§4) |
| 8 | Queued caller aborts | — (no queue existed) | Slot never taken; handler returns at the backstop; gated against leaks |

---

## 3. Risk matrix

| Finding | Likelihood | Impact | Severity | Fixed |
|---|---|---|---|---|
| 3.1 Unbounded buffered-body concurrency on `/scan` → OOM → fleet-wide fail-open | High on any shared sidecar under real load; certain under the SIMULATE list's connection-storm row | Security control off fleet-wide, plus a sidecar outage | **High** | Yes |
| 3.2 Capacity refusal logged as a budget expiry, naming the wrong remedy | Certain once 3.1 is fixed (this round makes the line reachable) | Operator investigates a healthy scanner instead of adding capacity; the capacity/fault split the counters preserve is lost in the one surface a human reads | **Medium** | Yes |
| 3.3 Both refusal classes shared one rate gate | Certain in a sustained saturation regime | A single budget line silences the saturation line for a whole interval; the remedy sentence may never be seen | **Low–Medium** | Yes |
| 3.4 This round's first design claimed the caller's deadline bounds the slot wait; it does not | Was certain | Over-stated guarantee in a comment and a test; the real backstop was always in place | **Low** (documentation of a real bound) | Yes — claim corrected, §6.3 |

---

## 4. The second defect, and why it belongs in this round

`remoteScanRefused` serves both fail-closed remote outcomes. It printed one
sentence for both:

```go
obs.Warnf("ScanSvc: remote scan did not complete within %s for hash %s — blocking (fail-closed)",
        scanBodyTimeout(), hash)
```

For a capacity refusal that sentence is false twice over: the round trip
**completed**, and it completed in the time the refusal took — measured at 5.26 s
against a stated 10 s. Worse, it points at the wrong remedy. The entire reason
`remoteOutcomeCapacity` is kept apart from `remoteOutcomeBudget` is the one
`internal/clamav`'s `ErrQueueFull` doc states for the local path:

> the daemon is healthy, this node is simply at its scanning capacity, and the
> two need different operator responses (add capacity vs. fix the daemon)

The counters preserved that distinction. The log — the only one of the three
surfaces a human reads unprompted — collapsed it.

This was latent while nothing in front of the sidecar emitted 429. Fix 3.1
makes it the line an operator reads in the saturation regime, which is why it is
not deferred: this round would otherwise have shipped a correct gate whose
first-order operator experience is a false sentence.

The split is deliberately narrow. `Reason`, `Source` and **both** counters are
identical on the two paths and must stay that way: the posture is one decision,
the alert dedups on `Reason`, and the block page quotes it. Only the sentence
and its rate gate differ — and the gates had to split too (3.3), or one budget
line would suppress the saturation line for a whole `degradedLogInterval`.

---

## 5. Recovery assessment

| Axis | Before | After |
|---|---|---|
| Automatic recovery | None at this layer. OOM → process death → external restart → same storm | Automatic and continuous: refusals stop as slots free; no state to clear |
| Manual recovery | Restart the sidecar, raise its memory limit, or reduce fleet traffic — none discoverable from any surface | Add capacity, with the arithmetic published on `/health` and `/metrics` |
| Deterministic | No. The OOM point depends on container limits, GC timing and traffic shape | Yes. `slots x (window+1)` is stated, derived from this process's own configuration, and tested |
| Posture during degradation | Fail **open** (unscanned content forwarded) via the sidecar's death | Fail **closed** (download blocked) via an explicit refusal |
| Blast radius | Every node pointed at the sidecar, for as long as the process stays dead | The requests that exceeded capacity, for as long as it is exceeded |

---

## 6. Design decisions, stated

**6.1 Why 429 and not 503.** The caller's `scanOnce` reads 429 as capacity
(fail closed) and **any other non-200** as `sidecar returned HTTP %d`, which is
a FAULT and fails **open**. Choosing 503 would have turned this fix into a
fleet-wide fail-open under exactly the load it exists to survive. The status
code is load-bearing in another package, so
`TestChaos115_CapacityRefusalFailsClosedAtTheCaller` gates it by running the
real `RemoteScanner` against a really saturated sidecar rather than by
inspecting the constant. Mutating 429 → 503 makes that gate report
`got <nil> — content was forwarded UNSCANNED` (§9, mutation 4).

**6.2 Why the bound is in bytes, and why admission precedes the read.** What
runs out is memory, and the per-request cost is the operator's
`security.max_scan_mb`. A fixed **request** count would have silently multiplied
the exposure of anyone who widened the window — the one direction that must not
surprise. So the slot count is a 256 MiB budget divided by this process's own
window, clamped to `[2, 32]`.

The ceiling of 32 is **not** about memory: `internal/clamav`'s
`clamMaxConcurrent` is 4, so slots far above that buy no throughput — they only
let the HTTP layer buffer work the engines cannot start, which is the defect.
32 is 8x the ClamAV limit, chosen so the gate cannot be the bottleneck on a
healthy deployment. The floor of 2 keeps a pathological window from serialising
the sidecar completely; at or below it the budget is advisory and the published
numbers say so.

Acquiring **before** `readScanWindow` is the whole fix. A gate acquired
afterwards bounds only engine work and leaves the heap exposure exactly where it
was — mutation 3 in §9 measures that directly: 47.4 MiB against a 16 MiB
ceiling, with the gauge still reading honestly. A request waiting for a slot
holds a goroutine and a connection it already had, and **no buffer**; its body
stays in the kernel's socket buffer, which is where backpressure belongs,
because TCP flow control then pushes it back to the caller for free.

**6.3 What bounds the slot wait — corrected.** The first form of this round
claimed `context.WithTimeout(r.Context(), scanSvcQueueWait)` lets the **caller's
own** budget cut the wait short, so a caller that had given up was never waited
on. That is wrong, and this round's own test caught it. An HTTP request carries
no deadline over the wire, so the server's `r.Context()` has no deadline to
keep, however short the caller's budget is; and `net/http` did not deliver even
the cancellation before the handler had started reading the body — measured, a
client that aborted at 400 ms left its waiter parked until the 5 s backstop.

`scanSvcQueueWait` is therefore the operative bound and effectively the only
one. Passing `r.Context()` is still right — a cancellation that does arrive
frees the waiter early, and a handler must not outlive its request — but the
guarantee is the backstop. `acquire`'s comment now says so, and the test that
found it is kept, re-aimed at the property that does hold: a refused request
never takes a slot. That matters more than the timing claim did, because a slot
leaked on every client abort would narrow the gate permanently until the sidecar
refused everything — a fleet-wide download outage built out of ordinary client
timeouts (§9, mutation 5).

**6.4 Why 5 seconds.** Chosen against the caller's budget, not for its own
sake. `internal/secscan`'s `ScanBodyTimeout` is 10 s. Waiting past that would
let the caller's deadline fire first, and the caller would then classify a
capacity refusal as `remoteOutcomeBudget` — fail-closed either way, but counted
as a timeout and pointing an operator at a slow scanner rather than a saturated
one. Answering at 5 s keeps the classification, and therefore the operator
action, correct. Same value and role as `clamQueueWaitFallback`.

**6.5 Graceful degradation before refusal.** A transient burst is **waited
out**, not refused on sight: the gate only refuses after the full queue wait.
This matters because a refusal fails closed and therefore blocks a user's
download. `TestChaos115_OrdinaryTrafficIsNotRefused` is the control that keeps
the gate invisible below its bound, and it is the gate this round would least
like to lose.

---

## 7. Operational and security impact

**7.1 The carried-forward residual risk, and what actually closed it.**
CHAOS-113 §8.3 and CHAOS-114 §8.1 both recorded that a node failing open
because its sidecar is unreachable reports a clean diagnostics report, and
CHAOS-114 called it "the most valuable remaining item in this area". The
proposed remedy was a caller-side contract row narrating the fail-open.

This round reached the same area from the other side and found something better
to do with it. For **this** condition — the sidecar overwhelmed rather than
absent — the right answer was not a row describing a fail-open; it was to stop
failing open. The condition now has a bounded, counted, fail-**closed** outcome
with the caller's existing saturation counter and the local path's timeout
alert, and the sidecar's own `/health` and `/metrics` publish the capacity and
its utilisation. A row narrating "I am currently forwarding bodies unscanned"
is still the right answer for the shapes that remain genuinely fail-open —
unreachable, 5xx, no verdict, oversize — and that is now the sharpest remaining
gap in this area rather than a vague one (§8.1).

**7.2 A posture change that is user-visible, stated plainly.** Under genuine
overload, downloads are now **blocked** (`403 scan timeout`) where previously
they were forwarded unscanned until the sidecar died. That is the documented
posture for capacity (CHAOS-52/53) and the IMPLEMENTATION RULES' "prefer fail
closed", and the thresholds are sized so only genuine overload reaches it — but
it is a change customers can see, and an operator who has been unknowingly
relying on the fail-open behaviour will experience the fix as new blocking.
`docs/operator/scan-capacity-and-timeouts.md` §6.2 says this in the runbook,
with the remedy.

**7.3 Security impact.** Net positive, in the direction the register cares
about: a control that could be switched off fleet-wide by volume alone now
refuses instead. The refusal surface is unauthenticated, as the whole `/scan`
endpoint already was, and carries no new information — a status code and a fixed
string. The log line sanitises the peer (`sanitizeLog` + `%q`), matching
`refuseTruncatedScan`.

**7.4 Data integrity.** No persistence, no wire-format and no configuration
change. Nothing to migrate, nothing to roll back beyond the code.

**7.5 Monitoring visibility.** The CALLER needed nothing new, which is worth
stating because it is the side an operator watches: `stat_remote_scan_saturated`
has been on `/api/security-scan/status` (and therefore in the Content Scanning
panel) and `culvert_remote_scan_saturated_total` on `/metrics` since CHAOS-52.
Both were structurally zero against the shipped sidecar because nothing emitted
429; they move now.

Three new series on the sidecar host, emitted
only where `scan_svc.listen` is configured — a node that never ran a sidecar
must not export a sidecar's saturation plane, the same `Configured` guard the
CHAOS-113 listener gauges use. `inflight` and `slots` ship as a pair on purpose:
`at_capacity_total` rising while `inflight < slots` would mean the gate is
misbuilt, not that the sidecar is busy.

---

## 8. Suggested improvements not taken

**8.1 The caller still has no contract row for the shapes that remain
fail-open.** Unreachable, 5xx, no-verdict and oversize still forward bodies
unscanned, and the node that does it still reports a clean
`/api/diagnostics`. This round narrowed the item rather than closing it, and it
is now specific enough to act on: a `remote_scan` row keyed on recency, not on
the monotonic `culvert_remote_scan_fail_total`, because the counter cannot
distinguish twenty faults three days ago from twenty in the last minute. That
missing recency state is the real work, and it is a caller-side design question
rather than a defect in this round's plane.

**8.2 `/api/security-scan/status`'s `scan_svc_degraded` is blind to a
verdict-shaped fault.** It is a live `/status` probe, so a sidecar that answers
`/status` with 200 while returning `{}` from `/scan` reads **not degraded** on
the admin UI while every body is forwarded unscanned. The fault is counted and
alerted (`remoteFaultNoVerdict`), so this is two surfaces disagreeing with the
reassuring one being the one an operator looks at — not a silent failure. Out
of scope here; it belongs with 8.1.

**8.3 The caller's transport has no `MaxConnsPerHost`.** One node can still
open an unbounded number of sockets to the sidecar (`MaxIdleConnsPerHost` is 16,
which bounds reuse, not creation). With the server-side gate in place those
connections hold no buffers, so the remaining exposure is file descriptors and
accept queue rather than heap. Fixing it belongs on the caller and interacts
with the queueing semantics this round introduced; recorded rather than taken,
to keep the diff on the shared resource.

**8.4 A window changed at runtime does not retune a running gate.** The slot
count is derived once per `NewScanService`. A resizable semaphore is materially
more machinery than this fault needs, and `security.max_scan_mb` changes are
rare and already require care across the two processes (CHAOS-101). Documented
in §6.2 of the runbook.

**8.5 The sidecar remains unauthenticated.** Anything that can route to
`:8484` can spend its scanning capacity, and now, provably, only its *bounded*
capacity. That is a deployment trust boundary rather than a regression, and
changing it is a configuration and compatibility decision, not a chaos fix.

**8.6 The flap detector still cannot see saturation.** A sidecar that is
refusing every scan is, to CHAOS-113/114's surfaces, perfectly healthy — it
binds, serves and never exits. That is correct separation (the socket is fine)
and the reason `scan-svc-listener-health.md` now opens by pointing at the
capacity runbook for this shape.

**8.7 No operator-contract row for saturation, and the reason is the same
missing thing as 8.1.** `checkScanSvcListener`'s healthy branch reports "scan
sidecar serving on X (N bind failure(s), M serve exit(s))" — a cheerful row on a
sidecar that is refusing every scan. A row was considered and not added because
neither available input makes a good one: `scanSvcInflight >= slots` is an
INSTANTANEOUS read, and a contract row that flickers between `ok` and `warn`
across diagnostics polls is noise rather than signal; and
`culvert_scan_svc_at_capacity_total > 0` is cumulative, so it would pin the row
to `warn` forever after one burst. What a usable row needs is recency state —
"refusals in the last N seconds" — which is the same missing ingredient 8.1
names on the caller side, and building two different ones in a round that is
already two defects wide is how a third gets introduced. An operator without
Prometheus reads `/health`, which the runbook leads with.

**8.8 Ten alert events remain unsubscribable from the UI**, pinned by
`alerts_gui_parity_chaos_test.go`. Unchanged from CHAOS-113 §8.1 and CHAOS-114
§8.2. This round deliberately added no eleventh event: saturation rides the
existing `scan_timeout` alert because it is the same decision.

---

## 9. Verification

**Mutation sweep.** Each mutation was applied to the fixed tree, the gates run,
and the tree restored.

| # | Mutation | Caught by | What it reported |
|---|---|---|---|
| 1 | Remove the gate entirely (the original defect) | 4 gates | gauge 0 / could not fill the gate |
| 2 | Keep the gauge, widen the semaphore 1000x (bound removed, instrumentation intact) | `SlowCallersCannotOutrunTheWindow` | `peak inflight = 16 with 8 slots: the admission bound does not hold` |
| 3 | Acquire **after** `readScanWindow` (the ordering mutation) | `SlowCallersCannotOutrunTheWindow` **and** the benchgate measurement | `peak inflight = 0 with 4 slots and 32 stalled callers` / `heap delta=36.4 MiB` against 5.0 MiB fixed |
| 4 | 429 → 503 | `CapacityRefusalFailsClosedAtTheCaller` | `a sidecar at capacity must fail CLOSED, got <nil> — content was forwarded UNSCANNED` |
| 5 | `release()` returns no slot (leak) | `OrdinaryTrafficIsNotRefused` | `request 4: status = 429, want 200` |

Mutation 2 is the one that justifies measuring at all rather than trusting the
gauge: mutation 1 is caught only because removing the gate also removes the
instrumentation, which is a weaker signal than a measured overshoot.

**The heap oracle moved, and the full suite is what moved it.** It began as an
assertion inside `SlowCallersCannotOutrunTheWindow`, passing in isolation. In
the full package run it failed: `HeapAlloc` is a PROCESS-wide number, and with
~140 live goroutines from unrelated tests churning, the same correctly-bounded
sidecar measured **37 MiB against a 16 MiB ceiling while `peak inflight`
correctly read 4**. The contract held and the oracle did not, which is the
definition of a flake, and it was this round's own recorded residual risk biting
in the one environment that matters. It now lives under the `benchgate` tag —
the division CHAOS-111's wall-clock budgets took for the same reason — and the
behavioural contract lives on the always-on gauge assertions.

Nothing was lost: mutation 3 (the ordering mutation the heap assertion was aimed
at) is caught by the `peak < slots` arm as well, because a stalled caller never
finishes its read and therefore never reaches a gate placed after it, leaving
the gauge at 0. Verified by re-running the mutation against both paths.

**A second measurement bug was fixed in the harness itself**, and it is worth
recording because it is the kind that makes a number look fine while meaning
nothing: these tests run in the same process as the sidecar they measure, and
`stallingScanPost` built its own 1 MiB payload per caller. That put **32 MiB of
client garbage on the same heap as the 4 MiB of sidecar buffers under test**.
The payload is now built once and shared, after which the measurement is 5.0 MiB
on three consecutive runs against a 16 MiB ceiling — a 3.2x margin below and 7x
below the unbounded regime, which is what makes it a measurement.

**Lint, measured in both directions** (the repository's own rule: `cyclop`,
`funlen` and `gocognit` attribute to a function's DECLARATION line, so
`--new-from-rev` cannot see a function made more complex). golangci-lint
`v2.15.0`, the version `pr-fast-gate.yml` installs, built with the `go.mod`
toolchain:

- The gate's own command, `run --timeout=10m --new-from-rev origin/main`:
  **0 issues**.
- Full tree on this branch: **174 issues**, all pre-existing. Exactly three land
  in a file this change touches, and none names a function it adds:
  `metrics.go:823` errcheck (600 lines above the edit), `scan_svc.go:439`
  gocritic `whyNoLint` (`handleStatus`'s `//nolint:errcheck`, at line 414 before
  this change shifted it), and `handleMetrics` gocognit 51. Because the
  full-tree run is on THIS branch, any finding the change introduced would be
  among those 174; the only open question was whether a declaration-attributed
  one got worse, so it was measured directly with `gocognit` against
  `origin/main`'s `metrics.go`: **51 on both**, identical, because the three new
  series added arguments and no branches.

**Gates added.**

Package `main`, `scan_svc_admission_chaos_test.go` (10):
`SlowCallersCannotOutrunTheWindow` (the fixed reproduction, plus the heap
oracle), `AbandonedWaiterLeaksNoSlot`, `DeadlinelessWaiterIsStillBounded`,
`CapacityRefusalFailsClosedAtTheCaller` (cross-plane, through the real client),
`OrdinaryTrafficIsNotRefused` (negative control),
`TruncationContractSurvivesAdmission` (CHAOS-101 regression control),
`SlotArithmetic` + `HeapCeilingIsStatedNotImplied`,
`SaturationSeriesRideTheConfiguredGuard` (both directions — an ordinary proxy
must not export a sidecar's saturation plane) and
`HealthPublishesTheCeilingArithmetic` (slots and window on the same reply,
because the ceiling an operator sizes against is their product).

Package `internal/secscan`, appended to `remote_chaos_test.go` (3):
`CapacityRefusalLogNamesCapacityNotTheClock`,
`BudgetRefusalKeepsItsOwnSentence` (negative control),
`TheTwoRefusalLinesDoNotSuppressEachOther`.

---

## 10. Residual risk

1. **The fleet can still be failed open by a sidecar that is absent rather
   than overwhelmed**, and the node that does it still reports clean. This
   round removed one route to that state — the self-inflicted, load-driven one
   — and did not close the state itself. §8.1 is now the sharpest gap in this
   area, and it is specific: the missing thing is *recency*, not a row.
2. **Refusals block downloads.** The posture is correct and documented, but an
   operator whose sidecar is chronically undersized will meet this fix as new
   user-visible blocking rather than as silent unscanned forwarding. The
   runbook leads with that; no alert fires on the transition itself, because
   the transition is `culvert_scan_svc_at_capacity_total` leaving zero, which
   the runbook's suggested rule covers.
3. **The 256 MiB budget is a chosen number, not a measured container limit.**
   It is not read from cgroups, so a sidecar in a 128 MiB container is still
   over-provisioned by this gate at the default window, and one in a 4 GiB
   container is under-provisioned. Reading the cgroup limit would make the
   bound self-sizing and is the obvious next step; it needs a non-Linux and
   no-limit fallback, which is more surface than this fault needed.
4. **A parked waiter still costs a goroutine and a connection for up to 5 s**
   after its caller has gone, because `net/http` does not deliver the
   cancellation before the body read (§6.3). This is strictly better than the
   pre-fix state, where the same connection held a window-sized buffer, but it
   is not zero: an abandoning client can hold `connections x 5 s` of goroutines.
5. **`scanSvcQueueWait` (5 s) and `ScanBodyTimeout` (10 s) must stay ordered.**
   Nothing enforces it. If a future round shortens the caller's budget below 5 s,
   every capacity refusal silently reclassifies as a budget expiry — still
   fail-closed, so no test fails, but the saturation counter stops moving and the
   operator is sent after a healthy scanner again. The constant's comment says
   so; a reader who changes the other one will not be warned.
6. **The heap oracle is a measurement, and measurements drift** — it already
   drifted once, in the full suite, which is why it is under the `benchgate`
   tag and not in the default run (§9). It samples `HeapAlloc` rather than
   accounting the buffers directly, so a Go release that changes `io.ReadAll`'s
   growth, or a CI host under memory pressure, could still move it. The
   behavioural contract does not depend on it — the gauge assertions carry
   that — which is why both shapes exist. A gauge of bytes actually buffered
   would be the honest instrument and was considered; it would not have caught
   the ordering mutation any better than the slot gauge does, so it was not
   worth new production surface.
