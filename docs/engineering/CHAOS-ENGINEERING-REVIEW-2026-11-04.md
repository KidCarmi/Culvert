# Chaos Engineering Review — 2026-11-04

## CHAOS-110 — The DPI scan goroutine: who counts the workers nobody is waiting for

**Date:** 2026-11-04
**Branch:** `claude/serene-cerf-nmqw2d`
**Baseline:** `origin/main` **2d03196** (freshly fetched; `CHAOS-109` is the
highest id anywhere on main, and no open PR held a chaos id at claim time —
#1803, #1802, #1705, #1549, #1548, #1536, #1528, #1526).
**Id allocation:** `CHAOS-110` claimed in a committed placeholder row in
[the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) as commit one, before
any code was written, per that file's own convention.
**Method:** evidence-first source review, then executed fault injection against
a build of the baseline through the package's own `patternSet.matcher` seam.
Every behavioural claim below was observed; the commands and raw numbers are in
§9. It closes the 2026-10-13 backlog's `X-5`, the row the 2026-10-30 round
re-confirmed as open while correcting its per-pattern wording.

---

## 1. Executive summary

`internal/scanner` bounds every DPI regex match with a 5s per-pattern budget,
and it enforces that budget the only way Go allows: `re.Match` is not
interruptible, so the match runs in a worker goroutine the parent can **abandon**
([scanner.go `patternSet.scan`](../../internal/scanner/scanner.go)). That
abandonment is correct and deliberate. It is also the leak, because an abandoned
worker is not a thing that goes away:

- it keeps running — only the *remaining* patterns are skipped, via the
  `abandoned` flag checked **between** patterns, so the match that overran keeps
  burning a core until it finishes;
- it keeps the **response body reachable**, because the worker holds `data`;
- and **nothing counted it and nothing capped it.** There was one worker per
  inspected response body, spawned from the SSL-inspect response path
  ([proxy_tunnel.go:1432](../../proxy_tunnel.go)), with no in-flight gauge, no
  limit, no saturation counter and no alert.

The twin engine already solves exactly this. `internal/yara` counts every
in-flight regex goroutine, has the **abandoned worker inherit its charge** so
the cap can see it, caps the total, warns at 80%, counts what it refuses and
resolves saturation through an admin posture
([regexrunner.go](../../internal/yara/regexrunner.go),
[yara.go `yaraSaturationCheck`](../../internal/yara/yara.go)). Its own comment
states the reason: *"Abandoned goroutines are tracked via `yaraInflight` to
prevent unbounded leaks."* The DPI engine, on the same response path, in the
same binary, had none of it.

Two consequences, measured, and the second is the one that is not a memory bug.

**The abandoned population is the memory.** Measured on the baseline, with every
parent already returned and the test holding no reference to any body: **200
concurrent abandoned scans retained 200.3 MiB** of reachable heap and 200 live
goroutines, and **64 abandoned scans at an 8 MiB scan window retained 512.1
MiB** — exactly one response body per worker, linear in arrival concurrency,
released only when the matches finally ended. This is reachable heap, which is
the one thing `GOMEMLIMIT` explicitly cannot reclaim — the same property
CHAOS-109 measured for the feed-ingest map. The per-worker size is **not**
bounded by the DPI scanner's own 1 MiB cap either: `safeDPIScan` is handed the
shared scan buffer, sized by `maxScanBufferBytes()` as the **larger** of the DPI
cap and the security scanner's operator-set `max_scan_mb`
([security_scan.go:157](../../security_scan.go)), so the retention per worker is
governed by a setting that belongs to a different scanner.

**The gateway blocked clean traffic in proportion to its own load.** The
per-pattern budget is **wall clock**. With no cap on concurrent CPU-bound
matches, a match's elapsed time grows with how many other matches are competing
for the same cores, so scans begin failing closed because the *gateway* is busy,
not because the *content* is slow. Measured on the baseline, one core, a match
needing 68ms against a 200ms budget — a 3x margin:

| concurrent clean scans | blocked (baseline) | wall |
|---|---|---|
| 1 | **0 of 1** | 68ms |
| 4 | **4 of 4** | 251ms |
| 8 | **8 of 8** | 348ms |
| 32 | **32 of 32** | 931ms |

Nothing about the content changed between those rows. And each of those blocks
left another abandoned worker competing for the same cores, which is the
feedback half: **the busier the gateway got, the more clean traffic it blocked,
and every block made the next scan slower.** That is a metastable failure — a
system with no stable operating point under load — reached without an attacker,
by four concurrent requests on a CPU-starved node. Each block also wrote an
un-rate-limited `WARN` line (64 timeouts ⇒ 64 lines), and per the 2026-10-13
backlog's `X-2` a full `internal/logsink` **blocks the request goroutine**, so
the storm has a third amplifier.

Worse for the operator: those blocks were logged as
`DPI: regex timeout after 200ms on pattern "p0"`. The node reported that the
operator's *pattern* was slow when the actual fault was that the node was out of
CPU. The remediation that log points at — fix or drop the pattern — is the wrong
one.

A third defect surfaced while reviewing the diff, in the same function, and it
is the same class the register has already closed twice elsewhere: **the DPI
worker goroutine had no panic guard.** It runs attacker-supplied bytes through a
compiled regexp on the response-scanning path, and `internal/scanner` contains
no `recover()` and no `obs.SafeCall` anywhere. What makes it sharper than a
plain omission is that there appears to be a guard and it is in the wrong place:
root's `safeDPIScan` wraps the call in `recover()`
([security_scan.go:126](../../security_scan.go)), but that `recover()` runs on
the CALLING goroutine and cannot see a panic in the worker's — so a reader of
`safeDPIScan` would reasonably conclude DPI panics are contained. The twin
guards every match for exactly this reason and says so: *"The match runs
attacker-supplied bytes through a compiled regexp on the response-scanning path,
so an unrecovered panic would take down an in-line gateway"* (CHAOS-25,
`regexrunner.go`), and CHAOS-105 closed the same class for five background
workers. This one was left.

**Two fixes shipped**: a counted, bounded in-flight gate on the owning package,
with the slot released by the **worker** rather than the parent, so an abandoned
worker keeps occupying the cap for exactly as long as it keeps occupying the
heap. Post-fix, the same two experiments:

| | baseline | with the gate |
|---|---|---|
| 64 scans × 8 MiB window, all abandoned | +64 goroutines, **512.1 MiB** retained, 0 counted | +8 goroutines, **64.0 MiB** retained (= cap × window), 8 abandoned + 56 refusals counted |
| 4 concurrent clean scans, 1 core | **4 of 4 blocked** | **0 of 4 blocked** |
| 32 concurrent clean scans, 1 core | 32 of 32 blocked, 0 served, 931ms of CPU | 28 refused (counted), **4 served**, 259ms |

The second row is the point, and it is the opposite of what a cap intuitively
costs: bounding concurrency **removes** false blocks, because it keeps each
match's elapsed time close to its CPU time and lets the budget go back to
measuring the content.

And the worker's pattern walk is now wrapped in `obs.SafeCall`, so a panicking
match fails closed with a distinguishable reason (`dpi-match-panic`, counted by
`MatchPanics()`) instead of terminating the gateway, answering the parent at
once rather than making it wait out a budget that can never be met.

---

## 2. Failure scenarios

Each row states the fault, what the baseline did, what it should do, and where
the behaviour is now decided.

### 2.1 `CPU starvation` / `Network latency` — a slow match under concurrency

**Fault.** Any condition that makes a match's wall-clock span exceed its budget
while its CPU cost stays inside it: a cgroup CPU quota shared with a noisy
neighbour, a throttled burst, a large `max_scan_mb` window, a costly pattern
set, or simply more concurrent inspected responses than cores.

**Baseline.** Fail closed on every affected scan (correct in isolation),
reported against the pattern (misleading), with no cap on how many such scans
can be in flight and no counter for how many were refused. Measured: 100% of
clean bodies blocked at concurrency 4 on one core with a 3x budget margin.

**Expected.** Concurrency bounded near the CPU allowance so the budget measures
content; refusals attributed to capacity, not to a pattern.

**Now.** `acquireSlot` admits at most `2 × GOMAXPROCS` concurrent workers
([inflight.go](../../internal/scanner/inflight.go)). Go sizes `GOMAXPROCS` from
the cgroup quota, so a CPU-limited container gets a correspondingly smaller gate
with no operator action. Measured 0 of 4 blocked where the baseline blocked 4 of 4.

### 2.2 `Memory pressure` / `OOM` — the abandoned population

**Fault.** N inspected responses whose matches overrun, concurrently.

**Baseline.** N live goroutines, each retaining one scan buffer, for as long as
each uninterruptible match runs. Unbounded in N, uncounted, invisible.
`recover()` cannot see a Go OOM and `GOMEMLIMIT` cannot reclaim reachable heap,
so neither existing backstop covers it — the same two facts CHAOS-109 recorded
for the ingest plane.

**Expected.** A hard ceiling of `cap × window`, and a gauge an operator can read.

**Now.** The worker releases its slot in a `defer`, so the cap counts abandoned
workers; `Inflight()` is a true gauge of live workers. Measured ceiling held at
64.0 MiB where the baseline reached 512.1 MiB on the same workload.

### 2.3 `Thousands of simultaneous connections` — arrival concurrency

**Fault.** A reconnect storm or a busy appliance drives many concurrent
inspected text responses.

**Baseline.** One goroutine per response, no bound.

**Expected.** Ordinary bursts must be *served*, not refused: a DPI scan is one
unit per response, so the cap is reached by arrival concurrency, and refusing at
the cap the way `internal/yara` does would turn "busy" into "blocking".

**Now.** This is the one deliberate divergence from the twin. A scan that finds
the gate full **waits** for a slot, bounded by the same budget one pattern may
run for. Because a typical operator pattern matches in hundreds of nanoseconds,
the wait is unobservable in normal operation: at a 5s wait budget and a 0.5ms
match, an 8-core node's gate sustains tens of thousands of scans per second with
microseconds of queueing. Only a gate occupied by genuinely long-running matches
makes the wait real. Negative control
(`TestChaos110_NegativeControl_RoomyGateRefusesNothing`) pins that a cap above
the offered load refuses nothing.

### 2.4 Wedged engine — sustained pathological matches

**Fault.** Every slot held by abandoned workers stuck in uninterruptible matches.

**Behaviour, by design.** Every new scan waits its budget and then fails closed.
That is the correct posture for an in-line security gateway — it cannot inspect,
so it must not pass — and it is the same verdict the existing timeout branch
already returns for the same epistemic state, so this is **not a new posture**,
only a bounded one. The difference from the baseline is that it is now counted
(`SaturationBlocks()`), logged with the cause, and visible in the admin UI,
instead of arriving as an unexplained block storm.

### 2.5 `Kernel panic`-adjacent — a panic inside the match

**Fault.** `ps.matchOne` panics: a fault in the regex engine, or in any future
matcher installed behind that seam.

**Baseline.** Process termination. The worker goroutine had no `recover()`, and
root's `safeDPIScan` guard is on a different goroutine, so nothing stood between
a panicking match and the death of the proxy, the control plane and the admin
UI. Go's `regexp` is not known to panic, which is presumably why this survived —
but it is also true of `internal/yara`'s matcher, and that one is guarded.

**Expected.** Contained, fail-closed, counted, and distinguishable from a
timeout — the posture CHAOS-24/25 set for every detached go-site in this tree.

**Now.** `obs.SafeCall(dpiMatchComponent, …)` wraps the whole pattern walk.
The guard is deliberately coarser than the twin's per-match one because the
granularity matches the verdict: a DPI scan yields ONE hit/no-hit over the whole
list, and a contained panic already forces that verdict to "block", so a
surviving loop would have nothing left to decide. Wrapping once also keeps the
cost O(1) in pattern count, which is the contract the alloc gate holds —
measured still 7 allocs/op flat at 1, 10, 20 and 50 patterns after the guard
was added.

### 2.6 Already-correct behaviour, and why

Three properties were checked and found sound; they are not findings.

- **The timeout verdict itself is fail-closed** and attributes the budget to the
  pattern actually running, with the *worker* also enforcing the budget on
  matches it has already finished — closing the window where a descheduled
  parent would forget an overrun and admit suspicious content
  (`patternSet.match`'s comment, verified in source). The budget is per pattern,
  not per scan, so a long pattern list does not fail closed on its own
  (`TestScan_BudgetIsPerPatternNotPerScan`).
- **The abandoned worker stops early**: it checks the `abandoned` flag between
  patterns, so it does not scan the remainder. It cannot stop the match it is
  inside, which is a property of `regexp`, not a defect here.
- **Go's `regexp` is RE2**, so classic catastrophic backtracking is not
  available to an attacker. Match cost is linear in input length times program
  size, which is why the realistic trigger for this round is CPU starvation and
  window size rather than a crafted body. This is a *narrowing* of `X-5`'s
  implied threat model and it is stated here so the row is not over-read.

---

## 3. Risk matrix

| id | finding | likelihood | impact | rating | status |
|---|---|---|---|---|---|
| 110-1 | Abandoned DPI workers unbounded and uncounted; `N × scan-window` reachable heap, invisible to `GOMEMLIMIT` and `recover()` | MED (needs overrunning matches) | HIGH (in-line gateway OOM takes proxy, control plane and admin UI with it) | **HIGH** | **FIXED** |
| 110-2 | Wall-clock budget + unbounded concurrency ⇒ clean traffic blocked in proportion to load, with a self-reinforcing loop | MED-HIGH (four concurrent requests on a CPU-starved node) | HIGH (false blocks of legitimate traffic, metastable) | **HIGH** | **FIXED** (0 of 4 where baseline blocked 4 of 4) |
| 110-3 | No in-flight gauge, saturation counter or alert for the DPI engine, where the twin has all three | HIGH (certain) | MED (silent degradation; operator cannot see the squeeze) | **MED** | **FIXED** for the gauge/counters and the GUI tiles; the alert plane is the open half (§8.1) |
| 110-4 | Capacity-induced blocks are logged against the operator's *pattern*, pointing at the wrong remediation | HIGH (certain, whenever 110-2 fires) | MED (misdiagnosis; operators delete sound patterns) | **MED** | **PARTLY**: gate refusals now name capacity; a contention-induced budget overrun still names the pattern (§8.2) |
| 110-7 | The DPI worker goroutine had no panic guard, while root's `safeDPIScan` *looks* like one and cannot reach it; the twin guards the same operation for the stated reason | LOW (Go `regexp` is not known to panic) | **CRITICAL** (process death on an in-line gateway: proxy, control plane and admin UI) | **MED** | **FIXED** |
| 110-5 | The per-event DPI timeout log is not rate-limited; one line per abandoned scan, into a sink that blocks the request goroutine when full (`X-2`) | MED | LOW-MED (amplification during the exact event that caused it) | **LOW-MED** | **NOT FIXED** — deliberately, to match the twin's precedent (§8.3) |
| 110-6 | Per-worker retention is governed by the *security* scanner's `max_scan_mb`, not the DPI scanner's own 1 MiB cap | HIGH (certain by construction) | MED (surprises an operator raising an unrelated setting) | **LOW-MED** | **BOUNDED** by the cap; the cross-owner coupling is recorded (§8.4) |

---

## 4. Recovery assessment

| | baseline | now |
|---|---|---|
| **Automatic** | Yes, eventually: each abandoned worker frees its body when its match ends. There is no bound on how long that takes or how many accumulate first, so recovery is not deterministic and can be outrun by arrival rate. | Deterministic. Live workers ≤ cap at all times, so the ceiling is `cap × window` regardless of arrival rate. Refusals clear the moment a slot frees. |
| **Manual** | None available. The engine exposed no gauge, so an operator had no way to see the state, and no setting to bound it. | `Inflight()`, `MaxInflight()`, `SaturationBlocks()`, `AbandonedWorkers()` on the role-gated status endpoint and two admin-UI tiles. `SetMaxInflight` is the wired seam for an operator setting if one is later wanted. Removing or narrowing the offending pattern remains the real remedy for a genuinely slow pattern. |
| **Restart** | Clears everything, as it always did; the gate changes nothing about restart semantics. No persistence is involved — all state is process-local counters. | Same. |
| **Fail direction** | Fail closed on timeout (correct), but unbounded in resource terms. | Fail closed on timeout **and** on wait-exhaustion, bounded in resource terms. No new fail-open path was introduced anywhere. |

---

## 5. Operational impact

- **Normal traffic: none.** The fast path is one non-blocking channel send and
  one atomic add. The package's allocation gate
  (`TestBenchGate_DPIScanAllocsConstantInPatternCount`, root, `benchgate` tag)
  still measures **7 allocs/op flat at 1, 10, 20 and 50 patterns**, unchanged;
  bytes went 480 → 496 B/op, one extra pointer inside the `scanState`
  allocation that already existed.
- **Busy traffic:** queueing instead of contention. Latency is added only when
  the engine is already occupied, and it is bounded by the per-pattern budget —
  inside the envelope a scan could already consume.
- **Saturated traffic:** the operator now gets a cause (`in-flight cap reached`,
  rate-limited to once per 10s), a count, and an 80%-of-cap warning *before*
  blocks start. Previously: an unexplained block storm attributed to a pattern.
- **No new operator setting**, so no GUI-parity obligation is incurred
  (conventions, "UI, configuration and API changes"). The cap is derived from
  the CPU allowance, which is the resource it bounds, and tracks a cgroup quota
  automatically.

---

## 6. Security impact

- **No fail-open path is introduced.** Both new exits — wait-exhaustion and the
  pre-existing timeout — report the content as suspicious (S17 / Zero Trust). A
  flood cannot be used to push content past DPI, which is the attack an
  immediate fail-*open* at the cap would have created.
- **The cap is not a new denial-of-service lever** for an attacker who could
  already saturate the engine: the baseline's response to that same saturation
  was to block **100%** of concurrent scans (§1) while exhausting heap. The
  gate's response is to block fewer of them (4 served instead of 0 at
  concurrency 32) and to stay inside a memory ceiling.
- **No posture is disclosed to clients.** `SaturatedReason` reaches the
  `DPI_BLOCKED` log line and the inspection record only; the client-visible
  block page is the pre-existing fixed string
  `"Blocked by content inspection policy"` naming no pattern
  ([scanner.go `dpiBlock`](../../scanner.go)). The magnitudes live on the
  role-gated `/api/security-scan/status`; `/healthz` and `/ready` stay coarse,
  per the rule those surfaces already follow.
- **Availability is a security property here.** 110-2 is a false-block
  generator on an in-line gateway, and the usual operator response to
  unexplained DPI blocks is to disable DPI. A fault whose natural remediation is
  "turn the control off" is a security finding, not only an availability one.

---

## 7. Data-integrity impact

None. Every surface this round touches is process-local: counters, a semaphore
channel, and one goroutine's stack. No persistence, wire format, snapshot or
config version is involved, and no file is written. The `scanState` struct gains
one unexported pointer field; it is never serialised.

---

## 8. Suggested improvements (the open halves)

Ranked. None of these is shipped in this round; each is recorded so it is not
re-discovered.

### 8.1 A `dpi_degraded` alert (MED)

`internal/yara` fires `yara_degraded` through `internal/alerts` on both
approaching-saturation and saturation. `internal/scanner` does not import
`internal/alerts`, so wiring one is a new package edge and belongs with a
[package isolation](../../roadmap/PACKAGE-ISOLATION.md) record and the relevant
ADR rather than inside a chaos fix. Until then the signal is a rate-limited log
line, the role-gated counters and the admin-UI tiles — visible, but it does not
page anyone. **This is the gap most worth closing next.**

### 8.2 Charge the budget against CPU time, not wall clock (MED)

The cap keeps elapsed time near CPU time, which makes 110-2 much harder to
reach, but it does not make the budget *correct*: a contention-induced overrun
still reports the pattern that was running. Measuring the match on a
per-goroutine CPU clock would attribute cost to the content rather than to the
node's load, and would let the gate's cap be raised safely. It is a real change
to how the budget is defined, so it needs an owner decision, not a rider.

### 8.3 Rate-limit the per-event DPI timeout log (LOW-MED)

Measured: 64 timeouts produced 64 `WARN` lines, and `X-2` records that a full
`internal/logsink` blocks the request goroutine. Deliberately **not** changed
here, because the in-tree precedent runs the other way — `yaraTimeoutResult`
logs every timeout unconditionally, and only the *saturation* log is
rate-limited (which is exactly what this round did for its new line). Narrowing
per-event forensics on the DPI path alone would be an unilateral posture change
across two engines that currently agree. Owner decision.

### 8.4 Give the DPI scanner its own window (LOW-MED)

`safeDPIScan` receives the buffer sized by `maxScanBufferBytes()`, i.e. the
larger of the DPI cap and `max_scan_mb`, so raising a *security-scanner* setting
silently multiplies what every DPI worker retains. Truncating to
`dpiScanner.MaxBytes()` at the call site would make the DPI engine's own cap
mean what it says. It is a behaviour change to what DPI inspects — a body
between 1 MiB and `max_scan_mb` would stop being DPI-scanned — so it is an owner
decision about inspection coverage, not a cleanup.

### 8.5 Make the cap an operator setting (LOW)

`SetMaxInflight` exists and is unused in production by design: adding a setting
pulls in the admin API endpoint, the `uiRoutes` entry and a UI surface. The
derived default tracks the CPU allowance, which is the right default for the
resource. Worth doing only if a deployment is found that needs to diverge.

### 8.6 Gate the standalone matcher (LOW)

`MatchRegexWithTimeout` / `runWithTimeout` spawn an ungated worker by the same
pattern. **No production caller exists** — root's `matchDPIRegexWithTimeout` is
a test re-export only ([scanner.go:33](../../scanner.go)) — so this is latent,
not live. A doc pointer to the gate was left on it so a future caller does not
reintroduce the hole.

---

## 9. Measurements and commands

Toolchain: `go1.27.3` (`go.mod` `toolchain`), `GOTOOLCHAIN=auto`, linux/amd64,
4 cores. All fault injection drives the match step through the package's own
`patternSet.matcher` seam, so timings are decided by the test and not by how
fast the machine runs a regex.

### 9.1 RED-A — abandoned workers retain one body each (baseline)

200 concurrent scans, 1 MiB bodies, 50ms budget, matchers blocked; measured
after every parent had returned and the test held no body reference, following
an explicit `runtime.GC()`:

```
RED-A  scans=200  bodyMiB=1  entered=200  verdict_blocked=200
RED-A  goroutines 2 -> 202 (delta +200)
RED-A  retained heap after GC with every parent returned: 200.3 MiB
RED-A  after releasing the matchers: goroutines=2 retained=0.2 MiB
```

Linearity, at an 8 MiB window (64 scans):

```
RED-A  scans=64  bodyMiB=8  entered=64  verdict_blocked=64
RED-A  goroutines 2 -> 66 (delta +64)
RED-A  retained heap after GC with every parent returned: 512.1 MiB
RED-A  after releasing the matchers: goroutines=2 retained=0.0 MiB
WARN lines emitted: 64
```

Exactly one body per worker, reclaimed in full only when the matches ended —
so the retention is the abandoned workers and nothing else.

### 9.2 GREEN-A — the same workload under the gate

Same 64 × 8 MiB workload, cap 8 (`2 × GOMAXPROCS` on this 4-core box):

```
RED-A  scans=64  bodyMiB=8  entered=8  verdict_blocked=64
RED-A  goroutines 2 -> 10 (delta +8)
RED-A  retained heap after GC with every parent returned: 64.0 MiB
RED-A  gate: inflight=8 max=8 saturation_blocks=56 abandoned=8
```

512.1 MiB → 64.0 MiB, and the ceiling is now `cap × window` by construction
rather than `arrivals × window`. Note `entered=8`: the 56 refused scans never
ran a match at all.

### 9.3 RED-B / GREEN-B — concurrency manufacturing blocks

`GOMAXPROCS=1` (the CPU-starvation row), 200ms per-pattern budget, a matcher
needing ~68ms of CPU — a 3x margin — and bodies that match nothing:

| concurrency | baseline blocked | wall | with gate (cap 2) | of which gate refusals | wall |
|---|---|---|---|---|---|
| 1 | 0 / 1 | 68ms | 0 / 1 | 0 | 67ms |
| 4 | **4 / 4** | 251ms | **0 / 4** | 0 | 259ms |
| 8 | 8 / 8 | 348ms | 4 / 8 | 4 | 264ms |
| 32 | 32 / 32 | 931ms | 28 / 32 | 28 | 259ms |

Read carefully, because the last two rows are not a clean win and should not be
reported as one. At concurrency 32 the offered work is 2.2 core-seconds against
a 200ms budget on one core: **no admission scheme can serve all of it.** What
changes is that the baseline served **0** of 32 while spending 931ms of CPU to
do it, and the gate serves **4** while spending 259ms and keeping heap bounded.
The row that carries the finding is concurrency **4**: the same clean bodies, a
3x budget margin, 4 of 4 blocked before and 0 of 4 after.

`GOMAXPROCS=1` is how the CPU-starvation row was simulated. On an N-core node
the same effect needs proportionally more concurrency; the invariant is that a
block appears once a match's wall span exceeds its budget, and wall span grows
with concurrent CPU-bound matches per core. Default `max_scan_mb` leaves the DPI
window at 1 MiB, so the 8 MiB figures above correspond to an operator-raised
window, not a stock install.

### 9.4 Mutation test — the gate has teeth

The load-bearing property is that the **worker**, not the parent, releases the
slot. Moving the release to the parent (the pre-CHAOS-110 ownership) is caught
exactly:

```
--- FAIL: TestChaos110_AbandonedWorkerStaysCountedUntilItsMatchReturns
    Inflight() = 0 after the parent abandoned, want 1 — an abandoned worker
    that is not counted is the unbounded population CHAOS-110 closes
--- FAIL: TestChaos110_CapIsNeverExceededAndRefusalsFailClosed
    timed out waiting for every worker to release (inflight=2 max=2)
```

### 9.5 Checks run

| check | command | result |
|---|---|---|
| owner package, race + determinism | `go test -race -shuffle=on -count=2 ./internal/scanner` | pass |
| owner package gates | `go test ./internal/scanner -run TestChaos110 -count=1 -v` | 7 pass |
| vet, tidy | `go vet ./...`, `go mod tidy -diff` | clean |
| build (amd64, arm64) | `CGO_ENABLED=0 go build …`, `GOOS=linux GOARCH=arm64 …` | pass |
| alloc gate | `go test -tags benchgate -run 'TestBenchGate_DPIScan' -v .` | 7 allocs/op at 1/10/20/50 patterns, bound 12 |
| guidance checker | `python3 docs/agent-context/check.py` | pass |

The remaining root-suite, lint and aggregate-CI results for the exact SHA are
reported on the pull request, not here. A passing local selection is not a
passing hosted gate.

---

## 10. Residual risk

- **A wedged engine still fails closed, fleet-wide if the cause is fleet-wide.**
  A pattern that overruns on common content will saturate the gate on every node
  that has it, and every node will refuse. That is the intended posture, and it
  is the same direction the timeout branch already took; what is new is that it
  is bounded and visible. It is not silent any more, but it is not *paged*
  either until §8.1 lands.
- **The budget is still wall clock** (§8.2). The cap narrows the window in which
  load can masquerade as a slow pattern; it does not close it. On a node
  oversubscribed far beyond its quota, false blocks remain reachable.
- **`2 × GOMAXPROCS` is a judgement, not a measurement.** It is defensible —
  two CPU-bound matches per core, slack for descheduling, no over-subscription
  of the budget — and it is pinned by a test, but no production workload was
  profiled to choose it. A deployment with many short patterns and high arrival
  concurrency could see queueing the baseline would not have had. The wait
  budget (one pattern's worth) and `SaturationBlocks()` are what make that
  visible rather than mysterious if it happens.
- **The 64 MiB ceiling is still 64 MiB.** The gate bounds the abandoned
  population; it does not shrink a body. An operator who raises `max_scan_mb`
  raises the ceiling proportionally, and §8.4 is unaddressed.
- **`X-5` is closed for `internal/scanner` only.** This round did not re-sweep
  the other scan producers; `internal/secscan`'s remote path, `internal/clamav`
  and the CDR sidecar have their own admission stories, examined by CHAOS-52 and
  CHAOS-53 and not revisited here.
