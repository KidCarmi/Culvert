# Chaos-Engineering Review — 2026-08-21

**Domain:** the body-scan pipeline (ClamAV + YARA) under scanner **slowness and
saturation** — the regime a production gateway reaches long before a scanner is
actually "down".

**Method:** evidence-first source review of `internal/secscan`,
`internal/clamav`, and `internal/hashcache`, followed by fault injection. Every
defect below was reproduced against the pre-fix tree before being fixed, and
each regression gate was re-run against the pre-fix behavior to confirm it
fails there (§8).

---

## 1. Executive Summary

The register has carried **WK-1** ("ClamAV daemon down → files pass UNSCANNED,
fail-open") as an open High since the first sweep, framed as a *posture*
question: is fail-open the right answer when the antivirus daemon is gone?
CHAOS-10 later made that branch visible (counter + `scan_clam_error` alert) and
stopped it poisoning the cache, and the posture was left as an owner decision.

That framing turns out to have understated it. **The fail-open branch is not
reachable only by a daemon fault. It is reachable by LOAD, on a completely
healthy daemon, with no infrastructure failure anywhere** — and the mechanism is
a private constant three call-frames below the decision it overrides.

`clamav.Client.Scan` limits concurrency to four (`clamMaxConcurrent`) and, when
all four slots were busy, waited **five seconds and then returned an ordinary
error**. The orchestrator classifies any error from the engine as a fault and
takes the fail-**open** branch. Its own budget — `ScanBodyTimeout`, ten seconds,
the limit that exists precisely to decide this case — fails **closed**. So the
inner limit always fired first and inverted the outer one's verdict:

> Five concurrent downloads large enough to keep four scans busy for five
> seconds cause the fifth and every subsequent response to be **forwarded
> without antivirus inspection**, reported as a daemon error.

That is attacker-inducible on demand and needs no privilege: saturate the
scanner with four slow, large, benign fetches, then pull the payload through the
gap. It is also self-sustaining, because of a second defect that amplifies it.

`ScanBody` enforced its deadline with `time.After` and simply **stopped waiting**
for the scan goroutine — nothing stopped the *work*. The abandoned scan kept its
ClamAV slot until the client's own 30 s timeout: **three times the budget that
had already given up on it**. So once scans begin to time out, abandoned work
crowds out live work, live scans hit the queue-full path, and the queue-full
path fails open. Load sustains the regime; the system does not climb out of it
while traffic continues. Measured directly: a scan cancelled at a 150 ms
deadline held its slot for **30.006 s** on the pre-fix tree.

Two further defects sit in the same function and decide what happens *after* a
timeout — and they pull in opposite directions, so the outcome for identical
content was decided by a race:

* The fail-closed refusal was written into the hash cache with the **content
  TTL** (one hour by default). Seconds of scanner slowness therefore blocked
  that exact object, node-wide, for every user, for an hour after recovery —
  recoverable only by an admin cache flush.
* Unless the abandoned goroutine finished first, in which case it wrote its own
  **`Clean: true`** verdict over the refusal — silently converting a fail-closed
  decision into a cached admission for the rest of the TTL, with no counter and
  no log line.

The second is the more serious of the pair and it is the exact mistake the code
two lines above it already knows about: the ClamAV-error branch carries a
comment explaining that a verdict computed while the daemon was dark must not be
cached, *"otherwise the same content stays admitted by hash long after ClamAV
recovers."* The reasoning had been applied to one branch and not to its
neighbour — the same shape as the 2026-08-19 review's own §13.1 finding, where a
gauge got the omit-when-absent treatment and the gauge beside it did not.

All four are fixed. The unifying rule is stated once, in the code:

> **An inner deadline must never preempt an outer one and invert its posture,
> and abandoned work must release what it holds.**

---

## 2. Failure Scenarios

### SC-1 — Capacity exhaustion admitted content unscanned (P1, security)

| | |
|---|---|
| **Trigger** | More than `clamMaxConcurrent` (4) concurrent body scans for longer than 5 s. A burst of large downloads; a signature reload; memory pressure on the ClamAV host. **No infrastructure fault required.** |
| **Pre-fix behavior** | `Scan` returns `"clamav: scan queue full (4 concurrent), timed out"`. `scanBodyInner` treats every error as an engine fault → `clamDark = true` → falls through to YARA → returns clean → content **forwarded unscanned by antivirus**, and a `scan_clam_error` alert blames a healthy daemon. |
| **Expected** | Exceeding the scan budget is what `ScanBodyTimeout` already decides, and it decides it fail-closed. |
| **Fix** | The queue wait is charged to the **caller's** context (`ScanContext`). Exceeding it now lands on the caller's fail-closed path. `ErrQueueFull` keeps saturation distinguishable from a daemon fault so the two get different counters, different log lines, and no alert for the one that is not a fault. |
| **Residual** | Effective scan concurrency is still the hardcoded 4 — see §7. |

### SC-2 — Abandoned scans held the scarce resource (P1, metastability)

| | |
|---|---|
| **Trigger** | Any scan exceeding `ScanBodyTimeout`. |
| **Pre-fix behavior** | The goroutine ran on uninterrupted, holding a ClamAV slot to the client's 30 s timeout plus a copy of the response body (up to `maxBytes`, 5 MiB default). Unbounded in count, invisible in every surface. Four such scans occupy every slot, so live requests take SC-1's fail-open path — the failure feeds itself. |
| **Expected** | Work nobody is waiting for must stop. |
| **Fix** | The budget is a `context`, not a timer. Cancellation reaches the dial, the connection deadline (`effectiveDeadline` takes the earlier of the caller's and the client's), and a watcher that closes the connection so a blocked read returns at once. Abandoned scans are now bounded in *time* by the budget, therefore bounded in *count* by (arrival rate × budget), and counted: `culvert_scan_inflight`. |

### SC-3 — The refusal outlived the fault (P2, availability)

| | |
|---|---|
| **Trigger** | Any scan timeout on content that is requested again within the cache TTL. |
| **Pre-fix behavior** | `cache.Set(hash, {Clean:false, Reason:"scan timeout"})` — the **content** TTL, one hour. An object scanned during a five-second stall stayed blocked for an hour for every user of the node. Recovery: an admin cache flush, or wait. |
| **Expected** | A verdict about the scanner is not a verdict about the content and must not inherit its lifetime. |
| **Fix** | `hashcache.SetTTL` + `scanTimeoutCooldown` (30 s). The useful half is kept — a burst of requests for one hot object must not each start a doomed 10 s scan, which is what fills the queue in the first place — without outliving the fault. |

### SC-4 — An abandoned scan could overturn the fail-closed verdict (P1, security)

| | |
|---|---|
| **Trigger** | A scan that finishes after its deadline. |
| **Pre-fix behavior** | The abandoned goroutine called `cache.Set(hash, {Clean:true})`, replacing the refusal the user had just been served with a cached admission for the rest of the TTL. No counter, no log. Whether a given object was blocked or served came down to which of two writers reached the cache first. |
| **Expected** | A fail-closed decision is a decision. Late work may **tighten** it, never loosen it. |
| **Fix** | `publishVerdict` enforces tighten-only: a late **blocking** verdict is still published (and usefully upgrades the placeholder `"scan timeout"` entry to the real threat name); a late **clean** verdict is discarded and counted (`culvert_scan_late_discarded_total`). The budget is additionally enforced from inside `scanBodyInner`, because `ScanBody`'s `select` can see a finished scan and an expired deadline as simultaneously ready and pick either — without that, an overrun could be laundered into a clean verdict by winning a coin flip. |

---

## 3. Risk Matrix

| # | Likelihood (pre-fix) | Impact | Severity | Detectability (pre-fix) |
|---|---|---|---|---|
| SC-1 | **High** — reachable by ordinary load; trivially inducible | Antivirus bypass for arbitrary content | **P1** | Misattributed: counted as a daemon error, alerted as a daemon fault |
| SC-2 | High wherever SC-1 is reachable | Turns a transient stall into a sustained one; memory held per abandoned scan | **P1** | **None** — no gauge, no counter, no log |
| SC-3 | Medium — one timeout is enough | Legitimate object blocked node-wide for up to 1 h post-recovery | P2 | Indistinguishable from a true positive in the block log |
| SC-4 | Medium — needs the late scan to win the race | Fail-closed refusal converted to a cached admission | **P1** | **None** |

---

## 4. Recovery Assessment

| | Pre-fix | Post-fix |
|---|---|---|
| **SC-1 automatic** | Yes, once load drops — but the traffic admitted during the window was never rescanned | Yes; refused traffic is retryable by the client |
| **SC-2 automatic** | Only after every abandoned scan reached the 30 s client timeout, which fresh load kept replenishing | Yes — abandonment is bounded by the scan budget |
| **SC-3 automatic** | After the full content TTL (1 h default) | After `scanTimeoutCooldown` (30 s) |
| **SC-3 manual** | `POST` the scan-cache clear (flushes *every* verdict, including real ones) | Same, rarely needed |
| **SC-4 automatic** | None — the cached admission stood for the TTL | N/A, cannot occur |

Recovery is on **observed evidence** throughout: the cooldown expires and the
object is rescanned by whatever engine is healthy at that moment; nothing is
latched on elapsed time alone.

---

## 5. Operational Impact

* **Counters and gauges are new, no configuration is.** No CLI flag, YAML key,
  or API knob is added, so the GUI-parity contract is satisfied by surfacing:
  `culvert_scan_timeout_total`, `culvert_clam_saturated_total`,
  `culvert_scan_late_discarded_total`, `culvert_scan_inflight`, plus
  `stat_clam_saturated` / `stat_scan_late_discard` / `scan_inflight` on
  `/api/security-scan/status`, three tiles in the Security panel, and three
  fields in the support bundle's `scan` section.
* **The alert plane gets quieter, not louder.** Capacity exhaustion no longer
  fires `scan_clam_error`. Pre-fix, one busy period produced a stream of alerts
  naming a daemon that was working perfectly — and it did so *while* the node
  was at its busiest, the same backwards-under-load shape the `HasSubscriber`
  gating rule exists to prevent.
* **Suggested paging rules.** `rate(culvert_clam_saturated_total[5m]) > 0` means
  add scanning capacity. `rate(culvert_scan_late_discarded_total[5m]) > 0` is a
  correctness signal, not a liveness one: content is being decided by the
  deadline rather than by the engines. `culvert_scan_inflight` staying at or
  above the ClamAV concurrency limit is the leading indicator of both.
* **Behavior change customers can observe:** under saturation a response is now
  **refused** (403, retryable) where it was previously **served unscanned**.
  That is the stated posture of the product — default deny, fail closed when
  recovery is impossible — and it was already the posture of the outer deadline;
  what changed is that an inner constant can no longer override it.

---

## 6. Security & Data-Integrity Impact

**Security.** SC-1 and SC-4 were both antivirus bypasses, one reachable by load
and one by a race. Neither required a compromised daemon, a malformed response,
or any privilege. SC-4 additionally made the bypass *durable*: once a clean
verdict was cached under the content hash, every later request for that exact
object skipped scanning entirely for the rest of the TTL.

**Data integrity.** Nothing persistent was corrupted — the hash cache is
volatile and node-local. What was corrupted was the *meaning* of its entries: it
held verdicts about the scanner (`"scan timeout"`) alongside verdicts about
content, with the same lifetime and no way for a reader to tell which kind it
had. `SetTTL` separates the lifetimes; `Source: "timeout"` already separated the
labels.

---

## 7. What Shipped

| Area | Change |
|---|---|
| `internal/clamav/clamav.go` | `ScanContext(ctx, …)` — the queue wait, dial, and connection deadline are charged to the caller's budget; `Scan` keeps the legacy budget via `clamQueueWaitFallback` for deadline-free callers. `ErrQueueFull` sentinel. `effectiveDeadline` (earlier of caller/client). `watchCancel` (cancellation closes the connection). Errors caused by our own abandonment are wrapped with the context cause. |
| `internal/secscan/secscan.go` | Budget is a `context`, propagated to ClamAV via the optional `clamContextScanner` capability (type-asserted, mirroring `clamVersioner`, so injected fakes are unaffected). `publishVerdict` tighten-only rule. Both-sides budget enforcement in `scanBodyInner`. `recordClamFailure` classifies budget-exhausted / saturated / engine-fault. `scanTimeoutCooldown` for the refusal. `scanInflight` gauge + `ScanInflight()`. New counters `ClamSaturated`, `ScanLateDiscarded`. |
| `internal/hashcache/hashcache.go` | `SetTTL(hash, result, ttl)`; `Set` delegates with `ttl = 0`. |
| `metrics.go` | `culvert_scan_timeout_total`, `culvert_clam_saturated_total`, `culvert_scan_late_discarded_total`, `culvert_scan_inflight`. |
| `security_scan.go` | `stat_clam_saturated`, `stat_scan_late_discard`, `scan_inflight` on the status map. |
| `support_collectors_posture_b.go` | Same three fields in the support bundle's `scan` section (`internal` class). |
| `static/index.html` | Three tiles: *ClamAV at capacity*, *Scans in flight*, *Late verdicts discarded*. |

---

## 8. Required Tests

`internal/clamav/clamav_budget_chaos_test.go` (4 gates) and
`internal/secscan/scan_saturation_chaos_test.go` (6 gates), plus
`internal/hashcache/hashcache_ttl_test.go` (2).

Each behavioral gate was re-run against the pre-fix behavior, restored branch by
branch, and observed to fail:

| Gate | Pre-fix failure observed |
|---|---|
| `TestChaos_QueueWaitIsChargedToTheCallersBudget` | `saturation must be distinguishable from a daemon fault, got clamav: scan queue full (4 concurrent), timed out` (after 5.00 s, ignoring the caller's 250 ms) |
| `TestChaos_QueueWaitOutlivesTheOldPrivateConstant` | the private 5 s cap fails out a caller with seconds of budget left |
| `TestChaos_AbandonedScanReleasesItsSlotPromptly` | `abandoned scan took 30.005879909s to unwind — it held its slot to the client timeout (30s)` |
| `TestChaos_LegacyScanKeepsItsOwnBudget` | (guards the compatibility path — deadline-free callers must not block forever) |
| `TestChaos_TimeoutRefusalDoesNotOutliveTheFault` | the refusal is still cached after the cooldown, under the content TTL |
| `TestChaos_AbandonedScanCannotOverturnTheFailClosedVerdict` | `an abandoned scan overturned the fail-closed verdict: {Clean:true … Source:clean}` |
| `TestChaos_AbandonedScanMayStillTighten` | (direction gate — proves the rule is tighten-only, not blanket discard) |
| `TestChaos_InnerScanNeverLaundersAnOverrunIntoClean` | `a scan completing outside its budget must fail closed, got <nil>` |
| `TestChaos_AbandonedScansAreCountedAndUnwind` | `abandoned scans must be visible while they are still holding resources` |
| `TestChaos_ClamSaturationIsNotReportedAsAnEngineFault` | `ClamSaturated delta = 0, want 1` |

All run under `-race`.

---

## 8b. Operator Runbook

`docs/operator/scan-capacity-and-timeouts.md` — signals, suggested paging rules, triage flow, how to
add scanning capacity, and the posture table.

---

## 9. Residual Risk

* **`clamMaxConcurrent` is still a hardcoded 4, and it is now availability-
  critical.** Making saturation fail closed converts a silent bypass into a
  visible refusal, which is the correct direction, but it means a node whose
  scanning capacity is genuinely too small now *blocks* where it used to *admit*.
  The counter and the in-flight gauge are the operator's signal, and no
  configuration knob was added — deliberately, because a knob whose only use is
  widening a security bypass deserves a design decision, not a side effect of a
  chaos fix. **Raising or making the limit configurable (with GUI parity) is the
  natural follow-up** and is recorded as a register row rather than smuggled in.
* **WK-1's original half is unchanged and remains an owner decision.** A ClamAV
  daemon that is genuinely *down* still fails **open** (counted and alerted, per
  CHAOS-10). The asymmetry with saturation is deliberate and worth stating:
  a down daemon is an operator-visible infrastructure state with its own alert
  and status surface, and refusing all traffic on it is a fleet-wide outage;
  saturation is transient, self-clearing in seconds, and inducible on demand by
  whoever wants the gap. That is the same shape as register row **CA-3b** and is
  recorded, not resolved, here.
* **YARA is not cancellable.** `YARAMatcher.Match` has no context, so the YARA
  leg of an abandoned scan still runs to its own internal timeouts. It is
  bounded (`internal/yara` has per-match deadlines, an in-flight cap and a
  posture), and the tighten-only rule means its late verdict can no longer do
  harm — but the CPU is still spent. Threading the budget into YARA is the same
  change one layer down and is deliberately not bundled here.
* **The remote scan sidecar (`internal/secscan/remote.go`) was not touched.** It
  is the other fail-open scanning path (WK-2, `AddRemoteScanFail`), with its own
  30 s per-request timeout and no budget threading. The findings above are
  structurally likely to repeat there; that is a separate sweep.
* **`scanTimeoutCooldown` is a constant.** 30 s is a judgement, not a measured
  optimum: long enough to absorb a burst for one hot object, short enough that
  the blast radius of a stall is seconds rather than an hour. Exposing it would
  add a knob whose failure mode is "operator sets it to an hour and reinvents
  SC-3".
* **A spurious refusal is still possible** for content whose scan legitimately
  exceeds 10 s (a very large archive on a loaded node). That is the intended
  fail-closed posture and was already true; what changed is that it is now
  visible in `culvert_scan_late_discarded_total` when the late verdict says the
  content was in fact clean.

---

## 10. Process Note

Both SC-3 and SC-4 sit within twenty lines of a comment that states the correct
rule for the *neighbouring* branch. This is the third time a sweep has found
that shape (2026-08-19 §13.1, the omitted gauge; CHAOS-28's paired persist
observers). The generalisable form:

> When a branch is given a special rule because of what it computed under
> failure, check every sibling branch that computes under the same failure. The
> reasoning is almost never specific to the branch that happened to be reviewed.
