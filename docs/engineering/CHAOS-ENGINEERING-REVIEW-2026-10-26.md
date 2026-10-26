# Chaos Engineering Review — 2026-10-26

## CHAOS-93 — The retry plane: does it wait, can it be interrupted, does the work survive?

**Scope.** Every loop in the tree that re-attempts a failed operation, asked the
three questions the SIMULATE list puts next to each other — *broken retries*,
*broken backoff*, *SIGTERM*, *unexpected restart*. The sweep's subject is the
retry *mechanism*, not any one subsystem, so it crosses three owners: release
delivery (`release_dispatch_exec.go`), the intelligence feeds
(`internal/threatfeed`, `internal/feedsync`) and observability
(`internal/alerts`).

**Origin.** The three retry/cancellation rows the
[2026-10-18 sweep](CHAOS-ENGINEERING-REVIEW-2026-10-18.md) verified and
deliberately left open — its suggested improvements 4, 5 and 6 — because each
needed "its own regression test and a judgment call about deployment-visible
timing". This sweep is that follow-up. Asking the third question (*does the work
survive the attempt?*) of the alert queue then turned up a defect that outranks
all three and was not in the inherited scope.

Id claimed in a committed register placeholder row as commit one, per the
convention `roadmap/CHAOS-ENGINEERING-REVIEW.md` §0 reaches after ten
collisions.

---

## 1. Executive Summary

**The tree knows how to retry. It has bounded exponential backoff with a
clamped floor and stable per-node jitter in `internal/feedsched`, a
consecutive-error budget on a ticker in `WaitOp`, a durable state machine in
`support_upload_queue.go`, and a ctx-aware bounded retry in
`mcp_telemetry.go`. Five retry sites did not use any of it, and the defect in
each is a different one of the three questions.**

| Question | Site | What it did |
|---|---|---|
| Does it wait? | `applyWithRetry` | 3 attempts, no sleep — the whole budget spent in microseconds |
| Can it be interrupted? | `threatfeed` / `feedsync` rounds | declared `Run: func(context.Context) bool` and **dropped the parameter** |
| Can it be interrupted? | alert retry pass | took no ctx; each delivery built its own from `context.Background()` |
| **Does the work survive?** | **alert retry pass** | **removed its entries from the durable queue before delivering any of them** |
| (observability) | alert retry pass | recorded every re-delivery as attempt 1 |

### The sharpest one: the alert queue loses its batch on an ordinary restart

`processRetryQueue` moved **every** due entry out of `retryQueue`, persisted the
truncated queue, released the lock, and only then began delivering them one at a
time at up to 5s each.

For the length of that pass, every not-yet-attempted entry existed **solely in a
local slice** — absent from memory's queue and absent from the file. The queue is
the durability mechanism, and the pass took the work out of it in order to do
the work.

So any of these discards all of them:

- `SIGTERM` on a config reload or a rolling upgrade;
- the lifecycle context cancelled at shutdown hook order 40 while the pass runs
  on (nothing joins the retry goroutine, and the late phase has a 30s budget —
  the process exits long before a long pass finishes);
- OOM, `SIGKILL`, a node reboot, power loss.

And it discards them **in silence**. The plane has two counters built precisely
so an admin can see alerting degradation on the delivery-history API —
`retryExhaustedTotal` and `retryDroppedTotal` — and neither covers this path.
No delivery is recorded. Nothing is logged. The queue depth simply drops.

Against a blackholing webhook the window is the whole pass:
`retryQueueMax` × `deliveryTimeout` = 500 × 5s ≈ **42 minutes**, with up to
**499** alerts lost. The regression gate measures it directly: **0 of 10 entries
persisted**.

This is the **ST-8** shape (register §13, silent audit-trail loss on a failing
volume) relocated into the alert queue — and it is worse there in one respect.
Losing alerts quietly is the worst available failure for the plane whose entire
job is to report that something *else* broke. An operator reading a healthy
dashboard after a restart has no way to know that the webhook queue was emptied
rather than drained.

The fix is the one the tree already uses one directory over: an entry stays in
the durable queue across its own attempt. `support_upload_queue.go` holds an
`uploading` state **in** the queue rather than lifting the entry out of it.

### The retry that could not retry

`applyWithRetry` looped `applyRetries = 2` (three attempts) with no sleep, no
backoff and no jitter. The budget exists for exactly one fault — a maintenance
agent that is briefly unreachable, nearly always because it is restarting — and
that fault **refuses the connection in microseconds**. All three attempts
therefore burned in well under a millisecond, and the dispatch landed
`TerminalFailedNeedsAttn`: an operator-visible failure requiring a manual
re-dispatch, for an agent that was serving again a second later.

"Three attempts" has to mean three attempts spread across the outage, not three
syscalls against the same closed socket. `WaitOp`, 170 lines further down the
same file, already got this right.

### The rounds that cannot be shut down

`feedsched` is a package written specifically to fix the feeds' scheduling, and
its doc comment promises "**prompt cancellation**" and "the wait is
interruptible: ctx cancellation returns promptly from inside a backoff, so
shutdown never waits out a delay". `Config.Run`'s own comment says "**It must
respect ctx**".

Both feeds declared `Run: func(context.Context) bool` and dropped the parameter,
then fetched on `context.Background()`. The scheduler's guarantee is only as
good as the round's, so in practice there was none: a stalled origin held the
round for up to `feedHTTPTimeout` (60s for the threat feed) past the point where
the process was told to stop. The propagation gate shows the pre-fix round
dialling the real third-party origins under an **already-cancelled** context.

For the UT1 feed there is a durability consequence too. The round goes on to a
50+ MB `BulkWrite` into a BadgerDB that shutdown hook order **120** is closing,
the lifecycle context having been cancelled at order **40**.

---

## 2. Failure scenarios

### RT-1 — Alert retry pass loses its unattempted entries (HIGH)

| | |
|---|---|
| **Current behavior** | Due entries are removed from `retryQueue` and the truncated queue is persisted *before* any delivery is attempted. They are re-enqueued only after their own attempt returns. |
| **Expected behavior** | An entry leaves durability only once its attempt has resolved. |
| **Failure mode** | Silent loss of up to `retryQueueMax`-1 queued alerts on any process exit during a pass. |
| **Trigger** | `SIGTERM` / `SIGKILL` / OOM / node reboot / power loss during a pass. Ordinary operations, not an exotic fault. |
| **Window** | Up to 500 × 5s ≈ 42 minutes against a blackholing webhook. |
| **Automatic recovery** | None. The alerts are gone. |
| **Manual recovery** | None — there is nothing to replay from. |
| **Monitoring visibility** | **None.** Not `retryExhaustedTotal`, not `retryDroppedTotal`, no delivery record, no log line. |
| **Evidence** | `internal/alerts/store.go`, pre-fix `processRetryQueue`; gate reports `persisted 0 of 10 entries`. |

### RT-2 — The alert retry pass is unbounded and uncancellable (MEDIUM)

`processRetryQueue` took no context and each delivery built
`context.WithTimeout(context.Background(), 5s)` (`store.go:909` pre-fix). The
loop's `select` on `ctx.Done()` is only reached *between* passes, so a pass
cannot be interrupted: against a blackholing webhook the loop is occupied for
~42 minutes, ticks dropped meanwhile, and a shutdown cannot stop it. Gate:
`cancelled pass did not return`.

### RT-3 — Dispatch Apply retries with zero delay (MEDIUM)

`release_dispatch_exec.go` pre-fix `applyWithRetry`: `for attempt := 0; attempt
<= e.applyRetries; attempt++` with no delay. A restarting agent refuses in
microseconds, so the retry budget is consumed before the fault can clear and the
dispatch terminates `FAILED_NEEDS_ATTN`. Visibility is good (the terminal detail
names the agent error); the defect is that recovery that should have been
automatic becomes manual. Gate: `retries were not spaced: got 0 waits`.

### RT-4 — Feed rounds discard the scheduler's context (MEDIUM)

`internal/threatfeed/threatfeed.go` and `internal/feedsync/feedsync.go`: `Run`
dropped its `ctx`; the fetches used `context.Background()`. Violates
`feedsched.Config.Run`'s documented contract. Consequences: a stalled origin
cannot be interrupted by `SIGTERM`, and the UT1 round's durable write races the
store close at shutdown order 120. Bounded by the fact that nothing joins these
goroutines, so shutdown is not *blocked* — it is simply not *honoured*. Gates:
`cancelled fetch did not return`, and a pre-fix failure summary naming the real
origins instead of the cancellation.

### RT-5 — Every re-delivery recorded as attempt 1 (LOW, observability)

The pass delivered through `Deliver`, which hardcodes `attempt: 1`. The
`Delivery.Attempt` field exists so the admin delivery-history surface can show
retry behavior (`ui_security.go:149` — "retries, permanently exhausted/dropped
deliveries ... without grepping logs"), and it could not distinguish a third
attempt from a first. Gate: `delivery recorded as attempt 1, want 3`.

> The first version of this fix passed `claimed.Attempt` straight through, which
> is off by one in both directions: `retryEntry.Attempt` counts the attempts
> ALREADY MADE — 1 after a failed first delivery, and **0** for an entry queued
> because the delivery semaphore was full and nothing was tried — so a
> semaphore-queued entry's first delivery would have been recorded as attempt
> **0**. The record is `Attempt+1`, and both ends of that are now pinned
> (`…RecordsRealAttemptNumber` and
> `…SemaphoreQueuedEntryDeliversAsAttemptOne`).

---

## 3. Risk matrix

| Id | Finding | Likelihood | Customer | Security | Data integrity | Visibility | Status |
|---|---|---|---|---|---|---|---|
| RT-1 | Retry pass loses unattempted alerts | **High** (any restart during a pass) | Medium | **Medium** (security alerts among the lost) | **High** | **None → full** | **FIXED** |
| RT-2 | Retry pass unbounded / uncancellable | **High** (any blackholing webhook) | Low | Low | Low | Partial | **FIXED** |
| RT-3 | Apply retries with zero delay | Medium (every agent restart) | Medium (manual re-dispatch) | None | None | Good | **FIXED** |
| RT-4 | Feed rounds ignore shutdown ctx | Medium (every shutdown during a round) | Low | Low | Medium (write races store close) | Good | **FIXED** |
| RT-5 | Re-delivery recorded as attempt 1 | High (every retry) | None | None | None | **Misleading** | **FIXED** |

---

## 4. Recovery assessment

- **RT-1, automatic:** full. A crash between claim and resolve leaves the entry
  queued; it becomes due again after `retryLease` (60s) with its attempt count
  **intact**, because an attempt that did not complete is not charged. The
  lease is a crash window, not a delay — a pass that completes re-arms the
  entry on its own 5s/15s/45s backoff and the lease is never observed.
- **RT-1, manual:** none needed.
- **RT-2, automatic:** full. A budgeted or cancelled pass leaves the remaining
  work in the durable queue and the next tick resumes from it, so the bound caps
  a pass's *length*, not recovery. Throughput is unchanged: deliveries were
  serial before and are serial now.
- **RT-3, automatic:** the dispatch now survives an agent restart that clears
  within ~6s. Beyond that it still terminates `FAILED_NEEDS_ATTN`, which is
  correct — the retry budget is not meant to cover a sustained outage.
- **RT-4, automatic:** a cancelled round is charged as a failure, so the
  scheduler backs off and the health plane reports it; the last-good category DB
  is untouched.

## 5. Operational impact

Before RT-1, an operator restarting a node during a webhook outage silently lost
the queued alerts — and the delivery history showed no evidence, because no
attempt was ever made for them. The queue depth metric dropped, which reads as
*drained* rather than *discarded*. After the fix the depth only falls when an
entry was delivered, exhausted or dropped at the cap, each of which is counted.

Before RT-3, a maintenance-agent restart that coincided with a dispatch produced
a `FAILED_NEEDS_ATTN` release that an operator had to re-dispatch by hand, for a
fault that had already cleared.

Before RT-5, the delivery history could not answer "is this webhook flapping or
is it just slow?" — every row said attempt 1.

## 6. Security impact

The material item is RT-1. Culvert's alert events include the security-relevant
ones (`policy_block`, DNS failure, storage degradation, CA and certificate
conditions), and the webhook is how they reach a SIEM. A plane that drops
security telemetry without recording that it did so is a detection gap, not just
an availability one: the operator's view is not "alerts are delayed" but "no
alerts fired". This is the same reasoning the register applies to ST-8 and to
CHAOS-81 (a SIEM feed must report whether it is *delivering*, not whether it once
connected).

RT-4 has a smaller security edge: a feed round that cannot be interrupted keeps
fetching and parsing attacker-adjacent third-party bodies after the process has
been told to stop.

## 7. Data-integrity impact

- RT-1: up to 499 durable queue entries discarded with no record. Fixed.
- RT-4: the UT1 round's 50+ MB `BulkWrite` could begin while the store is being
  closed at shutdown order 120. The round now checks for cancellation
  immediately before the write and leaves the last-good DB untouched.
- The `retryEntry.ID` field is additive and `omitempty`. A queue persisted by an
  older build loads with id 0 everywhere and is renumbered at load
  (`assignRetryIDsLocked`), with the issuer seeded past the file's maximum so a
  restart cannot reissue a live id. Pinned by
  `TestAssignRetryIDs_RenumbersQueuePersistedBeforeIDsExisted`.

---

## 8. What shipped

1. **`internal/alerts`** — claim-in-place retry pass (`claimNextRetry` /
   `resolveRetry` / `dropRetry`), a ctx-bounded pass with `retryPassBudget`,
   per-delivery context parented on the caller's
   (`deliverAttemptContext`), the real attempt number in the delivery record,
   `retryEntry.ID` with load-time renumbering, and `enqueueRetry` split so a
   remove-and-re-arm is one critical section.
2. **`release_dispatch_exec.go`** — bounded exponential backoff between Apply
   attempts (`dispatchApplyBackoffBase`, 2s then 4s), taken through an
   interruptible `waitInterruptible` so a shutdown does not sit out the backoff
   of a doomed dispatch, surfacing the context error rather than the agent's so
   a cancellation is never reported as an agent fault.
3. **`internal/threatfeed` / `internal/feedsync`** — the scheduler's context
   threaded through `syncRound` → `fetchFeedInto` → `fetchTextFeed` /
   `downloadAndParse`, plus a cancellation checkpoint immediately before the UT1
   bulk write. `Sync()` (the admin "sync now") deliberately keeps
   `context.Background()`: an operator who clicks it and closes the tab wants
   the sync, not a cancelled one.

### Why jitter was deliberately NOT added

Both new backoffs are deterministic. `feedsched` and `saas_feed_scheduler.go`
jitter because their origins are **shared** — a fleet in lockstep is a
thundering herd against a third-party provider. Neither new site has a shared
origin: a `DispatchExecutor` is single-flight against **one** agent, and the
alert retry queue is per-node and serial. This is the reasoning
`uploadRetryBackoff` already records for exactly the same decision, and
determinism keeps both schedules exactly testable.

---

## 9. Required tests

All gates were verified to FAIL against the pre-fix code, by restoring the
pre-fix body behind the new seams and re-running. The recorded pre-fix failures
are quoted in §2.

**`internal/alerts/retry_durability_chaos93_test.go`**

- `TestProcessRetryQueue_UnattemptedEntriesSurviveRestartMidPass` — RT-1. Holds
  the pass inside its first delivery, then reads **only the file**, as a fresh
  process would. Asserts all 10 entries persisted, no attempt charged to an
  unresolved attempt, and exactly one leased entry. Pre-fix: `persisted 0 of 10`.
- `TestProcessRetryQueue_PassIsCancellable` — RT-2. Pre-fix: did not return.
- `TestProcessRetryQueue_PassIsBoundedByBudget` — RT-2. Pre-fix: `12 attempts of
  12 queued`, budget overrun.
- `TestProcessRetryQueue_RecordsRealAttemptNumber` — RT-5. Pre-fix: attempt 1.
- `TestAssignRetryIDs_RenumbersQueuePersistedBeforeIDsExisted` — wire
  compatibility of the added id.
- `TestResolveRetry_FailedAttemptIsRearmedNotLost` — the resolve half: exactly
  one re-armed entry, attempt advanced, claim closed out; and a delivered entry
  leaves nothing behind.

**`release_dispatch_apply_backoff_chaos93_test.go`**

- `TestExec_ApplyRetryBacksOffBetweenAttempts` — pins the exact schedule
  `[2s 4s]`. Pre-fix: `got 0 waits []`.
- `TestExec_ApplyBackoffNotSpentWhenFirstAttemptSucceeds`.
- `TestExec_ApplyBackoffIsInterruptible` — and that the detail names the
  cancellation, not the agent's 503. Pre-fix: both failed.
- `TestWaitInterruptible_ReturnsOnCancel`.

**`internal/feedsync/round_cancellation_chaos93_test.go`**

- `TestDownloadAndParse_HonoursContextCancellation` — stalled origin. Pre-fix:
  did not return within 10s (the real bound is 60s).
- `TestSyncRound_DoesNotWriteAfterCancellation` — the durability half.

**`internal/threatfeed/round_cancellation_chaos93_test.go`**

- `TestFetchTextFeed_HonoursContextCancellation`.
- `TestSchedulerRound_PropagatesCancellationToTheFetches` — the propagation
  gate, hermetic and differential: with the ctx threaded both fetches fail
  before any dial and the summary names the cancellation. Pre-fix the summary
  named the real origins, which is the defect made visible.

### Seams added for the gates

`retryDeliver` (alerts) and `applyWait` (dispatch), both following the
`startupAlertFire` pattern already in package main. The alert queue's real
delivery path needs a reachable webhook origin and `ssrf.SafeDialContext`
correctly refuses the loopback address a test server would be on, so the
mid-attempt queue state is otherwise unobservable. `applyWait` keeps the
schedule assertion exact and costs no wall-clock time.

---

## 9a. Review follow-up — the shutdown that still charged an attempt

**Codex rejected the first version of the RT-1 fix on PR #1734, and it was
right.** The claim/resolve split made a *crash* mid-attempt safe — the entry
stays queued and is retried after the lease with its attempt count intact — but
a *clean cancellation* still charged the interrupted attempt.

The mechanism: once the delivery takes the lifecycle context (RT-2), a cancelled
POST returns exactly the `false` a badly-answering webhook returns, and
`resolveRetry` could not tell them apart. So a shutdown during an attempt spent
that attempt, and for an entry already on its **last** attempt
(`Attempt == retryMax-1`) the resolve removed it and counted it
`retryExhaustedTotal` — "exhausted after 3 attempts" — when the third attempt
had never reached the webhook at all. Codex also noted the narrower race:
cancellation can land between the pass's `ctx.Err()` check and the request,
burning an attempt with no contact whatsoever.

That is the RT-1 loss shape again, one entry wide instead of a whole batch, and
it contradicted this document's own claim that "an attempt that did not
complete is not charged" — which was true of a crash and false of a shutdown.
The two fixes interact, which is why neither sweep found it alone: RT-2 made
delivery cancellable, and RT-1's resolve treated cancellation as failure.

Fixed by distinguishing *interrupted* from *failed*: when a delivery returns
false and `ctx.Err() != nil`, the pass returns without resolving, leaving the
claimed entry in the durable queue at its original attempt count, due again
after the lease. The check sits AFTER the attempt, not only before it, which is
what closes Codex's between-check-and-request race. A delivery that SUCCEEDED
under a cancelled context still resolves normally — the webhook received it.

Where the two signals are genuinely ambiguous (a real webhook failure that
coincides with a shutdown), this now errs toward preserving the alert rather
than charging it. That is the direction this document already argues for under
at-least-once: a duplicate is visible, a loss is not.

Gate: `TestProcessRetryQueue_CancelledDeliveryDoesNotConsumeAnAttempt`, verified
to fail against the first version with `0 entries persisted, want 1`.

## 10. Residual risk

- **A shutdown can delay an interrupted entry by the lease.** An attempt
  cancelled by shutdown is not charged, so the entry waits out `retryLease`
  (measured from the claim) before becoming due again. After a restart that
  takes longer than the remaining lease it is due immediately; after a fast one
  it waits the remainder, which also keeps a crash-looping process from
  hammering the webhook from boot.
- **A claimed entry's lease is 60s.** A crash between claim and resolve delays
  that one entry by up to 60s. Deliberate: it has to exceed `deliveryTimeout` so
  a slow-but-live delivery is never double-sent by the next pass. The
  alternative — persisting an explicit "in flight" state — would need a crash
  recovery sweep to clear states the dead process left behind, which is more
  machinery for a 60s improvement on one entry.
- **At-least-once, not exactly-once.** A crash after the webhook accepted the
  POST but before `resolveRetry` persisted the removal re-delivers that alert.
  That is the right trade for an alert (a duplicate is visible; a loss is not),
  and it is the posture `mcp_telemetry.go` records for its own export cursor.
- **A retry for a deleted or disabled webhook is still dropped silently.**
  Pre-existing and deliberately unchanged: it is a configuration outcome, not a
  failure, and counting it under `retryDroppedTotal` would change a documented
  metric's meaning ("the queue was at capacity").
- **`retryQueueMax` still drops the NEWEST entry when full**, and counts it.
  Unchanged — a bounded queue has to refuse something, and the refusal is
  visible.
- **Write amplification: the queue is now persisted twice per entry** (claim and
  resolve) rather than once per pass. Accepted deliberately. The claim's persist
  is what gives a crash-looping process a cooldown instead of hammering the
  webhook from boot; the resolve's is what keeps a delivered alert from being
  re-sent. The file is a bounded JSON array of at most 500 entries, the writes
  are spread across deliveries that each take up to 5s, and entries only exist
  at all after deliveries have been failing — so the amplified case is one write
  per several seconds, not a hot path. The pre-existing pattern already fsynced
  under `retryMu` (`enqueueRetry` did), so the lock discipline is unchanged. If
  this ever matters, the repo's own answer is `Store.Add`'s
  `beginSaveLocked`/unlock/`persist()` split.
- **RT-3 adds up to 6s of latency** to a dispatch against a hard-down agent.
  Judged correct: that is the deployment-visible timing call the 2026-10-18
  sweep deferred, and 6s against a release dispatch is far cheaper than a
  manual re-dispatch.
- **Nothing joins the alert retry goroutine at shutdown.** The pass is now
  cancellable, so it stops promptly, but the shutdown registry does not *wait*
  for it. Not changed here: adding a join is a shutdown-ownership decision for
  that owner, and the durability fix makes it unnecessary for correctness —
  whatever the pass had not finished is in the file.
- **The `saasFeedScheduler` is still not on `feedsched`'s seams.** Pre-existing
  follow-up recorded in that package's doc comment; it schedules correctly
  already.

## 11. Reported, not fixed

- **Feed clients still dial without `ssrf.SafeDialContext`**
  (`internal/feedsync/feedsync.go`, `internal/threatfeed/threatfeed.go`). Left
  exactly as the 2026-10-18 sweep left it, and for its reason: an on-prem or
  air-gapped feed mirror on an RFC1918 address is a normal enterprise topology
  that the guard would reject. Still an owner decision, still unrecorded at
  either site. This sweep touched the same two functions and deliberately did
  not resolve it — threading a context is not the occasion to change a
  destination-trust boundary.
- **The open half of CHAOS-18** (the `config_unchanged` sentinel means the
  boot-time clobber of a CP-pushed default action never self-heals) and the
  **SOCKS5 pre-posture accept window** remain open from the 2026-10-18 sweep.
  Neither is a retry defect; neither is in scope here.
