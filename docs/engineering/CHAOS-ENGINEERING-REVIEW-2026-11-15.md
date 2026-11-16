# Chaos Engineering Review — 2026-11-15

## CHAOS-120 — Six rounds taught the gateway to survive a panicking background round. Nobody taught it to tell anyone.

**Scope.** The SIMULATE list's *Silent failures*, *Recovery failures*,
*Operational surprises*, *Monitoring visibility*, *Alert quality*, *Threat feed
unavailable*, *Database corruption* and *Unexpected restart* rows, applied to
the **reporting boundary of the panic-containment plane** — not whether a
background fault is contained (CHAOS-24/105/116/117/118 answered that), nor
whether it is *recorded* (CHAOS-119 answered that), but whether it reaches an
operator who is not already looking at the box.

**Status.** Fixed, in two parts. §3 closes a residual risk recorded verbatim by
**four consecutive rounds**. §4 closes CHAOS-119 §5.1 and §5.2 together, because
they are the same seam seen from two sides.

**Closes.** CHAOS-116 residual `4`, CHAOS-117 residual `5`, CHAOS-118 residual
`1`, CHAOS-119 residual `3` (all four are the same sentence: *no alert rule
ships on the crash counters*). CHAOS-119 §5.1 and §5.2 in full. CHAOS-118 §7.3
and §7.4 and CHAOS-119 §5.3–§5.5 are untouched and remain open as written.

---

## 1. Executive summary

Line references are at the base revision `origin/main` `0b11474`.

This family of rounds has one cumulative achievement and one cumulative debt,
and they are the same change.

**The achievement.** Go terminates the process on an unrecovered panic in *any*
goroutine. Six rounds removed that from Culvert's background plane: every
detached round now runs under `runGuarded` / `obs.SafeCall`, and `runGuarded`'s
own doc explains why the guard is per-ROUND and never per-goroutine — "Deferring
a recover at the top of a worker goroutine would let the worker RETURN on panic,
converting a loud crash into a silent permanent stall … with the process still
up and every dashboard green."

**The debt is the second half of that same sentence.** Guarding the round keeps
the loop alive, which is right for a *transient* fault. For a *systematic* one —
a corrupt feed DB, a null map entry, a wedged exporter, a poisoned archive — the
round panics on every window, forever. The node stays up. Every probe stays
green. The work never completes. And what the sink writes about it is:

| Sink | What an operator has to do to see it |
|---|---|
| `culvert_crash_records_total{component}` | have already built a rule on a counter nothing ships a rule for |
| `PANIC_RECOVERED` ERROR log line | be reading the log |
| `panic_recovered` audit entry | be reading a **bounded 500-entry ring** that the next shuffle may evict |
| `lastCrash` (one slot) | pull a support bundle |

Four of those are pull, not push, and none of them pages. **CHAOS-25 already
decided this question** — for exactly one component out of sixty-four. `HAState.
notePanicRound` ([ha.go:758](../../ha.go)) fires `ha_sync_panic` and states the
rule in its own doc: the counter and the alert "are the **ONLY** operator-facing
signal that replication has stalled — without them the containment would trade a
loud crash for a silent one, **which is the failure class the guard exists to
remove**." That reasoning was never specific to HA. It was never generalised.

§3 generalises it to the sink, so a component added by a *future* round inherits
the page instead of needing its own. §4 then fixes the one package whose
containment could not have reached the new page even if it fired, because its
reports never reached the sink at all.

**What this is not.** It is not an alerting rule for someone else's Prometheus;
it is the product's own webhook event, subscribable from the product's own UI, so
the fix lands inside the box the operator bought rather than in a runbook.

---

## 2. Failure scenarios

Each row is the state the gateway is *already* in at the base revision.

| # | Fault injected | Current behavior (base `0b11474`) | Expected | Customer impact | Visibility before | Visibility after |
|---|---|---|---|---|---|---|
| F1 | URLhaus/OpenPhish feed body panics the parse on every pass | round contained, charged a failure, backs off to one attempt/hour, **forever** | contained **and paged** | traffic enforced against **frozen** threat intelligence; on a fresh node, **none** | counter + log + 1 ring entry | `component_panic` page naming `threatfeed` |
| F2 | `cluster.json` holds a `null` member (CHAOS-117's defect, post-fix) | `cluster_heartbeat` round contained every 30 s, forever | contained and paged | liveness never evaluated; dead nodes stay "enrolled" | same | page naming `cluster_heartbeat` |
| F3 | HA leadership resume panics | node left **HA-gated until an operator restarts it** (CHAOS-119 §7.4) | contained and paged | no automatic failover from this node | same | page naming `ha_leadership_resume` |
| F4 | MCP telemetry export panics in the shutdown drain (CHAOS-119a, post-fix) | contained, shutdown continues, evidence unexported | contained and paged | MCP evidence stays in the spool | same | page naming `mcp_telemetry_drain` |
| F5 | `feedsync`'s BadgerDB handle is corrupt/closed when `RunNow` reads `Stats()` | **unrecovered panic in a detached goroutine → process death at startup** | contained, reported, loop lives | **gateway down**, crash-loop if supervised | a process exit | `feedsched_round` crash record + page; first sync delayed one window |
| F6 | A feed is added without its own `obs.SafeCall` wrapper and its round panics | `feedsched`'s second-level recover catches it → **one `obs.Warnf` line** and nothing else | reported to the crash plane | that feed never syncs | **one WARN line** | crash record + counter + audit + page |
| F7 | A request-triggered panic on the proxy hot path, repeatable by any client | contained per request, throttled to one record/s | contained, throttled, **one page per dedup window** | none to traffic | counter | one page, **not one per request** (§3.3) |
| F8 | The webhook **delivery path itself** panics | contained under `recoverGoroutine("alert")` | contained, recorded, **never paged** | none | counter + record | unchanged **by construction** (§3.4) |

F5 is the only row that was a process kill, and it is the one CHAOS-119 §5.2
flagged and handed forward. It is reproduced in §5 (MUTANT G) as a test-binary
`panic:` exit, not argued.

---

## 3. CHAOS-120a — the page

### 3.1 What changed

`recordCrash` ([crashguard.go:117](../../crashguard.go)) gains one call, as its
last step:

```go
	// CHAOS-120: and the one sink that reaches an operator who is not already
	// looking. LAST, so the durable evidence above is written before anything
	// leaves the box, and so a page can never be the reason a record is missing.
	fireComponentPanicAlert(component)
```

`component_panic` is a new alert event: fired from the single sink, catalogued in
[internal/alerts/store.go](../../internal/alerts/store.go) beside the other
twenty-nine, and **subscribable from the Alerts panel**
([static/index.html](../../static/index.html)). The last part is not cosmetic:
CHAOS-113 established that an event with no checkbox is an event that *never
fires*, because request-path producers gate on `HasSubscriber` and the panel is
the only place the vocabulary is discoverable.

### 3.2 The page carries the component and nothing else

Two independent constraints point at the same payload, and both are load-bearing.

**Secrets.** `recover()`'s value can embed a credential —
`panic(cfg.SessionHMAC)` is the case [crashguard.go](../../crashguard.go)'s own
header names — which is why the raw value is kept out of the log and masked on
export. A webhook body leaves the box to a third-party collector, so it is the
**last** place that text may appear. `Detail` therefore names the component; the
panic text stays in `lastCrash`, reachable only through the redacting accessor.

**Dedup.** `Store.Dispatch` dedups on `event + ":" + Detail`. The crash ID is
unique per crash *by construction*, so putting it in `Detail` would make every
page a distinct key the 30 s window cannot suppress, and the fan-out would land
in the 500-entry retry queue **where it evicts real threat alerts**. That is not
a hypothetical: it is the CHAOS-64 `dns_failure` defect exactly, where a
`*net.DNSError`'s text embedded the client-chosen hostname. Keying on the
component means a permanently panicking round pages once per window.

The admitted cost: **the page does not carry the crash ID.** The operator
correlates through the `panic_recovered` audit entry on the same component, which
does. Stated here rather than papered over.

### 3.3 Flood bound: inside the throttle, with the other floodable sinks

The page sits **after** `crashThrottleAllow`, beside the stack capture, the log
line and the audit entry — because its rate is set by the fault, not by the
operator, and `proxy` / `admin` / `tunnel-relay` / `socks5-relay` are
request-path components a client can drive. Three bounds compose:

1. `crashThrottleAllow` — one page per component per second, at the sink.
2. `HasSubscriber` — the default posture is no webhooks; nothing reaches
   `Dispatch`'s dedup mutex or its O(n) expiry scan. (On the detached goroutine,
   not the sink's stack — see §3.4.)
3. `Store.Dispatch`'s 30 s dedup on a key that is **constant per component**.

The component set itself is bounded: `crashThrottleAllow` fails **closed** past
`maxCrashLabels`, so this producer can contribute at most 128 distinct dedup
keys no matter what a future caller passes.

### 3.4 The sink must never block, and this round's first design made it

**This is the finding the round made about itself, and it is the sharpest thing
in §3.** The first version called `globalAlertStore.HasSubscriber` synchronously,
on `recordCrash`'s stack — copying `fireDNSFailureAlert`'s gate placement without
re-deriving whether it transferred. It does not.

`HasSubscriber` takes the store's `RWMutex`. `Store.Add`, `Store.Update` and
`Store.Delete` release that **write** lock with a non-deferred `as.mu.Unlock()`
(three sites in [internal/alerts/store.go](../../internal/alerts/store.go), named
by function rather than line because this change edits that file's header) — the
**CHAOS-118 §8.2a lock-pairing shape**. A panic inside one of those critical
sections leaks the write lock, and a synchronous probe on the sink's stack would
then have blocked the *recovering* goroutine forever against a lock nothing will
ever release:

- **from `runGuarded`**: the round never returns, so the loop is stalled
  permanently — the exact "silent permanent stall" `runGuarded`'s doc says
  guarding the round instead of the goroutine exists to remove, **reintroduced by
  the act of reporting it**;
- **from `withAdminPanicRecovery`**: the deferred func never completes, so the
  500 is never written and the request hangs holding a connection;
- and one goroutine leaks per subsequent crash, in **any** component.

Blocking is as fatal to a worker as panicking, so the sink's stated contract —
"can never crash the process it protects" — covers both. The whole outbound step,
**probe included**, now runs on the detached goroutine behind a single
`crashAlertPage` seam; what remains on the sink's stack is a map read and a var
read, neither of which can take a lock. A test makes that step block forever and
requires `runGuarded` to return anyway (MUTANT K reproduces the hang in 10 s).

The gate still earns its place *inside* the goroutine. What does not transfer is
`fireDNSFailureAlert`'s reason for putting it on the caller's stack: that
producer fires once per **request** with no throttle in front of it, while this
one is already bounded to one page per component per second — so the goroutine it
may now spawn for nothing is bounded with it.

### 3.5 Termination, which the compiler insisted on first

The first draft did not compile, and the diagnostic was the finding:

```
./alerts.go:45:5: initialization cycle for fireAlert
	fireAlert → recoverGoroutine("alert") → recordCrash →
	fireComponentPanicAlert → crashAlertPage → fireAlert
```

That is the compiler reporting, **statically**, a live re-entrancy: the alert
plane's delivery path is guarded *by the sink that would now page through it*.
Without a stop, a panicking delivery path would record a crash → fire a page →
panic in the same place → record a crash. The per-component throttle would bound
that loop's **rate** to one pass per second and would **never end it**, and it
would feed the persistent retry queue on every pass.

So the two planes are separated deliberately, not routed around:

- `crashAlertPage` is bound in `init()`, not as a variable initializer, which
  breaks the static cycle and — by reading `fireAlert` at **call** time rather
  than capturing it — preserves the documented test-reassignment tolerance.
- `crashAlertSelfExcluded` = `{"alert", "alerts_retry"}` makes the remaining
  edge safe. Both are real guard labels (the CHAOS-119 source enumerator lists
  them), and a test asserts each entry still corresponds to a live call site, so
  the exclusion set cannot quietly become a place where a component stops paging.

An excluded component still gets the counter, the record, the log line and the
audit entry — every sink except the one it cannot safely use.

---

## 4. CHAOS-120b — `internal/feedsched`: containment that reported nowhere, and one line that was never guarded

CHAOS-119 §5.1 and §5.2 recorded these and handed them to "the round that takes
the scheduler". Taken together, because they are one seam.

**§5.1 — `Config.OnPanic` was defined, documented, and wired by nobody.** A
tree-wide search finds zero production call sites setting it, so every panic this
package contained itself fell to the `obs.Warnf` branch. **`Warnf` does not reach
the panic sink.** No crash record, no `culvert_crash_records_total` increment, no
`panic_recovered` audit entry — and, after §3, no page. Containment with no
reporting, inside the package whose own doc promises "a panicking round is a
FAILED round, not a dead loop". It was latent rather than live only because both
shipped feeds wrap their own body in `obs.SafeCall`; it goes live the moment a
feed is added without that wrapper, **which is exactly how CHAOS-108 found
`blocklistfeed` outside the scheduler this package's doc claimed covered it.**

The nil fallback now reports to `obs.ReportPanic` **and** logs the WARN line. The
crash label is **one fixed constant**, `feedsched_round`, not one per feed: the
sink's component set is capped and past the cap `crashThrottleAllow` fails closed
(no record, no log, no audit, no page), so a label derived from `Config.Name`
would be an unbounded label in a bounded map — and the source enumerator that
*holds* that cap resolves same-file constants, so it could not be counted either.
The feed's identity rides the WARN line, where cardinality costs nothing.
Verified: the enumerator now reports **64 labels against a cap of 128**, with
`feedsched_round` among them.

**§5.2 — `Run` consulted `cfg.RunNow()` outside every guard.** Both feeds' guards
live *inside* `Config.Run`, and `internal/threatfeed` launches `Run` with a bare
`go` statement ([threatfeed.go:276](../../internal/threatfeed/threatfeed.go)).
The predicate is not a trivial read: `feedsync`'s is `fs.db.Stats() == 0`, a
BadgerDB call on a handle this package does not own. A corrupt or already-closed
store therefore killed the **process** from the one line in the cold-start path
nobody was guarding — at startup, before the first round, on the path whose whole
purpose is cold-start recovery.

`Run` now calls `s.runNow()`, which contains the predicate and answers `false`.
**Answering `false` is a choice with a cost, and it is not the only defensible
one.** Charging it as a failed round would start the backoff ladder from a fault
that is not the feed origin's, for work that never ran. Falling through to the
interval loop keeps the loop alive, runs a *real* round at the first tick, and
lets that round report its own outcome through the health plane the operator
already watches. The cost, stated: on a node whose store is empty **and** whose
predicate panics, the immediate cold-start sync is skipped, so the first sync
waits one interval — the pre-`feedsched` bare-ticker behaviour, for one window,
now reported instead of fatal.

Both paths report through **one** method, `reportPanic`, so a later round cannot
fix one and leave the other silent — which is precisely the state §5.1 and §5.2
together described. A configured `OnPanic` still **owns** the report (no
double-counting: the counter's rate is what distinguishes a transient fault from
a permanent one).

---

## 5. Mutation results

Every assertion was falsified against a mutant before it was trusted. Commands
and the unmutated baseline are in §9.

| # | Mutation | Caught by | Result |
|---|---|---|---|
| A | drop `fireComponentPanicAlert` (the pre-fix shape) | 4 tests | the defect, reproduced |
| B | hoist the page **outside** `crashThrottleAllow` | `…ThePageInheritsTheSinksFloodBound` | caught — see below |
| C | drop `crashAlertSelfExcluded` | `…TheAlertPlanesOwnPanicDoesNotPageItself` | caught, both arms |
| D | drop the `HasSubscriber` gate | `…NoSubscriberNoWork` | caught |
| E | put the crash ID in `Detail` (the CHAOS-64 defect) | `…ThePageIsKeyedOnTheComponent…` | caught, with the id printed |
| F | put the panic **value** in `Detail` | `…ThePageNeverCarriesThePanicValue` | caught: the secret appeared in the payload |
| G | revert `runNow()` to the bare `cfg.RunNow()` | `…APanickingRunNowPredicateIsContained…` | **test binary exits `panic: badger: DB closed`** — the process death, reproduced |
| H | fallback reports to `Warnf` only (the §5.1 shape) | 3 feedsched tests | caught |
| I | report to the sink *as well as* a configured `OnPanic` | `…AConfiguredOnPanicOwnsTheReport` | caught (double count) |
| J | derive the crash label from `Config.Name` | 3 feedsched tests | caught |
| K | make the outbound step synchronous (this round's own first design, §3.4) | `…TheSinkNeverBlocksOnTheAlertPlane` | **the guarded round never returns** — the deadlock, reproduced |

Mutants A–F and K were re-run against the final shape after §3.4 restructured
the producer; the table is that run, not the first one.

**Mutation K is the one worth recording, because it falsified this round's own
first IMPLEMENTATION** — see §3.4. The gate was placed by analogy with an
existing producer rather than by re-deriving the constraint, and the analogy was
wrong in the one way that mattered. It was found by asking what the change's
synchronous calls lock, not by any test failing.

**Mutation B is worth recording too, because it falsified this round's own first
test design.** The flood gate originally sampled whatever pages had landed
after waiting for the *first* one, and against mutant B it observed "5 pages,
want 1". It failed — but the **5 was scheduling-dependent**, and on a slower box
only one page might have arrived by the time the reader returned, which would
have passed the mutant. The observation was rewritten to wait for a **target
count** (`pages(2)`) instead of sampling: with the page inside the throttle the
wait times out and the caller asserts exactly 1; with the page hoisted out, the
second arrives at once. Deterministic in both directions. Same honest framing as
CHAOS-119's mutation B2.

**The barrier seam is production surface added for a test, and it is recorded as
such.** Detaching the page step made the tests racy for a reason that is not a
test bug: production assigns `globalAlertStore` and `fireAlert` once at startup
and never again, so nothing races — but a test that swaps either one to observe
the dispatch has **no happen-before edge** to a page goroutine that already ran,
and `-race` reports the restore as a write racing that goroutine's read. A
quiescence sleep would have hidden that rather than fixed it. `crashAlertPageBarrier`
(nil in production, one nil check, mirroring `internal/alerts`' `saveBarrier`) is
a barrier rather than a counter because the `Add` side must happen on the sink's
stack — before the goroutine exists — while the `Done` side happens inside it, so
no spawned page is ever unaccounted for. `go test -race` is clean; MUTANT K is
still caught with the barrier installed.

A second assertion was weakened **on purpose** and says so in the test: the
"metric still counts every crash" check asserts a floor (`>= 50`), not equality,
because this package's tests share process-global counters and a goroutine left
over from an earlier test can record its own crash — which would make an exact
count order-dependent under `-shuffle=on`. The floor still kills the mutant it
exists for (a metric moved inside the throttle reads 1).

---

## 6. Risk matrix

| ID | Failure | Likelihood | Impact | Detected before | Detected after | Recovery | Residual |
|---|---|---|---|---|---|---|---|
| F1 | feed round panics every window | Medium | **High** — stale/absent threat intelligence enforced as if fresh | pull-only | **push** | fix the fault; loop self-heals | needs a subscriber (§8.1) |
| F2 | cluster heartbeat round panics every 30 s | Low | High — liveness never evaluated | pull-only | **push** | restart or repair state | as above |
| F3 | HA resume round panics | Low | **High** — no automatic failover | pull-only | **push** | **restart (manual)** — unchanged | §8.4 |
| F4 | shutdown drain panics | Low | Medium — MCP evidence unexported | pull-only | **push** | evidence durable in spool | — |
| F5 | `RunNow` predicate panics | Low | **Critical** — process death at startup, crash-loop under supervision | process exit | contained + recorded + paged | automatic: loop continues | one delayed sync window |
| F6 | new feed added without its own wrapper | Medium | Medium — that feed never syncs, one WARN line | **none in practice** | crash plane + page | fix the feed | — |
| F7 | request-triggered panic flood | Medium | Low to traffic; **High** to the alert plane if unbounded | counter | 1 page/window | none needed | §8.2 |
| F8 | alert delivery path panics | Low | Medium — pages stop being delivered | counter + record | unchanged, **deliberately** | restart | §8.3 |

## 7. Impact assessment

**Operational.** A contained panic becomes a push notification instead of four
pull-only records. The page names the component, which is the one fact that
tells an operator *which work is not being done*. It changes no retry, no
backoff, no cadence and no fail-open/fail-closed decision anywhere: the only new
runtime behavior on the crash path is a gated, throttled, deduped, detached
webhook dispatch. On the default deployment (no webhooks configured) the fix is
a map lookup and a `HasSubscriber` call per contained panic.

**Security.** Net positive, with one new egress path examined deliberately. The
page is the first thing in the crash plane that *leaves the box*, so it carries
the component label only — never the panic value (which can embed a credential),
never the stack, never the correlation ID, never the crash ID. A test asserts
**every field of the delivered DTO**, not just `Detail`, so a future field cannot
become an unasserted channel. Delivery keeps the existing SSRF guard, HMAC
signing and bounded-concurrency path; nothing new was added to it. Two detection
gaps close: a systematically panicking `threatfeed` round (frozen intelligence
enforced as fresh) and a panicking `cluster_heartbeat` (liveness never
evaluated) are now reportable conditions rather than quiet ones.

**Data integrity.** Unchanged. The page is strictly additive and **last** in the
sink, after `lastCrash`, the log line and the audit entry, so a page can never be
the reason a record is missing. §4's `runNow` containment removes a process kill
that could land mid-write at startup.

**Compatibility.** Additive. A new optional webhook event (unsubscribed by
default), one new UI checkbox, one new fixed crash label. No persisted format,
wire format, API schema or config surface changes; `contractcheck impact` reports
no contract code paths touched. `ha_sync_panic` is unchanged and stays as the HA
plane's narrower page — it names the suppressed failover and the manual remedy,
which the generic event cannot.

---

## 8. Residual risk

1. **The page requires a subscriber, and the default posture has none.** This is
   the same shape as every other event in the catalog and it is the right trade
   (§3.3's gate exists because this producer's rate is set by the fault), but it
   means the fix is *available*, not *active*, until an operator ticks the box.
   Nothing in the product nudges them to. A default-on delivery channel —
   Diagnostics row, health surface, or a shipped alert rule — is the obvious
   follow-up and is deliberately **not** in this round: it is a product decision
   about default paging volume, not a chaos fix.

2. **A crash before the webhook store loads does not page.** Webhooks load in
   `loadPersistentAdminState`, the last startup slice, so `HasSubscriber` is
   false before it and a startup-window panic is recorded but not paged. The
   sanctioned mechanism for this is `deferStartupAlert` — and it is deliberately
   **not** used here, because that queue is an unbounded `append` and this is the
   only throttled-rather-than-fire-once producer that would enter it: a
   startup-window crash loop would turn into unbounded queue growth during boot,
   inside the plane whose job is containing faults. Capping that queue is a
   change to a shared plane and belongs to the round that takes it. Until then
   the startup window is covered by the log line and the audit entry only.

3. **Paging is not acting.** A page tells an operator a round is failing; it does
   not make the round succeed, and §6's F3 still ends in a manual restart. This
   round moved the signal from pull to push and changed no recovery path. That
   remains CHAOS-119 residual `4`, narrowed but not closed.

4. **A leaked alert-store write lock still silences paging, it just no longer
   wedges the gateway.** §3.4 moved the probe off the sink's stack, which bounds
   the damage to the detached page goroutine — but the underlying non-deferred
   `as.mu.Unlock()` in `Store.Add`, `Store.Update` and `Store.Delete` is
   untouched, and a panic
   inside one of those critical sections still leaves the webhook store
   permanently unreadable: no pages for anything, from then until restart, with
   the crash counter and audit entry still recording. That is the CHAOS-118 §7.3
   lock-pairing class in a new place, found here and **not fixed here** — it
   belongs to `internal/alerts`' own contract and to the mechanical pairing gate
   §7.3 asks for, and converting three critical sections to deferred unlocks is a
   change to the delivery plane that deserves its own round. Recorded with the
   evidence rather than left for the gate to rediscover.

5. **The exclusion set is correct today and is held by a gate, not by a design.**
   `{"alert", "alerts_retry"}` is enforced by a test that checks each entry still
   matches a live call site in the tree. A *new* component introduced inside the
   alert delivery path would page through the plane it just broke, and nothing
   would notice until the loop appeared. The gate fails loudly in the other
   direction (a stale entry) but cannot discover a new one; discovering it needs
   a call-graph walk of the kind CHAOS-118 §7.3 asks for and which remains open.

6. **`feedsched`'s remaining unguarded lines are narrower, not absent.**
   `Interval()` and the jitter function are still called outside any guard from
   `loop` and `NextDelay`. For both shipped feeds those are a field read behind
   an RWMutex, so the surface is a nil receiver rather than third-party input —
   which is why they are recorded rather than wrapped: wrapping the whole loop
   would guard the *goroutine*, which is the thing `internal/obs`'s rule and
   `runGuarded`'s doc both forbid. Recorded for the round that can do it at the
   round boundary.

7. **`maxCrashLabels` remains a cap held by a gate** (CHAOS-119 residual `1`
   and `2`, unchanged). This round added one label, taking the fixed set from 63
   to 64 against a cap of 128, and the page inherits the cap's fail-closed
   behaviour: a component past it loses its record *and* its page.

---

## 9. Verification

Base `origin/main` `0b11474`. Toolchain `go env GOVERSION` = `go1.27.4`,
`GOTOOLCHAIN=auto`, which matches the `toolchain` pin in `go.mod`.

| Check | Command | Result |
|---|---|---|
| Vet | `go vet ./...` | clean |
| Tidy drift | `go mod tidy -diff` | clean (no dependency change) |
| Build | `CGO_ENABLED=0 go build -ldflags="-s -w"` | ok |
| Cross-build | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` | ok |
| Contracts | `go run ./cmd/contractcheck impact -base origin/main` | *No contract code paths are touched* |
| New gates | `go test -run TestCHAOS120 . ./internal/feedsched` | 15 tests, pass |
| New gates, race | `go test -race -run TestCHAOS120 . ./internal/feedsched` | pass, **no race** |
| Neighbouring planes | `go test -race -count=2 -shuffle=on ./internal/feedsched ./internal/alerts ./internal/feedsync ./internal/threatfeed ./internal/blocklistfeed ./internal/obs` | pass |
| Prior rounds' gates | `go test -race -run 'TestCHAOS119_\|TestCHAOS118_\|TestChaos113_\|TestChaos71_\|TestCrash\|TestAlert\|TestWebhook\|Chaos25\|Chaos27\|Chaos64\|…' .` | pass |
| Label cap | `go test -run TestCHAOS119_FixedCrashLabelSetFitsTheCardinalityCap -v .` | **64 labels, cap 128**, `feedsched_round` enumerated |
| Determinism (Deep's command) | `TEST_SEED=20260421 go test -count=2 -shuffle=on -timeout=25m ./...` | **pass, whole module** |
| Lint, diff-scoped (Fast's own command) | `golangci-lint run --new-from-rev origin/main`, v2.15.0 built with the `go.mod` toolchain | **0 issues** |
| Lint, full tree vs base | same binary, full tree, at HEAD and in a worktree at `origin/main` | **174 issues at both, identical breakdown** — no finding added, including the declaration-line-attributed `cyclop`/`funlen`/`gocognit` that `--new-from-rev` cannot see |

The pinned linter needed the absolute path: `/usr/local/bin/golangci-lint` in
this container is **v2.5.0 built with go1.25.1** and shadows the installed one on
`PATH`, so it panics with *"package requires newer Go version go1.27"*. That is
the trap [conventions](../agent-context/conventions.md) records as having
"repeatedly been recorded as 'local lint is unavailable'"; the v2.15.0 binary
built with the `go.mod` toolchain runs clean.

**Not run, and why.** `make api-verify` and the frontend's `npm run verify`: no
OpenAPI schema, route, or `frontend/` file changes (the React tree hand-writes no
webhook event list — only `types.gen.ts`, which does not enumerate event names).
The `benchgate`-tagged gates and the coverage-floor diagnostic: no benchmark,
hot-path or floor-file change. `docs/agent-context/check.py`: no guidance path
changes (`docs/engineering/` is not guidance-shaped and no `AGENTS.md`,
`CLAUDE.md` or skill is touched). `cmd/culvert-maint`: separate module, untouched.

**This is a local pass, not aggregate CI approval.** `✅ Fast PR Gate —
APPROVED` and `✅ Deep PR Gate — APPROVED` must be read from the hosted run for
the pushed revision, and merge remains a separate decision.
