# Chaos engineering review — 2026-11-14

Reviewer: Culvert Chaos Engineer (automated round). Base revision `de0b6d1`
(`origin/main`), clean worktree at branch point. Recorded separately for the
reason the previous rounds were; [the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md)
stays the index.

Id claimed: **CHAOS-120**, in a committed placeholder row as commit one, before
any code, checked against `origin/main` rather than the working tree per the
register's 2026-09-25 amendment. `CHAOS-119` was the highest id anywhere on
`origin/main` at `de0b6d1`, and no open PR held a chaos id (#1894, #1893,
#1883, #1855, #1705, #1549, #1548, #1536, #1528, #1526).

---

## CHAOS-120 — The containment plane's NOTIFICATION boundary: sixty-two components that nothing pages on, and ten alerts an operator cannot subscribe to

Scope: **who tells the operator.** The CHAOS-24/105/116/117/118/119 family
established that every detached background round is CONTAINED, and CHAOS-119
asked what an operator can SEE afterwards and built the answer — a labelled
counter, a crash record, a log line, a system-actor audit entry. This round
asks the question one step further out, which is the only one that matters at
03:00: **does anything reach them.**

The answer was no, twice, in two independent planes.

---

## 1. Executive summary

**CHAOS-120a (HIGH) — the crash sink fired no alert, for 62 of its 63
components.** `recordCrash` (`crashguard.go`) is the single sink every
contained panic funnels into: the proxy plane's record-only guard, the admin
plane's recovery middleware, `runGuarded`, `recoverGoroutine`, and — through
`obs.SetPanicSink` — every `internal/*` background round. It increments
`culvert_crash_records_total{component}`, stores a bounded record, writes one
ERROR log line and one audit entry, and returned. A measured enumeration of the
tree (CHAOS-119's own AST enumerator) counts **63 distinct fixed component
labels**. Exactly **one** of them alerted, and it did so itself rather than
through the sink: `HAState.notePanicRound` fires a fire-once `ha_sync_panic`,
and its doc comment states the general rule the other 62 were missing —

> Because the panicking round is deliberately kept out of the failure streak,
> this counter + alert are the ONLY operator-facing signal that replication has
> stalled — **without them the containment would trade a loud crash for a
> silent one, which is the failure class the guard exists to remove.**

`guardedTick` says the same from the other side: "the cost of not counting is
that a permanently panicking standby never escalates on its own, so the
containment is reported instead: crash record + `culvert_crash_records_total`
{component="ha-standby-sync"}, the `sync_panics` status field, and a fire-once
`ha_sync_panic` alert". Three of those four signals are sink-wide. The alert
was not — so the plane that documents why containment needs a notification
shipped it for one component and not for the other 62, including
`ha_leadership_resume`, whose own contained failure CHAOS-119 residual `4`
describes as leaving "a node HA-gated until an operator restarts it".

This is the residual four consecutive rounds recorded and none closed:
CHAOS-116 `4`, CHAOS-117 `5`, CHAOS-118 `1`, CHAOS-119 `3` — the last of which
wrote "that it keeps being recorded rather than fixed is itself the finding".
Fixed here **in the sink**, so it covers every component rather than one plane,
and so the next round that adds a component inherits the notification instead
of having to remember it.

**CHAOS-120b (HIGH) — ten alert events were fired by production code with no
way to subscribe to them, and four of those could never be delivered at all.**
The Alerts panel's checkbox list is the only place Culvert's alert vocabulary is
discoverable; the admin API does not validate event names, so an operator who
already knows a string can POST it by hand, and nothing tells them the string
exists. CHAOS-113 built the differential oracle that proves every fired event
has a panel row, found thirteen gaps, fixed the four in its own scanning plane
and recorded the other ten in `scanAlertGUIKnownGaps` — correctly, because a
scan-sidecar round is the wrong owner for ten operator-facing panels, and
`REMOVING an entry from this list is the fix`.

Four of the ten are worse than undiscoverable. They **gate on a subscriber
before they build a payload**, which is the correct and deliberate pattern for a
producer whose rate is set by a fault rather than by an operator — and its
consequence, as CHAOS-113's own file comment says, is that "an event with NO WAY
TO SUBSCRIBE is an event that never fires":

| event | producer | what is lost |
|---|---|---|
| `admin_ui_unavailable` | `admin_ui_health.go:229` | the admin UI listener is down — operator ACCESS is gone, which is also how an operator would notice anything else |
| `cdr_unavailable` | `cdr_proxy.go:607` | the CDR sanitiser cannot be called; posture decides whether the file is forwarded unsanitised or blocked |
| `dns_failure` | `alerts.go:88`, `dns_health.go:178` | destination DNS is failing, so no request resolves |
| `yara_degraded` | `internal/yara/yara.go:663` | YARA match saturation under `fail_open_with_alert` — bodies forwarded with no YARA verdict |

For a deployment configured entirely through Culvert's own UI — the default, and
the only path most operators use — those four were **dark by construction**. The
remaining six (`disk_critical`, `pac_profile_degraded`, `ha_self_fenced`,
`ha_lease_reacquired`, `ha_resume_unfenced`, `ha_manual_failover_required`) do
fire, to whoever hand-POSTed the string. Two of them are the HA states that do
**not** clear on their own: `ha_resume_unfenced` ("operator action required")
and `ha_manual_failover_required` ("only an operator can promote it"). An HA
product whose two "only a human can fix this" alerts cannot be ticked in its own
UI is the sharpest instance in the set.

This round's scope IS the notification boundary, which makes it the owner
CHAOS-113 was waiting for. All ten now have a row, worded from their producer's
own posture, and `scanAlertGUIKnownGaps` is **empty** — kept as an empty map,
because the map is the mechanism: an entry added back is a new event shipping
unsubscribable and needs its reason written down. The panel went from 29
subscribable events to 40.

**The near-miss, recorded because it is the most useful thing this round
produced.** The obvious implementation of 120a was the one every other
fault-driven producer uses: gate on `HasSubscriber` before the `go`, to keep a
degraded node from spawning a goroutine per event in the default posture. That
would have put `globalAlertStore`'s mutex **on the crash-sink path** — and
`internal/alerts/store.go` releases that mutex with a **bare trailing
`as.mu.Unlock()`** in `Add`, `Update` and `Delete` (deliberately, so the
fsync-backed persist lands outside the lock). That is precisely the CHAOS-118
§7.4 lock-pairing shape, and unlike §7.4's own examples it **is** reachable from
a guard: a panic inside one of those critical sections strands `as.mu` held,
unwinds to `withAdminPanicRecovery`, and re-enters `recordCrash`. A subscriber
gate on the sink path would then have blocked the sink **forever** on a mutex
the panic itself stranded — hanging the admin request, and destroying the one
crash record that explains it. The sink whose contract is that it never fails
would have become the thing that hangs.

So the gate lives inside the goroutine, and the invariant that forced it is now
a gate of its own: **no function on the sink's synchronous path may touch a lock
owned by another plane.** The sink took no foreign lock before this round and
takes none after it; nothing had written that down.

**Also reached, NOT fixed (§5).** The crash record's `Summary` and `Stack` have
no reader anywhere in the product — they are `redact:"sensitive"`, so the only
export masks both to salted tokens, and neither the log line nor the audit entry
carries them. That is a diagnostic dead end, and the remedy is a
redaction-posture decision, not a chaos round's to take unilaterally. §5.1
records it with the evidence. §5.2 records the single-slot crash record, which
this round investigated, **falsified down to LOW**, and did not fix.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Expected | Post-fix |
|---|---|---|---|---|
| 1 | A background round panics once (any of 62 components) | counter + record + log + audit; **no notification** | the operator is told | `panic_contained` alert naming the component and crash id |
| 2 | `retryLeadershipResume` panics; the node stays HA-gated until restarted | silent; dashboards green (CHAOS-119 residual `4`) | paged | alert fires on the first occurrence |
| 3 | A round crash-loops deterministically (the CHAOS-109 shape: `RunNow` re-syncs at every boot) | silent | ONE page, not 86,400 | latched per component, re-arms after an hour; counter carries the repeat rate |
| 4 | The alert-delivery plane itself panics | counter + record + log + audit | no feedback loop, evidence kept | excluded from alerting; counter/record/log/audit unchanged |
| 5 | The notifier panics | n/a | sink must not re-panic | swallowed, counted in `culvert_crash_sink_panics_total`, record already committed |
| 6 | Backward clock step (NTP correction, VM snapshot restore) during a latched episode | n/a | lose at most one window | magnitude comparison (CHAOS-84's rule applied to the new latch) |
| 7 | A panic inside `Store.Update`'s critical section strands `as.mu` | sink unaffected (took no foreign lock) | sink unaffected | unchanged, and now pinned by a gate |
| 8 | Admin UI listener down, operator subscribes via the UI | gated on a subscriber that could not exist → **never fired** | deliverable | panel row |
| 9 | CDR sidecar unreachable, operator subscribes via the UI | **never fired** | deliverable | panel row |
| 10 | Destination DNS failing, operator subscribes via the UI | **never fired** | deliverable | panel row |
| 11 | YARA saturated under fail-open, operator subscribes via the UI | **never fired** | deliverable | panel row |
| 12 | Leader unreachable, auto-failover disabled | fired only to a hand-POSTed subscription | deliverable | panel row |
| 13 | Node read-only, lease held elsewhere, recovery abandoned | fired only to a hand-POSTed subscription | deliverable | panel row |

---

## 3. Risk matrix

| id | finding | severity | likelihood | detectability before fix | status |
|---|---|---|---|---|---|
| 120a | 62 of 63 crash components raise no alert | HIGH | certain (any contained panic) | counter scrape only; nothing pushes | FIXED |
| 120b.1 | four gated alerts undeliverable to a UI-configured operator | HIGH | certain once the fault occurs | none — the alert does not exist for them | FIXED |
| 120b.2 | six alerts deliverable only by hand-POSTing the event name | MED | high | none in the UI | FIXED |
| 120c | the near-miss: a subscriber gate on the sink path deadlocks the sink | HIGH (if shipped) | needs a panic inside an alert-store critical section | none — it would present as a hung admin request | AVOIDED + gated |
| 120d | crash `Summary`/`Stack` have no reader | MED | certain | n/a | RECORDED, §5.1 |
| 120e | single-slot crash record, last-write-wins | LOW | common on a busy node | n/a | RECORDED, §5.2 (falsified down from MED) |

---

## 4. Recovery assessment

**Automatic recovery.** Unchanged by this round, and that is the point: a
notification does not repair anything. What changes is that the operator learns
a repair is needed. For the five rounds CHAOS-119 §7.4 enumerated, the recovery
path is still a restart, and the alert now says so in its own Detail ("may be
degraded until the node is restarted").

**Deterministic recovery.** The latch re-arms on a fixed hour rather than on an
observed healthy round, because the sink has no healthy-round signal — it is
only ever called on a failure. `ha_sync_panic` can do better (it clears its
latch from `clearSyncPanicAlert` after a clean round) precisely because it lives
in the loop. The sink-level latch is therefore time-based by necessity, and the
review says so rather than implying episode semantics it does not have.

**Explicit ownership.** The notification is owned by the sink, not by 63 call
sites. A round that adds a component inherits it.

**Fail closed / fail open.** The notification path fails toward DELIVERY in
every direction: a nil seam falls through to the production dispatcher rather
than silently dropping (the contract `alerts.HasSubscriber` documents for a
missing probe), and a missing probe answers `true`. The one deliberate
suppression is the alert-delivery plane's own crashes, which cannot be delivered
by the plane that just failed and would otherwise feed back into the sink.

---

## 5. Also reached this round, NOT fixed

**5.1 The crash record's `Summary` and `Stack` have no reader, anywhere.**
`crashRecord` bounds the panic value to 512 bytes and `debug.Stack()` to 4096,
scrubs both with `sanitizeLog`, and stores them. Then:

- the ERROR log line carries "crash id + component + correlation ONLY" — by
  design, because "the raw panic VALUE is NEVER logged";
- the audit entry's Detail is `crash_id=… corr=… (value redacted)`;
- both fields are `redact:"sensitive"`, and the ONLY export accessor
  (`lastCrashRedacted`, feeding `crashCollector`) therefore masks them to a
  per-bundle salted token via `maskString`;
- the new alert deliberately carries neither.

So the two fields that would actually diagnose a contained panic are collected,
bounded, scrubbed and then unreadable by anyone, including the operator holding
the support bundle. The `sensitive` tag on `Stack` is itself documented as
defence-in-depth rather than necessity — "`debug.Stack` prints frames/PCs/arg
words, never string CONTENTS, so it cannot leak a secret string value — still
tagged sensitive". `Summary` is the genuinely secret-bearing field and its
tag is right.

Not fixed because the remedy is a change to a **security posture** — the export
class of a panic-derived field — and the conventions are explicit that no
convention authorizes "a security-setting change outside the task's scope". The
shape of a fix for whoever owns it: `Stack` is a candidate for
`redact:"internal"` (exported in a bundle the operator already holds, masked
nowhere else) while `Summary` stays `sensitive`; that is an owner decision about
what a support bundle may carry, and it needs the frame-content question
answered on current Go rather than on the comment's assertion.

**5.2 The single-slot crash record — investigated, falsified, LOW.** `lastCrash`
is one `*crashRecord`, last-write-wins, and `supportCollectorTimeline` says of
it "Most-recent recovered crash (0 or 1)" — against the ≤50 rows the
config-version trail contributes to the same timeline. The round's initial
reading was that a frequent request-path panic destroys the record of a rare
background one, which is the inversion CHAOS-119 found in the label cap, one
layer down.

That reading does not survive checking, and the round withdraws it rather than
shipping a ring buffer to fix a loss that is not one. The crash **index** is not
single-slot: every contained panic writes an audit entry with
`Action="panic_recovered"`, `Object=<component>` and the crash id, the audit log
is append-only JSONL, and in the support bundle `auditEntrySummary.Action` is
`public` and `.Object` is `internal` — so neither is masked, and the bundle's
audit section carries the readable who/when/which-component history that the
crash section carries one row of. What last-write-wins actually destroys is the
`Summary`/`Stack` pair, which per §5.1 nobody can read. A ring would have
retained, at some memory and byte-budget cost, data with no reader.

Recorded at LOW for the one thing that does remain: the timeline's crash rows
are a 1-row view of an n-row history that sits in the section next to it, which
is a presentation inconsistency for whoever owns the timeline, not a loss of
evidence. Noting also that `crashCollector`'s `ByteBudget` is 16 KiB and
`sectionSink.WriteJSON` replaces the **whole** body with a truncation
placeholder when a section exceeds it — so a future round that does add records
there must size the worst case against that budget rather than discovering it in
production.

**5.3 `feedsched.Config.OnPanic` and `feedsched.Run`'s unguarded `RunNow`
remain open.** CHAOS-119 §5.1/§5.2 handed both to "the round that takes the
scheduler". This round is not that round — they belong to
`internal/feedsched`'s own contract rather than to the notification boundary —
and they are unchanged.

**5.4 No alert rule ships on the crash counters, and that is now a different
statement.** The residual this round closes was recorded four times as "no alert
rule ships on the crash counters". It is closed by shipping the alert at the
SOURCE rather than as a rule over the counter, which is strictly better for the
operator (no scrape interval, no rule to author) and leaves one half genuinely
open: Culvert still ships no Prometheus alerting rules of any kind, for these
counters or any others. That is an alerting-asset question for the operator
documentation, not a code defect, and it is recorded here so the next round does
not re-file it as the same finding.

---

## 6. Mutation results

Every assertion was falsified before it was trusted.

| # | Mutation | Caught by | Result |
|---|---|---|---|
| A | drop `notePanicContained` from `recordCrash` (the pre-fix shape) | `ContainedPanicRaisesAnOperatorAlert`, `TheNotificationCannotCarryThePanicValue` | FAIL — the defect, reproduced |
| B | drop the `crashAlertAllow` latch | `AlertIsLatchedPerComponentThenRearms` | FAIL (2 dispatches, want 1) |
| C | replace the latch's `.Abs()` with a plain `<` | `AlertLatchSurvivesABackwardClockStep` | FAIL |
| D | `crashAlertExcluded` returns false | `AlertPlaneDoesNotAlertAboutItself` | FAIL |
| E | hoist the subscriber gate out of the goroutine onto the sink path | `CrashSinkTakesNoForeignLock` | FAIL — the near-miss, mechanically caught |
| F | remove the `panic_contained` checkbox | `NoFiredAlertShipsUnsubscribable` **and** CHAOS-113's oracle | FAIL (both) |
| G | re-add `dns_failure` to `scanAlertGUIKnownGaps` | `NoFiredAlertShipsUnsubscribable` | FAIL |
| H | remove the catalog entry | `PanicContainedIsDocumentedInTheAlertCatalog` | FAIL |

Two further checks that are not mutations but matter:

- **The oracle discovers the new event.** CHAOS-113's `alertFireRe` resolves no
  constants, so naming the event by a constant at the gate would have made the
  one gate whose job is to prove subscribability pass **vacuously**. The gate
  call site therefore uses the literal `"panic_contained"` on purpose, verified
  by running that regex over `crashguard.go` (one match). The round also asserts
  the checkbox directly, so coverage does not rest on another round's regex.
- **The foreign-lock gate has a negative control.** It fails if it resolves
  fewer than 5 of its named synchronous-path functions, and fails if
  `dispatchPanicContainedAlert` is not found — the vacuous-pass failure mode
  CHAOS-118 §7.2 found in its own first draft.

---

## 7. Operational, security and data-integrity impact

**Operational.** Strictly additive for an operator who subscribes to nothing:
`HasSubscriber` is false in the default posture, so the dispatch goroutine
returns immediately, and the latch bounds even the pathological case to ≤63
goroutines an hour. For an operator who does subscribe, the new event is the
first push notification Culvert has ever sent for a contained panic. The ten
reopened events are the second through eleventh.

**Security.** The payload carries the component and the crash id and nothing
else, for the reason the ERROR log line gives: a recovered panic value can embed
a credential (`panic(cfg.SessionHMAC)`), `sanitizeLog` scrubs control characters
rather than masking secrets, and a webhook is an **egress to a third party** —
so this boundary is stricter than the local log, not looser. Asserted at the
seam, which is what a future round would have to widen to leak it. No new
inbound surface, no new persisted state, no change to any posture decision
(fail-open/fail-closed outcomes are untouched end to end).

**Data integrity.** None. The notification is the LAST thing `recordCrash` does,
after the record, the log line and the audit entry are committed, so it cannot
delay or displace durable evidence — pinned by
`APanickingNotifierCannotBreakTheSink`, which asserts the record survives a
notifier that panics.

**Monitoring visibility.** `culvert_crash_records_total{component}` is unchanged
and remains the repeat-rate signal; the alert is the edge signal. The two are
complementary by design, which is why latching the alert loses no information.

---

## 8. Required tests

Shipped in `chaos120_crash_notification_test.go` (ten tests), plus the amended
CHAOS-113 oracle:

1. a contained panic raises one alert, naming the component and the crash id
   that joins it to the local evidence;
2. the notification cannot carry the panic value, and the local record still
   can;
3. the latch holds per component, is per-component rather than global, and
   re-arms;
4. the latch survives a backward clock step (CHAOS-84's rule);
5. the alert-delivery plane does not alert about itself, and still records;
6. a panicking notifier cannot break the sink and is counted;
7. a nil seam fails toward delivery and is not dereferenced;
8. the sink's synchronous path touches no foreign lock (AST gate, with a
   negative control);
9. no fired alert ships unsubscribable — the empty known-gaps map, the four
   gated events, the six hand-only events, and this round's own;
10. the event is documented in the alert catalog, including the egress boundary.

## 9. Verification run for this change

| check | command | result |
|---|---|---|
| package main, full | `go test -count=1 -timeout 45m .` | **ok**, 442.8s |
| all internal packages | `go test -count=1 ./internal/...` | **ok** |
| this round + neighbours, shuffled ×3 | `go test -run 'TestCHAOS120\|TestCHAOS119\|TestChaos113\|Crash\|Alert' -shuffle=on` | **ok** ×3 |
| lint, the gate's own command | `golangci-lint run --new-from-rev origin/main` (v2.15.0, installed with the `go.mod` toolchain) | **0 issues** |
| lint, full tree vs. the same measurement on the base | `golangci-lint run` on HEAD and on the stashed base | **identical** issue counts; none naming a touched file |
| guidance checker | `python3 docs/agent-context/check.py` | exit 0 |

These are local results for this tree. They are not a hosted review and not a
merge gate; the Fast PR Gate's own jobs are the authority for the exact SHA.

---

## 10. Residual risk

1. **The latch is time-based, not episode-based.** The sink is only ever called
   on a failure, so it has no healthy-round signal to re-arm on — unlike
   `ha_sync_panic`, which clears its latch from the loop after a clean round. A
   component that panics once an hour therefore pages once an hour and looks
   identical to one that panics once a second. The counter distinguishes them;
   the alert does not. An hour is a judgement call, and the honest statement is
   that it trades alert fidelity for not training operators to mute the event.

2. **Reporting a contained panic is still not acting on one.** CHAOS-119
   residual `4` stands in full. `retryLeadershipResume` still leaves a node
   HA-gated until an operator restarts it; what changed is that the operator
   now finds out without scraping a counter. No round in this family has yet
   proposed self-healing for a contained round, and it is not obvious that one
   should.

3. **Culvert ships no Prometheus alerting rules.** §5.4. The source-level alert
   covers the crash plane; every other counter in the product still depends on
   the operator authoring their own rule, with no shipped starting point.

4. **A subscriber is still required.** `panic_contained` is opt-in, like every
   other event. An operator with no webhook configured is in exactly the
   position they were before this round — which is the correct default for an
   egress, and does mean the fix only helps those who tick the box. Nothing
   surfaces the crash plane in the admin UI itself: `culvert_crash_records_total`
   has no panel, so the in-product answer to "has anything panicked" is still
   the metrics endpoint or a support bundle.

5. **The foreign-lock gate names a list, not a property.** It knows
   `globalAlertStore` and `configVersions` are foreign locks because this round
   named them. A future round that puts a THIRD process-wide store on the sink
   path gets no warning. Deriving the set mechanically (every package-level var
   whose type carries a mutex) is a bigger build with its own correctness
   question, and it belongs with CHAOS-118 §7.3's lock-pairing audit, which is
   still open.

6. **The ten reopened events are now subscribable, not validated.** Each has a
   row worded from its producer's posture, and nothing asserts the wording stays
   true if the producer's posture changes. The CHAOS-113 oracle proves a row
   EXISTS; no gate proves it still describes the fault.
