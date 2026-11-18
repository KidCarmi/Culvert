# Chaos engineering review — 2026-11-18

Reviewer: Culvert Chaos Engineer (automated round). Base revision `348a2cf`
(`origin/main`), clean worktree at branch point. Recorded separately for the
reason the previous rounds were; [the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md)
stays the index.

Id claimed: **CHAOS-123**, in a committed placeholder row as commit one, before
any code, checked against `origin/main` rather than the working tree per the
register's 2026-09-25 amendment. `CHAOS-122` was the highest id anywhere on
`origin/main` at `348a2cf`, and no open PR held a chaos id (#1944, #1943, #1942,
#1941, #1705, #1549, #1548, #1536, #1528, #1526 — the first four are the
internal-migrate and traffic-UI lines, #1943 a terminology review, the rest the
appliance and policy-design lines).

Every `file:line` below is at the **base revision** `348a2cf`, so the defect
citations stay readable against the tree as it was before this round's edits.

---

## CHAOS-123 — The deny control nobody could watch: 24 hours of unrefreshed blocklist and a green dashboard

Scope: **the operator's own remote blocklist feeds** — the ones a customer
points at their threat-sharing group, their industry ISAC, their internal
mirror, or a vendor list they pay for. Not the feeds Culvert ships.

This round was handed to it by name. CHAOS-108 fixed this feed's CADENCE and
then wrote down, in the owner's own package doc, exactly what it had not fixed:

> **NOT fixed here, and recorded as the open half:** this feed still has no
> staleness alert or health row. `internal/threatfeed` has both (a
> `threat_feed_stale` alert, plus a deferred startup variant); a blocklist feed
> that has never synced, or is arbitrarily stale, raises neither and is visible
> only as `LastError` in the admin API and one log line per attempt. Adding an
> alert type is an owner decision with GUI/API parity consequences, not a
> drive-by rider on a scheduling fix.

That note was right on every point, including that it needed its own round. The
audit found its description of the gap was also one shape short.

---

## 1. Executive summary

**CHAOS-123a (HIGH) — the remote blocklist feed exported NO freshness signal of
any kind, so the enterprise monitoring path could not see a deny control that
had stopped being refreshed.**

There were no `culvert_blocklist_feed_*` series at this revision. Not a stale
gauge, not a last-success timestamp, not a failure counter — the family did not
exist. An operator running Prometheus and Alertmanager, which is how an
enterprise SWG is actually watched, had nothing to scrape and nothing to page
on.

The one gauge that looks like it would help is the one that hides the problem.
`culvert_blocklist_size` (`metrics.go:838`) reports the blocklist's entry count,
and feed imports are **merge-only** by design — `blocklist.MergeFromLines`
(`internal/blocklist/blocklist.go:940`) adds and never deletes, then `b.Save()`
persists. So:

- a feed that has not fetched for three weeks leaves the list exactly as large
  as one that fetched ten minutes ago;
- a restart reloads the same entries from disk, so even a reboot does not make
  the count move.

This is the identical mechanism WK-5/CHAOS-59 closed for the threat feed, where
it is written down in `threatfeed_health.go:15-22`: the carry-forward fix was
correct and *"also removed the only signal an operator had"*. The blocklist feed
never had the loud phase at all — merge-only was its design from the start — so
it has always been in the state the threat feed only reached after its fix, and
nobody had noticed that the same remedy was owed.

**What degrades is specific and it is not a cache.** The destinations added to
the origin since the last clean round are precisely the ones the operator
configured the feed to block, and during the stale window they are allowed. The
gateway is not *failing* — policy, categories, DPI, AV, CDR and the threat feed
are untouched, and everything already imported is still enforced. One narrow
control is silently not being applied to anything new.

**CHAOS-123b (MEDIUM) — the only surface that existed, the `blocklist_feed`
diagnostics row, was gated on `LastError != ""` and therefore blind to the two
states in which nothing is attempted at all.**

`diagnostics_blocklist_feed.go:21-38` counted feeds with a non-empty
`LastError`. That is the right signal for "the last attempt failed" and it was
added for a good reason (SECURITY-REGRESSION-REVIEW-2026-11-06, PR #1809). It
cannot see a feed that is not being attempted:

- **Auto-sync off.** `blocklistFeedUpsert` accepts `"interval": "off"` and maps
  it to 0 (`ui_policy.go:329`); `dueURLs` skips `st.interval <= 0`
  (`internal/blocklistfeed/blocklistfeed.go:330-335`). The scheduler therefore
  **never** attempts the feed. No attempt means no `LastError`, so the
  diagnostics report said the node was healthy while a configured deny control
  contributed nothing to the blocklist — not for an interval, **forever**, until
  somebody clicked Sync Now. It is a supported configuration (it is how you pin
  a one-off import), which is exactly why it needed a row rather than a page:
  the product should say "this feed is configured and nothing will ever sync
  it", and it said nothing.
- **The window after a settings restore.** `applyBlocklistFeeds`
  (`admin_settings.go:588-612`) is authoritative over the startup seed and
  implements that as `ClearFeeds()` + `SetFeed()`, which constructs fresh
  `feedState`s. A persistently failing feed's `LastError`, `LastSync` and
  `ImportedCount` are all reset, so the WARN row **disappears**. The window is
  bounded and correctly bounded — `nextAttempt` is zero, so the feed is due on
  the next 60 s tick — but during it the only failure signal the product had
  reported "healthy", and a node that restarts into a feed outage spends that
  window with its one indicator green.

**CHAOS-123c (MEDIUM) — nothing paged.** There was no alert type for this feed.
The diagnostics row is report-only: it requires a human to open a page. Against
`internal/threatfeed`, which has a `threat_feed_stale` alert, a deferred startup
variant, five `/metrics` series and a diagnostics row, the operator-configured
feed had one of the four surfaces, and the one that does not reach anybody who
is not already looking.

**What was already right, and is left alone.** The cadence. CHAOS-108's work
holds and this round depends on it: a failed round is retried on a bounded
exponential ladder clamped below the feed's own interval rather than waiting out
24 hours; the phase is jittered per feed so a fleet that boots together does not
become a thundering herd against a third-party origin; the fetch is parented to
the lifecycle context so shutdown interrupts it; `resp.StatusCode` is checked so
a 503 error page is not merged as if it were the feed
(`internal/blocklistfeed/blocklistfeed.go:478-485`); and CHAOS-109's byte and
line budgets bound the ingest. The SSRF guard runs inline at every sync, not
only at save time (`:445`), which closes the "host starts resolving internally
after it was saved" hole. Panic containment is at the round, not the goroutine
(`:307`, `obs.SafeCall`). None of that needed changing — the gap was that none of
it was observable.

---

## 2. Failure scenarios

Each row is the state as measured at `348a2cf`, then the state after this round.

| # | Scenario | Before: what an operator saw | After |
|---|---|---|---|
| 1 | Feed origin returns 503 for a week | `last_error` on one admin panel; one log line per attempt; `blocklist_feed` WARN row. No metric, no page. | `_failing` and `_stale` gauges, `_stale_seconds` age, `blocklist_feed_stale` alert once per episode |
| 2 | Feed origin DNS goes away | as #1 | as #1 |
| 3 | Feed host starts resolving to a private address | as #1 (round fails on the SSRF guard) | as #1; cause still on the role-gated API |
| 4 | Feed URL's token is revoked (401/403) | as #1 | as #1 |
| 5 | **Feed added with auto-sync off, never synced** | **nothing — every surface green, forever** | own WARN row, `_manual_never_synced` gauge, deliberately no page |
| 6 | Node boots into a feed outage (fresh install) | WARN row once the first round fails; the feed contributes zero entries | plus `_never_synced`, and a page once past the 15-minute grace |
| 7 | Settings restore while a feed is failing | **WARN row disappears until the next round** | `_never_synced` row and gauge cover the window |
| 8 | Scheduler stopped (shutdown, contained panic before the stamp) | nothing moves; last state persists and reads healthy | `_stale_seconds` keeps growing; `_stale` fires on threshold |
| 9 | Clock steps backwards under a running node (NTP, VM restore) | n/a | age clamped at 0, reported fresh — a clock correction does not page |
| 10 | Two feeds, one healthy, one dead | one WARN row | one page for the dead feed; the healthy feed's clean rounds do **not** clear the episode |
| 11 | Node restarts daily, feed dead throughout | nothing | per-boot `_never_synced`; long-horizon staleness still not durable (§10) |

---

## 3. Risk matrix

| Finding | Likelihood | Impact | Severity | Why |
|---|---|---|---|---|
| 123a — no freshness metric at all | **High** — any third-party origin has outages; the default interval is 24 h | Medium-High — a deny control silently not applied to new entries | **HIGH** | The monitoring path a customer actually uses had zero visibility, and the gauge that looks relevant is held constant by design |
| 123b — row blind to "never attempted" | Medium — `off` is a documented setting; restores happen on every boot | Medium — a configured control contributing nothing, reported healthy | **MEDIUM** | Unbounded in the auto-sync-off case; bounded to one tick in the restore case |
| 123c — no alert type | **High** | Medium | **MEDIUM** | Report-only surfaces do not reach anybody who is not already looking |

Not a severity: the *enforcement* behaviour. Nothing here allows traffic that
policy would deny, nothing is wiped, and nothing fails open beyond the specific
entries the origin added while unreachable.

---

## 4. Recovery assessment

**Automatic.** A failed round retries on CHAOS-108's bounded ladder and the feed
returns to its interval on the first clean round. The alert episode clears only
on OBSERVED evidence — every auto-synced feed fresh — never on elapsed time,
because a feed that has stopped reporting failures because nothing is running
looks identical to a healthy one. That rule is `ca_health.go`'s and
`storage_health.go`'s, and it is gated here by
`TestChaos123_RecoveryNeedsObservedEvidenceFromEveryAutoSyncFeed`.

**Manual.** Sync Now, per feed or for all; the runbook
([`docs/operator/blocklist-feed-freshness.md`](../operator/blocklist-feed-freshness.md))
carries the triage order.

**Does not self-heal:** the auto-sync-off case. Nothing will sync it. The new row
says so in those words, and the operator action is "set an interval".

---

## 5. Operational impact

Before: an operator's only path to the truth was to open Policy → Blocklist →
Feeds and read a column, or grep the log. A dashboard built on
`culvert_blocklist_size` would be reassuring and wrong.

After: ten unlabelled series, three diagnostics shapes and one alert. The series
are emitted **only** when at least one feed is configured, so `== 0` stays a
safe alerting rule on the fleet — a `culvert_blocklist_feed_sync_ok 0` exported
by a node that never used the feature would page every such deployment, which is
the rule the SOCKS5, cluster-CA and threat-feed gauges already follow.

Deliberately **not** done, each for a reason recorded in the file comment:

- **No `/readyz` row and no `/healthz` failure.** A node with a stale blocklist
  feed is a fully serving gateway. Failing readiness would pull healthy
  gateways out of the load balancer over a third-party origin's outage —
  `threatfeed_health.go` and `catfeeddb_health.go` both record this judgement.
- **No fail-closed toggle.** Blocking traffic because an operator's feed origin
  is unreachable converts that origin's outage into the customer's outage, and
  this feed is an additive deny list on top of the policy engine's own default
  action, not the control that decides whether a request is allowed.
- **No per-feed label on any series.** See §6.

---

## 6. Security impact

**The exposure closed.** A deny control silently not being refreshed is a
security-relevant blind spot: the operator believes a list is being enforced and
it is being enforced only as of whenever it last loaded.

**The exposure not created.** Three containment rules, each with its own gate:

1. **No feed URL on any surface.** A feed URL is operator-configured and
   routinely embeds a token — the reason the pre-existing diagnostics row
   already refused to print it. `/metrics` is the wider exposure of the two,
   because it is commonly scraped unauthenticated when `metricsToken` is unset
   (`metrics.go:781`), so every new series is an **aggregate count or a
   worst-case age with no labels**. Cardinality is therefore also not a
   function of how many feeds an admin adds.
2. **No error text in the alert.** `SyncOutcome` carries no cause at all. The
   fetch error embeds the URL and, for a transport failure, the ephemeral local
   port — a per-attempt-unique value, which would defeat the alert store's
   event+Detail dedup window *by construction* and evict real alerts from the
   bounded retry queue. `internal/threatfeed` hit exactly this and answered it
   with a bounded reason class; the blocklist feed's equivalent needs sentinel
   errors threaded through `fetchFeedLines` and is recorded as the open item
   (§10) rather than improvised here.
3. `TestChaos123_NoSurfaceCarriesTheFeedURL` configures a feed with
   `?key=token-abc123`, seeds a fetch error containing the URL and an IP, and
   asserts that the scrape output, every diagnostics row and the alert detail
   carry none of the token, the host, the IP or the error text.

The alert is `HasSubscriber`-gated, so with no webhook configured — the default
posture, and the state of every test binary — it does not even build a payload.

---

## 7. Data-integrity impact

None. This round adds no durable state and writes nothing. It deliberately
declines the one durability change that was tempting; see §10.

The one behaviour change inside the engine is a clock-seam correction: the
success path stamped `st.lastSync = time.Now()` while `st.lastAttempt` one
branch up already read `bs.timeNow()`. Both now read the seam. In production
they are the same clock; the consequence was that the single field the freshness
plane measures from could not be driven by a fake clock, so the staleness
contract could only have been asserted by sleeping past a 24-hour threshold.

---

## 8. Monitoring, logging and alert quality

- **Metrics:** 10 series, documented in the runbook with four suggested PromQL
  rules and an explicit warning not to alert on `culvert_blocklist_size`.
- **Logging:** the failure line is rate-limited to one per 30 minutes with a
  recovery line naming how many were suppressed — `storage_health.go`'s
  discipline: the log carries the SIGNAL, the counter carries the MAGNITUDE.
- **Alerts:** one event, fire-once per episode, subscribable from the Alerts
  panel. The CHAOS-113 parity gate
  (`TestChaos113_EveryFiredAlertIsSubscribableInTheGUI`) passes without adding
  a known-gap entry, so the new vocabulary is discoverable where an operator
  looks for it.

---

## 9. Suggested improvements, in priority order

1. **A bounded reason class on `SyncOutcome`** so the alert can say *why*.
   Needs sentinel errors in `fetchFeedLines`. Open — see §10.
2. **Durable last-success timestamps.** Open, and refused here with a concrete
   reason — see §10.
3. **A fleet-level view.** These are per-node series; a cluster whose DP nodes
   have divergent feed freshness is readable only by scraping each one.
4. **Apply the same audit to the remaining optional feeds.** This round and
   CHAOS-108 have now each found the same class in a feed loop that the
   `internal/feedsched` doc's enumeration did not cover. The doc counts THREE
   loops; the tree has more. A gate that enumerates every periodic remote fetch
   and asserts each has a freshness surface would end the class rather than
   retiring it one feed at a time.

---

## 10. Residual risk

**Freshness is not durable across a restart.** `lastSync` lives in memory:
`AdminSettings` persists only each feed's URL and interval
(`admin_settings.go:578-580`). So every boot starts at "never synced" until the
first round lands, and a node that restarts frequently cannot be observed as
long-term stale. The practical effect is bounded — the boot pass is immediate
(`nextAttempt` zero is due now) and a reachable origin lands inside the first
60 s tick, so a reachable feed is fresh again at once and an unreachable one
shows up as failing — but the LONG-HORIZON signal "this feed has been dead for
three weeks across six restarts" is not recoverable from this node's state.

It was considered and rejected for this round, and the reason is not scope:
**the only durable store the feed set lives in is `AdminSettings`, which
configuration versioning captures.** A timestamp that advances on every
successful sync would turn each round into an apparent configuration change.
That makes it a config-surface owner's decision (see
[`config_surfaces.go`](../../config_surfaces.go) and the
[versioning triage](../../roadmap/CONFIG-VERSIONING-TRIAGE.md)), not an
observability rider — the same shape as the credential and CDR-hygiene paths
that must explicitly NOT create versions.

**The alert says what, not why.** Per §6.2.

**A manual-only feed is reported, never paged.** Deliberate: the operator
disabled the schedule, so paging would be paging on their configuration. The
residual risk is that a *mistaken* `off` is a WARN row somebody has to read
rather than a page. The row names the consequence in plain words to make that as
cheap as a row can be.

**The staleness threshold is 2× each feed's own interval.** With the 24 h
default, a feed can be 48 h stale before it pages. One interval would page on a
single missed window, which is the transient CHAOS-108's ladder exists to
absorb; the ladder is clamped below the interval, so by the time 2× has elapsed
the feed has already failed a run of bounded retries rather than one round. An
operator who wants tighter can set a shorter interval or alert on
`culvert_blocklist_feed_stale_seconds` directly, which the runbook says.

**`_stale_seconds` is an absolute age across feeds with different intervals.**
It is the worst case, not a per-feed verdict, which is why `_stale` (a count
against each feed's own threshold) is the series the runbook recommends paging
on.

---

## 11. Tests

Engine (`internal/blocklistfeed/observer_chaos123_test.go`, 7 tests):
the ladder count advances across rounds; the success path reports through the
clock seam and `Feeds()` agrees; an observer panic is contained and the round
still succeeds and still merges; the observer is invoked **without**
`Syncer.mu` held, asserted on both the success and failure paths with a bounded
wait, because an observer that took the lock from inside the critical section
would wedge the shared tick and therefore every feed on the node; a nil observer
is the default and is clearable; `LastAttempt` distinguishes never-tried from
tried-and-failed, and a manual-only feed is never due however much time passes.

Plane (`blocklist_feed_health_chaos123_test.go`, 12 tests): no series and no row
with no feed configured, and none on an unarmed plane; a fresh feed is green;
stale past 2× pages once and reports the right age and the right oldest-success
timestamp; never-synced is silent inside the grace and both reported and paged
past it, with its own wording; the manual-only shape is reported and **not**
paged, and its row clears once it has been synced by hand; the settings-restore
window is measured; the alert fires once for five failed rounds; recovery needs
every auto-sync feed observed fresh, and a new episode may page again; a
backwards clock reports fresh; no surface carries the URL, host, IP or error
text; every series carries HELP and TYPE through the same builder `metrics.go`
passes, so a dropped call site fails here.

**Commands run, at `cd565f4`:**

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go vet .` | pass |
| `go test ./internal/blocklistfeed/ -count=2 -race -shuffle=on` | pass |
| `go test . -run 'TestChaos123_' -count=2 -race -shuffle=on` | pass |
| `go test . -run 'TestChaos113_'` (alert GUI parity) | pass |
| `go test ./internal/alerts/ -run TestValidateEventNames` | pass |
| `go test . -run 'Blocklist\|Diagnostic\|Metrics\|OperatorContract\|Alert'` | pass |
| `golangci-lint run --new-from-rev origin/main` (v2.15.0, the gate's pin) | 0 issues |
| `golangci-lint run` full tree | 174 issues — identical to the base count at `348a2cf`, so nothing new attributed to a declaration line |
| `go run ./cmd/contractcheck impact -base origin/main` | no contract code paths touched |
| `python3 docs/agent-context/check.py` | pass |
| `go test ./internal/...` | pass |
| `go test .` (full root package) | see the PR body — a local pass is not a hosted gate |

---

## 12. Suggested PR

This one. Three commits: the id claim, the implementation, this review.

Scope boundaries held: no change to enforcement, to the fetch path, to the
cadence, to persisted state or to any wire format. The pre-existing
failing-attempt diagnostics row keeps its wording verbatim. No dependency
moved, no gate weakened, no suppression added.
