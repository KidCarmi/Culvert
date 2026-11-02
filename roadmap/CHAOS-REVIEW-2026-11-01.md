# Chaos engineering review — 2026-11-01

Reviewer: Culvert Chaos Engineer (automated round). Base revision `3c5fab1`
(`main`), clean worktree at branch point. Recorded separately for the reason
the previous four rounds were:
[CHAOS-ENGINEERING-REVIEW.md](CHAOS-ENGINEERING-REVIEW.md) stays the index.

Id claimed: **CHAOS-108**. Claimed in a committed placeholder row as commit
one, before any code, and checked against `origin/main` rather than the working
tree per the register's 2026-09-25 amendment. `CHAOS-107` was the highest id
anywhere on `origin/main` at `3c5fab1` and no open PR held `CHAOS-108`.

Scope: **the fourth periodic feed loop.** Not "what happens when a feed origin
is down" — the 2026-08 intelligence-feed round (§27) swept that for the feeds it
knew about — but the narrower question of which loops actually got the fix that
round produced.

---

## 1. Executive summary

`internal/feedsched` exists because Culvert's periodic feeds scheduled
themselves wrongly in two specific ways, and its package doc states both and
names the loops it covers:

> Culvert ships THREE periodic feed loops and, before this package, only the
> newest of them scheduled itself correctly […] **A failed round is not retried
> until the next full interval.** […] **A fleet stays in phase forever.**

It names the signed SaaS category feed, `internal/feedsync` (UT1) and
`internal/threatfeed` (URLhaus/OpenPhish). There is a **fourth**: the
operator-configured remote blocklist feed, `internal/blocklistfeed`. It was
never migrated, `grep` confirms it is not a `feedsched` consumer, and it had
both named defects — plus a second, independent root cause the three siblings
do not share.

**CHAOS-108a (HIGH) — a failed sync was not retried for a full interval, 24h on
a stock install.** `SyncFeed` stamped the attempt time on the *error* path and
`syncDue` gated the next attempt on it, so any transient failure — a DNS blip,
a 503, a connection reset, a TLS error — bought the origin a full interval of
silence. The worst shape is the boot pass, which runs precisely *because*
nothing has been attempted yet: a node that boots into a feed outage merges **no
domains from that feed at all** — not stale entries, none — and does not try
again for a day. The blocklist is a deny control, so that window is fail-open on
exactly the destinations the operator configured the feed to block. The cadence
also carried no jitter and pinned its phase at boot, closing the same loop
`feedsched`'s doc describes: a fleet restarted together herds a third-party
origin, the origin rate-limits, and the absent retry then holds the whole fleet
at that failure for the interval.

**CHAOS-108b (HIGH) — an HTTP error response was accepted as a feed body, and
its error page was merged into the durable blocklist.** `fetchFeedLines` never
checked `resp.StatusCode`, so "success" meant *the transport returned bytes*,
not *the origin served the feed*. Both siblings already gate on status
(`internal/threatfeed:950`, `internal/feedsync:411`); this loop did not. Two
consequences, both measured below: the error page was **merged** — `added` was
non-zero and the merge is persisted and merge-only, so it never self-heals —
and the round was recorded as a **success**, so an origin serving 503 for a week
reported "synced just now, no error". That second half also defeats 108a's new
ladder: backoff would never engage for the single most common outage mode.

Both defects share one root cause, which is why they are one id: **this loop's
notion of a successful round was never "the origin served the feed".**

A third, smaller defect in the same loop: the fetch was parented to
`context.Background()`, so shutdown could not interrupt an in-flight sync even
though `Start` is handed `appLifecycleCtx` with a SIGTERM hook.

All three are fixed in this PR, with gates measured red against each defect
separately. The loop's **observability** gap is NOT fixed and is recorded in
§10 as the open half: unlike `internal/threatfeed`, this feed has no staleness
alert and no health row.

---

## 2. Failure scenarios

| # | Scenario | Pre-fix behavior | Expected | Post-fix |
|---|---|---|---|---|
| 1 | Feed origin returns 503 on the boot pass | Feed merges nothing; next attempt in 24h; node serves without that deny list for a day | Retry on a bounded ladder, well inside the interval | Retry at `DefaultBackoffMin` (5m), doubling to the 1h ceiling |
| 2 | Transient DNS failure mid-life | One failure costs the full interval | Same | Same ladder; one success resets it |
| 3 | Fleet of N nodes restarted together | All sync in phase against a third-party origin, forever | Spread across the fleet | One stable `StableJitter` offset per feed per node |
| 4 | Origin serves a 5xx HTML error page | Page merged as entries (`<html>`, `upstream down` → host `upstream`), saved, never removed; feed reports healthy | Refuse the body; record the failure | `HTTP %d from %s` error; nothing merged; `LastError` set, `LastSync` untouched |
| 5 | Origin serves 429 under the herd of #3 | Counted as a *success*: ladder reset, staleness invisible | Treated as a failure | Charged to the ladder |
| 6 | SIGTERM during an in-flight fetch | Waits out `httpTimeout` (30s) | Interrupted promptly | ctx threaded from `Start` to the request |
| 7 | SIGTERM with several feeds due | Keeps starting fetches for the rest of the round | Stops starting new ones | `syncDue` checks `ctx.Err()` per feed |
| 8 | Operator shortens the interval after a sync | Took effect at once (gate recomputed per tick) | Unchanged | Preserved by `setFeedIntervalLocked`, which only ever pulls a pending wait IN |

### Reproduction (measured, not inferred)

Each gate was run against the pre-fix behavior restored surgically, one defect
at a time, so no gate is credited to a defect it does not actually detect:

- **RED-A** — next attempt forced back to `lastAttempt + interval` regardless of
  outcome: `FailedSyncRetriesBeforeTheConfiguredInterval`,
  `BootFailureDoesNotCostAFullDay`, `BackoffGrowsBoundedAndResetsOnSuccess`,
  `SteadyStateCadenceIsSpreadAcrossNodes` all FAIL.
- **RED-B** — status gate removed: `ErrorResponseIsNotMergedAndNotReportedHealthy`
  FAILS, with the measured detail for every status 400/401/403/404/429/500/502/503:
  `error page reached the blocklist (1 merge call(s), 4 added)`,
  `left LastError empty — the admin API would report a healthy feed`,
  `advanced LastSync`. `FailedSyncRetries…` and `BootFailure…` also FAIL,
  which is the ladder-defeat coupling in §1.
- **RED-C** — fetch re-parented to `context.Background()`:
  `ShutdownInterruptsAnInFlightFetch` FAILS, hanging for the full 5s test
  budget rather than returning.
- **RED-D** — backoff floor raised past a short interval (the ceiling-only
  clamp `feedsched` itself shipped once, per its `backoffBounds` comment):
  `RetryNeverLoosensTheCadence` FAILS with
  `failure 1 waited 5m0s against a 1m0s interval`. This gate guards a
  *regression*, not the pre-fix state, and is labelled as such.

---

## 3. Risk matrix

| Finding | Likelihood | Impact | Severity | Notes |
|---|---|---|---|---|
| 108a boot-into-outage, feed absent for a full interval | MED | HIGH | **HIGH** | Default 24h; deny control absent, not stale |
| 108b error page merged into durable blocklist | MED | HIGH | **HIGH** | Merge-only + persisted ⇒ no self-heal; over-block is an availability fault |
| 108b failing origin reports healthy | HIGH | MED | **HIGH** | Silent failure; also resets the retry ladder |
| 108a fleet in phase ⇒ self-inflicted rate-limit | MED | MED | MED | Closes the herd/retry loop `feedsched` documents |
| Fetch not cancellable at shutdown | HIGH | LOW | LOW | Bounded by the 30s `httpTimeout` |
| No staleness alert / health row (**open**) | HIGH | MED | MED | §10; owner decision |

---

## 4. Recovery assessment

- **Automatic recovery, pre-fix:** only at the next interval boundary, and for
  108b not at all — a 503 looked like a success forever.
- **Automatic recovery, post-fix:** bounded exponential backoff from 5m to a 1h
  ceiling, both clamped to the live interval so a retry is always *faster* than
  a healthy sync; the count resets on the first success. Retries are unbounded
  in count but bounded in rate, which is the posture `feedsched` and
  `ha_lease_recovery.go` already record — a feed that stopped retrying would be
  strictly worse, freezing intelligence on one transient error.
- **Manual recovery:** "Sync Now" in the admin UI, unchanged, and still
  deliberately not parented to the operator's HTTP request.
- **Residual, pre-existing:** entries already merged from a pre-fix error page
  stay in the blocklist. They are merge-only and attributed to the feed URL, so
  an operator must remove them by hand; this PR stops new ones and does not
  attempt a retroactive cleanup (a sweep that deletes blocklist entries on a
  guess is a worse change than the one it fixes).

## 5. Operational impact

Pre-fix, an operator reading the admin API could not distinguish a healthy feed
from one whose origin had answered 503 for a week. Post-fix, a failing feed
carries `LastError`, leaves `LastSync` where it was, and logs one line per
attempt naming the consecutive-failure count and the actual next delay
(`retrying in 5m0s, not at the configured interval`). Steady-state cadence now
carries ±10% jitter, so a 24h feed may sync up to ~26.4h apart; that is the
established `feedsched` contract the other feeds already follow.

## 6. Security impact

The blocklist is a deny control. 108a's boot window means a re-imaged or
freshly booted node proxies to the domains the feed exists to block, for up to
the configured interval, while every probe reports a healthy node. 108b is the
inverse direction: whatever answered the feed URL could write tokens into a
security control's durable state. Neither requires an attacker — an origin
outage or an intercepting upstream is enough — but both are reachable by one.

## 7. Data-integrity impact

108b wrote non-feed data into `blocklist` persistence through `MergeFromLines`
→ `Save()`, attributed to the feed URL in the `.sources` sidecar. Merge-only
semantics mean the pollution is durable and cumulative across every failed
sync. Post-fix nothing is merged unless the origin returned 200.

## 8. Suggested improvements (ranked)

1. **Shipped here:** migrate the fourth loop onto the owner's ladder; add the
   status gate; thread the lifecycle context.
2. **Open (§10):** a staleness alert and health row for this feed, mirroring
   `threat_feed_stale`.
3. **Observed, not fixed, shared with the siblings:** no feed caps its response
   body. `bufio.Scanner` bounds a *line* at 64 KiB, but total size is unbounded,
   so a compromised or hostile origin can drive the syncer's line slice to
   arbitrary memory. This is a pre-existing class common to `blocklistfeed`,
   `threatfeed` and `feedsync` — neither sibling uses a `LimitReader` — so it
   belongs to a round that treats all three, not to a unilateral patch of one.
   Recorded with its evidence rather than silently fixed here.

## 9. Verification

Revision verified: `5e68ec7` (this branch). Toolchain `go1.27.3`
(`go.mod` `toolchain` line; `go env GOVERSION` = `go1.27.3`).

| Check | Command | Result |
|---|---|---|
| Owner package, race + determinism | `go test -race -shuffle=on -count=2 ./internal/blocklistfeed ./internal/feedsched` | PASS |
| Red differential | RED-A/B/C/D above | each FAILS as recorded |
| Root callers | `go test -count=1 -run 'Blocklist\|BlFeed\|FeedSync\|Feed' .` | PASS — 182 tests, 0 fail, 3 SKIP (all `CULVERT_FEED_*` CI-only env gates, unrelated) |
| Vet | `go vet ./...` | clean |
| Tidy drift | `go mod tidy -diff` | clean |
| Build | `CGO_ENABLED=0 go build -ldflags="-s -w"` | OK |
| Cross-build | `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build` | OK |
| Lint, diff-scoped (the gate's own command) | `golangci-lint run --new-from-rev origin/main`, v2.15.0 built with `go1.27.3` | **0 issues** |
| Lint, full tree vs base | same binary, base `origin/main` in a worktree | base **174**, head **174**, per-linter counts identical, **0** in `internal/blocklistfeed` |
| Guidance checker | `python3 docs/agent-context/check.py` | PASS |

The full-tree pass earned its place: it caught a `nestif` finding this change
introduced in `SetFeed`, whose *declaration* line is unchanged and which
`--new-from-rev` therefore could not see — the exact case `conventions.md`
describes. Fixed by extracting `setFeedIntervalLocked` (commit `5e68ec7`).

**Not run / not claimed:** the full-module shuffled determinism run
(`-count=2 -shuffle=on ./...`), the sharded race path, coverage floors, the
`benchgate` lane (this change adds no wall-clock gate), the frontend tree and
the `cmd/culvert-maint` module — none of them own any contract this change
touches, and no hosted Fast/Deep PR Gate verdict for this SHA is claimed. A
passing local selection is not aggregate CI approval.

## 10. Residual risk — the open half

**This feed still has no staleness alert and no health row.** The contrast is
in-tree: `threatfeed_health.go:154` fires `threat_feed_stale` and `:217`
defers a startup variant. A blocklist feed that has never synced, or is
arbitrarily stale, is visible only as `LastError` in the admin API and one log
line per attempt — so post-fix the *node* recovers on its own, but an operator
whose feed origin is permanently gone still learns nothing unless they look.
That is the difference between "retries correctly" and "is monitored", and this
PR only closes the first.

Deliberately not bundled: a new alert type has GUI/API parity consequences
(alert registry, UI surface, documentation) that `conventions.md` routes through
the admin control plane, and inventing one inside a scheduling fix is the kind
of scope creep the register's own rules forbid. Recommended shape, for the
owner: a `blocklist_feed_stale` alert keyed on
`now - LastSync > k × interval` with a deferred startup variant for
never-synced feeds, plus a diagnostics row per feed.

Also residual: pre-fix merged error-page entries persist (§4), and the
unbounded feed body (§8.3) is open for all four loops.
